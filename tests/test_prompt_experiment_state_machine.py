import asyncio
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import settings_service
from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    COMPILED_STABLE_RELEASE_ID,
    MODERN_RELEASE_ID,
)
from app.db.models import Base, PromptExperiment, PromptExperimentSample, SystemSettings
from app.prompt_experiments import GateDecision, PromptExperimentService


async def _database():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, sessions


def _experiment(*, status: str = "live", now: datetime | None = None) -> PromptExperiment:
    current = now or datetime(2026, 7, 27, 12)
    return PromptExperiment(
        id="experiment",
        status=status,
        stable_release_id=COMPILED_STABLE_RELEASE_ID,
        candidate_release_id=CANDIDATE_RELEASE_ID,
        seed="seed",
        canary_percent=10,
        live_started_at=current - timedelta(days=8),
        promoted_at=current - timedelta(hours=1) if status == "promoted" else None,
    )


def test_promotion_compare_and_set_switches_stable_pointer(monkeypatch) -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                experiment = _experiment()
                session.add(experiment)
                session.add(SystemSettings(
                    id="global",
                    defaults={"stable_prompt_release_id": COMPILED_STABLE_RELEASE_ID},
                ))
                await session.commit()

                await PromptExperimentService().promote(
                    session,
                    experiment,
                    {"windows": 3},
                    now=datetime(2026, 7, 27, 12),
                )

                settings = await session.get(SystemSettings, "global")
                assert settings.defaults["stable_prompt_release_id"] == CANDIDATE_RELEASE_ID
                assert experiment.status == "promoted"
                assert experiment.previous_stable_id == COMPILED_STABLE_RELEASE_ID
                assert experiment.promoted_at is not None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_promotion_cas_conflict_never_overwrites_maintainer_setting() -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                experiment = _experiment()
                session.add(experiment)
                session.add(SystemSettings(
                    id="global",
                    defaults={"stable_prompt_release_id": MODERN_RELEASE_ID},
                ))
                await session.commit()

                await PromptExperimentService().promote(
                    session,
                    experiment,
                    {"windows": 3},
                    now=datetime(2026, 7, 27, 12),
                )

                settings = await session.get(SystemSettings, "global")
                assert settings.defaults["stable_prompt_release_id"] == MODERN_RELEASE_ID
                assert experiment.status == "failed"
                assert "Stable 指针冲突" in experiment.failure_reason
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_promoted_experiment_rolls_back_with_compare_and_set() -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                experiment = _experiment(status="promoted")
                experiment.previous_stable_id = COMPILED_STABLE_RELEASE_ID
                session.add(experiment)
                session.add(SystemSettings(
                    id="global",
                    defaults={"stable_prompt_release_id": CANDIDATE_RELEASE_ID},
                ))
                await session.commit()

                await PromptExperimentService().rollback(
                    session,
                    experiment,
                    "quality regression",
                    now=datetime(2026, 7, 27, 13),
                )

                settings = await session.get(SystemSettings, "global")
                assert settings.defaults["stable_prompt_release_id"] == COMPILED_STABLE_RELEASE_ID
                assert experiment.status == "rolled_back"
                assert experiment.rollback_reason == "quality regression"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_recompute_fails_live_experiment_on_protocol_error() -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                experiment = _experiment()
                session.add(experiment)
                session.add(PromptExperimentSample(
                    experiment_id="experiment",
                    phase="live",
                    cohort="candidate",
                    release_id=CANDIDATE_RELEASE_ID,
                    target_id="target",
                    terminal_verdict="no_vuln",
                    metrics={"protocol_error_count": 1},
                    finished_at=datetime(2026, 7, 26, 12),
                ))
                await session.commit()

                await PromptExperimentService().recompute(
                    session,
                    now=datetime(2026, 7, 27, 12),
                )

                assert experiment.status == "failed"
                assert "协议" in experiment.failure_reason
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_recompute_completes_clean_holdback_after_48_hours() -> None:
    async def scenario() -> None:
        now = datetime(2026, 7, 27, 12)
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                experiment = _experiment(status="promoted", now=now)
                experiment.promoted_at = now - timedelta(hours=48)
                experiment.previous_stable_id = COMPILED_STABLE_RELEASE_ID
                session.add(experiment)
                session.add(SystemSettings(
                    id="global",
                    defaults={"stable_prompt_release_id": CANDIDATE_RELEASE_ID},
                ))
                await session.commit()

                await PromptExperimentService().recompute(session, now=now)

                assert experiment.status == "completed"
        finally:
            await engine.dispose()

    asyncio.run(scenario())
