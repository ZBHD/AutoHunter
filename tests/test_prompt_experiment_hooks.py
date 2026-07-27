import asyncio
import inspect
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import orchestrator, prompt_experiments
from app.agents import prompt_releases
from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    COMPILED_STABLE_RELEASE_ID,
    MODERN_RELEASE_ID,
)
from app.api import findings, missed_signals
from app.db.models import Base, PromptExperiment, PromptExperimentSample, SystemSettings
from app.prompt_experiments import PromptExperimentService


async def _database():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, sessions


def _experiment(*, status: str, candidate_release_id: str = CANDIDATE_RELEASE_ID):
    now = datetime(2026, 7, 27, 12)
    return PromptExperiment(
        id=f"experiment-{status}",
        status=status,
        stable_release_id=COMPILED_STABLE_RELEASE_ID,
        candidate_release_id=candidate_release_id,
        previous_stable_id=MODERN_RELEASE_ID,
        seed="seed",
        canary_percent=10,
        live_started_at=now - timedelta(days=8),
        promoted_at=now - timedelta(hours=1) if status == "promoted" else None,
    )


def test_recompute_hook_logs_and_swallows_failures(monkeypatch, caplog) -> None:
    class FakeSession:
        rollback_count = 0

        async def rollback(self):
            self.rollback_count += 1

    async def fail_recompute(self, session, *, now=None):
        raise RuntimeError("recompute exploded")

    monkeypatch.setattr(PromptExperimentService, "recompute", fail_recompute)
    session = FakeSession()

    asyncio.run(prompt_experiments.recompute_active_prompt_experiment(session))

    assert session.rollback_count == 1
    assert "recompute exploded" in caplog.text


def test_recover_marks_offline_or_live_experiment_failed_when_candidate_missing(
    monkeypatch,
) -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        missing = "worker-2099-01-01-r1"
        try:
            async with sessions() as session:
                session.add(_experiment(status="live", candidate_release_id=missing))
                await session.commit()

                await prompt_experiments.recover_prompt_experiments(session)

                experiment = await session.get(PromptExperiment, "experiment-live")
                assert experiment.status == "failed"
                assert missing in experiment.failure_reason
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_recover_promoted_missing_release_restores_previous_stable(monkeypatch) -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                experiment = _experiment(status="promoted")
                session.add(experiment)
                session.add(SystemSettings(
                    id="global",
                    defaults={"stable_prompt_release_id": CANDIDATE_RELEASE_ID},
                ))
                await session.commit()

                monkeypatch.delitem(
                    prompt_releases.PROMPT_RELEASES,
                    CANDIDATE_RELEASE_ID,
                )
                await prompt_experiments.recover_prompt_experiments(session)

                settings = await session.get(SystemSettings, "global")
                assert settings.defaults["stable_prompt_release_id"] == MODERN_RELEASE_ID
                assert experiment.status == "rolled_back"
                assert CANDIDATE_RELEASE_ID in experiment.rollback_reason
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_recover_promoted_missing_release_falls_back_to_compiled_stable(
    monkeypatch,
) -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        missing_previous = "worker-2099-01-02-r1"
        try:
            async with sessions() as session:
                experiment = _experiment(status="promoted")
                experiment.previous_stable_id = missing_previous
                session.add(experiment)
                session.add(SystemSettings(
                    id="global",
                    defaults={"stable_prompt_release_id": CANDIDATE_RELEASE_ID},
                ))
                await session.commit()

                monkeypatch.delitem(
                    prompt_releases.PROMPT_RELEASES,
                    CANDIDATE_RELEASE_ID,
                )
                await prompt_experiments.recover_prompt_experiments(session)

                settings = await session.get(SystemSettings, "global")
                assert (
                    settings.defaults["stable_prompt_release_id"]
                    == COMPILED_STABLE_RELEASE_ID
                )
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_recompute_without_new_samples_does_not_duplicate_daily_windows() -> None:
    async def scenario() -> None:
        now = datetime(2026, 7, 27, 12)
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                experiment = _experiment(status="live")
                session.add(experiment)
                for cohort in ("stable", "candidate"):
                    session.add(PromptExperimentSample(
                        experiment_id=experiment.id,
                        phase="live",
                        cohort=cohort,
                        release_id=(
                            COMPILED_STABLE_RELEASE_ID
                            if cohort == "stable"
                            else CANDIDATE_RELEASE_ID
                        ),
                        target_id=f"target-{cohort}",
                        terminal_verdict="no_vuln",
                        metrics={},
                        finished_at=now - timedelta(days=1),
                    ))
                await session.commit()

                service = PromptExperimentService()
                await service.recompute(session, now=now)
                first = list(experiment.metrics["windows"])
                await service.recompute(session, now=now)

                assert experiment.metrics["windows"] == first
                assert len(experiment.metrics["windows"]) == 1
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def _assert_single_post_commit_hook(function) -> None:
    source = inspect.getsource(function)
    assert source.count("await recompute_active_prompt_experiment(session)") == 1
    assert source.rindex("await session.commit()") < source.rindex(
        "await recompute_active_prompt_experiment(session)"
    )


def test_business_transactions_trigger_one_post_commit_recompute() -> None:
    _assert_single_post_commit_hook(orchestrator.TaskRunner._persist_worker_result)
    _assert_single_post_commit_hook(findings.restore_archived)
    _assert_single_post_commit_hook(findings.user_review)
    _assert_single_post_commit_hook(missed_signals.reject_missed_signal)
    _assert_single_post_commit_hook(missed_signals.restore_missed_signal)
    _assert_single_post_commit_hook(missed_signals.confirm_missed_signal_draft)


def test_startup_recovers_experiments_before_restoring_tasks() -> None:
    from app import main

    source = inspect.getsource(main.lifespan)
    assert "async with SessionLocal() as session:" in source
    assert source.index("await init_settings_cache()") < source.index(
        "await recover_prompt_experiments(session)"
    )
    assert source.index("await recover_prompt_experiments(session)") < source.index(
        "await manager.restore_on_startup()"
    )
