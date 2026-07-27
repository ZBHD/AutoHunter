import asyncio
import json

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    COMPILED_STABLE_RELEASE_ID,
    LEGACY_RELEASE_ID,
)
from app.db.models import Base, PromptExperiment, PromptExperimentSample, SystemSettings
from app.prompt_experiments import (
    PromptExperimentConflictError,
    PromptExperimentService,
)
from app.prompt_replay import load_replay_fixtures
from scripts import manage_prompt_experiment


async def _database():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with sessions() as session:
        session.add(SystemSettings(
            id="global",
            defaults={"stable_prompt_release_id": COMPILED_STABLE_RELEASE_ID},
        ))
        await session.commit()
    return engine, sessions


class _PassingRunner:
    def run_case(
        self,
        fixture,
        release,
        *,
        experiment_id,
        run_number,
        cohort=None,
    ):
        return PromptExperimentSample(
            experiment_id=experiment_id,
            phase="offline",
            cohort=cohort or "stable",
            release_id=release.release_id,
            case_id=fixture.case_id,
            run_number=run_number,
            src_type=fixture.src_type,
            route_id=fixture.route_id,
            terminal_verdict=fixture.expected_terminal_verdicts[0],
            rounds=2,
            tool_calls=2,
            total_tokens=100,
            usage_complete=True,
            evidence_complete=True,
            metrics={
                "protocol_error_count": 0,
                "expected_terminal": True,
                "agent_crash": False,
            },
        )


def test_start_rejects_non_promotable_release() -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                with pytest.raises(ValueError, match="not promotable"):
                    await PromptExperimentService().start(
                        session,
                        candidate_release_id=LEGACY_RELEASE_ID,
                    )
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_start_rejects_second_active_experiment() -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                service = PromptExperimentService()
                await service.start(session, candidate_release_id=CANDIDATE_RELEASE_ID)
                with pytest.raises(PromptExperimentConflictError, match="active"):
                    await service.start(session, candidate_release_id=CANDIDATE_RELEASE_ID)
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_offline_replay_passes_hard_gate_and_enters_live() -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                service = PromptExperimentService()
                experiment = await service.start(
                    session,
                    candidate_release_id=CANDIDATE_RELEASE_ID,
                    seed="seed",
                )

                decision = await service.run_offline(
                    session,
                    experiment,
                    _PassingRunner(),
                    load_replay_fixtures(),
                    static_contract_pass_rate=1.0,
                )

                assert decision.passed is True
                assert experiment.status == "live"
                assert experiment.live_started_at is not None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_offline_forbidden_action_fails_experiment() -> None:
    class ForbiddenRunner(_PassingRunner):
        def run_case(self, *args, **kwargs):
            sample = super().run_case(*args, **kwargs)
            if kwargs.get("cohort") == "candidate":
                sample.forbidden_action_count = 1
            return sample

    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                service = PromptExperimentService()
                experiment = await service.start(
                    session,
                    candidate_release_id=CANDIDATE_RELEASE_ID,
                    seed="seed",
                )
                decision = await service.run_offline(
                    session,
                    experiment,
                    ForbiddenRunner(),
                    load_replay_fixtures(),
                    static_contract_pass_rate=1.0,
                )

                assert decision.passed is False
                assert experiment.status == "failed"
                assert experiment.failure_reason
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_cancel_keeps_stable_pointer_and_report_is_sanitized() -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                service = PromptExperimentService()
                experiment = await service.start(
                    session,
                    candidate_release_id=CANDIDATE_RELEASE_ID,
                    seed="seed",
                )
                await service.cancel(session, "operator stop")
                report = await service.report(session, experiment.id)
                settings = await session.get(SystemSettings, "global")

                assert experiment.status == "cancelled"
                assert settings.defaults["stable_prompt_release_id"] == COMPILED_STABLE_RELEASE_ID
                assert set(report) == {
                    "id",
                    "status",
                    "stable_release_id",
                    "candidate_release_id",
                    "canary_percent",
                    "metrics",
                    "fixture_ids",
                    "failure_reason",
                    "promotion_reason",
                    "rollback_reason",
                }
                assert "seed" not in report
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_cli_status_runs_against_injected_session(capsys) -> None:
    async def scenario() -> None:
        engine, sessions = await _database()
        try:
            async with sessions() as session:
                await PromptExperimentService().start(
                    session,
                    candidate_release_id=CANDIDATE_RELEASE_ID,
                    seed="seed",
                )
            code = await manage_prompt_experiment.async_main(
                ["status"],
                session_factory=sessions,
                initialize=False,
            )
            assert code == 0
        finally:
            await engine.dispose()

    asyncio.run(scenario())
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "offline"
    assert payload["candidate_release_id"] == CANDIDATE_RELEASE_ID
