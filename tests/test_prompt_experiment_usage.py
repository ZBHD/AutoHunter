import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents.prompt_releases import CANDIDATE_RELEASE_ID, COMPILED_STABLE_RELEASE_ID
from app import settings_service
from app.db.models import Base, PromptExperiment, PromptExperimentSample, Target, Task
from app.llm import usage as usage_module
from app.llm.usage import (
    UsageContext,
    pop_target_usage,
    record_usage,
    target_usage_snapshot,
    usage_snapshot,
)
from app.prompt_experiments import finalize_live_sample


def _reset_usage(monkeypatch) -> None:
    monkeypatch.setattr(usage_module, "_USAGE", {})
    monkeypatch.setattr(usage_module, "_TARGET_USAGE", {})


def test_usage_context_is_immutable_and_records_task_and_target(monkeypatch) -> None:
    _reset_usage(monkeypatch)
    context = UsageContext(
        task_id="task-1",
        target_id="target-1",
        experiment_id="experiment-1",
        release_id=CANDIDATE_RELEASE_ID,
        cohort="candidate",
    )

    record_usage(
        context,
        "model",
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
    )

    assert usage_snapshot("task-1")["total_tokens"] == 15
    assert target_usage_snapshot("target-1")["total_tokens"] == 15
    assert target_usage_snapshot("target-1")["context"] == {
        "task_id": "task-1",
        "target_id": "target-1",
        "experiment_id": "experiment-1",
        "release_id": CANDIDATE_RELEASE_ID,
        "cohort": "candidate",
    }


def test_pop_target_usage_releases_only_target_counter(monkeypatch) -> None:
    _reset_usage(monkeypatch)
    context = UsageContext(
        task_id="task-1",
        target_id="target-1",
        experiment_id="experiment-1",
        release_id=CANDIDATE_RELEASE_ID,
        cohort="candidate",
    )
    record_usage(context, "model", total_tokens=8)

    popped = pop_target_usage("target-1")

    assert popped["total_tokens"] == 8
    assert target_usage_snapshot("target-1")["requests"] == 0
    assert usage_snapshot("task-1")["total_tokens"] == 8


def test_llm_router_for_task_forwards_usage_context(monkeypatch) -> None:
    captured = {}
    context = UsageContext(
        task_id="task-1",
        target_id="target-1",
        experiment_id="experiment-1",
        release_id=CANDIDATE_RELEASE_ID,
        cohort="candidate",
    )

    class FakeRouter:
        def __init__(self, providers, *, usage_key, on_provider_disabled) -> None:
            captured["providers"] = providers
            captured["usage_key"] = usage_key
            captured["callback"] = on_provider_disabled

    monkeypatch.setattr(settings_service, "LLMRouter", FakeRouter)
    monkeypatch.setattr(settings_service, "resolve_llm_providers", lambda _task: ["provider"])
    monkeypatch.setattr(settings_service, "task_uses_global_pool", lambda _task: False)
    task = Task(id="task-1", name="Task")

    settings_service.llm_router_for_task(task, usage_context=context)

    assert captured["usage_key"] is context


def test_finalize_live_sample_is_idempotent_and_excludes_sensitive_payloads() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                session.add(Task(id="task-1", name="Task"))
                session.add(PromptExperiment(
                    id="experiment-1",
                    status="live",
                    stable_release_id=COMPILED_STABLE_RELEASE_ID,
                    candidate_release_id=CANDIDATE_RELEASE_ID,
                    seed="seed",
                    canary_percent=10,
                ))
                target = Target(
                    id="target-1",
                    task_id="task-1",
                    url="https://example.test",
                    host="example.test",
                    status="done",
                    verdict="found",
                    prompt_release_id=CANDIDATE_RELEASE_ID,
                    prompt_experiment_id="experiment-1",
                    prompt_cohort="candidate",
                    priority_reason="route:auth_boundary/身份边界/+2",
                )
                session.add(target)
                await session.commit()

                result = {
                    "verdict": "found",
                    "rounds": 7,
                    "findings": [{
                        "title": "Finding",
                        "evidence": {"request": "paired", "response": "paired"},
                        "raw_request": "Authorization: Bearer secret-token",
                        "raw_response": "Cookie: session=secret",
                    }],
                    "metrics": {
                        "tool_calls": 6,
                        "tool_errors": 1,
                        "protocol_error_count": 0,
                        "forbidden_action_count": 0,
                    },
                    "system_prompt": "secret prompt body",
                }
                usage = {
                    "prompt_tokens": 100,
                    "completion_tokens": 20,
                    "total_tokens": 120,
                    "requests": 2,
                }

                await finalize_live_sample(session, target, result, usage)
                await finalize_live_sample(session, target, result, usage)
                await session.commit()

                samples = list(await session.scalars(select(PromptExperimentSample)))

            assert len(samples) == 1
            sample = samples[0]
            assert sample.terminal_verdict == "found"
            assert sample.route_id == "auth_boundary"
            assert sample.rounds == 7
            assert sample.tool_calls == 6
            assert sample.tool_errors == 1
            assert sample.finding_count == 1
            assert sample.evidence_complete is True
            assert sample.usage_complete is True
            assert sample.total_tokens == 120
            serialized = repr(sample.metrics)
            assert "secret-token" not in serialized
            assert "session=secret" not in serialized
            assert "secret prompt body" not in serialized
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_finalize_live_sample_marks_missing_usage_incomplete() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                session.add(Task(id="task-1", name="Task"))
                session.add(PromptExperiment(
                    id="experiment-1",
                    status="live",
                    stable_release_id=COMPILED_STABLE_RELEASE_ID,
                    candidate_release_id=CANDIDATE_RELEASE_ID,
                    seed="seed",
                    canary_percent=10,
                ))
                target = Target(
                    id="target-1",
                    task_id="task-1",
                    url="https://example.test",
                    host="example.test",
                    status="dead",
                    verdict="no_vuln",
                    prompt_release_id=COMPILED_STABLE_RELEASE_ID,
                    prompt_experiment_id="experiment-1",
                    prompt_cohort="stable",
                )
                session.add(target)
                await session.commit()

                sample = await finalize_live_sample(
                    session,
                    target,
                    {"verdict": "no_vuln", "rounds": 2, "findings": []},
                    {},
                )

            assert sample.usage_complete is False
            assert sample.total_tokens == 0
        finally:
            await engine.dispose()

    asyncio.run(scenario())
