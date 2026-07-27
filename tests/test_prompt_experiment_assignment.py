import asyncio
from datetime import datetime, timedelta, timezone
import hashlib

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import orchestrator
from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    COMPILED_STABLE_RELEASE_ID,
    LEGACY_RELEASE_ID,
)
from app.db.models import Base, PromptExperiment, SystemSettings, Target, Task
from app.prompt_experiments import assignment_for_target, cohort_bucket


def _run(coro):
    return asyncio.run(coro)


def _target_id_for_bucket(*, seed: str, candidate: bool, percent: float = 10.0) -> str:
    threshold = round(percent * 100)
    for index in range(100_000):
        target_id = f"target-{index}"
        if (cohort_bucket(seed, target_id) < threshold) is candidate:
            return target_id
    raise AssertionError("could not find deterministic target bucket")


def test_cohort_bucket_matches_sha256_contract() -> None:
    seed = "experiment-seed"
    target_id = "target-42"
    expected = int.from_bytes(
        hashlib.sha256(f"{seed}:{target_id}".encode()).digest()[:8],
        "big",
    ) % 10_000

    assert cohort_bucket(seed, target_id) == expected
    assert cohort_bucket(seed, target_id) == cohort_bucket(seed, target_id)


def test_existing_target_assignment_is_never_recomputed() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                task = Task(id="task", name="Task")
                target = Target(
                    id="target",
                    task_id="task",
                    url="https://example.test",
                    host="example.test",
                    prompt_release_id=LEGACY_RELEASE_ID,
                    prompt_experiment_id="old-experiment",
                    prompt_cohort="manual",
                )
                assignment = await assignment_for_target(session, task, target)

            assert assignment.release_id == LEGACY_RELEASE_ID
            assert assignment.experiment_id == "old-experiment"
            assert assignment.cohort == "manual"
        finally:
            await engine.dispose()

    _run(scenario())


def test_fixed_legacy_task_uses_manual_cohort() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                task = Task(
                    id="task",
                    name="Task",
                    model_config_json={"prompt_version": "legacy"},
                )
                target = Target(
                    id="target",
                    task_id="task",
                    url="https://example.test",
                    host="example.test",
                )
                assignment = await assignment_for_target(session, task, target)

            assert assignment.release_id == LEGACY_RELEASE_ID
            assert assignment.experiment_id == ""
            assert assignment.cohort == "manual"
        finally:
            await engine.dispose()

    _run(scenario())


def test_live_experiment_assigns_stable_and_candidate_by_hash() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        seed = "live-seed"
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                task = Task(id="task", name="Task")
                experiment = PromptExperiment(
                    id="experiment",
                    status="live",
                    stable_release_id=COMPILED_STABLE_RELEASE_ID,
                    candidate_release_id=CANDIDATE_RELEASE_ID,
                    seed=seed,
                    canary_percent=10.0,
                    live_started_at=datetime.now(timezone.utc),
                )
                session.add(experiment)
                await session.flush()
                candidate = Target(
                    id=_target_id_for_bucket(seed=seed, candidate=True),
                    task_id="task",
                    url="https://candidate.test",
                    host="candidate.test",
                )
                stable = Target(
                    id=_target_id_for_bucket(seed=seed, candidate=False),
                    task_id="task",
                    url="https://stable.test",
                    host="stable.test",
                )

                candidate_assignment = await assignment_for_target(
                    session,
                    task,
                    candidate,
                )
                stable_assignment = await assignment_for_target(session, task, stable)

            assert candidate_assignment.release_id == CANDIDATE_RELEASE_ID
            assert candidate_assignment.cohort == "candidate"
            assert stable_assignment.release_id == COMPILED_STABLE_RELEASE_ID
            assert stable_assignment.cohort == "stable"
            assert candidate_assignment.experiment_id == "experiment"
            assert stable_assignment.experiment_id == "experiment"
        finally:
            await engine.dispose()

    _run(scenario())


def test_promoted_experiment_uses_ten_percent_old_stable_holdback() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        seed = "holdback-seed"
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                task = Task(id="task", name="Task")
                session.add(PromptExperiment(
                    id="experiment",
                    status="promoted",
                    stable_release_id=COMPILED_STABLE_RELEASE_ID,
                    candidate_release_id=CANDIDATE_RELEASE_ID,
                    previous_stable_id=COMPILED_STABLE_RELEASE_ID,
                    seed=seed,
                    canary_percent=10.0,
                    promoted_at=now - timedelta(hours=1),
                ))
                await session.flush()
                holdback = Target(
                    id=_target_id_for_bucket(seed=seed, candidate=True),
                    task_id="task",
                    url="https://holdback.test",
                    host="holdback.test",
                )
                promoted = Target(
                    id=_target_id_for_bucket(seed=seed, candidate=False),
                    task_id="task",
                    url="https://promoted.test",
                    host="promoted.test",
                )

                holdback_assignment = await assignment_for_target(
                    session,
                    task,
                    holdback,
                    now=now,
                )
                promoted_assignment = await assignment_for_target(
                    session,
                    task,
                    promoted,
                    now=now,
                )

            assert holdback_assignment.release_id == COMPILED_STABLE_RELEASE_ID
            assert holdback_assignment.cohort == "holdback"
            assert promoted_assignment.release_id == CANDIDATE_RELEASE_ID
            assert promoted_assignment.cohort == "candidate"
        finally:
            await engine.dispose()

    _run(scenario())


def test_pop_queued_pins_release_in_assignment_update(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(
            f"sqlite+aiosqlite:///{tmp_path / 'prompt-assignment.db'}"
        )
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                session.add(Task(id="task", name="Task", status="running"))
                session.add(SystemSettings(
                    id="global",
                    defaults={"stable_prompt_release_id": COMPILED_STABLE_RELEASE_ID},
                ))
                session.add(Target(
                    id="target",
                    task_id="task",
                    url="https://example.test",
                    host="example.test",
                    source="manual",
                    status="queued",
                ))
                await session.commit()

            runner = orchestrator.TaskRunner("task")
            runner._is_enterprise = True

            async def all_alive(targets):
                return {
                    target.id: {"alive": True, "url": target.url}
                    for target in targets
                }

            monkeypatch.setattr(runner, "_probe_queued_liveness", all_alive)
            async with sessions() as session:
                selected = await runner._pop_queued(session)

            assert selected is not None
            assert selected.status == "assigned"
            assert selected.prompt_release_id == COMPILED_STABLE_RELEASE_ID
            assert selected.prompt_experiment_id == ""
            assert selected.prompt_cohort == "stable"
        finally:
            await engine.dispose()

    _run(scenario())
