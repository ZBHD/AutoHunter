"""政府、军队和政法等敏感域名的前置跳过回归测试。"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents import collector, prefilter
from app.db.models import Base, Killsweep, Target, Task
from app.orchestrator import TaskRunner


async def _database(tmp_path, name: str):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / name}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, sessions


@pytest.mark.parametrize(
    "value",
    (
        "www.gov.cn",
        "gjzwfw.gov.cn",
        "foo.gov",
        "a.b.gov.uk",
        "https://service.gov.au/path",
        "portal.gov.ac.uk",
    ),
)
def test_is_gov_host_accepts_government_suffixes(value: str) -> None:
    assert prefilter.is_gov_host(value)


@pytest.mark.parametrize(
    "value",
    (
        "government.com",
        "mygov.edu.cn",
        "gov.example.com",
        "example.com",
        "1.2.3.4",
        "[2001:db8::1]:443",
        "school.edu.cn",
    ),
)
def test_is_gov_host_rejects_non_government_hosts(value: str) -> None:
    assert not prefilter.is_gov_host(value)


@pytest.mark.parametrize("value", ("www.mil.cn", "portal.mil", "a.unit.mil.uk"))
def test_is_sensitive_host_accepts_military_suffixes(value: str) -> None:
    assert prefilter.is_sensitive_host(value)


@pytest.mark.parametrize(
    "value",
    (
        "gongan.example.com",
        "xxjiancha.org.cn",
        "chinamil.com.cn",
        "某市公安局.example.com",
        "省纪委.example.cn",
        "国防.example.org",
    ),
)
def test_is_sensitive_host_accepts_sensitive_keywords(value: str) -> None:
    assert prefilter.is_sensitive_host(value)


@pytest.mark.parametrize(
    "value",
    (
        "government.com",
        "military.example.com",
        "court.student.edu.cn",
        "safe.example.com",
        "1.2.3.4",
    ),
)
def test_is_sensitive_host_rejects_unrelated_hosts(value: str) -> None:
    assert not prefilter.is_sensitive_host(value)


def test_is_sensitive_host_accepts_configured_suffixes(monkeypatch) -> None:
    monkeypatch.setenv(
        "AUTOHUNTER_SENSITIVE_HOSTS",
        " sensitive.test, .blocked.example, SENSITIVE.TEST ",
    )

    assert prefilter.is_sensitive_host("a.sensitive.test")
    assert prefilter.is_sensitive_host("blocked.example")
    assert not prefilter.is_sensitive_host("notsensitive.test")
    assert not prefilter.is_sensitive_host("safe.example.com")


def test_should_skip_gov_without_probe(monkeypatch) -> None:
    def unexpected_probe(*_args, **_kwargs):
        raise AssertionError("政府域名不应进入网络探测")

    monkeypatch.setattr(prefilter, "probe", unexpected_probe)

    skip, reason, info = prefilter.should_skip_ex(
        "www.gov.cn", "https://www.gov.cn/"
    )

    assert skip is True
    assert "敏感" in reason
    assert info == {}


def test_should_skip_sensitive_host_without_probe(monkeypatch) -> None:
    def unexpected_probe(*_args, **_kwargs):
        raise AssertionError("敏感域名不应进入网络探测")

    monkeypatch.setattr(prefilter, "probe", unexpected_probe)

    skip, reason, info = prefilter.should_skip_ex(
        "www.mil.cn", "https://www.mil.cn/"
    )

    assert skip is True
    assert "敏感" in reason
    assert info == {}


@pytest.mark.asyncio
async def test_refill_records_gov_manual_target_as_skipped(tmp_path) -> None:
    engine, sessions = await _database(tmp_path, "manual-gov.db")
    try:
        async with sessions() as session:
            task = Task(
                id="manual-gov",
                name="Manual gov",
                status="running",
                target_source="manual",
                manual_targets=["https://www.gov.cn/path", "safe.example"],
            )
            session.add(task)
            await session.commit()

            added = await collector.refill(session, task)
            targets = list(await session.scalars(
                select(Target).where(Target.task_id == task.id).order_by(Target.host)
            ))

            assert added == 1
            assert [
                (target.host, target.source, target.status, target.verdict)
                for target in targets
            ] == [
                ("safe.example", "manual", "queued", ""),
                ("www.gov.cn", "manual", "skipped", "skip_sensitive"),
            ]
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_site_collection_records_gov_target_without_routes(tmp_path) -> None:
    engine, sessions = await _database(tmp_path, "site-gov.db")
    try:
        async with sessions() as session:
            task = Task(
                id="site-gov",
                name="Site gov",
                status="running",
                target_source="site",
                manual_targets=["https://portal.gov.cn/login"],
            )
            session.add(task)
            await session.commit()

            added = await collector.refill(session, task)
            targets = list(await session.scalars(
                select(Target).where(Target.task_id == task.id)
            ))

            assert added == 0
            assert len(targets) == 1
            assert (
                targets[0].host,
                targets[0].source,
                targets[0].status,
                targets[0].verdict,
            ) == ("portal.gov.cn", "site", "skipped", "skip_sensitive")
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_fofa_collection_records_gov_before_network_prefilter(monkeypatch) -> None:
    class Engine:
        display_name = "Quake"

        @staticmethod
        def get_default_base_url() -> str:
            return "https://quake.example"

        async def search(self, *_args, **_kwargs):
            return SimpleNamespace(
                fields=["host", "ip", "org", "title"],
                results=[["https://www.gov.cn/", "1.2.3.4", "Gov", "Portal"]],
            )

    async def unexpected_prefilter(_candidates):
        raise AssertionError("政府域名不应进入网络预筛")

    monkeypatch.setattr(collector, "get_engine", lambda _name: Engine())
    monkeypatch.setattr(collector, "resolve_engine_config", lambda _task: {
        "engine": "quake",
        "key": "test-key",
        "base_url": "https://quake.example",
        "max_pages": 2,
        "page_size": 10,
    })
    monkeypatch.setattr(collector, "_llm_for_task", lambda _task: None)
    monkeypatch.setattr(collector, "_prefilter", unexpected_prefilter)
    added_targets: list[Target] = []
    session = SimpleNamespace(add=added_targets.append)
    task = SimpleNamespace(
        id="fofa-gov",
        fofa_config={"current_query": 'host="gov.cn"', "cursor": 0},
        src_type="edusrc",
        fofa_query="",
    )

    added = await collector._fofa_collect(session, task, set(), {})

    assert added == 0
    assert len(added_targets) == 1
    assert (
        added_targets[0].host,
        added_targets[0].source,
        added_targets[0].status,
        added_targets[0].verdict,
    ) == ("www.gov.cn", "fofa", "skipped", "skip_sensitive")


@pytest.mark.asyncio
async def test_killsweep_does_not_enqueue_gov_target(tmp_path) -> None:
    engine, sessions = await _database(tmp_path, "killsweep-gov.db")
    try:
        async with sessions() as session:
            session.add(Task(id="task", name="Task", status="running"))
            session.add(Killsweep(id="case", task_id="task", manual_verdict=None))
            await session.commit()

            enqueued = await TaskRunner._enqueue_killsweep_target(
                object(),
                session,
                task_id="task",
                case_id="case",
                url="https://service.gov.cn/check",
                origin="https://origin.example",
            )
            await session.commit()

            targets = list(await session.scalars(
                select(Target).where(Target.task_id == "task")
            ))
            assert enqueued is False
            assert targets == []
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_killsweep_does_not_enqueue_sensitive_target(tmp_path) -> None:
    engine, sessions = await _database(tmp_path, "killsweep-sensitive.db")
    try:
        async with sessions() as session:
            session.add(Task(id="task", name="Task", status="running"))
            session.add(Killsweep(id="case", task_id="task", manual_verdict=None))
            await session.commit()

            enqueued = await TaskRunner._enqueue_killsweep_target(
                object(),
                session,
                task_id="task",
                case_id="case",
                url="https://portal.mil.cn/check",
                origin="https://origin.example",
            )
            await session.commit()

            targets = list(await session.scalars(
                select(Target).where(Target.task_id == "task")
            ))
            assert enqueued is False
            assert targets == []
    finally:
        await engine.dispose()
