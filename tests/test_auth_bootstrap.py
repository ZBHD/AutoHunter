from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents.auth_bootstrap import (
    bootstrap_auth,
    match_auth_to_target,
    normalize_binding,
    parse_cookie_string,
    resolve_auth_context_for_target,
    try_user_login,
)
from app.db.models import Base, Target, Task


class FakeExecutor:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []
        self._session_cookies = {}
        self._session_headers = {}

    def session_set(self, *, cookies=None, headers=None):
        self.calls.append(("session_set", cookies, headers))
        self._session_cookies.update(cookies or {})
        self._session_headers.update(headers or {})
        return {"ok": True}

    def http_request(self, url, **kwargs):
        self.calls.append(("http_request", url, kwargs))
        response = self.responses.pop(0) if self.responses else {
            "ok": True,
            "status_code": 200,
            "body": "",
            "final_url": url,
        }
        self._session_cookies.update(response.get("cookies") or {})
        return response


def test_parse_raw_cookie_bearer_and_username_password() -> None:
    assert parse_cookie_string("Cookie: sid=abc; theme=dark") == {
        "sid": "abc", "theme": "dark"
    }
    parsed = normalize_binding({
        "target": "example.com",
        "raw": "Authorization: Bearer token-1\nusername: alice password: secret",
    })
    assert parsed["headers"] == {"Authorization": "Bearer token-1"}
    assert parsed["username"] == "alice"
    assert parsed["password"] == "secret"
    assert parsed["kinds"] == ["bearer", "password"]


def test_auth_matching_uses_specific_priority_and_merges_same_level() -> None:
    bindings = [
        {"target": "*", "cookie": "wild=1"},
        {"target": "example.com", "cookie": "host=1"},
        {"target": "example.com:8443", "cookie": "port=1"},
        {"target": "https://example.com:8443/app", "cookie": "url=1"},
        {"target": "https://example.com:8443/app", "authorization": "Bearer exact"},
    ]
    result = match_auth_to_target("https://example.com:8443/app", bindings)
    assert result.matched_by == "url"
    assert result.context["cookies"] == {"url": "1"}
    assert result.context["headers"] == {"Authorization": "Bearer exact"}
    assert "wild" not in result.context["cookies"]

    line_result = match_auth_to_target(
        "https://line.example/entry",
        [{"target": "line.example", "cookie": "host=1"}, {"target": "https://line.example/entry", "cookie": "url=1"}],
        manual_lines=["https://line.example/entry"],
    )
    assert line_result.matched_by == "url"

    manual_line = match_auth_to_target(
        "https://line.example/other",
        [
            {"target": "line.example", "cookie": "host=1"},
            {"target": "https://line.example/login", "cookie": "line=1"},
        ],
        manual_lines=["https://line.example/login"],
    )
    assert manual_line.matched_by == "line"
    assert manual_line.context["cookies"] == {"line": "1"}


def test_manual_line_beats_host_and_explicit_binding_excludes_wildcard() -> None:
    bindings = [
        {"target": "*", "cookie": "wild=1"},
        {"target": "manual.example", "cookie": "host=1"},
        {"target": "https://manual.example/login", "cookie": "line=1"},
    ]
    result = match_auth_to_target(
        "https://manual.example/login",
        bindings,
        manual_lines=["https://manual.example/login"],
    )
    assert result.matched_by == "url"
    assert result.context["cookies"] == {"line": "1"}
    assert "wild" not in result.context["cookies"]

    explicit = resolve_auth_context_for_target(
        [{"target": "other.example", "cookie": "sid=1"}, {"target": "*", "cookie": "wild=1"}],
        "https://unmatched.example/",
    )
    assert explicit is None


def test_login_uses_explicit_same_origin_url_only() -> None:
    executor = FakeExecutor([{
        "ok": True,
        "status_code": 200,
        "body": '<form action="/session"><input name="username"><input type="password" name="password"></form>',
        "final_url": "https://example.com/entry",
    }, {
        "ok": True,
        "status_code": 302,
        "body": "ok",
        "final_url": "https://example.com/home",
        "cookies": {"session": "s1"},
    }])
    result = try_user_login(
        executor,
        "https://example.com/entry",
        "alice",
        "secret",
        "https://example.com/login",
    )
    assert result["ok"] is True
    assert [call[1] for call in executor.calls if call[0] == "http_request"] == [
        "https://example.com/login", "https://example.com/session"
    ]

    cross_origin = FakeExecutor()
    failed = try_user_login(
        cross_origin, "https://example.com/entry", "alice", "secret", "https://other.example/login"
    )
    assert failed["ok"] is False
    assert cross_origin.calls == []


def test_login_inspects_entry_page_only_and_200_alone_is_not_success() -> None:
    no_form = FakeExecutor([{
        "ok": True, "status_code": 200, "body": "welcome", "final_url": "https://example.com/entry"
    }])
    result = try_user_login(no_form, "https://example.com/entry", "alice", "secret")
    assert result["ok"] is False
    assert [call[1] for call in no_form.calls if call[0] == "http_request"] == [
        "https://example.com/entry"
    ]

    plain_200 = FakeExecutor([{
        "ok": True,
        "status_code": 200,
        "body": '<form action="/session"><input name="username"><input type="password" name="password"></form>',
        "final_url": "https://example.com/entry",
    }, {
        "ok": True,
        "status_code": 200,
        "body": "still here",
        "final_url": "https://example.com/entry",
    }])
    result = try_user_login(plain_200, "https://example.com/entry", "alice", "secret")
    assert result["ok"] is False


def test_login_input_and_transport_errors_degrade_without_raising() -> None:
    malformed = FakeExecutor()
    result = try_user_login(
        malformed,
        "https://example.com/entry",
        "alice",
        "secret",
        "https://example.com:invalid/login",
    )
    assert result["ok"] is False
    assert malformed.calls == []

    class RaisingExecutor(FakeExecutor):
        def http_request(self, url, **kwargs):
            raise OSError("network unavailable")

    result = bootstrap_auth(
        RaisingExecutor(),
        {
            "matched": True,
            "username": "alice",
            "password": "secret",
            "kinds": ["password"],
        },
        "https://example.com/entry",
    )
    assert result.status == "login_fail"
    assert "secret" not in repr(result.as_event())


def test_bootstrap_without_credentials_makes_no_request_and_event_is_redacted() -> None:
    executor = FakeExecutor()
    result = bootstrap_auth(executor, None, "https://example.com/entry")
    assert result.status == "unused"
    assert executor.calls == []

    injected = bootstrap_auth(
        executor,
        {
            "matched": True,
            "matched_by": "host",
            "binding_target": "example.com",
            "cookies": {"sid": "secret-value"},
            "headers": {"Authorization": "Bearer secret-token"},
            "kinds": ["cookie", "bearer"],
        },
        "https://example.com/entry",
    )
    event = injected.as_event()
    assert injected.status == "injected"
    assert event["cookie_names"] == ["sid"]
    assert event["header_names"] == ["Authorization"]
    assert "secret-value" not in repr(event)
    assert "secret-token" not in repr(event)


def test_manual_target_is_enqueued_with_matching_auth_context() -> None:
    async def scenario() -> None:
        from app.agents import collector

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                task = Task(
                    id="auth-task",
                    name="Auth task",
                    target_source="manual",
                    manual_targets=["https://portal.example/login"],
                    auth_bindings=[{
                        "target": "https://portal.example/login",
                        "username": "alice",
                        "password": "secret",
                    }],
                )
                session.add(task)
                await session.commit()

                assert await collector.refill(session, task, low_watermark=1) == 1
                target = (
                    await session.execute(
                        select(Target).where(Target.task_id == task.id)
                    )
                ).scalar_one()
                assert target.auth_context["matched_by"] == "url"
                assert target.auth_context["binding_target"] == (
                    "https://portal.example/login"
                )
                assert target.auth_context["username"] == "alice"
                assert target.auth_context["password"] == "secret"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_worker_bootstraps_auth_before_first_llm_call(monkeypatch) -> None:
    from app.agents import worker as worker_module

    events = []

    class WorkerExecutor(FakeExecutor):
        def __init__(self, *args, **kwargs):
            super().__init__()

    class LLM:
        def chat(self, *args, **kwargs):
            events.append(("llm_called", {}))
            raise RuntimeError("stop after ordering assertion")

    monkeypatch.setattr(worker_module, "ToolExecutor", WorkerExecutor)
    worker = worker_module.Worker(
        "https://portal.example/entry",
        llm=LLM(),
        on_event=lambda kind, data: events.append((kind, dict(data))),
        auth_context={
            "matched": True,
            "matched_by": "host",
            "binding_target": "portal.example",
            "cookies": {"sid": "secret-value"},
            "kinds": ["cookie"],
        },
    )

    worker.run()

    event_names = [kind for kind, _data in events]
    assert event_names.index("auth_status") < event_names.index("llm_called")
    auth_event = next(data for kind, data in events if kind == "auth_status")
    assert auth_event["status"] == "injected"
    assert "secret-value" not in repr(auth_event)
    assert worker.executor._session_cookies == {"sid": "secret-value"}


def test_public_auth_event_uses_strict_whitelist() -> None:
    from app.orchestrator import public_worker_event

    projected = public_worker_event("auth_status", {
        "used": True,
        "matched": True,
        "status": "injected",
        "kinds": ["cookie"],
        "matched_by": "host",
        "binding_target": "portal.example",
        "reason": "session ready",
        "cookie_names": ["sid"],
        "header_names": [],
        "password": "secret-password",
        "cookies": {"sid": "secret-cookie"},
        "authorization": "Bearer secret-token",
    })

    assert projected == {
        "used": True,
        "matched": True,
        "status": "injected",
        "kinds": ["cookie"],
        "matched_by": "host",
        "binding_target": "portal.example",
        "reason": "session ready",
        "cookie_names": ["sid"],
        "header_names": [],
    }
    assert "secret" not in repr(projected)


def test_orchestrator_persists_only_public_auth_status(monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                session.add(Task(id="persist-task", name="Persist auth"))
                session.add(Target(
                    id="persist-target",
                    task_id="persist-task",
                    url="https://portal.example",
                    host="portal.example",
                ))
                await session.commit()

            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            runner = orchestrator.TaskRunner("persist-task")
            await runner._persist_target_auth_status(
                "persist-task",
                "persist-target",
                {
                    "used": True,
                    "matched": True,
                    "status": "injected",
                    "kinds": ["cookie"],
                    "cookie_names": ["sid"],
                    "cookies": {"sid": "secret-value"},
                },
            )

            async with sessions() as session:
                target = await session.get(Target, "persist-target")
                assert target.auth_status["status"] == "injected"
                assert target.auth_status["cookie_names"] == ["sid"]
                assert "secret-value" not in repr(target.auth_status)
        finally:
            await engine.dispose()

    asyncio.run(scenario())
