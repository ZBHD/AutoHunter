from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents import worker as worker_module
from app.db.models import (
    Base,
    MissedSignal,
    MissedSignalEvent,
    RawEvidence,
    RawEvidenceChunk,
    Target,
    Task,
    TaskEvent,
)
from app.llm.protocols import LLMResponse, ToolCall
from app.missed_signals import (
    SignalCandidate,
    finish_signal_deepening,
    queue_signal_deepening,
    upsert_signal,
)


def _run(coro):
    return asyncio.run(coro)


class _CaptureExecutor:
    init_kwargs: dict = {}

    def __init__(self, *_args, **kwargs):
        type(self).init_kwargs = dict(kwargs)
        self.capture_full = kwargs.get("capture_full")

    def kill_processes(self):
        return None

    def http_request(self, **_kwargs):
        return {
            "ok": True,
            "status_code": 200,
            "url": "https://example.edu.cn/api/login",
            "response_headers": {"content-type": "application/json"},
            "body": '{"success":true,"access_token":"live-token-value-12345"}',
            "_capture": {"id": "capture-worker", "channels": []},
        }


class _ScriptedLLM:
    def __init__(self):
        self.calls: list[dict] = []
        self.responses = [
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="http-1",
                        name="http_request",
                        arguments=json.dumps({
                            "url": "https://example.edu.cn/api/login",
                            "method": "POST",
                        }),
                    )
                ]
            ),
            LLMResponse(
                tool_calls=[
                    ToolCall(
                        id="finish-1",
                        name="finish",
                        arguments=json.dumps({
                            "verdict": "no_vuln",
                            "summary": "已验证登录响应，仅保留线索供后续人工判断",
                        }),
                    )
                ]
            ),
        ]

    def chat(self, messages, **kwargs):
        self.calls.append({"messages": messages, **kwargs})
        return self.responses.pop(0)


def test_worker_enables_full_capture_and_detaches_private_descriptor_before_llm(
    monkeypatch,
) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _CaptureExecutor)
    events: list[tuple[str, dict]] = []
    llm = _ScriptedLLM()
    worker = worker_module.Worker(
        "https://example.edu.cn",
        llm=llm,
        on_event=lambda kind, data: events.append((kind, data)),
        deepen_context={"directive": "continue"},
    )

    result = worker.run()

    assert result.verdict.value == "no_vuln"
    assert _CaptureExecutor.init_kwargs["capture_full"] is True
    assert "_capture" not in llm.calls[1]["messages"][1]["content"]
    private = [item for item in events if item[0] == "tool_capture_private"]
    assert len(private) == 1
    assert private[0][1]["capture"]["id"] == "capture-worker"
    assert private[0][1]["preview"]["status_code"] == 200
    assert "live-token-value" in private[0][1]["preview"]["body"]


def test_public_worker_event_projection_never_contains_capture_or_raw_preview(
    monkeypatch,
) -> None:
    from app.orchestrator import public_worker_event

    payload = public_worker_event(
        "tool_capture_private",
        {
            "tool": "http_request",
            "capture": {"id": "secret-capture", "channels": []},
            "preview": {"body": "secret-response", "raw_request": "GET /secret"},
            "status_code": 200,
            "url": "https://example.edu.cn/api/login",
        },
    )

    assert "secret-capture" not in repr(payload)
    assert "secret-response" not in repr(payload)
    assert "raw_request" not in repr(payload)
    assert payload["kind"] == "tool_result"
    assert payload["status_code"] == 200


def test_private_capture_task_drain_waits_for_all_persistence() -> None:
    from app.orchestrator import drain_private_tasks

    async def scenario():
        gate = asyncio.Event()
        completed: list[str] = []

        async def persist():
            await gate.wait()
            completed.append("saved")

        tasks = {asyncio.create_task(persist())}
        draining = asyncio.create_task(drain_private_tasks(tasks))
        await asyncio.sleep(0)
        assert not draining.done()
        gate.set()
        await draining
        assert completed == ["saved"]
        assert tasks == set()

    _run(scenario())


def test_private_persistence_is_tracked_before_worker_callback_returns() -> None:
    import threading

    from app.orchestrator import drain_private_tasks, schedule_private_persistence

    async def scenario():
        loop = asyncio.get_running_loop()
        gate = asyncio.Event()
        saved: list[str] = []
        futures: set = set()
        lock = threading.Lock()

        async def persist():
            await gate.wait()
            saved.append("stored")

        await asyncio.to_thread(
            schedule_private_persistence,
            loop,
            persist(),
            futures,
            lock,
        )
        with lock:
            assert len(futures) == 1
        draining = asyncio.create_task(drain_private_tasks(futures, lock))
        await asyncio.sleep(0)
        assert not draining.done()
        gate.set()
        await draining
        assert saved == ["stored"]

    _run(scenario())


def _capture(tmp_path: Path, capture_id: str = "capture-persist") -> dict:
    request = b"POST /api/login HTTP/1.1\r\nHost: example.edu.cn\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        b'{"success":true,"access_token":"live-token-value-12345"}'
    )
    directory = tmp_path / "worker" / ".captures" / capture_id
    directory.mkdir(parents=True)
    req_path = directory / "request.bin"
    resp_path = directory / "response.bin"
    req_path.write_bytes(request)
    resp_path.write_bytes(response)
    return {
        "id": capture_id,
        "tool": "http_request",
        "status": "complete",
        "meta": {"method": "POST", "url": "https://example.edu.cn/api/login"},
        "directory": str(directory),
        "channels": [
            {
                "name": "request",
                "path": str(req_path),
                "size": len(request),
                "sha256": hashlib.sha256(request).hexdigest(),
            },
            {
                "name": "response",
                "path": str(resp_path),
                "size": len(response),
                "sha256": hashlib.sha256(response).hexdigest(),
            },
        ],
    }


def test_worker_cancel_waits_for_late_private_capture_persistence(
    tmp_path,
    monkeypatch,
) -> None:
    from app import orchestrator
    from app.config import worker_config

    monkeypatch.setattr(worker_config, "work_root", str(tmp_path))
    capture = _capture(tmp_path, "capture-cancelled-worker")
    started = threading.Event()
    cancellation_seen = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class FakeExecutor:
        def cancel_running(self):
            cancellation_seen.set()

        def kill_processes(self):
            return None

    class FakeWorker:
        def __init__(self, *_args, on_event, cancel_event, **_kwargs):
            self.on_event = on_event
            self.cancel_event = cancel_event
            self.executor = FakeExecutor()

        def run(self):
            started.set()
            assert self.cancel_event.wait(5)
            cancellation_seen.set()
            assert release.wait(5)
            preview = {
                "ok": True,
                "status_code": 200,
                "url": "https://example.edu.cn/api/login",
                "response_headers": {"content-type": "application/json"},
                "body": '{"access_token":"late-private-token-12345"}',
            }
            self.on_event("tool_capture_private", {
                "tool": "http_request",
                "args": {"url": preview["url"], "method": "POST"},
                "result": preview,
                "preview": preview,
                "capture": capture,
            })
            finished.set()
            return SimpleNamespace(model_dump=lambda mode="json": {
                "verdict": "no_vuln",
                "findings": [],
                "summary": "cancelled after capture",
            })

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'cancel-worker.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-cancel", name="Cancel", status="running"))
            session.add(Target(
                id="target-cancel",
                task_id="task-cancel",
                url="https://example.edu.cn",
                host="example.edu.cn",
                source="manual",
                status="scanning",
                assigned_worker="worker-cancel",
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        monkeypatch.setattr(orchestrator, "Worker", FakeWorker)
        monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
        runner = orchestrator.TaskRunner("task-cancel")
        cancel_event = threading.Event()
        worker_task = asyncio.create_task(
            runner._run_worker(
                "task-cancel",
                "target-cancel",
                "https://example.edu.cn",
                cancel_event,
            )
        )
        runner._active_workers["target-cancel"] = worker_task
        runner._worker_cancel_events["target-cancel"] = cancel_event
        assert await asyncio.to_thread(started.wait, 5)

        cancel_task = asyncio.create_task(runner._cancel_active_workers("test cancel"))
        assert await asyncio.to_thread(cancellation_seen.wait, 5)
        await asyncio.sleep(0.05)
        returned_before_worker_finished = cancel_task.done()
        release.set()
        await asyncio.wait_for(cancel_task, 10)
        assert await asyncio.to_thread(finished.wait, 5)
        await asyncio.gather(worker_task, return_exceptions=True)

        async with sessions() as session:
            evidence = await session.get(RawEvidence, capture["id"])
            target = await session.get(Target, "target-cancel")
            assert returned_before_worker_finished is False
            assert evidence is not None
            assert evidence.capture_status == "complete"
            assert target.status == "queued"
        assert not Path(capture["directory"]).exists()
        await engine.dispose()

    _run(scenario())


def test_worker_cancel_interrupts_coroutine_waiting_for_semaphore_slot(
    tmp_path,
    monkeypatch,
) -> None:
    from app import orchestrator

    class BlockedWorkerSlot:
        def __init__(self):
            self.entered = asyncio.Event()
            self.release_gate = asyncio.Event()

        async def acquire(self):
            self.entered.set()
            await self.release_gate.wait()

        def release(self):
            self.release_gate.set()

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'worker-slot.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-slot", name="Slot", status="running"))
            session.add(Target(
                id="target-slot",
                task_id="task-slot",
                url="https://slot.example.edu.cn",
                host="slot.example.edu.cn",
                source="manual",
                status="assigned",
                assigned_worker="worker-slot",
            ))
            await session.commit()

        slot = BlockedWorkerSlot()
        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        monkeypatch.setattr(orchestrator, "agent_semaphore", lambda _kind: slot)
        monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())

        async def no_history(*_args, **_kwargs):
            return []

        runner = orchestrator.TaskRunner("task-slot")
        monkeypatch.setattr(runner, "_build_duplicate_history", no_history)
        cancel_event = threading.Event()
        worker_task = asyncio.create_task(
            runner._run_worker(
                "task-slot",
                "target-slot",
                "https://slot.example.edu.cn",
                cancel_event,
            )
        )
        runner._active_workers["target-slot"] = worker_task
        runner._worker_cancel_events["target-slot"] = cancel_event
        await asyncio.wait_for(slot.entered.wait(), 5)

        cancel_task = asyncio.create_task(runner._cancel_active_workers("stop queued worker"))
        assert await asyncio.to_thread(cancel_event.wait, 5)
        for _ in range(20):
            if worker_task.done():
                break
            await asyncio.sleep(0.01)
        cancelled_by_runner = worker_task.cancelled()

        if not worker_task.done():
            worker_task.cancel()
        await asyncio.wait_for(cancel_task, 5)
        slot.release()

        async with sessions() as session:
            target = await session.get(Target, "target-slot")
            assert cancelled_by_runner is True
            assert target.status == "queued"
            assert target.assigned_worker == ""
        await engine.dispose()

    _run(scenario())


def test_stop_waits_when_worker_is_draining_private_persistence(
    tmp_path,
    monkeypatch,
) -> None:
    from app import orchestrator

    class ImmediateWorkerSlot:
        async def acquire(self):
            return None

        def release(self):
            return None

    worker_returned = threading.Event()

    class FakeExecutor:
        def cancel_running(self):
            return None

        def kill_processes(self):
            return None

    class FakeWorker:
        def __init__(self, *_args, on_event, **_kwargs):
            self.on_event = on_event
            self.executor = FakeExecutor()

        def run(self):
            self.on_event("tool_capture_private", {
                "tool": "http_request",
                "args": {"url": "https://tail.example.edu.cn", "method": "GET"},
                "result": {"ok": True, "status_code": 200},
                "preview": {"ok": True, "status_code": 200},
            })
            worker_returned.set()
            return SimpleNamespace(model_dump=lambda mode="json": {
                "verdict": "no_vuln",
                "findings": [],
                "summary": "worker returned before evidence persistence",
            })

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'worker-tail.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-tail", name="Tail", status="running"))
            session.add(Target(
                id="target-tail",
                task_id="task-tail",
                url="https://tail.example.edu.cn",
                host="tail.example.edu.cn",
                source="manual",
                status="assigned",
                assigned_worker="worker-tail",
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        monkeypatch.setattr(orchestrator, "Worker", FakeWorker)
        monkeypatch.setattr(orchestrator, "agent_semaphore", lambda _kind: ImmediateWorkerSlot())
        monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
        runner = orchestrator.TaskRunner("task-tail")
        persist_entered = asyncio.Event()
        persist_release = asyncio.Event()
        persisted: list[str] = []

        async def delayed_private_persistence(*_args, **_kwargs):
            persist_entered.set()
            await persist_release.wait()
            persisted.append("saved")

        monkeypatch.setattr(runner, "_persist_worker_tool_event", delayed_private_persistence)
        cancel_event = threading.Event()
        worker_task = asyncio.create_task(
            runner._run_worker(
                "task-tail",
                "target-tail",
                "https://tail.example.edu.cn",
                cancel_event,
            )
        )
        runner._active_workers["target-tail"] = worker_task
        runner._worker_cancel_events["target-tail"] = cancel_event
        assert await asyncio.to_thread(worker_returned.wait, 5)
        await asyncio.wait_for(persist_entered.wait(), 5)
        await asyncio.sleep(0.05)

        stop_task = asyncio.create_task(runner.stop("stop during evidence drain"))
        await asyncio.sleep(0.15)
        stop_returned_before_persistence = stop_task.done()
        persist_release.set()
        await asyncio.wait_for(stop_task, 5)
        await asyncio.gather(worker_task, return_exceptions=True)

        assert stop_returned_before_persistence is False
        assert persisted == ["saved"]
        await engine.dispose()

    _run(scenario())


def test_later_worker_dispatch_reads_updated_task_hunt_direction(
    tmp_path,
    monkeypatch,
) -> None:
    from app import orchestrator

    captured_directions: list[str] = []

    class ImmediateWorkerSlot:
        async def acquire(self):
            return None

        def release(self):
            return None

    class FakeExecutor:
        def kill_processes(self):
            return None

    class FakeWorker:
        def __init__(self, *_args, hunt_direction, **_kwargs):
            captured_directions.append(hunt_direction)
            self.executor = FakeExecutor()

        def run(self):
            return SimpleNamespace(model_dump=lambda mode="json": {
                "verdict": "no_vuln",
                "findings": [],
                "summary": "captured task direction",
            })

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'direction-worker.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(
                id="task-direction",
                name="Direction",
                status="running",
                hunt_direction="第一轮方向",
            ))
            session.add_all([
                Target(
                    id="target-direction-1",
                    task_id="task-direction",
                    url="https://one.example.test",
                    host="one.example.test",
                    source="manual",
                    status="assigned",
                ),
                Target(
                    id="target-direction-2",
                    task_id="task-direction",
                    url="https://two.example.test",
                    host="two.example.test",
                    source="manual",
                    status="assigned",
                ),
            ])
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        monkeypatch.setattr(orchestrator, "Worker", FakeWorker)
        monkeypatch.setattr(orchestrator, "agent_semaphore", lambda _kind: ImmediateWorkerSlot())
        monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
        runner = orchestrator.TaskRunner("task-direction")

        async def no_heartbeat(_target_id):
            await asyncio.sleep(3600)

        async def no_persist(*_args, **_kwargs):
            return None

        monkeypatch.setattr(runner, "_heartbeat_target", no_heartbeat)
        monkeypatch.setattr(runner, "_persist_worker_result", no_persist)

        await runner._run_worker(
            "task-direction",
            "target-direction-1",
            "https://one.example.test",
            threading.Event(),
        )
        async with sessions() as session:
            task = await session.get(Task, "task-direction")
            task.hunt_direction = "第二轮更新方向"
            await session.commit()
        await runner._run_worker(
            "task-direction",
            "target-direction-2",
            "https://two.example.test",
            threading.Event(),
        )

        assert captured_directions == ["第一轮方向", "第二轮更新方向"]
        await engine.dispose()

    _run(scenario())


def test_stop_waits_for_worker_that_outlives_its_timeout_cleanup_window(
    tmp_path,
    monkeypatch,
) -> None:
    from app import orchestrator
    from app.config import worker_config

    monkeypatch.setattr(worker_config, "work_root", str(tmp_path))
    monkeypatch.setattr(orchestrator, "WORKER_IDLE_TIMEOUT", 0.01)
    monkeypatch.setattr(orchestrator, "WORKER_MAX_WALL_TIMEOUT", 60.0)
    monkeypatch.setattr(orchestrator, "WORKER_WAIT_POLL_INTERVAL", 0.01)
    monkeypatch.setattr(orchestrator, "WORKER_CLEANUP_TIMEOUT", 0.01)
    capture = _capture(tmp_path, "capture-after-worker-timeout")
    started = threading.Event()
    cancellation_seen = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class FakeExecutor:
        def cancel_running(self):
            cancellation_seen.set()

        def kill_processes(self):
            return None

    class FakeWorker:
        def __init__(self, *_args, on_event, cancel_event, **_kwargs):
            self.on_event = on_event
            self.cancel_event = cancel_event
            self.executor = FakeExecutor()

        def run(self):
            started.set()
            assert self.cancel_event.wait(5)
            assert release.wait(5)
            preview = {
                "ok": True,
                "status_code": 200,
                "url": "https://example.edu.cn/api/login",
                "response_headers": {"content-type": "application/json"},
                "body": '{"access_token":"post-timeout-token-12345"}',
            }
            self.on_event("tool_capture_private", {
                "tool": "http_request",
                "args": {"url": preview["url"], "method": "POST"},
                "result": preview,
                "preview": preview,
                "capture": capture,
            })
            finished.set()
            return SimpleNamespace(model_dump=lambda mode="json": {
                "verdict": "no_vuln",
                "findings": [],
                "summary": "thread returned after timeout",
            })

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'timeout-worker.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-timeout", name="Timeout", status="running"))
            session.add(Target(
                id="target-timeout",
                task_id="task-timeout",
                url="https://example.edu.cn",
                host="example.edu.cn",
                source="manual",
                status="scanning",
                assigned_worker="worker-timeout",
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        monkeypatch.setattr(orchestrator, "Worker", FakeWorker)
        monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
        runner = orchestrator.TaskRunner("task-timeout")
        cancel_event = threading.Event()
        worker_task = asyncio.create_task(
            runner._run_worker(
                "task-timeout",
                "target-timeout",
                "https://example.edu.cn",
                cancel_event,
            )
        )
        runner._active_workers["target-timeout"] = worker_task
        runner._worker_cancel_events["target-timeout"] = cancel_event
        assert await asyncio.to_thread(started.wait, 5)
        assert await asyncio.to_thread(cancellation_seen.wait, 5)

        # The legacy path abandons the executor future after this short window,
        # so reap removes the only handle that stop/delete could wait on.
        await asyncio.sleep(0.15)
        runner._reap_workers()
        stop_task = asyncio.create_task(runner.stop("delete task"))
        await asyncio.sleep(0.05)
        stop_returned_before_thread = stop_task.done()

        # Model deletion beginning immediately after stop.  If stop returned too
        # early, the late capture has no owning target and its spool is orphaned.
        if stop_returned_before_thread:
            async with sessions() as session:
                target = await session.get(Target, "target-timeout")
                await session.delete(target)
                await session.commit()

        release.set()
        await asyncio.wait_for(stop_task, 5)
        assert await asyncio.to_thread(finished.wait, 5)
        await asyncio.gather(worker_task, return_exceptions=True)
        await asyncio.sleep(0.1)

        async with sessions() as session:
            evidence = await session.get(RawEvidence, capture["id"])
            assert evidence is not None
            assert evidence.capture_status == "complete"
        assert stop_returned_before_thread is False
        assert not Path(capture["directory"]).exists()
        await engine.dispose()

    _run(scenario())


def test_stop_racing_tick_does_not_spawn_worker_after_cancel_snapshot(
    tmp_path,
    monkeypatch,
) -> None:
    from app import orchestrator

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'tick-stop-race.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(
                id="task-tick-stop",
                name="Tick Stop",
                status="running",
                concurrency=2,
            ))
            session.add_all([
                Target(
                    id="target-existing",
                    task_id="task-tick-stop",
                    url="https://existing.example.edu.cn",
                    host="existing.example.edu.cn",
                    source="manual",
                    status="scanning",
                    assigned_worker="worker-existing",
                ),
                Target(
                    id="target-next",
                    task_id="task-tick-stop",
                    url="https://next.example.edu.cn",
                    host="next.example.edu.cn",
                    source="manual",
                    status="queued",
                ),
            ])
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)

        async def no_refill(*_args, **_kwargs):
            return 0

        monkeypatch.setattr(orchestrator.collector, "refill", no_refill)
        runner = orchestrator.TaskRunner("task-tick-stop")
        existing_release = asyncio.Event()
        existing_task = asyncio.create_task(existing_release.wait())
        existing_cancel = threading.Event()
        runner._active_workers["target-existing"] = existing_task
        runner._worker_cancel_events["target-existing"] = existing_cancel

        pop_entered = asyncio.Event()
        pop_release = asyncio.Event()

        async def delayed_pop(session):
            pop_entered.set()
            await pop_release.wait()
            target = await session.get(Target, "target-next")
            target.status = "assigned"
            target.assigned_worker = "worker-next"
            await session.commit()
            return target

        monkeypatch.setattr(runner, "_pop_queued", delayed_pop)

        async def no_dispatch(*_args, **_kwargs):
            return None

        async def zero_count(*_args, **_kwargs):
            return 0

        monkeypatch.setattr(runner, "_dispatch_reviews", no_dispatch)
        monkeypatch.setattr(runner, "_dispatch_killsweep_attempts", no_dispatch)
        monkeypatch.setattr(runner, "_count", zero_count)
        monkeypatch.setattr(runner, "_count_inflight", zero_count)

        spawned: list[str] = []
        spawned_release = asyncio.Event()
        spawned_tasks: list[asyncio.Task] = []

        def fake_spawn(_task, target):
            spawned.append(target.id)
            spawned_task = asyncio.create_task(spawned_release.wait())
            spawned_tasks.append(spawned_task)
            runner._active_workers[target.id] = spawned_task

        monkeypatch.setattr(runner, "_spawn_worker", fake_spawn)

        tick_task = asyncio.create_task(runner._tick())
        await pop_entered.wait()
        stop_task = asyncio.create_task(runner.stop("stop during tick"))
        assert await asyncio.to_thread(existing_cancel.wait, 5)

        # stop has already snapshotted target-existing and is waiting for it;
        # let the in-flight queue pop return during that window.
        pop_release.set()
        await asyncio.wait_for(tick_task, 5)
        existing_release.set()
        await asyncio.wait_for(stop_task, 5)

        async with sessions() as session:
            next_target = await session.get(Target, "target-next")
            assert spawned == []
            assert next_target.status == "queued"
            assert next_target.assigned_worker == ""
        assert runner._active_workers == {}

        spawned_release.set()
        if spawned_tasks:
            await asyncio.gather(*spawned_tasks)
        await engine.dispose()

    _run(scenario())


def test_stop_during_review_query_prevents_late_review_task() -> None:
    from app import orchestrator

    async def scenario():
        runner = orchestrator.TaskRunner("task-review-dispatch")
        query_entered = asyncio.Event()
        query_release = asyncio.Event()
        review_release = asyncio.Event()

        class DelayedResult:
            def scalars(self):
                return self

            def all(self):
                return [SimpleNamespace(id="finding-late")]

        class DelayedSession:
            async def execute(self, _query):
                query_entered.set()
                await query_release.wait()
                return DelayedResult()

        async def fake_review(*_args):
            await review_release.wait()

        runner._run_review = fake_review
        dispatch_task = asyncio.create_task(
            runner._dispatch_reviews(
                DelayedSession(),
                SimpleNamespace(id="task-review-dispatch"),
            )
        )
        await query_entered.wait()
        await runner.stop("stop during review query")
        query_release.set()
        await dispatch_task
        await asyncio.sleep(0)

        late_tasks = list(runner._review_tasks.values())
        for task in late_tasks:
            task.cancel()
        if late_tasks:
            await asyncio.gather(*late_tasks, return_exceptions=True)
        review_release.set()

        assert runner._review_inflight == set()
        assert runner._review_tasks == {}

    _run(scenario())


def test_stop_during_killsweep_query_prevents_late_killsweep_task() -> None:
    from app import orchestrator

    async def scenario():
        runner = orchestrator.TaskRunner("task-killsweep-dispatch")
        query_entered = asyncio.Event()
        query_release = asyncio.Event()
        killsweep_release = asyncio.Event()

        class DelayedScalars:
            def all(self):
                return [SimpleNamespace(id="attempt-late")]

        class DelayedSession:
            async def scalars(self, _query):
                query_entered.set()
                await query_release.wait()
                return DelayedScalars()

        async def fake_killsweep(*_args):
            await killsweep_release.wait()

        runner._run_killsweep = fake_killsweep
        dispatch_task = asyncio.create_task(
            runner._dispatch_killsweep_attempts(
                DelayedSession(),
                SimpleNamespace(id="task-killsweep-dispatch"),
            )
        )
        await query_entered.wait()
        await runner.stop("stop during killsweep query")
        query_release.set()
        await dispatch_task
        await asyncio.sleep(0)

        late_tasks = list(runner._killsweep_tasks.values())
        for task in late_tasks:
            task.cancel()
        if late_tasks:
            await asyncio.gather(*late_tasks, return_exceptions=True)
        killsweep_release.set()

        assert runner._killsweep_inflight == set()
        assert runner._killsweep_tasks == {}

    _run(scenario())


def test_tick_rechecks_stop_between_review_and_killsweep_dispatch(
    tmp_path,
    monkeypatch,
) -> None:
    from app import orchestrator

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'dispatch-stage-stop.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(
                id="task-dispatch-stage",
                name="Dispatch Stage",
                status="running",
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)

        async def no_refill(*_args, **_kwargs):
            return 0

        monkeypatch.setattr(orchestrator.collector, "refill", no_refill)
        runner = orchestrator.TaskRunner("task-dispatch-stage")

        async def no_reclaim(*_args, **_kwargs):
            return None

        async def no_target(*_args, **_kwargs):
            return None

        review_entered = asyncio.Event()
        review_release = asyncio.Event()

        async def delayed_reviews(*_args, **_kwargs):
            review_entered.set()
            await review_release.wait()

        killsweep_calls: list[str] = []

        async def record_killsweep(*_args, **_kwargs):
            killsweep_calls.append("called")

        monkeypatch.setattr(runner, "_reclaim_stale", no_reclaim)
        monkeypatch.setattr(runner, "_pop_queued", no_target)
        monkeypatch.setattr(runner, "_dispatch_reviews", delayed_reviews)
        monkeypatch.setattr(runner, "_dispatch_killsweep_attempts", record_killsweep)

        tick_task = asyncio.create_task(runner._tick())
        await review_entered.wait()
        await runner.stop("stop between dispatch stages")
        review_release.set()
        await tick_task

        assert killsweep_calls == []
        await engine.dispose()

    _run(scenario())


def test_stop_waits_for_review_and_escalation_cancellation_tails() -> None:
    from app import orchestrator

    async def scenario():
        runner = orchestrator.TaskRunner("task-agent-tails")
        review_started = asyncio.Event()
        escalation_started = asyncio.Event()
        review_tail = asyncio.Event()
        escalation_tail = asyncio.Event()
        review_release = asyncio.Event()
        escalation_release = asyncio.Event()
        completed: list[str] = []

        async def cancellable_agent(
            name: str,
            started: asyncio.Event,
            tail: asyncio.Event,
            release: asyncio.Event,
        ):
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                tail.set()
                await release.wait()
                completed.append(name)

        review_task = asyncio.create_task(
            cancellable_agent("review", review_started, review_tail, review_release)
        )
        escalation_task = asyncio.create_task(
            cancellable_agent(
                "escalation",
                escalation_started,
                escalation_tail,
                escalation_release,
            )
        )
        runner._review_inflight.add("finding-review")
        runner._review_tasks["finding-review"] = review_task
        runner._escalation_inflight.add("finding-escalation")
        runner._escalation_tasks["finding-escalation"] = escalation_task
        await review_started.wait()
        await escalation_started.wait()

        stop_task = asyncio.create_task(runner.stop("stop agent tails"))
        await review_tail.wait()
        await asyncio.sleep(0.05)
        stop_returned_before_review_tail = stop_task.done()
        review_release.set()
        await escalation_tail.wait()
        await asyncio.sleep(0.05)
        stop_returned_before_escalation_tail = stop_task.done()
        escalation_release.set()
        await asyncio.wait_for(stop_task, 5)

        assert stop_returned_before_review_tail is False
        assert stop_returned_before_escalation_tail is False
        assert sorted(completed) == ["escalation", "review"]
        assert runner._review_tasks == {}
        assert runner._review_inflight == set()
        assert runner._escalation_tasks == {}
        assert runner._escalation_inflight == set()

    _run(scenario())


def test_manager_stop_blocks_new_killsweep_dispatch_until_restart(monkeypatch) -> None:
    from app import orchestrator

    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()
        created: list[tuple[str, str]] = []

        class FakeRunner:
            def __init__(self, task_id: str):
                self.task_id = task_id

            async def stop(self):
                entered.set()
                await release.wait()

            def dispatch_killsweep_attempt(self, task_id: str, attempt_id: str) -> bool:
                created.append((task_id, attempt_id))
                return True

        monkeypatch.setattr(orchestrator, "TaskRunner", FakeRunner)
        manager = orchestrator.OrchestratorManager()
        existing = FakeRunner("task-stop-race")
        manager._runners["task-stop-race"] = existing

        stopping = asyncio.create_task(manager.stop("task-stop-race"))
        await entered.wait()

        assert await manager.dispatch_killsweep_attempt(
            "task-stop-race", "attempt-during-stop"
        ) is False
        assert created == []
        assert manager._runners.get("task-stop-race") is existing

        release.set()
        await stopping
        assert await manager.dispatch_killsweep_attempt(
            "task-stop-race", "attempt-after-stop"
        ) is False
        assert created == []

    _run(scenario())


def test_manager_immediate_restart_replaces_a_stopped_live_runner(monkeypatch) -> None:
    from app import orchestrator

    async def scenario():
        instances = []

        class FakeRunner:
            def __init__(self, task_id: str):
                self.task_id = task_id
                self._stop = asyncio.Event()
                self._auto_drained = True
                self.started = asyncio.Event()
                self.cancelled = asyncio.Event()
                self.release = asyncio.Event()
                self.resume_calls = 0
                self.stop_calls = 0
                self.cleanup_complete = asyncio.Event()
                self.cancelled_after_cleanup = False
                instances.append(self)

            def resume(self):
                self.resume_calls += 1

            async def stop(self):
                self.stop_calls += 1
                self.cleanup_complete.set()

            async def run_forever(self):
                self.started.set()
                try:
                    await self.release.wait()
                except asyncio.CancelledError:
                    self.cancelled_after_cleanup = self.cleanup_complete.is_set()
                    self.cancelled.set()
                    raise

        monkeypatch.setattr(orchestrator, "TaskRunner", FakeRunner)
        manager = orchestrator.OrchestratorManager()
        old_runner = FakeRunner("task-immediate-restart")
        old_runner._stop.set()
        old_task = asyncio.create_task(old_runner.run_forever())
        manager._runners["task-immediate-restart"] = old_runner
        manager._tasks["task-immediate-restart"] = old_task
        await old_runner.started.wait()

        try:
            await manager.ensure_running("task-immediate-restart")

            new_runner = manager._runners["task-immediate-restart"]
            new_task = manager._tasks["task-immediate-restart"]
            await new_runner.started.wait()
            assert len(instances) == 2
            assert new_runner is not old_runner
            assert new_task is not old_task
            assert old_runner.cancelled.is_set()
            assert old_task.cancelled()
            assert old_runner.resume_calls == 0
            assert old_runner.stop_calls == 1
            assert old_runner.cancelled_after_cleanup is True
            assert new_runner.resume_calls == 1
            assert not new_task.done()
        finally:
            for runner in instances:
                runner.release.set()
            tasks = set(manager._tasks.values()) | {old_task}
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    _run(scenario())


def test_manager_discards_auto_drained_runner_when_run_forever_finishes(monkeypatch) -> None:
    from app import orchestrator

    async def scenario():
        class FakeRunner:
            def __init__(self, task_id: str):
                self.task_id = task_id
                self._stop = asyncio.Event()
                self._auto_drained = False
                self.release = asyncio.Event()

            def resume(self):
                return None

            async def run_forever(self):
                await self.release.wait()

        monkeypatch.setattr(orchestrator, "TaskRunner", FakeRunner)
        manager = orchestrator.OrchestratorManager()
        await manager.ensure_running("task-finished-runner")
        runner = manager._runners["task-finished-runner"]
        run_task = manager._tasks["task-finished-runner"]

        runner._auto_drained = True
        runner.release.set()
        await run_task
        await asyncio.sleep(0)

        assert "task-finished-runner" not in manager._tasks
        assert "task-finished-runner" not in manager._runners

        await manager.ensure_running("task-finished-runner")
        replacement_runner = manager._runners["task-finished-runner"]
        replacement_task = manager._tasks["task-finished-runner"]

        manager._runner_task_done("task-finished-runner", runner, run_task)

        assert manager._runners["task-finished-runner"] is replacement_runner
        assert manager._tasks["task-finished-runner"] is replacement_task

        replacement_runner.release.set()
        await replacement_task
        await asyncio.sleep(0)

        assert manager._runners["task-finished-runner"] is replacement_runner
        assert manager._tasks["task-finished-runner"] is replacement_task

    _run(scenario())


def test_manager_keeps_existing_semantics_for_non_drain_stopped_runner(monkeypatch) -> None:
    from app import orchestrator

    async def scenario():
        release = asyncio.Event()
        instances = []

        class FakeRunner:
            def __init__(self, task_id: str):
                self.task_id = task_id
                self._stop = asyncio.Event()
                self._stop.set()
                self._auto_drained = False
                self.resume_calls = 0
                self.stop_calls = 0
                instances.append(self)

            def resume(self):
                self.resume_calls += 1

            async def stop(self):
                self.stop_calls += 1

            async def run_forever(self):
                await release.wait()

        monkeypatch.setattr(orchestrator, "TaskRunner", FakeRunner)
        manager = orchestrator.OrchestratorManager()
        runner = FakeRunner("task-non-drain-stop")
        run_task = asyncio.create_task(release.wait())
        manager._runners["task-non-drain-stop"] = runner
        manager._tasks["task-non-drain-stop"] = run_task

        try:
            await manager.ensure_running("task-non-drain-stop")

            assert manager._runners["task-non-drain-stop"] is runner
            assert manager._tasks["task-non-drain-stop"] is run_task
            assert len(instances) == 1
            assert runner.resume_calls == 1
            assert runner.stop_calls == 0
            assert not run_task.done()
        finally:
            release.set()
            tasks = set(manager._tasks.values()) | {run_task}
            await asyncio.gather(*tasks, return_exceptions=True)

    _run(scenario())


def test_task_runner_persists_one_capture_without_losing_overlapping_candidates(
    tmp_path,
    monkeypatch,
) -> None:
    from app import orchestrator
    from app.config import worker_config

    monkeypatch.setattr(worker_config, "work_root", str(tmp_path))

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'runtime.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-runtime", name="Runtime", status="paused"))
            session.add(
                Target(
                    id="target-runtime",
                    task_id="task-runtime",
                    url="https://example.edu.cn",
                    host="example.edu.cn",
                    status="done",
                )
            )
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-runtime")
        capture = _capture(tmp_path)
        preview = {
            "ok": True,
            "status_code": 200,
            "url": "https://example.edu.cn/api/login",
            "response_headers": {"content-type": "application/json"},
            "body": '{"success":true,"access_token":"live-token-value-12345"}',
        }
        await runner._persist_worker_tool_event(
            "task-runtime",
            "target-runtime",
            {
                "tool": "http_request",
                "args": {"url": "https://example.edu.cn/api/login", "method": "POST"},
                "result": preview,
                "preview": preview,
                "capture": capture,
            },
        )

        async with sessions() as session:
            signals = list(await session.scalars(select(MissedSignal).order_by(MissedSignal.rule_key)))
            evidence = list(await session.scalars(select(RawEvidence)))
            chunks = await session.scalar(select(func.count()).select_from(RawEvidenceChunk))
            task_events = await session.scalar(select(func.count()).select_from(TaskEvent))
            assert {item.rule_key for item in signals} == {"login_success", "token_exposure"}
            assert len(evidence) == 1
            assert all(item.evidence_count == 1 for item in signals)
            assert chunks == 2
            assert task_events == 0
            assert "live-token-value" not in repr(
                [item.payload for item in await session.scalars(select(MissedSignalEvent))]
            )
        await engine.dispose()

    _run(scenario())


def test_signal_deepening_finishes_without_reusing_legacy_target_cap(tmp_path, monkeypatch) -> None:
    from app import orchestrator

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'finish.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-finish", name="Finish", status="paused"))
            target = Target(
                id="target-finish",
                task_id="task-finish",
                url="https://example.edu.cn",
                host="example.edu.cn",
                status="queued",
                deepen_count=2,
                deepen_context={
                    "missed_signal_id": "signal-finish",
                    "directive": "验证导出权限",
                },
            )
            session.add(target)
            signal = await upsert_signal(
                session,
                task_id="task-finish",
                target_id="target-finish",
                candidate=SignalCandidate(
                    rule_key="deepen_lead",
                    rule_label="深挖线索",
                    method="GET",
                    endpoint_key="GET https://example.edu.cn/export",
                    title="导出权限",
                    summary="待验证",
                    risk_level="high",
                    risk_score=8,
                    source_type="deepen_lead",
                ),
            )
            signal.status = "deepening"
            target.deepen_context = {
                **(target.deepen_context or {}),
                "missed_signal_id": signal.id,
            }
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-finish")
        await runner._finish_missed_signal_deepening(
            "task-finish", "target-finish", "worker completed without conversion"
        )

        async with sessions() as session:
            signal = await session.get(MissedSignal, signal.id)
            target = await session.get(Target, "target-finish")
            assert signal.status == "pending"
            assert signal.deepen_error == "worker completed without conversion"
            assert target.deepen_count == 2
            assert target.deepen_context is None
        await engine.dispose()

    _run(scenario())


def test_signal_deepening_queued_during_scan_survives_old_worker_finish(
    tmp_path, monkeypatch,
) -> None:
    from app import orchestrator

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'deepen-race.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-race", name="Race", status="paused"))
            target = Target(
                id="target-race",
                task_id="task-race",
                url="https://example.edu.cn",
                host="example.edu.cn",
                source="manual",
                status="scanning",
                assigned_worker="w-old",
            )
            session.add(target)
            signal = await upsert_signal(
                session,
                task_id="task-race",
                target_id="target-race",
                candidate=SignalCandidate(
                    rule_key="sensitive_endpoint",
                    rule_label="敏感接口",
                    method="GET",
                    endpoint_key="GET https://example.edu.cn/actuator/env",
                    title="待深挖配置接口",
                    summary="继续验证真实配置值",
                    risk_level="high",
                    risk_score=8,
                    source_type="tool",
                ),
            )
            await session.commit()

            signal_id = signal.id
        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-race")
        entered = asyncio.Event()
        release = asyncio.Event()

        async def hold_harvest(*_args, **_kwargs):
            entered.set()
            await release.wait()

        monkeypatch.setattr(runner, "_harvest_intel", hold_harvest)
        worker_task = asyncio.create_task(
            runner._persist_worker_result(
                "task-race",
                "target-race",
                {
                    "verdict": "no_vuln",
                    "findings": [],
                    "summary": "旧 worker 正常收尾",
                    "_runtime": {
                        "missed_signal_id": "",
                        "deepen_attempt_token": "",
                    },
                },
            )
        )
        await entered.wait()

        # Commit the manual request from a second session while the old worker
        # still holds its initial Target read snapshot.
        async with sessions() as session:
            await queue_signal_deepening(
                session,
                signal_id,
                directive="验证 propertySources 中的真实密钥",
            )
            await session.commit()
            target = await session.get(Target, "target-race")
            assert target.status == "scanning"
            assert target.assigned_worker == "w-old"
            assert target.deepen_context["missed_signal_id"] == signal_id
            assert target.deepen_context["attempt_token"]

        release.set()
        await worker_task

        async with sessions() as session:
            target = await session.get(Target, "target-race")
            signal = await session.get(MissedSignal, signal_id)
            assert target.status == "queued"
            assert target.verdict == ""
            assert target.assigned_worker == ""
            assert target.deepen_context["missed_signal_id"] == signal.id
            assert signal.status == "deepening"
            assert signal.deepen_phase == "queued"

        await engine.dispose()

    _run(scenario())


def test_recover_requeues_terminal_target_with_pending_signal_deepening(
    tmp_path, monkeypatch,
) -> None:
    from app import orchestrator

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'deepen-recover.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-recover", name="Recover", status="running"))
            session.add(Target(
                id="target-recover",
                task_id="task-recover",
                url="https://recover.example.edu.cn",
                host="recover.example.edu.cn",
                source="manual",
                status="dead",
                verdict="no_vuln",
                dead_reason="旧 worker 已提交终态",
            ))
            signal = MissedSignal(
                id="signal-recover",
                task_id="task-recover",
                target_id="target-recover",
                dedup_key="recover-dedup",
                rule_key="sensitive_endpoint",
                endpoint_key="GET https://recover.example.edu.cn/actuator/env",
                title="待恢复深挖",
                summary="进程在 reconcile 前退出",
                risk_level="high",
                risk_score=8,
                status="deepening",
                deepen_phase="queued",
                deepen_directive="验证 propertySources 中的真实密钥",
                deepen_count=1,
            )
            session.add(signal)
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-recover")
        async with sessions() as session:
            await runner.recover(session)

        async with sessions() as session:
            target = await session.get(Target, "target-recover")
            signal = await session.get(MissedSignal, "signal-recover")
            assert target.status == "queued"
            assert target.verdict == ""
            assert target.dead_reason == ""
            assert target.deepen_context["missed_signal_id"] == signal.id
            assert target.deepen_context["attempt_token"]
            assert signal.status == "deepening"
            assert signal.deepen_phase == "queued"

        await engine.dispose()

    _run(scenario())
