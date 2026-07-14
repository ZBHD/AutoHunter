from __future__ import annotations

import asyncio
import hashlib
import sys
import threading
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.tools import executor as executor_module
from app.tools.executor import ToolExecutor


EXPECTED_CHUNK_SIZE = 1024 * 1024


@pytest.fixture(autouse=True)
def _trusted_capture_root(tmp_path, monkeypatch) -> None:
    root = tmp_path / "trusted-capture-root"
    root.mkdir()
    monkeypatch.setattr(executor_module.worker_config, "work_root", str(root))


def _write_output_script(path: Path, payload: bytes, *, sleep: float = 0) -> Path:
    script = path / f"emit_{uuid.uuid4().hex}.py"
    script.write_text(
        "import sys, time\n"
        f"time.sleep({sleep!r})\n"
        f"sys.stdout.buffer.write(bytes.fromhex({payload.hex()!r}))\n",
        encoding="ascii",
    )
    return script


def _shell_command(script: Path) -> str:
    return f'"{sys.executable}" "{script}"'


def _capture_channel(capture: dict, channel: str) -> bytes:
    item = next(item for item in capture["channels"] if item["name"] == channel)
    return Path(item["path"]).read_bytes()


def test_shell_full_capture_survives_preview_limit_and_preserves_non_utf8(
    tmp_path, monkeypatch
) -> None:
    payload = (bytes(range(256)) + b"full-shell-output") * 32
    script = _write_output_script(tmp_path, payload)
    monkeypatch.setattr(executor_module, "_SHELL_CAPTURE_MAX_BYTES", 32)

    result = ToolExecutor(
        "capture", work_dir=str(tmp_path), capture_full=True
    ).run_shell(_shell_command(script))

    assert result["ok"] is True
    capture = result["_capture"]
    assert capture["status"] == "complete"
    assert _capture_channel(capture, "output") == payload
    assert len(result["output"].encode("utf-8")) < len(payload)
    output_meta = next(item for item in capture["channels"] if item["name"] == "output")
    assert output_meta["size"] == len(payload)
    assert output_meta["sha256"] == hashlib.sha256(payload).hexdigest()
    assert _capture_channel(capture, "command") == _shell_command(script).encode("utf-8")


def test_shell_cancelled_capture_is_marked_partial(tmp_path) -> None:
    script = _write_output_script(tmp_path, b"too-late", sleep=5)
    cancelled = threading.Event()
    cancelled.set()

    result = ToolExecutor(
        "cancelled",
        work_dir=str(tmp_path),
        capture_full=True,
        cancel_event=cancelled,
    ).run_shell(_shell_command(script), timeout=10)

    assert result["cancelled"] is True
    assert result["_capture"]["status"] == "partial"
    assert _capture_channel(result["_capture"], "command") == _shell_command(script).encode(
        "utf-8"
    )


class _ChunkedBytes(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks

    def __iter__(self):
        yield from self._chunks


def test_http_full_capture_drains_response_after_preview_limit(tmp_path, monkeypatch) -> None:
    body = bytes(range(256)) * 32
    real_client = httpx.Client
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"content-type": "application/octet-stream", "x-capture": "yes"},
            stream=_ChunkedBytes([body[:17], body[17:2049], body[2049:]]),
            request=request,
        )
    )

    def client_factory(**kwargs):
        return real_client(
            transport=transport,
            follow_redirects=kwargs.get("follow_redirects", False),
            timeout=kwargs.get("timeout", 20),
        )

    monkeypatch.setattr(executor_module.httpx, "Client", client_factory)
    monkeypatch.setattr(executor_module, "_HTTP_MAX_BYTES", 31)

    result = ToolExecutor(
        "http-capture", work_dir=str(tmp_path), capture_full=True
    ).http_request(
        "https://example.test/binary?token=original",
        method="POST",
        headers={"X-Test": "raw"},
        data="request-body",
    )

    assert result["ok"] is True
    assert result["body_truncated"] is True
    capture = result["_capture"]
    response_bytes = _capture_channel(capture, "response")
    response_headers, response_body = response_bytes.split(b"\r\n\r\n", 1)
    assert response_headers.startswith(b"HTTP/1.1 200")
    assert response_body == body
    request_bytes = _capture_channel(capture, "request")
    assert request_bytes.startswith(b"POST /binary?token=original HTTP/1.1\r\n")
    assert request_bytes.endswith(b"\r\n\r\nrequest-body")


def test_detach_capture_removes_private_descriptor_from_public_tool_result() -> None:
    from app.raw_evidence import detach_capture

    descriptor = {"id": uuid.uuid4().hex, "channels": []}
    result = {"ok": True, "body": "preview", "_capture": descriptor}

    detached = detach_capture(result)

    assert detached is descriptor
    assert result == {"ok": True, "body": "preview"}


def _spool_descriptor(tmp_path: Path, payload: bytes, *, status: str = "complete") -> dict:
    capture_id = uuid.uuid4().hex
    directory = Path(executor_module.worker_config.work_root) / "worker" / ".captures" / capture_id
    directory.mkdir(parents=True)
    spool = directory / "output.bin"
    spool.write_bytes(payload)
    return {
        "id": capture_id,
        "tool": "run_shell",
        "status": status,
        "error": "cancelled" if status == "partial" else "",
        "meta": {"return_code": -9 if status == "partial" else 0},
        "directory": str(directory),
        "channels": [
            {
                "name": "output",
                "path": str(spool),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
    }


def test_chunk_import_is_ordered_hashed_streamed_and_idempotent(tmp_path) -> None:
    from sqlalchemy import func, select

    from app.db.models import Base, RawEvidence, RawEvidenceChunk
    from app.raw_evidence import import_capture, stream_evidence_channel

    payload = b"first" * (EXPECTED_CHUNK_SIZE // 5) + b"tail-over-one-chunk"
    assert len(payload) > EXPECTED_CHUNK_SIZE
    capture = _spool_descriptor(tmp_path, payload)
    spool_path = Path(capture["channels"][0]["path"])

    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'evidence.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

            async with sessions() as session:
                first = await import_capture(
                    session,
                    capture,
                    task_id="task-1",
                    target_id="target-1",
                    source_kind="worker_tool",
                    preview="bounded preview",
                )
                assert first.id == capture["id"]
                assert first.capture_status == "complete"
                assert first.preview == {"text": "bounded preview"}
                assert first.content_hash == hashlib.sha256(payload).hexdigest()
                channel_meta = first.metadata_json["channels"]["output"]
                assert channel_meta == {
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "chunks": 2,
                }
                assert not spool_path.exists()

            async with sessions() as session:
                reconstructed = b"".join(
                    [part async for part in stream_evidence_channel(session, first.id, "output")]
                )
                assert reconstructed == payload

                second = await import_capture(
                    session,
                    capture,
                    task_id="task-1",
                    target_id="target-1",
                    source_kind="worker_tool",
                    preview="ignored on retry",
                )
                assert second.id == first.id
                evidence_count = await session.scalar(select(func.count(RawEvidence.id)))
                chunk_count = await session.scalar(select(func.count(RawEvidenceChunk.id)))
                assert evidence_count == 1
                assert chunk_count == 2
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_incomplete_capture_retry_rebuilds_chunks_from_changed_spool(tmp_path) -> None:
    from app.db.models import Base, RawEvidence, RawEvidenceChunk
    from app.raw_evidence import import_capture, stream_evidence_channel

    stale_payload = b"stale-before-interrupted-import"
    current_payload = b"current-retry-payload"
    capture = _spool_descriptor(tmp_path, current_payload)

    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                session.add(
                    RawEvidence(
                        id=capture["id"],
                        task_id="task-retry",
                        target_id="target-retry",
                        source_kind="worker_tool",
                        capture_status="failed",
                        metadata_json={"import_complete": False},
                        spool_directory=str(Path(capture["directory"]).resolve()),
                    )
                )
                session.add(
                    RawEvidenceChunk(
                        evidence_id=capture["id"],
                        channel="output",
                        seq=0,
                        data=stale_payload,
                    )
                )
                await session.commit()

                evidence = await import_capture(
                    session,
                    capture,
                    task_id="task-retry",
                    target_id="target-retry",
                    source_kind="worker_tool",
                )
                reconstructed = b"".join(
                    [
                        chunk
                        async for chunk in stream_evidence_channel(
                            session, capture["id"], "output"
                        )
                    ]
                )

                assert reconstructed == current_payload
                assert evidence.content_hash == hashlib.sha256(current_payload).hexdigest()
                assert evidence.metadata_json["channels"]["output"]["sha256"] == (
                    evidence.content_hash
                )
        finally:
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize("import_complete", [False, True], ids=["in-progress", "complete"])
@pytest.mark.parametrize(
    ("field", "changed_value"),
    [
        ("task_id", "task-other"),
        ("target_id", "target-other"),
        ("missed_signal_id", "signal-other"),
        ("killsweep_event_id", 22),
        ("source_kind", "killsweep_tool"),
    ],
)
def test_capture_replay_rejects_changed_ownership(
    tmp_path, import_complete, field, changed_value
) -> None:
    from app.db.models import Base, RawEvidence
    from app.raw_evidence import CaptureImportError, import_capture

    capture = _spool_descriptor(tmp_path, b"binding-sensitive-payload")
    stored_binding = {
        "task_id": "task-owner",
        "target_id": "target-owner",
        "missed_signal_id": "signal-owner",
        "killsweep_event_id": 11,
        "source_kind": "worker_tool",
    }
    replay_binding = dict(stored_binding)
    replay_binding[field] = changed_value

    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                session.add(
                    RawEvidence(
                        id=capture["id"],
                        **stored_binding,
                        capture_status="complete" if import_complete else "writing",
                        metadata_json={"import_complete": import_complete},
                    )
                )
                await session.commit()

                with pytest.raises(CaptureImportError, match=field):
                    await import_capture(session, capture, **replay_binding)
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_initial_evidence_registration_failure_removes_unowned_spool(
    tmp_path, monkeypatch,
) -> None:
    from sqlalchemy import func, select

    from app.db.models import Base, RawEvidence
    from app.raw_evidence import CaptureImportError, import_capture

    capture = _spool_descriptor(tmp_path, b"registration-failure-secret")
    directory = Path(capture["directory"])

    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'registration.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

            async with sessions() as session:
                async def fail_commit() -> None:
                    raise RuntimeError("database is locked")

                monkeypatch.setattr(session, "commit", fail_commit)
                with pytest.raises(CaptureImportError, match="register"):
                    await import_capture(
                        session,
                        capture,
                        task_id="task-registration",
                        source_kind="worker_tool",
                    )

            async with sessions() as session:
                count = await session.scalar(select(func.count()).select_from(RawEvidence))
                assert count == 0
            assert not directory.exists()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_partial_capture_import_keeps_available_bytes_and_status(tmp_path) -> None:
    from app.db.models import Base
    from app.raw_evidence import import_capture, stream_evidence_channel

    payload = b"partial-output\x00\xff"
    capture = _spool_descriptor(tmp_path, payload, status="partial")

    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                evidence = await import_capture(
                    session,
                    capture,
                    task_id="task-partial",
                    source_kind="worker_tool",
                )
                assert evidence.capture_status == "partial"
                assert evidence.metadata_json["capture_error"] == "cancelled"
            async with sessions() as session:
                assert b"".join(
                    [
                        chunk
                        async for chunk in stream_evidence_channel(
                            session, capture["id"], "output"
                        )
                    ]
                ) == payload
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_hash_mismatch_marks_failed_without_importing_corrupt_chunks(tmp_path) -> None:
    from sqlalchemy import func, select

    from app.db.models import Base, RawEvidence, RawEvidenceChunk
    from app.raw_evidence import CaptureImportError, import_capture

    capture = _spool_descriptor(tmp_path, b"original-evidence")
    spool_path = Path(capture["channels"][0]["path"])
    spool_path.write_bytes(b"tampered-evidence")

    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                with pytest.raises(CaptureImportError, match="sha256 mismatch"):
                    await import_capture(
                        session,
                        capture,
                        task_id="task-corrupt",
                        source_kind="worker_tool",
                    )
                evidence = await session.get(RawEvidence, capture["id"])
                assert evidence is not None
                assert evidence.capture_status == "failed"
                assert "sha256 mismatch" in evidence.metadata_json["import_error"]
                assert evidence.spool_directory == str(spool_path.parent.resolve())
                chunk_count = await session.scalar(select(func.count(RawEvidenceChunk.id)))
                assert chunk_count == 0
                assert spool_path.exists()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_missing_spool_file_keeps_safe_cleanup_ownership_on_import_error(tmp_path) -> None:
    from app.db.models import Base, RawEvidence
    from app.raw_evidence import CaptureImportError, import_capture

    capture = _spool_descriptor(tmp_path, b"vanished-evidence")
    spool_path = Path(capture["channels"][0]["path"])
    spool_path.unlink()

    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                with pytest.raises(CaptureImportError):
                    await import_capture(
                        session,
                        capture,
                        task_id="task-missing",
                        source_kind="worker_tool",
                    )
                evidence = await session.get(RawEvidence, capture["id"])
                assert evidence is not None
                assert evidence.capture_status == "failed"
                assert evidence.spool_directory == str(spool_path.parent.resolve())
                assert "FileNotFoundError" in evidence.metadata_json["import_error"]
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_import_rejects_capture_channel_outside_owned_spool_directory(tmp_path) -> None:
    from app.db.models import Base, RawEvidence
    from app.raw_evidence import CaptureImportError, import_capture

    capture_id = uuid.uuid4().hex
    directory = (
        Path(executor_module.worker_config.work_root) / "worker" / ".captures" / capture_id
    )
    directory.mkdir(parents=True)
    outside = tmp_path / "must-not-delete.bin"
    payload = b"unowned"
    outside.write_bytes(payload)
    capture = {
        "id": capture_id,
        "tool": "run_shell",
        "status": "complete",
        "error": "",
        "meta": {},
        "directory": str(directory),
        "channels": [{
            "name": "output",
            "path": str(outside),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }],
    }

    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                with pytest.raises(CaptureImportError, match="outside owned spool directory"):
                    await import_capture(
                        session,
                        capture,
                        task_id="task-boundary",
                        source_kind="worker_tool",
                    )
                evidence = await session.get(RawEvidence, capture_id)
                assert evidence is not None
                assert evidence.capture_status == "failed"
                assert evidence.spool_directory == str(directory.resolve())
                assert outside.read_bytes() == payload
                assert directory.exists()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_import_rejects_capture_directory_outside_worker_root(tmp_path) -> None:
    from app.db.models import Base, RawEvidence
    from app.raw_evidence import CaptureImportError, import_capture

    capture_id = uuid.uuid4().hex
    directory = tmp_path / "outside-root" / ".captures" / capture_id
    directory.mkdir(parents=True)
    spool = directory / "output.bin"
    payload = b"outside-worker-root"
    spool.write_bytes(payload)
    capture = {
        "id": capture_id,
        "tool": "run_shell",
        "status": "complete",
        "error": "",
        "meta": {},
        "directory": str(directory),
        "channels": [{
            "name": "output",
            "path": str(spool),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }],
    }

    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with sessions() as session:
                with pytest.raises(CaptureImportError, match="not safely owned"):
                    await import_capture(
                        session,
                        capture,
                        task_id="task-root-boundary",
                        source_kind="worker_tool",
                    )
                evidence = await session.get(RawEvidence, capture_id)
                assert evidence is not None
                assert evidence.capture_status == "failed"
                assert evidence.spool_directory is None
                assert spool.read_bytes() == payload
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_cleanup_rejects_registered_directory_outside_worker_root(tmp_path) -> None:
    from app.db.models import RawEvidence
    from app.raw_evidence import CaptureCleanupError, cleanup_evidence_spool

    capture_id = uuid.uuid4().hex
    directory = tmp_path / "outside-cleanup" / ".captures" / capture_id
    directory.mkdir(parents=True)
    spool = directory / "output.bin"
    spool.write_bytes(b"must-survive")
    evidence = RawEvidence(
        id=capture_id,
        task_id="task-other",
        spool_directory=str(directory),
    )

    with pytest.raises(CaptureCleanupError, match="outside worker root"):
        cleanup_evidence_spool(evidence)
    assert spool.read_bytes() == b"must-survive"


def test_cleanup_rejects_symlinked_capture_directory(tmp_path, monkeypatch) -> None:
    from app.db.models import RawEvidence
    from app.raw_evidence import CaptureCleanupError, cleanup_evidence_spool

    capture_id = uuid.uuid4().hex
    outside = tmp_path / "outside-symlink" / ".captures" / capture_id
    outside.mkdir(parents=True)
    (outside / "output.bin").write_bytes(b"must-survive")
    link = (
        Path(executor_module.worker_config.work_root)
        / "worker"
        / ".captures"
        / capture_id
    )
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        # Windows may deny symlink creation without Developer Mode. Simulate
        # the filesystem flag while retaining a real in-root directory.
        link.mkdir()
        original_is_symlink = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda path: path == link or original_is_symlink(path),
        )
    evidence = RawEvidence(
        id=capture_id,
        task_id="task-symlink",
        spool_directory=str(link),
    )

    with pytest.raises(CaptureCleanupError):
        cleanup_evidence_spool(evidence)
    assert (outside / "output.bin").read_bytes() == b"must-survive"
