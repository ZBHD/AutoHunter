"""Chunked persistence for private, full-fidelity tool captures.

Tool results keep bounded text previews for the LLM.  The private ``_capture``
descriptor points at spool files which this module imports without assembling a
whole channel in memory.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
from collections.abc import AsyncIterator, Iterator, Mapping, MutableMapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import worker_config
from app.db.models import RawEvidence, RawEvidenceChunk

CAPTURE_CHUNK_SIZE = 1024 * 1024
_CHUNKS_PER_COMMIT = 8
_FINAL_CAPTURE_STATUSES = {"complete", "partial", "failed", "legacy_partial"}

logger = logging.getLogger("autohunter.raw_evidence")


class CaptureImportError(RuntimeError):
    pass


class CaptureCleanupError(RuntimeError):
    pass


def _valid_capture_id(capture_id: str) -> bool:
    return bool(
        capture_id
        and len(capture_id) <= 64
        and capture_id not in {".", ".."}
        and "/" not in capture_id
        and "\\" not in capture_id
    )


def _inside_worker_root(path: Path) -> bool:
    try:
        worker_root = Path(worker_config.work_root).resolve(strict=False)
        path.relative_to(worker_root)
    except (OSError, ValueError):
        return False
    return True


def _discover_legacy_spool(capture_id: str) -> Path | None:
    """Find pre-registry spools in the executor's fixed one-target layout."""
    try:
        worker_root = Path(worker_config.work_root).resolve(strict=False)
        if not worker_root.is_dir():
            return None
        candidates = [worker_root / ".captures" / capture_id]
        candidates.extend(
            entry / ".captures" / capture_id
            for entry in worker_root.iterdir()
            if entry.is_dir()
        )
    except OSError as exc:
        raise CaptureCleanupError("worker root cannot be scanned for legacy spools") from exc

    matches = [
        candidate
        for candidate in candidates
        if candidate.exists() or candidate.is_symlink()
    ]
    if len(matches) > 1:
        raise CaptureCleanupError("multiple legacy spool directories match capture id")
    return matches[0] if matches else None


def _owned_spool_directory(capture: Mapping[str, Any]) -> Path | None:
    """Return the canonical private directory, never an arbitrary channel path."""
    capture_id = str(capture.get("id") or "").strip()
    if not _valid_capture_id(capture_id):
        return None

    raw_directory = str(capture.get("directory") or "").strip()
    if raw_directory:
        candidate = Path(raw_directory)
    else:
        parents = {
            Path(str(item.get("path") or "")).parent
            for item in capture.get("channels") or []
            if isinstance(item, Mapping) and str(item.get("path") or "").strip()
        }
        if len(parents) != 1:
            return None
        candidate = next(iter(parents))

    try:
        canonical = candidate.resolve(strict=False)
    except OSError:
        return None
    if (
        canonical.name != capture_id
        or canonical.parent.name != ".captures"
        or not _inside_worker_root(canonical)
    ):
        return None
    return canonical


def _validate_channel_ownership(
    capture: Mapping[str, Any],
    spool_directory: Path | None,
) -> None:
    if spool_directory is None:
        raise CaptureImportError("capture spool directory is not safely owned")
    for descriptor in capture.get("channels") or []:
        if not isinstance(descriptor, Mapping):
            continue
        path_text = str(descriptor.get("path") or "").strip()
        if not path_text:
            raise CaptureImportError("capture channel path is required")
        try:
            channel_path = Path(path_text).resolve(strict=False)
        except OSError as exc:
            raise CaptureImportError("capture channel path cannot be resolved") from exc
        if channel_path.parent != spool_directory:
            raise CaptureImportError("capture channel is outside owned spool directory")


def cleanup_evidence_spool(evidence: RawEvidence) -> bool:
    """Remove only the private capture directory registered to this evidence row."""
    capture_id = str(evidence.id or "").strip()
    if not _valid_capture_id(capture_id):
        raise CaptureCleanupError("invalid capture id in spool registry")

    path_text = str(evidence.spool_directory or "").strip()
    registered = Path(path_text) if path_text else _discover_legacy_spool(capture_id)
    if registered is None:
        return False
    try:
        directory = registered.resolve(strict=False)
    except OSError as exc:
        raise CaptureCleanupError("registered spool directory cannot be resolved") from exc
    if directory.name != capture_id or directory.parent.name != ".captures":
        raise CaptureCleanupError("registered spool directory is outside capture boundary")
    if not _inside_worker_root(directory):
        raise CaptureCleanupError("registered spool directory is outside worker root")
    if registered.absolute() != directory or registered.is_symlink():
        raise CaptureCleanupError("registered spool directory must be canonical and not symlinked")

    try:
        if directory.exists():
            if not directory.is_dir():
                raise CaptureCleanupError("registered spool path is not a directory")
            shutil.rmtree(directory)
        if directory.exists():
            raise CaptureCleanupError("registered spool directory still exists after cleanup")
        try:
            directory.parent.rmdir()
        except OSError:
            pass
    except CaptureCleanupError:
        raise
    except OSError as exc:
        raise CaptureCleanupError(f"capture spool cleanup failed: {exc}") from exc

    logger.info("removed capture spool evidence=%s directory=%s", capture_id, directory)
    return True


def detach_capture(result: MutableMapping[str, Any]) -> dict[str, Any] | None:
    """Remove the private descriptor before a tool result reaches an LLM/client."""
    capture = result.pop("_capture", None)
    return capture if isinstance(capture, dict) else None


def _channel_descriptor(capture: Mapping[str, Any], channel: str) -> Mapping[str, Any]:
    for item in capture.get("channels") or []:
        if isinstance(item, Mapping) and item.get("name") == channel:
            return item
    raise KeyError(f"capture channel not found: {channel}")


def iter_capture_channel(
    capture: Mapping[str, Any],
    channel: str,
    *,
    chunk_size: int = CAPTURE_CHUNK_SIZE,
) -> Iterator[bytes]:
    """Stream one spool channel from disk in bounded chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    item = _channel_descriptor(capture, channel)
    path = Path(str(item.get("path") or ""))
    with path.open("rb") as spool:
        while True:
            chunk = spool.read(chunk_size)
            if not chunk:
                break
            yield chunk


def _combined_hash(channels: Mapping[str, Mapping[str, Any]]) -> str:
    if len(channels) == 1:
        return str(next(iter(channels.values()))["sha256"])
    digest = hashlib.sha256()
    for name in sorted(channels):
        item = channels[name]
        digest.update(name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(item["size"]).encode("ascii"))
        digest.update(b"\x00")
        digest.update(str(item["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _capture_metadata(capture: Mapping[str, Any]) -> dict[str, Any]:
    meta = capture.get("meta")
    return {
        "capture_id": str(capture.get("id") or ""),
        "tool": str(capture.get("tool") or ""),
        "capture_meta": dict(meta) if isinstance(meta, Mapping) else {},
        "capture_error": str(capture.get("error") or ""),
        "channels": {},
        "import_complete": False,
    }


def _preview_payload(preview: Mapping[str, Any] | str | None) -> dict[str, Any]:
    if isinstance(preview, Mapping):
        return dict(preview)
    if isinstance(preview, str) and preview:
        return {"text": preview}
    return {}


def _validate_replay_ownership(
    evidence: RawEvidence,
    *,
    task_id: str,
    target_id: str | None,
    missed_signal_id: str | None,
    killsweep_event_id: int | None,
    source_kind: str,
) -> None:
    expected = {
        "task_id": task_id,
        "target_id": target_id,
        "missed_signal_id": missed_signal_id,
        "killsweep_event_id": killsweep_event_id,
        "source_kind": source_kind,
    }
    for field, value in expected.items():
        if getattr(evidence, field) != value:
            raise CaptureImportError(f"capture ownership mismatch: {field}")


async def import_capture(
    session: AsyncSession,
    capture: Mapping[str, Any],
    *,
    task_id: str,
    source_kind: str,
    target_id: str | None = None,
    missed_signal_id: str | None = None,
    killsweep_event_id: int | None = None,
    preview: Mapping[str, Any] | str | None = None,
    occurred_at: datetime | None = None,
) -> RawEvidence:
    """Import a descriptor into fixed 1 MiB chunks and remove spools on success.

    The capture id is also the evidence id. Replaying a descriptor after a
    successful import returns the existing row, including after spool cleanup.
    """
    evidence_id = str(capture.get("id") or "").strip()
    if not evidence_id:
        raise CaptureImportError("capture id is required")
    if not task_id:
        raise CaptureImportError("task_id is required")

    spool_directory = _owned_spool_directory(capture)

    evidence = await session.get(RawEvidence, evidence_id)
    is_retry = evidence is not None
    if evidence is not None:
        _validate_replay_ownership(
            evidence,
            task_id=task_id,
            target_id=target_id,
            missed_signal_id=missed_signal_id,
            killsweep_event_id=killsweep_event_id,
            source_kind=source_kind,
        )
        stored_meta = evidence.metadata_json or {}
        if stored_meta.get("import_complete"):
            if evidence.spool_directory:
                try:
                    if cleanup_evidence_spool(evidence):
                        evidence.spool_directory = None
                        await session.commit()
                except CaptureCleanupError as exc:
                    logger.warning("deferred capture spool cleanup evidence=%s: %s", evidence_id, exc)
            return evidence
        if spool_directory is not None:
            registered = str(evidence.spool_directory or "")
            if registered and Path(registered) != spool_directory:
                raise CaptureImportError("capture spool directory changed during retry")
            if not registered:
                evidence.spool_directory = str(spool_directory)
                await session.commit()
    else:
        evidence = RawEvidence(
            id=evidence_id,
            task_id=task_id,
            target_id=target_id,
            missed_signal_id=missed_signal_id,
            killsweep_event_id=killsweep_event_id,
            source_kind=source_kind,
            capture_status="writing",
            metadata_json=_capture_metadata(capture),
            preview=_preview_payload(preview),
            content_hash="",
            spool_directory=str(spool_directory) if spool_directory is not None else None,
            occurred_at=occurred_at or datetime.now(timezone.utc),
        )
        session.add(evidence)
        try:
            await session.commit()
        except Exception as exc:
            await session.rollback()
            try:
                cleanup_evidence_spool(evidence)
            except CaptureCleanupError as cleanup_exc:
                logger.error(
                    "capture registration and cleanup both failed evidence=%s: %s",
                    evidence_id,
                    cleanup_exc,
                )
            raise CaptureImportError("failed to register capture evidence") from exc

    metadata = _capture_metadata(capture)
    channel_metadata: dict[str, dict[str, Any]] = {}
    try:
        _validate_channel_ownership(capture, spool_directory)
        if is_retry:
            await session.execute(
                delete(RawEvidenceChunk).where(
                    RawEvidenceChunk.evidence_id == evidence_id
                )
            )
            await session.commit()
        channels = capture.get("channels") or []
        seen_names: set[str] = set()
        for descriptor in channels:
            if not isinstance(descriptor, Mapping):
                raise CaptureImportError("invalid capture channel descriptor")
            name = str(descriptor.get("name") or "").strip()
            if not name or name in seen_names:
                raise CaptureImportError(f"invalid or duplicate capture channel: {name!r}")
            seen_names.add(name)

            digest = hashlib.sha256()
            size = 0
            chunk_count = 0
            for data in iter_capture_channel(capture, name):
                digest.update(data)
                size += len(data)
                chunk_count += 1

            actual_hash = digest.hexdigest()
            declared_size = descriptor.get("size")
            declared_hash = str(descriptor.get("sha256") or "")
            if declared_size is not None and int(declared_size) != size:
                raise CaptureImportError(
                    f"capture channel {name!r} size mismatch: {size} != {declared_size}"
                )
            if declared_hash and declared_hash != actual_hash:
                raise CaptureImportError(f"capture channel {name!r} sha256 mismatch")

            rows = await session.scalars(
                select(RawEvidenceChunk.seq).where(
                    RawEvidenceChunk.evidence_id == evidence_id,
                    RawEvidenceChunk.channel == name,
                )
            )
            existing_sequences = set(rows.all())
            pending = 0
            for sequence, data in enumerate(iter_capture_channel(capture, name)):
                if sequence not in existing_sequences:
                    session.add(
                        RawEvidenceChunk(
                            evidence_id=evidence_id,
                            channel=name,
                            seq=sequence,
                            data=data,
                        )
                    )
                    pending += 1
                    if pending >= _CHUNKS_PER_COMMIT:
                        await session.commit()
                        pending = 0
            if pending:
                await session.commit()

            channel_metadata[name] = {
                "size": size,
                "sha256": actual_hash,
                "chunks": chunk_count,
            }

        metadata["channels"] = channel_metadata
        metadata["import_complete"] = True
        source_status = str(capture.get("status") or "failed")
        final_status = source_status if source_status in _FINAL_CAPTURE_STATUSES else "failed"
        evidence.capture_status = final_status
        evidence.metadata_json = metadata
        evidence.content_hash = _combined_hash(channel_metadata)
        await session.commit()
    except Exception as exc:
        await session.rollback()
        evidence = await session.get(RawEvidence, evidence_id)
        if evidence is not None:
            metadata["channels"] = channel_metadata
            metadata["import_error"] = f"{type(exc).__name__}: {exc}"
            evidence.capture_status = "failed"
            evidence.metadata_json = metadata
            await session.commit()
        if isinstance(exc, CaptureImportError):
            raise
        raise CaptureImportError(str(exc)) from exc

    try:
        if cleanup_evidence_spool(evidence):
            evidence.spool_directory = None
            await session.commit()
    except CaptureCleanupError as exc:
        logger.warning("deferred capture spool cleanup evidence=%s: %s", evidence_id, exc)
    return evidence


async def stream_evidence_channel(
    session: AsyncSession,
    evidence_id: str,
    channel: str,
) -> AsyncIterator[bytes]:
    """Yield a stored channel in sequence order without concatenating it."""
    rows = await session.stream_scalars(
        select(RawEvidenceChunk)
        .where(
            RawEvidenceChunk.evidence_id == evidence_id,
            RawEvidenceChunk.channel == channel,
        )
        .order_by(RawEvidenceChunk.seq.asc())
    )
    expected = 0
    async for row in rows:
        if row.seq != expected:
            raise CaptureImportError(
                f"evidence channel {channel!r} has sequence gap at {expected}"
            )
        expected += 1
        yield bytes(row.data)
