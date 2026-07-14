from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api import findings as findings_api
from app.api import killsweeps as killsweeps_api
from app.config import worker_config
from app.db.models import Base, Finding, Killsweep, Review, Target, Task
from app.db.session import get_session
from app.killsweep_service import (
    append_event,
    claim_attempt,
    finalize_attempt,
    queue_initial_attempt,
)
from app.raw_evidence import import_capture


@pytest.fixture
def killsweep_api(tmp_path, monkeypatch):
    monkeypatch.setattr(worker_config, "work_root", str(tmp_path))
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'api.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def setup() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-api", name="API Task", status="running"))
            session.add(Target(
                id="target-api", task_id="task-api", url="https://origin.test",
                host="origin.test", source="manual", status="done",
            ))
            session.add(Finding(
                id="finding-api", task_id="task-api", target_id="target-api",
                vuln_type="idor", title="Source IDOR", severity_claimed="high",
                target_url="https://origin.test/api",
            ))
            session.add(Target(
                id="target-pass", task_id="task-api", url="https://pass.test",
                host="pass.test", source="manual", status="done",
            ))
            session.add(Finding(
                id="finding-pass", task_id="task-api", target_id="target-pass",
                vuln_type="upload", title="Upload", severity_claimed="high",
                target_url="https://pass.test/upload", status="reviewed",
            ))
            session.add(Review(
                id="review-pass", finding_id="finding-pass", task_id="task-api",
                verdict="accepted", confidence="confirmed", user_status="pending",
            ))
            case, attempt, _ = await queue_initial_attempt(
                session, task_id="task-api", finding_id="finding-api"
            )
            await claim_attempt(session, attempt.id)
            event = await append_event(
                session, case_id=case.id, attempt_id=attempt.id,
                kind="http_result", summary="HTTP 200",
                payload={"status_code": 200},
            )
            payload = b"HTTP/1.1 200 OK\r\n\r\nsecret-response"
            directory = tmp_path / "worker" / ".captures" / "evidence-api"
            directory.mkdir(parents=True)
            spool = directory / "response.bin"
            spool.write_bytes(payload)
            await import_capture(session, {
                "id": "evidence-api", "tool": "http_request", "status": "complete",
                "error": "", "meta": {}, "directory": str(directory),
                "channels": [{
                    "name": "response", "path": str(spool), "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }],
            }, task_id="task-api", killsweep_event_id=event.id,
               source_kind="killsweep_http", preview={"status_code": 200})
            await finalize_attempt(session, attempt.id, result={
                "product_name": "Example CMS", "fofa_query": 'title="Example"',
                "fingerprint": "title", "asset_count": 10, "edu_count": 2,
                "is_killsweep": True, "verified": False,
            })
            session.add(Killsweep(
                id="failed-case", task_id="task-api", origin_finding_id="legacy",
                legacy_without_timeline=True, status="failed", failure_kind="timeout",
                failure_message="timed out",
            ))
            await session.commit()

    asyncio.run(setup())

    async def override_session():
        async with sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(killsweeps_api.router)
    app.include_router(findings_api.router)
    app.dependency_overrides[get_session] = override_session

    async def no_dispatch(_task_id: str, _attempt_id: str) -> bool:
        return True

    monkeypatch.setattr(killsweeps_api.manager, "dispatch_killsweep_attempt", no_dispatch)
    with TestClient(app) as client:
        yield client
    asyncio.run(engine.dispose())


def test_global_stats_and_paginated_list(killsweep_api: TestClient) -> None:
    stats = killsweep_api.get("/api/killsweeps/stats", params={"task_id": "task-api"})
    assert stats.status_code == 200
    assert stats.json()["pending_validation"] == 1
    assert stats.json()["failed"] == 1

    response = killsweep_api.get(
        "/api/killsweeps",
        params={"task_id": "task-api", "status": "pending_validation", "limit": 50},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["origin_title"] == "Source IDOR"
    assert payload["items"][0]["automatic_verdict"] == "pending_validation"


def test_detail_exposes_attempt_history_and_event_evidence_metadata(
    killsweep_api: TestClient,
) -> None:
    listing = killsweep_api.get(
        "/api/killsweeps", params={"status": "pending_validation"}
    ).json()
    case_id = listing["items"][0]["id"]

    detail = killsweep_api.get(f"/api/killsweeps/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["attempts"][0]["status"] == "succeeded"

    events = killsweep_api.get(f"/api/killsweeps/{case_id}/events")
    assert events.status_code == 200
    http_event = next(item for item in events.json()["items"] if item["kind"] == "http_result")
    assert http_event["evidence"][0]["id"] == "evidence-api"
    assert http_event["evidence"][0]["channels"] == ["response"]

    content = killsweep_api.get(
        f"/api/killsweeps/{case_id}/events/{http_event['id']}"
        "/evidence/evidence-api/content",
        params={"channel": "response"},
    )
    assert content.status_code == 200
    assert content.content.endswith(b"secret-response")


def test_manual_review_keeps_automatic_verdict(killsweep_api: TestClient) -> None:
    case_id = killsweep_api.get(
        "/api/killsweeps", params={"status": "pending_validation"}
    ).json()["items"][0]["id"]
    response = killsweep_api.post(
        f"/api/killsweeps/{case_id}/manual-review",
        json={"verdict": "confirmed", "reason": "人工复核通过"},
    )
    assert response.status_code == 200
    assert response.json()["automatic_verdict"] == "pending_validation"
    assert response.json()["manual_verdict"] == "confirmed"


def test_retry_and_filtered_batch_append_attempts(killsweep_api: TestClient) -> None:
    retry = killsweep_api.post("/api/killsweeps/failed-case/reanalyze")
    assert retry.status_code == 200
    assert retry.json()["queued"] is True
    assert retry.json()["attempt_no"] == 1

    # An active queued attempt is skipped by the batch instead of duplicated.
    batch = killsweep_api.post(
        "/api/killsweeps/reanalysis-batches",
        json={"filters": {"status": "failed"}},
    )
    assert batch.status_code == 200
    assert batch.json()["selected_count"] == 0
    assert batch.json()["max_count"] == 40


def test_human_pass_queues_case_before_dispatch(killsweep_api: TestClient) -> None:
    response = killsweep_api.patch(
        "/api/results/finding-pass", json={"user_status": "passed"}
    )
    assert response.status_code == 200
    assert response.json()["killsweep_triggered"] is True

    queued = killsweep_api.get(
        "/api/killsweeps", params={"task_id": "task-api", "status": "queued"}
    ).json()
    assert queued["total"] == 1
    assert queued["items"][0]["origin_finding_id"] == "finding-pass"
