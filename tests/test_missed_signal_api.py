from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api import missed_signals as missed_api
from app.db.models import (
    Base,
    Finding,
    MissedSignal,
    MissedSignalDraft,
    MissedSignalEvent,
    RawEvidence,
    RawEvidenceChunk,
    Review,
    Target,
    Task,
)
from app.db.session import get_session
from app.llm.protocols import LLMResponse
from app.missed_signals import register_signal_evidence
from app.security import observer_path_allowed


class DraftLLM:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.enabled_providers = ["weighted-primary", "fallback"]
        self.error: Exception | None = None

    def chat(self, messages, **kwargs):
        self.calls.append({"messages": messages, **kwargs})
        if self.error:
            raise self.error
        return LLMResponse(
            content=json.dumps(
                {
                    "title": "调试接口泄露运行配置",
                    "vuln_type": "information_disclosure",
                    "severity": "中危",
                    "owner": "待确认（现有证据无法确认归属）",
                    "target_url": "https://example.edu.cn/actuator/env",
                    "description": "未授权响应包含运行配置。",
                    "affected_scope": "待补充",
                    "steps": ["访问目标接口", "确认响应包含 propertySources"],
                    "poc": "curl -i https://example.edu.cn/actuator/env",
                    "raw_request": "GET /actuator/env HTTP/1.1\r\nHost: example.edu.cn",
                    "raw_response": "HTTP/1.1 200 OK\r\n\r\n{propertySources:[]}",
                    "evidence": {"notes": "propertySources 出现在实际响应中"},
                    "kill_chain": [
                        {"method": "接口探测", "detail": "访问 /actuator/env"},
                        {"method": "取证", "detail": "保存同次请求响应"},
                    ],
                    "missing_evidence": ["归属单位", "实际敏感配置值"],
                },
                ensure_ascii=False,
            )
        )


@pytest.fixture
def missed_api_client(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'missed-api.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    now = datetime.now(timezone.utc)

    async def setup() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-api", name="API Signals", status="paused"))
            session.add(
                Target(
                    id="target-api",
                    task_id="task-api",
                    url="https://example.edu.cn/",
                    host="example.edu.cn",
                    source="manual",
                    status="done",
                )
            )
            session.add_all(
                [
                    MissedSignal(
                        id="signal-high",
                        task_id="task-api",
                        target_id="target-api",
                        dedup_key="dedup-high",
                        rule_key="sensitive_endpoint",
                        rule_label="敏感接口可访问",
                        method="GET",
                        endpoint_key="GET https://example.edu.cn/actuator/env",
                        title="Actuator 配置接口",
                        summary="响应包含 propertySources",
                        risk_level="high",
                        risk_score=9.0,
                        source_types=["tool"],
                        status="pending",
                        hit_count=2,
                        evidence_count=1,
                        first_seen_at=now - timedelta(hours=2),
                        last_seen_at=now,
                        created_at=now - timedelta(hours=2),
                        updated_at=now,
                    ),
                    MissedSignal(
                        id="signal-low",
                        task_id="task-api",
                        target_id="target-api",
                        dedup_key="dedup-low",
                        rule_key="coverage_gap",
                        rule_label="覆盖遗漏",
                        method="GET",
                        endpoint_key="GET https://example.edu.cn/api/users?id",
                        title="用户接口尚未验证",
                        summary="对象级权限缺少验证",
                        risk_level="medium",
                        risk_score=4.0,
                        source_types=["coverage_gap"],
                        status="rejected",
                        hit_count=1,
                        evidence_count=0,
                        last_rejection_reason="无有效响应",
                        rejected_at=now - timedelta(hours=1),
                        first_seen_at=now - timedelta(days=1),
                        last_seen_at=now - timedelta(hours=1),
                        created_at=now - timedelta(days=1),
                        updated_at=now - timedelta(hours=1),
                    ),
                    MissedSignal(
                        id="signal-limit",
                        task_id="task-api",
                        target_id="target-api",
                        dedup_key="dedup-limit",
                        rule_key="deepen_lead",
                        rule_label="定向深挖线索",
                        method="GET",
                        endpoint_key="GET https://example.edu.cn/api/export",
                        title="批量导出待深挖",
                        summary="继续验证导出权限",
                        risk_level="high",
                        risk_score=7.0,
                        source_types=["deepen_lead"],
                        status="pending",
                        deepen_count=10,
                        first_seen_at=now,
                        last_seen_at=now,
                        created_at=now,
                        updated_at=now,
                    ),
                    MissedSignal(
                        id="signal-fail",
                        task_id="task-api",
                        target_id="target-api",
                        dedup_key="dedup-fail",
                        rule_key="exception_leak",
                        rule_label="异常信息泄露",
                        method="GET",
                        endpoint_key="GET https://example.edu.cn/api/error",
                        title="异常栈线索",
                        summary="响应包含 Traceback",
                        risk_level="medium",
                        risk_score=5.0,
                        source_types=["tool"],
                        status="pending",
                        first_seen_at=now,
                        last_seen_at=now,
                        created_at=now,
                        updated_at=now,
                    ),
                ]
            )
            request = b"GET /actuator/env HTTP/1.1\r\nHost: example.edu.cn\r\n\r\n"
            response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"propertySources\":[]}"
            session.add(
                RawEvidence(
                    id="evidence-api",
                    task_id="task-api",
                    target_id="target-api",
                    missed_signal_id="signal-high",
                    source_kind="worker_tool",
                    capture_status="complete",
                    metadata_json={
                        "import_complete": True,
                        "channels": {
                            "request": {"size": len(request), "sha256": "request-hash", "chunks": 1},
                            "response": {"size": len(response), "sha256": "response-hash", "chunks": 1},
                        },
                    },
                    preview={"status_code": 200, "body": "propertySources"},
                    content_hash="combined-hash",
                    occurred_at=now,
                    created_at=now,
                )
            )
            session.add_all(
                [
                    RawEvidenceChunk(
                        evidence_id="evidence-api", channel="request", seq=0, data=request
                    ),
                    RawEvidenceChunk(
                        evidence_id="evidence-api", channel="response", seq=0, data=response
                    ),
                    MissedSignalEvent(
                        signal_id="signal-high",
                        task_id="task-api",
                        kind="created",
                        actor_role="system",
                        from_status="",
                        to_status="pending",
                        reason="",
                        payload={},
                        created_at=now - timedelta(hours=2),
                    ),
                ]
            )
            await session.commit()

    asyncio.run(setup())

    async def override_session():
        async with sessions() as session:
            yield session

    llm = DraftLLM()
    monkeypatch.setattr(missed_api, "_draft_llm_for_task", lambda task: llm)
    app = FastAPI()
    app.include_router(missed_api.router)
    app.dependency_overrides[get_session] = override_session

    with TestClient(app) as client:
        yield client, sessions, llm

    asyncio.run(engine.dispose())


def test_stats_and_compact_list_are_paginated_and_ordered(missed_api_client) -> None:
    client, _sessions, _llm = missed_api_client

    stats = client.get("/api/missed-signals/stats")
    page = client.get(
        "/api/missed-signals",
        params={"status": "all", "task_id": "task-api", "limit": 1, "offset": 0},
    )

    assert stats.status_code == 200
    assert stats.json() == {
        "total": 4,
        "pending": 3,
        "deepening": 0,
        "converted": 0,
        "rejected": 1,
    }
    assert page.status_code == 200
    payload = page.json()
    assert payload.keys() >= {"items", "total", "has_more", "limit", "offset"}
    assert payload["total"] == 4
    assert payload["has_more"] is True
    assert payload["items"][0]["id"] == "signal-high"
    assert payload["items"][0]["task_name"] == "API Signals"
    assert payload["items"][0]["target_url"] == "https://example.edu.cn/"
    assert "raw_evidence_chunks" not in page.text
    assert "propertySources\":[]" not in page.text


def test_search_applies_before_pagination(missed_api_client) -> None:
    client, _sessions, _llm = missed_api_client

    response = client.get(
        "/api/missed-signals",
        params={"status": "all", "q": "对象级权限", "limit": 50, "offset": 0},
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["id"] == "signal-low"


def test_detail_and_evidence_metadata_do_not_inline_raw_chunks(missed_api_client) -> None:
    client, _sessions, _llm = missed_api_client

    detail = client.get("/api/missed-signals/signal-high")
    evidence = client.get("/api/missed-signals/signal-high/evidence")

    assert detail.status_code == 200
    payload = detail.json()
    assert payload["events"][0]["kind"] == "created"
    assert payload["evidence"][0]["id"] == "evidence-api"
    assert payload["evidence"][0]["channels"]["response"]["size"] > 0
    assert "data" not in detail.text
    assert evidence.status_code == 200
    assert evidence.json()[0]["content_hash"] == "combined-hash"


def test_readonly_compatible_get_streams_raw_channel_without_assembly_contract(
    missed_api_client,
) -> None:
    client, _sessions, _llm = missed_api_client

    response = client.get(
        "/api/missed-signals/signal-high/evidence/evidence-api/content",
        params={"channel": "response"},
        headers={"X-Autohunter-Token": "readonly-token"},
    )

    assert response.status_code == 200
    assert response.content.startswith(b"HTTP/1.1 200 OK")
    assert response.content.endswith(b'{"propertySources":[]}')
    assert response.headers["content-type"].startswith("text/plain")


def test_evidence_stream_rejects_cross_signal_access_and_unknown_channel(
    missed_api_client,
) -> None:
    client, _sessions, _llm = missed_api_client

    wrong_signal = client.get(
        "/api/missed-signals/signal-low/evidence/evidence-api/content",
        params={"channel": "response"},
    )
    unknown_channel = client.get(
        "/api/missed-signals/signal-high/evidence/evidence-api/content",
        params={"channel": "stderr"},
    )

    assert wrong_signal.status_code == 404
    assert unknown_channel.status_code == 404


def test_one_capture_is_accessible_to_every_matching_signal_and_draft(
    missed_api_client,
) -> None:
    client, sessions, llm = missed_api_client

    async def attach_shared_capture():
        async with sessions() as session:
            signal = await session.get(MissedSignal, "signal-low")
            evidence = await session.get(RawEvidence, "evidence-api")
            assert signal is not None and evidence is not None
            assert await register_signal_evidence(session, signal, evidence) is True
            await session.commit()

    asyncio.run(attach_shared_capture())

    metadata = client.get("/api/missed-signals/signal-low/evidence")
    content = client.get(
        "/api/missed-signals/signal-low/evidence/evidence-api/content",
        params={"channel": "response"},
    )
    generated = client.post("/api/missed-signals/signal-low/draft/generate")

    assert metadata.status_code == 200
    assert [item["id"] for item in metadata.json()] == ["evidence-api"]
    assert content.status_code == 200
    assert b"propertySources" in content.content
    assert generated.status_code == 200, generated.text
    assert "propertySources" in llm.calls[-1]["messages"][1]["content"]

    async def chunk_count():
        async with sessions() as session:
            return await session.scalar(select(func.count()).select_from(RawEvidenceChunk))

    assert asyncio.run(chunk_count()) == 2


def test_reject_requires_reason_and_restore_preserves_audit_history(missed_api_client) -> None:
    client, sessions, _llm = missed_api_client

    missing_reason = client.post("/api/missed-signals/signal-high/reject", json={"reason": " "})
    rejected = client.post(
        "/api/missed-signals/signal-high/reject", json={"reason": "尚未证明实际敏感值"}
    )
    restored = client.post("/api/missed-signals/signal-high/restore")

    assert missing_reason.status_code == 422
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    assert restored.status_code == 200
    assert restored.json()["status"] == "pending"

    async def audit_kinds():
        async with sessions() as session:
            return list(
                await session.scalars(
                    select(MissedSignalEvent.kind)
                    .where(MissedSignalEvent.signal_id == "signal-high")
                    .order_by(MissedSignalEvent.id)
                )
            )

    assert asyncio.run(audit_kinds())[-2:] == ["rejected", "restored"]


def test_deepen_queues_against_paused_task_and_enforces_per_signal_limit_10(
    missed_api_client,
) -> None:
    client, _sessions, _llm = missed_api_client

    queued = client.post(
        "/api/missed-signals/signal-high/deepen",
        json={"directive": "验证 propertySources 中的真实密钥是否可用"},
    )
    limited = client.post(
        "/api/missed-signals/signal-limit/deepen",
        json={"directive": "再次验证"},
    )

    assert queued.status_code == 200
    assert queued.json()["status"] == "deepening"
    assert queued.json()["deepen_phase"] == "queued"
    assert queued.json()["deepen_count"] == 1
    async def target_after_queue():
        async with _sessions() as session:
            return await session.get(Target, "target-api")

    target = asyncio.run(target_after_queue())
    assert target.status == "queued"
    assert target.verdict == ""
    assert target.assigned_worker == ""
    assert target.heartbeat_at is None
    assert target.deepen_context["missed_signal_id"] == "signal-high"
    assert target.deepen_context["directive"] == "验证 propertySources 中的真实密钥是否可用"
    assert target.priority_score >= 100
    assert limited.status_code == 409
    assert "10" in limited.text


def test_generate_autosave_and_confirm_draft_are_persistent_and_idempotent(
    missed_api_client,
) -> None:
    client, sessions, llm = missed_api_client

    generated = client.post("/api/missed-signals/signal-high/draft/generate")
    assert generated.status_code == 200, generated.text
    draft = generated.json()
    assert draft["status"] == "ready"
    assert draft["revision"] == 1
    assert draft["content"]["severity"] == "中危"
    assert draft["missing_evidence"] == ["归属单位", "实际敏感配置值"]
    assert llm.calls[0]["tools"] is None
    assert llm.calls[0]["tool_choice"] == "none"
    assert "不得调用任何工具" in llm.calls[0]["messages"][0]["content"]
    assert "propertySources" in llm.calls[0]["messages"][1]["content"]

    edited_content = dict(draft["content"])
    edited_content["owner"] = "示例大学（由站点页脚确认）"
    saved = client.patch(
        "/api/missed-signals/signal-high/draft",
        json={
            "revision": 1,
            "content": edited_content,
            "missing_evidence": ["实际敏感配置值"],
        },
    )
    stale = client.patch(
        "/api/missed-signals/signal-high/draft",
        json={"revision": 1, "content": edited_content},
    )

    assert saved.status_code == 200
    assert saved.json()["revision"] == 2
    assert saved.json()["content"]["owner"].startswith("示例大学")
    assert stale.status_code == 409

    confirmed = client.post(
        "/api/missed-signals/signal-high/draft/confirm", json={"revision": 2}
    )
    repeated = client.post(
        "/api/missed-signals/signal-high/draft/confirm", json={"revision": 2}
    )

    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["ok"] is True
    assert repeated.status_code == 200
    assert repeated.json()["finding_id"] == confirmed.json()["finding_id"]
    assert repeated.json()["already_confirmed"] is True

    async def persisted_rows():
        async with sessions() as session:
            signal = await session.get(MissedSignal, "signal-high")
            created = await session.get(Finding, confirmed.json()["finding_id"])
            review = (
                await session.scalars(
                    select(Review).where(Review.finding_id == confirmed.json()["finding_id"])
                )
            ).one()
            draft_row = (
                await session.scalars(
                    select(MissedSignalDraft).where(MissedSignalDraft.signal_id == "signal-high")
                )
            ).one()
            return signal, created, review, draft_row

    signal, finding, review, draft_row = asyncio.run(persisted_rows())
    assert signal.status == "converted"
    assert signal.converted_finding_id == finding.id
    assert finding.worker_id == "missed_signal"
    assert finding.status == "reviewed"
    assert finding.owner.startswith("示例大学")
    assert finding.severity_claimed == "中危"
    assert review.verdict == "accepted"
    assert review.confidence == "uncertain"
    assert review.user_status == "pending"
    assert draft_row.status == "confirmed"


def test_llm_failure_is_retained_and_can_be_retried_or_manually_edited(
    missed_api_client,
) -> None:
    client, sessions, llm = missed_api_client
    llm.error = RuntimeError("provider pool unavailable")

    response = client.post("/api/missed-signals/signal-fail/draft/generate")

    assert response.status_code == 503

    async def load_draft():
        async with sessions() as session:
            return (
                await session.scalars(
                    select(MissedSignalDraft).where(MissedSignalDraft.signal_id == "signal-fail")
                )
            ).one()

    draft = asyncio.run(load_draft())
    assert draft.status == "failed"
    assert draft.generation_count == 1
    assert "provider pool unavailable" in draft.last_error
    assert draft.content == {}


def test_observer_allowlist_denies_global_missed_signal_pages() -> None:
    assert observer_path_allowed("/api/missed-signals") is False
    assert observer_path_allowed("/api/missed-signals/stats") is False
