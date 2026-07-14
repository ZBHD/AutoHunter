from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import (
    Base,
    Finding,
    MissedSignal,
    MissedSignalEvent,
    RawEvidence,
    Review,
    Target,
    Task,
)
from app.missed_signals import (
    SignalCandidate,
    backfill_archived_signals,
    canonical_endpoint,
    detect_tool_signals,
    mark_matching_signals_converted,
    record_archived_review,
    record_coverage_gap,
    record_deepen_lead,
    register_signal_evidence,
    reject_signal,
    restore_signal,
    upsert_signal,
)


def run(coro):
    return asyncio.run(coro)


async def make_database(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'signals.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with sessions() as session:
        session.add(Task(id="task-1", name="Signals", status="running"))
        session.add(
            Target(
                id="target-1",
                task_id="task-1",
                url="https://Example.EDU.CN/",
                host="example.edu.cn",
                source="manual",
                status="done",
            )
        )
        await session.commit()
    return engine, sessions


def test_canonical_endpoint_uses_method_host_path_and_query_names_only() -> None:
    endpoint = canonical_endpoint(
        "post",
        "HTTPS://Example.EDU.CN:443/api/../api/users/?token=secret&id=2&id=1#row",
    )

    assert endpoint == "POST https://example.edu.cn/api/users/?id&token"


def test_generic_http_200_and_spa_fallback_are_not_signals() -> None:
    generic = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/", "method": "GET"},
        {
            "ok": True,
            "status_code": 200,
            "url": "https://example.edu.cn/",
            "response_headers": {"content-type": "text/html"},
            "body": "<html><title>Example University</title><div id='app'></div></html>",
        },
    )
    spa_fallback = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/actuator/env", "method": "GET"},
        {
            "ok": True,
            "status_code": 200,
            "url": "https://example.edu.cn/actuator/env",
            "response_headers": {"content-type": "text/html"},
            "body": "<html><title>Example University</title><script src='/app.js'></script></html>",
        },
    )

    assert generic == []
    assert spa_fallback == []


def test_sensitive_endpoint_requires_matching_response_evidence() -> None:
    no_evidence = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/actuator/env", "method": "GET"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {"content-type": "application/json"},
            "body": '{"message":"ok"}',
        },
    )
    evidenced = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/actuator/env", "method": "GET"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {"content-type": "application/json"},
            "body": '{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties"}]}',
        },
    )

    assert no_evidence == []
    assert [item.rule_key for item in evidenced] == ["sensitive_endpoint"]


def test_login_success_requires_session_or_token_evidence() -> None:
    success_text_only = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/login", "method": "POST"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {"content-type": "application/json"},
            "body": '{"success":true,"message":"login successful"}',
        },
    )
    with_session = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/login", "method": "POST"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {
                "content-type": "application/json",
                "set-cookie": "SESSION=opaque-session-value; HttpOnly; Secure",
            },
            "body": '{"success":true}',
        },
    )

    assert success_text_only == []
    assert any(item.rule_key == "login_success" for item in with_session)


def test_login_success_rejects_non_session_preference_cookie() -> None:
    preference_cookie = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/login", "method": "POST"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {
                "content-type": "application/json",
                "set-cookie": "theme=dark; Path=/; SameSite=Lax",
            },
            "session_cookies_updated": ["theme"],
            "body": '{"success":true}',
        },
    )
    access_token = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/login", "method": "POST"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {"content-type": "application/json"},
            "body": '{"access_token":"live-access-token-value-12345"}',
        },
    )

    assert preference_cookie == []
    assert any(item.rule_key == "login_success" for item in access_token)


def test_login_success_rejects_csrf_cookie_and_generic_token() -> None:
    csrf_cookie = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/login", "method": "POST"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {
                "content-type": "application/json",
                "set-cookie": "XSRF-TOKEN=opaque-csrf-value-12345; Path=/",
            },
            "session_cookies_updated": ["XSRF-TOKEN"],
            "body": '{"success":true}',
        },
    )
    generic_token = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/login", "method": "POST"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {"content-type": "application/json"},
            "body": '{"token":"opaque-csrf-value-12345"}',
        },
    )

    assert not any(item.rule_key == "login_success" for item in csrf_cookie)
    assert not any(item.rule_key == "login_success" for item in generic_token)


def test_upload_success_requires_write_method_and_returned_path() -> None:
    get_result = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/upload", "method": "GET"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {"content-type": "application/json"},
            "body": '{"url":"/uploads/proof.txt"}',
        },
    )
    post_without_path = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/upload", "method": "POST"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {"content-type": "application/json"},
            "body": '{"success":true}',
        },
    )
    post_with_path = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/upload", "method": "POST"},
        {
            "ok": True,
            "status_code": 201,
            "response_headers": {"content-type": "application/json"},
            "body": '{"success":true,"fileUrl":"/uploads/proof.txt"}',
        },
    )

    assert get_result == []
    assert post_without_path == []
    assert any(item.rule_key == "upload_success" for item in post_with_path)


def test_exception_and_secret_rules_create_signals() -> None:
    exception = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/api/search?q=x", "method": "GET"},
        {
            "ok": True,
            "status_code": 500,
            "response_headers": {"content-type": "text/plain"},
            "body": 'Traceback (most recent call last):\n  File "/srv/app/views.py", line 42, in search',
        },
    )
    secret = detect_tool_signals(
        "http_request",
        {"url": "https://example.edu.cn/static/config.js", "method": "GET"},
        {
            "ok": True,
            "status_code": 200,
            "response_headers": {"content-type": "application/javascript"},
            "body": 'window.config={api_key:"live_4f9a7c88d3554a87ad76"};',
        },
    )

    assert any(item.rule_key == "exception_leak" for item in exception)
    assert any(item.rule_key == "token_exposure" for item in secret)


def test_same_evidence_increments_hit_and_changed_evidence_reopens_rejected(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await make_database(tmp_path)
        candidate = SignalCandidate(
            rule_key="sensitive_endpoint",
            rule_label="敏感接口可访问",
            method="GET",
            endpoint_key="GET https://example.edu.cn/actuator/env",
            title="Actuator 环境接口返回配置",
            summary="响应包含 propertySources",
            risk_level="high",
            risk_score=8.0,
            source_type="tool",
        )
        try:
            async with sessions() as session:
                first_evidence = RawEvidence(
                    id="evidence-1",
                    task_id="task-1",
                    target_id="target-1",
                    source_kind="worker_tool",
                    capture_status="complete",
                    metadata_json={"channels": {}},
                    preview={"body": "propertySources"},
                    content_hash="hash-a",
                )
                session.add(first_evidence)
                signal = await upsert_signal(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    candidate=candidate,
                    evidence=first_evidence,
                )
                await session.commit()

                assert signal.hit_count == 1
                assert signal.evidence_count == 1

                same = await upsert_signal(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    candidate=candidate,
                    evidence_hash="hash-a",
                )
                await session.commit()
                assert same.id == signal.id
                assert same.hit_count == 2
                assert same.evidence_count == 1

                await reject_signal(session, signal.id, reason="暂不能形成实际危害", actor_role="full")
                await session.commit()
                assert signal.status == "rejected"

                second_evidence = RawEvidence(
                    id="evidence-2",
                    task_id="task-1",
                    target_id="target-1",
                    source_kind="worker_tool",
                    capture_status="complete",
                    metadata_json={"channels": {}},
                    preview={"body": "db.password=real-value"},
                    content_hash="hash-b",
                )
                session.add(second_evidence)
                reopened = await upsert_signal(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    candidate=candidate,
                    evidence=second_evidence,
                )
                await session.commit()

                assert reopened.status == "pending"
                assert reopened.hit_count == 3
                assert reopened.evidence_count == 2
                assert reopened.last_rejection_reason == "暂不能形成实际危害"

                restored = await restore_signal(session, reopened.id, actor_role="full")
                assert restored.status == "pending"

                kinds = list(
                    await session.scalars(
                        select(MissedSignalEvent.kind)
                        .where(MissedSignalEvent.signal_id == signal.id)
                        .order_by(MissedSignalEvent.id)
                    )
                )
                assert kinds == [
                    "created",
                    "evidence_added",
                    "seen_again",
                    "rejected",
                    "evidence_added",
                    "reopened",
                ]
        finally:
            await engine.dispose()

    run(scenario())


def test_prelinked_imported_evidence_is_registered_once_and_can_reopen_rejected(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await make_database(tmp_path)
        candidate = SignalCandidate(
            rule_key="exception_leak",
            rule_label="异常信息泄露",
            method="GET",
            endpoint_key="GET https://example.edu.cn/api/error",
            title="异常调用栈",
            summary="响应包含真实文件路径",
            risk_level="medium",
            risk_score=6.0,
            source_type="tool",
        )
        try:
            async with sessions() as session:
                signal = await upsert_signal(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    candidate=candidate,
                )
                await session.commit()

                imported = RawEvidence(
                    id="prelinked-1",
                    task_id="task-1",
                    target_id="target-1",
                    missed_signal_id=signal.id,
                    source_kind="worker_tool",
                    capture_status="complete",
                    metadata_json={"channels": {}},
                    preview={"body": "Traceback"},
                    content_hash="prelinked-hash-a",
                )
                session.add(imported)
                await session.commit()

                await register_signal_evidence(session, signal, imported)
                await session.commit()
                assert signal.evidence_count == 1

                await register_signal_evidence(session, signal, imported)
                await session.commit()
                assert signal.evidence_count == 1

                await reject_signal(session, signal.id, reason="证据影响不足")
                await session.commit()
                second = RawEvidence(
                    id="prelinked-2",
                    task_id="task-1",
                    target_id="target-1",
                    missed_signal_id=signal.id,
                    source_kind="worker_tool",
                    capture_status="complete",
                    metadata_json={"channels": {}},
                    preview={"body": "Traceback with credential"},
                    content_hash="prelinked-hash-b",
                )
                session.add(second)
                await session.commit()

                await register_signal_evidence(session, signal, second)
                await session.commit()
                assert signal.evidence_count == 2
                assert signal.status == "pending"

                kinds = list(
                    await session.scalars(
                        select(MissedSignalEvent.kind)
                        .where(MissedSignalEvent.signal_id == signal.id)
                        .order_by(MissedSignalEvent.id)
                    )
                )
                assert kinds.count("evidence_added") == 2
                assert kinds.count("reopened") == 1
        finally:
            await engine.dispose()

    run(scenario())


def test_archived_deepen_and_coverage_sources_are_actionable_only(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await make_database(tmp_path)
        try:
            async with sessions() as session:
                finding = Finding(
                    id="finding-archived",
                    task_id="task-1",
                    target_id="target-1",
                    worker_id="worker-1",
                    vuln_type="information_disclosure",
                    title="配置泄露线索",
                    severity_claimed="中危",
                    target_url="https://example.edu.cn/debug/config",
                    description="存在配置响应但影响未确认",
                    steps=["GET /debug/config"],
                    poc="curl https://example.edu.cn/debug/config",
                    raw_request="GET /debug/config HTTP/1.1",
                    raw_response="HTTP/1.1 200 OK",
                    status="reviewed",
                )
                review = Review(
                    id="review-archived",
                    finding_id=finding.id,
                    task_id="task-1",
                    verdict="ignored",
                    confidence="uncertain",
                    severity_final=None,
                    score=4.0,
                    in_scope=True,
                    ignore_reasons=["影响不足"],
                    reviewer_notes="需要更多配置值",
                )
                session.add_all([finding, review])
                await session.flush()

                archived = await record_archived_review(session, finding, review)
                no_lead = await record_deepen_lead(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    lead="   ",
                )
                lead = await record_deepen_lead(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    lead="继续验证 /api/export 的未授权批量导出",
                    endpoint="https://example.edu.cn/api/export?format=csv",
                )
                no_gap = await record_coverage_gap(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    gap={"endpoint": "/api/users", "actionable": False},
                )
                gap = await record_coverage_gap(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    gap={
                        "endpoint": "https://example.edu.cn/api/users?id=1",
                        "method": "GET",
                        "reason": "接口已发现但尚未验证对象级权限",
                        "actionable": True,
                    },
                )
                await session.commit()

                assert archived is not None and "archived_review" in archived.source_types
                assert no_lead is None
                assert lead is not None and "deepen_lead" in lead.source_types
                assert no_gap is None
                assert gap is not None and "coverage_gap" in gap.source_types
        finally:
            await engine.dispose()

    run(scenario())


def test_real_finding_marks_matching_candidates_converted(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await make_database(tmp_path)
        try:
            async with sessions() as session:
                signal = await upsert_signal(
                    session,
                    task_id="task-1",
                    target_id="target-1",
                    candidate=SignalCandidate(
                        rule_key="sensitive_endpoint",
                        rule_label="敏感接口可访问",
                        method="GET",
                        endpoint_key="GET https://example.edu.cn/api/users?id",
                        title="用户接口疑似未授权",
                        summary="待进一步确认",
                        risk_level="high",
                        risk_score=7.5,
                        source_type="coverage_gap",
                    ),
                )
                finding = Finding(
                    id="finding-real",
                    task_id="task-1",
                    target_id="target-1",
                    worker_id="worker-2",
                    vuln_type="idor",
                    title="用户接口越权",
                    severity_claimed="高危",
                    target_url="https://example.edu.cn/api/users?id=2",
                    description="可读取其他用户数据",
                    steps=["请求其他用户 ID"],
                    poc="curl 'https://example.edu.cn/api/users?id=2'",
                    raw_request="GET /api/users?id=2 HTTP/1.1",
                    raw_response="HTTP/1.1 200 OK",
                    status="pending_review",
                )
                session.add(finding)
                await session.flush()

                converted = await mark_matching_signals_converted(session, finding)
                await session.commit()

                assert converted == [signal.id]
                assert signal.status == "converted"
                assert signal.converted_finding_id == finding.id
                assert signal.converted_at is not None
        finally:
            await engine.dispose()

    run(scenario())


def test_archived_backfill_is_idempotent_and_preserves_only_existing_evidence(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await make_database(tmp_path)
        try:
            async with sessions() as session:
                finding = Finding(
                    id="finding-legacy",
                    task_id="task-1",
                    target_id="target-1",
                    worker_id="worker-old",
                    vuln_type="debug_info",
                    title="旧调试信息线索",
                    severity_claimed="低危",
                    target_url="https://example.edu.cn/debug",
                    description="旧记录",
                    steps=["访问 /debug"],
                    poc="curl https://example.edu.cn/debug",
                    raw_request="GET /debug HTTP/1.1\r\nHost: example.edu.cn",
                    raw_response="HTTP/1.1 200 OK\r\n\r\nexisting legacy response",
                    status="reviewed",
                )
                review = Review(
                    id="review-legacy",
                    finding_id=finding.id,
                    task_id="task-1",
                    verdict="deepen",
                    confidence="uncertain",
                    severity_final=None,
                    score=3.0,
                    in_scope=True,
                    deepen_directive="确认调试信息中的凭据是否可用",
                )
                session.add_all([finding, review])
                await session.commit()

                first = await backfill_archived_signals(session, limit=1)
                await session.commit()
                second = await backfill_archived_signals(session)
                await session.commit()

                assert first == 1
                assert second == 0
                assert await session.scalar(select(func.count()).select_from(MissedSignal)) == 1
                evidence = (
                    await session.scalars(select(RawEvidence).where(RawEvidence.source_kind == "archived_backfill"))
                ).one()
                assert evidence.capture_status == "legacy_partial"
                assert evidence.metadata_json["legacy_partial"] is True
                assert set(evidence.metadata_json["channels"]) == {"request", "response"}
                assert "tool output" not in str(evidence.preview).lower()
        finally:
            await engine.dispose()

    run(scenario())


def test_backfill_adds_legacy_evidence_to_an_existing_runtime_archived_signal(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await make_database(tmp_path)
        try:
            async with sessions() as session:
                finding = Finding(
                    id="finding-runtime-archive",
                    task_id="task-1",
                    target_id="target-1",
                    worker_id="worker-old",
                    vuln_type="debug_info",
                    title="运行期归档线索",
                    severity_claimed="低危",
                    target_url="https://example.edu.cn/runtime-debug",
                    description="仅有旧响应",
                    steps=["访问调试地址"],
                    poc="curl https://example.edu.cn/runtime-debug",
                    raw_request="GET /runtime-debug HTTP/1.1",
                    raw_response="HTTP/1.1 200 OK\r\n\r\nlegacy body",
                    status="reviewed",
                )
                review = Review(
                    id="review-runtime-archive",
                    finding_id=finding.id,
                    task_id="task-1",
                    verdict="ignored",
                    confidence="uncertain",
                    severity_final=None,
                    score=2.0,
                    in_scope=True,
                    ignore_reasons=["影响不足"],
                )
                session.add_all([finding, review])
                await session.flush()
                signal = await record_archived_review(session, finding, review)
                await session.commit()
                assert signal is not None and signal.evidence_count == 0

                imported = await backfill_archived_signals(session)
                await session.commit()
                repeated = await backfill_archived_signals(session)
                await session.commit()

                assert imported == 1
                assert repeated == 0
                assert signal.evidence_count == 1
                assert await session.scalar(select(func.count()).select_from(MissedSignal)) == 1
                assert await session.scalar(select(func.count()).select_from(RawEvidence)) == 1
        finally:
            await engine.dispose()

    run(scenario())
