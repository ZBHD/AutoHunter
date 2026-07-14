"""Deterministic missed-signal detection and transactional state handling."""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import uuid
from http.cookies import SimpleCookie
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

from sqlalchemy import case, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding,
    MissedSignal,
    MissedSignalEvidence,
    MissedSignalEvent,
    RawEvidence,
    RawEvidenceChunk,
    Review,
    Target,
)

MAX_DEEPEN_COUNT = 10


class MissedSignalError(RuntimeError):
    """Base error for a missed-signal operation."""


class SignalNotFoundError(MissedSignalError):
    pass


class InvalidSignalTransitionError(MissedSignalError):
    pass


class SignalValidationError(MissedSignalError):
    pass


@dataclass(frozen=True)
class SignalCandidate:
    rule_key: str
    rule_label: str
    method: str
    endpoint_key: str
    title: str
    summary: str
    risk_level: str
    risk_score: float
    source_type: str


_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
_LOGIN_PATH_RE = re.compile(r"/(?:login|signin|sign-in|auth|session|token)(?:[/?#]|$)", re.I)
_UPLOAD_PATH_RE = re.compile(r"/(?:upload|uploads|import|attachment|avatar|file)(?:[/?#]|$)", re.I)
_RETURNED_PATH_RE = re.compile(
    r"[\"']?(?:file_?url|fileurl|download_?url|url|path|location)[\"']?\s*[:=]\s*"
    r"[\"']((?:https?://|/)[^\"'\s]{2,1000})[\"']",
    re.I,
)
_TOKEN_PAIR_RE = re.compile(
    r"\b(?:access[_-]?token|refresh[_-]?token|api[_-]?key|secret(?:[_-]?key)?|authorization)\b"
    r"[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?([A-Za-z0-9._~+/=-]{12,})",
    re.I,
)
_LOGIN_TOKEN_PAIR_RE = re.compile(
    r"\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|auth(?:entication)?[_-]?token|"
    r"session[_-]?token|jwt|authorization)\b"
    r"[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?([A-Za-z0-9._~+/=-]{12,})",
    re.I,
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SENSITIVE_PATH_RE = re.compile(
    r"(?:/(?:actuator/(?:env|configprops|beans|heapdump)|debug(?:/|$)|config(?:/|$)|"
    r"swagger(?:\.json|/|$)|v[23]/api-docs(?:/|$)|openapi\.json|graphql(?:/|$))|/(?:\.env)(?:/|$))",
    re.I,
)
_SENSITIVE_RESPONSE_RE = re.compile(
    r"(?:propertySources|activeProfiles|configProps|DATABASE_URL|DB_(?:PASSWORD|USER)|"
    r"AWS_(?:ACCESS_KEY|SECRET)|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|"
    r"[\"']openapi[\"']\s*:|[\"']paths[\"']\s*:\s*\{|__schema|jdbc:|"
    r"(?:redis|mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://|"
    r"[\"'](?:password|passwd|secret)[\"']\s*:\s*[\"'][^\"']{4,})",
    re.I,
)
_DOTENV_RESPONSE_RE = re.compile(
    r"(?m)^(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|AWS_ACCESS_KEY_ID)\s*=\s*\S+"
)
_EXCEPTION_RE = re.compile(
    r"(?:Traceback \(most recent call last\):|\bFile [\"'][^\"']+[\"'], line \d+|"
    r"\bat [\w.$<>]+\([^\n()]+\.(?:java|kt|cs):\d+\)|"
    r"(?:SQL|PDO|Hibernate|Sequelize|Doctrine)(?:Exception|Error)|"
    r"(?:NullPointer|ClassNotFound|TemplateSyntax|Operational)Exception)",
    re.I,
)
_PLACEHOLDER_SECRET_RE = re.compile(r"^(?:true|false|null|undefined|none|masked|redacted|x+|\*+)$", re.I)
_SESSION_COOKIE_NAME_RE = re.compile(
    r"(?:^|[_-])(?:session(?:id)?|auth(?:entication)?|token|jwt|sid)(?:$|[_-])",
    re.I,
)
_WELL_KNOWN_SESSION_COOKIES = frozenset(
    {"jsessionid", "phpsessid", "asp.net_sessionid", "connect.sid"}
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_endpoint(method: str, url: str) -> str:
    """Canonicalize an endpoint without retaining query values or fragments."""
    verb = str(method or "GET").strip().upper() or "GET"
    value = str(url or "").strip()
    if not value:
        return f"{verb} /"

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"

    raw_path = parsed.path or "/"
    trailing_slash = raw_path.endswith("/")
    path = posixpath.normpath(raw_path)
    if not path.startswith("/"):
        path = "/" + path
    if trailing_slash and path != "/":
        path += "/"

    query_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    canonical_query = "&".join(quote(name, safe="[]_.-") for name in query_names)
    if scheme and host:
        endpoint = urlunsplit((scheme, host, path, canonical_query, ""))
    else:
        endpoint = path + (f"?{canonical_query}" if canonical_query else "")
    return f"{verb} {endpoint}"[:1000]


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _response_headers(result: Mapping[str, Any]) -> dict[str, str]:
    headers = result.get("response_headers")
    if not isinstance(headers, Mapping):
        return {}
    return {str(key).lower(): _text(value) for key, value in headers.items()}


def _looks_like_spa_fallback(headers: Mapping[str, str], body: str) -> bool:
    content_type = headers.get("content-type", "").lower()
    lower = body.lower()
    return (
        "text/html" in content_type
        and "<html" in lower
        and ("<script" in lower or "id=\"app\"" in lower or "id='app'" in lower)
        and not _SENSITIVE_RESPONSE_RE.search(body)
        and not _EXCEPTION_RE.search(body)
    )


def _is_session_cookie_name(value: Any) -> bool:
    name = str(value or "").strip().lower()
    if "csrf" in name or "xsrf" in name:
        return False
    return bool(
        name
        and (
            name in _WELL_KNOWN_SESSION_COOKIES
            or _SESSION_COOKIE_NAME_RE.search(name)
        )
    )


def _response_session_cookie_names(
    output: Mapping[str, Any], headers: Mapping[str, str]
) -> set[str]:
    names: set[str] = set()
    updated = output.get("session_cookies_updated")
    if isinstance(updated, (list, tuple, set)):
        names.update(str(item) for item in updated)
    elif isinstance(updated, str):
        names.add(updated)
    raw_cookie = headers.get("set-cookie", "")
    if raw_cookie:
        try:
            parsed = SimpleCookie()
            parsed.load(raw_cookie)
            names.update(parsed.keys())
        except Exception:
            pass
    return {name for name in names if _is_session_cookie_name(name)}


def detect_tool_signals(
    tool_name: str,
    arguments: Mapping[str, Any] | None,
    result: Mapping[str, Any] | None,
) -> list[SignalCandidate]:
    """Return deterministic, high-signal candidates from one completed tool call."""
    args = arguments if isinstance(arguments, Mapping) else {}
    output = result if isinstance(result, Mapping) else {}
    if str(tool_name or "") != "http_request" or output.get("ok") is not True:
        return []

    try:
        status = int(output.get("status_code") or 0)
    except (TypeError, ValueError):
        status = 0
    if not 100 <= status <= 599:
        return []

    method = str(args.get("method") or "GET").upper()
    url = str(output.get("url") or args.get("url") or "").strip()
    path = urlsplit(url).path or "/"
    endpoint = canonical_endpoint(method, url)
    headers = _response_headers(output)
    body = _text(output.get("body"))
    combined = body + "\n" + "\n".join(f"{key}: {value}" for key, value in headers.items())
    is_success = 200 <= status < 300
    spa_fallback = _looks_like_spa_fallback(headers, body)
    candidates: list[SignalCandidate] = []

    token_match = _TOKEN_PAIR_RE.search(combined) or _JWT_RE.search(combined)
    token_value = token_match.group(1) if token_match and token_match.lastindex else token_match.group(0) if token_match else ""
    valid_token = bool(token_match and not _PLACEHOLDER_SECRET_RE.fullmatch(token_value.strip("'\"")))

    login_token_match = _LOGIN_TOKEN_PAIR_RE.search(combined) or _JWT_RE.search(combined)
    login_token_value = (
        login_token_match.group(1)
        if login_token_match and login_token_match.lastindex
        else login_token_match.group(0) if login_token_match else ""
    )
    valid_login_token = bool(
        login_token_match
        and not _PLACEHOLDER_SECRET_RE.fullmatch(login_token_value.strip("'\""))
    )
    session_evidence = bool(
        _response_session_cookie_names(output, headers) or valid_login_token
    )
    if (
        is_success
        and method in _WRITE_METHODS
        and _LOGIN_PATH_RE.search(path)
        and session_evidence
        and not spa_fallback
    ):
        candidates.append(
            SignalCandidate(
                rule_key="login_success",
                rule_label="登录或会话建立成功",
                method=method,
                endpoint_key=endpoint,
                title="登录接口返回有效会话信号",
                summary="写请求成功后响应建立了 Cookie、会话或访问令牌，值得继续验证受限功能。",
                risk_level="high",
                risk_score=8.0,
                source_type="tool",
            )
        )

    returned_path = _RETURNED_PATH_RE.search(body) or _RETURNED_PATH_RE.search(headers.get("location", ""))
    if (
        is_success
        and method in _WRITE_METHODS
        and _UPLOAD_PATH_RE.search(path)
        and returned_path
        and not spa_fallback
    ):
        candidates.append(
            SignalCandidate(
                rule_key="upload_success",
                rule_label="上传写入成功",
                method=method,
                endpoint_key=endpoint,
                title="上传接口返回可定位的文件路径",
                summary="写请求成功且响应返回了文件 URL 或路径，需要继续验证访问与执行影响。",
                risk_level="high",
                risk_score=8.5,
                source_type="tool",
            )
        )

    if is_success and valid_token and not spa_fallback:
        candidates.append(
            SignalCandidate(
                rule_key="token_exposure",
                rule_label="令牌或密钥暴露",
                method=method,
                endpoint_key=endpoint,
                title="响应中出现可用凭据形态",
                summary="响应包含非占位的令牌、API Key 或密钥形态，需要验证其权限与实际影响。",
                risk_level="high",
                risk_score=8.0,
                source_type="tool",
            )
        )

    sensitive_evidence = bool(
        _SENSITIVE_RESPONSE_RE.search(body)
        or (path.lower().endswith("/.env") and _DOTENV_RESPONSE_RE.search(body))
    )
    if is_success and _SENSITIVE_PATH_RE.search(path) and sensitive_evidence and not spa_fallback:
        candidates.append(
            SignalCandidate(
                rule_key="sensitive_endpoint",
                rule_label="敏感接口可访问",
                method=method,
                endpoint_key=endpoint,
                title="敏感端点返回结构化配置证据",
                summary="敏感路径与响应特征同时命中，需要确认其中数据和权限影响。",
                risk_level="high",
                risk_score=7.5,
                source_type="tool",
            )
        )

    if _EXCEPTION_RE.search(body) and not spa_fallback:
        candidates.append(
            SignalCandidate(
                rule_key="exception_leak",
                rule_label="异常信息泄露",
                method=method,
                endpoint_key=endpoint,
                title="响应泄露服务端异常调用栈",
                summary="响应包含文件路径、行号、框架或数据库异常，需要判断能否推进到实际利用。",
                risk_level="medium",
                risk_score=6.0,
                source_type="tool",
            )
        )

    # A rule is emitted once even if several signatures matched it.
    unique: dict[str, SignalCandidate] = {}
    for candidate in candidates:
        unique.setdefault(candidate.rule_key, candidate)
    return list(unique.values())


def _dedup_key(task_id: str, target_id: str | None, candidate: SignalCandidate) -> str:
    value = "\x1f".join(
        [task_id, target_id or "", candidate.rule_key.strip().lower(), candidate.endpoint_key.strip()]
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event(
    signal: MissedSignal,
    *,
    kind: str,
    actor_role: str = "system",
    from_status: str = "",
    to_status: str = "",
    reason: str = "",
    payload: Mapping[str, Any] | None = None,
) -> MissedSignalEvent:
    return MissedSignalEvent(
        signal_id=signal.id,
        task_id=signal.task_id,
        kind=kind,
        actor_role=actor_role,
        from_status=from_status,
        to_status=to_status,
        reason=reason,
        payload=dict(payload or {}),
    )


async def get_signal(session: AsyncSession, signal_id: str) -> MissedSignal:
    signal = await session.get(MissedSignal, signal_id)
    if signal is None:
        raise SignalNotFoundError("疑似信号不存在")
    return signal


def signal_evidence_filter(signal_id: str):
    """Match both legacy direct links and shared capture associations."""
    linked_ids = select(MissedSignalEvidence.evidence_id).where(
        MissedSignalEvidence.missed_signal_id == signal_id
    )
    return or_(
        RawEvidence.missed_signal_id == signal_id,
        RawEvidence.id.in_(linked_ids),
    )


def signal_evidence_query(signal_id: str):
    return (
        select(RawEvidence)
        .where(signal_evidence_filter(signal_id))
        .order_by(RawEvidence.occurred_at.asc(), RawEvidence.id.asc())
    )


async def register_signal_evidence(
    session: AsyncSession,
    signal: MissedSignal,
    evidence: RawEvidence,
) -> bool:
    """Attach one imported evidence row and audit it exactly once.

    ``import_capture`` may have already populated ``missed_signal_id`` and
    committed before this function is called.  The stored evidence count is
    therefore compared with the current linked-row count instead of assuming
    an unlinked transient ORM object.
    """
    if evidence.task_id and evidence.task_id != signal.task_id:
        raise SignalValidationError("原始证据不属于当前任务")
    content_hash = str(evidence.content_hash or "").strip()
    if not content_hash:
        content_hash = hashlib.sha256(
            json.dumps(
                {"preview": evidence.preview or {}, "metadata": evidence.metadata_json or {}},
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        evidence.content_hash = content_hash

    session.add(evidence)
    await session.flush()
    duplicate = await session.scalar(
        select(func.count())
        .select_from(RawEvidence)
        .where(
            signal_evidence_filter(signal.id),
            RawEvidence.content_hash == content_hash,
            RawEvidence.id != evidence.id,
        )
    )
    if duplicate:
        # Keep the complete capture at task level, but do not append the same
        # evidence hash to the signal for a second time.
        return False

    already_linked = bool(
        await session.scalar(
            select(func.count())
            .select_from(MissedSignalEvidence)
            .where(
                MissedSignalEvidence.missed_signal_id == signal.id,
                MissedSignalEvidence.evidence_id == evidence.id,
            )
        )
    )
    # A legacy row can be directly linked without a link-table row when this
    # function is first called on an old database.  Preserve its historical
    # evidence_count semantics while promoting the association.
    direct_legacy_link = evidence.missed_signal_id == signal.id
    linked_before = int(
        await session.scalar(
            select(func.count())
            .select_from(RawEvidence)
            .where(signal_evidence_filter(signal.id))
        )
        or 0
    )
    historically_counted = direct_legacy_link and linked_before <= signal.evidence_count
    if already_linked:
        return False

    evidence.task_id = signal.task_id
    evidence.target_id = evidence.target_id or signal.target_id
    if evidence.missed_signal_id is None:
        # Keep the first/legacy owner for compatibility; the association table
        # is authoritative for additional signals.
        evidence.missed_signal_id = signal.id
    session.add(
        MissedSignalEvidence(
            missed_signal_id=signal.id,
            evidence_id=evidence.id,
        )
    )
    if historically_counted:
        await session.flush()
        return False
    signal.evidence_count += 1
    signal.updated_at = _now()
    session.add(
        _event(
            signal,
            kind="evidence_added",
            payload={"evidence_id": evidence.id, "content_hash": content_hash},
        )
    )
    if signal.status == "rejected":
        signal.status = "pending"
        signal.rejected_at = None
        session.add(
            _event(
                signal,
                kind="reopened",
                from_status="rejected",
                to_status="pending",
                reason="检测到与驳回时不同的新证据",
                payload={"content_hash": content_hash},
            )
        )
    await session.flush()
    return True


async def upsert_signal(
    session: AsyncSession,
    *,
    task_id: str,
    target_id: str | None,
    candidate: SignalCandidate,
    evidence: RawEvidence | None = None,
    evidence_hash: str = "",
    source_finding_id: str | None = None,
) -> MissedSignal:
    """Insert or update one candidate without committing the caller's transaction."""
    if not task_id or not candidate.rule_key or not candidate.endpoint_key:
        raise SignalValidationError("task_id、rule_key 和 endpoint_key 不能为空")
    dedup = _dedup_key(task_id, target_id, candidate)
    signal = (
        await session.scalars(select(MissedSignal).where(MissedSignal.dedup_key == dedup))
    ).one_or_none()
    created = signal is None
    now = _now()
    if created:
        signal = MissedSignal(
            task_id=task_id,
            target_id=target_id,
            source_finding_id=source_finding_id,
            dedup_key=dedup,
            rule_key=candidate.rule_key[:80],
            rule_label=candidate.rule_label[:200],
            method=candidate.method[:16].upper(),
            endpoint_key=candidate.endpoint_key[:1000],
            title=candidate.title[:500],
            summary=candidate.summary,
            risk_level=candidate.risk_level[:20],
            risk_score=float(candidate.risk_score),
            source_types=[candidate.source_type] if candidate.source_type else [],
            status="pending",
            hit_count=1,
            evidence_count=0,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(signal)
        await session.flush()
        session.add(_event(signal, kind="created", to_status="pending"))
    else:
        signal.hit_count += 1
        signal.last_seen_at = now
        signal.updated_at = now
        if candidate.source_type and candidate.source_type not in (signal.source_types or []):
            signal.source_types = [*(signal.source_types or []), candidate.source_type]
        if candidate.risk_score > signal.risk_score:
            signal.risk_score = float(candidate.risk_score)
            signal.risk_level = candidate.risk_level[:20]
        if candidate.summary:
            signal.summary = candidate.summary
        if source_finding_id and not signal.source_finding_id:
            signal.source_finding_id = source_finding_id

    effective_hash = str(
        (evidence.content_hash if evidence is not None else "") or evidence_hash or ""
    ).strip()
    added_evidence = (
        await register_signal_evidence(session, signal, evidence)
        if evidence is not None
        else False
    )
    if not created and not added_evidence:
        session.add(
            _event(
                signal,
                kind="seen_again",
                payload={"content_hash": effective_hash} if effective_hash else {},
            )
        )

    await session.flush()
    return signal


async def reject_signal(
    session: AsyncSession,
    signal_id: str,
    *,
    reason: str,
    actor_role: str = "full",
) -> MissedSignal:
    signal = await get_signal(session, signal_id)
    cleaned = str(reason or "").strip()
    if not cleaned:
        raise SignalValidationError("驳回原因不能为空")
    if signal.status == "converted":
        raise InvalidSignalTransitionError("已转报告的信号不能驳回")
    if signal.status == "rejected":
        return signal
    previous = signal.status
    signal.status = "rejected"
    signal.last_rejection_reason = cleaned
    signal.rejected_at = _now()
    signal.updated_at = _now()
    session.add(
        _event(
            signal,
            kind="rejected",
            actor_role=actor_role,
            from_status=previous,
            to_status="rejected",
            reason=cleaned,
        )
    )
    await session.flush()
    return signal


async def restore_signal(
    session: AsyncSession,
    signal_id: str,
    *,
    actor_role: str = "full",
) -> MissedSignal:
    signal = await get_signal(session, signal_id)
    if signal.status == "pending":
        return signal
    if signal.status != "rejected":
        raise InvalidSignalTransitionError("只有已驳回信号可以恢复")
    signal.status = "pending"
    signal.rejected_at = None
    signal.updated_at = _now()
    session.add(
        _event(
            signal,
            kind="restored",
            actor_role=actor_role,
            from_status="rejected",
            to_status="pending",
            reason="人工恢复",
        )
    )
    await session.flush()
    return signal


async def queue_signal_deepening(
    session: AsyncSession,
    signal_id: str,
    *,
    directive: str,
    actor_role: str = "full",
) -> MissedSignal:
    signal = await get_signal(session, signal_id)
    cleaned = str(directive or "").strip()
    if not cleaned:
        raise SignalValidationError("深挖指令不能为空")
    if signal.deepen_count >= MAX_DEEPEN_COUNT:
        raise InvalidSignalTransitionError(f"每条疑似信号最多深挖 {MAX_DEEPEN_COUNT} 次")
    if signal.status != "pending":
        raise InvalidSignalTransitionError("只有待复核信号可以加入深挖队列")
    target = await session.get(Target, signal.target_id) if signal.target_id else None
    if target is None or target.task_id != signal.task_id:
        raise InvalidSignalTransitionError("原目标不存在，无法加入深挖队列")
    attempt_token = uuid.uuid4().hex
    signal.status = "deepening"
    signal.deepen_phase = "queued"
    signal.deepen_directive = cleaned
    signal.deepen_error = ""
    signal.deepen_count += 1
    signal.updated_at = _now()
    previous_context = dict(target.deepen_context or {})
    context = {
        **previous_context,
        "missed_signal_id": signal.id,
        "directive": cleaned,
        "source": "missed_signal",
        "signal_deepen_count": signal.deepen_count,
        "attempt_token": attempt_token,
    }
    inflight = Target.status.in_(("assigned", "scanning"))
    # One atomic write creates a pending intent.  An in-flight worker keeps its
    # lease until it exits; terminal/idle targets enter the existing queue now.
    await session.execute(
        update(Target)
        .where(Target.id == target.id, Target.task_id == signal.task_id)
        .values(
            deepen_context=context,
            status=case((inflight, Target.status), else_="queued"),
            verdict=case((inflight, Target.verdict), else_=""),
            assigned_worker=case((inflight, Target.assigned_worker), else_=""),
            heartbeat_at=case((inflight, Target.heartbeat_at), else_=None),
            last_error=case((inflight, Target.last_error), else_=""),
            dead_reason=case((inflight, Target.dead_reason), else_=""),
            priority_score=func.coalesce(Target.priority_score, 0.0) + 100.0,
            priority_reason=f"[疑似深挖#{signal.deepen_count}] {cleaned[:80]}",
        )
    )
    session.add(
        _event(
            signal,
            kind="deepening_queued",
            actor_role=actor_role,
            from_status="pending",
            to_status="deepening",
            reason=cleaned,
            payload={
                "attempt": signal.deepen_count,
                "phase": "queued",
                "attempt_token": attempt_token,
            },
        )
    )
    await session.flush()
    return signal


async def finish_signal_deepening(
    session: AsyncSession,
    signal_id: str,
    *,
    error: str = "",
) -> MissedSignal:
    signal = await get_signal(session, signal_id)
    if signal.status != "deepening":
        raise InvalidSignalTransitionError("信号当前不在深挖中")
    signal.status = "pending"
    signal.deepen_phase = ""
    signal.deepen_error = str(error or "")
    signal.updated_at = _now()
    session.add(
        _event(
            signal,
            kind="deepening_finished",
            from_status="deepening",
            to_status="pending",
            reason=signal.deepen_error,
            payload={"attempt": signal.deepen_count},
        )
    )
    await session.flush()
    return signal


def _request_method(raw_request: str) -> str:
    match = re.match(r"\s*([A-Z]+)\s+", raw_request or "", re.I)
    return match.group(1).upper() if match else "GET"


async def record_archived_review(
    session: AsyncSession,
    finding: Finding,
    review: Review,
) -> MissedSignal | None:
    if review.verdict not in {"ignored", "deepen"}:
        return None
    method = _request_method(finding.raw_request)
    reasons = review.ignore_reasons or []
    summary = review.deepen_directive or review.reviewer_notes or "；".join(map(str, reasons))
    candidate = SignalCandidate(
        rule_key="archived_review",
        rule_label="AI 未采纳或要求深挖",
        method=method,
        endpoint_key=canonical_endpoint(method, finding.target_url),
        title=finding.title,
        summary=summary or finding.description,
        risk_level="medium",
        risk_score=float(review.score or 0),
        source_type="archived_review",
    )
    return await upsert_signal(
        session,
        task_id=finding.task_id,
        target_id=finding.target_id,
        candidate=candidate,
        source_finding_id=finding.id,
    )


async def _absolute_target_url(session: AsyncSession, target_id: str | None, endpoint: str) -> str:
    if urlsplit(endpoint).scheme:
        return endpoint
    if target_id:
        target = await session.get(Target, target_id)
        if target:
            return urljoin(target.url.rstrip("/") + "/", endpoint)
    return endpoint


async def record_deepen_lead(
    session: AsyncSession,
    *,
    task_id: str,
    target_id: str | None,
    lead: str,
    endpoint: str = "",
) -> MissedSignal | None:
    cleaned = str(lead or "").strip()
    if not cleaned:
        return None
    absolute = await _absolute_target_url(session, target_id, endpoint or "/")
    candidate = SignalCandidate(
        rule_key="deepen_lead",
        rule_label="定向深挖线索",
        method="GET",
        endpoint_key=canonical_endpoint("GET", absolute),
        title="Worker 留下可执行的定向深挖线索",
        summary=cleaned,
        risk_level="high",
        risk_score=7.0,
        source_type="deepen_lead",
    )
    return await upsert_signal(
        session, task_id=task_id, target_id=target_id, candidate=candidate
    )


async def record_coverage_gap(
    session: AsyncSession,
    *,
    task_id: str,
    target_id: str | None,
    gap: Mapping[str, Any],
) -> MissedSignal | None:
    if not isinstance(gap, Mapping) or gap.get("actionable") is not True:
        return None
    endpoint = str(gap.get("endpoint") or gap.get("url") or "").strip()
    reason = str(gap.get("reason") or gap.get("summary") or "").strip()
    if not endpoint or not reason:
        return None
    method = str(gap.get("method") or "GET").upper()
    absolute = await _absolute_target_url(session, target_id, endpoint)
    candidate = SignalCandidate(
        rule_key="coverage_gap",
        rule_label="高价值攻击面覆盖遗漏",
        method=method,
        endpoint_key=canonical_endpoint(method, absolute),
        title=str(gap.get("title") or "高价值接口尚未完成验证"),
        summary=reason,
        risk_level=str(gap.get("risk_level") or "medium"),
        risk_score=float(gap.get("risk_score") or 5.0),
        source_type="coverage_gap",
    )
    return await upsert_signal(
        session, task_id=task_id, target_id=target_id, candidate=candidate
    )


async def mark_matching_signals_converted(
    session: AsyncSession,
    finding: Finding,
) -> list[str]:
    method = _request_method(finding.raw_request)
    endpoint = canonical_endpoint(method, finding.target_url)
    rows = list(
        await session.scalars(
            select(MissedSignal).where(
                MissedSignal.task_id == finding.task_id,
                MissedSignal.target_id == finding.target_id,
                MissedSignal.endpoint_key == endpoint,
                MissedSignal.status != "converted",
            )
        )
    )
    now = _now()
    for signal in rows:
        previous = signal.status
        signal.status = "converted"
        signal.converted_finding_id = finding.id
        signal.converted_at = now
        signal.updated_at = now
        session.add(
            _event(
                signal,
                kind="converted",
                from_status=previous,
                to_status="converted",
                reason="真实 Finding 已持久化",
                payload={"finding_id": finding.id},
            )
        )
    await session.flush()
    return [signal.id for signal in rows]


def _legacy_evidence(finding: Finding) -> tuple[RawEvidence, list[RawEvidenceChunk]]:
    values = {
        "request": (finding.raw_request or "").encode("utf-8"),
        "response": (finding.raw_response or "").encode("utf-8"),
    }
    values = {name: data for name, data in values.items() if data}
    channels = {
        name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "chunks": 1}
        for name, data in values.items()
    }
    combined = hashlib.sha256(
        json.dumps(channels, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    evidence_id = uuid.uuid5(uuid.NAMESPACE_URL, f"autohunter:archived:{finding.id}").hex
    evidence = RawEvidence(
        id=evidence_id,
        task_id=finding.task_id,
        target_id=finding.target_id,
        source_kind="archived_backfill",
        capture_status="legacy_partial",
        metadata_json={
            "legacy_partial": True,
            "source_finding_id": finding.id,
            "channels": channels,
            "import_complete": True,
        },
        preview={
            "title": finding.title,
            "description": finding.description,
            "note": "仅回填旧 Finding 已保存的请求响应；未推断已丢失的工具输出。",
        },
        content_hash=combined,
        occurred_at=finding.created_at,
    )
    chunks = [
        RawEvidenceChunk(evidence_id=evidence_id, channel=name, seq=0, data=data)
        for name, data in values.items()
    ]
    return evidence, chunks


async def backfill_archived_signals(
    session: AsyncSession,
    *,
    task_id: str | None = None,
    limit: int = 200,
) -> int:
    """Idempotently backfill currently archived Findings without inventing evidence."""
    limit = max(1, min(int(limit or 200), 1000))
    query = (
        select(Finding, Review)
        .join(Review, Review.finding_id == Finding.id)
        .where(
            Review.verdict.in_(["ignored", "deepen"]),
            Review.user_status == "pending",
            Finding.status != "superseded",
        )
        .order_by(Finding.created_at.asc())
    )
    if task_id:
        query = query.where(Finding.task_id == task_id)
    rows = (await session.execute(query.limit(limit))).all()
    created = 0
    for finding, review in rows:
        signal = (
            await session.scalars(
                select(MissedSignal)
                .where(
                    MissedSignal.source_finding_id == finding.id,
                    MissedSignal.rule_key == "archived_review",
                )
            )
        ).one_or_none()
        evidence, chunks = _legacy_evidence(finding)
        if await session.get(RawEvidence, evidence.id) is not None:
            continue
        method = _request_method(finding.raw_request)
        candidate = SignalCandidate(
            rule_key="archived_review",
            rule_label="AI 未采纳或要求深挖",
            method=method,
            endpoint_key=canonical_endpoint(method, finding.target_url),
            title=finding.title,
            summary=review.deepen_directive
            or review.reviewer_notes
            or "；".join(map(str, review.ignore_reasons or []))
            or finding.description,
            risk_level="medium",
            risk_score=float(review.score or 0),
            source_type="archived_review",
        )
        session.add(evidence)
        if signal is None:
            signal = await upsert_signal(
                session,
                task_id=finding.task_id,
                target_id=finding.target_id,
                candidate=candidate,
                evidence=evidence,
                source_finding_id=finding.id,
            )
        else:
            await register_signal_evidence(session, signal, evidence)
        session.add_all(chunks)
        await session.flush()
        created += 1
    return created


__all__ = [
    "MAX_DEEPEN_COUNT",
    "InvalidSignalTransitionError",
    "MissedSignalError",
    "SignalCandidate",
    "SignalNotFoundError",
    "SignalValidationError",
    "backfill_archived_signals",
    "canonical_endpoint",
    "detect_tool_signals",
    "finish_signal_deepening",
    "get_signal",
    "mark_matching_signals_converted",
    "queue_signal_deepening",
    "register_signal_evidence",
    "record_archived_review",
    "record_coverage_gap",
    "record_deepen_lead",
    "reject_signal",
    "restore_signal",
    "upsert_signal",
]
