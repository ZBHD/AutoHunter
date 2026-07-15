"""Pure, bounded state for candidates discovered by SRC tooling."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import math
import re
from typing import Iterable, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


MAX_PUBLIC_TEXT = 160
MAX_REFERENCES = 32
MAX_VERIFY_ATTEMPTS = 2

_KINDS = {"endpoint", "parameter", "fingerprint", "service", "hypothesis"}
_LOCATIONS = {"path", "query", "body", "header", "cookie", "fragment", "unknown"}
_STATUSES = {"pending", "verified", "failed", "inconclusive", "skipped"}
_INCONCLUSIVE_OUTCOMES = {"timeout", "network", "insufficient", "inconclusive"}
_METHOD_PREFIX = re.compile(r"^(?P<method>[A-Za-z]+)\s+(?P<target>.+)$")


def _raw_text(value: object) -> str:
    """Normalize control/whitespace without truncating before parsing."""

    return " ".join(str(value or "").replace("\x00", " ").split())


def _text(value: object, limit: int = MAX_PUBLIC_TEXT) -> str:
    text = _raw_text(value)
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 3)].rstrip() + "..."


def _query_names(query: str) -> str:
    """Retain query names for verification while dropping their values."""

    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        pairs = []
    if not pairs:
        pairs = [(part.split("=", 1)[0], "") for part in query.split("&") if part]
    normalized = {_text(name, 64) for name, _ in pairs if _text(name, 64)}
    names = [(name, "") for name in sorted(normalized, key=lambda item: (item.lower(), item))]
    return urlencode(names, doseq=True)


def _strip_bare_userinfo(path: str) -> str:
    """Drop ``user:password@`` when a URL lacks an explicit authority marker."""

    if "@" not in path:
        return path
    prefix, suffix = path.rsplit("@", 1)
    if prefix and "/" not in prefix and re.fullmatch(r"[^/@:?#\s]+(?::[^/@?#\s]*)?", prefix):
        return suffix
    return path


_PATH_USERINFO = re.compile(r"(?:(?<=/)|^)[^/@:?#\s]+(?::[^/@?#\s]*)?@")


def _scrub_path_userinfo(path: str) -> str:
    """Remove credential-like ``name:value@`` segments from malformed paths."""

    return _PATH_USERINFO.sub("", path)


def _normalize_opaque_scheme(raw: str) -> str:
    """Turn malformed ``scheme:authority`` spellings into parseable URLs."""

    match = re.match(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*:)(?P<rest>.*)$", raw)
    if not match:
        return raw
    scheme = match.group("scheme").lower()
    if scheme not in {"http:", "https:"}:
        return raw
    rest = match.group("rest")
    if rest.startswith("//"):
        # Collapse excess slashes so ``https:////user:pass@host`` still gets
        # parsed as an authority and has its userinfo removed.
        return f"{scheme}//{rest.lstrip('/')}"

    if rest.startswith("/"):
        # A single slash is another common malformed spelling of an authority.
        stripped = rest.lstrip("/")
        authority, separator, tail = stripped.partition("/")
        if "@" in authority:
            userinfo, host = authority.rsplit("@", 1)
            if userinfo:
                return f"{scheme}//{host}" + (f"/{tail}" if separator else "")

    authority, separator, tail = rest.partition("/")
    if "@" in authority:
        userinfo, host = authority.rsplit("@", 1)
        if userinfo:
            return f"{scheme}//{host}" + (f"/{tail}" if separator else "")
    return raw


def _split_http_method_target(raw: str) -> tuple[str, str]:
    """Split only a recognized HTTP method followed by a URL-like target."""

    match = _METHOD_PREFIX.match(raw)
    if not match:
        return "", raw
    method = match.group("method").upper()
    target = match.group("target")
    looks_like_url = (
        target.startswith("/")
        or re.match(r"^https?://", target, re.IGNORECASE) is not None
        or re.match(r"^https?:", target, re.IGNORECASE) is not None
    )
    return (method, target) if looks_like_url else ("", raw)


def _fallback_public(raw: str) -> str:
    """Best-effort sanitization for malformed URL authorities."""

    no_fragment = raw.split("#", 1)[0]
    path, separator, query = no_fragment.partition("?")
    authority_match = re.match(
        r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*:)?//(?P<authority>[^/]*)(?P<path>/.*)?$",
        path,
    )
    if authority_match:
        authority = authority_match.group("authority").rsplit("@", 1)[-1]
        if authority.startswith("["):
            closing = authority.find("]")
            host = authority[: closing + 1] if closing >= 0 else authority.split(":", 1)[0]
        else:
            host = authority.split(":", 1)[0]
        scheme = (authority_match.group("scheme") or "").lower()
        prefix = f"{scheme}//" if scheme else "//"
        clean = f"{prefix}{host.lower()}{authority_match.group('path') or ''}"
    else:
        clean = _strip_bare_userinfo(path)
    clean = _scrub_path_userinfo(clean)
    if separator:
        clean += f"?{_query_names(query)}"
    return _text(clean)


def _public_value(
    value: object,
    *,
    expected_method: str | None = None,
    strip_any_method: bool = False,
) -> str:
    """Bound a URL/path and remove userinfo, fragments, and query values."""

    raw = _raw_text(value)
    if not raw:
        return ""
    method_token, target = _split_http_method_target(raw)
    if method_token and (strip_any_method or expected_method is None or method_token == expected_method.upper()):
        raw = target
    raw = _normalize_opaque_scheme(raw)
    try:
        parsed = urlsplit(raw)
    except ValueError:
        sanitized = _fallback_public(raw)
        return _text(sanitized)
    if not parsed.netloc:
        if "?" not in raw:
            path = _scrub_path_userinfo(_strip_bare_userinfo(raw.split("#", 1)[0]))
            return _text(path)
        path, query = raw.split("?", 1)
        clean_path = _scrub_path_userinfo(_strip_bare_userinfo(path.split('#', 1)[0]))
        sanitized = f"{clean_path}?{_query_names(query)}"
        return _text(sanitized)

    scheme = parsed.scheme.lower()
    try:
        host = (parsed.hostname or "").lower()
    except ValueError:
        return _text(_fallback_public(raw))
    try:
        port = parsed.port
    except ValueError:
        # A malformed port is discarded rather than exposing authority text.
        port = None
    if not host:
        return _text(_fallback_public(raw))
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    sanitized = urlunsplit((scheme, host, _scrub_path_userinfo(parsed.path), _query_names(parsed.query), ""))
    return _text(sanitized)


def _parameter_name(value: object) -> str:
    raw = _text(value, 80)
    # Scanner output occasionally includes a sample assignment or header
    # fragment.  Keep only the parameter name, never its value.
    name = re.split(r"[=&;?#:\s]+", raw, maxsplit=1)[0]
    return _text(name.strip("[](){}\"'"), 80)


def _method(value: object) -> str:
    return _text(value, 16).upper() or "GET"


def _endpoint_key(value: object, method: str) -> str:
    raw = _raw_text(value)
    method_token, target = _split_http_method_target(raw)
    if method_token:
        return _text(f"{method} {_public_value(target)}")
    return _text(_public_value(raw, expected_method=method))


def _confidence(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        number = 0.0
    if not math.isfinite(number):
        number = 0.0
    return round(min(1.0, max(0.0, number)), 4)


def _priority(value: object) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        number = 0
    return min(10, max(0, number))


def _round(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def _unique(values: Iterable[object]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        item = _text(value, 96)
        if item and item not in result:
            result.append(item)
        if len(result) >= MAX_REFERENCES:
            break
    return tuple(result)


@dataclass(frozen=True)
class SrcCandidate:
    kind: Literal["endpoint", "parameter", "fingerprint", "service", "hypothesis"]
    endpoint_key: str
    value: str
    method: str
    parameter: str
    location: str
    status_code: int | None
    confidence: float
    priority: int
    reason: str

    def __post_init__(self) -> None:
        kind = _text(self.kind, 32).lower()
        kind = {
            "path_candidate": "endpoint",
            "scanner_candidate": "hypothesis",
            "xss_candidate": "hypothesis",
        }.get(kind, kind)
        if kind not in _KINDS:
            raise ValueError(f"unsupported SRC candidate kind: {kind or '<empty>'}")

        method = _method(self.method)
        location = _text(self.location, 24).lower() or "unknown"
        try:
            status_code = int(self.status_code) if self.status_code is not None and not isinstance(self.status_code, bool) else None
        except (TypeError, ValueError, OverflowError):
            status_code = None
        if status_code is not None and not 100 <= status_code <= 599:
            status_code = None

        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "endpoint_key", _endpoint_key(self.endpoint_key, method))
        object.__setattr__(
            self,
            "value",
            _text(
                _public_value(
                    self.value,
                    expected_method=method,
                    strip_any_method=kind in {"endpoint", "parameter", "service"},
                )
            ),
        )
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "parameter", _parameter_name(self.parameter))
        object.__setattr__(self, "location", location if location in _LOCATIONS else "unknown")
        object.__setattr__(self, "status_code", status_code)
        object.__setattr__(self, "confidence", _confidence(self.confidence))
        object.__setattr__(self, "priority", _priority(self.priority))
        object.__setattr__(self, "reason", _text(self.reason))


def lead_key(candidate: SrcCandidate) -> tuple[str, str, str, str, str]:
    return (
        candidate.kind,
        candidate.endpoint_key,
        candidate.method,
        candidate.parameter,
        candidate.location,
    )


def _lead_id(key: tuple[str, str, str, str, str]) -> str:
    digest = hashlib.sha256("\x1f".join(key).encode("utf-8", "replace")).hexdigest()
    return f"lead-{digest[:24]}"


def _verify_action(candidate: SrcCandidate) -> str:
    endpoint = candidate.endpoint_key
    prefix = f"{candidate.method} "
    if endpoint.upper().startswith(prefix.upper()):
        endpoint = endpoint[len(prefix):]
    if candidate.kind == "parameter":
        return _text(
            f"Verify {candidate.method} {endpoint} "
            f"parameter {candidate.parameter} ({candidate.location})"
        )
    return _text(f"Verify {candidate.method} {candidate.value or endpoint}")


@dataclass
class Lead:
    id: str
    kind: str
    endpoint_key: str
    value: str
    method: str
    parameter: str
    location: str
    sources: tuple[str, ...]
    capture_ids: tuple[str, ...]
    confidence: float
    priority: int
    status: Literal["pending", "verified", "failed", "inconclusive", "skipped"]
    verify_action: str
    attempt_count: int
    created_round: int
    last_attempt_round: int | None
    resolution_reason: str
    evidence_ids: tuple[str, ...]
    vulnerability_confirmed: bool = False

    @property
    def identity_key(self) -> tuple[str, str, str, str, str]:
        return (self.kind, self.endpoint_key, self.method, self.parameter, self.location)

    @classmethod
    def from_candidate(cls, candidate: SrcCandidate, round_no: int, capture_id: str = "") -> "Lead":
        key = lead_key(candidate)
        return cls(
            id=_lead_id(key),
            kind=candidate.kind,
            endpoint_key=candidate.endpoint_key,
            value=candidate.value,
            method=candidate.method,
            parameter=candidate.parameter,
            location=candidate.location,
            sources=_unique((candidate.reason,)),
            capture_ids=_unique((capture_id,)),
            confidence=candidate.confidence,
            priority=candidate.priority,
            status="pending",
            verify_action=_verify_action(candidate),
            attempt_count=0,
            created_round=_round(round_no),
            last_attempt_round=None,
            resolution_reason="",
            evidence_ids=(),
        )


def merge_candidate(lead: Lead, candidate: SrcCandidate, capture_id: str = "", source_tool: str = "") -> Lead:
    if lead.identity_key != lead_key(candidate):
        raise ValueError("candidate identity does not match lead")
    lead.sources = _unique((*lead.sources, source_tool or candidate.reason))
    lead.capture_ids = _unique((*lead.capture_ids, capture_id))
    lead.confidence = max(lead.confidence, candidate.confidence)
    lead.priority = max(lead.priority, candidate.priority)
    return lead


def resolve_lead(
    lead: Lead,
    *,
    outcome: str,
    round_no: int,
    evidence_id: str = "",
    reason: str = "",
) -> Lead:
    normalized = _text(outcome, 24).lower()
    allowed_outcomes = (_STATUSES - {"pending"}) | _INCONCLUSIVE_OUTCOMES
    if normalized not in allowed_outcomes:
        raise ValueError(f"unsupported lead outcome: {outcome}")
    if evidence_id:
        lead.evidence_ids = _unique((*lead.evidence_ids, evidence_id))
    if lead.status in {"verified", "failed", "skipped"}:
        return lead

    lead.attempt_count += 1
    lead.last_attempt_round = _round(round_no)
    if normalized in _INCONCLUSIVE_OUTCOMES:
        lead.status = "skipped" if lead.attempt_count >= MAX_VERIFY_ATTEMPTS else "inconclusive"
    else:
        lead.status = normalized  # type: ignore[assignment]
    lead.resolution_reason = _text(reason) or normalized
    return lead


@dataclass(frozen=True)
class LeadSummary:
    counts: dict[str, int]
    deepen_lead: str
    samples: tuple[str, ...]


def finalize_leads(
    leads: Iterable[Lead],
    *,
    reason: str,
    round_no: int,
    high_priority: int = 8,
) -> LeadSummary:
    items = list(leads)
    actionable = [
        lead
        for lead in items
        if lead.priority >= high_priority and lead.status in {"pending", "inconclusive"}
    ]
    actionable.sort(key=lambda lead: (-lead.priority, lead.created_round, lead.id))

    final_reason = _text(reason) or "finalized"
    for lead in items:
        if lead.status in {"pending", "inconclusive"}:
            lead.status = "skipped"
            lead.last_attempt_round = _round(round_no)
            lead.resolution_reason = final_reason

    return LeadSummary(
        counts=dict(Counter(lead.status for lead in items)),
        deepen_lead=_text(actionable[0].verify_action) if actionable else "",
        samples=tuple(_text(_public_value(lead.value)) for lead in items[:3]),
    )


__all__ = [
    "Lead",
    "LeadSummary",
    "SrcCandidate",
    "finalize_leads",
    "lead_key",
    "merge_candidate",
    "resolve_lead",
]
