"""由版本化 Profile 生成确定性的测绘查询和独立游标。"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence

from app.gateway_hunt.registry import get_profile
from app.gateway_hunt.schemas import (
    QueryFamilyState,
    QueryPlan,
    ScopeAnchor,
    ScopeMode,
)


_ANCHOR_FIELDS: dict[str, dict[str, str]] = {
    "fofa": {
        "domain": "domain",
        "organization": "org",
        "certificate": "cert",
        "brand": "title",
    },
    "quake": {
        "domain": "domain",
        "organization": "service.http.response.headers.server",
        "certificate": "service.tls.handshake_log.server_certificates.certificate.parsed.subject.organization",
        "brand": "service.http.response.html_title",
    },
    "hunter": {
        "domain": "domain",
        "organization": "company",
        "certificate": "cert",
        "brand": "web.title",
    },
    "zoomeye": {
        "domain": "site",
        "organization": "organization",
        "certificate": "ssl",
        "brand": "title",
    },
    "shodan": {
        "domain": "hostname",
        "organization": "org",
        "certificate": "ssl.cert.subject.cn",
        "brand": "http.title",
    },
    "censys": {
        "domain": "dns.names",
        "organization": "services.tls.certificates.leaf_data.subject.organization",
        "certificate": "services.tls.certificates.leaf_data.subject.common_name",
        "brand": "services.http.response.html_title",
    },
}

_OPERATORS = {
    "fofa": ("&&", "||", "="),
    "quake": ("AND", "OR", ":"),
    "hunter": ("&&", "||", "="),
    "zoomeye": ("&&", "||", ":"),
    "shodan": ("AND", "OR", ":"),
    "censys": ("AND", "OR", ":"),
}


def _quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _coerce_anchor(value: ScopeAnchor | str | Mapping[str, str]) -> ScopeAnchor:
    if isinstance(value, ScopeAnchor):
        return value.model_copy(deep=True)
    if isinstance(value, Mapping):
        return ScopeAnchor.model_validate(dict(value))

    raw = str(value or "").strip()
    match = re.fullmatch(
        r"(?i)(domain|org|organization|cert|certificate|brand)\s*:\s*(.+)",
        raw,
    )
    if match:
        aliases = {"org": "organization", "cert": "certificate"}
        kind = aliases.get(match.group(1).lower(), match.group(1).lower())
        return ScopeAnchor(kind=kind, value=match.group(2))
    kind = "domain" if "." in raw and not any(char.isspace() for char in raw) else "organization"
    return ScopeAnchor(kind=kind, value=raw)


def _normalized_anchors(
    anchors: Sequence[ScopeAnchor | str | Mapping[str, str]],
) -> tuple[ScopeAnchor, ...]:
    unique = {
        (anchor.kind, anchor.value): anchor
        for anchor in (_coerce_anchor(value) for value in anchors)
    }
    return tuple(unique[key] for key in sorted(unique))


def _scope_hash(scope_mode: ScopeMode, anchors: Sequence[ScopeAnchor]) -> str:
    scope = [scope_mode, *(f"{anchor.kind}:{anchor.value}" for anchor in anchors)]
    return hashlib.sha256("\n".join(scope).encode("utf-8")).hexdigest()[:12]


def _scope_clause(engine: str, anchors: Sequence[ScopeAnchor]) -> str:
    _and_operator, or_operator, comparison = _OPERATORS[engine]
    fields = _ANCHOR_FIELDS[engine]
    return f" {or_operator} ".join(
        f"{fields[anchor.kind]}{comparison}{_quoted(anchor.value)}"
        for anchor in anchors
    )


def _state_for(
    state: Mapping[str, QueryFamilyState | Mapping[str, object]],
    cursor_key: str,
) -> QueryFamilyState:
    raw = state.get(cursor_key)
    if raw is None:
        return QueryFamilyState()
    if isinstance(raw, QueryFamilyState):
        return raw.model_copy(deep=True)
    return QueryFamilyState.model_validate(dict(raw))


class QueryPlanner:
    def plan(
        self,
        scope_mode: ScopeMode,
        anchors: Sequence[ScopeAnchor | str | Mapping[str, str]],
        engine: str,
        profile_id: str,
        state: Mapping[str, QueryFamilyState | Mapping[str, object]] | None,
    ) -> tuple[QueryPlan, ...]:
        if scope_mode not in {"targeted", "global"}:
            raise ValueError(f"unsupported scope mode: {scope_mode}")
        normalized_engine = str(engine or "").strip().lower()
        if normalized_engine not in _ANCHOR_FIELDS:
            raise ValueError(f"unsupported query engine: {normalized_engine or '<empty>'}")

        normalized_anchors = _normalized_anchors(anchors)
        if scope_mode == "targeted" and not normalized_anchors:
            raise ValueError("targeted query planning requires at least one scope anchor")

        profile = get_profile(profile_id)
        scope_hash = _scope_hash(scope_mode, normalized_anchors)
        input_state = state or {}
        plans: list[QueryPlan] = []
        for signature in profile.search_signatures():
            if not signature.enabled_by_default:
                continue
            if scope_mode == "global" and signature.strength != "high":
                continue
            try:
                product_clause = signature.engine_clauses[normalized_engine]
            except KeyError as exc:
                raise ValueError(
                    f"profile {profile.profile_id}:{profile.version} signature "
                    f"{signature.signature_id} does not support {normalized_engine}"
                ) from exc

            and_operator = _OPERATORS[normalized_engine][0]
            query = f"({product_clause})"
            if scope_mode == "targeted":
                query += (
                    f" {and_operator} "
                    f"({_scope_clause(normalized_engine, normalized_anchors)})"
                )

            cursor_key = (
                f"{normalized_engine}:{profile.profile_id}:{profile.version}:"
                f"{signature.signature_id}:{scope_hash}"
            )
            current = _state_for(input_state, cursor_key)
            next_state = current.model_copy(
                update={"cursor": current.cursor + 1},
                deep=True,
            )
            plans.append(
                QueryPlan(
                    query=query,
                    cursor_key=cursor_key,
                    engine=normalized_engine,
                    profile_id=profile.profile_id,
                    profile_version=profile.version,
                    signature_id=signature.signature_id,
                    scope_hash=scope_hash,
                    cursor=next_state.cursor,
                    current_state=current,
                    next_state=next_state,
                )
            )
        return tuple(plans)


__all__ = ["QueryPlanner"]
