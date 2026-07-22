"""LiteLLM 网关发现链路共用的结构化值对象。"""
from __future__ import annotations

from datetime import datetime
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator


JsonScalar: TypeAlias = str | int | float | bool | None
ScopeMode: TypeAlias = Literal["targeted", "global"]
SignatureStrength: TypeAlias = Literal["low", "medium", "high"]
FingerprintStatus: TypeAlias = Literal["confirmed", "probable", "rejected"]
ProbeCategory: TypeAlias = Literal[
    "public", "models", "model_info", "inference", "readonly_admin"
]


class GatewayValue(BaseModel):
    """默认严格且不可变，防止扫描阶段悄然改写规划输入。"""

    model_config = ConfigDict(extra="forbid", frozen=True)


class GatewayCandidate(GatewayValue):
    source_engine: str
    source_query_id: str
    discovered_url: str
    host: str
    ip: str = ""
    port: int | None = Field(default=None, ge=1, le=65535)
    title: str = ""
    server: str = ""
    certificate: str = ""
    organization: str = ""
    body_snippet: str = ""


class HttpObservation(GatewayValue):
    path: str
    status_code: int = Field(ge=100, le=599)
    content_type: str = ""
    body: str = ""
    method: Literal["GET", "HEAD", "POST"] = "GET"
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    redirect_url: str | None = None

    @field_validator("method", mode="before")
    @classmethod
    def _uppercase_method(cls, value: object) -> str:
        return str(value or "GET").upper()


class SearchSignature(GatewayValue):
    signature_id: str
    signal_kind: Literal["body", "header", "route", "response_schema", "combined"]
    engine_clauses: dict[str, str]
    strength: SignatureStrength
    enabled_by_default: bool = True

    @field_validator("engine_clauses")
    @classmethod
    def _non_empty_clauses(cls, value: dict[str, str]) -> dict[str, str]:
        normalized = {
            str(engine).strip().lower(): str(clause).strip()
            for engine, clause in value.items()
            if str(engine).strip() and str(clause).strip()
        }
        if not normalized:
            raise ValueError("engine_clauses must contain at least one query")
        return normalized


class ProbeSpec(GatewayValue):
    probe_id: str
    method: Literal["GET", "HEAD", "POST"]
    path: str
    category: ProbeCategory
    public_by_design: bool = False
    finding_eligible: bool = True
    read_only: bool = True
    request_json: dict[str, JsonValue] | None = None
    accepted_content_types: tuple[str, ...] = ()


class FingerprintSignal(GatewayValue):
    probe_id: str
    signal_kind: Literal["body", "header", "response_schema", "combined"]
    strength: SignatureStrength
    detail: str
    public_by_design: bool = False


class FingerprintResult(GatewayValue):
    status: FingerprintStatus
    confidence: float = Field(ge=0, le=1)
    signals: tuple[FingerprintSignal, ...] = ()
    public_only: bool = False
    finding_eligible: bool = False
    detected_version: str = ""


class ScopeAnchor(GatewayValue):
    kind: Literal["domain", "organization", "certificate", "brand"]
    value: str

    @field_validator("value")
    @classmethod
    def _trim_non_empty_value(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            raise ValueError("anchor value must not be empty")
        return normalized


class QueryFamilyState(GatewayValue):
    cursor: int = Field(default=0, ge=0)
    opaque_engine_cursor: str | int | None = None
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    empty_streak: int = Field(default=0, ge=0)
    failure_count: int = Field(default=0, ge=0)
    backoff_until: datetime | None = None


class QueryPlan(GatewayValue):
    query: str
    cursor_key: str
    engine: str
    profile_id: str
    profile_version: str
    signature_id: str
    scope_hash: str
    cursor: int = Field(ge=1)
    current_state: QueryFamilyState
    next_state: QueryFamilyState


__all__ = [
    "FingerprintResult",
    "FingerprintSignal",
    "FingerprintStatus",
    "GatewayCandidate",
    "HttpObservation",
    "JsonScalar",
    "JsonValue",
    "ProbeCategory",
    "ProbeSpec",
    "QueryFamilyState",
    "QueryPlan",
    "ScopeAnchor",
    "ScopeMode",
    "SearchSignature",
    "SignatureStrength",
]
