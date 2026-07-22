"""LiteLLM 网关发现链路共用的结构化值对象。"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal, TypeAlias, TypeVar, cast

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
)


JsonScalar: TypeAlias = str | int | float | bool | None
ScopeMode: TypeAlias = Literal["targeted", "global"]
SignatureStrength: TypeAlias = Literal["low", "medium", "high"]
FingerprintStatus: TypeAlias = Literal["confirmed", "probable", "rejected"]
ProbeCategory: TypeAlias = Literal[
    "public", "models", "model_info", "inference", "readonly_admin"
]

_Key = TypeVar("_Key")
_Value = TypeVar("_Value")


class FrozenDict(dict[_Key, _Value]):
    """可序列化、可深拷贝，但所有常规写操作都明确失败的字典。"""

    def _immutable(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FrozenDict is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __copy__(self) -> "FrozenDict[_Key, _Value]":
        return self

    def __deepcopy__(
        self,
        _memo: dict[int, object],
    ) -> "FrozenDict[_Key, _Value]":
        return self

    def copy(self) -> "FrozenDict[_Key, _Value]":
        return self


class FrozenList(list[_Value]):
    """保留 JSON list 序列化语义的只读列表。"""

    def _immutable(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FrozenList is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable

    def __copy__(self) -> "FrozenList[_Value]":
        return self

    def __deepcopy__(
        self,
        _memo: dict[int, object],
    ) -> "FrozenList[_Value]":
        return self

    def copy(self) -> "FrozenList[_Value]":
        return self


def _deep_freeze(value: object) -> object:
    if isinstance(value, dict):
        return FrozenDict(
            {
                key: _deep_freeze(child)
                for key, child in value.items()
            }
        )
    if isinstance(value, list):
        return FrozenList(_deep_freeze(child) for child in value)
    if isinstance(value, tuple):
        return tuple(_deep_freeze(child) for child in value)
    return value


class SuccessMatcher(StrEnum):
    EXACT_ALIVE_TEXT = "exact_alive_text"
    MODELS_JSON = "models_json"
    MODEL_INFO_JSON = "model_info_json"
    OPENAI_CHAT_JSON = "openai_chat_json"
    ADMIN_JSON = "admin_json"


class ModelSchemaKind(StrEnum):
    NONE = "none"
    OPENAI_MODELS = "openai_models"
    LITELLM_MODEL_INFO = "litellm_model_info"


class ResponseCategory(StrEnum):
    PUBLIC_BASELINE = "public_baseline"
    MODELS = "models"
    MODEL_INFO = "model_info"
    INFERENCE = "inference"
    MANAGEMENT = "management"
    AUTH_REQUIRED = "auth_required"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    SERVER_ERROR = "server_error"
    ERROR_RESPONSE = "error_response"
    HTML_RESPONSE = "html_response"
    WAF_RESPONSE = "waf_response"
    INVALID_RESPONSE = "invalid_response"


class GatewayValue(BaseModel):
    """默认严格且不可变，防止扫描阶段悄然改写规划输入。"""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


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
    fingerprint_probe: bool = False
    headers_template: dict[str, str]
    body_template: dict[str, JsonValue] | None = Field(
        default=None,
        validation_alias=AliasChoices("body_template", "request_json"),
    )
    expected_content_types: tuple[str, ...] = Field(
        validation_alias=AliasChoices(
            "expected_content_types",
            "accepted_content_types",
        )
    )
    success_matcher: SuccessMatcher
    request_cost: int = Field(ge=1)

    @field_validator("headers_template")
    @classmethod
    def _freeze_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return cast(dict[str, str], _deep_freeze(value))

    @field_validator("body_template")
    @classmethod
    def _freeze_body(
        cls,
        value: dict[str, JsonValue] | None,
    ) -> dict[str, JsonValue] | None:
        return cast(dict[str, JsonValue] | None, _deep_freeze(value))

    @property
    def request_json(self) -> dict[str, JsonValue] | None:
        """兼容旧调用方；请求正文只存于 body_template。"""

        return self.body_template

    @property
    def accepted_content_types(self) -> tuple[str, ...]:
        """兼容旧调用方；响应类型只存于 expected_content_types。"""

        return self.expected_content_types


class SecretPattern(GatewayValue):
    pattern_id: str
    secret_kind: Literal["master_key", "virtual_key"]
    provider: str
    variable_names: tuple[str, ...] = Field(min_length=1)
    value_prefixes: tuple[str, ...] = Field(min_length=1)
    description: str = ""


class ModelParseResult(GatewayValue):
    valid: bool
    schema_kind: ModelSchemaKind = ModelSchemaKind.NONE
    model_ids: tuple[str, ...] = ()
    reason: str = ""


class ResponseClassification(GatewayValue):
    category: ResponseCategory
    valid: bool
    reason: str
    model_ids: tuple[str, ...] = ()


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
    "FrozenDict",
    "FrozenList",
    "GatewayCandidate",
    "HttpObservation",
    "JsonScalar",
    "JsonValue",
    "ModelParseResult",
    "ModelSchemaKind",
    "ProbeCategory",
    "ProbeSpec",
    "QueryFamilyState",
    "QueryPlan",
    "ResponseCategory",
    "ResponseClassification",
    "ScopeAnchor",
    "ScopeMode",
    "SearchSignature",
    "SecretPattern",
    "SignatureStrength",
    "SuccessMatcher",
]
