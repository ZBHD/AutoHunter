"""API 请求/响应 DTO。"""
from __future__ import annotations

from typing import Literal, Optional
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from app.agents.prompts import is_litellm_src


LLMProtocol = Literal["openai_chat", "anthropic_messages", "openai_responses"]


def _validated_http_url(value: str) -> str:
    normalized = str(value or "").strip()
    try:
        parsed = urlparse(normalized)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "must be an absolute HTTP(S) URL without credentials or query"
        ) from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or (port is not None and not 1 <= port <= 65535)
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        raise ValueError("must be an absolute HTTP(S) URL without credentials or query")
    return normalized


def validate_litellm_manual_target_url(value: str) -> str:
    """校验 LiteLLM 手动资产 URL；路径和 query 可作为网关挂载线索。"""

    normalized = str(value or "").strip()
    try:
        parsed = urlparse(normalized)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(
            "LiteLLM manual target must be an absolute HTTP(S) URL "
            "without credentials or fragment"
        ) from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or (port is not None and not 1 <= port <= 65535)
        or parsed.username is not None
        or parsed.password is not None
        or "#" in normalized
    ):
        raise ValueError(
            "LiteLLM manual target must be an absolute HTTP(S) URL "
            "without credentials or fragment"
        )
    return normalized


class ModelConfigDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_global_pool: bool = True
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    model: str = "deepseek-chat"
    protocol: LLMProtocol = "openai_chat"
    temperature: float = Field(default=0.3, ge=0, le=2)
    prompt_version: str = ""

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, value: str) -> str:
        normalized = str(value or "").strip()
        return _validated_http_url(normalized) if normalized else ""

    @field_validator("api_key", "model", "prompt_version")
    @classmethod
    def _trim_text(cls, value: str) -> str:
        return str(value or "").strip()


class FofaConfigDTO(BaseModel):
    key: str = ""
    base_url: str = ""
    max_pages: int = 20
    page_size: int = 100
    intent_mode: str = ""
    site_recon_mode: Literal["full", "light"] = "full"


class EngineConfigDTO(BaseModel):
    """多引擎配置。"""
    key: str = ""
    base_url: str = ""


class LiteLlmChecksDTO(BaseModel):
    """LiteLLM 专项检查开关。

    这些开关只影响服务端生成的专项漏洞类型，不接受客户端直接注入通用
    Web 漏洞类型。
    """

    model_config = ConfigDict(extra="forbid")

    key_leak: bool = True
    env_leak: bool = True
    management_exposure: bool = True
    anonymous_models: bool = True
    anonymous_inference: bool = True


class LiteLlmValidationDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: Literal["basic", "full"] = "full"
    max_tokens: int = Field(default=1, ge=1, le=8)
    max_provider_validations_per_cycle: int = Field(default=20, ge=0, le=10000)
    max_requests_per_asset_epoch: int = Field(default=24, ge=1, le=10000)


class LiteLlmRecheckIntervalsDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed_seconds: int = Field(default=21600, ge=0, le=2_592_000)
    protected_seconds: int = Field(default=86400, ge=0, le=2_592_000)
    unreachable_seconds: int = Field(default=3600, ge=0, le=2_592_000)


class LiteLlmModeConfigDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_mode: Literal["targeted", "global"] = "targeted"
    scope_anchors: list[str] = Field(default_factory=list, max_length=100)
    enabled_profiles: list[str] = Field(
        default_factory=lambda: ["litellm"], max_length=10
    )
    profile_versions: dict[str, str] = Field(
        default_factory=lambda: {"litellm": "1"}
    )
    checks: LiteLlmChecksDTO = Field(default_factory=LiteLlmChecksDTO)
    validation: LiteLlmValidationDTO = Field(default_factory=LiteLlmValidationDTO)
    recheck_intervals: LiteLlmRecheckIntervalsDTO = Field(
        default_factory=LiteLlmRecheckIntervalsDTO
    )
    collection_state: dict = Field(default_factory=dict)

    @field_validator("scope_anchors")
    @classmethod
    def _scope_anchors(cls, values: list[str]) -> list[str]:
        normalized = [str(value or "").strip() for value in values]
        if any(not value for value in normalized):
            raise ValueError("scope_anchors must not contain empty values")
        if any(len(value) > 255 for value in normalized):
            raise ValueError("scope_anchors entries must be at most 255 characters")
        return normalized

    @field_validator("enabled_profiles")
    @classmethod
    def _enabled_profiles(cls, values: list[str]) -> list[str]:
        normalized = [str(value or "").strip().lower() for value in values]
        if any(not value for value in normalized):
            raise ValueError("enabled_profiles must not contain empty values")
        return normalized

    @field_validator("profile_versions")
    @classmethod
    def _profile_versions(cls, values: dict[str, str]) -> dict[str, str]:
        return {
            str(profile or "").strip().lower(): str(version or "").strip()
            for profile, version in values.items()
        }


# 保留两种 Python 类名写法，JSON/API 标识统一使用 litellm。
LiteLLMChecksDTO = LiteLlmChecksDTO
LiteLLMValidationDTO = LiteLlmValidationDTO
LiteLLMModeConfigDTO = LiteLlmModeConfigDTO


class CreateTaskRequest(BaseModel):
    name: str
    src_type: str = "edusrc"
    vuln_types: list[str] = Field(default_factory=list)
    src_rules: str = ""
    target_source: str = "fofa"
    engine: str = ""                                           # 搜索引擎：fofa/quake/hunter/...
    fofa_query: str = ""
    hunt_direction: str = Field(default="", max_length=2000)
    manual_targets: list[str] = Field(default_factory=list)
    auth_bindings: list[dict] = Field(default_factory=list)
    model_config_data: ModelConfigDTO = Field(default_factory=ModelConfigDTO)
    fofa_config: FofaConfigDTO = Field(default_factory=FofaConfigDTO)
    engine_config: EngineConfigDTO = Field(default_factory=EngineConfigDTO)  # 引擎 Key/URL
    concurrency: int = 3
    mode_config: LiteLlmModeConfigDTO | None = None

    @field_validator("hunt_direction", mode="before")
    @classmethod
    def _hunt_direction(cls, value: str) -> str:
        return str(value or "").strip()

    @model_validator(mode="after")
    def _validate_litellm_mode(self):
        if is_litellm_src(self.src_type):
            if self.mode_config is None:
                self.mode_config = LiteLlmModeConfigDTO()
            self.manual_targets = [
                validate_litellm_manual_target_url(target)
                for target in self.manual_targets
            ]
            if (
                self.target_source in {"fofa", "manual", "both"}
                and self.mode_config.scope_mode == "targeted"
                and not self.mode_config.scope_anchors
                and not self.manual_targets
            ):
                raise ValueError(
                    "targeted LiteLLM tasks require scope_anchors or manual_targets"
                )
        return self


class PartialModelConfigDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_global_pool: Optional[bool] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    protocol: Optional[LLMProtocol] = None
    temperature: Optional[float] = Field(default=None, ge=0, le=2)
    prompt_version: Optional[str] = None

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        return _validated_http_url(normalized) if normalized else ""

    @field_validator("api_key", "model", "prompt_version")
    @classmethod
    def _trim_text(cls, value: str | None) -> str | None:
        return None if value is None else str(value).strip()


class PartialFofaConfigDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None
    max_pages: Optional[int] = None
    page_size: Optional[int] = None
    intent_mode: Optional[str] = None
    site_recon_mode: Optional[Literal["full", "light"]] = None


class PartialEngineConfigDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None


class UpdateTaskRequest(BaseModel):
    name: Optional[str] = None
    src_type: Optional[str] = None
    vuln_types: Optional[list[str]] = None
    src_rules: Optional[str] = None
    target_source: Optional[str] = None
    engine: Optional[str] = None                                 # 切换引擎
    fofa_query: Optional[str] = None
    hunt_direction: Optional[str] = Field(default=None, max_length=2000)
    manual_targets: Optional[list[str]] = None
    auth_bindings: Optional[list[dict]] = None
    model_config_data: Optional[PartialModelConfigDTO] = None
    fofa_config: Optional[PartialFofaConfigDTO] = None
    engine_config: Optional[PartialEngineConfigDTO] = None
    concurrency: Optional[int] = None
    mode_config: Optional[LiteLlmModeConfigDTO] = None

    @field_validator("hunt_direction", mode="before")
    @classmethod
    def _hunt_direction(cls, value: str | None) -> str | None:
        return None if value is None else str(value).strip()

    @model_validator(mode="after")
    def _validate_explicit_litellm_targets(self):
        if (
            self.src_type is not None
            and is_litellm_src(self.src_type)
            and self.manual_targets is not None
        ):
            self.manual_targets = [
                validate_litellm_manual_target_url(target)
                for target in self.manual_targets
            ]
        return self


class TaskStats(BaseModel):
    queued: int = 0
    scanning: int = 0
    done: int = 0
    dead: int = 0
    skipped: int = 0
    findings_total: int = 0
    pending_review: int = 0
    accepted: int = 0
    ignored: int = 0
    deepen: int = 0
    killsweep: int = 0
    review_pending: int = 0
    submit_ready: int = 0
    rejected: int = 0
    archived: int = 0


class QueueOrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_ids: list[str] = Field(max_length=5000)


class TaskResponse(BaseModel):
    id: str
    name: str
    status: str
    src_type: str
    vuln_types: list[str]
    target_source: str
    engine: str = ""
    fofa_query: str
    hunt_direction: str = ""
    concurrency: int
    src_rules: str = ""
    manual_targets: list[str] = Field(default_factory=list)
    auth_bindings: list[dict] = Field(default_factory=list)
    mode_config: dict = Field(default_factory=dict)
    model_config_data: dict = Field(default_factory=dict)
    fofa_config: dict = Field(default_factory=dict)
    search_enabled: bool = True
    engine_config: dict = Field(default_factory=dict)
    llm_usage: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str
    stats: Optional[TaskStats] = None
    pending_user_review: int = 0


class LLMSettingsDTO(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None


class FofaSettingsDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None
    max_pages: Optional[int] = None
    page_size: Optional[int] = None
    default_intent_mode: Optional[str] = None


class EngineSettingsDTO(BaseModel):
    """单个搜索引擎的设置。"""
    key: Optional[str] = None
    base_url: Optional[str] = None


class DefaultsSettingsDTO(BaseModel):
    concurrency: Optional[int] = None
    skip_score_threshold: Optional[float] = None
    worker_prompt_version: Optional[str] = None
    engine: Optional[str] = None


class SettingsUpdateRequest(BaseModel):
    llm: Optional[LLMSettingsDTO] = None
    fofa: Optional[FofaSettingsDTO] = None
    engines: Optional[dict[str, EngineSettingsDTO]] = None   # 按引擎名索引
    defaults: Optional[DefaultsSettingsDTO] = None


class LLMProviderDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    base_url: str
    api_key: str = ""
    model: str
    temperature: float = Field(default=0.3, ge=0, le=2)
    weight: int = Field(default=5, ge=1, le=100)
    protocol: LLMProtocol = "openai_chat"
    enabled: bool = True

    @field_validator("name", "model")
    @classmethod
    def _nonempty_text(cls, value: str, info: ValidationInfo) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            raise ValueError("must not be empty")
        if info.field_name == "name" and (
            normalized.casefold() == "order"
            or any(char in normalized for char in "/\\?#")
            or any(ord(char) < 32 for char in normalized)
        ):
            raise ValueError("provider name is reserved or cannot be used in a URL path")
        return normalized

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, value: str) -> str:
        return _validated_http_url(value)

    @field_validator("api_key")
    @classmethod
    def _api_key(cls, value: str) -> str:
        return str(value or "").strip()

    @model_validator(mode="after")
    def _enabled_requires_key(self):
        if self.enabled and not self.api_key:
            raise ValueError("enabled provider requires api_key")
        return self


class LLMProviderUpdateDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = Field(default=None, ge=0, le=2)
    weight: Optional[int] = Field(default=None, ge=1, le=100)
    protocol: Optional[LLMProtocol] = None
    enabled: Optional[bool] = None

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, value: str | None) -> str | None:
        return None if value is None else _validated_http_url(value)

    @field_validator("model")
    @classmethod
    def _model(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        if not normalized:
            raise ValueError("must not be empty")
        return normalized

    @field_validator("api_key")
    @classmethod
    def _api_key(cls, value: str | None) -> str | None:
        return None if value is None else str(value).strip()


class LLMProviderOrderDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    names: list[str]

    @field_validator("names")
    @classmethod
    def _normalized_names(cls, names: list[str]) -> list[str]:
        normalized = [str(name or "").strip() for name in names]
        if any(not name for name in normalized):
            raise ValueError("provider names must not be empty")
        return normalized


class FofaKeyDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    key: str = ""
    base_url: str = "https://fofa.info"
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if (
            not normalized
            or normalized.casefold() == "order"
            or any(char in normalized for char in "/\\?#")
            or any(ord(char) < 32 for char in normalized)
        ):
            raise ValueError("FOFA Key name is reserved or cannot be used in a URL path")
        return normalized

    @field_validator("key")
    @classmethod
    def _key(cls, value: str) -> str:
        return str(value or "").strip()

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, value: str) -> str:
        return _validated_http_url(value)

    @model_validator(mode="after")
    def _enabled_requires_key(self):
        if self.enabled and not self.key:
            raise ValueError("enabled FOFA Key requires key")
        return self


class FofaKeyUpdateDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: Optional[str] = None
    base_url: Optional[str] = None
    enabled: Optional[bool] = None

    @field_validator("key")
    @classmethod
    def _key(cls, value: str | None) -> str | None:
        return None if value is None else str(value).strip()

    @field_validator("base_url")
    @classmethod
    def _base_url(cls, value: str | None) -> str | None:
        return None if value is None else _validated_http_url(value)


class FofaKeyOrderDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    names: list[str]

    @field_validator("names")
    @classmethod
    def _normalized_names(cls, names: list[str]) -> list[str]:
        normalized = [str(name or "").strip() for name in names]
        if any(not name for name in normalized):
            raise ValueError("FOFA Key names must not be empty")
        return normalized
