"""配置模型：LLM provider 与 Worker 参数。"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


_load_dotenv()


class LLMProviderConfig(BaseModel):
    """单个 LLM provider 的配置。"""
    name: str = "Default"
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    model: str = "deepseek-chat"
    temperature: float = Field(default=0.3, ge=0, le=2)
    weight: int = Field(default=5, ge=1, le=100)
    protocol: Literal["openai_chat", "anthropic_messages", "openai_responses"] = "openai_chat"
    enabled: bool = True

    @field_validator("name", "model")
    @classmethod
    def _nonempty_text(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            raise ValueError("must not be empty")
        return normalized

    @field_validator("base_url")
    @classmethod
    def _http_base_url(cls, value: str) -> str:
        normalized = str(value or "").strip()
        try:
            parsed = urlparse(normalized)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("must be an absolute HTTP(S) URL") from exc
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not hostname
            or (port is not None and not 1 <= port <= 65535)
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.query)
            or bool(parsed.fragment)
        ):
            raise ValueError("must be an absolute HTTP(S) URL")
        return normalized

    @field_validator("api_key")
    @classmethod
    def _trim_api_key(cls, value: str) -> str:
        return str(value or "").strip()


class LLMConfig(LLMProviderConfig):
    """兼容旧单模型调用方的完整 provider 配置。"""


llm_config = LLMConfig()


class WorkerConfig(BaseModel):
    shell_timeout: int = int(os.environ.get("WORKER_SHELL_TIMEOUT", "120"))
    shell_timeout_max: int = int(os.environ.get("WORKER_SHELL_TIMEOUT_MAX", "600"))
    output_truncate: int = int(os.environ.get("WORKER_OUTPUT_TRUNCATE", "4096"))
    llm_tool_output_truncate: int = int(os.environ.get("WORKER_LLM_TOOL_OUTPUT_TRUNCATE", "4096"))
    history_full_tool_rounds: int = int(os.environ.get("WORKER_HISTORY_FULL_TOOL_ROUNDS", "4"))
    max_rounds: int = int(os.environ.get("WORKER_MAX_ROUNDS", "90"))
    soft_rounds: int = int(os.environ.get("WORKER_SOFT_ROUNDS", "45"))
    enterprise_max_rounds: int = int(os.environ.get("ENTERPRISE_WORKER_MAX_ROUNDS", "110"))
    enterprise_soft_rounds: int = int(os.environ.get("ENTERPRISE_WORKER_SOFT_ROUNDS", "60"))
    round_budget_cap: int = int(os.environ.get("WORKER_ROUND_BUDGET_CAP", "0"))
    soft_round_budget_cap: int = int(os.environ.get("WORKER_SOFT_ROUND_BUDGET_CAP", "0"))
    enterprise_round_budget_cap: int = int(os.environ.get("ENTERPRISE_WORKER_ROUND_BUDGET_CAP", "0"))
    enterprise_soft_round_budget_cap: int = int(os.environ.get("ENTERPRISE_WORKER_SOFT_ROUND_BUDGET_CAP", "0"))
    js_tool_always_on: bool = os.environ.get("WORKER_JS_TOOL_ALWAYS_ON", "0").lower() in {"1", "true", "yes"}
    prompt_version: str = os.environ.get("WORKER_PROMPT_VERSION", "legacy")
    work_root: str = os.environ.get("WORKER_WORK_ROOT", "/tmp/autohunter/work")

    def rounds_for(self, src_type: str | None) -> tuple[int, int]:
        st = (src_type or "").strip().lower()
        if st in {"enterprise", "corp", "company", "企业", "企业src"}:
            max_rounds = self._cap(self.enterprise_max_rounds, self.enterprise_round_budget_cap)
            soft_rounds = self._cap(self.enterprise_soft_rounds, self.enterprise_soft_round_budget_cap)
        else:
            max_rounds = self._cap(self.max_rounds, self.round_budget_cap)
            soft_rounds = self._cap(self.soft_rounds, self.soft_round_budget_cap)
        return max(1, max_rounds), max(1, min(soft_rounds, max_rounds))

    @staticmethod
    def _cap(value: int, cap: int) -> int:
        return min(value, cap) if cap > 0 else value


worker_config = WorkerConfig()
