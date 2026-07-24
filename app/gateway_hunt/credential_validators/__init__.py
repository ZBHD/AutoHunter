"""内置 Provider Validator 注册表。"""
from __future__ import annotations

from app.gateway_hunt.credential_validators.anthropic import AnthropicValidator
from app.gateway_hunt.credential_validators.azure_openai import AzureOpenAIValidator
from app.gateway_hunt.credential_validators.base import CredentialValidator
from app.gateway_hunt.credential_validators.bedrock import BedrockValidator
from app.gateway_hunt.credential_validators.gemini import GeminiValidator
from app.gateway_hunt.credential_validators.litellm import LiteLLMValidator
from app.gateway_hunt.credential_validators.openai import OpenAIValidator


_VALIDATORS: dict[str, CredentialValidator] = {
    validator.provider: validator
    for validator in (
        AnthropicValidator(),
        AzureOpenAIValidator(),
        BedrockValidator(),
        GeminiValidator(),
        LiteLLMValidator(),
        OpenAIValidator(),
    )
}


def get_validator(provider: str) -> CredentialValidator:
    normalized = str(provider or "").strip().lower()
    try:
        return _VALIDATORS[normalized]
    except KeyError as exc:
        raise KeyError(f"unknown credential validator: {provider}") from exc


def list_validators() -> tuple[str, ...]:
    return tuple(sorted(_VALIDATORS))


__all__ = ["get_validator", "list_validators"]
