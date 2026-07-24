from app.gateway_hunt.credential_validators.common import OpenAICompatibleValidator


class LiteLLMValidator(OpenAICompatibleValidator):
    provider = "litellm"


__all__ = ["LiteLLMValidator"]
