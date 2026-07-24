from app.gateway_hunt.credential_validators.common import OpenAICompatibleValidator


class OpenAIValidator(OpenAICompatibleValidator):
    provider = "openai"


__all__ = ["OpenAIValidator"]
