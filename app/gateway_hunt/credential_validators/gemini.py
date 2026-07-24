from app.gateway_hunt.credential_validators.common import OpenAICompatibleValidator


class GeminiValidator(OpenAICompatibleValidator):
    provider = "gemini"
    auth_header = "x-goog-api-key"
    auth_prefix = ""
    models_path = "/v1beta/models"
    inference_path = "/v1beta/openai/chat/completions"


__all__ = ["GeminiValidator"]
