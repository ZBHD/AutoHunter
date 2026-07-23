import secrets

from app.gateway_hunt.credential_validators.base import (
    ValidationContext,
    ValidationResult,
    classify_response,
    endpoint,
    parse_json,
    request,
)
from app.gateway_hunt.credential_validators.common import OpenAICompatibleValidator
from app.gateway_hunt.schemas import SecretArtifact


class AnthropicValidator(OpenAICompatibleValidator):
    provider = "anthropic"
    auth_header = "x-api-key"
    auth_prefix = ""
    inference_path = "/v1/messages"

    def headers(self, artifact: SecretArtifact) -> dict[str, str]:
        headers = super().headers(artifact)
        headers["anthropic-version"] = "2023-06-01"
        return headers

    def validate_inference(
        self,
        artifact: SecretArtifact,
        context: ValidationContext,
        model: str,
        headers: dict[str, str],
    ) -> ValidationResult:
        request_json: dict[str, object] = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": f"Reply OK. nonce={secrets.token_hex(8)}",
                }
            ],
            "max_tokens": 1,
            "stream": False,
        }
        try:
            response = request(
                context.transport,
                "POST",
                endpoint(context.base_url, self.inference_path),
                headers=headers,
                json_body=request_json,
                timeout=context.timeout,
            )
        except ConnectionError as exc:
            return ValidationResult(
                status="network_error",
                provider=self.provider,
                detail=str(exc),
                request_count=1,
                request_json=request_json,
            )
        payload = parse_json(response)
        content = payload.get("content") if isinstance(payload, dict) else None
        valid = (
            200 <= response.status_code < 300
            and isinstance(payload, dict)
            and payload.get("type") == "message"
            and isinstance(content, list)
            and any(
                isinstance(item, dict)
                and item.get("type") == "text"
                and isinstance(item.get("text"), str)
                for item in content
            )
        )
        return ValidationResult(
            status="valid" if valid else classify_response(response),
            provider=self.provider,
            detail=(
                "minimal Anthropic message response matched"
                if valid
                else "minimal Anthropic response did not match"
            ),
            request_count=1,
            request_json=request_json,
        )


__all__ = ["AnthropicValidator"]
