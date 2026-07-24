"""共享一次模型枚举和一次最小推理的 Provider 验证流程。"""
from __future__ import annotations

from app.gateway_hunt.credential_validators.base import (
    ValidationContext,
    ValidationResult,
    classify_response,
    endpoint,
    parse_model_ids,
    request,
)
from app.gateway_hunt.inference_validator import validate_minimal_inference
from app.gateway_hunt.schemas import SecretArtifact


class OpenAICompatibleValidator:
    provider = ""
    models_path = "/v1/models"
    inference_path = "/v1/chat/completions"
    auth_header = "Authorization"
    auth_prefix = "Bearer "

    def headers(self, artifact: SecretArtifact) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            self.auth_header: f"{self.auth_prefix}{artifact.value}",
        }
        return headers

    def inference_path_for(self, artifact: SecretArtifact) -> str:
        return self.inference_path

    def validate_inference(
        self,
        artifact: SecretArtifact,
        context: ValidationContext,
        model: str,
        headers: dict[str, str],
    ) -> ValidationResult:
        return validate_minimal_inference(
            base_url=context.base_url,
            model=model,
            transport=context.transport,
            path=self.inference_path_for(artifact),
            headers=headers,
            timeout=context.timeout,
        )

    def validate(
        self,
        artifact: SecretArtifact,
        context: ValidationContext,
    ) -> ValidationResult:
        headers = self.headers(artifact)
        try:
            response = request(
                context.transport,
                "GET",
                endpoint(context.base_url, self.models_path),
                headers=headers,
                timeout=context.timeout,
            )
        except ConnectionError as exc:
            return ValidationResult(
                status="network_error",
                provider=self.provider,
                detail=str(exc),
                request_count=1,
            )
        model_ids = parse_model_ids(response, self.provider)
        if not model_ids:
            status = classify_response(response)
            return ValidationResult(
                status=status,
                provider=self.provider,
                detail="model enumeration did not return a supported schema",
                request_count=1,
            )
        inference = self.validate_inference(
            artifact,
            context,
            model_ids[0],
            headers,
        )
        return ValidationResult(
            status=inference.status,
            provider=self.provider,
            detail=inference.detail,
            model_ids=model_ids,
            request_count=1 + inference.request_count,
            request_json=inference.request_json,
        )


__all__ = ["OpenAICompatibleValidator"]
