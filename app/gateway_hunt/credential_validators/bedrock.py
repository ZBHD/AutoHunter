from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

from app.gateway_hunt.credential_validators.base import (
    ValidationContext,
    ValidationResponse,
    ValidationResult,
    classify_response,
    endpoint,
    parse_json,
    request,
)
from app.gateway_hunt.schemas import SecretArtifact


class BedrockValidator:
    provider = "bedrock"

    @staticmethod
    def _signature_headers(
        *,
        method: str,
        url: str,
        body: bytes,
        access_key: str,
        secret_key: str,
        region: str,
        session_token: str = "",
    ) -> dict[str, str]:
        parsed = urlsplit(url)
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()
        canonical_headers = {
            "host": parsed.netloc,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if session_token:
            canonical_headers["x-amz-security-token"] = session_token
        signed_headers = ";".join(sorted(canonical_headers))
        canonical_header_text = "".join(
            f"{name}:{canonical_headers[name]}\n" for name in sorted(canonical_headers)
        )
        canonical_request = "\n".join(
            (
                method,
                parsed.path or "/",
                parsed.query,
                canonical_header_text,
                signed_headers,
                payload_hash,
            )
        )
        scope = f"{date_stamp}/{region}/bedrock/aws4_request"
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            )
        )

        def sign(key: bytes, value: str) -> bytes:
            return hmac.new(key, value.encode(), hashlib.sha256).digest()

        date_key = sign(f"AWS4{secret_key}".encode(), date_stamp)
        region_key = sign(date_key, region)
        service_key = sign(region_key, "bedrock")
        signing_key = sign(service_key, "aws4_request")
        signature = hmac.new(
            signing_key,
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "Authorization": (
                "AWS4-HMAC-SHA256 "
                f"Credential={access_key}/{scope}, "
                f"SignedHeaders={signed_headers}, Signature={signature}"
            ),
            "Content-Type": "application/json",
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if session_token:
            headers["x-amz-security-token"] = session_token
        return headers

    @staticmethod
    def _model_ids(response: ValidationResponse) -> tuple[str, ...]:
        payload = parse_json(response)
        records = payload.get("modelSummaries") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            return ()
        values = []
        for record in records:
            if not isinstance(record, dict):
                continue
            modalities = record.get("outputModalities")
            model_id = record.get("modelId")
            if (
                isinstance(model_id, str)
                and isinstance(modalities, list)
                and "TEXT" in modalities
            ):
                values.append(model_id)
        return tuple(dict.fromkeys(values))

    def validate(
        self,
        artifact: SecretArtifact,
        context: ValidationContext,
    ) -> ValidationResult:
        values = artifact.validation_context
        access_key = values.get("access_key_id") or values.get("AWS_ACCESS_KEY_ID")
        secret_key = values.get("secret_access_key") or values.get(
            "AWS_SECRET_ACCESS_KEY"
        )
        region = values.get("region") or values.get("AWS_REGION")
        if not all(isinstance(value, str) and value for value in (access_key, secret_key, region)):
            return ValidationResult(
                status="unknown",
                provider=self.provider,
                detail="complete credential group and region are required",
                request_count=0,
            )
        session_token = values.get("session_token") or values.get("AWS_SESSION_TOKEN")
        session_token = session_token if isinstance(session_token, str) else ""
        models_url = endpoint(context.base_url, "/foundation-models")
        list_headers = self._signature_headers(
            method="GET",
            url=models_url,
            body=b"",
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            session_token=session_token,
        )
        try:
            models_response = request(
                context.transport,
                "GET",
                models_url,
                headers=list_headers,
                timeout=context.timeout,
            )
        except ConnectionError as exc:
            return ValidationResult(
                status="network_error",
                provider=self.provider,
                detail=str(exc),
                request_count=1,
            )
        model_ids = self._model_ids(models_response)
        if not model_ids:
            return ValidationResult(
                status=classify_response(models_response),
                provider=self.provider,
                detail="Bedrock model enumeration did not return a text model",
                request_count=1,
            )
        request_json: dict[str, object] = {
            "inputText": "Reply OK.",
            "textGenerationConfig": {"maxTokenCount": 1},
        }
        body = json.dumps(request_json, separators=(",", ":")).encode()
        invoke_url = endpoint(
            context.base_url,
            f"/model/{quote(model_ids[0], safe='')}/invoke",
        )
        invoke_headers = self._signature_headers(
            method="POST",
            url=invoke_url,
            body=body,
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            session_token=session_token,
        )
        try:
            inference_response = request(
                context.transport,
                "POST",
                invoke_url,
                headers=invoke_headers,
                content_body=body,
                timeout=context.timeout,
            )
        except ConnectionError as exc:
            return ValidationResult(
                status="network_error",
                provider=self.provider,
                detail=str(exc),
                model_ids=model_ids,
                request_count=2,
                request_json=request_json,
            )
        payload = parse_json(inference_response)
        results = payload.get("results") if isinstance(payload, dict) else None
        valid = (
            200 <= inference_response.status_code < 300
            and isinstance(results, list)
            and any(
                isinstance(item, dict) and isinstance(item.get("outputText"), str)
                for item in results
            )
        )
        return ValidationResult(
            status="valid" if valid else classify_response(inference_response),
            provider=self.provider,
            detail=(
                "Bedrock text inference response matched"
                if valid
                else "Bedrock inference response did not match"
            ),
            model_ids=model_ids,
            request_count=2,
            request_json=request_json,
        )


__all__ = ["BedrockValidator"]
