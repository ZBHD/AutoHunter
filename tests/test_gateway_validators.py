from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from app.gateway_hunt.credential_validators import get_validator, list_validators
from app.gateway_hunt.credential_validators.base import (
    ValidationContext,
    ValidationResponse,
)
from app.gateway_hunt.inference_validator import validate_minimal_inference
from app.gateway_hunt.schemas import SecretArtifact


@dataclass
class FixtureTransport:
    responses: list[ValidationResponse]

    def __post_init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def request(self, method: str, url: str, **kwargs: object) -> ValidationResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError("unexpected extra request")
        return self.responses.pop(0)


def _response(
    status_code: int,
    body: str,
    content_type: str = "application/json",
) -> ValidationResponse:
    return ValidationResponse(status_code, content_type, body)


def _artifact(provider: str, **context: str) -> SecretArtifact:
    value = "sk-fixture-secret-value"
    return SecretArtifact(
        name=f"{provider.upper()}_API_KEY",
        value=value,
        sha256=hashlib.sha256(value.encode()).hexdigest(),
        secret_type="provider_key",
        provider=provider,
        validation_context={"provider": provider, **context},
    )


def test_inference_validator_requires_openai_shape() -> None:
    transport = FixtureTransport(
        [_response(200, '{"choices":[{"message":{"content":"ok"}}]}')]
    )

    result = validate_minimal_inference(
        base_url="https://fixture.test",
        model="fixture-model",
        transport=transport,
    )

    assert result.status == "valid"
    assert result.request_json["stream"] is False
    assert result.request_json["max_tokens"] == 1
    assert result.request_json["model"] == "fixture-model"
    assert len(transport.calls) == 1


def test_http_200_error_json_is_not_valid_inference() -> None:
    result = validate_minimal_inference(
        base_url="https://fixture.test",
        model="fixture-model",
        transport=FixtureTransport(
            [_response(200, '{"error":{"message":"quota exceeded"}}')]
        ),
    )

    assert result.status == "quota_exhausted"


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_response(200, "<html>ok</html>", "text/html"), "unknown"),
        (_response(200, "request blocked by web application firewall", "text/plain"), "unknown"),
        (_response(200, ""), "unknown"),
        (_response(401, '{"error":"invalid api key"}'), "invalid"),
        (_response(403, '{"error":"forbidden"}'), "permission_denied"),
        (_response(429, '{"error":"rate limit"}'), "rate_limited"),
        (_response(503, '{"error":"upstream unavailable"}'), "network_error"),
    ],
)
def test_inference_validator_classifies_failures(
    response: ValidationResponse,
    expected: str,
) -> None:
    result = validate_minimal_inference(
        base_url="https://fixture.test",
        model="fixture-model",
        transport=FixtureTransport([response]),
    )

    assert result.status == expected


def test_validator_registry_lists_all_supported_providers() -> None:
    assert list_validators() == (
        "anthropic",
        "azure_openai",
        "bedrock",
        "gemini",
        "litellm",
        "openai",
    )
    assert get_validator("OPENAI").provider == "openai"
    with pytest.raises(KeyError, match="unknown credential validator"):
        get_validator("unknown")


def test_openai_validator_enumerates_once_and_infers_once() -> None:
    transport = FixtureTransport(
        [
            _response(
                200,
                '{"object":"list","data":[{"id":"gpt-fixture","object":"model"}]}',
            ),
            _response(200, '{"choices":[{"message":{"content":"ok"}}]}'),
        ]
    )

    result = get_validator("openai").validate(
        _artifact("openai"),
        ValidationContext(
            base_url="https://provider.fixture",
            transport=transport,
        ),
    )

    assert result.status == "valid"
    assert result.model_ids == ("gpt-fixture",)
    assert result.request_count == 2
    assert len(transport.calls) == 2
    assert transport.calls[0]["method"] == "GET"
    assert transport.calls[1]["method"] == "POST"
    for call in transport.calls:
        timeout = call["timeout"]
        assert timeout.connect == 5.0
        assert timeout.read == 15.0


def test_invalid_model_list_stops_before_inference() -> None:
    transport = FixtureTransport([_response(401, '{"error":"invalid api key"}')])

    result = get_validator("openai").validate(
        _artifact("openai"),
        ValidationContext(base_url="https://provider.fixture", transport=transport),
    )

    assert result.status == "invalid"
    assert result.request_count == 1
    assert len(transport.calls) == 1


def test_bedrock_requires_complete_group_and_region() -> None:
    transport = FixtureTransport([])
    artifact = _artifact("bedrock", access_key_id="AKIAABCDEFGHIJKLMNOP")

    result = get_validator("bedrock").validate(
        artifact,
        ValidationContext(base_url="https://bedrock.fixture", transport=transport),
    )

    assert result.status == "unknown"
    assert result.request_count == 0
    assert "complete credential group" in result.detail
    assert transport.calls == []


def test_anthropic_validator_uses_native_messages_shape() -> None:
    transport = FixtureTransport(
        [
            _response(200, '{"data":[{"id":"claude-fixture"}]}'),
            _response(
                200,
                '{"id":"msg-1","type":"message",'
                '"content":[{"type":"text","text":"ok"}]}',
            ),
        ]
    )

    result = get_validator("anthropic").validate(
        _artifact("anthropic"),
        ValidationContext(base_url="https://anthropic.fixture", transport=transport),
    )

    assert result.status == "valid"
    assert result.request_count == 2
    assert transport.calls[1]["url"].endswith("/v1/messages")
    assert transport.calls[1]["json"]["max_tokens"] == 1
    assert transport.calls[1]["headers"]["anthropic-version"] == "2023-06-01"


def test_azure_validator_uses_extracted_deployment() -> None:
    transport = FixtureTransport(
        [
            _response(200, '{"data":[{"id":"ignored-model"}]}'),
            _response(200, '{"choices":[{"message":{"content":"ok"}}]}'),
        ]
    )

    result = get_validator("azure_openai").validate(
        _artifact("azure_openai", deployment="deploy-one"),
        ValidationContext(base_url="https://azure.fixture", transport=transport),
    )

    assert result.status == "valid"
    assert "/openai/deployments/deploy-one/chat/completions" in transport.calls[1]["url"]


def test_bedrock_complete_group_enumerates_and_infers_without_exposing_secret() -> None:
    transport = FixtureTransport(
        [
            _response(
                200,
                '{"modelSummaries":[{"modelId":"amazon.titan-text-express-v1",'
                '"outputModalities":["TEXT"]}]}',
            ),
            _response(200, '{"results":[{"outputText":"ok"}]}'),
        ]
    )
    artifact = _artifact(
        "bedrock",
        access_key_id="AKIAABCDEFGHIJKLMNOP",
        secret_access_key="bedrock-secret-value",
        region="us-east-1",
    )

    result = get_validator("bedrock").validate(
        artifact,
        ValidationContext(base_url="https://bedrock.fixture", transport=transport),
    )

    assert result.status == "valid"
    assert result.request_count == 2
    assert result.model_ids == ("amazon.titan-text-express-v1",)
    assert all(
        "bedrock-secret-value" not in str(call)
        for call in transport.calls
    )
    assert all(
        str(call["headers"]["Authorization"]).startswith("AWS4-HMAC-SHA256")
        for call in transport.calls
    )
