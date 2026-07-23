from __future__ import annotations

import json

import httpx
import pytest

from app.db.models import GatewayAsset
from app.gateway_hunt.client import LiteLLMScanClient


@pytest.mark.asyncio
async def test_client_confirms_litellm_anonymous_inference_with_profile_routes() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        auth = request.headers.get("authorization", "")
        if request.url.path == "/health/liveliness":
            return httpx.Response(200, text="I'm alive!", headers={"content-type": "text/plain"})
        if request.url.path == "/v1/models":
            if auth:
                return httpx.Response(401, json={"error": {"message": "invalid key"}})
            return httpx.Response(200, json={"data": [{"id": "fixture-model"}]})
        if request.url.path == "/v1/chat/completions" and not auth:
            body = json.loads(request.content)
            assert body["model"] == "fixture-model"
            assert body["stream"] is False
            assert body["max_tokens"] == 1
            return httpx.Response(
                200,
                json={"id": "chatcmpl-fixture", "model": "fixture-model", "choices": [{"message": {"content": "ok"}}]},
            )
        return httpx.Response(401, json={"error": {"message": "invalid key"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        result = await LiteLLMScanClient(http_client=http_client).scan(
            GatewayAsset(
                id="asset-fixture",
                task_id="task-fixture",
                canonical_base_url="https://gateway.test",
                origin_key="https://gateway.test/",
                profile_id="litellm",
            ),
            scan_epoch=1,
            request_budget=12,
        )

    assert result.fingerprint_status == "confirmed"
    assert result.auth_state == "anonymous_inference"
    assert result.model_names == ("fixture-model",)
    assert any(item.result == "anonymous_models" for item in result.observations)
    assert any(item.result == "anonymous_inference" for item in result.observations)
    assert result.request_count <= 12
    assert {request.url.host for request in requests} == {"gateway.test"}


@pytest.mark.asyncio
async def test_client_stops_at_request_budget() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "not found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        result = await LiteLLMScanClient(http_client=http_client).scan(
            GatewayAsset(
                id="asset-budget",
                task_id="task-fixture",
                canonical_base_url="https://gateway.test/proxy",
                origin_key="https://gateway.test/proxy",
                mount_path="/proxy",
                profile_id="litellm",
            ),
            scan_epoch=1,
            request_budget=2,
        )

    assert result.request_count == 2
    assert result.partial is True
