from __future__ import annotations

import httpx


class LiteLLMProxyFixture:
    """Deterministic LiteLLM-like HTTP states for integration tests."""

    PROVIDER_KEY = "sk-proj-fixture-key-abcdefghijklmnopqrstuvwxyz"
    MASTER_KEY = "sk-fixture-master-key-abcdefghijklmnopqrstuvwxyz"
    MODES = {"authenticated", "no_master_key", "env_exposure", "spa_waf"}

    def __init__(self, mode: str) -> None:
        if mode not in self.MODES:
            raise ValueError(f"unknown LiteLLM fixture mode: {mode}")
        self.mode = mode
        self.requests: list[tuple[str, str, str]] = []

    @staticmethod
    def _json(status: int, payload: object) -> httpx.Response:
        return httpx.Response(status, json=payload, headers={"content-type": "application/json"})

    def _handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.rstrip("/") or "/"
        auth = request.headers.get("authorization", "")
        self.requests.append((request.method, path, auth))

        if self.mode == "spa_waf":
            return httpx.Response(
                200,
                text="<html><title>Access denied</title>Web Application Firewall</html>",
                headers={"content-type": "text/html"},
            )
        if path == "/.well-known/autohunter-gateway-control":
            return self._json(404, {"detail": "not found"})
        if path in {"/health/liveliness", "/health/liveness", "/health/readiness"}:
            return httpx.Response(200, text="I'm alive!", headers={"content-type": "text/plain"})

        if self.mode == "authenticated":
            if auth == f"Bearer {self.MASTER_KEY}":
                return self._business_response(request, path)
            return self._json(401, {"error": {"message": "invalid key"}})

        if auth == f"Bearer {self.PROVIDER_KEY}":
            return self._business_response(request, path)
        if auth:
            return self._json(401, {"error": {"message": "invalid key"}})
        return self._business_response(request, path)

    def _business_response(self, request: httpx.Request, path: str) -> httpx.Response:
        if path in {"/v1/models", "/models"}:
            return self._json(200, {
                "object": "list",
                "data": [{"id": "fixture-model", "object": "model"}],
            })
        if path in {"/v1/chat/completions", "/chat/completions"}:
            return self._json(200, {
                "id": "chatcmpl-fixture",
                "model": "fixture-model",
                "choices": [{"message": {"content": "ok"}}],
            })
        if self.mode == "env_exposure" and path == "/config/list":
            return self._json(200, [{
                "field_name": "OPENAI_API_KEY",
                "field_type": "str",
                "value": self.PROVIDER_KEY,
            }])
        return self._json(401, {"error": {"message": "authentication required"}})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handler)

    def credential_transport(self) -> object:
        fixture = self

        class Transport:
            def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
                with httpx.Client(transport=fixture.transport()) as client:
                    return client.request(method, url, **kwargs)

        return Transport()


__all__ = ["LiteLLMProxyFixture"]
