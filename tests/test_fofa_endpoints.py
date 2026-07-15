from __future__ import annotations

import asyncio
from urllib.parse import quote, quote_plus

import httpx

from app.fofa.endpoints import (
    FofaEndpointCandidate,
    FofaTransportResult,
    endpoint_candidates,
    request_async,
    request_sync,
)


class _AsyncClient:
    calls: list[tuple[str, str]] = []
    responses: list[httpx.Response] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, url, **_kwargs):
        self.calls.append(("GET", str(url)))
        response = self.responses.pop(0)
        response.request = httpx.Request("GET", str(url))
        return response

    async def post(self, url, **_kwargs):
        self.calls.append(("POST", str(url)))
        response = self.responses.pop(0)
        response.request = httpx.Request("POST", str(url))
        return response


class _SyncClient:
    calls: list[tuple[str, str]] = []
    responses: list[httpx.Response] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def get(self, url, **_kwargs):
        self.calls.append(("GET", str(url)))
        response = self.responses.pop(0)
        response.request = httpx.Request("GET", str(url))
        return response

    def post(self, url, **_kwargs):
        self.calls.append(("POST", str(url)))
        response = self.responses.pop(0)
        response.request = httpx.Request("POST", str(url))
        return response


def test_root_endpoint_uses_purpose_standard_paths(monkeypatch) -> None:
    _AsyncClient.calls = []
    _AsyncClient.responses = [httpx.Response(200, json={"ok": True})]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncClient())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        request_async("https://fofa.example", purpose="info", params={"key": "KEY"})
    )

    assert result.resolved_url == "https://fofa.example/api/v1/info/my"
    assert result.endpoint_mode == "root"
    assert result.http_status == 200
    assert result.category == "ok"
    assert _AsyncClient.calls == [("GET", result.resolved_url)]


def test_full_api_php_is_called_without_path_rewrite(monkeypatch) -> None:
    _AsyncClient.calls = []
    _AsyncClient.responses = [httpx.Response(200, json={"ok": True})]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncClient())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        request_async("https://fofa.example/api.php", purpose="search", params={"key": "KEY"})
    )

    assert result.resolved_url == "https://fofa.example/api.php"
    assert result.endpoint_mode == "exact"
    assert _AsyncClient.calls == [("GET", "https://fofa.example/api.php")]


def test_known_standard_path_404_is_not_retried(monkeypatch) -> None:
    _AsyncClient.calls = []
    _AsyncClient.responses = [httpx.Response(404)]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncClient())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        request_async("https://fofa.example/api/v1/search/all", purpose="search", params={"key": "KEY"})
    )

    assert result.endpoint_mode == "known"
    assert result.http_status == 404
    assert _AsyncClient.calls == [("GET", "https://fofa.example/api/v1/search/all")]


def test_endpoint_candidates_are_immutable_and_include_fallback() -> None:
    candidates = endpoint_candidates("https://fofa.example/api.php", purpose="search")

    assert isinstance(candidates[0], FofaEndpointCandidate)
    assert candidates[0].url == "https://fofa.example/api.php"
    assert candidates[0].mode == "exact"
    assert candidates[1].mode == "fallback"
    assert isinstance(candidates, tuple)

    try:
        candidates[0].url = "https://changed.example"
    except AttributeError:
        pass
    else:
        raise AssertionError("endpoint candidates must be immutable")


def test_transport_result_is_public_dataclass() -> None:
    assert issubclass(FofaTransportResult, object)
    assert FofaTransportResult.__dataclass_params__.frozen is True


def test_api_php_405_retries_post_and_keeps_exact_url(monkeypatch) -> None:
    _AsyncClient.calls = []
    _AsyncClient.responses = [httpx.Response(405), httpx.Response(200, json={"ok": True})]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncClient())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        request_async("KEY", "https://fofa.example/api.php", purpose="search")
    )

    assert result.endpoint_mode == "exact"
    assert result.category == "ok"
    assert _AsyncClient.calls == [
        ("GET", "https://fofa.example/api.php"),
        ("POST", "https://fofa.example/api.php"),
    ]


def test_api_php_404_falls_back_and_terminal_endpoint_is_classified(monkeypatch) -> None:
    _AsyncClient.calls = []
    _AsyncClient.responses = [httpx.Response(404), httpx.Response(405)]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncClient())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        request_async("KEY", "https://fofa.example/api.php", purpose="search")
    )

    assert result.endpoint_mode == "fallback"
    assert result.category == "endpoint"
    assert result.http_status == 405
    assert _AsyncClient.calls == [
        ("GET", "https://fofa.example/api.php"),
        ("GET", "https://fofa.example/api/v1/search/all"),
    ]


def test_explicit_key_is_added_to_transport_params(monkeypatch) -> None:
    captured: list[dict] = []

    class Client(_AsyncClient):
        async def get(self, url, **kwargs):
            captured.append(dict(kwargs.get("params") or {}))
            return await super().get(url, **kwargs)

    _AsyncClient.calls = []
    _AsyncClient.responses = [httpx.Response(200, json={"ok": True})]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    asyncio.run(request_async("KEY", "https://fofa.example", purpose="search"))

    assert captured == [{"key": "KEY"}]


def test_sync_network_error_does_not_expose_key(monkeypatch) -> None:
    key = "sync key/with+symbols"
    encoded = quote(key, safe="")
    plus_encoded = quote_plus(key, safe="")

    class Client(_SyncClient):
        def get(self, url, **_kwargs):
            raise httpx.ConnectError(
                f"connect failed {key} {encoded} {plus_encoded}",
                request=httpx.Request("GET", f"https://fixture.example/{encoded}"),
            )

    monkeypatch.setattr(httpx, "Client", lambda **_kwargs: Client())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = request_sync(key, "https://fixture.example", purpose="search")

    assert result.category == "network"
    assert result.error is not None
    rendered = str(result.error) + repr(result.error)
    assert key not in rendered
    assert encoded not in rendered
    assert plus_encoded not in rendered


def test_async_network_error_does_not_expose_key(monkeypatch) -> None:
    key = "async key/with+symbols"
    encoded = quote(key, safe="")
    plus_encoded = quote_plus(key, safe="")

    class Client(_AsyncClient):
        async def get(self, url, **_kwargs):
            raise httpx.ReadTimeout(
                f"timeout {key} {encoded} {plus_encoded}",
                request=httpx.Request("GET", f"https://fixture.example/{encoded}"),
            )

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = asyncio.run(request_async(key, "https://fixture.example", purpose="search"))

    assert result.category == "network"
    assert result.error is not None
    rendered = str(result.error) + repr(result.error)
    assert key not in rendered
    assert encoded not in rendered
    assert plus_encoded not in rendered


def test_custom_path_retries_post_then_reports_same_url(monkeypatch) -> None:
    _AsyncClient.calls = []
    _AsyncClient.responses = [httpx.Response(405), httpx.Response(200, json={"ok": True})]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncClient())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        request_async("https://fofa.example/private/search/", purpose="search", params={"key": "KEY"})
    )

    assert result.resolved_url == "https://fofa.example/private/search/"
    assert result.endpoint_mode == "exact"
    assert _AsyncClient.calls == [
        ("GET", "https://fofa.example/private/search/"),
        ("POST", "https://fofa.example/private/search/"),
    ]


def test_custom_404_falls_back_to_same_origin_standard_path(monkeypatch) -> None:
    _SyncClient.calls = []
    _SyncClient.responses = [httpx.Response(404), httpx.Response(200, json={"ok": True})]
    monkeypatch.setattr(httpx, "Client", lambda **_kwargs: _SyncClient())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = request_sync(
        "https://fofa.example/private/search", purpose="search", params={"key": "KEY"}
    )

    assert result.resolved_url == "https://fofa.example/api/v1/search/all"
    assert result.endpoint_mode == "fallback"
    assert result.http_status == 200
    assert _SyncClient.calls == [
        ("GET", "https://fofa.example/private/search"),
        ("GET", "https://fofa.example/api/v1/search/all"),
    ]


def test_custom_auth_failure_does_not_switch_path(monkeypatch) -> None:
    _AsyncClient.calls = []
    _AsyncClient.responses = [httpx.Response(401, json={"error": "invalid"})]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncClient())
    monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

    result = asyncio.run(
        request_async("https://fofa.example/private/search", purpose="search", params={"key": "KEY"})
    )

    assert result.resolved_url == "https://fofa.example/private/search"
    assert result.endpoint_mode == "exact"
    assert result.http_status == 401
    assert result.category == "auth"
    assert len(_AsyncClient.calls) == 1


def test_body_errors_are_classified_without_path_switch(monkeypatch) -> None:
    cases = [
        ({"error": True, "code": "820041", "errmsg": "daily quota exceeded"}, "daily_limit"),
        ({"error": True, "code": "Q3005", "errmsg": "too many requests"}, "rate_limit"),
        ({"error": True, "errmsg": "invalid key"}, "auth"),
    ]
    for payload, category in cases:
        _AsyncClient.calls = []
        _AsyncClient.responses = [httpx.Response(200, json=payload)]
        monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: _AsyncClient())
        monkeypatch.setattr("app.tools.netguard.assert_safe_outbound_url", lambda *_args, **_kwargs: None)

        result = asyncio.run(
            request_async("https://fofa.example/private/search", purpose="search", params={"key": "KEY"})
        )

        assert result.category == category
        assert len(_AsyncClient.calls) == 1
