from __future__ import annotations

import asyncio
from urllib.parse import quote, quote_plus

import httpx
import pytest

from app.fofa import client as fofa_client


def classify(message: str, **kwargs):
    return fofa_client.classify_fofa_failure(message, **kwargs)


def test_fofa_error_exposes_structured_fields() -> None:
    error = fofa_client.FofaError(
        "请求太频繁",
        kind="rate_limit",
        code="Q3005",
        retry_after=120,
    )

    assert str(error) == "请求太频繁"
    assert error.kind == "rate_limit"
    assert error.code == "Q3005"
    assert error.retry_after == 120
    assert error.account_error is False


def test_fofa_error_defaults_to_transient() -> None:
    error = fofa_client.FofaError("connection reset")

    assert error.kind == "transient"
    assert error.code == ""
    assert error.retry_after is None
    assert error.account_error is False


def test_fofa_error_keeps_legacy_account_error_compatibility() -> None:
    error = fofa_client.FofaError("invalid key", account_error=True)

    assert error.kind == "auth"
    assert error.account_error is True


def test_daily_limit_wins_over_generic_quota_marker() -> None:
    kind, code, retry_after = classify(
        "[820041] daily quota exceeded",
        status=200,
    )

    assert kind == "daily_limit"
    assert code == "820041"
    assert retry_after == 3600


def test_daily_limit_wins_over_conflicting_http_rate_status() -> None:
    kind, code, retry_after = classify(
        "[820041] daily quota exceeded",
        status=429,
    )

    assert kind == "daily_limit"
    assert code == "820041"
    assert retry_after == 3600


def test_standalone_daily_marker_is_daily_limit() -> None:
    assert classify("每日", status=200)[0] == "daily_limit"


@pytest.mark.parametrize(
    ("message", "status", "expected_code"),
    [
        ("Too Many Requests", 429, "429"),
        ("Too Many", 200, ""),
        ("Q3005", 200, "Q3005"),
        ("rate limit exceeded", 200, ""),
        ("请求太频繁", 200, ""),
    ],
)
def test_rate_limit_failures_are_classified(
    message: str,
    status: int,
    expected_code: str,
) -> None:
    kind, code, retry_after = classify(
        message,
        status=status,
        retry_after=90,
    )

    assert kind == "rate_limit"
    assert code == expected_code
    assert retry_after == 90


@pytest.mark.parametrize(
    ("message", "status"),
    [
        ("invalid key", 200),
        ("账号无效", 200),
        ("账号已过期", 200),
        ("过期", 200),
        ("权限不足", 200),
        ("无权限", 200),
        ("request rejected", 401),
        ("request rejected", 403),
    ],
)
def test_auth_failures_are_classified(message: str, status: int) -> None:
    kind, _code, retry_after = classify(message, status=status)

    assert kind == "auth"
    assert retry_after is None


@pytest.mark.parametrize(
    "message",
    [
        "connection reset",
        "network timeout",
        "连接失败",
        "网络超时",
    ],
)
def test_network_failures_are_transient(message: str) -> None:
    assert classify(message)[0] == "transient"


def test_search_http_429_raises_structured_rate_limit(monkeypatch) -> None:
    class Response:
        status_code = 429
        text = "Too Many Requests"
        headers = {"Retry-After": "45"}

        @staticmethod
        def json():
            return {"error": True, "errmsg": "Too Many Requests"}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(fofa_client.FofaError) as exc_info:
        asyncio.run(fofa_client.search("key", 'domain="example.com"'))

    assert exc_info.value.kind == "rate_limit"
    assert exc_info.value.code == "429"
    assert exc_info.value.retry_after == 45


@pytest.mark.parametrize(
    ("status", "expected_kind"),
    [(429, "rate_limit"), (401, "auth"), (403, "auth"), (500, "transient")],
)
def test_search_classifies_non_2xx_before_json_shape(
    monkeypatch,
    status: int,
    expected_kind: str,
) -> None:
    class Response:
        status_code = status
        text = "upstream body"
        headers = {}

        @staticmethod
        def json():
            return ["not", "an", "object"]

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(fofa_client.FofaError) as exc_info:
        asyncio.run(fofa_client.search("key", 'domain="example.com"'))

    assert exc_info.value.kind == expected_kind
    assert exc_info.value.code == str(status)


def test_get_userinfo_classifies_non_2xx_before_json_shape(monkeypatch) -> None:
    class Response:
        status_code = 403
        text = "upstream body"
        headers = {}

        @staticmethod
        def json():
            return "not an object"

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(fofa_client.FofaError) as exc_info:
        asyncio.run(fofa_client.get_userinfo("key"))

    assert exc_info.value.kind == "auth"
    assert exc_info.value.code == "403"


@pytest.mark.parametrize("endpoint", ["search", "userinfo"])
def test_upstream_error_does_not_echo_plain_or_encoded_key(monkeypatch, endpoint: str) -> None:
    key = "fofa/probe+secret-VERYSECRET"
    encoded = quote(key, safe="")
    encoded_plus = quote_plus(key, safe="")
    echoed = f"invalid key: {key}; encoded={encoded}; plus={encoded_plus}"

    class Response:
        status_code = 200
        text = echoed
        headers = {}

        @staticmethod
        def json():
            return {"error": True, "errmsg": echoed}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url",
        lambda *_args, **_kwargs: None,
    )

    operation = (
        fofa_client.search(key, 'domain="example.com"')
        if endpoint == "search"
        else fofa_client.get_userinfo(key)
    )
    with pytest.raises(fofa_client.FofaError) as exc_info:
        asyncio.run(operation)

    assert key not in str(exc_info.value)
    assert encoded not in str(exc_info.value)
    assert encoded_plus not in str(exc_info.value)
    assert key not in repr(exc_info.value)
    assert encoded not in repr(exc_info.value)
    assert encoded_plus not in repr(exc_info.value)


def test_search_data_error_prefers_daily_limit(monkeypatch) -> None:
    class Response:
        status_code = 200
        text = ""
        headers = {}

        @staticmethod
        def json():
            return {
                "error": True,
                "errmsg": "daily quota exceeded",
                "code": "820041",
            }

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(fofa_client.FofaError) as exc_info:
        asyncio.run(fofa_client.search("key", 'domain="example.com"'))

    assert exc_info.value.kind == "daily_limit"
    assert exc_info.value.code == "820041"
    assert exc_info.value.retry_after == 3600


def test_classifies_before_redacting_marker_like_key(monkeypatch) -> None:
    key = "Too Many"

    class Response:
        status_code = 200
        text = key
        headers = {}

        @staticmethod
        def json():
            return {"error": True, "errmsg": key}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(fofa_client.FofaError) as exc_info:
        asyncio.run(fofa_client.search(key, 'domain="example.com"'))

    assert exc_info.value.kind == "rate_limit"
    assert key not in str(exc_info.value)
    assert key not in repr(exc_info.value)


def test_get_userinfo_uses_shared_auth_classification(monkeypatch) -> None:
    class Response:
        status_code = 403
        text = ""
        headers = {}

        @staticmethod
        def json():
            return {"error": True, "errmsg": "invalid key"}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(fofa_client.FofaError) as exc_info:
        asyncio.run(fofa_client.get_userinfo("key"))

    assert exc_info.value.kind == "auth"
    assert exc_info.value.account_error is True
    assert exc_info.value.code == "403"


def test_engine_exports_shared_fofa_error() -> None:
    from app.engines.fofa import FofaError as EngineFofaError

    assert EngineFofaError is fofa_client.FofaError


def test_engine_classifies_non_2xx_before_json_shape(monkeypatch) -> None:
    from app.engines.fofa import FofaEngine

    class Response:
        status_code = 429
        text = "upstream body"
        headers = {}

        @staticmethod
        def json():
            return ["not", "an", "object"]

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(fofa_client.FofaError) as exc_info:
        asyncio.run(FofaEngine().search("key", 'domain="example.com"'))

    assert exc_info.value.kind == "rate_limit"
    assert exc_info.value.code == "429"
