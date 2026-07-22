from __future__ import annotations

import base64
import json

import httpx
import pytest

from app.engines.censys import CensysEngine
from app.engines.hunter import HunterEngine
from app.engines.shodan import ShodanEngine
from app.engines.zoomeye import ZoomEyeEngine


def _mock_client(monkeypatch, module, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda **_kwargs: client)
    return client


@pytest.mark.asyncio
async def test_hunter_uses_openapi_and_base64_query(monkeypatch) -> None:
    from app.engines import hunter as module
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, request=request, json={
            "code": 200,
            "data": {"total": 1, "arr": [{
                "domain": "app.test",
                "ip": "192.0.2.10",
                "port": 443,
                "web_title": "Login",
                "company": "Example",
            }]},
        })

    _mock_client(monkeypatch, module, handler)
    result = await HunterEngine().search("hunter-key", 'domain="example.com"', page_size=500)
    request = captured["request"]
    assert isinstance(request, httpx.Request)
    assert request.url.path.endswith("/openApi/search")
    decoded_query = base64.urlsafe_b64decode(
        request.url.params["search"] + "=" * (-len(request.url.params["search"]) % 4)
    ).decode()
    assert decoded_query == 'domain="example.com"'
    assert request.url.params["is_web"] == "3"
    assert request.url.params["page_size"] == "100"
    assert result.results[0][3] == "Login"


@pytest.mark.asyncio
async def test_zoomeye_uses_v2_json_request(monkeypatch) -> None:
    from app.engines import zoomeye as module
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, request=request, json={
            "code": 60000,
            "total": 1,
            "data": [{
                "hostname": "app.test",
                "ip": "192.0.2.11",
                "port": 443,
                "title": ["Login", "Portal"],
                "domain": "app.test",
                "organization.name": "Example",
            }],
        })

    _mock_client(monkeypatch, module, handler)
    result = await ZoomEyeEngine().search("zoomeye-key", 'title="Login"', page_size=200)
    request = captured["request"]
    assert isinstance(request, httpx.Request)
    assert request.url.host == "api.zoomeye.ai"
    assert request.url.path == "/v2/search"
    payload = json.loads(request.content)
    assert base64.b64decode(payload["qbase64"]).decode() == 'title="Login"'
    assert payload["pagesize"] == 200
    assert payload["sub_type"] == "web"
    assert result.results[0][3] == "Login | Portal"


@pytest.mark.asyncio
async def test_shodan_uses_host_search_parameters(monkeypatch) -> None:
    from app.engines import shodan as module
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, request=request, json={
            "total": 1,
            "matches": [{
                "ip_str": "192.0.2.12",
                "port": 443,
                "hostnames": ["app.test"],
                "http": {"title": "Login"},
                "org": "Example",
            }],
        })

    _mock_client(monkeypatch, module, handler)
    result = await ShodanEngine().search("shodan-key", "http.title:Login", page=2, page_size=10)
    request = captured["request"]
    assert isinstance(request, httpx.Request)
    assert request.url.path == "/shodan/host/search"
    assert request.url.params["page"] == "2"
    assert "limit" not in request.url.params
    assert result.results[0][:4] == ["app.test", "192.0.2.12", "443", "Login"]


@pytest.mark.asyncio
async def test_censys_uses_cursor_and_extracts_v2_fields(monkeypatch) -> None:
    from app.engines import censys as module
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, request=request, json={
            "result": {
                "total": 1,
                "hits": [{
                    "ip": "192.0.2.13",
                    "dns": {"names": ["app.test"]},
                    "services": [{
                        "port": 443,
                        "service_name": "HTTPS",
                        "http": {"host": "app.test", "response": {"html_title": "Login"}},
                    }],
                    "autonomous_system": {"organization": "Example"},
                }],
                "links": {"next": "cursor-next"},
            },
        })

    _mock_client(monkeypatch, module, handler)
    result = await CensysEngine().search(
        "api-id:api-secret", 'services.http.response.html_title="Login"', cursor="cursor-current"
    )
    request = captured["request"]
    assert isinstance(request, httpx.Request)
    assert request.url.params["cursor"] == "cursor-current"
    assert "page" not in request.url.params
    assert result.next_cursor == "cursor-next"
    assert result.results[0] == ["app.test", "192.0.2.13", "443", "Login", "app.test", "Example"]
