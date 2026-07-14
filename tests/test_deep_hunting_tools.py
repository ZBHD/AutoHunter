from __future__ import annotations

import base64
import json
import threading

from app.agents.escalate import EscalateHunter
from app.agents.history import bounded_tool_content
from app.agents.worker import Worker
from app.tools.auth_analyzer import analyze_auth_material
from app.tools.evidence import analyze_api_schema, compare_http_responses
from app.tools.http_surface import extract_http_surface
from app.tools.executor import ToolExecutor
from app.tools.schemas import ESCALATE_TOOL_SCHEMAS, TOOL_SCHEMAS


def _tool_names(schemas: list[dict]) -> set[str]:
    return {item["function"]["name"] for item in schemas}


def test_compare_http_responses_reports_structured_json_changes() -> None:
    baseline = {
        "status_code": 200,
        "headers": {"content-type": "application/json", "x-request-id": "req-a"},
        "body": json.dumps({
            "user": {"id": 1, "role": "user"},
            "requestId": "req-a",
        }),
    }
    candidate = {
        "status_code": 200,
        "headers": {"content-type": "application/json", "x-request-id": "req-b"},
        "body": json.dumps({
            "user": {"id": 2, "role": "admin"},
            "requestId": "req-b",
            "token": "candidate-token",
        }),
    }

    result = compare_http_responses(
        baseline,
        candidate,
        ignore_json_paths=["$.requestId"],
    )

    assert result["ok"] is True
    assert result["body"]["format"] == "json"
    assert result["material_difference"] is True
    assert {item["path"] for item in result["body"]["changed_paths"]} == {
        "$.user.id",
        "$.user.role",
    }
    assert {item["path"] for item in result["body"]["added_paths"]} == {"$.token"}
    assert "$.requestId" not in json.dumps(result, ensure_ascii=False)


def test_compare_http_responses_ignores_selected_volatile_fields() -> None:
    baseline = {"status_code": 200, "body": '{"ok":true,"timestamp":"a"}'}
    candidate = {"status_code": 200, "body": '{"ok":true,"timestamp":"b"}'}

    result = compare_http_responses(
        baseline,
        candidate,
        ignore_json_paths=["timestamp"],
    )

    assert result["material_difference"] is False
    assert result["body"]["similarity"] == 1.0


def test_analyze_api_schema_prioritizes_sensitive_write_endpoints() -> None:
    document = json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/v1"}],
        "security": [{"bearerAuth": []}],
        "paths": {
            "/health": {
                "get": {"security": [], "summary": "Health check"},
            },
            "/users/{id}": {
                "get": {
                    "summary": "Read user",
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                },
            },
            "/admin/users/{id}": {
                "delete": {
                    "summary": "Delete admin user",
                    "tags": ["admin"],
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                },
            },
        },
    })

    result = analyze_api_schema(document)

    assert result["ok"] is True
    assert result["endpoint_count"] == 3
    assert result["endpoints"][0]["path"] == "/admin/users/{id}"
    assert result["endpoints"][0]["method"] == "DELETE"
    assert result["endpoints"][0]["auth"] == "required"
    health = next(item for item in result["endpoints"] if item["path"] == "/health")
    assert health["auth"] == "public"
    assert result["endpoints"][0]["risk_score"] > health["risk_score"]


def test_analyze_api_schema_scores_late_paths_before_truncating_output() -> None:
    paths = {f"/health/{index}": {"get": {"summary": "Health"}} for index in range(130)}
    paths["/admin/users/export"] = {"post": {"summary": "Export all users"}}

    result = analyze_api_schema(json.dumps({"openapi": "3.0.0", "paths": paths}))

    assert result["endpoint_count"] == 131
    assert result["endpoints"][0]["path"] == "/admin/users/export"
    assert len(result["endpoints"]) == 80
    assert result["truncated"] is True


def test_executor_api_analyzer_can_fetch_full_document_by_url() -> None:
    document = json.dumps({
        "openapi": "3.0.0",
        "info": {"description": "x" * 5000},
        "paths": {"/admin/export": {"post": {"summary": "Export users"}}},
    })
    executor = ToolExecutor.__new__(ToolExecutor)
    calls: list[dict] = []

    def fake_http_request(**kwargs):
        calls.append(kwargs)
        return {
            "ok": True,
            "status_code": 200,
            "url": "https://example.test/openapi.json",
            "response_headers": {"content-type": "application/json"},
            "body": document,
            "body_truncated": False,
            "_capture": {"id": "capture-api"},
        }

    executor.http_request = fake_http_request

    result = ToolExecutor.analyze_api_schema(
        executor,
        url="https://example.test/openapi.json",
    )

    assert result["ok"] is True
    assert result["endpoint_count"] == 1
    assert result["endpoints"][0]["path"] == "/admin/export"
    assert result["_capture"] == {"id": "capture-api"}
    assert calls[0]["body_preview_limit"] > 4096


def test_executor_html_analyzer_can_fetch_full_page_by_url() -> None:
    body = "<!--" + ("x" * 5000) + "--><form action='/admin/import'><input type='file' name='f'></form>"
    executor = ToolExecutor.__new__(ToolExecutor)

    def fake_http_request(**_kwargs):
        return {
            "ok": True,
            "status_code": 200,
            "url": "https://example.test/app",
            "response_headers": {"content-type": "text/html"},
            "body": body,
            "body_truncated": False,
        }

    executor.http_request = fake_http_request

    result = ToolExecutor.extract_http_surface(executor, url="https://example.test/app")

    assert result["ok"] is True
    assert result["forms"][0]["has_file_input"] is True
    assert result["forms"][0]["action"] == "https://example.test/admin/import"


def test_extract_http_surface_finds_forms_uploads_and_api_paths() -> None:
    body = """
    <html><head><script src="/assets/app.js"></script></head><body>
      <form action="/api/login" method="post">
        <input name="username"><input name="password" type="password">
      </form>
      <form action="/admin/import" method="post" enctype="multipart/form-data">
        <input name="archive" type="file">
      </form>
      <a href="/api/users/export">Export users</a>
    </body></html>
    """

    result = extract_http_surface(
        body,
        base_url="https://example.test/root",
        response_headers={"content-type": "text/html"},
    )

    assert result["ok"] is True
    assert len(result["forms"]) == 2
    assert result["forms"][1]["has_file_input"] is True
    assert result["forms"][1]["action"] == "https://example.test/admin/import"
    assert "https://example.test/assets/app.js" in result["scripts"]
    paths = {item["url"] for item in result["candidates"]}
    assert "https://example.test/api/users/export" in paths
    assert result["candidates"][0]["risk_score"] >= result["candidates"][-1]["risk_score"]


def test_analyze_auth_material_summarizes_jwt_cookie_and_csrf_without_raw_secrets() -> None:
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjQxMDI0NDQ4MDB9."
        "signature"
    )

    result = analyze_auth_material(
        request_headers={"Authorization": f"Bearer {token}", "Cookie": "session=abc123; theme=dark"},
        response_headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly; SameSite=Lax"},
        body='<input type="hidden" name="csrf_token" value="secret-csrf">',
    )

    assert result["ok"] is True
    assert result["authorization"]["scheme"] == "bearer"
    assert result["authorization"]["jwt"]["payload"]["role"] == "admin"
    assert result["authorization"]["jwt"]["signature_verified"] is False
    assert {item["name"] for item in result["request_cookies"]} == {"session", "theme"}
    session_cookie = next(item for item in result["response_cookies"] if item["name"] == "session")
    assert session_cookie["http_only"] is True
    assert session_cookie["same_site"] == "Lax"
    assert "csrf_token" in result["csrf_candidates"]
    assert token not in json.dumps(result, ensure_ascii=False)


def test_analyze_auth_material_redacts_sensitive_jwt_claim_values() -> None:
    def segment(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    secret = "claim-secret-value"
    token = (
        f"{segment({'alg': 'none'})}."
        f"{segment({'role': 'admin', 'api_key': secret, 'context': {'client_secret': secret}})}.sig"
    )

    result = analyze_auth_material(request_headers={"Authorization": f"Bearer {token}"})
    payload = result["authorization"]["jwt"]["payload"]

    assert payload["role"] == "admin"
    assert payload["api_key"]["length"] == len(secret)
    assert "sha256_prefix" in payload["api_key"]
    assert payload["context"]["client_secret"]["length"] == len(secret)
    assert secret not in json.dumps(result, ensure_ascii=False)


def test_analyze_auth_material_preserves_multiple_set_cookie_headers() -> None:
    result = analyze_auth_material(
        set_cookie_headers=[
            "session=abc; Path=/; HttpOnly; SameSite=Lax",
            "csrf=def; Path=/; Secure; SameSite=Strict",
        ],
    )

    assert {item["name"] for item in result["response_cookies"]} == {"session", "csrf"}


def test_bounded_tool_content_caps_recent_analyzer_output(monkeypatch) -> None:
    from app.agents import history as history_module

    monkeypatch.setattr(history_module.worker_config, "output_truncate", 600)
    monkeypatch.setattr(history_module.worker_config, "llm_tool_output_truncate", 600)
    result = {
        "ok": True,
        "endpoint_count": 100,
        "endpoints": [
            {
                "method": "POST",
                "path": f"/admin/export/{index}",
                "risk_score": 90 - index,
                "risk_reasons": ["管理/权限接口", "批量读取入口"],
            }
            for index in range(80)
        ],
    }

    content = bounded_tool_content(result, "analyze_api_schema")

    assert len(content) <= 600
    assert "/admin/export/0" in content
    assert "endpoint_count" in content


def test_evidence_tools_are_registered_for_worker_and_escalation() -> None:
    expected = {
        "compare_http_responses",
        "analyze_api_schema",
        "extract_http_surface",
        "analyze_auth_material",
    }

    assert expected <= _tool_names(TOOL_SCHEMAS)
    assert expected <= _tool_names(ESCALATE_TOOL_SCHEMAS)


class _EvidenceExecutor:
    def compare_http_responses(self, baseline, candidate, ignore_json_paths=None):
        return {
            "kind": "compare",
            "baseline": baseline,
            "candidate": candidate,
            "ignore_json_paths": ignore_json_paths,
        }

    def analyze_api_schema(self, document="", url="", base_url="", focus=None):
        return {
            "kind": "schema",
            "document": document,
            "url": url,
            "base_url": base_url,
            "focus": focus,
        }

    def extract_http_surface(self, body="", url="", base_url="", response_headers=None):
        return {
            "kind": "surface",
            "body": body,
            "url": url,
            "base_url": base_url,
            "response_headers": response_headers,
        }

    def analyze_auth_material(self, request_headers=None, response_headers=None, set_cookie_headers=None, body=""):
        return {
            "kind": "auth",
            "request_headers": request_headers,
            "response_headers": response_headers,
            "set_cookie_headers": set_cookie_headers,
            "body": body,
        }


def _bare_worker() -> Worker:
    worker = Worker.__new__(Worker)
    worker.executor = _EvidenceExecutor()
    worker.on_event = lambda *_args, **_kwargs: None
    worker._tool_counts = {}
    worker._last_js_analysis_round = 0
    worker._post_js_validation_count = 0
    return worker


def test_worker_dispatches_evidence_tools() -> None:
    worker = _bare_worker()

    compared = worker._dispatch(
        "compare_http_responses",
        {"baseline": {"body": "a"}, "candidate": {"body": "b"}},
        3,
    )
    analyzed = worker._dispatch(
        "analyze_api_schema",
        {"document": "{}", "base_url": "https://api.example.test", "focus": ["admin"]},
        4,
    )
    surfaced = worker._dispatch(
        "extract_http_surface",
        {"body": "<form></form>", "base_url": "https://example.test"},
        5,
    )
    auth = worker._dispatch(
        "analyze_auth_material",
        {"request_headers": {"Authorization": "Bearer token"}},
        6,
    )

    assert compared["kind"] == "compare"
    assert analyzed == {
        "kind": "schema",
        "document": "{}",
        "url": "",
        "base_url": "https://api.example.test",
        "focus": ["admin"],
    }
    assert surfaced["kind"] == "surface"
    assert auth["kind"] == "auth"


def test_escalation_dispatches_evidence_tools() -> None:
    hunter = EscalateHunter.__new__(EscalateHunter)
    hunter.cancel_event = threading.Event()
    hunter.executor = _EvidenceExecutor()
    hunter.on_event = lambda *_args, **_kwargs: None
    hunter._result = None

    compared = hunter._dispatch(
        "compare_http_responses",
        {"baseline": {"body": "a"}, "candidate": {"body": "b"}},
    )
    analyzed = hunter._dispatch(
        "analyze_api_schema",
        {"document": "{}", "base_url": "https://api.example.test"},
    )
    surfaced = hunter._dispatch(
        "extract_http_surface",
        {"body": "<form></form>", "base_url": "https://example.test"},
    )
    auth = hunter._dispatch(
        "analyze_auth_material",
        {"response_headers": {"Set-Cookie": "session=x"}},
    )

    assert compared["kind"] == "compare"
    assert analyzed["kind"] == "schema"
    assert surfaced["kind"] == "surface"
    assert auth["kind"] == "auth"
