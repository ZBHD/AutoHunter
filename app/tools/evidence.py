"""Pure, bounded evidence analyzers used by Worker and escalation agents."""
from __future__ import annotations

import json
import re
from difflib import SequenceMatcher
from typing import Any


_MAX_DOCUMENT = 1_500_000
_MAX_FLAT_PATHS = 600
_MAX_DIFF_ITEMS = 40
_MAX_PATHS = 1000
_MAX_DISCOVERED_ENDPOINTS = 2000
_SEMANTIC_HEADERS = {
    "allow",
    "content-disposition",
    "content-type",
    "location",
    "set-cookie",
    "www-authenticate",
}
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
_VOLATILE_JSON_NAMES = {"requestid", "request_id", "traceid", "trace_id"}


def _clip(value: Any, limit: int = 300) -> Any:
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "..."
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    try:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _path_rule(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if value.startswith("$"):
        return value
    return f"$.{value.lstrip('.')}"


def _ignored(path: str, rules: set[str]) -> bool:
    leaf = re.split(r"[.\[]", path)[-1].rstrip("]").lower()
    if leaf in _VOLATILE_JSON_NAMES:
        return True
    return any(
        path == rule or path.startswith(rule + ".") or path.startswith(rule + "[")
        for rule in rules
    )


def _flatten_json(
    value: Any,
    *,
    path: str = "$",
    rules: set[str] | None = None,
    out: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rules = rules or set()
    out = out if out is not None else {}
    if len(out) >= _MAX_FLAT_PATHS or _ignored(path, rules):
        return out
    if isinstance(value, dict):
        if not value:
            out[path] = {}
        for key in sorted(value, key=str):
            child = f"{path}.{key}"
            _flatten_json(value[key], path=child, rules=rules, out=out)
            if len(out) >= _MAX_FLAT_PATHS:
                break
        return out
    if isinstance(value, list):
        if not value:
            out[path] = []
        for index, item in enumerate(value[:100]):
            _flatten_json(item, path=f"{path}[{index}]", rules=rules, out=out)
            if len(out) >= _MAX_FLAT_PATHS:
                break
        return out
    out[path] = value
    return out


def _normalized_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key).strip().lower(): str(item).strip()
        for key, item in value.items()
        if str(key).strip().lower() in _SEMANTIC_HEADERS
    }


def _response_body(value: dict[str, Any]) -> str:
    body = value.get("body", "") if isinstance(value, dict) else ""
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(body)


def _json_value(text: str) -> Any | None:
    try:
        return json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def compare_http_responses(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    ignore_json_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Compare two already captured responses without asserting exploitability."""
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        return {"ok": False, "error": "baseline 和 candidate 必须是响应对象"}

    rules = {_path_rule(item) for item in (ignore_json_paths or []) if _path_rule(item)}
    baseline_body = _response_body(baseline)
    candidate_body = _response_body(candidate)
    baseline_json = _json_value(baseline_body)
    candidate_json = _json_value(candidate_body)

    baseline_status = baseline.get("status_code")
    candidate_status = candidate.get("status_code")
    status_changed = baseline_status != candidate_status
    baseline_headers = _normalized_headers(baseline.get("headers") or baseline.get("response_headers"))
    candidate_headers = _normalized_headers(candidate.get("headers") or candidate.get("response_headers"))
    header_names = sorted(set(baseline_headers) | set(candidate_headers))
    header_changes = [
        {
            "name": name,
            "baseline": _clip(baseline_headers.get(name)),
            "candidate": _clip(candidate_headers.get(name)),
        }
        for name in header_names
        if baseline_headers.get(name) != candidate_headers.get(name)
    ][:_MAX_DIFF_ITEMS]

    if baseline_json is not None and candidate_json is not None:
        baseline_flat = _flatten_json(baseline_json, rules=rules)
        candidate_flat = _flatten_json(candidate_json, rules=rules)
        baseline_paths = set(baseline_flat)
        candidate_paths = set(candidate_flat)
        changed = [
            {
                "path": path,
                "baseline": _clip(baseline_flat[path]),
                "candidate": _clip(candidate_flat[path]),
            }
            for path in sorted(baseline_paths & candidate_paths)
            if baseline_flat[path] != candidate_flat[path]
        ][:_MAX_DIFF_ITEMS]
        added = [
            {"path": path, "value": _clip(candidate_flat[path])}
            for path in sorted(candidate_paths - baseline_paths)
        ][:_MAX_DIFF_ITEMS]
        removed = [
            {"path": path, "value": _clip(baseline_flat[path])}
            for path in sorted(baseline_paths - candidate_paths)
        ][:_MAX_DIFF_ITEMS]
        baseline_canonical = json.dumps(baseline_flat, ensure_ascii=False, sort_keys=True, default=str)
        candidate_canonical = json.dumps(candidate_flat, ensure_ascii=False, sort_keys=True, default=str)
        similarity = round(SequenceMatcher(None, baseline_canonical, candidate_canonical).ratio(), 3)
        body_result = {
            "format": "json",
            "similarity": similarity,
            "changed_paths": changed,
            "added_paths": added,
            "removed_paths": removed,
            "truncated": len(baseline_flat) >= _MAX_FLAT_PATHS or len(candidate_flat) >= _MAX_FLAT_PATHS,
        }
        body_changed = bool(changed or added or removed)
    else:
        baseline_normalized = " ".join(baseline_body.split())
        candidate_normalized = " ".join(candidate_body.split())
        similarity = round(SequenceMatcher(None, baseline_normalized, candidate_normalized).ratio(), 3)
        body_result = {
            "format": "text",
            "similarity": similarity,
            "baseline_preview": _clip(baseline_normalized, 1200),
            "candidate_preview": _clip(candidate_normalized, 1200),
        }
        body_changed = baseline_normalized != candidate_normalized

    material = status_changed or body_changed or bool(header_changes)
    return {
        "ok": True,
        "status": {
            "baseline": baseline_status,
            "candidate": candidate_status,
            "changed": status_changed,
        },
        "headers": {"changed": header_changes},
        "body": body_result,
        "material_difference": material,
        "guidance": (
            "差异只说明两个响应不一致。请确认请求上下文只改变了待验证变量，并用最小样本复核；"
            "形成真实越权、鉴权绕过或状态变化证据后再提交漏洞。"
        ),
    }


def _resolve_local_ref(document: dict[str, Any], value: Any) -> Any:
    if not isinstance(value, dict) or not isinstance(value.get("$ref"), str):
        return value
    ref = value["$ref"]
    if not ref.startswith("#/"):
        return value
    current: Any = document
    for token in ref[2:].split("/"):
        if not isinstance(current, dict):
            return value
        current = current.get(token.replace("~1", "/").replace("~0", "~"))
    return current if current is not None else value


def _schema_properties(document: dict[str, Any], schema: Any) -> list[str]:
    schema = _resolve_local_ref(document, schema)
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return [str(name) for name in list(properties)[:40]]
    if schema.get("type") == "array":
        return _schema_properties(document, schema.get("items"))
    return []


def _request_fields(document: dict[str, Any], operation: dict[str, Any]) -> list[str]:
    request_body = _resolve_local_ref(document, operation.get("requestBody"))
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []
    fields: list[str] = []
    for media in content.values():
        if not isinstance(media, dict):
            continue
        fields.extend(_schema_properties(document, media.get("schema")))
    return list(dict.fromkeys(fields))[:40]


def _api_base_url(document: dict[str, Any], explicit: str) -> str:
    if explicit.strip():
        return explicit.strip().rstrip("/")
    servers = document.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        return str(servers[0].get("url") or "").rstrip("/")
    host = str(document.get("host") or "").strip()
    if not host:
        return ""
    schemes = document.get("schemes") if isinstance(document.get("schemes"), list) else []
    scheme = str(schemes[0] if schemes else "https")
    base_path = str(document.get("basePath") or "").strip("/")
    return f"{scheme}://{host}" + (f"/{base_path}" if base_path else "")


def _auth_mode(root_security: Any, operation: dict[str, Any]) -> str:
    if "security" in operation:
        security = operation.get("security")
        return "public" if security == [] else "required"
    if isinstance(root_security, list) and root_security:
        return "required"
    return "unspecified"


def _risk_profile(method: str, path: str, operation: dict[str, Any], auth: str, focus: list[str]) -> tuple[int, list[str]]:
    text = " ".join([
        path,
        str(operation.get("summary") or ""),
        str(operation.get("description") or ""),
        " ".join(str(item) for item in (operation.get("tags") or [])),
    ]).lower()
    score = {"GET": 8, "HEAD": 4, "OPTIONS": 2, "POST": 24, "PUT": 30, "PATCH": 30, "DELETE": 34}.get(method, 6)
    reasons: list[str] = []
    weighted = (
        (("admin", "role", "permission", "管理员", "权限"), 28, "管理/权限接口"),
        (("password", "reset", "token", "session", "oauth", "login", "auth", "密码", "认证"), 24, "认证或凭证入口"),
        (("upload", "import", "file", "attachment", "上传", "导入", "文件"), 24, "文件处理入口"),
        (("export", "download", "report", "backup", "导出", "下载", "备份"), 18, "批量读取入口"),
        (("exec", "command", "script", "template", "命令", "执行", "脚本"), 34, "执行类入口"),
        (("config", "secret", "credential", "key", "配置", "密钥", "凭证"), 22, "配置或密钥入口"),
        (("pay", "refund", "order", "invoice", "finance", "审批", "支付", "退款", "订单"), 22, "关键业务状态入口"),
    )
    for markers, weight, reason in weighted:
        if any(marker in text for marker in markers):
            score += weight
            reasons.append(reason)
    if "{" in path and "}" in path:
        score += 10
        reasons.append("对象标识参数")
    if auth == "public" and score >= 20:
        score += 16
        reasons.append("文档声明无需鉴权")
    for keyword in focus:
        if keyword.lower() in text:
            score += 12
            reasons.append(f"命中关注方向:{keyword[:24]}")
    return min(score, 100), list(dict.fromkeys(reasons))[:8]


def analyze_api_schema(
    document: str,
    base_url: str = "",
    focus: list[str] | None = None,
) -> dict[str, Any]:
    """Parse OpenAPI/Swagger JSON into a prioritized, bounded endpoint inventory."""
    if not isinstance(document, str) or not document.strip():
        return {"ok": False, "error": "document 不能为空"}
    if len(document) > _MAX_DOCUMENT:
        return {"ok": False, "error": f"API 文档超过 {_MAX_DOCUMENT} 字符上限"}
    try:
        parsed = json.loads(document)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"API 文档不是有效 JSON: {exc}"}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("paths"), dict):
        return {"ok": False, "error": "未找到 OpenAPI/Swagger paths 对象"}

    root_security = parsed.get("security")
    resolved_base = _api_base_url(parsed, base_url)
    focus_terms = [str(item).strip() for item in (focus or []) if str(item).strip()][:12]
    endpoints: list[dict[str, Any]] = []
    all_paths = parsed["paths"]
    scan_truncated = len(all_paths) > _MAX_PATHS
    for path, path_item in list(all_paths.items())[:_MAX_PATHS]:
        if len(endpoints) >= _MAX_DISCOVERED_ENDPOINTS:
            scan_truncated = True
            break
        path_item = _resolve_local_ref(parsed, path_item)
        if not isinstance(path_item, dict):
            continue
        shared_parameters = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        for method_name, operation in path_item.items():
            if len(endpoints) >= _MAX_DISCOVERED_ENDPOINTS:
                scan_truncated = True
                break
            if str(method_name).lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            method = str(method_name).upper()
            auth = _auth_mode(root_security, operation)
            parameters = [*shared_parameters, *(operation.get("parameters") or [])]
            parameter_names = [
                str(item.get("name"))
                for item in parameters
                if isinstance(item, dict) and item.get("name")
            ]
            request_fields = _request_fields(parsed, operation)
            risk_score, risk_reasons = _risk_profile(method, str(path), operation, auth, focus_terms)
            endpoint_url = (
                f"{resolved_base}/{str(path).lstrip('/')}" if resolved_base else str(path)
            )
            endpoints.append({
                "method": method,
                "path": str(path),
                "url": endpoint_url,
                "summary": _clip(operation.get("summary") or operation.get("description") or "", 240),
                "tags": [str(item) for item in (operation.get("tags") or [])[:8]],
                "auth": auth,
                "parameters": list(dict.fromkeys(parameter_names))[:40],
                "request_fields": request_fields,
                "risk_score": risk_score,
                "risk_reasons": risk_reasons,
                "deprecated": bool(operation.get("deprecated", False)),
            })

    endpoints.sort(key=lambda item: (-item["risk_score"], item["path"], item["method"]))
    return {
        "ok": True,
        "title": _clip((parsed.get("info") or {}).get("title", ""), 160) if isinstance(parsed.get("info"), dict) else "",
        "version": str(parsed.get("openapi") or parsed.get("swagger") or ""),
        "base_url": resolved_base,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints[:80],
        "truncated": scan_truncated or len(endpoints) > 80,
        "guidance": (
            "清单只用于选择高价值最小验证点。优先核对文档鉴权声明、对象参数和读写对称接口；"
            "再用 http_request 获取真实请求响应，禁止把文档存在本身当成漏洞。"
        ),
    }
