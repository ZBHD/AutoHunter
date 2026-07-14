"""LLM 多轮对话历史压缩：在「不漏信息、不影响出洞」前提下榨掉重复大文本。

worker / killsweep 走 function-calling 循环，每轮把【完整 messages 历史】重发给模型。
其中 role=tool 的响应里塞了 HTTP 完整 body、shell 全量输出，单条可达十几 KB。几十轮下来，
最早的大响应被重复发送几十次——这是输入 token 暴涨（输入/输出比 ~200:1）的根因。

核心原则（务必遵守，避免压坏出洞）：
1. 只压缩「超出最近窗口」的旧 tool 响应；窗口内的最新响应一字不动。
2. 差异化保留——不同工具的「关键决策信息」不一样，分别精准保留：
   - analyze_javascript：旧结果保留 summary、关键 chains、最高分 endpoint/finding；
     不再整包重发上百个接口，避免 JS 站点后续每轮重复烧输入。
   - http_request：压 body（只留开头），但保留 status / url / body_len / 关键响应头
     （Server/Content-Type/Set-Cookie/Location/WWW-Authenticate/CSP），这些是判断
     鉴权/指纹/跳转的依据。
   - run_shell：压 output（只留开头），保留 return_code / timed_out。
   - 错误 / blocked：保留 error + guidance 开头，模型需要知道为什么失败/被拦才能纠偏。
3. 原始 messages 不变，只返回【发送副本】，保证 OpenAI 协议历史完整可继续 append。

要求：append tool 消息时带上 "_round"(本轮序号) 和 "_tool"(工具名) 元字段。
"""
from __future__ import annotations

import json
from typing import Any

from app.config import worker_config
from app.tools.src_toolkit import SRC_TOOL_NAMES

# http 响应里值得在历史中保留的关键头（小写匹配）：鉴权/指纹/跳转/会话判断依据。
_KEY_RESP_HEADERS = (
    "server", "content-type", "content-length", "set-cookie", "location",
    "www-authenticate", "x-powered-by", "content-security-policy",
    "access-control-allow-origin", "x-frame-options",
)


def _compress_http(data: dict) -> dict:
    keep: dict[str, Any] = {}
    for k in ("ok", "status_code", "url", "body_len", "body_truncated", "blocked",
              "session_applied", "session_cookies_updated"):
        v = data.get(k)
        if v not in (None, "", [], {}):
            keep[k] = v
    headers = data.get("response_headers")
    if isinstance(headers, dict) and headers:
        picked = {k: v for k, v in headers.items() if k.lower() in _KEY_RESP_HEADERS}
        if picked:
            keep["key_headers"] = picked
    body = data.get("body")
    if isinstance(body, str) and body:
        keep["body_head"] = body[:240]
    for k in ("error", "guidance"):
        v = data.get(k)
        if isinstance(v, str) and v:
            keep[k] = v[:200]
    return keep


def _compress_shell(data: dict) -> dict:
    keep: dict[str, Any] = {}
    for k in ("ok", "return_code", "timed_out", "cancelled", "elapsed_sec",
              "blocked", "output_file"):
        v = data.get(k)
        if v not in (None, "", [], {}):
            keep[k] = v
    out = data.get("output")
    if isinstance(out, str) and out:
        keep["output_head"] = out[:300]
    for k in ("error", "guidance"):
        v = data.get(k)
        if isinstance(v, str) and v:
            keep[k] = v[:200]
    return keep


def _short(value: Any, limit: int = 160) -> str:
    text = str(value or "").replace("\n", " ").strip()
    return text if len(text) <= limit else text[: max(1, limit - 1)] + "…"


def _pick_fields(item: dict, fields: tuple[str, ...], limit: int = 160) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field in fields:
        value = item.get(field)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str):
            out[field] = _short(value, limit)
        elif isinstance(value, list):
            out[field] = [_short(v, 90) for v in value[:5]]
        else:
            out[field] = value
    return out


def _compress_js_analysis(data: dict) -> dict:
    """JS 审计旧结果专用摘要：保留可行动线索，丢弃大数组和长上下文。"""
    keep: dict[str, Any] = {}
    for key in ("ok", "source", "base_url"):
        value = data.get(key)
        if value not in (None, "", [], {}):
            keep[key] = _short(value, 180) if isinstance(value, str) else value
    if isinstance(data.get("summary"), dict):
        keep["summary"] = data["summary"]
    if isinstance(data.get("assets"), list):
        keep["assets_count"] = len(data["assets"])
        keep["assets_sample"] = [_short(x, 120) for x in data["assets"][:8]]
    if isinstance(data.get("fetch_errors"), list) and data["fetch_errors"]:
        keep["fetch_error_count"] = len(data["fetch_errors"])
        keep["fetch_errors_sample"] = [_short(x, 160) for x in data["fetch_errors"][:4]]

    chains = data.get("chains")
    if isinstance(chains, list) and chains:
        keep["chains_top"] = [
            _pick_fields(c, ("chain_type", "title", "severity", "score", "why", "evidence", "next_steps"), 180)
            for c in chains[:8] if isinstance(c, dict)
        ]

    endpoints = data.get("endpoint_inventory")
    if isinstance(endpoints, list) and endpoints:
        if len(endpoints) > 12:
            keep["endpoint_omitted"] = len(endpoints) - 12
        keep["endpoint_top"] = [
            _pick_fields(ep, ("url", "kind", "title", "severity", "score", "tags", "suggested_tests"), 160)
            for ep in endpoints[:12] if isinstance(ep, dict)
        ]

    findings = data.get("findings")
    if isinstance(findings, list) and findings:
        if len(findings) > 8:
            keep["findings_omitted"] = len(findings) - 8
        keep["findings_top"] = [
            _pick_fields(f, ("kind", "title", "severity", "score", "value", "evidence", "tags", "next_steps"), 160)
            for f in findings[:8] if isinstance(f, dict)
        ]
    return keep


def _compress_api_schema(data: dict) -> dict:
    keep = _pick_fields(data, ("ok", "title", "version", "base_url", "endpoint_count", "truncated"), 180)
    endpoints = data.get("endpoints")
    if isinstance(endpoints, list):
        keep["endpoints_top"] = [
            _pick_fields(
                item,
                ("method", "path", "url", "auth", "risk_score", "risk_reasons", "parameters", "request_fields"),
                140,
            )
            for item in endpoints[:10]
            if isinstance(item, dict)
        ]
    return keep


def _compress_http_surface(data: dict) -> dict:
    keep = _pick_fields(data, ("ok", "content_type", "generator"), 160)
    forms = data.get("forms")
    if isinstance(forms, list):
        keep["forms_top"] = [
            _pick_fields(item, ("action", "method", "has_password", "has_file_input", "risk_score", "risk_reasons"), 140)
            for item in forms[:6]
            if isinstance(item, dict)
        ]
    candidates = data.get("candidates")
    if isinstance(candidates, list):
        keep["candidates_top"] = [
            _pick_fields(item, ("method", "url", "source", "risk_score", "risk_reasons"), 140)
            for item in candidates[:10]
            if isinstance(item, dict)
        ]
    if isinstance(data.get("scripts"), list):
        keep["scripts_sample"] = [_short(item, 140) for item in data["scripts"][:8]]
    return keep


def _compress_response_compare(data: dict) -> dict:
    keep: dict[str, Any] = {
        "ok": data.get("ok"),
        "material_difference": data.get("material_difference"),
        "status": data.get("status"),
    }
    body = data.get("body")
    if isinstance(body, dict):
        keep["body"] = {
            "format": body.get("format"),
            "similarity": body.get("similarity"),
            "changed_paths": (body.get("changed_paths") or [])[:8],
            "added_paths": (body.get("added_paths") or [])[:8],
            "removed_paths": (body.get("removed_paths") or [])[:8],
        }
    return keep


def _compress_auth_analysis(data: dict) -> dict:
    keep = _pick_fields(data, ("ok", "authorization", "session_signals", "api_key_headers", "csrf_candidates"), 240)
    for name in ("request_cookies", "response_cookies", "jwt_candidates"):
        value = data.get(name)
        if isinstance(value, list):
            keep[name] = value[:8]
    return keep


def _compress_generic(data: dict) -> dict:
    """未知工具的兜底压缩：保留标量/短字段，长字符串只留开头。"""
    keep: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, (bool, int, float)):
            keep[k] = v
        elif isinstance(v, str):
            keep[k] = v[:200] if len(v) > 200 else v
        elif isinstance(v, (list, dict)) and not v:
            continue
        elif isinstance(v, list):
            keep[k + "_count"] = len(v)
    return keep


def summarize_tool_content(raw: str, tool: str) -> str:
    """把旧 tool 响应压成紧凑摘要：差异化保留关键决策信息，丢弃重复大文本。"""
    try:
        data = json.loads(raw)
    except Exception:
        return raw[:240]
    if not isinstance(data, dict):
        return str(data)[:240]

    if tool == "http_request":
        keep = _compress_http(data)
    elif tool == "run_shell":
        keep = _compress_shell(data)
    elif tool == "analyze_javascript":
        keep = _compress_js_analysis(data)
    elif tool == "analyze_api_schema":
        keep = _compress_api_schema(data)
    elif tool == "extract_http_surface":
        keep = _compress_http_surface(data)
    elif tool == "compare_http_responses":
        keep = _compress_response_compare(data)
    elif tool == "analyze_auth_material":
        keep = _compress_auth_analysis(data)
    elif tool in SRC_TOOL_NAMES:
        keep = _compress_shell(data)
    else:
        keep = _compress_generic(data)

    summary = json.dumps(keep, ensure_ascii=False, separators=(",", ":"))
    limit = 2400 if tool in {
        "analyze_javascript", "analyze_api_schema", "extract_http_surface",
        "compare_http_responses", "analyze_auth_material",
    } else 720
    # 分析工具摘要稍宽一些，保留后续可验证端点；其它工具保持小而稳定。
    return f"[历史已压缩·{tool}] {summary}"[:limit]


def bounded_tool_content(result: Any, tool: str) -> str:
    """Serialize a recent tool result without exceeding the configured LLM cap."""
    raw = json.dumps(result, ensure_ascii=False, default=str)
    if tool not in SRC_TOOL_NAMES | {
        "analyze_api_schema", "extract_http_surface",
        "compare_http_responses", "analyze_auth_material",
    }:
        return raw
    limit = max(1, int(worker_config.output_truncate or 4096))
    if worker_config.llm_tool_output_truncate > 0:
        limit = min(limit, int(worker_config.llm_tool_output_truncate))
    if len(raw) <= limit:
        return raw
    return summarize_tool_content(raw, tool)[:limit]


def compact_messages(messages: list[dict[str, Any]], cur_round: int) -> list[dict[str, Any]]:
    """生成发送给 LLM 的瘦身副本：超窗口的旧 tool 响应压成摘要，剥离内部 _round/_tool 字段。

    不带元字段的 tool 消息按 cur_round 处理（视为最新，不压缩）。
    """
    window = worker_config.history_full_tool_rounds
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.get("role") != "tool":
            out.append(m)
            continue
        rnd = m.get("_round", cur_round)
        tool = m.get("_tool", "tool")
        clean: dict[str, Any] = {
            "role": "tool",
            "tool_call_id": m.get("tool_call_id"),
            "content": m.get("content", ""),
        }
        if cur_round - rnd >= window:
            clean["content"] = summarize_tool_content(m.get("content", ""), tool)
        out.append(clean)
    return out
