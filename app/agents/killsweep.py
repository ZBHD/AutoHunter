"""通杀 Hunter Agent：审核 accepted 一个洞后，分析该系统能否「一打一片」。

流程（对应用户需求）：
  收到一个已采纳的 Finding → 认系统指纹 → FOFA 圈定同款系统+统计规模
  → 实打 1 个同款站点验证 → 判定是否可通杀 → 产出 KillsweepResult。

同步执行（内部 LLM/FOFA/工具均阻塞），由 orchestrator 在线程池里调用。
任何异常都降级返回，不阻断主循环。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
from typing import Any, Callable, Mapping, Optional
from urllib.parse import parse_qsl, urljoin, urlparse

from app.agents.history import compact_messages
from app.agents.prompts import is_enterprise_src, killsweep_system_prompt
from app.dedup import normalize_vuln_type
from app.llm.router import LLMRouter
from app.missed_signals import detect_tool_signals
from app.raw_evidence import detach_capture
from app.tools.executor import ToolExecutor
from app.tools.schemas import killsweep_tool_schemas
from app.fofa import endpoints as fofa_endpoints
from app.fofa.client import FofaError, _FOFA_ALLOWED_HOSTS, classify_fofa_failure, extract_fofa_error, extract_fofa_response_failure
from app.fofa.router import FofaKeyRouter, FofaPoolExhaustedError

_FOFA_BASE = "https://fofa.info"
# 通杀分析只做产品指纹、FOFA 圈定、抽样验证，必须有限轮数，避免模型递归空转。
_MAX_ROUNDS = int(os.environ.get("KILLSWEEP_MAX_ROUNDS", "24"))
# 叠加到查询上、把统计限定在教育行业的条件
_EDU_FILTER = '(domain=".edu.cn" || cert="edu" || org="edu")'
_HTTP_VERIFICATION_VERSION = 1
_HTTP_VERIFICATION_SECRET = secrets.token_bytes(32)
_SIGNAL_VULN_TYPES = {
    "token_exposure": frozenset({"info_leak"}),
    "sensitive_endpoint": frozenset({"info_leak", "unauthorized_access"}),
    "exception_leak": frozenset({"info_leak"}),
    "login_success": frozenset({"weak_password", "unauthorized_access"}),
}


def _qbase64(q: str) -> str:
    return base64.b64encode(q.encode("utf-8")).decode("ascii")


def _normalize_ip_address(value: str) -> str:
    address = ipaddress.ip_address(value)
    if (
        isinstance(address, ipaddress.IPv6Address)
        and address.ipv4_mapped is not None
    ):
        return address.ipv4_mapped.compressed
    return address.compressed


def _normalize_hostname(value: str) -> str:
    host = str(value or "").lower().rstrip(".")
    try:
        return _normalize_ip_address(host)
    except ValueError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return host


def _normalize_host(url_or_host: str, *, include_port: bool = True) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return ""
    from app.urlnorm import is_bare_ipv6, safe_hostname, safe_port, safe_urlparse
    try:
        return _normalize_ip_address(s.strip("[]"))
    except ValueError:
        pass
    parsed = safe_urlparse(s)
    host = _normalize_hostname(safe_hostname(parsed))
    if not host:
        return s.lower().strip("/")
    if include_port:
        port = safe_port(parsed)
        if port and port not in (80, 443):
            authority_host = f"[{host}]" if is_bare_ipv6(host) else host
            return f"{authority_host}:{port}"
    return f"[{host}]" if is_bare_ipv6(host) else host


def _canonical_http_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        hostname = _normalize_host(parsed.hostname or "")
        if scheme not in {"http", "https"} or not hostname:
            return ""
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    default_port = 80 if scheme == "http" else 443
    netloc = hostname if not port or port == default_port else f"{hostname}:{port}"
    return parsed._replace(
        scheme=scheme,
        netloc=netloc,
        path=parsed.path or "/",
        params="",
        fragment="",
    ).geturl()


def _body_parameter_names(body: str, content_type: str = "") -> set[str]:
    value = str(body or "").strip()
    if not value:
        return set()
    if "json" in content_type.lower() or value.startswith("{"):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, Mapping):
            return {str(key) for key in parsed if str(key)}
    if "multipart/form-data" in content_type.lower():
        return set(re.findall(r'name="([^"]+)"', value, re.I))
    return {
        name for name, _item in parse_qsl(value, keep_blank_values=True) if name
    }


def _source_request(raw_request: str, fallback_url: str) -> tuple[str, str, set[str]]:
    normalized = str(raw_request or "").replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = head.lstrip().splitlines()
    first_line = lines[:1]
    content_type = ""
    host_header = ""
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        header_name = name.strip().lower()
        if colon and header_name == "content-type":
            content_type = value.strip()
        elif colon and header_name == "host" and not host_header:
            host_header = value.strip()
    if first_line:
        match = re.match(r"([A-Z]+)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?", first_line[0], re.I)
        if match:
            method = match.group(1).upper()
            target = match.group(2)
            request_base = fallback_url
            if "://" not in target and host_header:
                fallback = str(fallback_url or "")
                if "://" not in fallback:
                    fallback = "http://" + fallback
                scheme = urlparse(fallback).scheme.lower()
                if scheme not in {"http", "https"}:
                    scheme = "http"
                host_base = f"{scheme}://{host_header}"
                try:
                    parsed_host = urlparse(host_base)
                    parsed_host.port
                except (TypeError, ValueError):
                    parsed_host = None
                if parsed_host is not None and parsed_host.hostname:
                    request_base = host_base
            url = target if "://" in target else urljoin(request_base, target)
            return method, url, _body_parameter_names(body if separator else "", content_type)
    return "GET", str(fallback_url or ""), set()


def _request_shape(
    method: str, url: str, body_parameter_names: set[str] | None = None
) -> str:
    canonical = _canonical_http_url(url)
    if not canonical:
        return ""
    parsed = urlparse(canonical)
    query_names = sorted({
        name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name
    })
    query = "&".join(query_names)
    shape = f"{str(method or 'GET').upper()} {parsed.path or '/'}" + (
        f"?{query}" if query else ""
    )
    body_names = sorted(body_parameter_names or set())
    return shape + (f" body={'&'.join(body_names)}" if body_names else "")


def _argument_body_parameter_names(arguments: Mapping[str, Any]) -> set[str]:
    json_body = arguments.get("json_body")
    if isinstance(json_body, Mapping):
        return {str(key) for key in json_body if str(key)}
    data = arguments.get("data")
    if isinstance(data, Mapping):
        return {str(key) for key in data if str(key)}
    return _body_parameter_names(str(data or ""))


def _raw_response_result(raw_response: str, url: str) -> dict[str, Any]:
    raw = str(raw_response or "")
    normalized = raw.replace("\r\n", "\n")
    status_code = 200
    headers: dict[str, str] = {}
    body = normalized
    if normalized.startswith("HTTP/"):
        head, separator, remainder = normalized.partition("\n\n")
        lines = head.splitlines()
        status_match = re.match(r"HTTP/\S+\s+(\d{3})", lines[0]) if lines else None
        if status_match:
            status_code = int(status_match.group(1))
        for line in lines[1:]:
            name, colon, value = line.partition(":")
            if colon and name.strip():
                headers[name.strip()] = value.strip()
        body = remainder if separator else ""
    return {
        "ok": True,
        "status_code": status_code,
        "url": url,
        "response_headers": headers,
        "body": body,
    }


def _source_verification_context(finding: Mapping[str, Any]) -> tuple[str, set[str]]:
    source_url = str(finding.get("target_url") or "")
    method, request_url, body_parameter_names = _source_request(
        str(finding.get("raw_request") or ""), source_url
    )
    result = _raw_response_result(
        str(finding.get("raw_response") or ""), request_url
    )
    signals = detect_tool_signals(
        "http_request", {"method": method, "url": request_url}, result
    )
    vuln_type = normalize_vuln_type(str(finding.get("vuln_type") or ""))
    return _request_shape(method, request_url, body_parameter_names), {
        item.rule_key
        for item in signals
        if vuln_type in _SIGNAL_VULN_TYPES.get(item.rule_key, frozenset())
    }


def _sign_http_verification(fields: dict[str, Any]) -> str:
    encoded = json.dumps(
        fields, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(_HTTP_VERIFICATION_SECRET, encoded, hashlib.sha256).hexdigest()


def _http_verification_proof(
    *,
    url: str,
    source_url: str,
    status_code: int,
    capture_id: str,
    request_shape: str,
    signal_keys: list[str],
    source_vuln_type: str,
    source_finding_id: str,
    capture_status: str,
    request_sha256: str,
    response_sha256: str,
) -> dict[str, Any] | None:
    canonical_url = _canonical_http_url(url)
    host = _normalize_host(canonical_url)
    origin_host = _normalize_host(source_url)
    host_identity = _normalize_host(canonical_url, include_port=False)
    origin_identity = _normalize_host(source_url, include_port=False)
    if (
        not canonical_url
        or not host
        or not origin_host
        or not host_identity
        or not origin_identity
        or host_identity == origin_identity
    ):
        return None
    fields: dict[str, Any] = {
        "version": _HTTP_VERIFICATION_VERSION,
        "url": canonical_url,
        "host": host,
        "origin_host": origin_host,
        "status_code": int(status_code),
        "capture_id": str(capture_id),
        "request_shape": str(request_shape),
        "signal_keys": sorted({str(key) for key in signal_keys if str(key)}),
        "source_vuln_type": normalize_vuln_type(source_vuln_type),
        "source_finding_id": str(source_finding_id or ""),
        "capture_status": str(capture_status or ""),
        "request_sha256": str(request_sha256 or ""),
        "response_sha256": str(response_sha256 or ""),
    }
    if (
        not fields["request_shape"]
        or not fields["signal_keys"]
        or not fields["source_vuln_type"]
        or not fields["source_finding_id"]
        or fields["capture_status"] != "complete"
        or not fields["request_sha256"]
        or not fields["response_sha256"]
    ):
        return None
    return {**fields, "signature": _sign_http_verification(fields)}


def has_valid_http_verification(
    result: dict[str, Any],
    *,
    source_url: str,
    source_raw_request: str = "",
    source_raw_response: str = "",
    source_vuln_type: str = "",
    source_finding_id: str = "",
) -> bool:
    proof = result.get("_http_verification_proof")
    if not isinstance(proof, dict):
        return False
    try:
        fields: dict[str, Any] = {
            "version": int(proof.get("version")),
            "url": str(proof.get("url") or ""),
            "host": str(proof.get("host") or ""),
            "origin_host": str(proof.get("origin_host") or ""),
            "status_code": int(proof.get("status_code")),
            "capture_id": str(proof.get("capture_id") or ""),
            "request_shape": str(proof.get("request_shape") or ""),
            "signal_keys": sorted({
                str(key) for key in (proof.get("signal_keys") or []) if str(key)
            }),
            "source_vuln_type": str(proof.get("source_vuln_type") or ""),
            "source_finding_id": str(proof.get("source_finding_id") or ""),
            "capture_status": str(proof.get("capture_status") or ""),
            "request_sha256": str(proof.get("request_sha256") or ""),
            "response_sha256": str(proof.get("response_sha256") or ""),
        }
    except (TypeError, ValueError):
        return False
    if fields["version"] != _HTTP_VERIFICATION_VERSION:
        return False
    if (
        not 200 <= fields["status_code"] < 300
        or not fields["capture_id"]
        or fields["capture_status"] != "complete"
        or not fields["request_sha256"]
        or not fields["response_sha256"]
    ):
        return False
    if fields["url"] != _canonical_http_url(str(result.get("verified_url") or "")):
        return False
    if fields["host"] != _normalize_host(fields["url"]):
        return False
    _, effective_source_url, _ = _source_request(
        source_raw_request, source_url
    )
    expected_origin = _normalize_host(effective_source_url)
    if not expected_origin or fields["origin_host"] != expected_origin:
        return False
    verified_host_identity = _normalize_host(fields["url"], include_port=False)
    expected_host_identity = _normalize_host(effective_source_url, include_port=False)
    if (
        not verified_host_identity
        or not expected_host_identity
        or verified_host_identity == expected_host_identity
    ):
        return False
    source_shape, source_signal_keys = _source_verification_context({
        "target_url": source_url,
        "raw_request": source_raw_request,
        "raw_response": source_raw_response,
        "vuln_type": source_vuln_type,
    })
    if fields["source_vuln_type"] != normalize_vuln_type(source_vuln_type):
        return False
    if fields["source_finding_id"] != str(source_finding_id or ""):
        return False
    if fields["request_shape"] != source_shape:
        return False
    if not fields["signal_keys"] or not set(fields["signal_keys"]).issubset(
        source_signal_keys
    ):
        return False
    signature = str(proof.get("signature") or "")
    return bool(signature) and hmac.compare_digest(
        signature, _sign_http_verification(fields)
    )


def _affected_row_key(host: str, vuln_title: str, vuln_type: str) -> str:
    raw = f"killsweep|{host}|{(vuln_type or '').lower()}|{vuln_title or ''}"
    return hashlib.md5(raw.encode()).hexdigest()


def _normalize_affected_table(rows: Any, vuln_type: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return out
    seen: set[str] = set()
    for row in rows[:50]:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("host") or "").strip()
        host = _normalize_host(str(row.get("host") or url))
        if not host:
            continue
        vuln_title = str(row.get("vuln_title") or "").strip() or f"{host} - 通杀漏洞"
        key = _affected_row_key(host, vuln_title, vuln_type)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "school": str(row.get("school") or "待确认")[:120],
            "url": url if "://" in url else f"http://{host}",
            "host": host,
            "title": str(row.get("title") or "")[:200],
            "vuln_type": vuln_type,
            "vuln_title": vuln_title[:300],
            "status": row.get("status") if row.get("status") in ("verified", "candidate") else "candidate",
            "evidence": str(row.get("evidence") or "")[:1000],
            "dedup_key": key,
        })
    return out


def _fofa_search_sync(key: str, query: str, edu_only: bool = False,
                      size: int = 20, base_url: str | None = None,
                      executor: ToolExecutor | None = None,
                      router: FofaKeyRouter | None = None) -> dict[str, Any]:
    """同步 FOFA 查询，返回 {size, sample:[{host,title,org}], query}。"""
    if router is None and not key:
        return {"size": 0, "sample": [], "query": query, "error": "缺少 FOFA key"}
    q = f"{query} && {_EDU_FILTER}" if edu_only else query
    params = {
        "qbase64": _qbase64(q),
        "fields": "host,title,org", "page": "1", "size": str(size), "full": "false",
    }
    if router is None and key:
        from app.config import FofaKeyConfig
        router = FofaKeyRouter([FofaKeyConfig(name="Legacy", key=key, base_url=(base_url or _FOFA_BASE))], active_name="Legacy")
    if router is None:
        return {"size": 0, "sample": [], "query": q, "error": "缺少 FOFA key"}

    def operation(routed_key: str, routed_base: str):
        result = fofa_endpoints.request_sync(
            routed_key,
            routed_base,
            purpose="search",
            params=params,
            timeout=30,
            allow_extra_hosts=_FOFA_ALLOWED_HOSTS,
        )
        if result.category == "network":
            raise FofaError("FOFA 网络请求失败", kind="transient")
        response = result.response
        if response is None:
            raise FofaError("FOFA 返回为空", kind="transient")
        if not 200 <= int(getattr(response, "status_code", 0) or 0) < 300:
            text = extract_fofa_response_failure(response)
            kind, code, retry_after = classify_fofa_failure(text, status=getattr(response, "status_code", None))
            raise FofaError(text, kind=kind, code=code, retry_after=retry_after)
        try:
            data = response.json()
        except Exception:
            raise FofaError("FOFA 返回非 JSON", kind="transient") from None
        if not isinstance(data, dict):
            raise FofaError("FOFA 返回格式异常", kind="transient")
        if data.get("error"):
            text, _ = extract_fofa_error(data, "FOFA 错误")
            kind, code, retry_after = classify_fofa_failure(text)
            raise FofaError(text, kind=kind, code=code, retry_after=retry_after)
        return data

    try:
        data = router.execute_sync(operation)
    except FofaPoolExhaustedError as exc:
        retry_at = exc.next_retry_at.isoformat().replace("+00:00", "Z") if exc.next_retry_at else None
        return {"size": 0, "sample": [], "query": q, "error": "FOFA 凭据池暂不可用",
                "kind": "pool_exhausted", **({"next_retry_at": retry_at} if retry_at else {})}
    except FofaError as exc:
        return {"size": 0, "sample": [], "query": q, "error": "FOFA 请求失败",
                "kind": str(exc.kind or "transient"),
                **({"next_retry_after": exc.retry_after} if exc.retry_after is not None else {})}
    except Exception:
        return {"size": 0, "sample": [], "query": q, "error": "FOFA 调用失败", "kind": "transient"}
    sample = []
    for row in data.get("results", [])[:size]:
        if isinstance(row, list):
            sample.append({"host": row[0] if len(row) > 0 else "",
                           "title": row[1] if len(row) > 1 else "",
                           "org": row[2] if len(row) > 2 else ""})
    result = {"size": data.get("size", 0), "sample": sample, "query": q}
    return result


class KillsweepResult:
    def __init__(self, data: dict):
        self.data = data

    def model_dump(self, mode: str = "json") -> dict:
        return self.data


class KillsweepHunter:
    def __init__(
        self,
        finding: dict,
        fofa_key: str = "",
        llm: LLMRouter | None = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
        src_type: str = "edusrc",
        cancel_event: Optional[threading.Event] = None,
        fofa_base_url: str = "",
        fofa_router: FofaKeyRouter | None = None,
    ):
        self.finding = finding
        self.fofa_key = fofa_key
        self.fofa_base_url = fofa_base_url
        self.fofa_router = fofa_router
        self.llm = llm
        self.cancel_event = cancel_event or threading.Event()
        self.src_type = src_type
        self._enterprise = is_enterprise_src(src_type)
        target_url = str(finding.get("target_url") or "")
        self.executor = ToolExecutor(
            f"killsweep_{target_url or 'x'}",
            cancel_event=self.cancel_event,
            enterprise=self._enterprise,
            capture_full=True,
            scope_target=target_url,
            fofa_router=fofa_router,
        )
        self._tools = killsweep_tool_schemas(enterprise=self._enterprise)
        self.on_event = on_event or (lambda kind, data: None)
        self._result: Optional[dict] = None
        self._verified_http_results: dict[str, dict[str, Any]] = {}
        _, self._source_url, _ = _source_request(
            str(finding.get("raw_request") or ""),
            str(finding.get("target_url") or ""),
        )
        self._source_request_shape, self._source_signal_keys = (
            _source_verification_context(finding)
        )

    def _emit(self, kind: str, **data: Any) -> None:
        self.on_event(kind, data)

    def _brief(self) -> str:
        f = self.finding
        unit_label = "企业/系统归属" if is_enterprise_src(self.src_type) else "归属"
        return (
            f"# 待分析的已采纳漏洞\n"
            f"- 标题：{f.get('title','')}\n"
            f"- 漏洞类型：{f.get('vuln_type','')}\n"
            f"- 目标 URL：{f.get('target_url','')}\n"
            f"- {unit_label}：{f.get('owner','')}\n"
            f"- 描述：{(f.get('description') or '')[:600]}\n"
            f"- PoC：{(f.get('poc') or '')[:500]}\n"
            f"- 原始请求(片段)：{(f.get('raw_request') or '')[:800]}\n"
            f"- 原始响应(片段)：{(f.get('raw_response') or '')[:800]}\n\n"
            f"请分析这套系统能否通杀。先认指纹→FOFA 圈定+统计→实打 1 个同款站点验证→调 submit_killsweep 下结论。"
        )

    def run(self) -> KillsweepResult:
        self._emit("killsweep_start", title=self.finding.get("title", ""))
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": killsweep_system_prompt(self.src_type)},
            {"role": "user", "content": self._brief()},
        ]
        rounds = 0
        while _MAX_ROUNDS <= 0 or rounds < _MAX_ROUNDS:
            if self.cancel_event.is_set():
                self.executor.cancel_running()
                return KillsweepResult({"error": "通杀分析已被取消"})
            rounds += 1
            try:
                send_messages = compact_messages(messages, rounds)
                msg = self.llm.chat(send_messages, tools=self._tools, tool_choice="auto")
            except Exception as e:
                self._emit("killsweep_error", error=str(e))
                return KillsweepResult({"error": f"LLM 调用失败: {e}"})

            tool_calls = getattr(msg, "tool_calls", None)
            messages.append(msg.as_history_message())

            if not tool_calls:
                messages.append({"role": "user", "content": "请继续，或调用 submit_killsweep 给出结论。"})
                continue

            for tc in tool_calls:
                if self.cancel_event.is_set():
                    self.executor.cancel_running()
                    return KillsweepResult({"error": "通杀分析已被取消"})
                try:
                    args = json.loads(tc.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = self._dispatch(tc.name, args)
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps(result, ensure_ascii=False),
                                 "_round": rounds, "_tool": tc.name})

            if self._result is not None:
                break

        if self._result is not None:
            return KillsweepResult(self._result)
        return KillsweepResult({"error": f"未在 {_MAX_ROUNDS} 轮内给出结论"})

    def _dispatch(self, name: str, args: dict) -> dict:
        if self.cancel_event.is_set():
            return {"ok": False, "cancelled": True, "error": "通杀分析已被取消"}
        if name == "fofa_search":
            q = args.get("query", "")
            edu = bool(args.get("edu_only", False))
            self._emit("killsweep_fofa", query=q, edu_only=edu)
            result = _fofa_search_sync(
                self.fofa_key, q, edu_only=edu,
                base_url=self.fofa_base_url, executor=self.executor,
                router=self.fofa_router,
            )
            return self._emit_tool_result(name, result, arguments=args)
        if name == "http_request":
            url = args.get("url")
            if not url:
                return self._emit_tool_result(
                    name, {"ok": False, "error": "http_request 缺少 url"}, arguments=args
                )
            self._emit("killsweep_http", url=args.get("url"))
            result = self.executor.http_request(
                url=url, method=args.get("method", "GET"),
                headers=args.get("headers"), data=args.get("data"),
                json_body=args.get("json_body"), follow_redirects=args.get("follow_redirects", False),
            )
            return self._emit_tool_result(name, result, arguments=args)
        if name == "run_shell":
            command = args.get("command")
            if not command:
                return self._emit_tool_result(
                    name, {"ok": False, "error": "run_shell 缺少 command"}, arguments=args
                )
            self._emit("killsweep_shell", command=args.get("command", "")[:160])
            result = self.executor.run_shell(command, timeout=args.get("timeout"))
            return self._emit_tool_result(name, result, arguments=args)
        if name == "submit_killsweep":
            submitted_url = str(args.get("verified_url") or "")
            proof = self._verified_http_results.get(
                _canonical_http_url(submitted_url)
            )
            verified = bool(args.get("verified", False)) and proof is not None
            self._result = {
                "is_generic_product": bool(args.get("is_generic_product", False)),
                "product_name": args.get("product_name", ""),
                "is_killsweep": bool(args.get("is_killsweep", False)),
                "confidence": args.get("confidence", "uncertain"),
                "fofa_query": args.get("fofa_query", ""),
                "fingerprint": args.get("fingerprint", ""),
                "asset_count": int(args.get("asset_count", 0) or 0),
                "edu_count": int(args.get("edu_count", 0) or 0),
                "verified_url": proof["url"] if verified else submitted_url,
                "verified": verified,
                "affected_table": _normalize_affected_table(args.get("affected_table", []), self.finding.get("vuln_type", "")),
                "notes": args.get("notes", ""),
            }
            if verified:
                self._result["_http_verification_proof"] = dict(proof)
            self._emit("killsweep_done", is_killsweep=self._result["is_killsweep"],
                       product=self._result["product_name"], count=self._result["asset_count"])
            return {"ok": True, "message": "已记录通杀分析结论。"}
        return {"ok": False, "error": f"未知工具: {name}"}

    def _emit_tool_result(
        self,
        name: str,
        result: dict[str, Any],
        *,
        arguments: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Emit after execution and keep private capture data out of LLM history."""
        if name == "http_request":
            capture = result.get("_capture")
            try:
                status_code = int(result.get("status_code"))
            except (TypeError, ValueError):
                status_code = 0
            channel_names = {
                str(item.get("name") or "")
                for item in ((capture.get("channels") or []) if isinstance(capture, dict) else [])
                if isinstance(item, dict)
            }
            channel_map = {
                str(item.get("name") or ""): item
                for item in ((capture.get("channels") or []) if isinstance(capture, dict) else [])
                if isinstance(item, dict)
            }
            args = arguments if isinstance(arguments, Mapping) else {}
            request_url = str(args.get("url") or result.get("url") or "")
            request_method = str(args.get("method") or "GET").upper()
            candidate_signal_keys = {
                item.rule_key
                for item in detect_tool_signals("http_request", args, result)
            }
            matching_signal_keys = sorted(
                self._source_signal_keys.intersection(candidate_signal_keys)
            )
            request_shape = _request_shape(
                request_method,
                request_url,
                _argument_body_parameter_names(args),
            )
            response_url = str(result.get("url") or "")
            request_url_matches_response = (
                bool(_canonical_http_url(request_url))
                and _canonical_http_url(request_url) == _canonical_http_url(response_url)
            )
            request_sha256 = str((channel_map.get("request") or {}).get("sha256") or "")
            response_sha256 = str((channel_map.get("response") or {}).get("sha256") or "")
            if (
                result.get("ok") is True
                and 200 <= status_code < 300
                and isinstance(capture, dict)
                and capture.get("status") == "complete"
                and {"request", "response"}.issubset(channel_names)
                and not bool(args.get("follow_redirects", False))
                and request_url_matches_response
                and request_shape == self._source_request_shape
                and matching_signal_keys
                and request_sha256
                and response_sha256
            ):
                proof = _http_verification_proof(
                    url=str(result.get("url") or ""),
                    source_url=self._source_url,
                    status_code=status_code,
                    capture_id=str(capture.get("id") or ""),
                    request_shape=request_shape,
                    signal_keys=matching_signal_keys,
                    source_vuln_type=str(self.finding.get("vuln_type") or ""),
                    source_finding_id=str(self.finding.get("id") or ""),
                    capture_status=str(capture.get("status") or ""),
                    request_sha256=request_sha256,
                    response_sha256=response_sha256,
                )
                if proof is not None and proof["capture_id"]:
                    self._verified_http_results[proof["url"]] = proof
        capture = detach_capture(result)
        ok = bool(result.get("ok", not result.get("error")))
        if name == "http_request":
            summary = f"HTTP {result.get('status_code', '失败')} {result.get('url', '')}".strip()
        elif name == "fofa_search":
            summary = f"FOFA 查询完成，命中 {int(result.get('size') or 0)} 个资产"
        else:
            summary = f"命令执行{'完成' if ok else '失败'}，退出码 {result.get('return_code', '-')}"
        self._emit(
            "killsweep_tool_result",
            tool=name,
            summary=summary,
            payload=dict(result),
            capture=capture,
            source_kind=f"killsweep_{name}",
        )
        return result


def product_key(product_name: str, fofa_query: str = "", fingerprint: str = "") -> str:
    """产品指纹去重键：同款系统只分析一次，不按漏洞类型重复分析。"""
    raw = product_name or fofa_query or fingerprint or "unknown"
    name = "".join(ch.lower() for ch in raw if ch.isalnum() or '\u4e00' <= ch <= '\u9fff')
    return name[:120] or "unknown"
