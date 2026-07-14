"""Structured, bounded command plans for SRC-focused CLI tools."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit


SRC_TOOL_NAMES = frozenset({
    "probe_http",
    "crawl_endpoints",
    "discover_content",
    "discover_parameters",
    "scan_nuclei",
    "verify_xss",
    "fingerprint_waf",
    "scan_web_ports",
})
ENTERPRISE_BLOCKED_SRC_TOOLS = frozenset({"scan_nuclei", "verify_xss"})

_WORDLIST_FILES = {
    "common": "src-common.txt",
    "api": "src-api.txt",
}
_PARAM_WORDLIST = "src-params.txt"
_DEFAULT_WEB_PORTS = (80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 9443)
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:*,-]{1,300}$")
_SAFE_PARAM_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}


class SrcToolError(ValueError):
    def __init__(self, message: str, *, blocked: bool = False):
        super().__init__(message)
        self.blocked = blocked


@dataclass(frozen=True)
class SrcToolPlan:
    tool: str
    binary: str
    argv: tuple[str, ...]
    display_argv: tuple[str, ...]
    timeout: int
    guidance: str


def _bounded_int(value: Any, default: int, minimum: int, maximum: int, name: str) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise SrcToolError(f"{name} 必须是整数") from exc
    return max(minimum, min(parsed, maximum))


def _items(value: Any, *, limit: int) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raise SrcToolError("列表参数格式错误")
    return [str(item).strip() for item in raw if str(item).strip()][:limit]


def _headers(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, Mapping):
        pairs = [(str(key).strip(), str(item).strip()) for key, item in value.items()]
    elif isinstance(value, (list, tuple)):
        pairs = []
        for item in value:
            text = str(item)
            if ":" not in text:
                raise SrcToolError("headers 列表必须使用 Name: Value 格式")
            key, val = text.split(":", 1)
            pairs.append((key.strip(), val.strip()))
    else:
        raise SrcToolError("headers 必须是对象或字符串数组")
    result: list[str] = []
    for key, val in pairs[:12]:
        if not key or any(char in key + val for char in ("\r", "\n")):
            raise SrcToolError("header 名称和值不得包含换行")
        if len(key) > 100 or len(val) > 2000:
            raise SrcToolError("header 超过长度上限")
        result.append(f"{key}: {val}")
    return result


def _host(value: str) -> str:
    text = str(value or "").strip().replace("FUZZ", "probe")
    if not text:
        return ""
    parsed = urlsplit(text if "://" in text else f"//{text}")
    return str(parsed.hostname or "").rstrip(".").lower()


def _url(value: Any, scope_target: str) -> str:
    text = str(value or "").strip()
    parsed = urlsplit(text.replace("FUZZ", "probe"))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SrcToolError("url 必须是完整的 http/https URL")
    _enforce_scope(text, scope_target)
    return text


def _enforce_scope(value: str, scope_target: str) -> None:
    expected = _host(scope_target)
    actual = _host(value)
    if expected and actual and expected != actual:
        raise SrcToolError(
            f"SRC 工具只允许当前目标 {expected}，收到 {actual}",
            blocked=True,
        )


def _header_args(argv: list[str], display: list[str], headers: list[str], flag: str = "-H") -> None:
    for header in headers:
        name = header.split(":", 1)[0]
        argv.extend([flag, header])
        display.extend([flag, f"{name}: <redacted>"])


def _plan(
    tool: str,
    argv: list[str],
    display: list[str],
    *,
    timeout: int,
    guidance: str,
) -> SrcToolPlan:
    return SrcToolPlan(
        tool=tool,
        binary=argv[0],
        argv=tuple(argv),
        display_argv=tuple(display),
        timeout=timeout,
        guidance=guidance,
    )


def _probe_http(args: Mapping[str, Any], scope: str) -> SrcToolPlan:
    url = _url(args.get("url"), scope)
    rate = _bounded_int(args.get("rate_limit"), 20, 1, 50, "rate_limit")
    request_timeout = _bounded_int(args.get("request_timeout"), 10, 3, 30, "request_timeout")
    argv = [
        "httpx", "-u", url, "-silent", "-json", "-status-code", "-title",
        "-server", "-tech-detect", "-ip", "-cname", "-rate-limit", str(rate),
        "-timeout", str(request_timeout), "-no-color", "-disable-update-check",
    ]
    display = list(argv)
    if bool(args.get("follow_redirects", True)):
        argv.append("-follow-redirects")
        display.append("-follow-redirects")
    _header_args(argv, display, _headers(args.get("headers")))
    return _plan(
        "probe_http", argv, display, timeout=90,
        guidance="指纹结果用于选择后续入口；漏洞结论仍需 http_request 取得请求/响应证据。",
    )


def _crawl_endpoints(args: Mapping[str, Any], scope: str) -> SrcToolPlan:
    url = _url(args.get("url"), scope)
    depth = _bounded_int(args.get("depth"), 2, 1, 3, "depth")
    concurrency = _bounded_int(args.get("concurrency"), 5, 1, 10, "concurrency")
    rate = _bounded_int(args.get("rate_limit"), 20, 1, 50, "rate_limit")
    request_timeout = _bounded_int(args.get("request_timeout"), 10, 3, 30, "request_timeout")
    argv = [
        "katana", "-u", url, "-silent", "-jsonl", "-no-color", "-depth", str(depth),
        "-concurrency", str(concurrency), "-parallelism", "1", "-rate-limit", str(rate),
        "-timeout", str(request_timeout), "-crawl-duration", "120s", "-field-scope", "fqdn",
        "-max-domain-pages", "200", "-max-response-size", "1048576", "-form-extraction",
        "-tech-detect", "-filter-similar", "-disable-update-check",
    ]
    display = list(argv)
    if bool(args.get("js_crawl", True)):
        argv.append("-js-crawl")
        display.append("-js-crawl")
    _header_args(argv, display, _headers(args.get("headers")))
    return _plan(
        "crawl_endpoints", argv, display, timeout=180,
        guidance="优先复核带参数、上传、导出、管理和认证端点，再用 http_request 做最小验证。",
    )


def _discover_content(
    args: Mapping[str, Any],
    scope: str,
    wordlist_root: Path,
) -> SrcToolPlan:
    url = _url(args.get("url"), scope)
    if "FUZZ" not in url:
        raise SrcToolError("discover_content 的 url 必须包含 FUZZ 占位符")
    preset = str(args.get("wordlist") or "common").strip().lower()
    if preset not in _WORDLIST_FILES:
        raise SrcToolError("wordlist 仅支持 common/api 内置小字典")
    rate = _bounded_int(args.get("rate_limit"), 20, 1, 50, "rate_limit")
    threads = _bounded_int(args.get("threads"), 10, 1, 20, "threads")
    request_timeout = _bounded_int(args.get("request_timeout"), 10, 3, 20, "request_timeout")
    codes = _items(args.get("match_codes"), limit=12) or [
        "200-299", "301", "302", "307", "401", "403", "405", "500",
    ]
    if any(not re.fullmatch(r"\d{3}(?:-\d{3})?|all", item) for item in codes):
        raise SrcToolError("match_codes 包含非法状态码")
    argv = [
        "ffuf", "-u", url, "-w", str(wordlist_root / _WORDLIST_FILES[preset]),
        "-json", "-s", "-ac", "-noninteractive", "-rate", str(rate), "-t", str(threads),
        "-maxtime", "180", "-timeout", str(request_timeout), "-mc", ",".join(codes),
    ]
    display = list(argv)
    if bool(args.get("follow_redirects", False)):
        argv.append("-r")
        display.append("-r")
    _header_args(argv, display, _headers(args.get("headers")))
    return _plan(
        "discover_content", argv, display, timeout=210,
        guidance="只复核少量高价值命中；软 404 和统一跳转必须用基线响应排除。",
    )


def _discover_parameters(
    args: Mapping[str, Any],
    scope: str,
    wordlist_root: Path,
) -> SrcToolPlan:
    url = _url(args.get("url"), scope)
    method = str(args.get("method") or "GET").strip().upper()
    if method not in {"GET", "POST", "JSON", "XML"}:
        raise SrcToolError("method 仅支持 GET/POST/JSON/XML")
    threads = _bounded_int(args.get("threads"), 3, 1, 5, "threads")
    rate = _bounded_int(args.get("rate_limit"), 10, 1, 20, "rate_limit")
    request_timeout = _bounded_int(args.get("request_timeout"), 10, 3, 15, "request_timeout")
    argv = [
        "arjun", "-u", url, "-m", method, "-w", str(wordlist_root / _PARAM_WORDLIST),
        "-t", str(threads), "-T", str(request_timeout), "-c", "50", "--rate-limit", str(rate),
        "--stable",
    ]
    display = list(argv)
    headers = _headers(args.get("headers"))
    if headers:
        argv.extend(["--headers", "\n".join(headers)])
        display.extend(["--headers", "<redacted headers>"])
    include = str(args.get("include") or "").strip()
    if include:
        if len(include) > 2000:
            raise SrcToolError("include 超过 2000 字符")
        argv.extend(["--include", include])
        display.extend(["--include", "<redacted body>"])
    if not bool(args.get("follow_redirects", False)):
        argv.append("--disable-redirects")
        display.append("--disable-redirects")
    return _plan(
        "discover_parameters", argv, display, timeout=180,
        guidance="发现参数后先用无害值做基线/候选对比，再按参数语义验证鉴权、注入或业务影响。",
    )


def _scan_nuclei(args: Mapping[str, Any], scope: str) -> SrcToolPlan:
    url = _url(args.get("url"), scope)
    templates = _items(args.get("template"), limit=6)
    tags = _items(args.get("tags"), limit=8)
    template_ids = _items(args.get("template_id"), limit=8)
    if not templates and not tags and not template_ids:
        raise SrcToolError("scan_nuclei 必须提供 template/tags/template_id 之一")
    for item in [*templates, *tags, *template_ids]:
        if not _SAFE_NAME_RE.fullmatch(item) or ".." in item:
            raise SrcToolError("nuclei selector 含非法字符")
    severities = [item.lower() for item in _items(args.get("severity"), limit=6)]
    if any(item not in _VALID_SEVERITIES for item in severities):
        raise SrcToolError("severity 包含非法等级")
    rate = _bounded_int(args.get("rate_limit"), 15, 1, 50, "rate_limit")
    concurrency = _bounded_int(args.get("concurrency"), 5, 1, 10, "concurrency")
    request_timeout = _bounded_int(args.get("request_timeout"), 10, 3, 30, "request_timeout")
    argv = [
        "nuclei", "-target", url, "-silent", "-jsonl", "-no-color", "-rate-limit", str(rate),
        "-concurrency", str(concurrency), "-bulk-size", "1", "-timeout", str(request_timeout),
        "-retries", "1", "-disable-update-check",
    ]
    display = list(argv)
    if templates:
        argv.extend(["-templates", ",".join(templates)])
        display.extend(["-templates", ",".join(templates)])
    if tags:
        argv.extend(["-tags", ",".join(tags)])
        display.extend(["-tags", ",".join(tags)])
    if template_ids:
        argv.extend(["-template-id", ",".join(template_ids)])
        display.extend(["-template-id", ",".join(template_ids)])
    if severities:
        argv.extend(["-severity", ",".join(severities)])
        display.extend(["-severity", ",".join(severities)])
    _header_args(argv, display, _headers(args.get("headers")))
    return _plan(
        "scan_nuclei", argv, display, timeout=180,
        guidance="Nuclei 命中只是候选证据；必须回到具体 URL 和最小请求复核后再提交。",
    )


def _verify_xss(args: Mapping[str, Any], scope: str) -> SrcToolPlan:
    url = _url(args.get("url"), scope)
    params = _items(args.get("params"), limit=5)
    if not params:
        raise SrcToolError("verify_xss 必须提供已知可控 params")
    if any(not _SAFE_PARAM_RE.fullmatch(item) for item in params):
        raise SrcToolError("params 含非法名称")
    workers = _bounded_int(args.get("workers"), 3, 1, 5, "workers")
    rate = _bounded_int(args.get("rate_limit"), 10, 1, 20, "rate_limit")
    request_timeout = _bounded_int(args.get("request_timeout"), 10, 3, 20, "request_timeout")
    argv = [
        "dalfox", "url", "--url", url, "--format", "jsonl", "--silence", "--no-color",
        "--workers", str(workers), "--rate-limit", str(rate), "--timeout", str(request_timeout),
        "--scan-timeout", "120", "--max-payloads-per-param", "200", "--skip-discovery",
        "--skip-mining", "--limit", "20", "--limit-result-type", "all",
    ]
    display = list(argv)
    for param in params:
        argv.extend(["--param", param])
        display.extend(["--param", param])
    _header_args(argv, display, _headers(args.get("headers")), "--headers")
    return _plan(
        "verify_xss", argv, display, timeout=240,
        guidance="只把 verified/reflected 输出当候选；需保存实际触发上下文并判断 SRC 是否接收该类型。",
    )


def _fingerprint_waf(args: Mapping[str, Any], scope: str) -> SrcToolPlan:
    url = _url(args.get("url"), scope)
    argv = ["wafw00f", url, "-a", "--no-colors", "-f", "json"]
    return _plan(
        "fingerprint_waf", argv, list(argv), timeout=90,
        guidance="WAF 指纹只用于调整验证节奏和请求形态，不代表存在绕过。",
    )


def _scan_web_ports(args: Mapping[str, Any], scope: str) -> SrcToolPlan:
    raw_host = str(args.get("host") or "").strip()
    host = _host(raw_host)
    if not host or any(marker in raw_host for marker in ("/", ",", " ")):
        raise SrcToolError("host 必须是单个主机名或 IP")
    _enforce_scope(host, scope)
    raw_ports = args.get("ports")
    if raw_ports in (None, "", []):
        ports = list(_DEFAULT_WEB_PORTS)
    elif isinstance(raw_ports, str):
        values = [item.strip() for item in raw_ports.split(",") if item.strip()]
        try:
            ports = [int(item) for item in values]
        except ValueError as exc:
            raise SrcToolError("ports 必须是端口整数列表") from exc
    elif isinstance(raw_ports, (list, tuple, set)):
        try:
            ports = [int(item) for item in raw_ports]
        except (TypeError, ValueError) as exc:
            raise SrcToolError("ports 必须是端口整数列表") from exc
    else:
        raise SrcToolError("ports 必须是端口整数列表")
    ports = list(dict.fromkeys(ports))
    if len(ports) > 20:
        raise SrcToolError("单次最多验证 20 个明确端口")
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise SrcToolError("ports 包含非法端口")
    argv = [
        "nmap", "-Pn", "-sT", "-sV", "--version-light", "--open", "-n", "-T3",
        "--max-retries", "1", "--host-timeout", "120s", "-p", ",".join(map(str, ports)), host,
    ]
    return _plan(
        "scan_web_ports", argv, list(argv), timeout=150,
        guidance="只对开放的 Web/管理端口继续 HTTP 指纹与页面验证，不扩展到宽端口扫描。",
    )


def build_src_plan(
    tool: str,
    args: Mapping[str, Any] | None,
    *,
    scope_target: str = "",
    wordlist_root: str | Path | None = None,
) -> SrcToolPlan:
    """Normalize one LLM call into a bounded argv plan with no shell parsing."""
    name = str(tool or "").strip()
    if name not in SRC_TOOL_NAMES:
        raise SrcToolError(f"未知 SRC 工具: {name}")
    values: Mapping[str, Any] = args if isinstance(args, Mapping) else {}
    root = Path(wordlist_root) if wordlist_root else Path(__file__).resolve().parents[2] / "wordlists"
    if name == "probe_http":
        return _probe_http(values, scope_target)
    if name == "crawl_endpoints":
        return _crawl_endpoints(values, scope_target)
    if name == "discover_content":
        return _discover_content(values, scope_target, root)
    if name == "discover_parameters":
        return _discover_parameters(values, scope_target, root)
    if name == "scan_nuclei":
        return _scan_nuclei(values, scope_target)
    if name == "verify_xss":
        return _verify_xss(values, scope_target)
    if name == "fingerprint_waf":
        return _fingerprint_waf(values, scope_target)
    return _scan_web_ports(values, scope_target)


__all__ = [
    "ENTERPRISE_BLOCKED_SRC_TOOLS",
    "SRC_TOOL_NAMES",
    "SrcToolError",
    "SrcToolPlan",
    "build_src_plan",
]
