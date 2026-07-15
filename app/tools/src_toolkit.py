"""Structured, bounded command plans for SRC-focused CLI tools."""
from __future__ import annotations

import re
import json
import io
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping
from urllib.parse import urlsplit

from app.config import worker_config
from app.agents.src_leads import SrcCandidate


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

_MAX_PARSE_BYTES = 64 * 1024 * 1024
_MAX_PARSE_LINES = 50_000
_SUMMARY_WIDTH = 3


@dataclass(frozen=True)
class ToolSpec:
    """Boundaries and workflow metadata for one external SRC CLI."""

    name: str
    stage: str
    roles: tuple[str, ...]
    routes: tuple[str, ...]
    enterprise_allowed: bool
    requires: tuple[str, ...]
    produces: tuple[str, ...]
    max_rate: int
    timeout: int
    summary_kind: str


SRC_TOOL_CATALOG: dict[str, ToolSpec] = {
    "probe_http": ToolSpec(
        "probe_http", "recon", ("worker",), (), True,
        ("url",), ("fingerprint", "http_baseline"), 50, 90, "fingerprint",
    ),
    "fingerprint_waf": ToolSpec(
        "fingerprint_waf", "recon", ("worker",), (), True,
        ("url",), ("waf_fingerprint",), 1, 90, "fingerprint",
    ),
    "scan_web_ports": ToolSpec(
        "scan_web_ports", "recon", ("worker",), (), True,
        ("host",), ("service",), 1, 150, "service",
    ),
    "crawl_endpoints": ToolSpec(
        "crawl_endpoints", "locate", ("worker",), (), True,
        ("url",), ("endpoint", "parameter", "js_asset"), 50, 180, "endpoint",
    ),
    "discover_content": ToolSpec(
        "discover_content", "locate", ("worker",), (), True,
        ("url", "wordlist"), ("endpoint", "path_candidate"), 50, 210, "endpoint",
    ),
    "discover_parameters": ToolSpec(
        "discover_parameters", "locate", ("worker",), (), True,
        ("url",), ("parameter",), 20, 180, "parameter",
    ),
    "scan_nuclei": ToolSpec(
        "scan_nuclei", "verify", ("worker",), (), False,
        ("url", "selector"), ("scanner_candidate",), 50, 180, "hypothesis",
    ),
    "verify_xss": ToolSpec(
        "verify_xss", "verify", ("worker",), (), False,
        ("url", "params"), ("xss_candidate",), 20, 240, "hypothesis",
    ),

}


@dataclass(frozen=True)
class SrcParseResult:
    tool: str
    parse_ok: bool
    count: int
    head_candidates: tuple[SrcCandidate, ...]
    tail_candidates: tuple[SrcCandidate, ...]
    priority_candidates: tuple[SrcCandidate, ...]
    omitted: int
    parse_errors: tuple[str, ...]
    next_actions: tuple[str, ...]
    partial: bool
    remaining_unknown: bool
    failure_kind: str


def _status_code(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if 100 <= number <= 599 else None


def _candidate_priority(status: int | None, record: Mapping[str, Any], *, scanner: bool = False) -> int:
    if scanner:
        return 8
    if status in {401, 403}:
        return 8
    if status in {500, 502, 503}:
        return 7
    try:
        if int(record.get("content_length") or record.get("length") or 0) > 512:
            return 8
    except (TypeError, ValueError, OverflowError):
        pass
    raw = str(record.get("url") or record.get("endpoint") or record.get("input") or "").lower()
    if any(token in raw for token in ("/admin", "/login", "/api", "/internal", "/debug")):
        return 7
    return 5


def _new_candidate(
    kind: str,
    endpoint: Any,
    value: Any,
    *,
    method: Any = "GET",
    parameter: Any = "",
    location: Any = "path",
    status: Any = None,
    confidence: float = 0.6,
    priority: int | None = None,
    reason: str = "",
    record: Mapping[str, Any] | None = None,
    scanner: bool = False,
) -> SrcCandidate | None:
    item = record or {}
    code = _status_code(status)
    selected_priority = priority if priority is not None else _candidate_priority(code, item, scanner=scanner)
    try:
        return SrcCandidate(
            kind=kind,
            endpoint_key=str(endpoint or value or ""),
            value=str(value or endpoint or ""),
            method=str(method or "GET"),
            parameter=str(parameter or ""),
            location=str(location or "unknown"),
            status_code=code,
            confidence=confidence,
            priority=selected_priority,
            reason=reason,
        )
    except (TypeError, ValueError):
        return None


def _iter_json_array(
    text: str,
    start: int,
    errors: list[str],
    *,
    allow_suffix: bool = False,
) -> Iterator[Mapping[str, Any]]:
    decoder = json.JSONDecoder()
    cursor = start + 1
    length = len(text)
    expect_value = True
    saw_value = False
    while cursor < length:
        while cursor < length and text[cursor].isspace():
            cursor += 1
        if cursor >= length:
            if len(errors) < 64:
                errors.append("json array: unterminated array")
            return
        if expect_value:
            if text[cursor] == "]":
                if saw_value and len(errors) < 64:
                    errors.append("json array: trailing comma")
                if not allow_suffix and text[cursor + 1 :].strip() and len(errors) < 64:
                    errors.append("json array: trailing data")
                return
            try:
                value, cursor = decoder.raw_decode(text, cursor)
            except json.JSONDecodeError as exc:
                if len(errors) < 64:
                    errors.append(f"json array: {exc.msg}")
                return
            saw_value = True
            if isinstance(value, Mapping):
                yield value
            elif isinstance(value, list):
                yield from (item for item in value if isinstance(item, Mapping))
            expect_value = False
            continue
        if text[cursor] == ",":
            cursor += 1
            expect_value = True
            continue
        if text[cursor] == "]":
            if not allow_suffix and text[cursor + 1 :].strip() and len(errors) < 64:
                errors.append("json array: trailing data")
            return
        if len(errors) < 64:
            errors.append("json array: expected comma")
        return
    if len(errors) < 64:
        errors.append("json array: unterminated array")


def _json_records(text: str, errors: list[str]) -> Iterator[Mapping[str, Any]]:
    if not text.strip():
        return
    first = next((index for index, char in enumerate(text) if not char.isspace()), -1)
    if first >= 0 and text[first] == "[":
        yield from _iter_json_array(text, first, errors)
        return
    results_match = re.search(r'"results"\s*:\s*\[', text)
    if results_match:
        yield from _iter_json_array(text, results_match.end() - 1, errors, allow_suffix=True)
        return
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, Mapping):
        results = parsed.get("results")
        if isinstance(results, list):
            yield from (item for item in results if isinstance(item, Mapping))
            return
        yield parsed
        return
    if isinstance(parsed, list):
        yield from (item for item in parsed if isinstance(item, Mapping))
        return
    for line_number, line in enumerate(io.StringIO(text), 1):
        if line_number > _MAX_PARSE_LINES:
            break
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            if len(errors) < 64:
                errors.append(f"line {line_number}: json:{exc.msg}")
            continue
        if isinstance(value, Mapping):
            yield value
        elif isinstance(value, list):
            yield from (item for item in value if isinstance(item, Mapping))


def _record_url(record: Mapping[str, Any]) -> str:
    request = record.get("request")
    if isinstance(request, Mapping):
        for key in ("endpoint", "url", "input"):
            if request.get(key):
                return str(request[key])
    for key in ("url", "endpoint", "input", "target", "matched-at", "host"):
        if record.get(key):
            value = record[key]
            if isinstance(value, Mapping):
                for item in value.values():
                    if item:
                        return str(item)
                continue
            return str(value)
    return ""


def _scope_host(value: str) -> str:
    try:
        parsed = urlsplit(str(value or "").replace("FUZZ", "probe"))
    except ValueError:
        return ""
    return str(parsed.hostname or "").rstrip(".").lower()


def _candidate_in_scope(candidate: SrcCandidate, scope_target: str) -> bool:
    expected = _scope_host(scope_target)
    if not expected:
        return True
    for value in (candidate.value, candidate.endpoint_key):
        candidate_value = re.sub(r"^[A-Za-z]+\s+", "", str(value or ""), count=1)
        host = _scope_host(candidate_value)
        if host and host != expected:
            return False
    return True


def _bounded_text(output: str) -> tuple[str, int, bool, bool]:
    """Build a bounded text window without copying the complete input first."""

    raw = str(output or "")
    if not raw:
        return "", 0, False, False
    pieces: list[str] = []
    byte_count = 0
    line_count = 1
    partial = False
    for offset in range(0, len(raw), 8192):
        chunk = raw[offset : offset + 8192]
        encoded_length = len(chunk.encode("utf-8", "replace"))
        is_last_chunk = offset + len(chunk) >= len(raw)
        line_increment = chunk.count("\n") - int(is_last_chunk and chunk.endswith("\n"))
        if (
            byte_count + encoded_length <= _MAX_PARSE_BYTES
            and line_count + line_increment <= _MAX_PARSE_LINES
        ):
            pieces.append(chunk)
            byte_count += encoded_length
            line_count += line_increment
            continue
        prefix = chunk
        remaining_lines = _MAX_PARSE_LINES - line_count
        if prefix.count("\n") > remaining_lines:
            if remaining_lines <= 0:
                prefix = prefix[: prefix.find("\n")]
            else:
                cursor = -1
                for _ in range(remaining_lines + 1):
                    cursor = prefix.find("\n", cursor + 1)
                prefix = prefix[:cursor]
        remaining_bytes = _MAX_PARSE_BYTES - byte_count
        if len(prefix.encode("utf-8", "replace")) > remaining_bytes:
            lower, upper = 0, len(prefix)
            while lower < upper:
                middle = (lower + upper + 1) // 2
                if len(prefix[:middle].encode("utf-8", "replace")) <= remaining_bytes:
                    lower = middle
                else:
                    upper = middle - 1
            prefix = prefix[:lower]
        if prefix:
            pieces.append(prefix)
            byte_count += len(prefix.encode("utf-8", "replace"))
            line_count += prefix.count("\n")
        if len(prefix) < len(chunk):
            partial = True
        break
    text = "".join(pieces)
    return text, 0, partial, partial


def _next_actions(tool: str) -> tuple[str, ...]:
    return {
        "probe_http": ("保存基线并对高价值端点做最小请求复核",),
        "crawl_endpoints": ("优先复核带参数、认证和管理端点",),
        "discover_content": ("排除软 404 后复核高状态码路径",),
        "discover_parameters": ("使用无害值建立参数响应基线",),
        "fingerprint_waf": ("据指纹调整请求节奏并保留原始证据",),
        "scan_web_ports": ("仅对开放 Web 服务做 HTTP 指纹",),
        "scan_nuclei": ("将命中回到具体 URL 做最小请求验证",),
        "verify_xss": ("保存反射上下文并用请求证据确认",),
    }.get(tool, ("检查工具输出并进行人工复核",))


def _parse_src_text(tool: str, output: str, *, scope_target: str = "") -> SrcParseResult:
    name = str(tool or "").strip()
    text, _omitted, partial, remaining_unknown = _bounded_text(output)
    errors: list[str] = []
    head_candidates: list[tuple[int, SrcCandidate]] = []
    tail_candidates: deque[tuple[int, SrcCandidate]] = deque(maxlen=_SUMMARY_WIDTH)
    priority_candidates: list[tuple[int, SrcCandidate]] = []
    candidate_count = 0
    record_limit_hit = False

    def add_error(message: str) -> None:
        if len(errors) < 64:
            errors.append(message)

    def add(candidate: SrcCandidate | None) -> None:
        nonlocal candidate_count
        if candidate is None:
            return
        if not _candidate_in_scope(candidate, scope_target):
            add_error(f"scope filtered: {candidate.value or candidate.endpoint_key}")
            return
        candidate_index = candidate_count
        candidate_count += 1
        if len(head_candidates) < _SUMMARY_WIDTH:
            head_candidates.append((candidate_index, candidate))
        tail_candidates.append((candidate_index, candidate))
        priority_candidates.append((candidate_index, candidate))
        priority_candidates.sort(key=lambda pair: (-pair[1].priority, pair[0]))
        del priority_candidates[_SUMMARY_WIDTH:]

    if not text.strip():
        return SrcParseResult(name, False, 0, (), (), (), 0, (), _next_actions(name), partial, remaining_unknown, "empty")

    if name in {"probe_http", "crawl_endpoints", "discover_content", "scan_nuclei", "verify_xss"}:
        records_seen = False
        for record_number, record in enumerate(_json_records(text, errors), 1):
            if record_number > _MAX_PARSE_LINES:
                record_limit_hit = True
                break
            records_seen = True
            url = _record_url(record)
            if not url:
                add_error("record missing url")
                continue
            request = record.get("request") if isinstance(record.get("request"), Mapping) else {}
            method = request.get("method") if isinstance(request, Mapping) else record.get("method", "GET")
            response = record.get("response") if isinstance(record.get("response"), Mapping) else {}
            status = record.get("status_code", record.get("status"))
            if status is None and isinstance(response, Mapping):
                status = response.get("status_code", response.get("status"))
            scanner = name in {"scan_nuclei", "verify_xss"}
            kind = "hypothesis" if scanner else "endpoint"
            if name == "probe_http":
                kind = "fingerprint"
            reason = str(record.get("title") or record.get("template-id") or record.get("type") or name)
            add(_new_candidate(
                kind, url, url, method=method, status=status,
                confidence=0.8 if scanner else 0.7, reason=reason,
                record=record, scanner=scanner,
            ))
        if not records_seen and not errors:
            add_error("no JSON records")
    elif name == "fingerprint_waf":
        records_seen = False
        for record_number, record in enumerate(_json_records(text, errors), 1):
            if record_number > _MAX_PARSE_LINES:
                record_limit_hit = True
                break
            records_seen = True
            url = _record_url(record)
            firewall = record.get("firewall") or record.get("waf") or record.get("manufacturer") or record.get("name")
            if not url and not firewall:
                add_error("record missing target")
                continue
            add(_new_candidate(
                "fingerprint", url or str(firewall), url or str(firewall),
                location="unknown", confidence=0.8 if record.get("detected", True) else 0.4,
                priority=6 if record.get("detected", True) else 3,
                reason=str(firewall or "waf fingerprint"), record=record,
            ))
        if not records_seen and not errors:
            add_error("no JSON records")
    elif name == "discover_parameters":
        current_url = ""
        current_method = "GET"
        for line_number, line in enumerate(io.StringIO(text), 1):
            if line_number > _MAX_PARSE_LINES:
                break
            stripped = line.strip()
            if not stripped:
                continue
            match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|JSON|XML)\s+(https?://\S+)", stripped, re.I)
            if match:
                current_method, current_url = match.group(1).upper(), match.group(2).rstrip(")],")
                add(_new_candidate("endpoint", current_url, current_url, method=current_method, reason="arjun endpoint"))
                continue
            scanning = re.search(r"\bScanning\s+\[\d+\s*/\s*\d+\]\s*:\s*(https?://\S+)", stripped, re.I)
            if scanning:
                current_method, current_url = "GET", scanning.group(1).rstrip(")],")
                add(_new_candidate("endpoint", current_url, current_url, method=current_method, reason="arjun endpoint"))
                continue
            found = re.search(
                r"(?:valid\s+parameters?\s+found|parameters?\s+found|found(?:\s+\d+)?(?:\s+parameters?)?|param(?:eters)?)\s*:?\s*(.+)$",
                stripped,
                re.I,
            )
            if found:
                params = re.split(r"[,\s]+", found.group(1).strip())
                for parameter in params:
                    parameter = parameter.strip("[](){}\"'")
                    if not parameter or "=" in parameter:
                        continue
                    add(_new_candidate(
                        "parameter", current_url, parameter, method=current_method,
                        parameter=parameter, location="query", priority=7,
                        confidence=0.75, reason="arjun parameter",
                    ))
            elif current_url and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", stripped):
                add(_new_candidate(
                    "parameter", current_url, stripped, method=current_method,
                    parameter=stripped, location="query", priority=7,
                    confidence=0.7, reason=f"arjun line {line_number}",
                ))
    elif name == "scan_web_ports":
        service_re = re.compile(r"^(\d+)/(tcp|udp)\s+open\s*(.*)$", re.I)
        for line_number, line in enumerate(io.StringIO(text), 1):
            if line_number > _MAX_PARSE_LINES:
                break
            match = service_re.match(line.strip())
            if not match:
                continue
            port, protocol, service = match.groups()
            service = service.strip() or "unknown"
            add(_new_candidate(
                "service", f"{port}/{protocol.lower()}", service,
                location="unknown", priority=6, confidence=0.8,
                reason=f"nmap {port}/{protocol.lower()}",
            ))
        if not head_candidates and not errors:
            add_error("no open service lines")
    else:
        add_error(f"unsupported SRC parser: {name}")

    if record_limit_hit:
        partial = True
        remaining_unknown = True

    # Keep summaries stable and bounded while count remains the number admitted.
    head = tuple(candidate for _index, candidate in head_candidates)
    tail = tuple(candidate for _index, candidate in tail_candidates)
    priority = tuple(candidate for _index, candidate in priority_candidates)
    retained_indices = {
        *(_index for _index, _candidate in head_candidates),
        *(_index for _index, _candidate in tail_candidates),
        *(_index for _index, _candidate in priority_candidates),
    }
    omitted_in_window = max(0, candidate_count - len(retained_indices))
    parse_ok = candidate_count > 0
    failure_kind = "" if parse_ok else ("empty" if not text.strip() else "parse_error")
    return SrcParseResult(
        name, parse_ok, candidate_count, head, tail, priority,
        omitted_in_window, tuple(errors[:64]), _next_actions(name), partial, remaining_unknown,
        failure_kind,
    )


def parse_src_output(tool: str, output: str) -> SrcParseResult:
    """Parse bounded CLI output into normalized, scope-neutral candidates."""

    return _parse_src_text(tool, output)


def _capture_output(capture: Mapping[str, Any]) -> tuple[str, str]:
    capture_id = str(capture.get("id") or "").strip()
    directory_text = str(capture.get("directory") or "").strip()
    if (
        not capture_id
        or len(capture_id) > 64
        or capture_id in {".", ".."}
        or "/" in capture_id
        or "\\" in capture_id
        or not directory_text
    ):
        return "", "capture directory is unavailable"
    raw_directory = Path(directory_text)
    if raw_directory.is_symlink():
        return "", "capture directory must not be symlinked"
    try:
        owned_directory = Path(directory_text).resolve(strict=False)
    except OSError as exc:
        return "", f"capture directory resolve failed: {exc}"
    if (
        not owned_directory.is_dir()
        or owned_directory.name != capture_id
        or owned_directory.parent.name != ".captures"
    ):
        return "", "capture directory is outside owned .captures boundary"
    try:
        owned_directory.relative_to(Path(worker_config.work_root).resolve(strict=False))
    except (OSError, ValueError):
        return "", "capture directory is outside worker root"

    channels = capture.get("channels")
    descriptors: Iterable[Any]
    if isinstance(channels, Mapping):
        mapped_descriptors: list[Any] = []
        for channel_name, descriptor in channels.items():
            if isinstance(descriptor, Mapping) and "name" not in descriptor:
                mapped_descriptors.append({"name": channel_name, **descriptor})
            else:
                mapped_descriptors.append(descriptor)
        descriptors = mapped_descriptors
    elif isinstance(channels, (list, tuple)):
        descriptors = channels
    else:
        descriptors = ()
    for descriptor in descriptors:
        if not isinstance(descriptor, Mapping) or str(descriptor.get("name") or "") not in {"output", "stdout"}:
            continue
        path_text = str(descriptor.get("path") or "")
        if not path_text:
            continue
        raw_channel_path = Path(path_text)
        if raw_channel_path.is_symlink():
            return "", "capture output channel must not be symlinked"
        try:
            channel_path = raw_channel_path.resolve(strict=False)
        except OSError as exc:
            return "", f"capture output ownership failed: {exc}"
        if channel_path.parent != owned_directory:
            return "", "capture output channel is outside owned directory"
        try:
            with channel_path.open("rb") as stream:
                data = stream.read(_MAX_PARSE_BYTES + 1)
            return data.decode("utf-8", "replace"), ""
        except (OSError, ValueError) as exc:
            return "", f"capture output read failed: {exc}"
    return "", "capture output channel not found"


def parse_src_capture(tool: str, capture: Mapping[str, Any], scope_target: str) -> SrcParseResult:
    """Read the private output channel and admit only same-scope candidates."""

    if not isinstance(capture, Mapping):
        return SrcParseResult(str(tool or ""), False, 0, (), (), (), 0, ("invalid capture",), _next_actions(str(tool or "")), True, True, "capture_unavailable")
    output, capture_error = _capture_output(capture)
    result = _parse_src_text(tool, output, scope_target=scope_target)
    capture_partial = str(capture.get("status") or "").lower() in {"partial", "writing", "failed", "legacy_partial"}
    if capture_partial and not result.partial:
        result = SrcParseResult(
            result.tool, result.parse_ok, result.count, result.head_candidates, result.tail_candidates,
            result.priority_candidates, result.omitted, result.parse_errors, result.next_actions,
            True, True, result.failure_kind,
        )
    if capture_error:
        return SrcParseResult(
            result.tool, False, result.count, result.head_candidates, result.tail_candidates,
            result.priority_candidates, result.omitted, tuple((*result.parse_errors, capture_error))[:64],
            result.next_actions, True, True, "capture_unavailable",
        )
    return result


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
    follow_redirects: bool = False


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
    follow_redirects: bool = False,
) -> SrcToolPlan:
    return SrcToolPlan(
        tool=tool,
        binary=argv[0],
        argv=tuple(argv),
        display_argv=tuple(display),
        timeout=timeout,
        guidance=guidance,
        follow_redirects=follow_redirects,
    )


def _probe_http(args: Mapping[str, Any], scope: str) -> SrcToolPlan:
    url = _url(args.get("url"), scope)
    rate = _bounded_int(args.get("rate_limit"), 20, 1, 50, "rate_limit")
    request_timeout = _bounded_int(args.get("request_timeout"), 10, 3, 30, "request_timeout")
    follow_redirects = bool(args.get("follow_redirects", False))
    argv = [
        "httpx", "-u", url, "-silent", "-json", "-status-code", "-title",
        "-server", "-tech-detect", "-ip", "-cname", "-rate-limit", str(rate),
        "-timeout", str(request_timeout), "-no-color", "-disable-update-check",
    ]
    display = list(argv)
    # Keep accepting the legacy flag in callers, but leave redirects disabled.
    # Redirect handling belongs to the bounded HTTP executor so a Location header
    # cannot silently move the probe to another host.
    _header_args(argv, display, _headers(args.get("headers")))
    return _plan(
        "probe_http", argv, display, timeout=90,
        follow_redirects=follow_redirects,
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
        "-crawl-scope", rf"^https?://{re.escape(_host(scope) or _host(url))}(?::\d+)?(?:/|$)",
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
    # Keep accepting the compatibility flag, but Arjun must never follow an
    # external redirect inside the discovery process.
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
    "SRC_TOOL_CATALOG",
    "SrcToolError",
    "SrcToolPlan",
    "SrcParseResult",
    "SrcCandidate",
    "ToolSpec",
    "build_src_plan",
    "parse_src_capture",
    "parse_src_output",
]
