"""工具执行器：worker 真实挖洞的底层能力。

提供给 LLM 通过 function calling 调用：
- run_shell: 受控执行任意命令（带超时、输出截断、自毁防护、工作目录隔离）
- http_request: 发原始 HTTP 请求，返回完整请求包+响应包（取证用）
"""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from copy import copy
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, BinaryIO, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from app.config import worker_config
from app.tools.auth_analyzer import analyze_auth_material as _analyze_auth_material
from app.tools.decoder import decode_transform as _decode_transform
from app.tools.evidence import (
    analyze_api_schema as _analyze_api_schema,
    compare_http_responses as _compare_http_responses,
)
from app.tools.guard import (
    ENTERPRISE_ALLOWED_PARSERS,
    CommandBlocked,
    check_command,
    check_enterprise_command,
)
from app.tools.http_surface import extract_http_surface as _extract_http_surface
from app.tools.js_analyzer import analyze_javascript as analyze_js_text
from app.tools.js_analyzer import analyze_url as analyze_js_url
from app.tools.src_toolkit import (
    ENTERPRISE_BLOCKED_SRC_TOOLS,
    SRC_TOOL_NAMES,
    SrcToolError,
    build_src_plan,
    parse_src_capture,
    parse_src_output,
)
from app.tools.waf_advisor import suggest_waf_bypass as _suggest_waf_bypass
from app.fofa import endpoints as fofa_endpoints
from app.fofa.client import (
    FofaError,
    _FOFA_ALLOWED_HOSTS,
    classify_fofa_failure,
    extract_fofa_error,
    extract_fofa_response_failure,
)
from app.fofa.router import FofaKeyRouter, FofaPoolExhaustedError

_FOFA_BASE = "https://fofa.info"
# FOFA 只读查询硬上限：worker 用它确认归属/探攻击面，不是测绘，给小额度即可。
_FOFA_LOOKUP_MAX_SIZE = 30
# 企业 session cookie jar 上限，防异常站点塞爆内存。
_SESSION_MAX_COOKIES = 50
_SESSION_MAX_HEADERS = 30

# 单目标工作目录落地日志体积上限（字节）。24x7 防撞盘：超限后停止写新日志文件，
# 仍把截断输出回传给 LLM，不影响挖掘，只是不再落地完整证据。
_WORKDIR_MAX_BYTES = int(os.environ.get("WORKER_WORKDIR_MAX_BYTES", str(50 * 1024 * 1024)))
_SHELL_CAPTURE_MAX_BYTES = int(os.environ.get("WORKER_SHELL_CAPTURE_MAX_BYTES", str(512 * 1024)))
_HTTP_MAX_BYTES = int(os.environ.get("WORKER_HTTP_MAX_BYTES", str(1024 * 1024)))
_MAX_HTTP_REDIRECTS = 3


def _scope_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlsplit(text if "://" in text else f"//{text}")
    host = str(parsed.hostname or "").rstrip(".").lower()
    # Test and local worker identifiers are not network scopes.  Real URL,
    # dotted host, IPv4/IPv6 and localhost targets remain enforceable.
    if not (parsed.scheme in {"http", "https"} or "." in host or ":" in host or host == "localhost"):
        return ""
    return host


class _CaptureWriter:
    """Write one raw evidence channel without retaining its bytes in memory."""

    def __init__(self, path: Path):
        self.path = path
        self._file: BinaryIO = path.open("wb")
        self._hash = hashlib.sha256()
        self.size = 0
        self._closed = False

    def write(self, data: bytes) -> None:
        if not data:
            return
        self._file.write(data)
        self._hash.update(data)
        self.size += len(data)

    def close(self) -> dict[str, Any]:
        if not self._closed:
            self._file.flush()
            self._file.close()
            self._closed = True
        return {
            "path": str(self.path),
            "size": self.size,
            "sha256": self._hash.hexdigest(),
        }


class _CaptureSpool:
    """Private, file-backed capture descriptor consumed by persistence code."""

    def __init__(self, work_dir: Path, tool: str):
        self.id = uuid.uuid4().hex
        self.tool = tool
        self.directory = work_dir / ".captures" / self.id
        self.directory.mkdir(parents=True, exist_ok=False)
        self._writers: dict[str, _CaptureWriter] = {}

    def open_channel(self, name: str) -> _CaptureWriter:
        writer = self._writers.get(name)
        if writer is not None:
            return writer
        writer = _CaptureWriter(self.directory / f"{name}.bin")
        self._writers[name] = writer
        return writer

    def write_channel(self, name: str, data: bytes) -> None:
        self.open_channel(name).write(data)

    def descriptor(
        self,
        *,
        status: str,
        error: str = "",
        meta: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        channels = []
        for name, writer in self._writers.items():
            channels.append({"name": name, **writer.close()})
        return {
            "id": self.id,
            "tool": self.tool,
            "status": status,
            "error": error,
            "meta": dict(meta or {}),
            "directory": str(self.directory),
            "channels": channels,
        }


def _truncate(text: str, limit: Optional[int] = None) -> str:
    if limit is None:
        limit = worker_config.output_truncate
        if worker_config.llm_tool_output_truncate > 0:
            limit = min(limit, worker_config.llm_tool_output_truncate)
    else:
        limit = int(limit)
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 4 :]
    return f"{head}\n\n...[输出过长已截断，完整内容已写入工作目录文件]...\n\n{tail}"


def _normalize_headers(headers: Any) -> dict[str, str]:
    """把 LLM 可能乱传的 headers 统一成 {str: str}，容错非 dict 形态，绝不抛异常。

    支持：
      - dict            → 原样（值转字符串）
      - list["K: V"]    → 逐行按第一个冒号切分
      - "K: V\\nK2: V2"  → 按行切分
      - None / 其它      → {}
    """
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    lines: list[str] = []
    if isinstance(headers, str):
        lines = headers.splitlines()
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, dict):
                if "name" in item and "value" in item:
                    lines.append(f"{item['name']}: {item['value']}")
                else:
                    lines.extend(f"{k}: {v}" for k, v in item.items())
            else:
                lines.append(str(item))
    else:
        return {}
    out: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


class ToolExecutor:
    def __init__(
        self,
        target: str,
        work_dir: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
        enterprise: bool = False,
        fofa_key: str = "",
        fofa_base_url: str = "",
        fofa_router: FofaKeyRouter | None = None,
        capture_full: bool = False,
        scope_target: str = "",
    ):
        self.target = target
        self.scope_target = scope_target or target
        self.cancel_event = cancel_event or threading.Event()
        # 企业模式：对目标生产环境的破坏性命令做额外硬拦截。
        self.enterprise = enterprise
        self.fofa_key = fofa_key or ""
        self.fofa_base_url = (fofa_base_url or _FOFA_BASE).rstrip("/")
        if fofa_router is not None:
            self.fofa_router = fofa_router
        elif self.fofa_key:
            from app.config import FofaKeyConfig
            self.fofa_router = FofaKeyRouter([
                FofaKeyConfig(name="Legacy", key=self.fofa_key, base_url=self.fofa_base_url)
            ], active_name="Legacy")
        else:
            self.fofa_router = None
        self.capture_full = bool(capture_full)
        # 每个目标独立工作目录
        safe_name = "".join(c if c.isalnum() else "_" for c in target)[:60]
        self.work_dir = Path(work_dir or worker_config.work_root) / safe_name
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._log_seq = 0
        self._active_procs: set[subprocess.Popen] = set()
        # 会话态：worker 登录/拿到 token 后自动携带到后续 http_request，
        # 解决"明明登进去了，深挖请求却忘带凭证导致越权失败"的断链问题。
        # 每个 target 独立 executor 实例、session jar 相互隔离，不会串号。
        # 全模式启用（登录后同样必须带登录态深入）。
        self._session_cookies: dict[str, str] = {}
        self._session_cookie_jar = httpx.Cookies()
        self._session_headers: dict[str, str] = {}

    def _new_capture(self, tool: str) -> Optional[_CaptureSpool]:
        if not self.capture_full:
            return None
        return _CaptureSpool(self.work_dir, tool)

    def cancel_running(self) -> None:
        """协作取消：置取消信号 + 杀子进程。仅用于控制面真取消（pause/stop/超时）。

        注意：会 set cancel_event，worker 据此判定"被取消、结果丢弃"。所以
        【正常完成后的清理】绝不能调这个（否则正常结果会被误判成取消而丢弃，
        历史事故根因：每个 worker 完成都被丢弃、findings/done 永远为 0）。
        正常完成清理请用 kill_processes()。
        """
        self.cancel_event.set()
        self.kill_processes()

    def kill_processes(self) -> None:
        """只杀掉当前 executor 启动的所有子进程组，不触碰 cancel_event。

        用于 worker 正常完成后的资源清理（杀残留子进程），不污染取消信号。
        """
        for proc in list(self._active_procs):
            self._kill_process_group(proc)

    # ---- run_shell ----
    def run_shell(self, command: str, timeout: Optional[int] = None) -> dict[str, Any]:
        try:
            timeout = int(timeout) if timeout else worker_config.shell_timeout
        except (TypeError, ValueError):
            timeout = worker_config.shell_timeout
        # 硬上限 + 下限：防 LLM 传超大/非法 timeout 长期占用 worker 槽位（DoS）。
        timeout = max(1, min(timeout, worker_config.shell_timeout_max))
        try:
            check_command(command, enterprise=self.enterprise)
            if self.enterprise:
                argv = check_enterprise_command(
                    command,
                    scope_target=self.scope_target,
                    allowed_parsers=ENTERPRISE_ALLOWED_PARSERS,
                )
                process_argv = argv
                process_env = None
                if tuple(argv[:3]) == ("python", "-m", "app.tools.local_parsers"):
                    process_argv = (sys.executable, *argv[1:])
                    process_env = os.environ.copy()
                    project_root = str(Path(__file__).resolve().parents[2])
                    existing_pythonpath = process_env.get("PYTHONPATH", "")
                    process_env["PYTHONPATH"] = os.pathsep.join(
                        item for item in (project_root, existing_pythonpath) if item
                    )
                return self._run_process(
                    process_argv,
                    timeout=timeout,
                    shell=False,
                    capture_tool="run_shell",
                    display_command=command,
                    env=process_env,
                )
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}

        return self._run_process(
            command,
            timeout=timeout,
            shell=True,
            capture_tool="run_shell",
            display_command=command,
        )

    def _run_process(
        self,
        command: str | list[str] | tuple[str, ...],
        *,
        timeout: int,
        shell: bool,
        capture_tool: str,
        display_command: str,
        env: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Run one bounded process, preserving the existing capture/cancel contract."""
        capture = self._new_capture(capture_tool)
        capture_output: Optional[_CaptureWriter] = None
        if capture is not None:
            capture.write_channel("command", display_command.encode("utf-8", "surrogatepass"))
            capture_output = capture.open_channel("output")

        start = time.time()
        proc: subprocess.Popen | None = None
        timed_out = False
        cancelled = False
        omitted_bytes = 0
        preview_size = 0
        chunks: list[bytes] = []
        try:
            proc = subprocess.Popen(
                command,
                shell=shell,
                cwd=str(self.work_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # 独立进程组，便于超时整组 kill
                env=env,
            )
            self._active_procs.add(proc)
            deadline = start + timeout
            if proc.stdout is None:
                rc = proc.wait(timeout=timeout)
            else:
                read_errors: list[Exception] = []

                def _drain_stdout() -> None:
                    nonlocal preview_size, omitted_bytes
                    try:
                        while True:
                            data = proc.stdout.read1(8192)
                            if not data:
                                break
                            if capture_output is not None:
                                capture_output.write(data)
                            room = max(0, _SHELL_CAPTURE_MAX_BYTES - preview_size)
                            if room:
                                kept = data[:room]
                                chunks.append(kept)
                                preview_size += len(kept)
                            if len(data) > room:
                                omitted_bytes += len(data) - room
                    except Exception as exc:
                        read_errors.append(exc)

                reader = threading.Thread(target=_drain_stdout, daemon=True)
                reader.start()
                kill_sent = False
                while proc.poll() is None:
                    if self.cancel_event.is_set():
                        cancelled = True
                        if not kill_sent:
                            self._kill_process_group(proc)
                            kill_sent = True
                    elif time.time() >= deadline:
                        timed_out = True
                        if not kill_sent:
                            self._kill_process_group(proc)
                            kill_sent = True
                    time.sleep(0.05)
                rc = proc.wait(timeout=3)
                reader.join(timeout=3)
                if reader.is_alive():
                    try:
                        proc.stdout.close()
                    except Exception:
                        pass
                    reader.join(timeout=1)
                if read_errors and not (cancelled or timed_out):
                    raise read_errors[0]
            cancelled = cancelled or self.cancel_event.is_set()
        except Exception as e:
            result: dict[str, Any] = {"ok": False, "error": f"命令执行异常: {e}"}
            if capture is not None:
                result["_capture"] = capture.descriptor(
                    status="partial" if proc is not None else "failed",
                    error=str(e),
                    meta={"command_started": proc is not None},
                )
            return result
        finally:
            if proc is not None:
                self._active_procs.discard(proc)
                if proc.poll() is None:
                    self._kill_process_group(proc)
                    try:
                        proc.wait(timeout=3)
                    except Exception:
                        pass

        elapsed = round(time.time() - start, 2)
        full_out = b"".join(chunks).decode("utf-8", "replace")
        if omitted_bytes:
            suffix = "完整字节已保存到原始证据" if capture is not None else "超出部分未保留"
            full_out += (
                f"\n\n...[输出超过 {_SHELL_CAPTURE_MAX_BYTES} 字节，"
                f"预览省略约 {omitted_bytes} 字节，{suffix}]..."
            )
        # 人类可读预览仍写工作目录；完整字节由私有 capture spool 单独保存。
        log_file = self._write_log(f"$ {display_command}\n\n{full_out}")

        result = {
            "ok": rc == 0 and not timed_out and not cancelled,
            "return_code": rc,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "elapsed_sec": elapsed,
            "output": _truncate(full_out),
            "output_file": str(log_file) if log_file else "",
        }
        if capture is not None:
            capture_status = "partial" if timed_out or cancelled else "complete"
            capture_error = "cancelled" if cancelled else "timed_out" if timed_out else ""
            result["_capture"] = capture.descriptor(
                status=capture_status,
                error=capture_error,
                meta={
                    "return_code": rc,
                    "timed_out": timed_out,
                    "cancelled": cancelled,
                    "elapsed_sec": elapsed,
                },
            )
        return result

    def _src_args_with_session(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        values = dict(args)
        if tool in {"scan_web_ports", "fingerprint_waf"}:
            return values
        supplied = _normalize_headers(values.get("headers"))
        merged = dict(self._session_headers)
        merged.update(supplied)
        cookie_url = str(values.get("url") or values.get("target") or self.target)
        cookie_header = self._session_cookie_header(cookie_url)
        if cookie_header and not any(key.lower() == "cookie" for key in merged):
            merged["Cookie"] = cookie_header
        if merged:
            values["headers"] = merged
        return values

    def run_src_tool(self, tool: str, args: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Execute one structured SRC tool plan without invoking a command shell."""
        name = str(tool or "").strip()
        if name not in SRC_TOOL_NAMES:
            return {
                "ok": False,
                "process_ok": False,
                "parse_ok": False,
                "failure_kind": "unknown_tool",
                "kind": "arg_error",
                "summary": {},
                "tool": name,
                "error": f"未知 SRC 工具: {name}",
            }
        if self.enterprise and name in ENTERPRISE_BLOCKED_SRC_TOOLS:
            return {
                "ok": False,
                "process_ok": False,
                "parse_ok": False,
                "failure_kind": "enterprise_policy",
                "kind": "enterprise_policy",
                "summary": {},
                "blocked": True,
                "tool": name,
                "error": "企业 SRC 模式禁止使用 Nuclei 类漏洞扫描工具；请改用已知入口的最小请求验证。",
            }
        try:
            plan_args = self._src_args_with_session(name, dict(args or {}))
            plan = build_src_plan(
                name,
                plan_args,
                scope_target=self.scope_target,
            )
        except SrcToolError as exc:
            return {
                "ok": False,
                "process_ok": False,
                "parse_ok": False,
                "failure_kind": "scope" if exc.blocked else "arg",
                "kind": "arg_error",
                "summary": {},
                "blocked": bool(exc.blocked),
                "tool": name,
                "error": str(exc),
            }

        requested_follow_redirects = plan.follow_redirects
        redirect_metadata: dict[str, Any] = {}
        if name == "probe_http" and requested_follow_redirects:
            redirect_result = self.http_request(
                url=str(plan_args.get("url") or ""),
                method="GET",
                headers=_normalize_headers(plan_args.get("headers")),
                follow_redirects=True,
                timeout=max(3, min(int(plan_args.get("request_timeout") or 10), 30)),
                body_preview_limit=512,
                _capture_enabled=False,
            )
            for key in (
                "redirect_chain",
                "final_url",
                "redirect_location",
                "redirect_blocked",
                "redirect_limit_reached",
            ):
                if key in redirect_result:
                    redirect_metadata[key] = redirect_result[key]
            final_url = str(redirect_result.get("final_url") or "")
            if redirect_result.get("ok") and final_url and not redirect_result.get("redirect_blocked"):
                redirected_args = dict(plan_args)
                redirected_args["url"] = final_url
                redirected_args["follow_redirects"] = False
                plan = build_src_plan(
                    name,
                    redirected_args,
                    scope_target=self.scope_target,
                )

        for index, token in enumerate(plan.argv[:-1]):
            if token == "-w":
                wordlist = Path(plan.argv[index + 1])
                if not wordlist.is_file():
                    return {
                        "ok": False,
                        "process_ok": False,
                        "parse_ok": False,
                        "failure_kind": "missing_resource",
                        "kind": "missing_resource",
                        "summary": {},
                        "tool": name,
                        "error": f"内置字典不存在: {wordlist}",
                    }

        binary = shutil.which(plan.binary)
        if not binary:
            return {
                "ok": False,
                "process_ok": False,
                "parse_ok": False,
                "failure_kind": "missing_binary",
                "kind": "missing_tool",
                "summary": {},
                "missing_tool": True,
                "tool": name,
                "binary": plan.binary,
                "error": f"SRC 工具 {plan.binary} 未安装；请重新构建包含安全工具层的镜像。",
            }
        display_command = subprocess.list2cmdline(list(plan.display_argv))
        try:
            check_command(display_command, enterprise=self.enterprise)
        except CommandBlocked as exc:
            return {
                "ok": False,
                "process_ok": False,
                "parse_ok": False,
                "failure_kind": "command_policy",
                "kind": "command_policy",
                "summary": {},
                "blocked": True,
                "tool": name,
                "error": str(exc),
            }
        command = [binary, *plan.argv[1:]]
        result = self._run_process(
            command,
            timeout=min(plan.timeout, worker_config.shell_timeout_max),
            shell=False,
            capture_tool=name,
            display_command=display_command,
        )
        result.update({
            "tool": name,
            "binary": plan.binary,
            "command": display_command,
            "guidance": plan.guidance,
            "follow_redirects": requested_follow_redirects,
            **redirect_metadata,
        })
        process_ok = bool(result.get("ok"))
        if bool(result.get("cancelled")):
            process_failure = "cancelled"
        elif bool(result.get("timed_out")):
            process_failure = "timeout"
        elif not process_ok:
            process_failure = "nonzero_exit"
        else:
            process_failure = ""

        capture = result.get("_capture")
        if isinstance(capture, dict):
            parsed = parse_src_capture(name, capture, self.scope_target)
            capture_failure = (
                "capture_unavailable" if parsed.failure_kind == "capture_unavailable" else ""
            )
        else:
            parsed = parse_src_output(
                name,
                str(result.get("output") or ""),
                self.scope_target,
            )
            parsed = replace(parsed, partial=True, remaining_unknown=True)
            capture_failure = "capture_unavailable"

        failure_kind = process_failure or capture_failure
        if not failure_kind and not parsed.parse_ok:
            failure_kind = parsed.failure_kind or "parse_error"
        result.update(
            {
                "process_ok": process_ok,
                "parse_ok": parsed.parse_ok,
                "failure_kind": failure_kind,
                "summary": asdict(parsed),
                "ok": process_ok and parsed.parse_ok and not parsed.remaining_unknown,
            }
        )
        return result

    @staticmethod
    def _kill_process_group(proc: subprocess.Popen) -> None:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                    check=False,
                )
                return
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _dir_size(self) -> int:
        try:
            return sum(f.stat().st_size for f in self.work_dir.glob("*") if f.is_file())
        except Exception:
            return 0

    def _write_log(self, content: str) -> Optional[Path]:
        """落地日志文件；工作目录超体积上限则跳过（返回 None），不再写盘。"""
        if self._dir_size() >= _WORKDIR_MAX_BYTES:
            return None
        self._log_seq += 1
        log_file = self.work_dir / f"shell_{self._log_seq}.log"
        try:
            log_file.write_text(content, encoding="utf-8")
        except Exception:
            return None
        return log_file

    def _enforce_scope_url(self, url: str) -> None:
        expected = _scope_host(self.scope_target)
        actual = _scope_host(url)
        if not actual or (expected and actual != expected):
            raise CommandBlocked(
                f"HTTP URL 超出当前目标范围: {actual or '<invalid>'}"
            )

    # ---- http_request ----
    def http_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        data: Optional[str] = None,
        json_body: Optional[Any] = None,
        follow_redirects: bool = False,
        timeout: int = 20,
        body_preview_limit: Optional[int] = None,
        _capture_enabled: bool = True,
    ) -> dict[str, Any]:
        # LLM 可能把 headers 传成非 dict 形态（list["K: V"] / "K: V\nK2: V2" / None），
        # 直接喂给 dict()/httpx 会抛 "dictionary update sequence element..." 崩掉整个 agent。
        # 这里统一规范化成 dict，容错所有 agent 的 http_request 调用。
        headers = _normalize_headers(headers)
        try:
            self._enforce_scope_url(url)
        except CommandBlocked as exc:
            return {
                "ok": False,
                "blocked": True,
                "failure_kind": "scope",
                "error": str(exc),
                "url": url,
            }
        # 会话保持：把已维持的 cookie/header 合并进本次请求（用户传的同名键优先）。
        merged_headers, session_applied = self._apply_session(headers, url)

        capture = self._new_capture("http_request") if _capture_enabled else None
        req: httpx.Request | None = None
        initial_req: httpx.Request | None = None
        resp: httpx.Response | None = None
        redirect_chain: list[str] = []
        redirect_location = ""
        redirect_blocked = False
        redirect_limit_reached = False
        current_url = url
        current_method = method.upper()
        current_data = data
        current_json = json_body
        try:
            with httpx.Client(
                verify=False,
                follow_redirects=False,
                timeout=timeout,
                cookies=self._session_cookie_jar,
            ) as client:
                for hop in range(_MAX_HTTP_REDIRECTS + 1):
                    req = client.build_request(
                        current_method,
                        current_url,
                        headers=merged_headers,
                        content=current_data,
                        json=current_json,
                    )
                    if initial_req is None:
                        initial_req = req
                    if capture is not None and hop == 0:
                        capture.write_channel("request", self._raw_request_bytes(req))
                    resp = client.send(req, stream=True)
                    redirect_chain.append(
                        f"{resp.status_code} {resp.request.method} {resp.request.url}"
                    )
                    location = resp.headers.get("location")
                    next_url = str(urljoin(str(resp.url), location)) if location else ""
                    location_in_scope = True
                    if next_url:
                        redirect_location = next_url
                        try:
                            self._enforce_scope_url(next_url)
                        except CommandBlocked:
                            redirect_blocked = True
                            location_in_scope = False
                    if not (
                        follow_redirects
                        and location
                        and location_in_scope
                        and resp.status_code in {301, 302, 303, 307, 308}
                    ):
                        break
                    if hop >= _MAX_HTTP_REDIRECTS:
                        redirect_limit_reached = True
                        break
                    client.cookies.extract_cookies(resp)
                    status_code = resp.status_code
                    resp.close()
                    if status_code == 303 or (
                        status_code in {301, 302}
                        and current_method not in {"GET", "HEAD"}
                    ):
                        current_method = "GET"
                        current_data = None
                        current_json = None
                    current_url = next_url
                response_capture = capture.open_channel("response") if capture is not None else None
                if response_capture is not None:
                    response_capture.write(self._raw_response_head(resp))
                body, truncated = self._read_limited_response(resp, response_capture)
                session_updated = self._absorb_cookie_jar(client)
        except Exception as e:
            result: dict[str, Any] = {
                "ok": False,
                "error": f"HTTP 请求异常: {e}",
                "url": url,
            }
            if capture is not None:
                result["_capture"] = capture.descriptor(
                    status="partial" if resp is not None else "failed",
                    error=str(e),
                    meta={"method": method.upper(), "url": url},
                )
            return result

        assert resp is not None

        # 原始请求行（取证/格式参考）。响应报文不再单独回传：状态码 + response_headers +
        # body 已结构化提供，raw_response 会与它们 100% 重复，是当轮就纯冗余的双份大文本。
        # 模型 submit_finding 时按 prompt 规范从 body 自行裁剪取证，不依赖这份 raw_response。
        raw_req = self._raw_request(initial_req or req, data, json_body)

        response_headers = dict(resp.headers)
        set_cookie_headers = resp.headers.get_list("set-cookie")
        result = {
            "ok": True,
            "status_code": resp.status_code,
            "url": str(resp.url),
            "response_headers": response_headers,
            "body": _truncate(body, body_preview_limit) if body_preview_limit else _truncate(body),
            "body_len": len(body),
            "body_truncated": truncated,
            "raw_request": _truncate(raw_req, 1536),
        }
        if set_cookie_headers:
            result["set_cookie_headers"] = set_cookie_headers
        if len(redirect_chain) > 1 or redirect_location:
            result["redirect_chain"] = redirect_chain[:12]
            result["final_url"] = str(resp.url)
        if redirect_location:
            result["redirect_location"] = redirect_location
        if redirect_blocked:
            result["redirect_blocked"] = True
        if redirect_limit_reached:
            result["redirect_limit_reached"] = True
        if session_applied:
            result["session_applied"] = session_applied
        if session_updated:
            result["session_cookies_updated"] = session_updated
        if capture is not None:
            result["_capture"] = capture.descriptor(
                status="complete",
                meta={
                    "method": method.upper(),
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                },
            )
        return result

    # ---- 会话状态管理（全模式）----
    def _session_cookie_header(self, url: str) -> str:
        """返回仅适用于当前 URL 的自动 Cookie，并叠加 session_set 的显式 Cookie。"""
        scoped_parts: list[str] = []
        try:
            cookie_url = str(url or self.target).strip()
            if "://" not in cookie_url:
                cookie_url = f"https://{cookie_url.lstrip('/')}"
            request = httpx.Request("GET", cookie_url)
            self._session_cookie_jar.set_cookie_header(request)
            scoped_parts = [
                part.strip() for part in request.headers.get("cookie", "").split(";") if part.strip()
            ]
        except Exception:
            scoped_parts = []

        manual_names = set(self._session_cookies)
        filtered = [
            part for part in scoped_parts if part.split("=", 1)[0].strip() not in manual_names
        ]
        filtered.extend(f"{name}={value}" for name, value in self._session_cookies.items())
        return "; ".join(filtered)

    def _apply_session(
        self,
        headers: Optional[dict[str, str]],
        url: str = "",
    ) -> tuple[dict[str, str], list[str]]:
        """把维持的 session cookie/header 合并进请求头。返回 (合并后headers, 应用了哪些)。

        合并规则：用户本次显式传入的头优先（不被 session 覆盖），保证可手动覆写。
        会话为空时原样返回、零开销；全模式启用。
        """
        if not self._session_cookies and not self._session_cookie_jar.jar and not self._session_headers:
            return (dict(headers) if headers else {}), []
        try:
            merged: dict[str, str] = {}
            applied: list[str] = []
            for k, v in self._session_headers.items():
                merged[k] = v
            cookie_header = self._session_cookie_header(url or self.target)
            if cookie_header:
                merged["Cookie"] = cookie_header
                applied.append(f"Cookie({len(cookie_header.split(';'))})")
            if self._session_headers:
                applied.append(f"headers({len(self._session_headers)})")
            # 用户本次传入的头覆盖 session（显式优先）。
            if headers:
                for k, v in headers.items():
                    merged[k] = v
            return merged, applied
        except Exception:
            return (dict(headers) if headers else {}), []

    @staticmethod
    def _cookie_jar_state(cookies: httpx.Cookies) -> dict[tuple[str, str, str], str]:
        return {
            (cookie.name, cookie.domain or "", cookie.path or "/"): cookie.value
            for cookie in cookies.jar
        }

    def _absorb_cookie_jar(self, client: httpx.Client) -> list[str]:
        """持久化整个 Client jar，保留重定向链中 Cookie 的 domain/path 作用域。"""
        try:
            previous = self._cookie_jar_state(self._session_cookie_jar)
            persisted = httpx.Cookies()
            for cookie in client.cookies.jar:
                if len(persisted.jar) >= _SESSION_MAX_COOKIES:
                    break
                persisted.jar.set_cookie(copy(cookie))
            current = self._cookie_jar_state(persisted)
            self._session_cookie_jar = persisted
            changed_keys = {
                key for key in previous.keys() | current.keys() if previous.get(key) != current.get(key)
            }
            return sorted({key[0] for key in changed_keys})
        except Exception:
            return []

    def session_set(
        self,
        cookies: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        """worker 显式设置/查看会话态：手动登记拿到的 token/cookie，后续自动携带。全模式可用。"""
        try:
            if clear:
                self._session_cookies.clear()
                self._session_cookie_jar.clear()
                self._session_headers.clear()
            if isinstance(cookies, dict):
                for k, v in cookies.items():
                    if not isinstance(k, str):
                        continue
                    if k in self._session_cookies or len(self._session_cookies) < _SESSION_MAX_COOKIES:
                        self._session_cookies[k] = str(v)[:4096]
            if isinstance(headers, dict):
                for k, v in headers.items():
                    if not isinstance(k, str):
                        continue
                    if k in self._session_headers or len(self._session_headers) < _SESSION_MAX_HEADERS:
                        self._session_headers[k] = str(v)[:4096]
            return {
                "ok": True,
                "active_cookies": sorted(
                    set(self._session_cookies)
                    | {cookie.name for cookie in self._session_cookie_jar.jar}
                ),
                "active_headers": sorted(self._session_headers.keys()),
                "guidance": "已更新会话态，后续 http_request 会自动携带；继续以此据点深挖受限接口。",
            }
        except Exception as e:
            return {"ok": False, "error": f"session_set 异常: {type(e).__name__}: {e}"}

    # ---- decode_transform ----
    def decode_transform(self, value: str = "", mode: str = "auto") -> dict[str, Any]:
        """编码/解码/哈希分析（纯内存，无外部副作用）。详见 tools/decoder.py。"""
        return _decode_transform(value, mode)

    def compare_http_responses(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        ignore_json_paths: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """对比两份已取得的 HTTP 响应，提取可复核的结构差异。"""
        return _compare_http_responses(baseline, candidate, ignore_json_paths)

    def analyze_api_schema(
        self,
        document: str = "",
        url: str = "",
        base_url: str = "",
        focus: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """解析 OpenAPI/Swagger JSON 并排序高价值验证入口。"""
        capture = None
        source: dict[str, Any] = {}
        if not document and url:
            fetched = self.http_request(
                url=url,
                method="GET",
                follow_redirects=True,
                body_preview_limit=_HTTP_MAX_BYTES + 512,
            )
            capture = fetched.pop("_capture", None)
            if not fetched.get("ok"):
                if capture:
                    fetched["_capture"] = capture
                return fetched
            if fetched.get("body_truncated"):
                result = {"ok": False, "error": "OpenAPI 文档超过 WORKER_HTTP_MAX_BYTES，无法完整解析"}
                if capture:
                    result["_capture"] = capture
                return result
            document = str(fetched.get("body") or "")
            base_url = base_url or str(fetched.get("url") or url)
            source = {
                "url": fetched.get("url") or url,
                "status_code": fetched.get("status_code"),
                "content_type": (fetched.get("response_headers") or {}).get("content-type", ""),
            }
        result = _analyze_api_schema(document, base_url, focus)
        if source:
            result["source"] = source
        if capture:
            result["_capture"] = capture
        return result

    def extract_http_surface(
        self,
        body: str = "",
        url: str = "",
        base_url: str = "",
        response_headers: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """从 HTML 响应提取表单、资源和高价值候选入口。"""
        capture = None
        source: dict[str, Any] = {}
        if not body and url:
            fetched = self.http_request(
                url=url,
                method="GET",
                follow_redirects=True,
                body_preview_limit=_HTTP_MAX_BYTES + 512,
            )
            capture = fetched.pop("_capture", None)
            if not fetched.get("ok"):
                if capture:
                    fetched["_capture"] = capture
                return fetched
            body = str(fetched.get("body") or "")
            base_url = base_url or str(fetched.get("url") or url)
            response_headers = response_headers or fetched.get("response_headers")
            source = {
                "url": fetched.get("url") or url,
                "status_code": fetched.get("status_code"),
                "body_truncated": bool(fetched.get("body_truncated")),
            }
        result = _extract_http_surface(body, base_url, response_headers)
        if source:
            result["source"] = source
        if capture:
            result["_capture"] = capture
        return result

    def analyze_auth_material(
        self,
        request_headers: Optional[dict[str, Any]] = None,
        response_headers: Optional[dict[str, Any]] = None,
        set_cookie_headers: Optional[list[str]] = None,
        body: str = "",
    ) -> dict[str, Any]:
        """归纳请求/响应中的鉴权、Cookie、JWT 和 CSRF 材料。"""
        return _analyze_auth_material(request_headers, response_headers, set_cookie_headers, body)

    # ---- fofa_lookup（只读资产测绘，确认归属 + 探攻击面）----
    def fofa_lookup(self, query: str = "", size: int = 10) -> dict[str, Any]:
        """对 FOFA 发一次只读查询，返回命中规模和样本（host/ip/port/title/domain/org）。

        用途：① 确认目标归属（org/备案/证书）填准 owner；② 看同 IP/同域还开了
        哪些端口/服务，发现隐藏攻击面。只读查询，不对目标产生任何请求。
        """
        if self.fofa_router is None:
            return {"ok": False, "error": "未配置 FOFA key，无法查询。",
                    "guidance": "跳过测绘，直接用 http_request 验证归属（看证书/页脚/备案）。"}
        q = (query or "").strip()
        if not q:
            return {"ok": False, "kind": "arg_error", "error": "query 不能为空",
                    "guidance": '传 FOFA 语法，如 ip="1.2.3.4" 或 host="example.com"。'}
        safe_size = max(1, min(int(size or 10), _FOFA_LOOKUP_MAX_SIZE))
        import base64 as _b64
        params = {
            "qbase64": _b64.b64encode(q.encode("utf-8")).decode("ascii"),
            "fields": "host,ip,port,title,domain,org,protocol",
            "page": "1", "size": str(safe_size), "full": "false",
        }

        def operation(key: str, base_url: str):
            result = fofa_endpoints.request_sync(
                key,
                base_url,
                purpose="search",
                params=params,
                timeout=25,
                allow_extra_hosts=_FOFA_ALLOWED_HOSTS,
            )
            if result.category == "network":
                message = str(result.error or "网络错误")
                raise FofaError(message, kind="transient")
            response = result.response
            if response is None:
                raise FofaError("FOFA 返回为空", kind="transient")
            category = str(result.category or "")
            if category in {"auth", "rate_limit", "daily_limit"}:
                text = extract_fofa_response_failure(response)
                kind, code, retry_after = classify_fofa_failure(
                    text, status=getattr(response, "status_code", None)
                )
                raise FofaError(text, kind=kind, code=code, retry_after=retry_after)
            if not 200 <= int(getattr(response, "status_code", 0) or 0) < 300:
                text = extract_fofa_response_failure(response)
                kind, code, retry_after = classify_fofa_failure(
                    text, status=getattr(response, "status_code", None)
                )
                raise FofaError(text, kind=kind, code=code, retry_after=retry_after)
            try:
                data = response.json()
            except Exception:
                raise FofaError("FOFA 返回非 JSON", kind="transient") from None
            if not isinstance(data, dict):
                raise FofaError("FOFA 返回格式异常", kind="transient")
            if data.get("error"):
                message, _display = extract_fofa_error(data, "FOFA 错误")
                kind, code, retry_after = classify_fofa_failure(message)
                raise FofaError(message, kind=kind, code=code, retry_after=retry_after)
            return data

        try:
            data = self.fofa_router.execute_sync(operation)
        except FofaPoolExhaustedError as exc:
            retry_at = exc.next_retry_at.isoformat().replace("+00:00", "Z") if exc.next_retry_at else None
            return {
                "ok": False,
                "kind": "pool_exhausted",
                "error": "FOFA 凭据池暂不可用",
                **({"next_retry_at": retry_at} if retry_at else {}),
                "guidance": "FOFA 暂不可用，稍后重试。",
            }
        except FofaError as exc:
            return {
                "ok": False,
                "kind": str(exc.kind or "transient"),
                "error": "FOFA 请求失败",
                **({"next_retry_after": exc.retry_after} if exc.retry_after is not None else {}),
                "guidance": "FOFA 不可用，改用 http_request 直接验证归属。",
            }
        except Exception:
            return {"ok": False, "kind": "transient", "error": "FOFA 调用失败",
                    "guidance": "FOFA 不可用，改用 http_request 直接验证归属。"}
        def _cell(row: list, i: int) -> str:
            # FOFA 字段可能为 null/非字符串，统一转成安全字符串，杜绝 None[:n] 崩溃。
            return str(row[i]) if len(row) > i and row[i] is not None else ""

        sample = []
        for row in (data.get("results") or [])[:safe_size]:
            if isinstance(row, list):
                sample.append({
                    "host": _cell(row, 0),
                    "ip": _cell(row, 1),
                    "port": _cell(row, 2),
                    "title": _cell(row, 3)[:120],
                    "domain": _cell(row, 4),
                    "org": _cell(row, 5),
                    "protocol": _cell(row, 6),
                })
        return {
            "ok": True,
            "query": q,
            "size": data.get("size", 0),
            "sample": sample,
            "guidance": "据此核实 owner 归属、发现同 IP/同域其它端口与服务；测绘只读，验证仍需 http_request 实证。",
        }

    @staticmethod
    def _read_limited_response(
        resp: httpx.Response,
        capture: Optional[_CaptureWriter] = None,
    ) -> tuple[str, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                if capture is not None:
                    capture.write(chunk)
                room = max(0, _HTTP_MAX_BYTES - total)
                if room:
                    kept = chunk[:room]
                    chunks.append(kept)
                    total += len(kept)
                if len(chunk) > room:
                    truncated = True
                    if capture is None:
                        break
        finally:
            resp.close()
        body = b"".join(chunks).decode(resp.encoding or "utf-8", "replace")
        if truncated:
            body += f"\n\n...[响应超过 {_HTTP_MAX_BYTES} 字节，已截断以保护内存]..."
        return body, truncated

    @staticmethod
    def _raw_request(req: httpx.Request, data: Optional[str], json_body: Any) -> str:
        return ToolExecutor._raw_request_bytes(req).decode("utf-8", "replace")

    @staticmethod
    def _raw_request_bytes(req: httpx.Request) -> bytes:
        start = b" ".join(
            (
                req.method.encode("ascii", "replace"),
                req.url.raw_path,
                b"HTTP/1.1",
            )
        )
        header_lines = [name + b": " + value for name, value in req.headers.raw]
        return b"\r\n".join([start, *header_lines]) + b"\r\n\r\n" + req.content

    @staticmethod
    def _raw_response_head(resp: httpx.Response) -> bytes:
        version = (resp.http_version or "HTTP/1.1").encode("ascii", "replace")
        reason = httpx.codes.get_reason_phrase(resp.status_code).encode("ascii", "replace")
        start = b" ".join((version, str(resp.status_code).encode("ascii"), reason))
        header_lines = [name + b": " + value for name, value in resp.headers.raw]
        return b"\r\n".join([start, *header_lines]) + b"\r\n\r\n"

    # ---- analyze_javascript（条件开放给 worker）----
    def analyze_javascript(
        self,
        url: str = "",
        text: str = "",
        max_depth: int = 2,
        max_assets: int = 80,
    ) -> dict[str, Any]:
        """分析入口 URL 或 JS 文本，返回高价值链路和统一接口清单。"""
        try:
            safe_depth = max(0, min(int(max_depth or 2), 4))
            safe_assets = max(1, min(int(max_assets or 80), 150))
            if url:
                result = analyze_js_url(url, max_depth=safe_depth, max_assets=safe_assets)
            elif text:
                result = analyze_js_text(text[:800_000], base_url=self.target, source="worker_text")
            else:
                return {
                    "ok": False,
                    "kind": "arg_error",
                    "error": "analyze_javascript 需要 url 或 text",
                    "guidance": "传入口 URL 或已抓到的 JS 文本；不要空调用。",
                }
            return {
                "ok": True,
                "summary": result.get("summary", {}),
                "chains": result.get("chains", [])[:8],
                "endpoint_inventory": result.get("endpoint_inventory", [])[:80],
                "assets": result.get("assets", [])[:30],
                "fetch_errors": result.get("fetch_errors", [])[:20],
                "guidance": (
                    "这些只是 JS 静态线索。优先按 chains 里的 probes 用 http_request/run_shell 做真实验证；"
                    "没有实证危害不要 submit_finding。"
                ),
            }
        except Exception as e:
            return {"ok": False, "error": f"JS 分析异常: {type(e).__name__}: {e}"}

    # ---- suggest_waf_bypass（纯本地，不发网络）----
    def suggest_waf_bypass(
        self,
        payload: str,
        status_code: int | None = None,
        response_headers: Optional[dict[str, Any]] = None,
        response_body: str = "",
        context: str = "generic",
    ) -> dict[str, Any]:
        try:
            return _suggest_waf_bypass(
                payload=payload,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                context=context,
            )
        except Exception as e:
            return {"ok": False, "error": f"WAF 建议生成异常: {type(e).__name__}: {e}"}
