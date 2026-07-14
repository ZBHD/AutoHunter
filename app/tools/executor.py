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
import threading
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Optional

import httpx

from app.config import worker_config
from app.tools.auth_analyzer import analyze_auth_material as _analyze_auth_material
from app.tools.decoder import decode_transform as _decode_transform
from app.tools.evidence import (
    analyze_api_schema as _analyze_api_schema,
    compare_http_responses as _compare_http_responses,
)
from app.tools.guard import CommandBlocked, check_command
from app.tools.http_surface import extract_http_surface as _extract_http_surface
from app.tools.js_analyzer import analyze_javascript as analyze_js_text
from app.tools.js_analyzer import analyze_url as analyze_js_url
from app.tools.src_toolkit import (
    ENTERPRISE_BLOCKED_SRC_TOOLS,
    SRC_TOOL_NAMES,
    SrcToolError,
    build_src_plan,
)
from app.tools.waf_advisor import suggest_waf_bypass as _suggest_waf_bypass

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
        command: str | list[str],
        *,
        timeout: int,
        shell: bool,
        capture_tool: str,
        display_command: str,
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
        if self._session_cookies and not any(key.lower() == "cookie" for key in merged):
            merged["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in self._session_cookies.items()
            )
        if merged:
            values["headers"] = merged
        return values

    def run_src_tool(self, tool: str, args: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Execute one structured SRC tool plan without invoking a command shell."""
        name = str(tool or "").strip()
        if name not in SRC_TOOL_NAMES:
            return {"ok": False, "kind": "arg_error", "error": f"未知 SRC 工具: {name}"}
        if self.enterprise and name in ENTERPRISE_BLOCKED_SRC_TOOLS:
            return {
                "ok": False,
                "blocked": True,
                "kind": "enterprise_policy",
                "tool": name,
                "error": "企业 SRC 模式禁止使用 Nuclei 类漏洞扫描工具；请改用已知入口的最小请求验证。",
            }
        try:
            plan = build_src_plan(
                name,
                self._src_args_with_session(name, dict(args or {})),
                scope_target=self.scope_target,
            )
        except SrcToolError as exc:
            return {
                "ok": False,
                "blocked": bool(exc.blocked),
                "kind": "arg_error",
                "tool": name,
                "error": str(exc),
            }

        for index, token in enumerate(plan.argv[:-1]):
            if token == "-w":
                wordlist = Path(plan.argv[index + 1])
                if not wordlist.is_file():
                    return {
                        "ok": False,
                        "kind": "missing_resource",
                        "tool": name,
                        "error": f"内置字典不存在: {wordlist}",
                    }

        binary = shutil.which(plan.binary)
        if not binary:
            return {
                "ok": False,
                "missing_tool": True,
                "kind": "missing_tool",
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
                "blocked": True,
                "kind": "command_policy",
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
        })
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
    ) -> dict[str, Any]:
        # LLM 可能把 headers 传成非 dict 形态（list["K: V"] / "K: V\nK2: V2" / None），
        # 直接喂给 dict()/httpx 会抛 "dictionary update sequence element..." 崩掉整个 agent。
        # 这里统一规范化成 dict，容错所有 agent 的 http_request 调用。
        headers = _normalize_headers(headers)
        # 会话保持：把已维持的 cookie/header 合并进本次请求（用户传的同名键优先）。
        merged_headers, session_applied = self._apply_session(headers)

        capture = self._new_capture("http_request")
        req: httpx.Request | None = None
        resp: httpx.Response | None = None
        try:
            with httpx.Client(verify=False, follow_redirects=follow_redirects, timeout=timeout) as client:
                req = client.build_request(
                    method.upper(), url, headers=merged_headers, content=data, json=json_body
                )
                if capture is not None:
                    capture.write_channel("request", self._raw_request_bytes(req))
                resp = client.send(req, stream=True)
                response_capture = capture.open_channel("response") if capture is not None else None
                if response_capture is not None:
                    response_capture.write(self._raw_response_head(resp))
                body, truncated = self._read_limited_response(resp, response_capture)
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

        # 自动吸收响应 Set-Cookie，后续请求自动续上登录态（全模式）。
        session_updated = self._absorb_set_cookie(resp)

        # 原始请求行（取证/格式参考）。响应报文不再单独回传：状态码 + response_headers +
        # body 已结构化提供，raw_response 会与它们 100% 重复，是当轮就纯冗余的双份大文本。
        # 模型 submit_finding 时按 prompt 规范从 body 自行裁剪取证，不依赖这份 raw_response。
        raw_req = self._raw_request(req, data, json_body)

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
    def _apply_session(self, headers: Optional[dict[str, str]]) -> tuple[dict[str, str], list[str]]:
        """把维持的 session cookie/header 合并进请求头。返回 (合并后headers, 应用了哪些)。

        合并规则：用户本次显式传入的头优先（不被 session 覆盖），保证可手动覆写。
        会话为空时原样返回、零开销；全模式启用。
        """
        if not self._session_cookies and not self._session_headers:
            return (dict(headers) if headers else {}), []
        try:
            merged: dict[str, str] = {}
            applied: list[str] = []
            for k, v in self._session_headers.items():
                merged[k] = v
            if self._session_cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
                merged["Cookie"] = cookie_str
                applied.append(f"Cookie({len(self._session_cookies)})")
            if self._session_headers:
                applied.append(f"headers({len(self._session_headers)})")
            # 用户本次传入的头覆盖 session（显式优先）。
            if headers:
                for k, v in headers.items():
                    merged[k] = v
            return merged, applied
        except Exception:
            return (dict(headers) if headers else {}), []

    def _absorb_set_cookie(self, resp: httpx.Response) -> list[str]:
        """从响应吸收 Set-Cookie 进 session jar（带数量上限防爆内存）。"""
        try:
            updated: list[str] = []
            for name, value in resp.cookies.items():
                if name in self._session_cookies:
                    self._session_cookies[name] = value
                    updated.append(name)
                elif len(self._session_cookies) < _SESSION_MAX_COOKIES:
                    self._session_cookies[name] = value
                    updated.append(name)
            return updated
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
                "active_cookies": sorted(self._session_cookies.keys()),
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
        if not self.fofa_key:
            return {"ok": False, "error": "未配置 FOFA key，无法查询。",
                    "guidance": "跳过测绘，直接用 http_request 验证归属（看证书/页脚/备案）。"}
        q = (query or "").strip()
        if not q:
            return {"ok": False, "kind": "arg_error", "error": "query 不能为空",
                    "guidance": '传 FOFA 语法，如 ip="1.2.3.4" 或 host="example.com"。'}
        safe_size = max(1, min(int(size or 10), _FOFA_LOOKUP_MAX_SIZE))
        import base64 as _b64
        params = {
            "key": self.fofa_key,
            "qbase64": _b64.b64encode(q.encode("utf-8")).decode("ascii"),
            "fields": "host,ip,port,title,domain,org,protocol",
            "page": "1", "size": str(safe_size), "full": "false",
        }
        try:
            with httpx.Client(timeout=25) as client:
                resp = client.get(f"{self.fofa_base_url}/api/v1/search/all", params=params)
                data = resp.json()
        except Exception as e:
            return {"ok": False, "error": f"FOFA 调用失败: {type(e).__name__}: {e}",
                    "guidance": "FOFA 不可用，改用 http_request 直接验证归属。"}
        if not isinstance(data, dict):
            return {"ok": False, "error": "FOFA 返回格式异常"}
        if data.get("error"):
            return {"ok": False, "error": f"FOFA 错误: {data.get('errmsg', '')}"[:300]}
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
