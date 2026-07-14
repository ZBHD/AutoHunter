"""扩大危害 Hunter Agent：审核 accepted 一个洞后，顺着已确认的入口再往下打一层。

流程：
  收到一个已采纳的 Finding → 复用其入口/凭证 → 尝试越权写/遍历/改密/接管/RCE
  → 只有【危害等级实际提升】或【影响面数量级变化】才 submit_escalation，否则 abandon。

同步执行（内部 LLM/工具均阻塞），由 orchestrator 在线程池里调用。
任何异常都降级返回，不阻断主循环。轮数按原洞等级分配，只在显著升级时产出。
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Callable, Optional

from app.agents.depth_policy import depth_policy_for
from app.agents.history import bounded_tool_content, compact_messages
from app.agents.prompts import escalate_system_prompt, is_enterprise_src
from app.llm.router import LLMRouter
from app.tools.executor import ToolExecutor
from app.tools.schemas import escalate_tool_schemas
from app.tools.src_toolkit import SRC_TOOL_NAMES

# 显式环境变量保持全局覆盖能力；未设置时由等级策略给出预算。
_MAX_ROUNDS_OVERRIDE = int(os.environ.get("ESCALATE_MAX_ROUNDS", "0"))


class EscalateResult:
    def __init__(self, data: dict):
        self.data = data

    def model_dump(self, mode: str = "json") -> dict:
        return self.data


class EscalateHunter:
    def __init__(
        self,
        finding: dict,
        llm: LLMRouter,
        on_event: Optional[Callable[[str, dict], None]] = None,
        src_type: str = "edusrc",
        cancel_event: Optional[threading.Event] = None,
        max_rounds: int | None = None,
    ):
        self.finding = finding
        self.llm = llm
        self.cancel_event = cancel_event or threading.Event()
        self.src_type = src_type
        self._enterprise = is_enterprise_src(src_type)
        target_url = str(finding.get("target_url") or "")
        self.executor = ToolExecutor(
            f"escalate_{target_url or 'x'}",
            cancel_event=self.cancel_event,
            enterprise=self._enterprise,
            scope_target=target_url,
        )
        self.on_event = on_event or (lambda kind, data: None)
        self._result: Optional[dict] = None
        self._tools = escalate_tool_schemas(enterprise=self._enterprise)
        self.depth_policy = depth_policy_for(finding.get("severity"))
        self.max_rounds = max(1, int(max_rounds)) if max_rounds and max_rounds > 0 else (
            _MAX_ROUNDS_OVERRIDE if _MAX_ROUNDS_OVERRIDE > 0
            else self.depth_policy.escalation_rounds
        )

    def _emit(self, kind: str, **data: Any) -> None:
        self.on_event(kind, data)

    def _brief(self) -> str:
        f = self.finding
        unit_label = "企业/系统归属" if is_enterprise_src(self.src_type) else "归属"
        return (
            f"# 已确认存在的漏洞（你的深挖起点）\n"
            f"- 标题：{f.get('title','')}\n"
            f"- 漏洞类型：{f.get('vuln_type','')}\n"
            f"- 当前等级：{f.get('severity','')}\n"
            f"- 目标 URL：{f.get('target_url','')}\n"
            f"- {unit_label}：{f.get('owner','')}\n"
            f"- 描述：{(f.get('description') or '')[:800]}\n"
            f"- 攻击链：{json.dumps(f.get('kill_chain') or [], ensure_ascii=False)[:600]}\n"
            f"- PoC：{(f.get('poc') or '')[:600]}\n"
            f"- 原始请求(片段)：{(f.get('raw_request') or '')[:600]}\n"
            f"- 原始响应(片段)：{(f.get('raw_response') or '')[:900]}\n\n"
            f"# 当前等级深挖策略\n"
            f"- 目标：{self.depth_policy.objective}\n"
            f"- 证据要求：{'；'.join(self.depth_policy.evidence_requirements)}\n"
            f"- 本轮预算：{self.max_rounds} 轮\n\n"
            f"请在这个已确认据点上继续往下打，把危害做大。"
            f"打出任何原洞没证明、而你新证明出来的实锤危害（等级提升 / 影响面数量级 / 或在原洞基础上"
            f"实际拿到敏感数据·写操作·账号接管等新实质危害）就 submit_escalation；只有纯原地打转、"
            f"和原洞完全等价时才 abandon_escalation。"
        )

    def run(self) -> EscalateResult:
        self._emit("escalate_start", title=self.finding.get("title", ""))
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": escalate_system_prompt(self.src_type)},
            {"role": "user", "content": self._brief()},
        ]
        rounds = 0
        while rounds < self.max_rounds:
            if self.cancel_event.is_set():
                self.executor.cancel_running()
                return EscalateResult({"error": "扩大危害深挖已被取消"})
            rounds += 1
            try:
                send_messages = compact_messages(messages, rounds)
                msg = self.llm.chat(send_messages, tools=self._tools, tool_choice="auto")
            except Exception as e:
                self._emit("escalate_error", error=str(e))
                return EscalateResult({"error": f"LLM 调用失败: {e}"})

            tool_calls = getattr(msg, "tool_calls", None)
            messages.append(msg.as_history_message())

            if not tool_calls:
                messages.append({"role": "user", "content": "请继续深挖，或调用 submit_escalation / abandon_escalation 收尾。"})
                continue

            for tc in tool_calls:
                if self.cancel_event.is_set():
                    self.executor.cancel_running()
                    return EscalateResult({"error": "扩大危害深挖已被取消"})
                try:
                    args = json.loads(tc.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = self._dispatch(tc.name, args)
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": bounded_tool_content(result, tc.name),
                                 "_round": rounds, "_tool": tc.name})

            if self._result is not None:
                break

        if self._result is not None:
            return EscalateResult(self._result)
        # 到达轮数上限仍无结论：视作未能升级，安静放弃。
        return EscalateResult({"escalated": False, "reason": f"未在 {self.max_rounds} 轮内实现显著升级"})

    def _dispatch(self, name: str, args: dict) -> dict:
        if self.cancel_event.is_set():
            return {"ok": False, "cancelled": True, "error": "扩大危害深挖已被取消"}
        if name == "http_request":
            url = args.get("url")
            if not url:
                return {"ok": False, "error": "http_request 缺少 url"}
            self._emit("escalate_http", url=url)
            return self.executor.http_request(
                url=url, method=args.get("method", "GET"),
                headers=args.get("headers"), data=args.get("data"),
                json_body=args.get("json_body"), follow_redirects=args.get("follow_redirects", False),
            )
        if name == "run_shell":
            command = args.get("command")
            if not command:
                return {"ok": False, "error": "run_shell 缺少 command"}
            self._emit("escalate_shell", command=str(args.get("command", ""))[:160])
            return self.executor.run_shell(command, timeout=args.get("timeout"))
        if name in SRC_TOOL_NAMES:
            self._emit("escalate_src_cli", tool=name)
            return self.executor.run_src_tool(name, args)
        if name == "compare_http_responses":
            baseline = args.get("baseline")
            candidate = args.get("candidate")
            if not isinstance(baseline, dict) or not isinstance(candidate, dict):
                return {"ok": False, "error": "compare_http_responses 缺少 baseline/candidate 响应对象"}
            self._emit("escalate_compare")
            return self.executor.compare_http_responses(
                baseline=baseline,
                candidate=candidate,
                ignore_json_paths=args.get("ignore_json_paths"),
            )
        if name == "analyze_api_schema":
            document = args.get("document") or ""
            url = args.get("url") or ""
            if (not isinstance(document, str) or not document.strip()) and not url:
                return {"ok": False, "error": "analyze_api_schema 缺少 document/url"}
            self._emit("escalate_api_schema", document_len=len(document))
            return self.executor.analyze_api_schema(
                document=document,
                url=url,
                base_url=args.get("base_url", ""),
                focus=args.get("focus"),
            )
        if name == "extract_http_surface":
            body = args.get("body") or ""
            url = args.get("url") or ""
            if (not isinstance(body, str) or not body.strip()) and not url:
                return {"ok": False, "error": "extract_http_surface 缺少 body/url"}
            self._emit("escalate_http_surface", body_len=len(body))
            return self.executor.extract_http_surface(
                body=body,
                url=url,
                base_url=args.get("base_url", ""),
                response_headers=args.get("response_headers"),
            )
        if name == "analyze_auth_material":
            request_headers = args.get("request_headers")
            response_headers = args.get("response_headers")
            body = args.get("body") or ""
            set_cookie_headers = args.get("set_cookie_headers")
            if not request_headers and not response_headers and not set_cookie_headers and not body:
                return {"ok": False, "error": "analyze_auth_material 缺少可分析材料"}
            self._emit("escalate_auth_analysis")
            return self.executor.analyze_auth_material(
                request_headers=request_headers,
                response_headers=response_headers,
                set_cookie_headers=set_cookie_headers,
                body=body,
            )
        if name == "session_set":
            self._emit("escalate_session",
                       has_cookies=bool(args.get("cookies")), has_headers=bool(args.get("headers")))
            return self.executor.session_set(
                cookies=args.get("cookies"), headers=args.get("headers"),
                clear=bool(args.get("clear", False)),
            )
        if name == "submit_escalation":
            self._result = {
                "escalated": True,
                "vuln_type": args.get("vuln_type", ""),
                "title": args.get("title", ""),
                "severity": args.get("severity", ""),
                "description": args.get("description", ""),
                "kill_chain": args.get("kill_chain", []) if isinstance(args.get("kill_chain"), list) else [],
                "poc": args.get("poc", ""),
                "raw_request": args.get("raw_request", ""),
                "raw_response": args.get("raw_response", ""),
                "affected_scope": args.get("affected_scope", ""),
                "impact_count": int(args.get("impact_count", 0) or 0),
            }
            self._emit("escalate_done", title=self._result["title"], severity=self._result["severity"])
            return {"ok": True, "message": "已记录升级结论。"}
        if name == "abandon_escalation":
            self._result = {"escalated": False, "reason": args.get("reason", "")}
            self._emit("escalate_abandon", reason=str(args.get("reason", ""))[:200])
            return {"ok": True, "message": "已放弃本次升级。"}
        return {"ok": False, "error": f"未知工具: {name}"}
