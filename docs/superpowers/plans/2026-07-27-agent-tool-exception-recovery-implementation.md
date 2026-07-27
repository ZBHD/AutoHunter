# Agent 工具异常恢复 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `EscalateHunter` 和 `KillsweepHunter` 在工具执行异常时生成完整、脱敏、有限收敛的 tool response，而不是中断整个 Agent。

**Architecture:** 新增无业务依赖的 `app/agents/tool_dispatch.py`，统一捕获、分类、脱敏并返回工具异常。两个 Agent 只负责维护连续失败计数和收敛策略，既不修改各自 `_dispatch()` 业务逻辑，也不改变取消语义。

**Tech Stack:** Python 3.11+、dataclasses、pytest、现有 LLM history/tool-call 协议。

---

### Task 1: 工具异常包装器

**Files:**
- Create: `app/agents/tool_dispatch.py`
- Create: `tests/test_agent_tool_dispatch.py`

- [ ] **Step 1: 写包装器失败测试**

在 `tests/test_agent_tool_dispatch.py` 增加：

```python
from app.agents.tool_dispatch import dispatch_tool_safely


def test_dispatch_tool_safely_returns_success_unchanged() -> None:
    events = []
    outcome = dispatch_tool_safely(
        lambda name, args: {"ok": True, "name": name, "value": args["value"]},
        "lookup",
        {"value": 7},
        emit=lambda kind, **payload: events.append((kind, payload)),
    )
    assert outcome.failed is False
    assert outcome.result == {"ok": True, "name": "lookup", "value": 7}
    assert events == []


def test_dispatch_tool_safely_masks_secret_and_emits_failure() -> None:
    events = []

    def fail(_name, _args):
        raise RuntimeError("api_key=sk-super-secret-value password=hunter2")

    outcome = dispatch_tool_safely(
        fail,
        "lookup",
        {},
        emit=lambda kind, **payload: events.append((kind, payload)),
    )
    serialized = str(outcome.result)
    assert outcome.failed is True
    assert outcome.error_kind == "tool_exception"
    assert "sk-super-secret-value" not in serialized
    assert "hunter2" not in serialized
    assert outcome.result["error"]["kind"] == "tool_exception"
    assert events[0][0] == "tool_exception"


def test_dispatch_tool_safely_truncates_long_error() -> None:
    def fail(_name, _args):
        raise RuntimeError("x" * 2000)

    outcome = dispatch_tool_safely(fail, "lookup", {}, emit=lambda *_args, **_kwargs: None)
    assert len(outcome.result["error"]["message"]) <= 400
```

- [ ] **Step 2: 运行测试确认失败**

Run: `python -m pytest -q tests/test_agent_tool_dispatch.py`

Expected: FAIL，因为 `app.agents.tool_dispatch` 尚不存在。

- [ ] **Step 3: 实现最小包装器**

新增 `app/agents/tool_dispatch.py`，实现：

```python
from __future__ import annotations

from dataclasses import dataclass
import logging
import re
from typing import Any, Callable

logger = logging.getLogger(__name__)

_SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9_-]{8,}"
    r"|Bearer\s+[A-Za-z0-9._-]{12,}"
    r"|(?i:api[_-]?key|token|secret|password|passwd|pwd|fofa[_-]?key)"
    r"\s*[=:]\s*[^\s'\"&]{3,})"
)


@dataclass(frozen=True)
class ToolDispatchOutcome:
    result: dict[str, Any]
    failed: bool
    retryable: bool = False
    error_kind: str = ""


def _safe_error_message(exc: Exception, limit: int = 400) -> str:
    text = _SECRET_RE.sub("<masked>", f"{type(exc).__name__}: {exc}")
    return text[:limit]


def dispatch_tool_safely(
    dispatch: Callable[[str, dict[str, Any]], dict[str, Any]],
    name: str,
    arguments: dict[str, Any],
    *,
    emit: Callable[..., None],
) -> ToolDispatchOutcome:
    try:
        result = dispatch(name, arguments)
        if not isinstance(result, dict):
            result = {"ok": True, "result": result}
        return ToolDispatchOutcome(result=result, failed=False)
    except Exception as exc:
        logger.exception("tool dispatch failed: %s", name)
        message = _safe_error_message(exc)
        emit("tool_exception", tool=name, error=message)
        result = {
            "ok": False,
            "error": {
                "kind": "tool_exception",
                "retryable": True,
                "message": message,
            },
        }
        return ToolDispatchOutcome(
            result=result,
            failed=True,
            retryable=True,
            error_kind="tool_exception",
        )
```

- [ ] **Step 4: 运行包装器测试**

Run: `python -m pytest -q tests/test_agent_tool_dispatch.py`

Expected: PASS。

- [ ] **Step 5: 提交包装器**

```powershell
git add app/agents/tool_dispatch.py tests/test_agent_tool_dispatch.py
git commit -m "修复：增加 Agent 工具异常安全包装器"
```

### Task 2: EscalateHunter 异常续跑与收敛

**Files:**
- Modify: `app/agents/escalate.py`
- Modify: `tests/test_agent_tool_dispatch.py`

- [ ] **Step 1: 写 EscalateHunter 循环失败测试**

增加 Fake LLM/ToolCall 测试，覆盖：第一轮工具异常后第二轮能够调用 `abandon_escalation` 收尾；发送给第二轮 LLM 的 history 含与失败 call ID 配对的 tool response；连续第三次异常出现纠偏 user 消息；第五次异常结构化结束。

核心断言：

```python
result = hunter.run().model_dump()
assert result["escalated"] is False
assert any(
    item.get("role") == "tool" and item.get("tool_call_id") == "call-failed"
    for item in llm.calls[1]
)
assert any("连续 3 次" in item.get("content", "") for item in llm.calls[3])
assert "连续 5 次工具执行异常" in exhausted["reason"]
```

- [ ] **Step 2: 运行定向测试确认失败**

Run: `python -m pytest -q tests/test_agent_tool_dispatch.py -k escalate`

Expected: FAIL，因为 `_dispatch()` 异常仍会冒泡。

- [ ] **Step 3: 接入包装器和计数器**

在 `EscalateHunter.run()` 初始化 `consecutive_tool_errors = 0`。每个 tool call 使用：

```python
outcome = dispatch_tool_safely(self._dispatch, tc.name, args, emit=self._emit)
result = outcome.result
if outcome.failed:
    consecutive_tool_errors += 1
else:
    consecutive_tool_errors = 0
messages.append({
    "role": "tool",
    "tool_call_id": tc.id,
    "content": bounded_tool_content(result, tc.name),
    "_round": rounds,
    "_tool": tc.name,
})
```

处理完整一轮的所有 tool call 后：

```python
if consecutive_tool_errors >= 5:
    return EscalateResult({
        "escalated": False,
        "reason": "连续 5 次工具执行异常，已停止扩大危害深挖",
        "failure_kind": "tool_exception",
    })
if consecutive_tool_errors == 3:
    messages.append({
        "role": "user",
        "content": "工具已连续 3 次执行异常，请切换工具、缩小参数，或调用 abandon_escalation 收尾。",
    })
```

取消检查保持在包装器调用之前。

- [ ] **Step 4: 运行 EscalateHunter 定向测试**

Run: `python -m pytest -q tests/test_agent_tool_dispatch.py -k escalate`

Expected: PASS。

- [ ] **Step 5: 提交 EscalateHunter 改造**

```powershell
git add app/agents/escalate.py tests/test_agent_tool_dispatch.py
git commit -m "修复：扩大危害 Agent 工具异常后继续收敛"
```

### Task 3: KillsweepHunter 异常续跑与收敛

**Files:**
- Modify: `app/agents/killsweep.py`
- Modify: `tests/test_agent_tool_dispatch.py`

- [ ] **Step 1: 写 KillsweepHunter 多工具测试**

增加测试：同一轮两个 call，第一个 `_dispatch()` 抛异常，第二个成功；下一轮 LLM history 必须同时包含两个 tool response。再覆盖连续第五次异常返回 `failure_kind=tool_exception`，且不得出现 `is_killsweep=true`。

核心断言：

```python
tool_messages = [item for item in llm.calls[1] if item.get("role") == "tool"]
assert [item["tool_call_id"] for item in tool_messages] == ["call-1", "call-2"]
assert result["failure_kind"] == "tool_exception"
assert result.get("is_killsweep") is not True
```

- [ ] **Step 2: 运行定向测试确认失败**

Run: `python -m pytest -q tests/test_agent_tool_dispatch.py -k killsweep`

Expected: FAIL，因为第一项异常会中断循环。

- [ ] **Step 3: 接入包装器和计数器**

按 Task 2 相同方式包装 `_dispatch()`。Killsweep 第三次提示使用 `submit_killsweep`，第五次返回：

```python
KillsweepResult({
    "error": "连续 5 次工具执行异常，已停止通杀分析",
    "failure_kind": "tool_exception",
    "is_killsweep": False,
})
```

所有工具结果使用 `bounded_tool_content(result, tc.name)`，与 EscalateHunter 保持一致。

- [ ] **Step 4: 运行 KillsweepHunter 定向测试**

Run: `python -m pytest -q tests/test_agent_tool_dispatch.py -k killsweep`

Expected: PASS。

- [ ] **Step 5: 提交 KillsweepHunter 改造**

```powershell
git add app/agents/killsweep.py tests/test_agent_tool_dispatch.py
git commit -m "修复：通杀 Agent 工具异常后保持调用配对"
```

### Task 4: 可靠性回归

**Files:**
- Verify only

- [ ] **Step 1: 运行 Agent 与协议相关测试**

Run:

```powershell
python -m pytest -q tests/test_agent_tool_dispatch.py tests/test_llm_protocols.py tests/test_deep_hunting_tools.py tests/test_escalation_service.py tests/test_killsweep_service.py
```

Expected: PASS。

- [ ] **Step 2: 运行后端全量测试**

Run: `python -m pytest -q`

Expected: 1093 个基线测试加新增测试全部通过。

- [ ] **Step 3: 检查工作区和提交历史**

Run:

```powershell
git diff --check
git status --short
git log -4 --oneline
```

Expected: 无未提交改动，最近提交均为本计划的中文提交。
