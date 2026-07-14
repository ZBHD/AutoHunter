# Backdoor Compromised Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `backdoor_compromised` as a first-class finding type with evidence-aware worker/reviewer guidance, canonical deduplication, targeted post-acceptance escalation, duplicate-upgrade protection, and a default frontend option.

**Architecture:** Keep the database and API shapes unchanged. Register one canonical type in dedup and the shared frontend catalog, append compact shared policy blocks at the prompt-composition boundary so every runtime profile stays consistent, and pass the selected task types into the collector prompt for deterministic gating. Accepted findings continue through the existing escalation queue; a source-evidence-aware significance check blocks repeated page evidence while allowing a newly proved root-cause finding.

**Tech Stack:** Python 3, pytest, FastAPI/Pydantic, SQLAlchemy orchestration helpers, Vue 3, Node test runner, Vite.

---

## Working Tree Guardrails

The current workspace already contains unrelated edits, including `app/orchestrator.py`. Before each task, inspect the path-specific diff. Never run `git add .`; stage only the files or hunks belonging to this feature. For `app/orchestrator.py`, keep the existing deepening-handoff diff intact and stage only the significance helper and call-site hunk.

### Task 1: Canonical Type and Deduplication

**Files:**
- Create: `tests/test_dedup.py`
- Modify: `app/dedup.py`

- [ ] **Step 1: Write failing alias and duplicate tests**

Create `tests/test_dedup.py`:

```python
from __future__ import annotations

import pytest

from app.dedup import is_duplicate, normalize_vuln_type, vuln_type_alias_set


BACKDOOR_ALIASES = (
    "backdoor_compromised",
    "backdoorcompromised",
    "疑似后门",
    "疑似被黑",
    "服务器被攻陷",
    "被攻陷",
    "被挂马",
    "挂马",
    "网页被篡改",
    "被篡改",
    "后门",
    "webshell",
    "compromised",
    "hacked",
    "defaced",
    "被黑",
    "植入后门",
    "web后门",
    "网页挂马",
    "暗链",
)


@pytest.mark.parametrize("raw", BACKDOOR_ALIASES)
def test_backdoor_aliases_normalize_to_canonical_type(raw: str) -> None:
    assert normalize_vuln_type(raw) == "backdoor_compromised"


def test_backdoor_alias_set_contains_database_spellings() -> None:
    aliases = vuln_type_alias_set("网页被篡改")

    assert "backdoor_compromised" in aliases
    assert "webshell" in aliases
    assert "暗链" in aliases


def test_backdoor_aliases_deduplicate_the_same_endpoint() -> None:
    candidate = {
        "vuln_type": "backdoor_compromised",
        "title": "Example University - 首页被篡改",
        "target_url": "https://example.test/index.php",
        "raw_request": "GET /index.php HTTP/1.1\r\nHost: example.test\r\n\r\n",
    }
    history = [{
        "vuln_type": "webshell",
        "title": "Example University - 首页发现后门",
        "target_url": "https://example.test/index.php",
        "raw_request": "GET /index.php HTTP/1.1\r\nHost: example.test\r\n\r\n",
    }]

    duplicate, matches = is_duplicate(candidate, history)

    assert duplicate is True
    assert "同系统同 endpoint 同漏洞类型" in matches[0]["reason"]
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
python -m pytest tests/test_dedup.py -q
```

Expected: failures show aliases normalize to `backdoorcompromised`, `webshell`, or their original spellings instead of `backdoor_compromised`.

- [ ] **Step 3: Register the canonical aliases**

Add this entry to `_VULN_TYPE_ALIASES` in `app/dedup.py` after `logic_flaw`:

```python
    "backdoor_compromised": (
        "backdoorcompromised", "疑似后门", "疑似被黑", "服务器被攻陷", "被攻陷",
        "被挂马", "挂马", "网页被篡改", "被篡改", "后门", "webshell", "compromised",
        "hacked", "defaced", "被黑", "植入后门", "web后门", "网页挂马", "暗链",
    ),
```

The `backdoorcompromised` alias is required because `normalize_vuln_type()` removes underscores before lookup.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run:

```powershell
python -m pytest tests/test_dedup.py -q
```

Expected: all tests in `tests/test_dedup.py` pass.

- [ ] **Step 5: Commit only the dedup change**

```powershell
git add -- app/dedup.py tests/test_dedup.py
git commit -m "Feat: normalize compromised server findings"
```

### Task 2: Shared Detection, Review, Collection, and Escalation Guidance

**Files:**
- Create: `tests/test_backdoor_prompt_policy.py`
- Modify: `app/agents/prompts.py`
- Modify: `app/agents/collector_llm.py`
- Modify: `app/agents/escalate.py`
- Modify: `app/schemas.py`
- Modify: `app/tools/schemas.py`

- [ ] **Step 1: Write failing prompt, brief, collector-gate, and schema tests**

Create `tests/test_backdoor_prompt_policy.py`:

```python
from __future__ import annotations

import pytest

from app.agents.depth_policy import depth_policy_for
from app.agents.escalate import EscalateHunter
from app.agents.prompts import (
    collector_query_prompt,
    escalate_system_prompt,
    reviewer_system_prompt,
    worker_system_prompt,
)
from app.schemas import Finding
from app.tools.schemas import ESCALATE_TOOL_SCHEMAS, TOOL_SCHEMAS


def _function_schema(schemas: list[dict], name: str) -> dict:
    return next(item["function"] for item in schemas if item["function"]["name"] == name)


@pytest.mark.parametrize(
    ("src_type", "version"),
    [
        ("edusrc", "current"),
        ("edusrc", "modern"),
        ("edusrc", "legacy"),
        ("enterprise", "current"),
    ],
)
def test_worker_profiles_share_backdoor_evidence_policy(src_type: str, version: str) -> None:
    prompt = worker_system_prompt(src_type, version)

    for marker in (
        "backdoor_compromised",
        "raw_request",
        "raw_response",
        "Cache-Control: no-cache",
        "redirect chain",
        "归属",
        "webshell",
        "可重复",
        "域名停放",
        "合法 SSO",
        "CDN/WAF",
        "历史缓存",
        "广告",
        "UGC",
        "iframe",
    ):
        assert marker in prompt


@pytest.mark.parametrize("src_type", ["edusrc", "enterprise"])
def test_reviewer_profiles_share_backdoor_decision_matrix(src_type: str) -> None:
    prompt = reviewer_system_prompt(src_type)

    for marker in (
        "backdoor_compromised",
        "当前复取",
        "响应来源",
        "高危 7~8",
        "严重 9~10",
        "初始入口",
        "accepted",
        "deepen",
        "ignored",
    ):
        assert marker in prompt
    assert "任何异常页面都 accepted" not in prompt


@pytest.mark.parametrize("src_type", ["edusrc", "enterprise"])
def test_collector_policy_is_gated_by_selected_type(src_type: str) -> None:
    backdoor_prompt = collector_query_prompt(src_type, ["backdoor_compromised"])
    ordinary_prompt = collector_query_prompt(src_type, ["idor"])

    assert "后门类型查询门槛" in backdoor_prompt
    assert "归属锚点" in backdoor_prompt
    assert "宽泛词" in backdoor_prompt
    assert "后门类型查询门槛" not in ordinary_prompt


@pytest.mark.parametrize("src_type", ["edusrc", "enterprise"])
def test_escalation_prompt_has_backdoor_root_cause_route(src_type: str) -> None:
    prompt = escalate_system_prompt(src_type)

    for marker in (
        "服务器被攻陷",
        "初始入口",
        "上传",
        "未授权管理面",
        "组件漏洞",
        "文件写入",
        "泄露凭证",
        "abandon_escalation",
    ):
        assert marker in prompt


def test_backdoor_escalation_brief_requests_new_root_cause_evidence() -> None:
    hunter = EscalateHunter.__new__(EscalateHunter)
    hunter.finding = {
        "severity": "高危",
        "title": "Example University - 首页被篡改",
        "vuln_type": "网页被篡改",
        "target_url": "https://example.test/",
        "raw_request": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "raw_response": "HTTP/1.1 200 OK\r\n\r\nCasino page",
    }
    hunter.src_type = "edusrc"
    hunter.depth_policy = depth_policy_for("高危")
    hunter.max_rounds = hunter.depth_policy.escalation_rounds

    brief = hunter._brief()

    assert "后门/被攻陷专用目标" in brief
    assert "初始入口" in brief
    assert "新的 raw_request 和 raw_response" in brief
    assert "真正对应的漏洞类型" in brief
    assert "abandon_escalation" in brief


def test_non_backdoor_escalation_brief_keeps_generic_route() -> None:
    hunter = EscalateHunter.__new__(EscalateHunter)
    hunter.finding = {
        "severity": "高危",
        "title": "Example IDOR",
        "vuln_type": "idor",
        "target_url": "https://example.test/api/records/1",
    }
    hunter.src_type = "edusrc"
    hunter.depth_policy = depth_policy_for("高危")
    hunter.max_rounds = hunter.depth_policy.escalation_rounds

    assert "后门/被攻陷专用目标" not in hunter._brief()


def test_schema_examples_document_canonical_backdoor_type() -> None:
    finding_description = Finding.model_fields["vuln_type"].description or ""
    duplicate_schema = _function_schema(TOOL_SCHEMAS, "check_duplicate_finding")
    submit_schema = _function_schema(TOOL_SCHEMAS, "submit_finding")
    escalation_schema = _function_schema(ESCALATE_TOOL_SCHEMAS, "submit_escalation")

    assert "backdoor_compromised" in finding_description
    assert "backdoor_compromised" in duplicate_schema["parameters"]["properties"]["vuln_type"]["description"]
    assert "backdoor_compromised" in submit_schema["parameters"]["properties"]["vuln_type"]["description"]
    assert "backdoor_compromised" in escalation_schema["parameters"]["properties"]["vuln_type"]["description"]
```

- [ ] **Step 2: Run the feature contract and verify RED**

Run:

```powershell
python -m pytest tests/test_backdoor_prompt_policy.py -q
```

Expected: collection succeeds, then tests fail because the shared policies, optional collector argument, type-specific brief, and schema examples are absent.

- [ ] **Step 3: Add shared worker and reviewer policy blocks**

Import the canonical normalizer near the top of `app/agents/prompts.py`:

```python
from app.dedup import normalize_vuln_type
```

Add these constants immediately before `_WORKER_STRUCTURED_TOOL_GUIDE`:

```python
_BACKDOOR_WORKER_POLICY = """

# 疑似后门/服务器被攻陷（backdoor_compromised）
发现目标自有服务返回与正常业务冲突的赌博/色情/博彩页面、SEO 暗链、deface 或 webshell 时，不要按纯静态页直接 no_vuln。先保留未跟随跳转的 Host、状态码、Location、响应头和正文；需要跟随时同时记录 redirect chain 与 final URL。再加随机 query 或 `Cache-Control: no-cache` 复取，提供证书/备案/官网链接/同站品牌或业务路径等归属依据，并用正常页面或同站身份做对照。
deface/暗链必须证明恶意内容由目标 origin 当前返回。webshell 必须有当前 URL 可重复、无害的服务端执行证据；只看到 shell.php 文件名、登录页、源码字符串或目录条目不够。域名停放、合法 SSO/活动跳转、白标 SaaS、第三方托管、CDN/WAF 错误页、历史缓存、广告、UGC 和 iframe 不按服务器被攻陷提交。
证据闭环后先 check_duplicate_finding，再以 vuln_type=backdoor_compromised 提交；raw_request/raw_response 必须来自同次真实请求，描述中区分已证事实、推测和未知初始入口。当前性、归属或响应来源缺一项但可具体补齐时，在 deepen_lead 写明复取、跳转链或对照动作。
"""

_BACKDOOR_REVIEWER_POLICY = """

# 疑似后门/服务器被攻陷审核（backdoor_compromised）
完整性事件不要求先证明初始入口，但必须核对目标归属、当前复取和响应来源。归属明确、无缓存复取仍由目标 origin 返回篡改/SEO 暗链且有正常内容对照 -> accepted，高危 7~8；有可重复的服务端命令/脚本执行证据 -> accepted，严重 9~10。当前性、归属或来源对照缺一项且有明确补证动作 -> deepen，并写清下一次复取、跳转链或对照要求。
域名停放/出售页、合法 SSO/活动跳转、白标 SaaS/第三方托管、CDN/WAF 错误页、历史缓存/历史 FOFA/Wayback、单个关键词、广告、UGC、iframe -> ignored。只有 shell.php 等文件名而无执行证据时不能认定 webshell；有具体可验证动作才 deepen，否则 ignored。异常页面必须经过上述证据矩阵，不能无条件收录。
"""
```

Update the composition functions to append the policies once:

```python
def worker_system_prompt(src_type: str | bool | None, version: str | None = None) -> str:
    if is_enterprise_src(src_type):
        base = ENTERPRISE_WORKER_SYSTEM_PROMPT_COMPACT
    else:
        v = normalize_worker_prompt_version(version)
        if v == "legacy":
            base = WORKER_SYSTEM_PROMPT_LEGACY
        elif v == "modern":
            base = WORKER_SYSTEM_PROMPT
        else:
            base = WORKER_SYSTEM_PROMPT_COMPACT
    return base + _BACKDOOR_WORKER_POLICY + _WORKER_STRUCTURED_TOOL_GUIDE


def reviewer_system_prompt(src_type: str | bool | None, src_rules: str | None = None) -> str:
    base = ENTERPRISE_REVIEWER_SYSTEM_PROMPT if is_enterprise_src(src_type) else REVIEWER_SYSTEM_PROMPT_COMPACT
    return compose_reviewer_policy(base + _BACKDOOR_REVIEWER_POLICY, src_rules)
```

- [ ] **Step 4: Gate collector guidance by the selected task type**

Add the collector block beside the shared policies in `app/agents/prompts.py`:

```python
_BACKDOOR_COLLECTOR_POLICY = """

# 后门类型查询门槛
仅因本任务类型包含 backdoor_compromised 才应用本段。查询必须同时带明确的系统、产品或归属锚点；不得只用博彩、色情、暗链、被黑、异常、Error 等宽泛词圈资产。FOFA 命中只用于找候选，不能代替 Worker 对当前响应、归属和 origin 来源的取证。
"""
```

Replace `collector_query_prompt()` with:

```python
def collector_query_prompt(
    src_type: str | bool | None,
    vuln_types: list[str] | None = None,
) -> str:
    base = (
        ENTERPRISE_COLLECTOR_QUERY_PROMPT_COMPACT
        if is_enterprise_src(src_type)
        else COLLECTOR_QUERY_PROMPT_COMPACT
    )
    selected = {normalize_vuln_type(value) for value in (vuln_types or [])}
    if "backdoor_compromised" in selected:
        return base + _BACKDOOR_COLLECTOR_POLICY
    return base
```

Update the system prompt call in `app/agents/collector_llm.py`:

```python
    msg = llm.chat(
        [{"role": "system", "content": collector_query_prompt(src_type, vuln_types)},
         {"role": "user", "content": user}],
        tools=COLLECTOR_QUERY_SCHEMAS,
        tool_choice="auto",
        temperature=0.5,
    )
```

- [ ] **Step 5: Add the accepted-finding escalation route**

Add this policy after `ESCALATE_SYSTEM_PROMPT_ENTERPRISE` and before `escalate_system_prompt()` in `app/agents/prompts.py`:

```python
_BACKDOOR_ESCALATION_POLICY = """

# J. 服务器被攻陷 / backdoor_compromised
原 Finding 的篡改页面、暗链或 webshell 是已确认起点，不是本轮可重复提交的升级结果。先复核当前性并排除跳转、缓存和第三方托管，再沿已观察到的同一目标入口查找初始入口：上传、未授权管理面、组件漏洞、文件写入、泄露凭证或其它可控点。每一步使用最小、可复核的请求。
只有取得新的 raw_request/raw_response，并证明 RCE、可用凭证、管理员入口、未授权写或规模化影响时，才以真正对应的漏洞类型 submit_escalation。只有原页面、原 webshell 路径或原始证据重复出现时调用 abandon_escalation。
"""
```

Replace `escalate_system_prompt()` with:

```python
def escalate_system_prompt(src_type: str | bool | None) -> str:
    base = ESCALATE_SYSTEM_PROMPT_ENTERPRISE if is_enterprise_src(src_type) else ESCALATE_SYSTEM_PROMPT
    return base + _BACKDOOR_ESCALATION_POLICY
```

Import the normalizer in `app/agents/escalate.py`:

```python
from app.dedup import normalize_vuln_type
```

Add this method to `EscalateHunter` before `_brief()`:

```python
    def _backdoor_focus(self) -> str:
        if normalize_vuln_type(self.finding.get("vuln_type", "")) != "backdoor_compromised":
            return ""
        return (
            "\n\n# 后门/被攻陷专用目标\n"
            "先复核当前篡改证据，排除跳转、缓存和第三方托管；再查上传点、未授权管理入口、"
            "组件漏洞、文件写入和泄露凭证等初始入口。只有证明新的 RCE、可用凭证、管理员入口、"
            "未授权写或规模化影响时，才携带新的 raw_request 和 raw_response，并使用真正对应的漏洞类型"
            "提交 submit_escalation。重复原页面、原 webshell 路径或原始证据时调用 abandon_escalation。"
        )
```

Change `_brief()` to build and return the generic text plus this focus:

```python
    def _brief(self) -> str:
        f = self.finding
        unit_label = "企业/系统归属" if is_enterprise_src(self.src_type) else "归属"
        brief = (
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
        return brief + self._backdoor_focus()
```

- [ ] **Step 6: Document the canonical type in schema descriptions**

Use these exact descriptions in `app/schemas.py` and `app/tools/schemas.py`:

```python
vuln_type: str = Field(
    ...,
    description="漏洞类型，如 sql_injection / rce / captcha_bypass / idor / unauthorized_access / backdoor_compromised",
)
```

```python
"vuln_type": {
    "type": "string",
    "description": "漏洞类型，如 idor/unauthorized_access/sql_injection/backdoor_compromised",
},
```

```python
"vuln_type": {
    "type": "string",
    "description": "漏洞类型，如 sql_injection/rce/captcha_bypass/idor/unauthorized_access/file_upload/backdoor_compromised",
},
```

```python
"vuln_type": {
    "type": "string",
    "description": "升级后的真实根因类型，如 rce/file_upload/unauthorized_access；完整性事件可为 backdoor_compromised",
},
```

- [ ] **Step 7: Run focused tests and verify GREEN**

Run:

```powershell
python -m pytest tests/test_backdoor_prompt_policy.py tests/test_collector_scope.py tests/test_prompt_profiles.py -q
```

Expected: all selected tests pass, including the existing one-argument `collector_query_prompt("edusrc")` call.

- [ ] **Step 8: Commit the prompt and schema slice**

```powershell
git add -- app/agents/prompts.py app/agents/collector_llm.py app/agents/escalate.py app/schemas.py app/tools/schemas.py tests/test_backdoor_prompt_policy.py
git commit -m "Feat: teach agents to verify compromised servers"
```

### Task 3: Block Repeated Backdoor Escalation Evidence

**Files:**
- Modify: `tests/test_escalation_service.py`
- Modify: `app/orchestrator.py`

- [ ] **Step 1: Add failing significance tests**

Append these tests to `tests/test_escalation_service.py`:

```python
def _backdoor_source() -> dict:
    return {
        "vuln_type": "backdoor_compromised",
        "raw_request": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "raw_response": "HTTP/1.1 200 OK\r\n\r\nCasino page",
    }


def test_regular_escalation_keeps_existing_severity_behavior() -> None:
    from app import orchestrator

    assert orchestrator._escalation_is_significant(
        "高危",
        {"escalated": True, "severity": "严重", "vuln_type": "idor"},
        source_finding={"vuln_type": "idor"},
    ) is True


def test_backdoor_escalation_requires_complete_new_evidence() -> None:
    from app import orchestrator

    assert orchestrator._escalation_is_significant(
        "高危",
        {
            "escalated": True,
            "severity": "严重",
            "vuln_type": "rce",
            "raw_request": "GET /shell.php HTTP/1.1",
            "raw_response": "",
        },
        source_finding=_backdoor_source(),
    ) is False


def test_backdoor_escalation_rejects_reused_evidence_even_with_higher_severity() -> None:
    from app import orchestrator

    source = _backdoor_source()
    assert orchestrator._escalation_is_significant(
        "高危",
        {
            "escalated": True,
            "severity": "严重",
            "vuln_type": "backdoor_compromised",
            "title": "RCE through existing webshell",
            "raw_request": source["raw_request"],
            "raw_response": source["raw_response"],
        },
        source_finding=source,
    ) is False


def test_backdoor_escalation_accepts_new_same_type_evidence_only_when_impact_grows() -> None:
    from app import orchestrator

    base = {
        "escalated": True,
        "severity": "高危",
        "vuln_type": "backdoor_compromised",
        "raw_request": "GET /shell.php?probe=whoami HTTP/1.1",
        "raw_response": "HTTP/1.1 200 OK\r\n\r\nprobe-user",
    }
    assert orchestrator._escalation_is_significant(
        "高危",
        base,
        source_finding=_backdoor_source(),
    ) is False
    assert orchestrator._escalation_is_significant(
        "高危",
        {**base, "impact_count": orchestrator._ESCALATE_IMPACT_THRESHOLD},
        source_finding=_backdoor_source(),
    ) is True


def test_backdoor_escalation_accepts_new_same_type_evidence_when_severity_grows() -> None:
    from app import orchestrator

    assert orchestrator._escalation_is_significant(
        "高危",
        {
            "escalated": True,
            "severity": "严重",
            "vuln_type": "backdoor_compromised",
            "raw_request": "GET /shell.php?probe=whoami HTTP/1.1",
            "raw_response": "HTTP/1.1 200 OK\r\n\r\nprobe-user",
        },
        source_finding=_backdoor_source(),
    ) is True


def test_backdoor_escalation_accepts_new_root_cause_evidence() -> None:
    from app import orchestrator

    assert orchestrator._escalation_is_significant(
        "高危",
        {
            "escalated": True,
            "severity": "严重",
            "vuln_type": "rce",
            "title": "Confirmed RCE root cause",
            "raw_request": "GET /shell.php?probe=whoami HTTP/1.1",
            "raw_response": "HTTP/1.1 200 OK\r\n\r\nprobe-user",
        },
        source_finding={**_backdoor_source(), "vuln_type": "网页被篡改"},
    ) is True


def test_runner_skips_backdoor_escalation_with_reused_evidence(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator
        from app.agents import escalate as escalate_module

        engine, sessions = await _database(tmp_path)
        source = _backdoor_source()
        try:
            async with sessions() as session:
                finding = await session.get(Finding, "finding-0")
                finding.vuln_type = source["vuln_type"]
                finding.raw_request = source["raw_request"]
                finding.raw_response = source["raw_response"]
                attempt, _ = await queue_attempt(
                    session,
                    task_id="task",
                    finding_id="finding-0",
                    orig_severity="高危",
                )
                attempt_id = attempt.id
                await session.commit()

            class FakeExecutor:
                def kill_processes(self) -> None:
                    pass

            class FakeHunter:
                def __init__(self, *_args, **_kwargs) -> None:
                    self.executor = FakeExecutor()

                def run(self):
                    return SimpleNamespace(model_dump=lambda **_kwargs: {
                        "escalated": True,
                        "severity": "严重",
                        "vuln_type": "backdoor_compromised",
                        "title": "Repeated compromised page",
                        "raw_request": source["raw_request"],
                        "raw_response": source["raw_response"],
                    })

            monkeypatch.setattr(escalate_module, "EscalateHunter", FakeHunter)
            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
            monkeypatch.setattr(orchestrator, "agent_semaphore", lambda _kind: asyncio.Semaphore(1))

            runner = orchestrator.TaskRunner("task")
            await runner._run_escalation_inner("task", attempt_id)

            async with sessions() as session:
                persisted = await session.get(EscalationAttempt, attempt_id)
                generated = (await session.scalars(
                    select(Finding).where(Finding.worker_id == "escalation")
                )).all()
                assert persisted.status == "skipped"
                assert persisted.error_kind == "not_significant"
                assert generated == []
        finally:
            await engine.dispose()

    asyncio.run(scenario())
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
python -m pytest tests/test_escalation_service.py -k "regular_escalation or backdoor_escalation" -q
```

Expected: tests fail because `_escalation_is_significant()` does not accept `source_finding` and does not compare evidence.

- [ ] **Step 3: Implement the source-evidence-aware significance check**

Replace `_escalation_is_significant()` in `app/orchestrator.py` with these helpers:

```python
def _normalize_escalation_evidence(value: object) -> str:
    return str(value or "").replace("\r\n", "\n").strip()


def _escalation_is_significant(
    orig_severity: str,
    res: dict,
    *,
    source_finding: dict | None = None,
) -> bool:
    """Return whether an escalation proves a materially new impact."""
    if not res or not res.get("escalated"):
        return False

    new_severity = res.get("severity") or ""
    severity_up = _SEVERITY_RANK.get(new_severity, 0) > _SEVERITY_RANK.get(orig_severity, 0)
    impact_up = int(res.get("impact_count", 0) or 0) >= _ESCALATE_IMPACT_THRESHOLD
    blob = f"{res.get('vuln_type', '')} {res.get('title', '')}".lower()
    top_tier = any(keyword in blob for keyword in _ESCALATE_TOPTIER_KEYWORDS)

    source = source_finding or {}
    if dedup.normalize_vuln_type(source.get("vuln_type", "")) == "backdoor_compromised":
        new_request = _normalize_escalation_evidence(res.get("raw_request"))
        new_response = _normalize_escalation_evidence(res.get("raw_response"))
        if not new_request or not new_response:
            return False
        old_request = _normalize_escalation_evidence(source.get("raw_request"))
        old_response = _normalize_escalation_evidence(source.get("raw_response"))
        if new_request == old_request and new_response == old_response:
            return False
        if dedup.normalize_vuln_type(res.get("vuln_type", "")) == "backdoor_compromised":
            if not severity_up and not impact_up:
                return False

    return severity_up or top_tier or impact_up
```

Keep `_ESCALATE_TOPTIER_KEYWORDS` unchanged; do not add `后门`, `被黑`, `webshell`, or `compromised`.

- [ ] **Step 4: Pass the source finding at the runner call site**

Replace the call in `_run_escalation_inner()` with:

```python
        if not _escalation_is_significant(
            orig_severity,
            res,
            source_finding=finding_dict,
        ):
```

- [ ] **Step 5: Run focused and existing escalation tests**

Run:

```powershell
python -m pytest tests/test_escalation_service.py tests/test_depth_policy.py -q
```

Expected: all escalation and depth-policy tests pass.

- [ ] **Step 6: Stage only feature hunks and commit**

First inspect the shared dirty file:

```powershell
git diff -- app/orchestrator.py tests/test_escalation_service.py
```

Stage only the `_normalize_escalation_evidence`, `_escalation_is_significant`, and call-site hunks from `app/orchestrator.py`, then stage the test file:

```powershell
git add -p -- app/orchestrator.py
git add -- tests/test_escalation_service.py
git commit -m "Fix: reject repeated compromised-server escalation"
```

Leave every pre-existing orchestrator hunk unstaged.

### Task 4: Frontend Canonical Option and Default Selection

**Files:**
- Modify: `frontend/tests/taskVulnerabilityTypes.test.js`
- Modify: `frontend/src/vulnerabilityTypes.js`

- [ ] **Step 1: Update the exact frontend expectation first**

Add this item after `captcha_bypass` in the expected array in `frontend/tests/taskVulnerabilityTypes.test.js`:

```javascript
      {
        value: "backdoor_compromised",
        label: "疑似后门 / 服务器被攻陷",
      },
```

- [ ] **Step 2: Run the frontend test and verify RED**

Run:

```powershell
node --test frontend/tests/taskVulnerabilityTypes.test.js
```

Expected: the canonical options assertion fails because the production catalog lacks the new item.

- [ ] **Step 3: Add the shared catalog option**

Add this item after `captcha_bypass` in `frontend/src/vulnerabilityTypes.js`:

```javascript
  Object.freeze({
    value: "backdoor_compromised",
    label: "疑似后门 / 服务器被攻陷",
  }),
```

Do not modify `CreateView.vue` or `TaskEditModal.vue`: `defaultVulnerabilityTypes()` already selects every canonical option for new tasks, while edit mode preserves each existing task array.

- [ ] **Step 4: Run frontend tests and verify GREEN**

Run:

```powershell
npm --prefix frontend test
```

Expected: all frontend Node tests pass.

- [ ] **Step 5: Build the frontend**

Run:

```powershell
npm --prefix frontend run build
```

Expected: Vite exits successfully and writes the production bundle.

- [ ] **Step 6: Commit the frontend slice**

```powershell
git add -- frontend/src/vulnerabilityTypes.js frontend/tests/taskVulnerabilityTypes.test.js
git commit -m "Feat: add compromised server task option"
```

### Task 5: Full Regression Verification

**Files:**
- Verify only; no production edits expected.

- [ ] **Step 1: Run the complete Python suite**

```powershell
python -m pytest -q
```

Expected: all tests pass with no collection errors or warnings introduced by this feature.

- [ ] **Step 2: Re-run the complete frontend suite and build**

```powershell
npm --prefix frontend test
npm --prefix frontend run build
```

Expected: all Node tests pass and Vite builds successfully.

- [ ] **Step 3: Check patch hygiene and scope**

```powershell
git diff --check
git status --short
git log -5 --oneline
```

Expected: `git diff --check` prints nothing; status contains no unexpected generated files; recent commits contain the four feature slices without unrelated workspace changes.

- [ ] **Step 4: Review the final behavior against the design**

Confirm all six acceptance behaviors from `docs/superpowers/specs/2026-07-15-backdoor-compromised-design.md`: default selection, all runtime profiles, accepted-to-escalation flow, repeated-evidence rejection, alias deduplication, and full regression coverage.
