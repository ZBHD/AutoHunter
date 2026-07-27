from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any

from app.agents import playbook_router
from app.agents.prompts import worker_system_prompt
from app.tools.schemas import worker_tool_schemas

LEGACY_RELEASE_ID = "worker-2026-06-25-r1"
COMPILED_STABLE_RELEASE_ID = "worker-2026-07-15-r1"
MODERN_RELEASE_ID = "worker-2026-07-15-r2"
CANDIDATE_RELEASE_ID = "worker-2026-07-27-r1"
CONTROL_SURFACE_VERSION = "worker-control-v1"
RELEASE_ID_RE = re.compile(r"worker-\d{4}-\d{2}-\d{2}-r[1-9]\d*")

CANDIDATE_ROUTE_POLICIES = (
    {
        "route": "SSRF",
        "pattern": re.compile(
            r"(?i)(callback[_-]?url|webhook|proxy(?:[_-]?url)?|preview(?:[_-]?url)?|"
            r"image[_-]?url|import[_-]?url|url\s*[=:])"
        ),
        "steps": (
            "先做基线与单变量 URL 参数对照，再验证是否由服务端发起请求。",
            "最低证据：受控目标或允许范围内资源的服务端请求差异；错误文本不算访问成功。",
        ),
    },
    {
        "route": "XXE/解析",
        "pattern": re.compile(r"(?i)(\bxml\b|soap|office|docx|xlsx|富文本导入|xml导入)"),
        "steps": (
            "先确认解析器确实处理 XML/Office 内容，再做单变量实体或引用对照。",
            "最低证据：解析行为差异或允许范围内的受控资源读取；单纯接收 XML 不成立。",
        ),
    },
    {
        "route": "反序列化",
        "pattern": re.compile(
            r"(?i)(shiro|fastjson|java\s*seriali[sz]ation|viewstate|dubbo|反序列化)"
        ),
        "steps": (
            "先确认组件与数据格式，再使用无害、可重复的解析对照验证。",
            "最低证据：可重复的解析或执行证据；指纹和报错只能作为线索。",
        ),
    },
    {
        "route": "Token/身份边界",
        "pattern": re.compile(r"(?i)(\bjwt\b|authorization|bearer\s|access[_-]?token)"),
        "steps": (
            "对声明、算法或身份材料做单变量对照，并请求同一受限资源确认边界。",
            "最低证据：声明或算法变化必须实际获得不同身份或受限资源；只解码 payload 不成立。",
        ),
    },
)


class UnknownPromptReleaseError(LookupError):
    pass


class PromptReleaseNotPromotableError(ValueError):
    pass


@dataclass(frozen=True)
class PromptRelease:
    release_id: str
    label: str
    base_profile: str
    prompt_revision: str
    policy_revision: str
    playbook_revision: str
    tool_schema_revision: str
    promotable: bool


_RELEASE_LIST = (
    PromptRelease(
        release_id=LEGACY_RELEASE_ID,
        label="legacy compatibility",
        base_profile="legacy",
        prompt_revision="legacy-20260625",
        policy_revision="worker-policy-20260715",
        playbook_revision="playbook-20260715",
        tool_schema_revision="worker-tools-20260715",
        promotable=False,
    ),
    PromptRelease(
        release_id=COMPILED_STABLE_RELEASE_ID,
        label="balanced compact stable",
        base_profile="current",
        prompt_revision="compact-20260715",
        policy_revision="worker-policy-20260715",
        playbook_revision="playbook-20260715",
        tool_schema_revision="worker-tools-20260715",
        promotable=True,
    ),
    PromptRelease(
        release_id=MODERN_RELEASE_ID,
        label="full current compatibility",
        base_profile="modern",
        prompt_revision="modern-20260715",
        policy_revision="worker-policy-20260715",
        playbook_revision="playbook-20260715",
        tool_schema_revision="worker-tools-20260715",
        promotable=False,
    ),
    PromptRelease(
        release_id=CANDIDATE_RELEASE_ID,
        label="conditional route candidate",
        base_profile="current",
        prompt_revision="compact-20260715",
        policy_revision="worker-policy-20260715",
        playbook_revision="conditional-routes-20260727",
        tool_schema_revision="worker-tools-20260715",
        promotable=True,
    ),
)

PROMPT_RELEASES = {release.release_id: release for release in _RELEASE_LIST}

if len(PROMPT_RELEASES) != len(_RELEASE_LIST):
    raise RuntimeError("prompt release IDs must be unique")
if any(not RELEASE_ID_RE.fullmatch(release_id) for release_id in PROMPT_RELEASES):
    raise RuntimeError("prompt release IDs must match worker-YYYY-MM-DD-rN")

_FIXED_ALIASES = {
    "legacy": LEGACY_RELEASE_ID,
    "old": LEGACY_RELEASE_ID,
    "20260625": LEGACY_RELEASE_ID,
    "2026-06-25": LEGACY_RELEASE_ID,
    "modern": MODERN_RELEASE_ID,
    "full": MODERN_RELEASE_ID,
}


def get_prompt_release(release_id: str) -> PromptRelease:
    try:
        return PROMPT_RELEASES[str(release_id or "").strip()]
    except KeyError:
        raise UnknownPromptReleaseError(
            f"prompt release is not registered: {release_id}"
        ) from None


def require_promotable_release(release_id: str) -> PromptRelease:
    release = get_prompt_release(release_id)
    if not release.promotable:
        raise PromptReleaseNotPromotableError(
            f"prompt release is not promotable: {release_id}"
        )
    return release


def resolve_prompt_release(
    channel_or_alias: str | None,
    *,
    stable_release_id: str,
) -> PromptRelease:
    value = str(channel_or_alias or "").strip()
    lowered = value.lower()
    fixed = _FIXED_ALIASES.get(lowered)
    if fixed:
        return get_prompt_release(fixed)
    if value in PROMPT_RELEASES:
        return get_prompt_release(value)
    return get_prompt_release(stable_release_id)


def render_worker_prompt(
    release: PromptRelease,
    src_type: str | bool | None,
) -> str:
    return worker_system_prompt(src_type, release.base_profile)


def render_candidate_route_block(release: PromptRelease, signal_text: str) -> str:
    if release.release_id != CANDIDATE_RELEASE_ID:
        return ""
    text = str(signal_text or "")
    matched = [
        policy
        for policy in CANDIDATE_ROUTE_POLICIES
        if policy["pattern"].search(text)
    ]
    if not matched:
        return ""
    lines = ["# Candidate 条件化验证路线（仅执行命中项）"]
    for policy in matched:
        lines.append(f"## {policy['route']}")
        lines.extend(f"- {step}" for step in policy["steps"])
    return "\n".join(lines) + "\n\n"


def _playbook_control_surface() -> dict[str, Any]:
    routes = [asdict(route) for route in playbook_router._ROUTES]
    return {
        "routes": routes,
        "tool_sequences": playbook_router.ROUTE_TOOL_SEQUENCES,
        "default_tool_sequence": playbook_router.DEFAULT_ROUTE_TOOL_SEQUENCE,
    }


def _tool_control_surface() -> dict[str, Any]:
    variants: dict[str, Any] = {}
    for enterprise in (False, True):
        for include_js in (False, True):
            for stage in ("", "recon", "verify"):
                key = f"enterprise={enterprise};js={include_js};stage={stage or 'all'}"
                variants[key] = worker_tool_schemas(
                    enterprise=enterprise,
                    include_js=include_js,
                    stage=stage,
                )
    return variants


def prompt_release_fingerprint(release: PromptRelease) -> str:
    payload = {
        "control_surface_version": CONTROL_SURFACE_VERSION,
        "release": asdict(release),
        "rendered_prompts": {
            "edusrc": render_worker_prompt(release, "edusrc"),
            "enterprise": render_worker_prompt(release, "enterprise"),
        },
        "candidate_route_policies": [
            {
                "route": policy["route"],
                "pattern": policy["pattern"].pattern,
                "steps": policy["steps"],
            }
            for policy in CANDIDATE_ROUTE_POLICIES
        ],
        "playbook": _playbook_control_surface(),
        "tool_schemas": _tool_control_surface(),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "CANDIDATE_RELEASE_ID",
    "CANDIDATE_ROUTE_POLICIES",
    "COMPILED_STABLE_RELEASE_ID",
    "CONTROL_SURFACE_VERSION",
    "LEGACY_RELEASE_ID",
    "MODERN_RELEASE_ID",
    "PROMPT_RELEASES",
    "PromptRelease",
    "PromptReleaseNotPromotableError",
    "RELEASE_ID_RE",
    "UnknownPromptReleaseError",
    "get_prompt_release",
    "prompt_release_fingerprint",
    "render_candidate_route_block",
    "render_worker_prompt",
    "require_promotable_release",
    "resolve_prompt_release",
]
