"""Shared severity-tier policy for reviewer requeue, Worker, and escalation."""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DepthPolicy:
    severity: str
    deepen_cap: int
    priority_bonus: float
    soft_round_ratio: float
    escalation_rounds: int
    objective: str
    evidence_requirements: tuple[str, ...]

    def as_dict(self) -> dict:
        value = asdict(self)
        value["evidence_requirements"] = list(self.evidence_requirements)
        return value


_POLICIES = {
    "低危": DepthPolicy(
        severity="低危",
        deepen_cap=1,
        priority_bonus=80.0,
        soft_round_ratio=0.60,
        escalation_rounds=6,
        objective="确认低影响线索能否与鉴权、会话、对象接口或业务状态串联，升级为可独立复现的中危影响",
        evidence_requirements=(
            "证明线索不是公开设计或纯信息展示",
            "给出从线索到实际受限资源或状态影响的最短链路",
        ),
    ),
    "中危": DepthPolicy(
        severity="中危",
        deepen_cap=2,
        priority_bonus=100.0,
        soft_round_ratio=0.72,
        escalation_rounds=10,
        objective="把单对象或局部影响扩展为批量读取、敏感写操作、认证突破或更高权限能力",
        evidence_requirements=(
            "用基线与候选响应证明对象或身份边界确实被突破",
            "量化可影响对象并检查同资源的读写对称接口",
        ),
    ),
    "高危": DepthPolicy(
        severity="高危",
        deepen_cap=3,
        priority_bonus=130.0,
        soft_round_ratio=0.85,
        escalation_rounds=14,
        objective="沿已确认入口继续验证管理员能力、任意用户接管、核心数据、关键写操作或代码执行链",
        evidence_requirements=(
            "复用原始入口或登录态取得新的受限能力实证",
            "对接管、写操作或批量影响给出可复核的成功证据",
        ),
    ),
    "严重": DepthPolicy(
        severity="严重",
        deepen_cap=3,
        priority_bonus=160.0,
        soft_round_ratio=0.95,
        escalation_rounds=16,
        objective="确认顶格危害的稳定性、权限边界和影响范围，并寻找可量化的横向或供应链级扩展",
        evidence_requirements=(
            "复核关键执行或权限证据，排除偶发响应与误判",
            "量化受影响系统、租户、账号或数据范围且不重复原洞结论",
        ),
    ),
}


def normalize_severity(severity: str | None, default: str = "中危") -> str:
    value = str(severity or "").strip().lower()
    if not value:
        return default
    exact = {
        "low": "低危",
        "低": "低危",
        "低危": "低危",
        "medium": "中危",
        "moderate": "中危",
        "中": "中危",
        "中危": "中危",
        "high": "高危",
        "高": "高危",
        "高危": "高危",
        "critical": "严重",
        "severe": "严重",
        "严重": "严重",
        "致命": "严重",
    }
    if value in exact:
        return exact[value]
    if "严重" in value or "critical" in value or "severe" in value or "致命" in value:
        return "严重"
    if "高危" in value or value.startswith("high"):
        return "高危"
    if "中危" in value or value.startswith("medium") or value.startswith("moderate"):
        return "中危"
    if "低危" in value or value.startswith("low"):
        return "低危"
    return default


def severity_is_supported(severity: str | None) -> bool:
    value = str(severity or "").strip()
    if not value:
        return False
    return normalize_severity(value, "") in _POLICIES


def depth_policy_for(severity: str | None) -> DepthPolicy:
    return _POLICIES[normalize_severity(severity)]
