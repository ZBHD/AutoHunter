from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.prompt_releases import (
    COMPILED_STABLE_RELEASE_ID,
    resolve_prompt_release,
)
from app.db.models import (
    PromptExperiment,
    PromptExperimentSample,
    SystemSettings,
    Target,
    Task,
)
from app.settings_service import resolve_stable_prompt_release_id

_ACTIVE_ASSIGNMENT_STATUSES = ("live", "promoted")
_MANUAL_ALIASES = frozenset({
    "legacy",
    "old",
    "20260625",
    "2026-06-25",
    "modern",
    "full",
})
_HOLDBACK_DURATION = timedelta(hours=48)
_HOLDBACK_PERCENT = 10.0
_ROUTE_REASON_RE = re.compile(r"(?:^|\s|·)route:([^/\s]+)")


@dataclass(frozen=True)
class PromptAssignment:
    release_id: str
    experiment_id: str = ""
    cohort: str = "stable"


def cohort_bucket(seed: str, target_id: str) -> int:
    digest = hashlib.sha256(f"{seed}:{target_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % 10_000


def _utc_naive(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is not None:
        current = current.astimezone(timezone.utc).replace(tzinfo=None)
    return current


async def _stable_release_id(session: AsyncSession) -> str:
    settings = await session.get(SystemSettings, "global")
    if settings is None:
        return resolve_stable_prompt_release_id()
    return resolve_stable_prompt_release_id(dict(settings.defaults or {}))


async def _active_assignment_experiment(
    session: AsyncSession,
) -> PromptExperiment | None:
    return await session.scalar(
        select(PromptExperiment)
        .where(PromptExperiment.status.in_(_ACTIVE_ASSIGNMENT_STATUSES))
        .order_by(PromptExperiment.created_at.desc())
        .limit(1)
    )


async def assignment_for_target(
    session: AsyncSession,
    task: Task,
    target: Target,
    *,
    now: datetime | None = None,
) -> PromptAssignment:
    if target.prompt_release_id:
        return PromptAssignment(
            release_id=target.prompt_release_id,
            experiment_id=str(target.prompt_experiment_id or ""),
            cohort=str(target.prompt_cohort or "stable"),
        )

    stable_release_id = await _stable_release_id(session)
    model_config = dict(task.model_config_json or {})
    alias = str(model_config.get("prompt_version") or "current").strip().lower()
    if alias in _MANUAL_ALIASES:
        release = resolve_prompt_release(
            alias,
            stable_release_id=stable_release_id,
        )
        return PromptAssignment(release.release_id, cohort="manual")

    experiment = await _active_assignment_experiment(session)
    if experiment is None:
        return PromptAssignment(stable_release_id)

    bucket = cohort_bucket(experiment.seed, target.id)
    if experiment.status == "live":
        threshold = round(max(0.0, min(100.0, experiment.canary_percent)) * 100)
        if bucket < threshold:
            return PromptAssignment(
                experiment.candidate_release_id,
                experiment.id,
                "candidate",
            )
        return PromptAssignment(
            experiment.stable_release_id,
            experiment.id,
            "stable",
        )

    promoted_at = _utc_naive(experiment.promoted_at)
    current = _utc_naive(now)
    if current < promoted_at + _HOLDBACK_DURATION:
        holdback_threshold = round(_HOLDBACK_PERCENT * 100)
        if bucket < holdback_threshold:
            return PromptAssignment(
                experiment.previous_stable_id or experiment.stable_release_id,
                experiment.id,
                "holdback",
            )
        return PromptAssignment(
            experiment.candidate_release_id,
            experiment.id,
            "candidate",
        )

    return PromptAssignment(experiment.candidate_release_id)


def _sample_route_id(target: Target, result: dict) -> str:
    explicit = str(result.get("route_id") or "").strip()
    if explicit:
        return explicit[:80]
    match = _ROUTE_REASON_RE.search(str(target.priority_reason or ""))
    return match.group(1)[:80] if match else ""


def _evidence_complete(findings: list) -> bool:
    if not findings:
        return False
    for finding in findings:
        if not isinstance(finding, dict):
            return False
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict) or not evidence:
            return False
    return True


async def finalize_live_sample(
    session: AsyncSession,
    target: Target,
    result: dict,
    usage: dict,
) -> PromptExperimentSample | None:
    experiment_id = str(target.prompt_experiment_id or "")
    if not experiment_id or not target.prompt_release_id:
        return None

    sample = await session.scalar(
        select(PromptExperimentSample).where(
            PromptExperimentSample.experiment_id == experiment_id,
            PromptExperimentSample.target_id == target.id,
        )
    )
    if sample is None:
        sample = PromptExperimentSample(
            experiment_id=experiment_id,
            phase="holdback" if target.prompt_cohort == "holdback" else "live",
            cohort=str(target.prompt_cohort or "stable"),
            release_id=target.prompt_release_id,
            task_id=target.task_id,
            target_id=target.id,
        )
        session.add(sample)

    metrics = result.get("metrics") if isinstance(result.get("metrics"), dict) else {}
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    sample.release_id = target.prompt_release_id
    sample.cohort = str(target.prompt_cohort or "stable")
    sample.src_type = str(result.get("src_type") or "")[:20]
    sample.route_id = _sample_route_id(target, result)
    sample.terminal_verdict = str(result.get("verdict") or target.verdict or "")[:30]
    sample.rounds = max(0, int(result.get("rounds") or 0))
    sample.tool_calls = max(0, int(metrics.get("tool_calls") or 0))
    sample.tool_errors = max(0, int(metrics.get("tool_errors") or 0))
    sample.agent_terminated_by_tool = bool(
        result.get("failure_kind") == "tool_exception"
        or metrics.get("agent_terminated_by_tool")
    )
    sample.prompt_tokens = max(0, int(usage.get("prompt_tokens") or 0))
    sample.completion_tokens = max(0, int(usage.get("completion_tokens") or 0))
    sample.total_tokens = max(0, int(usage.get("total_tokens") or 0))
    sample.usage_complete = int(usage.get("requests") or 0) > 0
    sample.finding_count = len(findings)
    sample.evidence_complete = _evidence_complete(findings)
    sample.forbidden_action_count = max(
        0,
        int(metrics.get("forbidden_action_count") or 0),
    )
    sample.metrics = {
        "protocol_error_count": max(
            0,
            int(metrics.get("protocol_error_count") or 0),
        ),
        "evidence_crossing_count": max(
            0,
            int(metrics.get("evidence_crossing_count") or 0),
        ),
    }
    sample.finished_at = _utc_naive()
    return sample


__all__ = [
    "PromptAssignment",
    "assignment_for_target",
    "cohort_bucket",
    "finalize_live_sample",
]
