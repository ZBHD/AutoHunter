from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.prompt_releases import (
    COMPILED_STABLE_RELEASE_ID,
    resolve_prompt_release,
)
from app.db.models import PromptExperiment, SystemSettings, Target, Task
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


__all__ = [
    "PromptAssignment",
    "assignment_for_target",
    "cohort_bucket",
]
