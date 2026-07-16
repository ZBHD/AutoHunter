"""Credential-free task runtime summaries for FOFA collection."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


_BLOCKED = frozenset({"auth_invalid", "daily_suspended"})
_ROTATION_REASONS = frozenset({"auth", "rate_limit", "daily_limit"})


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("FOFA 运行摘要时间必须包含时区")
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _public_rotation(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict) or value.get("reason") not in _ROTATION_REASONS:
        return None
    return {
        "from_key_name": str(value.get("from_key_name") or ""),
        "to_key_name": str(value.get("to_key_name") or ""),
        "reason": str(value["reason"]),
    }


def public_runtime_summary(
    task: Any,
    router: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return task and pool status without exposing credential values."""
    current = _as_utc(now or datetime.now(timezone.utc))
    cfg = dict(getattr(task, "fofa_config", None) or {})
    snapshots = list(router.state_snapshot)
    configured = [item for item in snapshots if item.key_set]
    available = []
    cooling = []

    for item in configured:
        if not item.enabled or item.runtime_state in _BLOCKED:
            continue
        if item.cooldown_until is not None and _as_utc(item.cooldown_until) > current:
            cooling.append(item)
            continue
        available.append(item)

    if available:
        pool_state = "ready"
    elif cooling:
        pool_state = "cooling"
    else:
        pool_state = "blocked"

    if str(cfg.get("key") or "").strip():
        source = "task_override"
    elif router.legacy_fallback:
        source = "legacy"
    else:
        source = "global_pool"

    retry_values = [
        item.cooldown_until
        for item in cooling
        if item.cooldown_until is not None
    ]
    return {
        "key_source": source,
        "active_key_name": (
            str(router.active_name or "") if source == "global_pool" else ""
        ),
        "last_key_name": str(
            cfg.get("last_key_name")
            or ("Task override" if source == "task_override" else "")
        ),
        "pool_available": len(available),
        "pool_total": len(configured),
        "pool_state": pool_state,
        "last_rotation": _public_rotation(cfg.get("last_rotation")),
        "cooldown_until": _iso(min(retry_values) if retry_values else None),
    }
