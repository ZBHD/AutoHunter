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


def _parse_persisted_time(value: object) -> datetime | None:
    if isinstance(value, datetime):
        try:
            return _as_utc(value)
        except ValueError:
            return None
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return _as_utc(parsed)
    except (TypeError, ValueError):
        return None


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
    # A task override router is rebuilt per request, so its persisted runtime
    # markers are authoritative until the next successful request clears them.
    if source == "task_override":
        if cfg.get("fofa_pool_blocked") is True:
            pool_state = "blocked"
            available = []
            cooling = []
            retry_values = []
        else:
            persisted_retry = _parse_persisted_time(
                cfg.get("fofa_next_retry_at") or cfg.get("cooldown_until")
            )
            if persisted_retry is not None and persisted_retry > current:
                pool_state = "cooling"
                available = []
                cooling = []
                retry_values = [persisted_retry]
    result = {
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
    # Collector markers are fixed, credential-free status values. Include
    # them only while present so older snapshots retain their stable shape.
    if "fofa_pool_summary" in cfg:
        result["fofa_pool_summary"] = str(cfg.get("fofa_pool_summary") or "")[:200]
    if "fofa_next_retry_at" in cfg:
        result["fofa_next_retry_at"] = str(cfg.get("fofa_next_retry_at") or "")
    if "fofa_pool_blocked" in cfg:
        result["fofa_pool_blocked"] = bool(cfg.get("fofa_pool_blocked"))
    return result
