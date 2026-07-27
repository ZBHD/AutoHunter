"""任务级 LLM token 用量计数。

运行态计数足够支撑看板实时观察；进程重启后清零，不参与审计结算。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from threading import Lock
from time import time
from typing import Any

_LOCK = Lock()
_USAGE: dict[str, dict[str, Any]] = {}
_TARGET_USAGE: dict[str, dict[str, Any]] = {}


@dataclass(frozen=True)
class UsageContext:
    task_id: str
    target_id: str
    experiment_id: str
    release_id: str
    cohort: str


def _record_row(
    storage: dict[str, dict[str, Any]],
    key: str,
    model: str,
    *,
    prompt: int,
    completion: int,
    total: int,
    cache_hit: int,
    cache_miss: int,
    context: UsageContext | None = None,
) -> None:
    row = storage.setdefault(key, {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cache_hit_tokens": 0,
        "cache_miss_tokens": 0,
        "requests": 0,
        "model": model,
        "updated_at": None,
    })
    row["prompt_tokens"] += prompt
    row["completion_tokens"] += completion
    row["total_tokens"] += total
    row["cache_hit_tokens"] = row.get("cache_hit_tokens", 0) + cache_hit
    row["cache_miss_tokens"] = row.get("cache_miss_tokens", 0) + cache_miss
    row["requests"] += 1
    row["model"] = model
    row["updated_at"] = time()
    if context is not None:
        row["context"] = asdict(context)


def record_usage(task_id: str | UsageContext | None, model: str, prompt_tokens: int = 0,
                 completion_tokens: int = 0, total_tokens: int = 0,
                 cache_hit_tokens: int = 0, cache_miss_tokens: int = 0) -> None:
    if not task_id:
        return
    prompt = max(0, int(prompt_tokens or 0))
    completion = max(0, int(completion_tokens or 0))
    total = max(0, int(total_tokens or 0)) or (prompt + completion)
    cache_hit = max(0, int(cache_hit_tokens or 0))
    cache_miss = max(0, int(cache_miss_tokens or 0))
    context = task_id if isinstance(task_id, UsageContext) else None
    task_key = context.task_id if context is not None else task_id
    with _LOCK:
        _record_row(
            _USAGE,
            task_key,
            model,
            prompt=prompt,
            completion=completion,
            total=total,
            cache_hit=cache_hit,
            cache_miss=cache_miss,
        )
        if context is not None and context.target_id:
            _record_row(
                _TARGET_USAGE,
                context.target_id,
                model,
                prompt=prompt,
                completion=completion,
                total=total,
                cache_hit=cache_hit,
                cache_miss=cache_miss,
                context=context,
            )


def usage_snapshot(task_id: str | None, model: str = "") -> dict[str, Any]:
    if not task_id:
        return _empty(model)
    with _LOCK:
        row = dict(_USAGE.get(task_id) or {})
    if not row:
        return _empty(model)
    if model and not row.get("model"):
        row["model"] = model
    return row


def target_usage_snapshot(target_id: str | None, model: str = "") -> dict[str, Any]:
    if not target_id:
        return _empty(model)
    with _LOCK:
        row = dict(_TARGET_USAGE.get(target_id) or {})
    if not row:
        return _empty(model)
    if model and not row.get("model"):
        row["model"] = model
    return row


def pop_target_usage(target_id: str | None, model: str = "") -> dict[str, Any]:
    if not target_id:
        return _empty(model)
    with _LOCK:
        row = dict(_TARGET_USAGE.pop(target_id, {}) or {})
    if not row:
        return _empty(model)
    if model and not row.get("model"):
        row["model"] = model
    return row


def _empty(model: str = "") -> dict[str, Any]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cache_hit_tokens": 0,
        "cache_miss_tokens": 0,
        "requests": 0,
        "model": model,
        "updated_at": None,
    }
