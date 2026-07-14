"""Shared ordering contract for persisted task targets."""
from __future__ import annotations

from sqlalchemy import case

from app.db.models import Target


def queue_dispatch_order():
    """Return the authoritative worker/list ordering for queued targets."""
    return (
        case((Target.queue_position.is_not(None), 0), else_=1),
        Target.queue_position.asc(),
        Target.priority_score.desc(),
        Target.created_at.asc(),
        Target.id.asc(),
    )
