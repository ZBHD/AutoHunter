"""Sticky, failover routing for a pool of FOFA credentials."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Awaitable, Callable, Generic, TypeVar

from app.config import FofaKeyConfig
from app.fofa.client import FofaError, redact_fofa_secrets


logger = logging.getLogger(__name__)
T = TypeVar("T")
_CREDENTIAL_FINGERPRINT_SECRET = os.urandom(32)


class FofaFailureKind(StrEnum):
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    DAILY_LIMIT = "daily_limit"
    TRANSIENT = "transient"


def fofa_credential_fingerprint(name: str, key: str, base_url: str) -> str:
    """Return a process-local, irreversible fingerprint for one credential unit."""
    parts = [str(name).encode("utf-8"), str(key).encode("utf-8"), str(base_url).encode("utf-8")]
    canonical = b"".join(len(part).to_bytes(8, "big") + part for part in parts)
    return hmac.new(_CREDENTIAL_FINGERPRINT_SECRET, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class FofaKeyStateChange:
    name: str
    base_url: str
    runtime_state: str
    failure_kind: str
    failure_count: int
    cooldown_until: datetime | None
    active_key_name: str
    credential_fingerprint: str = ""
    revision: int = 0


@dataclass(frozen=True)
class FofaKeyStateSnapshot:
    """Public state view that never carries a configured credential."""

    name: str
    base_url: str
    enabled: bool
    key_set: bool
    runtime_state: str
    failure_kind: str
    failure_count: int
    cooldown_until: datetime | None
    credential_fingerprint: str
    revision: int


@dataclass(frozen=True)
class FofaPoolFailure:
    name: str
    kind: str
    message: str


class FofaPoolExhaustedError(RuntimeError):
    """Raised when a complete routing round has no successful operation."""

    def __init__(self, failures: list[FofaPoolFailure], next_retry_at: datetime | None):
        self.failures = list(failures)
        self.next_retry_at = next_retry_at
        super().__init__(f"FOFA 凭据池暂不可用，共 {len(self.failures)} 项")


@dataclass
class _Entry:
    config: FofaKeyConfig
    credential_fingerprint: str
    generation: int = 0


@dataclass(frozen=True)
class _Candidate:
    index: int
    name: str
    key: str
    base_url: str
    credential_fingerprint: str
    generation: int
    active_name: str
    active_revision: int


class FofaKeyRouter(Generic[T]):
    """Select one key/base URL pair and keep the successful key sticky."""

    def __init__(
        self,
        keys: list[FofaKeyConfig],
        *,
        active_name: str = "",
        on_state_change: Callable[[FofaKeyStateChange], None] | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._entries = []
        for item in keys:
            # model_copy(update=...) bypasses Pydantic validators; revalidate
            # before taking the private credential snapshot.
            config = FofaKeyConfig.model_validate(item.model_dump())
            self._entries.append(
                _Entry(
                    config=config,
                    credential_fingerprint=fofa_credential_fingerprint(
                        config.name, config.key, config.base_url
                    ),
                )
            )
        self._active_name = str(active_name or "")
        self._active_revision = 0
        self._state_revision = 0
        self._on_state_change = on_state_change
        self._now = now
        self._lock = threading.RLock()
        self._pending_callbacks = deque[FofaKeyStateChange]()
        self._callback_dispatch_lock = threading.RLock()
        self._callback_dispatching = False

    @property
    def active_name(self) -> str:
        with self._lock:
            return self._active_name

    @property
    def keys(self) -> list[FofaKeyStateSnapshot]:
        """Return a deep, credential-free state snapshot."""
        return self.state_snapshot

    @property
    def state_snapshot(self) -> list[FofaKeyStateSnapshot]:
        with self._lock:
            return [self._snapshot_entry(entry) for entry in self._entries]

    @property
    def key_states(self) -> list[FofaKeyStateSnapshot]:
        return self.state_snapshot

    def execute_sync(self, operation: Callable[[str, str], T]) -> T:
        return self._execute_sync_ring(operation)

    async def execute_async(self, operation: Callable[[str, str], Awaitable[T]]) -> T:
        return await self._execute_async_ring(operation)

    def _snapshot_entry(self, entry: _Entry) -> FofaKeyStateSnapshot:
        item = entry.config
        return FofaKeyStateSnapshot(
            name=item.name,
            base_url=self._redact(item.base_url),
            enabled=item.enabled,
            key_set=bool(item.key),
            runtime_state=item.runtime_state,
            failure_kind=item.failure_kind,
            failure_count=item.failure_count,
            cooldown_until=item.cooldown_until,
            credential_fingerprint=entry.credential_fingerprint,
            revision=entry.generation,
        )

    def _current_time(self) -> datetime:
        value = self._now()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("FOFA Router 的 now 必须返回带时区的 aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _failure_kind(value: object) -> FofaFailureKind:
        try:
            return FofaFailureKind(str(value))
        except ValueError:
            return FofaFailureKind.TRANSIENT

    def _redact(self, message: object) -> str:
        text = str(message or "")
        with self._lock:
            secrets = sorted(
                {
                    entry.config.key
                    for entry in self._entries
                    if entry.config.key
                },
                key=len,
                reverse=True,
            )
        for secret in secrets:
            text = redact_fofa_secrets(text, secret)
        return text

    @staticmethod
    def _blocked_failure(entry: _Entry, kind: str, message: str) -> FofaPoolFailure:
        return FofaPoolFailure(entry.config.name, kind, message)

    def _candidate_snapshot(
        self,
    ) -> tuple[list[_Candidate], datetime | None, list[FofaPoolFailure]]:
        """Take one ordered candidate and pre-blocked snapshot under the state lock."""
        with self._lock:
            now = self._current_time()
            active_index = next(
                (
                    index
                    for index, entry in enumerate(self._entries)
                    if entry.config.name == self._active_name
                    and entry.config.enabled
                    and bool(entry.config.key)
                    and entry.config.runtime_state
                    not in {"auth_invalid", "daily_suspended"}
                    and (
                        entry.config.cooldown_until is None
                        or entry.config.cooldown_until <= now
                    )
                ),
                None,
            )
            start = active_index if active_index is not None else 0
            candidates: list[_Candidate] = []
            blocked: list[FofaPoolFailure] = []
            earliest_retry: datetime | None = None
            for offset in range(len(self._entries)):
                if not self._entries:
                    break
                index = (start + offset) % len(self._entries)
                entry = self._entries[index]
                item = entry.config
                if not item.enabled:
                    blocked.append(self._blocked_failure(entry, "disabled", "已停用"))
                    continue
                if item.runtime_state == "auth_invalid":
                    blocked.append(self._blocked_failure(entry, FofaFailureKind.AUTH.value, "认证失效"))
                    continue
                if item.runtime_state == "daily_suspended":
                    blocked.append(
                        self._blocked_failure(entry, FofaFailureKind.DAILY_LIMIT.value, "已达每日上限")
                    )
                    continue
                if not item.key:
                    blocked.append(self._blocked_failure(entry, "missing_key", "未配置密钥"))
                    continue
                if item.cooldown_until is not None and item.cooldown_until > now:
                    if earliest_retry is None or item.cooldown_until < earliest_retry:
                        earliest_retry = item.cooldown_until
                    if item.failure_kind in {
                        FofaFailureKind.RATE_LIMIT.value,
                        FofaFailureKind.DAILY_LIMIT.value,
                    }:
                        cooldown_kind = item.failure_kind
                    elif item.runtime_state == "daily_cooldown":
                        cooldown_kind = FofaFailureKind.DAILY_LIMIT.value
                    elif item.runtime_state == "rate_limited":
                        cooldown_kind = FofaFailureKind.RATE_LIMIT.value
                    else:
                        cooldown_kind = "cooldown"
                    blocked.append(self._blocked_failure(entry, cooldown_kind, "冷却中"))
                    continue
                candidates.append(
                    _Candidate(
                        index=index,
                        name=item.name,
                        key=item.key,
                        base_url=item.base_url,
                        credential_fingerprint=entry.credential_fingerprint,
                        generation=entry.generation,
                        active_name=self._active_name,
                        active_revision=self._active_revision,
                    )
                )
            return candidates, earliest_retry, blocked

    def _state_fingerprint(self, item: FofaKeyConfig) -> tuple[object, ...]:
        return (
            item.base_url,
            item.runtime_state,
            item.failure_kind,
            item.failure_count,
            item.cooldown_until,
            self._active_name,
        )

    def _record_state_change(
        self,
        before: tuple[object, ...],
        entry: _Entry,
    ) -> FofaKeyStateChange | None:
        item = entry.config
        after = self._state_fingerprint(item)
        if before == after:
            return None
        entry.generation += 1
        self._state_revision += 1
        if before[-1] != self._active_name:
            self._active_revision = self._state_revision
        change = FofaKeyStateChange(
            name=item.name,
            base_url=self._redact(item.base_url),
            runtime_state=item.runtime_state,
            failure_kind=item.failure_kind,
            failure_count=item.failure_count,
            cooldown_until=item.cooldown_until,
            active_key_name=self._active_name,
            credential_fingerprint=entry.credential_fingerprint,
            revision=self._state_revision,
        )
        if self._on_state_change is not None:
            self._pending_callbacks.append(change)
        return change

    def _drain_callbacks(self) -> None:
        callback = self._on_state_change
        if callback is None:
            return
        with self._callback_dispatch_lock:
            if self._callback_dispatching:
                return
            self._callback_dispatching = True
        try:
            while True:
                with self._callback_dispatch_lock:
                    with self._lock:
                        if not self._pending_callbacks:
                            self._callback_dispatching = False
                            return
                        change = self._pending_callbacks.popleft()
                try:
                    callback(change)
                except Exception as exc:  # callback failures never affect routing
                    logger.error("FOFA 状态回调失败：%s", self._redact(exc))
        finally:
            with self._callback_dispatch_lock:
                self._callback_dispatching = False

    def _entry_is_current(self, candidate: _Candidate) -> bool:
        if candidate.index >= len(self._entries):
            return False
        entry = self._entries[candidate.index]
        current_fingerprint = fofa_credential_fingerprint(
            entry.config.name, entry.config.key, entry.config.base_url
        )
        return (
            entry.generation == candidate.generation
            and entry.credential_fingerprint == candidate.credential_fingerprint
            and current_fingerprint == candidate.credential_fingerprint
            and entry.config.name == candidate.name
        )

    def _candidate_is_fresh_for_write(self, candidate: _Candidate) -> bool:
        if not self._entry_is_current(candidate):
            return False
        # A request from an older active key must not put that key back in front.
        return self._active_revision == candidate.active_revision or self._active_name == candidate.name

    def _mark_success(self, candidate: _Candidate) -> bool:
        with self._lock:
            if not self._candidate_is_fresh_for_write(candidate):
                return False
            entry = self._entries[candidate.index]
            item = entry.config
            before = self._state_fingerprint(item)
            item.runtime_state = "ready"
            item.failure_kind = ""
            item.failure_count = 0
            item.cooldown_until = None
            self._active_name = item.name
            change = self._record_state_change(before, entry)
            # Even a ready/active no-op success advances the entry generation,
            # invalidating older in-flight failures for the same credential.
            if change is None:
                entry.generation += 1
        self._drain_callbacks()
        return True

    def _mark_failure(
        self,
        candidate: _Candidate,
        kind: FofaFailureKind,
        retry_after: int | None,
    ) -> bool:
        with self._lock:
            if not self._candidate_is_fresh_for_write(candidate):
                if not self._merge_stale_failure_locked(candidate, kind, retry_after):
                    return False
            else:
                entry = self._entries[candidate.index]
                item = entry.config
                if kind is FofaFailureKind.AUTH and item.runtime_state == "auth_invalid":
                    return False
                self._apply_failure_locked(entry, kind, retry_after)
        self._drain_callbacks()
        return True

    def _merge_stale_failure_locked(
        self,
        candidate: _Candidate,
        kind: FofaFailureKind,
        retry_after: int | None,
    ) -> bool:
        """Merge a same-generation concurrent quota result without changing active."""
        if candidate.index >= len(self._entries):
            return False
        entry = self._entries[candidate.index]
        item = entry.config
        current_fingerprint = fofa_credential_fingerprint(
            item.name, item.key, item.base_url
        )
        if (
            entry.generation <= candidate.generation
            or entry.credential_fingerprint != candidate.credential_fingerprint
            or current_fingerprint != candidate.credential_fingerprint
        ):
            return False
        if kind is FofaFailureKind.RATE_LIMIT:
            same_state = (
                item.failure_kind == kind.value and item.runtime_state == "rate_limited"
            )
        elif kind is FofaFailureKind.DAILY_LIMIT:
            same_state = (
                item.failure_kind == kind.value and item.runtime_state == "daily_cooldown"
            )
        else:
            same_state = False
        if not same_state:
            return False
        self._apply_failure_locked(entry, kind, retry_after)
        return True

    def _apply_failure_locked(
        self,
        entry: _Entry,
        kind: FofaFailureKind,
        retry_after: int | None,
    ) -> None:
        item = entry.config
        before = self._state_fingerprint(item)
        previous_cooldown = item.cooldown_until
        item.failure_count = (
            item.failure_count + 1 if item.failure_kind == kind.value else 1
        )
        item.failure_kind = kind.value
        item.cooldown_until = None
        if kind is FofaFailureKind.AUTH:
            item.runtime_state = "auth_invalid"
        elif kind is FofaFailureKind.RATE_LIMIT:
            item.runtime_state = "rate_limited"
            delay = min(60 * (2 ** min(item.failure_count - 1, 4)), 600)
            if retry_after is not None:
                delay = max(delay, retry_after)
            calculated_cooldown = self._current_time() + timedelta(seconds=delay)
            item.cooldown_until = max(
                calculated_cooldown,
                previous_cooldown or calculated_cooldown,
            )
        elif kind is FofaFailureKind.DAILY_LIMIT:
            if item.failure_count >= 12:
                item.runtime_state = "daily_suspended"
            else:
                item.runtime_state = "daily_cooldown"
                item.cooldown_until = self._current_time() + timedelta(hours=1)
        else:
            item.runtime_state = "ready"
        self._record_state_change(before, entry)

    def _safe_error(self, error: BaseException, kind: FofaFailureKind) -> FofaError:
        if isinstance(error, FofaError):
            code = self._redact(error.code)
            retry_after = error.retry_after
        else:
            code = ""
            retry_after = None
        return FofaError(
            self._redact(error),
            kind=kind.value,
            code=code,
            retry_after=retry_after,
        )

    def _pool_failure(
        self,
        candidate: _Candidate,
        error: BaseException,
        kind: FofaFailureKind,
    ) -> FofaPoolFailure:
        return FofaPoolFailure(candidate.name, kind.value, self._redact(error))

    def _next_retry_at(self) -> datetime | None:
        with self._lock:
            now = self._current_time()
            result: datetime | None = None
            for entry in self._entries:
                item = entry.config
                if not item.enabled or not item.key:
                    continue
                if item.runtime_state in {"auth_invalid", "daily_suspended"}:
                    continue
                if item.cooldown_until is not None and item.cooldown_until > now:
                    if result is None or item.cooldown_until < result:
                        result = item.cooldown_until
            return result

    def _execute_sync_ring(self, operation: Callable[[str, str], T]) -> T:
        candidates, _initial_retry, blocked = self._candidate_snapshot()
        failures: list[FofaPoolFailure] = list(blocked)
        for candidate in candidates:
            result: T | None = None
            have_result = False
            transient_error: FofaError | None = None
            pool_failure: FofaPoolFailure | None = None
            try:
                result = operation(candidate.key, candidate.base_url)
                have_result = True
            except Exception as error:
                kind = self._failure_kind(error.kind if isinstance(error, FofaError) else "transient")
                if kind is FofaFailureKind.TRANSIENT:
                    self._mark_failure(candidate, kind, None)
                    transient_error = self._safe_error(error, kind)
                else:
                    retry_after = error.retry_after if isinstance(error, FofaError) else None
                    self._mark_failure(candidate, kind, retry_after)
                    pool_failure = self._pool_failure(candidate, error, kind)
            if transient_error is not None:
                raise transient_error from None
            if pool_failure is not None:
                failures.append(pool_failure)
                continue
            if have_result:
                self._mark_success(candidate)
                return result  # type: ignore[return-value]
        raise FofaPoolExhaustedError(failures, self._next_retry_at())

    async def _execute_async_ring(self, operation: Callable[[str, str], Awaitable[T]]) -> T:
        candidates, _initial_retry, blocked = self._candidate_snapshot()
        failures: list[FofaPoolFailure] = list(blocked)
        for candidate in candidates:
            result: T | None = None
            have_result = False
            transient_error: FofaError | None = None
            pool_failure: FofaPoolFailure | None = None
            try:
                result = await operation(candidate.key, candidate.base_url)
                have_result = True
            except Exception as error:
                kind = self._failure_kind(error.kind if isinstance(error, FofaError) else "transient")
                if kind is FofaFailureKind.TRANSIENT:
                    self._mark_failure(candidate, kind, None)
                    transient_error = self._safe_error(error, kind)
                else:
                    retry_after = error.retry_after if isinstance(error, FofaError) else None
                    self._mark_failure(candidate, kind, retry_after)
                    pool_failure = self._pool_failure(candidate, error, kind)
            if transient_error is not None:
                raise transient_error from None
            if pool_failure is not None:
                failures.append(pool_failure)
                continue
            if have_result:
                self._mark_success(candidate)
                return result  # type: ignore[return-value]
        raise FofaPoolExhaustedError(failures, self._next_retry_at())


__all__ = [
    "FofaFailureKind",
    "FofaKeyRouter",
    "FofaKeyStateChange",
    "FofaKeyStateSnapshot",
    "FofaPoolExhaustedError",
    "FofaPoolFailure",
    "fofa_credential_fingerprint",
]
