"""Sticky, failover routing for a pool of FOFA credentials."""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Awaitable, Callable, Generic, TypeVar

from app.config import FofaKeyConfig
from app.fofa.client import FofaError, redact_fofa_secrets


logger = logging.getLogger(__name__)
T = TypeVar("T")


class FofaFailureKind(StrEnum):
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    DAILY_LIMIT = "daily_limit"
    TRANSIENT = "transient"


@dataclass(frozen=True)
class FofaKeyStateChange:
    name: str
    base_url: str
    runtime_state: str
    failure_kind: str
    failure_count: int
    cooldown_until: datetime | None
    active_key_name: str


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
        # Do not put credential values (or a credential-oriented repr) in the message.
        super().__init__(f"FOFA 凭据池暂不可用，共 {len(self.failures)} 项")


@dataclass(frozen=True)
class _Candidate:
    index: int
    name: str
    key: str
    base_url: str


class FofaKeyRouter(Generic[T]):
    """Selects one key/base URL pair and keeps the successful key sticky."""

    def __init__(
        self,
        keys: list[FofaKeyConfig],
        *,
        active_name: str = "",
        on_state_change: Callable[[FofaKeyStateChange], None] | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._keys = [item.model_copy(deep=True) for item in keys]
        self._active_name = str(active_name or "")
        self._on_state_change = on_state_change
        self._now = now
        self._lock = threading.RLock()

    @property
    def active_name(self) -> str:
        with self._lock:
            return self._active_name

    @property
    def keys(self) -> list[FofaKeyConfig]:
        """Return a deep snapshot so callers cannot mutate router state."""
        with self._lock:
            return [item.model_copy(deep=True) for item in self._keys]

    def execute_sync(self, operation: Callable[[str, str], T]) -> T:
        return self._execute_sync_ring(operation)

    async def execute_async(self, operation: Callable[[str, str], Awaitable[T]]) -> T:
        return await self._execute_async_ring(operation)

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
                {item.key for item in self._keys if item.key},
                key=len,
                reverse=True,
            )
        for secret in secrets:
            text = redact_fofa_secrets(text, secret)
        return text

    def _candidate_snapshot(self) -> tuple[list[_Candidate], datetime | None]:
        """Take one ordered candidate snapshot while holding the state lock."""
        with self._lock:
            now = self._current_time()
            active_index = next(
                (
                    index
                    for index, item in enumerate(self._keys)
                    if item.name == self._active_name
                    and item.enabled
                    and bool(item.key)
                    and item.runtime_state not in {"auth_invalid", "daily_suspended"}
                    and (item.cooldown_until is None or item.cooldown_until <= now)
                ),
                None,
            )
            start = active_index if active_index is not None else 0
            candidates: list[_Candidate] = []
            earliest_retry: datetime | None = None
            for offset in range(len(self._keys)):
                index = (start + offset) % len(self._keys) if self._keys else 0
                if not self._keys:
                    break
                item = self._keys[index]
                if not item.enabled or not item.key:
                    continue
                if item.runtime_state in {"auth_invalid", "daily_suspended"}:
                    continue
                if item.cooldown_until is not None and item.cooldown_until > now:
                    if earliest_retry is None or item.cooldown_until < earliest_retry:
                        earliest_retry = item.cooldown_until
                    continue
                candidates.append(_Candidate(index, item.name, item.key, item.base_url))
            return candidates, earliest_retry

    def _state_fingerprint(self, item: FofaKeyConfig) -> tuple[object, ...]:
        return (
            item.base_url,
            item.runtime_state,
            item.failure_kind,
            item.failure_count,
            item.cooldown_until,
            self._active_name,
        )

    def _state_change(
        self,
        before: tuple[object, ...],
        item: FofaKeyConfig,
    ) -> FofaKeyStateChange | None:
        after = self._state_fingerprint(item)
        if before == after:
            return None
        return FofaKeyStateChange(
            name=item.name,
            base_url=item.base_url,
            runtime_state=item.runtime_state,
            failure_kind=item.failure_kind,
            failure_count=item.failure_count,
            cooldown_until=item.cooldown_until,
            active_key_name=self._active_name,
        )

    def _notify(self, change: FofaKeyStateChange | None) -> None:
        callback = self._on_state_change
        if change is None or callback is None:
            return
        try:
            callback(change)
        except Exception as exc:  # callback failures must not affect routing
            logger.error("FOFA 状态回调失败：%s", self._redact(exc))

    def _mark_success(self, candidate: _Candidate) -> None:
        change: FofaKeyStateChange | None = None
        with self._lock:
            item = self._keys[candidate.index]
            before = self._state_fingerprint(item)
            item.runtime_state = "ready"
            item.failure_kind = ""
            item.failure_count = 0
            item.cooldown_until = None
            self._active_name = item.name
            change = self._state_change(before, item)
        self._notify(change)

    def _mark_failure(
        self,
        candidate: _Candidate,
        kind: FofaFailureKind,
        retry_after: int | None,
    ) -> None:
        change: FofaKeyStateChange | None = None
        with self._lock:
            item = self._keys[candidate.index]
            before = self._state_fingerprint(item)
            # A concurrent auth report for an already blocked item is idempotent.
            if kind is FofaFailureKind.AUTH and item.runtime_state == "auth_invalid":
                return
            item.failure_count = (
                item.failure_count + 1 if item.failure_kind == kind.value else 1
            )
            item.failure_kind = kind.value
            item.cooldown_until = None
            if kind is FofaFailureKind.AUTH:
                item.runtime_state = "auth_invalid"
            elif kind is FofaFailureKind.RATE_LIMIT:
                item.runtime_state = "rate_limited"
                delay = min(60 * (2 ** (item.failure_count - 1)), 600)
                if retry_after is not None:
                    delay = max(delay, retry_after)
                item.cooldown_until = self._current_time() + timedelta(seconds=delay)
            elif kind is FofaFailureKind.DAILY_LIMIT:
                if item.failure_count >= 12:
                    item.runtime_state = "daily_suspended"
                else:
                    item.runtime_state = "daily_cooldown"
                    item.cooldown_until = self._current_time() + timedelta(hours=1)
            else:
                item.runtime_state = "ready"
            change = self._state_change(before, item)
        self._notify(change)

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

    def _pool_failure(self, candidate: _Candidate, error: BaseException, kind: FofaFailureKind) -> FofaPoolFailure:
        return FofaPoolFailure(candidate.name, kind.value, self._redact(error))

    def _next_retry_at(self) -> datetime | None:
        with self._lock:
            now = self._current_time()
            result: datetime | None = None
            for item in self._keys:
                if not item.enabled or not item.key:
                    continue
                if item.runtime_state in {"auth_invalid", "daily_suspended"}:
                    continue
                if item.cooldown_until is not None and item.cooldown_until > now:
                    if result is None or item.cooldown_until < result:
                        result = item.cooldown_until
            return result

    def _execute_sync_ring(self, operation: Callable[[str, str], T]) -> T:
        candidates, _initial_retry = self._candidate_snapshot()
        failures: list[FofaPoolFailure] = []
        for candidate in candidates:
            try:
                result = operation(candidate.key, candidate.base_url)
            except Exception as error:
                kind = self._failure_kind(error.kind if isinstance(error, FofaError) else "transient")
                if kind is FofaFailureKind.TRANSIENT:
                    self._mark_failure(candidate, kind, None)
                    raise self._safe_error(error, kind) from error
                retry_after = error.retry_after if isinstance(error, FofaError) else None
                self._mark_failure(candidate, kind, retry_after)
                failures.append(self._pool_failure(candidate, error, kind))
                continue
            self._mark_success(candidate)
            return result
        raise FofaPoolExhaustedError(failures, self._next_retry_at())

    async def _execute_async_ring(self, operation: Callable[[str, str], Awaitable[T]]) -> T:
        candidates, _initial_retry = self._candidate_snapshot()
        failures: list[FofaPoolFailure] = []
        for candidate in candidates:
            try:
                result = await operation(candidate.key, candidate.base_url)
            except Exception as error:
                kind = self._failure_kind(error.kind if isinstance(error, FofaError) else "transient")
                if kind is FofaFailureKind.TRANSIENT:
                    self._mark_failure(candidate, kind, None)
                    raise self._safe_error(error, kind) from error
                retry_after = error.retry_after if isinstance(error, FofaError) else None
                self._mark_failure(candidate, kind, retry_after)
                failures.append(self._pool_failure(candidate, error, kind))
                continue
            self._mark_success(candidate)
            return result
        raise FofaPoolExhaustedError(failures, self._next_retry_at())


__all__ = [
    "FofaFailureKind",
    "FofaKeyRouter",
    "FofaKeyStateChange",
    "FofaPoolExhaustedError",
    "FofaPoolFailure",
]
