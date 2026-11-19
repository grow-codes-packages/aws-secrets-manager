"""A version-stage aware secret cache with the semantics of the AWS caching clients.

``aws-secretsmanager-caching-*`` (DECISIONS.md #3): entries per ``(secret_id, version_stage)``,
default TTL 1 h and 1024 entries; when an entry expires ``DescribeSecret`` checks whether the
stage moved to another version and ``GetSecretValue`` runs only when it did. A refresh that fails
keeps serving the cached value and retries with exponential backoff (capped at the TTL); a first
read that fails raises. Concurrent reads of one key share a single AWS call.
"""

from __future__ import annotations

import asyncio
import collections
import concurrent.futures
import dataclasses
import datetime as _dt
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from ._core import ValidationError, to_seconds
from ._core.hooks import call_hook
from .models import AWSCURRENT, AwsSecretValue, SecretDescription

__all__ = [
    "AWS_SECRET_CACHE_DEFAULTS",
    "AwsSecretCache",
    "AsyncAwsSecretCache",
    "AwsSecretCacheStats",
    "SecretCacheSource",
    "AsyncSecretCacheSource",
]

#: The AWS caching-client defaults (TTL 1 h, 1024 entries); also valid keyword arguments of the
#: template :class:`~grow_aws_secrets_manager.SecretCache`.
AWS_SECRET_CACHE_DEFAULTS: dict[str, Any] = {"ttl_s": 3600.0, "max_entries": 1024}

#: Initial delay before retrying a failed refresh (doubles per failure, capped at the TTL).
REFRESH_RETRY_S = 1.0


class SecretCacheSource(Protocol):
    """The client operations :class:`AwsSecretCache` needs."""

    def get_secret_value(
        self, secret_id: str, *, version_stage: str | None = ...
    ) -> AwsSecretValue: ...

    def describe_secret(self, secret_id: str) -> SecretDescription: ...


class AsyncSecretCacheSource(Protocol):
    """The client operations :class:`AsyncAwsSecretCache` needs."""

    async def get_secret_value(
        self, secret_id: str, *, version_stage: str | None = ...
    ) -> AwsSecretValue: ...

    async def describe_secret(self, secret_id: str) -> SecretDescription: ...


@dataclasses.dataclass(frozen=True)
class AwsSecretCacheStats:
    """Counters of :meth:`AwsSecretCache.stats`."""

    hits: int
    misses: int
    #: Expired entries checked with ``DescribeSecret``.
    refreshes: int
    #: Refreshes that fetched a new version.
    version_changes: int
    evictions: int
    size: int


@dataclasses.dataclass
class _Entry:
    secret_id: str
    value: AwsSecretValue
    checked_at: float
    failures: int = 0


_Key = tuple[str, str]


class _Core:
    """Entries, LRU order, counters and the expiry rule (no I/O)."""

    def __init__(
        self,
        ttl_s: float | _dt.timedelta,
        max_entries: int,
        version_stage: str,
        clock: Callable[[], float],
        on_refresh_error: Callable[[BaseException], None] | None,
    ) -> None:
        self.ttl = to_seconds(ttl_s)
        if not self.ttl > 0:
            raise ValidationError("AwsSecretCache: ttl_s must be > 0")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValidationError("AwsSecretCache: max_entries must be >= 1")
        if not version_stage or not version_stage.strip():
            raise ValidationError("AwsSecretCache: version_stage must not be empty")
        self.max = max_entries
        self.stage = version_stage
        self.clock = clock
        self.on_refresh_error = on_refresh_error
        self.entries: collections.OrderedDict[_Key, _Entry] = collections.OrderedDict()
        self.lock = threading.Lock()
        self.hits = self.misses = self.refreshes = self.version_changes = self.evictions = 0

    def key(self, secret_id: str, stage: str | None) -> _Key:
        return (secret_id, stage or self.stage)

    def lookup(self, key: _Key) -> tuple[_Entry | None, bool]:
        """``(entry, due)``: the entry (LRU-touched) and whether it needs a refresh check."""
        with self.lock:
            entry = self.entries.get(key)
            if entry is None:
                self.misses += 1
                return None, False
            self.hits += 1
            self.entries.move_to_end(key)
            return entry, self.clock() - entry.checked_at >= self.next_check_after(entry)

    def next_check_after(self, entry: _Entry) -> float:
        if entry.failures == 0:
            return self.ttl
        return float(min(self.ttl, REFRESH_RETRY_S * 2 ** (entry.failures - 1)))

    def store(self, key: _Key, secret_id: str, value: AwsSecretValue) -> None:
        with self.lock:
            self.entries[key] = _Entry(secret_id, value, self.clock())
            self.entries.move_to_end(key)
            while len(self.entries) > self.max:
                self.entries.popitem(last=False)
                self.evictions += 1

    def moved(self, entry: _Entry, described: SecretDescription, stage: str) -> bool:
        """Starts a refresh; true when the stage now points to another version."""
        with self.lock:
            self.refreshes += 1
        current = described.version_id_for_stage(stage)
        return current is None or current != entry.value.version_id

    def changed(self) -> None:
        with self.lock:
            self.version_changes += 1

    def failed(self, entry: _Entry, exc: BaseException) -> AwsSecretValue:
        with self.lock:
            entry.failures += 1
            entry.checked_at = self.clock()
        call_hook(self.on_refresh_error, exc)
        return entry.value

    def force(self, key: _Key) -> bool:
        with self.lock:
            entry = self.entries.get(key)
            if entry is None:
                return False
            entry.checked_at = float("-inf")
            entry.failures = 0
            return True

    def invalidate(self, secret_id: str) -> None:
        with self.lock:
            for key in [k for k, e in self.entries.items() if e.secret_id == secret_id]:
                del self.entries[key]

    def clear(self) -> None:
        with self.lock:
            self.entries.clear()

    def stats(self) -> AwsSecretCacheStats:
        with self.lock:
            return AwsSecretCacheStats(
                self.hits,
                self.misses,
                self.refreshes,
                self.version_changes,
                self.evictions,
                len(self.entries),
            )


class AwsSecretCache:
    """Version-stage aware cache in front of an :class:`AwsSecretsManagerClient`
    (``client.secret_cache()``). Thread-safe.

    Options: ``ttl_s`` (refresh interval, default 3600), ``max_entries`` (LRU capacity, default
    1024), ``version_stage`` (default ``AWSCURRENT``), ``clock`` (monotonic seconds) and
    ``on_refresh_error`` (called when a refresh fails and the cached value is served instead).
    """

    @staticmethod
    def aws_defaults() -> dict[str, Any]:
        """The AWS caching-client defaults: ``{"ttl_s": 3600.0, "max_entries": 1024}``."""
        return dict(AWS_SECRET_CACHE_DEFAULTS)

    def __init__(
        self,
        source: SecretCacheSource,
        *,
        ttl_s: float | _dt.timedelta = 3600.0,
        max_entries: int = 1024,
        version_stage: str = AWSCURRENT,
        clock: Callable[[], float] = time.monotonic,
        on_refresh_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        self._source = source
        self._core = _Core(ttl_s, max_entries, version_stage, clock, on_refresh_error)
        self._inflight: dict[_Key, concurrent.futures.Future[AwsSecretValue]] = {}
        self._inflight_lock = threading.Lock()

    def _coalesce(self, key: _Key, load: Callable[[], AwsSecretValue]) -> AwsSecretValue:
        with self._inflight_lock:
            pending = self._inflight.get(key)
            owner = pending is None
            if pending is None:
                pending = concurrent.futures.Future()
                self._inflight[key] = pending
        if not owner:
            return pending.result()
        try:
            value = load()
        except BaseException as exc:
            pending.set_exception(exc)
            raise
        else:
            pending.set_result(value)
            return value
        finally:
            with self._inflight_lock:
                self._inflight.pop(key, None)

    def _refresh(self, key: _Key, entry: Any) -> AwsSecretValue:
        stage = key[1]
        try:
            described = self._source.describe_secret(entry.secret_id)
            value: AwsSecretValue = entry.value
            if self._core.moved(entry, described, stage):
                value = self._source.get_secret_value(entry.secret_id, version_stage=stage)
                self._core.changed()
        except Exception as exc:  # noqa: BLE001 - keep serving the cached value
            return self._core.failed(entry, exc)
        self._core.store(key, entry.secret_id, value)
        return value

    def get_secret_value(
        self, secret_id: str, *, version_stage: str | None = None
    ) -> AwsSecretValue:
        """The cached value of ``secret_id`` at the stage (default: the cache's stage)."""
        key = self._core.key(secret_id, version_stage)
        entry, due = self._core.lookup(key)
        if entry is not None:
            if not due:
                return entry.value
            return self._coalesce(key, lambda: self._refresh(key, entry))

        def load() -> AwsSecretValue:
            value = self._source.get_secret_value(secret_id, version_stage=key[1])
            self._core.store(key, secret_id, value)
            return value

        return self._coalesce(key, load)

    def get_secret_string(self, secret_id: str, *, version_stage: str | None = None) -> str:
        """The value as text (``SecretString``, or UTF-8 of the binary)."""
        return self.get_secret_value(secret_id, version_stage=version_stage).value.reveal()

    def get_secret_binary(self, secret_id: str, *, version_stage: str | None = None) -> bytes:
        """The value as bytes."""
        return self.get_secret_value(secret_id, version_stage=version_stage).value.reveal_bytes()

    def refresh_now(self, secret_id: str, *, version_stage: str | None = None) -> AwsSecretValue:
        """Forces a refresh check now (and a fetch when the stage moved); returns the value."""
        self._core.force(self._core.key(secret_id, version_stage))
        return self.get_secret_value(secret_id, version_stage=version_stage)

    def invalidate(self, secret_id: str) -> None:
        """Drops every cached stage of ``secret_id``."""
        self._core.invalidate(secret_id)

    def clear(self) -> None:
        """Drops every entry."""
        self._core.clear()

    def stats(self) -> AwsSecretCacheStats:
        """Counters and the current size."""
        return self._core.stats()


class AsyncAwsSecretCache:
    """Async :class:`AwsSecretCache` in front of an :class:`AsyncAwsSecretsManagerClient`."""

    @staticmethod
    def aws_defaults() -> dict[str, Any]:
        """The AWS caching-client defaults: ``{"ttl_s": 3600.0, "max_entries": 1024}``."""
        return dict(AWS_SECRET_CACHE_DEFAULTS)

    def __init__(
        self,
        source: AsyncSecretCacheSource,
        *,
        ttl_s: float | _dt.timedelta = 3600.0,
        max_entries: int = 1024,
        version_stage: str = AWSCURRENT,
        clock: Callable[[], float] = time.monotonic,
        on_refresh_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        self._source = source
        self._core = _Core(ttl_s, max_entries, version_stage, clock, on_refresh_error)
        self._inflight: dict[_Key, asyncio.Future[AwsSecretValue]] = {}

    async def _coalesce(
        self, key: _Key, load: Callable[[], Awaitable[AwsSecretValue]]
    ) -> AwsSecretValue:
        pending = self._inflight.get(key)
        if pending is not None:
            return await asyncio.shield(pending)
        future: asyncio.Future[AwsSecretValue] = asyncio.get_running_loop().create_future()
        self._inflight[key] = future
        try:
            value = await load()
        except BaseException as exc:
            future.set_exception(exc)
            future.exception()  # mark retrieved when nobody else waits
            raise
        else:
            future.set_result(value)
            return value
        finally:
            self._inflight.pop(key, None)

    async def _refresh(self, key: _Key, entry: Any) -> AwsSecretValue:
        stage = key[1]
        try:
            described = await self._source.describe_secret(entry.secret_id)
            value: AwsSecretValue = entry.value
            if self._core.moved(entry, described, stage):
                value = await self._source.get_secret_value(entry.secret_id, version_stage=stage)
                self._core.changed()
        except Exception as exc:  # noqa: BLE001 - keep serving the cached value
            return self._core.failed(entry, exc)
        self._core.store(key, entry.secret_id, value)
        return value

    async def get_secret_value(
        self, secret_id: str, *, version_stage: str | None = None
    ) -> AwsSecretValue:
        """See :meth:`AwsSecretCache.get_secret_value`."""
        key = self._core.key(secret_id, version_stage)
        entry, due = self._core.lookup(key)
        if entry is not None:
            if not due:
                return entry.value
            return await self._coalesce(key, lambda: self._refresh(key, entry))

        async def load() -> AwsSecretValue:
            value = await self._source.get_secret_value(secret_id, version_stage=key[1])
            self._core.store(key, secret_id, value)
            return value

        return await self._coalesce(key, load)

    async def get_secret_string(self, secret_id: str, *, version_stage: str | None = None) -> str:
        """See :meth:`AwsSecretCache.get_secret_string`."""
        return (await self.get_secret_value(secret_id, version_stage=version_stage)).value.reveal()

    async def get_secret_binary(self, secret_id: str, *, version_stage: str | None = None) -> bytes:
        """See :meth:`AwsSecretCache.get_secret_binary`."""
        value = await self.get_secret_value(secret_id, version_stage=version_stage)
        return value.value.reveal_bytes()

    async def refresh_now(
        self, secret_id: str, *, version_stage: str | None = None
    ) -> AwsSecretValue:
        """See :meth:`AwsSecretCache.refresh_now`."""
        self._core.force(self._core.key(secret_id, version_stage))
        return await self.get_secret_value(secret_id, version_stage=version_stage)

    def invalidate(self, secret_id: str) -> None:
        """Drops every cached stage of ``secret_id``."""
        self._core.invalidate(secret_id)

    def clear(self) -> None:
        """Drops every entry."""
        self._core.clear()

    def stats(self) -> AwsSecretCacheStats:
        """Counters and the current size."""
        return self._core.stats()
