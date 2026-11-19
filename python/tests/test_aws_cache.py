"""AwsSecretCache / AsyncAwsSecretCache: stage-aware entries, DescribeSecret version check,
refresh backoff, LRU, coalescing, stats."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

import grow_aws_secrets_manager as sdk


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def value(secret_id: str, version: str, text: str) -> sdk.AwsSecretValue:
    return sdk.AwsSecretValue(
        arn=f"arn:{secret_id}",
        name=secret_id,
        version_id=version,
        version_stages=("AWSCURRENT",),
        created_date=None,
        binary=False,
        value=sdk.SecretValue(text, version),
    )


class Source:
    """Fake client: stages per secret, counts calls, can fail or block."""

    def __init__(self) -> None:
        self.stages: dict[str, dict[str, str]] = {}  # secret → stage → version
        self.texts: dict[str, str] = {}  # version → text
        self.gets = 0
        self.describes = 0
        self.fail_describe = 0
        self.gate: threading.Event | None = None

    def put(self, secret_id: str, version: str, text: str, stage: str = "AWSCURRENT") -> None:
        self.stages.setdefault(secret_id, {})[stage] = version
        self.texts[version] = text

    def get_secret_value(
        self, secret_id: str, *, version_stage: str | None = None
    ) -> sdk.AwsSecretValue:
        self.gets += 1
        if self.gate is not None:
            self.gate.wait(5)
        stages = self.stages.get(secret_id)
        if not stages or (version_stage or "AWSCURRENT") not in stages:
            raise sdk.NotFoundError(f"{secret_id}: not found")
        version = stages[version_stage or "AWSCURRENT"]
        return value(secret_id, version, self.texts[version])

    def describe_secret(self, secret_id: str) -> sdk.SecretDescription:
        self.describes += 1
        if self.fail_describe:
            self.fail_describe -= 1
            raise sdk.UnavailableError("down")
        by_version: dict[str, tuple[str, ...]] = {}
        for stage, version in self.stages.get(secret_id, {}).items():
            by_version[version] = (*by_version.get(version, ()), stage)
        return sdk.SecretDescription(arn="a", name=secret_id, version_ids_to_stages=by_version)


class AsyncSource:
    def __init__(self, inner: Source) -> None:
        self.inner = inner
        self.delay = 0.0

    async def get_secret_value(
        self, secret_id: str, *, version_stage: str | None = None
    ) -> sdk.AwsSecretValue:
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.inner.get_secret_value(secret_id, version_stage=version_stage)

    async def describe_secret(self, secret_id: str) -> sdk.SecretDescription:
        return self.inner.describe_secret(secret_id)


def test_defaults_and_validation() -> None:
    assert sdk.AwsSecretCache.aws_defaults() == {"ttl_s": 3600.0, "max_entries": 1024}
    assert sdk.AsyncAwsSecretCache.aws_defaults() == sdk.AWS_SECRET_CACHE_DEFAULTS
    src = Source()
    for kwargs in ({"ttl_s": 0}, {"max_entries": 0}, {"max_entries": True}, {"version_stage": " "}):
        with pytest.raises(sdk.ValidationError):
            sdk.AwsSecretCache(src, **kwargs)
    from grow_aws_secrets_manager.testing import InMemorySecretsProvider

    preset = sdk.SecretCache(InMemorySecretsProvider(), **sdk.AwsSecretCache.aws_defaults())
    assert preset.get("missing") is None


def test_refresh_checks_the_version_and_fetches_only_on_change() -> None:
    src, clock = Source(), Clock()
    src.put("db", "v1", "one")
    cache = sdk.AwsSecretCache(src, ttl_s=10, clock=clock)
    assert cache.get_secret_string("db") == "one"
    assert cache.get_secret_binary("db") == b"one"
    assert (src.gets, src.describes) == (1, 0)
    clock.now = 11
    assert cache.get_secret_string("db") == "one"
    assert (src.gets, src.describes) == (1, 1)  # same version: no GetSecretValue
    src.put("db", "v2", "two")
    src.put("db", "v1", "one", stage="AWSPREVIOUS")
    clock.now = 22
    assert cache.get_secret_string("db") == "two"
    assert (src.gets, src.describes) == (2, 2)
    assert cache.get_secret_string("db", version_stage="AWSPREVIOUS") == "one"
    stats = cache.stats()
    assert stats == sdk.AwsSecretCacheStats(
        hits=3, misses=2, refreshes=2, version_changes=1, evictions=0, size=2
    )
    src.put("db", "v3", "three")
    assert cache.refresh_now("db").value.reveal() == "three"
    cache.invalidate("db")
    assert cache.stats().size == 0
    assert cache.get_secret_string("db") == "three"
    cache.clear()
    assert cache.stats().size == 0


def test_refresh_failures_serve_cached_and_back_off() -> None:
    src, clock = Source(), Clock()
    src.put("db", "v1", "one")
    errors: list[BaseException] = []
    cache = sdk.AwsSecretCache(src, ttl_s=100, clock=clock, on_refresh_error=errors.append)
    cache.get_secret_value("db")
    src.fail_describe = 2
    clock.now = 100
    assert cache.get_secret_string("db") == "one"  # failure 1 → retry after 1 s
    clock.now = 100.5
    assert cache.get_secret_string("db") == "one"
    assert src.describes == 1
    clock.now = 101
    assert cache.get_secret_string("db") == "one"  # failure 2 → retry after 2 s
    clock.now = 103
    assert cache.get_secret_string("db") == "one"  # succeeds
    assert len(errors) == 2
    assert src.describes == 3
    src.stages["db"] = {}
    clock.now = 300
    assert cache.get_secret_value("db").version_id == "v1"  # stage gone → fetch fails → cached
    assert len(errors) == 3
    with pytest.raises(sdk.NotFoundError):
        cache.get_secret_value("missing")


def test_lru_eviction() -> None:
    src = Source()
    for i in range(3):
        src.put(f"s{i}", f"v{i}", str(i))
    cache = sdk.AwsSecretCache(src, max_entries=2)
    cache.get_secret_value("s0")
    cache.get_secret_value("s1")
    cache.get_secret_value("s0")
    cache.get_secret_value("s2")
    assert cache.stats().evictions == 1
    gets = src.gets
    cache.get_secret_value("s0")
    assert src.gets == gets  # s0 survived, s1 was evicted
    cache.get_secret_value("s1")
    assert src.gets == gets + 1


def test_concurrent_reads_share_one_call() -> None:
    src = Source()
    src.put("db", "v1", "one")
    src.gate = threading.Event()
    cache = sdk.AwsSecretCache(src)
    results: list[str] = []
    threads = [
        threading.Thread(target=lambda: results.append(cache.get_secret_string("db")))
        for _ in range(5)
    ]
    for t in threads:
        t.start()
    while src.gets == 0:
        pass
    src.gate.set()
    for t in threads:
        t.join(5)
    assert results == ["one"] * 5
    assert src.gets <= 2


def test_concurrent_failures_propagate() -> None:
    src = Source()
    src.gate = threading.Event()
    cache = sdk.AwsSecretCache(src)
    errors: list[BaseException] = []

    def read() -> None:
        try:
            cache.get_secret_value("missing")
        except sdk.NotFoundError as err:
            errors.append(err)

    threads = [threading.Thread(target=read) for _ in range(3)]
    for t in threads:
        t.start()
    while src.gets == 0:
        pass
    src.gate.set()
    for t in threads:
        t.join(5)
    assert len(errors) == 3


async def test_async_cache() -> None:
    inner, clock = Source(), Clock()
    inner.put("db", "v1", "one")
    src = AsyncSource(inner)
    errors: list[BaseException] = []
    cache = sdk.AsyncAwsSecretCache(src, ttl_s=10, clock=clock, on_refresh_error=errors.append)
    src.delay = 0.01
    results = await asyncio.gather(*(cache.get_secret_string("db") for _ in range(5)))
    assert results == ["one"] * 5
    assert inner.gets == 1
    src.delay = 0
    assert await cache.get_secret_binary("db") == b"one"
    inner.put("db", "v2", "two")
    clock.now = 11
    assert await cache.get_secret_string("db") == "two"
    assert cache.stats().version_changes == 1
    inner.fail_describe = 1
    clock.now = 30
    assert await cache.get_secret_string("db") == "two"
    assert len(errors) == 1
    inner.put("db", "v3", "three")
    assert (await cache.refresh_now("db")).value.reveal() == "three"
    cache.invalidate("db")
    cache.clear()
    assert cache.stats().size == 0
    src.delay = 0.01
    outcomes = await asyncio.gather(
        cache.get_secret_value("missing"), cache.get_secret_value("missing"), return_exceptions=True
    )
    assert all(isinstance(o, sdk.NotFoundError) for o in outcomes)
    for kwargs in ({"ttl_s": -1}, {"max_entries": 0}):
        with pytest.raises(sdk.ValidationError):
            sdk.AsyncAwsSecretCache(src, **kwargs)  # type: ignore[arg-type]


def test_cache_keys_are_stage_aware(**_: Any) -> None:
    src = Source()
    src.put("db", "v1", "one")
    src.put("db", "v0", "zero", stage="AWSPREVIOUS")
    cache = sdk.AwsSecretCache(src, version_stage="AWSPREVIOUS")
    assert cache.get_secret_string("db") == "zero"
    assert cache.get_secret_string("db", version_stage="AWSCURRENT") == "one"
    assert cache.stats().size == 2
