"""SecretsProvider (category interface) against the real service: the conformance scenarios
(sync and async providers) plus paths, versions, binary values, tags/description, permanent
delete, watch, get_all / load_env and the template SecretCache with the AWS preset.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from factories import (
    SECRETS_CAPABILITIES,
    async_core_client,
    core_client,
    secrets_provider,
)

import grow_aws_secrets_manager as sdk
from conftest import purge, uid
from grow_aws_secrets_manager.testing import ConformanceRunner, assert_scenario, pytest_params


@pytest.fixture
def provider(env: dict[str, str]) -> Iterator[sdk.SecretsProvider]:
    with core_client(env) as client:
        found = secrets_provider(client)
        assert found is not None
        yield found


def _prefix() -> str:
    run_id = os.environ.get("GROW_TEST_RUN_ID", "local")
    return f"grow-conformance/{run_id}-${{run}}/"


@pytest.mark.parametrize("scenario", pytest_params(categories=["secrets"]))
def test_secrets_conformance(provider: sdk.SecretsProvider, scenario: dict[str, Any]) -> None:
    runner = ConformanceRunner(
        {"secrets": lambda ctx: provider}, capabilities=SECRETS_CAPABILITIES, prefix=_prefix()
    )
    assert_scenario(runner, scenario)


class _OwningAsyncProvider(sdk.AsyncAwsSecretsManagerSecretsProvider):
    """Closes its client on teardown (the runner gives every scenario its own event loop)."""

    async def aclose(self) -> None:
        await super().aclose()
        await self.client.aclose()


@pytest.mark.parametrize("scenario", pytest_params(categories=["secrets"]))
def test_async_secrets_conformance(env: dict[str, str], scenario: dict[str, Any]) -> None:
    runner = ConformanceRunner(
        {"secrets": lambda ctx: _OwningAsyncProvider(async_core_client(env))},
        capabilities=SECRETS_CAPABILITIES,
        prefix=_prefix(),
    )
    assert_scenario(runner, scenario)


@pytest.fixture(scope="module")
def base(env: dict[str, str]) -> Iterator[str]:
    prefix = uid("pyp")
    yield prefix
    with core_client(env) as c:
        purge(c, [m.name for m in c.secrets().list(f"{prefix}/")])


def test_set_get_with_path_versions_metadata(env: dict[str, str], base: str) -> None:
    with core_client(env) as c:
        p = c.secrets()
        v1 = p.set("db", "one", path=base, description="desc", tags={"a": "1"})
        v2 = p.set(f"{base}/db", "two", tags={"b": "2"})
        assert v1 != v2
        assert p.get_string("db", path=f"/{base}/") == "two"
        old = p.get(f"{base}/db", version=v1)
        assert old is not None
        assert old.reveal() == "one"
        meta = p.metadata(f"{base}/db")
        assert meta is not None
        assert meta.version == v2
        assert meta.versions == 2
        assert dict(meta.tags) == {"a": "1", "b": "2"}
        assert meta.extra["description"] == "desc"
        assert meta.path == base
        assert p.get_many([f"{base}/db"], version=v1)[f"{base}/db"].reveal() == "one"


def test_binary_get_many_get_all_load_env_list(env: dict[str, str], base: str) -> None:
    with core_client(env) as c:
        p = c.secrets()
        p.set(f"{base}/bin", bytes([0xFF, 0xFE]))
        value = p.get(f"{base}/bin")
        assert value is not None
        assert value.reveal_bytes() == bytes([0xFF, 0xFE])
        p.set(f"{base}/env/user", "u")
        p.set(f"{base}/env/pass", "p")
        p.set(f"{base}/env/nested/deep", "d")
        many = p.get_many([f"{base}/env/user", f"{base}/none", f"{base}/env/pass"])
        assert list(many) == [f"{base}/env/user", f"{base}/env/pass"]
        assert sorted(p.get_all(f"{base}/env")) == [f"{base}/env/pass", f"{base}/env/user"]
        target: dict[str, str] = {}
        exported = p.load_env(f"{base}/env", prefix="APP_", environ=target)
        assert sorted(exported) == ["APP_PASS", "APP_USER"]
        assert target["APP_USER"] == "u"
        assert [m.name for m in p.list(f"{base}/env/")] == [
            f"{base}/env/nested/deep",
            f"{base}/env/pass",
            f"{base}/env/user",
        ]


def test_delete_window_then_permanent(env: dict[str, str], base: str) -> None:
    with core_client(env) as c:
        p = c.secrets()
        p.set(f"{base}/soft", "x")
        p.delete(f"{base}/soft")
        assert p.get(f"{base}/soft") is None
        assert p.metadata(f"{base}/soft") is None
        with pytest.raises(sdk.NotFoundError):
            p.delete(f"{base}/soft")
        c.restore_secret(f"{base}/soft")
        assert p.get_string(f"{base}/soft") == "x"
        p.delete(f"{base}/soft", permanent=True)
        with pytest.raises(sdk.NotFoundError):
            c.describe_secret(f"{base}/soft")
        with pytest.raises(sdk.ValidationError):
            p.set(f"{base}/cas", "x", cas=0)


def test_watch_and_template_cache_with_aws_preset(env: dict[str, str], base: str) -> None:
    with core_client(env) as c:
        p = c.secrets()
        key = f"{base}/watched"
        p.set(key, "w1")
        cache = sdk.SecretCache(p, **sdk.AWS_SECRET_CACHE_DEFAULTS)
        assert cache.get_string(key) == "w1"
        seen: list[str | None] = []
        changed = threading.Event()

        def on_change(new: sdk.SecretValue | None, old: sdk.SecretValue | None) -> None:
            seen.append(None if new is None else new.reveal())
            changed.set()

        handle = p.watch(key, 0.2, on_change)
        try:
            time.sleep(1.0)  # let the watcher take its baseline (the first fetch)
            p.set(key, "w2")
            assert changed.wait(10)
        finally:
            handle.stop()
        assert seen == ["w2"]
        assert cache.get_string(key) == "w1"
