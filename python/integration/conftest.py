"""Integration fixtures: environment from /bootstrap/env and the service URL (SPEC section 8)."""

from __future__ import annotations

import contextlib
import os
import secrets
from collections.abc import Iterable, Iterator
from pathlib import Path

import pytest
from factories import URL_VAR, core_client

import grow_aws_secrets_manager as sdk


def load_env() -> dict[str, str]:
    """Process environment overlaid with the KEY=value lines of the bootstrap file."""
    env = dict(os.environ)
    path = Path(env.get("GROW_BOOTSTRAP_ENV", "/bootstrap/env"))
    if path.is_file():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env.setdefault(key.strip(), value.strip())
    return env


def uid(prefix: str = "py") -> str:
    """A unique secret-name prefix for this run: ``py-<run>-<random>``."""
    run = "".join(ch for ch in os.environ.get("GROW_TEST_RUN_ID", "local") if ch.isalnum())
    return f"{prefix}-{run[:8].lower()}-{secrets.token_hex(4)}"


def purge(client: sdk.AwsSecretsManagerClient, names: Iterable[str]) -> None:
    """Force-deletes secrets a test created (missing ones are ignored)."""
    for name in names:
        with contextlib.suppress(sdk.AwsSecretsManagerError):
            client.delete_secret(name, force_delete_without_recovery=True)


@pytest.fixture(scope="session")
def env() -> dict[str, str]:
    values = load_env()
    if not values.get(URL_VAR):
        pytest.skip(f"{URL_VAR} is not set (run through docker/compose.yml)")
    return values


@pytest.fixture(scope="session")
def is_moto(env: dict[str, str]) -> bool:
    return env.get("GROW_TEST_EMULATOR") == "moto"


@pytest.fixture
def client(env: dict[str, str]) -> Iterator[sdk.AwsSecretsManagerClient]:
    with core_client(env) as c:
        yield c
