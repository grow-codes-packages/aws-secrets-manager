"""Factories the integration suite and the conformance runner use (owned by this repository).

The clients read the test environment (``/bootstrap/env`` overlaid on the process environment):
``GROW_AWS_SECRETS_MANAGER_URL`` / ``_REGION`` and the bootstrap admin key in ``AWS_*``.
Capabilities: AWS has no server version (``version`` is not declared, so the core scenario skips
that step); the secrets provider supports ``write``, ``delete`` and ``versions``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import grow_aws_secrets_manager as sdk

URL_VAR = "GROW_AWS_SECRETS_MANAGER_URL"

#: Capabilities of the deployment under test for the core scenarios ("version" = serverVersion).
CORE_CAPABILITIES: set[str] = set()


def core_client(env: Mapping[str, str], **overrides: Any) -> sdk.AwsSecretsManagerClient:
    """A client configured from the test environment (endpoint, region, bootstrap admin key)."""
    return sdk.AwsSecretsManagerClient.from_env(env, **overrides)


def async_core_client(env: Mapping[str, str], **overrides: Any) -> sdk.AsyncAwsSecretsManagerClient:
    return sdk.AsyncAwsSecretsManagerClient.from_env(env, **overrides)


#: Capabilities for the secrets scenarios: write, delete, versions.
SECRETS_CAPABILITIES: set[str] = set(sdk.AwsSecretsManagerSecretsProvider.capabilities)


def secrets_provider(client: sdk.AwsSecretsManagerClient) -> sdk.SecretsProvider | None:
    """The service's secrets provider on top of ``client``."""
    return client.secrets()
