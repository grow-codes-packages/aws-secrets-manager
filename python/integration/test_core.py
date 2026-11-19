"""Core client functions against the real service: health, ping (incl. auth failures),
server_version, close, from_env, a caller-supplied boto3 client and the core conformance scenario.
"""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from factories import CORE_CAPABILITIES, core_client

import grow_aws_secrets_manager as sdk
from grow_aws_secrets_manager.testing import ConformanceRunner, assert_scenario, pytest_params

NO_RETRY = sdk.RetryPolicy(max_retries=0)


def test_health(client: sdk.AwsSecretsManagerClient) -> None:
    status = client.health()
    assert status == sdk.HealthStatus(True, "ok", {}), status


def test_ping(client: sdk.AwsSecretsManagerClient) -> None:
    latency = client.ping()
    assert isinstance(latency, float)
    assert latency >= 0


def test_server_version_unsupported_and_close_idempotent(env: dict[str, str]) -> None:
    c = core_client(env)
    with pytest.raises(sdk.UnsupportedError):
        c.server_version()
    assert sdk.API_VERSION == "2017-10-17"
    c.close()
    c.close()
    assert c.closed
    with pytest.raises(sdk.CancelledError, match="client is closed"):
        c.ping()


@pytest.mark.parametrize("which", ["unknown-key", "wrong-secret"])
def test_bad_credentials_raise_authentication_and_never_leak(
    env: dict[str, str], which: str
) -> None:
    wrong = "wrong-secret-for-integration-0123456789"
    key = "AKIAUNKNOWNKEY000000" if which == "unknown-key" else env["AWS_ACCESS_KEY_ID"]
    with core_client(env, access_key_id=key, secret_access_key=wrong, retry=NO_RETRY) as c:
        with pytest.raises(sdk.AuthenticationError) as info:
            c.ping()
        assert info.value.http_status == 403
        assert wrong not in str(info.value)
        assert wrong not in repr(c)
        health = c.health()  # the service answered: healthy, auth reported as failed
        assert health.healthy
        assert health.details.get("auth") == "failed"


def test_read_only_principal_gets_permission_denied(env: dict[str, str]) -> None:
    with core_client(
        env,
        access_key_id=env["GROW_TEST_READONLY_ACCESS_KEY_ID"],
        secret_access_key=env["GROW_TEST_READONLY_SECRET_ACCESS_KEY"],
        retry=NO_RETRY,
    ) as c:
        assert c.ping() >= 0
        with pytest.raises(sdk.PermissionDeniedError):
            c.create_secret("py-readonly-denied", "v")


def test_wraps_a_caller_supplied_boto3_client(env: dict[str, str]) -> None:
    boto = boto3.client(
        "secretsmanager",
        region_name=env["AWS_REGION"],
        endpoint_url=env["GROW_AWS_SECRETS_MANAGER_URL"],
        aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
    )
    c = sdk.AwsSecretsManagerClient.with_sdk_client(boto)
    assert c.sdk is boto
    assert c.ping() >= 0
    c.close()
    # close() never closes a caller-supplied client
    again = sdk.AwsSecretsManagerClient(sdk.AwsSecretsManagerConfig(sdk_client=boto))
    assert again.get_secret_value(env["GROW_TEST_SEED_JSON_SECRET"]).name
    again.close()
    boto.close()


def test_hooks_see_every_attempt_redacted(env: dict[str, str]) -> None:
    seen: list[Any] = []
    hooks = sdk.Hooks(on_request=seen.append, on_response=seen.append)
    with core_client(env, hooks=hooks, headers={"x-grow-test": "1"}) as c:
        c.ping()
    request, response = seen
    assert isinstance(request, sdk.RequestInfo)
    assert request.headers["Authorization"] == sdk.REDACTED
    assert request.headers["x-grow-test"] == "1"
    assert "grow-codes-aws-secrets-manager/" in request.headers["User-Agent"]
    assert isinstance(response, sdk.ResponseInfo)
    assert response.status == 200
    assert response.request_id


@pytest.mark.parametrize("scenario", pytest_params(categories=["core"]))
def test_core_conformance(env: dict[str, str], scenario: dict[str, Any]) -> None:
    runner = ConformanceRunner(
        {"core": lambda ctx: core_client(env)}, capabilities=CORE_CAPABILITIES
    )
    assert_scenario(runner, scenario)
