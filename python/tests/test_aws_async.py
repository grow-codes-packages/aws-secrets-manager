"""Async client on aioboto3 against the local AWS server, plus the assume-role helper."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest

import grow_aws_secrets_manager as sdk
from _support import closed_port_url, spawn_capturing
from aws_support import SECRET_KEY, AwsMock, AwsReply, aws_config, aws_error, reply
from fake_backend import AsyncFakeSecretsManager

SEED = "sdkv-0badc0de/app/db"
VID = "11111111-1111-4111-8111-11110badc0de"
VID2 = "22222222-2222-4222-8222-0badc0de0000"

ASSUME_ROLE_XML = """<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAASSUMEDKEY000001</AccessKeyId>
      <SecretAccessKey>assumed-secret-key-0001</SecretAccessKey>
      <SessionToken>assumed-session-token-0001</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <AssumedRoleId>AROA:grow-sdk</AssumedRoleId>
      <Arn>arn:aws:sts::123456789012:assumed-role/r/grow-sdk</Arn>
    </AssumedRoleUser>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>sts-1</RequestId></ResponseMetadata>
</AssumeRoleResponse>"""


@pytest.fixture
def aws() -> Iterator[AwsMock]:
    mock = AwsMock()
    yield mock
    mock.stop()


def aclient(url: str, **kw: Any) -> sdk.AsyncAwsSecretsManagerClient:
    return sdk.AsyncAwsSecretsManagerClient(aws_config(url, **kw))


async def test_async_core(aws: AwsMock) -> None:
    aws.defaults["ListSecrets"] = reply("ping.ok")
    async with aclient(aws.url) as c:
        assert c.sdk is None
        assert await c.health() == sdk.HealthStatus(True, "ok", {})
        assert await c.ping() >= 0
        assert c.sdk is not None
        with pytest.raises(sdk.UnsupportedError):
            await c.server_version()
    assert c.closed
    await c.close()
    with pytest.raises(sdk.CancelledError, match="closed"):
        await c.ping()
    aws.enqueue("ListSecrets", reply("ping.auth-unknown-key"), aws_error("ThrottlingException"))
    async with aclient(aws.url) as c:
        assert (await c.health()).details["auth"] == "failed"
        assert (await c.health()).status == "degraded"
    async with aclient(closed_port_url()) as c:
        assert (await c.health()).status == "unreachable"
        with pytest.raises(sdk.UnavailableError):
            await c.ping()


async def test_async_from_env_and_build_errors(
    aws: AwsMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = {
        "GROW_AWS_SECRETS_MANAGER_URL": aws.url,
        "AWS_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "AKIAENV",
        "AWS_SECRET_ACCESS_KEY": SECRET_KEY,
    }
    aws.defaults["ListSecrets"] = reply("ping.ok")
    async with sdk.AsyncAwsSecretsManagerClient.from_env(env) as c:
        assert await c.ping() >= 0
    monkeypatch.setenv("GROW_AWS_SECRETS_MANAGER_URL", aws.url)
    monkeypatch.setenv("GROW_AWS_SECRETS_MANAGER_REGION", "us-east-1")
    async with sdk.AsyncAwsSecretsManagerClient() as c:
        assert c.config.region == "us-east-1"
    for var in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("GROW_AWS_SECRETS_MANAGER_REGION")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/grow-config")
    async with sdk.AsyncAwsSecretsManagerClient(sdk.AwsSecretsManagerConfig()) as c:
        with pytest.raises(sdk.ConfigError, match="no AWS region"):
            await c.health()


async def test_async_operations(aws: AwsMock) -> None:
    aws.enqueue(
        "GetSecretValue",
        reply("getSecretValue.ok-string"),
        reply("getSecretValue.json-seed"),
    )
    aws.enqueue("BatchGetSecretValue", reply("batchGetSecretValue.ids-partial"))
    aws.enqueue(
        "BatchGetSecretValue",
        reply("batchGetSecretValue.filters"),
        reply("batchGetSecretValue.filters-page2"),
    )
    aws.enqueue("DescribeSecret", reply("describeSecret.ok"))
    aws.enqueue("ListSecrets", reply("listSecrets.page1"), reply("listSecrets.page2"))
    aws.enqueue("ListSecretVersionIds", reply("listSecretVersionIds.ok"))
    aws.enqueue("CreateSecret", reply("createSecret.ok-string"))
    aws.enqueue("PutSecretValue", reply("putSecretValue.ok"))
    aws.enqueue("UpdateSecret", reply("updateSecret.value"))
    aws.enqueue("UpdateSecretVersionStage", reply("updateSecretVersionStage.move"))
    aws.enqueue("DeleteSecret", reply("deleteSecret.recovery-window"))
    aws.enqueue("RestoreSecret", reply("restoreSecret.ok"))
    aws.enqueue("TagResource", reply("tagResource.ok"))
    aws.enqueue("UntagResource", reply("untagResource.ok"))
    aws.enqueue("PutResourcePolicy", reply("putResourcePolicy.ok"))
    aws.enqueue("GetResourcePolicy", reply("getResourcePolicy.ok"))
    aws.enqueue("DeleteResourcePolicy", reply("deleteResourcePolicy.ok"))
    aws.enqueue(
        "ValidateResourcePolicy",
        AwsReply(200, {"PolicyValidationPassed": True, "ValidationErrors": []}),
    )
    aws.enqueue("RotateSecret", reply("rotateSecret.rules-only"))
    aws.enqueue("CancelRotateSecret", reply("cancelRotateSecret.ok"))
    aws.enqueue("GetRandomPassword", reply("getRandomPassword.ok"))
    async with aclient(aws.url) as c:
        assert (await c.get_secret_value(SEED, version_stage="AWSCURRENT")).name == SEED
        assert await c.get_json_field("grow-bootstrap/seed-json", "username") == "seed-user"
        res = await c.batch_get_secret_value(["sdkv-0badc0de/app/blob", "x", SEED])
        assert len(res.secret_values) == 2
        assert len(res.errors) == 1
        filtered = await c.batch_get_secret_value(
            filters=[sdk.SecretFilter("name", ["sdkv-0badc0de/app/"])], max_results=1
        )
        assert len(filtered.secret_values) >= 2
        assert (await c.describe_secret(SEED)).tags["team"] == "sdk"
        pages = [page async for page in c.list_secrets(max_results=2).pages()]
        assert len(pages) == 2
        versions = [v async for v in c.list_secret_version_ids(SEED, include_deprecated=True)]
        assert len(versions) == 4
        assert (await c.create_secret("n", "v", tags={"a": "b"})).version_id
        assert (await c.put_secret_value(SEED, "v2", version_stages=["AWSCURRENT"])).version_id
        assert (await c.update_secret(SEED, value="v3")).version_id
        moved = await c.update_secret_version_stage(
            SEED, "STAGEX", move_to_version_id=VID, remove_from_version_id=VID2
        )
        assert moved.name
        assert (await c.delete_secret(SEED, recovery_window_days=7)).deletion_date
        assert (await c.restore_secret(SEED)).name
        await c.tag_resource(SEED, {"a": "1"})
        await c.untag_resource(SEED, ["a"])
        assert (await c.put_resource_policy(SEED, "{}", block_public_policy=False)).name
        assert (await c.get_resource_policy(SEED)).policy is not None
        assert (await c.delete_resource_policy(SEED)).name
        assert (await c.validate_resource_policy({}, secret_id=SEED)).policy_validation_passed
        rules = sdk.RotationRules(automatically_after_days=1)
        assert (await c.rotate_secret(SEED, rules=rules)).version_id
        assert (await c.cancel_rotate_secret(SEED)).name
        assert (await c.get_random_password(length=24)).reveal()
        aws.defaults["GetSecretValue"] = reply("getSecretValue.ok-binary")
        cache = c.secret_cache()
        assert await cache.get_secret_binary("blob") == bytes([0, 1, 2, 0xFE, 0xFF])
        assert isinstance(c.secrets(), sdk.AsyncAwsSecretsManagerSecretsProvider)
        aws.enqueue("BatchGetSecretValue", AwsReply(200, {"SecretValues": [], "NextToken": "t"}))
        await c.batch_get_secret_value([f"s{i}" for i in range(21)])
        with pytest.raises(sdk.ValidationError):
            c.list_secret_version_ids(" ")
    ops = aws.ops()
    for op in ("GetRandomPassword", "CancelRotateSecret", "ValidateResourcePolicy"):
        assert op in ops


async def test_async_errors_timeout_and_cancel(aws: AwsMock) -> None:
    aws.enqueue("DescribeSecret", reply("describeSecret.not-found"))
    errors: list[sdk.ErrorInfo] = []
    async with aclient(aws.url, hooks=sdk.Hooks(on_error=errors.append)) as c:
        with pytest.raises(sdk.NotFoundError):
            await c.describe_secret("missing")
        assert errors and errors[0].error.code is sdk.ErrorCode.NOT_FOUND
    aws.defaults["GetSecretValue"] = AwsReply(200, {}, delay=0.5)
    async with aclient(aws.url, total_timeout=0.1) as c:
        await c.ping()
        with pytest.raises(sdk.TimeoutError, match="total timeout"):
            await c.get_secret_value("slow")
    async with aclient(aws.url) as c:
        await c.ping()
        sink: list[BaseException] = []
        task = spawn_capturing(c.get_secret_value("slow"), sink)
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert isinstance(sink[0], sdk.CancelledError)
    async with aclient(aws.url) as c:
        sink = []
        task = spawn_capturing(c.ping(), sink)
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert sink
        assert isinstance(sink[0], asyncio.CancelledError)


async def test_async_with_sdk_client() -> None:
    fake = AsyncFakeSecretsManager()
    fake.backend.create_secret(Name="a", SecretString="1")
    async with sdk.AsyncAwsSecretsManagerClient.with_sdk_client(fake) as c:
        assert c.sdk is fake
        assert (await c.get_secret_value("a")).value.reveal() == "1"
        assert (await c.health()).healthy
    assert not fake.backend.closed


def test_assume_role_sync(aws: AwsMock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ENDPOINT_URL_STS", aws.url)
    aws.defaults[""] = AwsReply(200, ASSUME_ROLE_XML, content_type="text/xml")
    aws.defaults["ListSecrets"] = reply("ping.ok")
    cfg = aws_config(
        aws.url,
        role_arn="arn:aws:iam::123456789012:role/r",
        external_id="ext-0001",
        role_duration_s=900,
    )
    with sdk.AwsSecretsManagerClient(cfg) as c:
        c.ping()
    sts = next(s for s in aws.seen if s.operation == "")
    assert "AKIAGROWTESTKEY00001/" in sts.headers["Authorization"]
    call = aws.last("ListSecrets")
    assert "ASIAASSUMEDKEY000001/" in call.headers["Authorization"]
    assert call.headers["X-Amz-Security-Token"] == "assumed-session-token-0001"


def test_assume_role_without_base_credentials(
    aws: AwsMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    cfg = sdk.AwsSecretsManagerConfig(
        url=aws.url,
        region="us-east-1",
        role_arn="arn:aws:iam::123456789012:role/r",
        retry=sdk.RetryPolicy(max_retries=0),
    )
    with sdk.AwsSecretsManagerClient(cfg) as c:
        with pytest.raises(sdk.AuthenticationError):
            c.ping()

    async def run() -> None:
        async with sdk.AsyncAwsSecretsManagerClient(cfg) as ac:
            with pytest.raises(sdk.AuthenticationError):
                await ac.ping()

    asyncio.run(run())


async def test_assume_role_async(aws: AwsMock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ENDPOINT_URL_STS", aws.url)
    aws.defaults[""] = AwsReply(200, ASSUME_ROLE_XML, content_type="text/xml")
    aws.defaults["ListSecrets"] = reply("ping.ok")
    cfg = aws_config(aws.url, role_arn="arn:aws:iam::123456789012:role/r")
    async with sdk.AsyncAwsSecretsManagerClient(cfg) as c:
        await c.ping()
    call = aws.last("ListSecrets")
    assert "ASIAASSUMEDKEY000001/" in call.headers["Authorization"]


def test_explicit_credentials_object(aws: AwsMock) -> None:
    from botocore.credentials import Credentials

    aws.defaults["ListSecrets"] = reply("ping.ok")
    cfg = sdk.AwsSecretsManagerConfig(
        url=aws.url,
        region="us-east-1",
        credentials=Credentials("AKIAOBJECTKEY0000001", "object-secret-0001"),
    )
    with sdk.AwsSecretsManagerClient(cfg) as c:
        c.ping()
    assert "AKIAOBJECTKEY0000001/" in aws.last("ListSecrets").headers["Authorization"]

    async def run() -> None:
        from aiobotocore.credentials import AioCredentials

        acfg = sdk.AwsSecretsManagerConfig(
            url=aws.url,
            region="us-east-1",
            credentials=AioCredentials("AKIAASYNCOBJKEY00001", "object-secret-0002"),
        )
        async with sdk.AsyncAwsSecretsManagerClient(acfg) as ac:
            await ac.ping()

    asyncio.run(run())
    assert "AKIAASYNCOBJKEY00001/" in aws.last("ListSecrets").headers["Authorization"]
