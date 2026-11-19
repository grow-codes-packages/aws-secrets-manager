"""SecretsProvider on AWS (sync + async) over the stateful fake boto3 client, including the
secrets conformance scenarios."""

from __future__ import annotations

from typing import Any

import pytest

import grow_aws_secrets_manager as sdk
from fake_backend import AsyncFakeSecretsManager, FakeSecretsManager, client_error
from grow_aws_secrets_manager.testing import ConformanceRunner, assert_scenario, pytest_params


def sync_provider(**kw: Any) -> tuple[sdk.AwsSecretsManagerSecretsProvider, FakeSecretsManager]:
    fake = FakeSecretsManager()
    client = sdk.AwsSecretsManagerClient.with_sdk_client(fake, **kw)
    return client.secrets(), fake


def async_provider(
    **kw: Any,
) -> tuple[sdk.AsyncAwsSecretsManagerSecretsProvider, FakeSecretsManager]:
    fake = AsyncFakeSecretsManager()
    client = sdk.AsyncAwsSecretsManagerClient.with_sdk_client(fake, **kw)
    return client.secrets(), fake.backend


@pytest.mark.parametrize("scenario", pytest_params(categories=["secrets"]))
def test_conformance_sync(scenario: dict[str, Any]) -> None:
    provider, _ = sync_provider()
    runner = ConformanceRunner(
        {"secrets": lambda ctx: provider},
        capabilities=sdk.AwsSecretsManagerSecretsProvider.capabilities,
    )
    assert_scenario(runner, scenario)


@pytest.mark.parametrize("scenario", pytest_params(categories=["secrets"]))
def test_conformance_async(scenario: dict[str, Any]) -> None:
    runner = ConformanceRunner(
        {"secrets": lambda ctx: async_provider()[0]},
        capabilities=sdk.AsyncAwsSecretsManagerSecretsProvider.capabilities,
    )
    assert_scenario(runner, scenario)


def test_full_name_and_metadata() -> None:
    assert sdk.full_name("db", None) == "db"
    assert sdk.full_name("db", "/app/") == "app/db"
    assert sdk.full_name("db", "//") == "db"
    d = sdk.SecretDescription(
        arn="arn:x",
        name="app/db",
        description="d",
        kms_key_id="k",
        rotation_enabled=True,
        next_rotation_date=sdk.models.utc(0),
        deleted_date=sdk.models.utc(1),
        primary_region="eu-west-1",
        tags={"a": "1"},
        version_ids_to_stages={"v1": ("AWSPREVIOUS",), "v2": ("AWSCURRENT",)},
    )
    meta = sdk.to_metadata(d)
    assert meta.path == "app"
    assert meta.version == "v2"
    assert meta.versions == 2
    assert meta.extra["rotationEnabled"] == "true"
    assert meta.extra["nextRotationDate"].startswith("1970-01-01T00:00:00")
    assert set(meta.extra) == {
        "arn",
        "rotationEnabled",
        "description",
        "kmsKeyId",
        "nextRotationDate",
        "deletedDate",
        "primaryRegion",
    }
    plain = sdk.to_metadata(sdk.SecretDescription(arn="a", name="top"))
    assert plain.path is None
    assert plain.version is None
    assert plain.extra == {"arn": "a", "rotationEnabled": "false"}


def test_sync_provider_paths_versions_and_writes() -> None:
    p, fake = sync_provider()
    assert p.client.config.sdk_client is fake
    v1 = p.set("db", "one", path="app", description="desc", tags={"a": "1"})
    assert fake.calls[-1][0] == "CreateSecret"
    v2 = p.set("app/db", b"\xff\x00", tags={"b": "2"}, description="new")
    assert [op for op, _ in fake.calls[-3:]] == ["PutSecretValue", "TagResource", "UpdateSecret"]
    assert v1 != v2
    assert p.get("db", path="/app/") == sdk.SecretValue(b"\xff\x00", v2)
    old = p.get("app/db", version=v1)
    assert old is not None
    assert old.reveal() == "one"
    meta = p.metadata("app/db")
    assert meta is not None
    assert meta.version == v2
    assert dict(meta.tags) == {"a": "1", "b": "2"}
    assert meta.extra["description"] == "new"
    assert p.metadata("missing") is None
    assert p.get_many(["app/db", "nope"], version=v1) == {"app/db": old}
    with pytest.raises(sdk.ValidationError, match="compare-and-set"):
        p.set("x", "v", cas=1)
    with pytest.raises(sdk.ValidationError, match="single versions"):
        p.delete("app/db", versions=["v"])


def test_sync_provider_create_race_and_errors() -> None:
    p, fake = sync_provider()
    fake.create_secret(Name="raced", SecretString="first")
    fake.fail["CreateSecret"] = [client_error("ResourceExistsException", "CreateSecret")]
    fake.fail["PutSecretValue"] = [client_error("ResourceNotFoundException", "PutSecretValue")]
    version = p.set("raced", "second")
    assert p.get_string("raced") == "second"
    assert version
    fake.fail["PutSecretValue"] = [client_error("ResourceNotFoundException", "PutSecretValue")]
    fake.fail["CreateSecret"] = [client_error("AccessDeniedException", "CreateSecret")]
    with pytest.raises(sdk.PermissionDeniedError):
        p.set("denied", "v")
    fake.fail["PutSecretValue"] = [client_error("ThrottlingException", "PutSecretValue")]
    with pytest.raises(sdk.RateLimitError):
        p.set("raced", "v")
    fake.fail["GetSecretValue"] = [client_error("AccessDeniedException", "GetSecretValue")]
    with pytest.raises(sdk.PermissionDeniedError):
        p.get("raced")
    fake.fail["DescribeSecret"] = [client_error("AccessDeniedException", "DescribeSecret")]
    with pytest.raises(sdk.PermissionDeniedError):
        p.metadata("raced")
    fake.fail["BatchGetSecretValue"] = []
    fake.secrets["raced"].deleted = None
    original = fake.batch_get_secret_value

    def denied_batch(**kw: Any) -> dict[str, Any]:
        out = original(**kw)
        out["Errors"].append({"SecretId": "x", "ErrorCode": "DecryptionFailure"})
        return out

    fake.batch_get_secret_value = denied_batch  # type: ignore[method-assign]
    with pytest.raises(sdk.ValidationError, match="DecryptionFailure"):
        p.get_many(["raced"])

    def odd_batch(**kw: Any) -> dict[str, Any]:
        out = original(**kw)
        out["Errors"].append({"SecretId": "y"})
        out["SecretValues"].append({"ARN": "arn:other", "Name": "other", "SecretString": "z"})
        return out

    fake.batch_get_secret_value = odd_batch  # type: ignore[method-assign]
    with pytest.raises(sdk.UnavailableError, match="error"):
        p.get_many(["raced"])


def test_sync_provider_delete_get_all_list_and_chunks() -> None:
    p, fake = sync_provider(recovery_window_days=10)
    for i in range(25):
        p.set(f"bulk/item{i:02d}", f"v{i}")
    p.set("bulk/nested/deep", "d")
    p.set("bulkier", "w")
    got = p.get_all("bulk")
    assert len(got) == 25
    assert list(got) == sorted(got)
    batches = [kw for op, kw in fake.calls if op == "BatchGetSecretValue"]
    assert [len(b["SecretIdList"]) for b in batches[-2:]] == [20, 5]
    names = [m.name for m in p.list("bulk/")]
    assert names[-1] == "bulk/nested/deep"
    assert len(p.list()) == 27
    assert len(p.get_all()) == 1  # only "bulkier" sits at the top level
    p.delete("bulkier")
    assert fake.calls[-1] == ("DeleteSecret", {"SecretId": "bulkier", "RecoveryWindowInDays": 10})
    assert p.get("bulkier") is None
    assert p.metadata("bulkier") is None
    with pytest.raises(sdk.NotFoundError):
        p.delete("bulkier")
    p.delete("bulk/item00", permanent=True)
    assert fake.calls[-1][1] == {"SecretId": "bulk/item00", "ForceDeleteWithoutRecovery": True}
    with pytest.raises(sdk.NotFoundError):
        p.delete("never")
    assert p.get_many(["bulkier", "bulk/item01", "bulk/item01"]) == {
        "bulk/item01": sdk.SecretValue("v1", fake.secrets["bulk/item01"].versions[0].vid)
    }


def test_provider_recovery_window_validation() -> None:
    client = sdk.AwsSecretsManagerClient.with_sdk_client(FakeSecretsManager())
    with pytest.raises(sdk.ValidationError):
        client.secrets(recovery_window_days=3)
    aclient = sdk.AsyncAwsSecretsManagerClient.with_sdk_client(AsyncFakeSecretsManager())
    with pytest.raises(sdk.ValidationError):
        aclient.secrets(recovery_window_days=True)  # type: ignore[arg-type]


def test_client_close_stops_provider_watchers() -> None:
    p, _ = sync_provider()
    p.set("w", "1")
    handle = p.watch("w", 10, lambda new, old: None)
    p.client.close()
    assert handle.stopped


async def test_async_provider_end_to_end() -> None:
    p, fake = async_provider(recovery_window_days=7)
    v1 = await p.set("db", "one", path="app", description="desc", tags={"a": "1"})
    v2 = await p.set("app/db", "two", tags={"b": "2"}, description="d2")
    assert (await p.get("app/db", version=v1)) == sdk.SecretValue("one", v1)
    assert (await p.get_string("db", path="app")) == "two"
    meta = await p.metadata("app/db")
    assert meta is not None
    assert meta.version == v2
    assert await p.metadata("none") is None
    many = await p.get_many(["app/db", "zzz"], version=v2)
    assert list(many) == ["app/db"]
    for i in range(21):
        await p.set(f"bulk/i{i:02d}", str(i))
    assert len(await p.get_all("bulk/")) == 21
    assert len(await p.list("bulk")) == 21
    assert (await p.get_many(["bulk/i00", "missing"])) == {
        "bulk/i00": sdk.SecretValue("0", fake.secrets["bulk/i00"].versions[0].vid)
    }
    await p.delete("bulk/i00")
    assert await p.get("bulk/i00") is None
    with pytest.raises(sdk.NotFoundError):
        await p.delete("bulk/i00")
    await p.delete("bulk/i01", permanent=True)
    assert "bulk/i01" not in fake.secrets
    with pytest.raises(sdk.ValidationError):
        await p.set("x", "y", cas=2)
    with pytest.raises(sdk.ValidationError):
        await p.delete("x", versions=["a"])
    fake.fail["PutSecretValue"] = [client_error("ResourceNotFoundException", "PutSecretValue")]
    fake.fail["CreateSecret"] = [client_error("ResourceExistsException", "CreateSecret")]
    assert await p.set("app/db", "three")
    fake.fail["PutSecretValue"] = [client_error("ResourceNotFoundException", "PutSecretValue")]
    fake.fail["CreateSecret"] = [client_error("ValidationException", "CreateSecret")]
    with pytest.raises(sdk.ValidationError):
        await p.set("new", "v")
    fake.fail["GetSecretValue"] = [client_error("InternalServiceError", "GetSecretValue", 500)]
    with pytest.raises(sdk.UnavailableError):
        await p.get("app/db")
    fake.fail["DescribeSecret"] = [client_error("AccessDenied", "DescribeSecret")]
    with pytest.raises(sdk.PermissionDeniedError):
        await p.metadata("app/db")
    assert p.client.config.recovery_window_days == 7
    await p.client.aclose()
