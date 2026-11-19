"""Every service-specific function of the sync client against the real service, each with a
round-trip assertion (write → read back). Moto gaps (API.md section 7) assert the documented
emulator behaviour.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator

import pytest
from factories import core_client

import grow_aws_secrets_manager as sdk
from conftest import purge, uid


@pytest.fixture(scope="module")
def c(env: dict[str, str]) -> Iterator[sdk.AwsSecretsManagerClient]:
    with core_client(env) as client:
        yield client


@pytest.fixture(scope="module")
def name(c: sdk.AwsSecretsManagerClient) -> Iterator[object]:
    base = uid()
    created: list[str] = []

    def make(leaf: str) -> str:
        full = f"{base}/{leaf}"
        created.append(full)
        return full

    make.base = base  # type: ignore[attr-defined]
    yield make
    purge(c, created)


def test_get_secret_value_reads_the_seeds(
    c: sdk.AwsSecretsManagerClient, env: dict[str, str]
) -> None:
    seed = c.get_secret_value(env["GROW_TEST_SEED_JSON_SECRET"])
    assert seed.binary is False
    assert seed.value.json()["username"] == "seed-user"
    assert "AWSCURRENT" in seed.version_stages
    assert isinstance(seed.created_date, dt.datetime)
    assert seed.created_date.tzinfo is not None
    by_arn = c.get_secret_value(env["GROW_TEST_SEED_JSON_SECRET_ARN"])
    assert by_arn.version_id == seed.version_id
    blob = c.get_secret_value(env["GROW_TEST_SEED_BINARY_SECRET"])
    assert blob.binary is True
    assert blob.value.reveal_bytes() == bytes([0x00, 0x01, 0x02, 0xFE, 0xFF])
    assert "seed" not in repr(blob.value)
    with pytest.raises(sdk.NotFoundError):
        c.get_secret_value(f"{uid()}/missing")


def test_create_secret_variants(c: sdk.AwsSecretsManagerClient, name: object) -> None:
    s = name("create/string")  # type: ignore[operator]
    r = c.create_secret(s, "s3cr3t", description="made by python", tags={"team": "sdk"})
    assert r.name == s
    assert r.version_id
    assert c.get_secret_value(s).value.reveal() == "s3cr3t"
    b = name("create/bytes")  # type: ignore[operator]
    c.create_secret(b, bytes([7, 0, 255]))
    assert c.get_secret_value(b).value.reveal_bytes() == bytes([7, 0, 255])
    o = name("create/object")  # type: ignore[operator]
    c.create_secret(o, {"a": 1, "b": "two"})
    assert c.get_secret_value(o).value.json() == {"a": 1, "b": "two"}
    e = name("create/empty")  # type: ignore[operator]
    empty = c.create_secret(e, kms_key_id="alias/aws/secretsmanager")
    assert empty.version_id is None
    with pytest.raises(sdk.NotFoundError):
        c.get_secret_value(e)
    d = c.describe_secret(s)
    assert d.description == "made by python"
    assert d.tags == {"team": "sdk"}
    assert d.rotation_enabled is False
    with pytest.raises(sdk.ConflictError):
        c.create_secret(s, "again")


def test_versions_and_stages(c: sdk.AwsSecretsManagerClient, name: object) -> None:
    s = name("versions")  # type: ignore[operator]
    v1 = c.create_secret(s, "one").version_id
    put = c.put_secret_value(s, "two")
    assert put.version_stages == ("AWSCURRENT",)
    v2 = put.version_id
    assert c.get_secret_value(s, version_stage="AWSPREVIOUS").value.reveal() == "one"
    custom = c.put_secret_value(s, "three", version_stages=["STAGED"])
    assert c.get_secret_value(s, version_stage="STAGED").value.reveal() == "three"
    assert c.get_secret_value(s, version_stage="AWSCURRENT").value.reveal() == "two"
    assert c.get_secret_value(s, version_id=v1).version_id == v1
    # promote the staged version (read back with an explicit stage: Moto quirk)
    ref = c.update_secret_version_stage(
        s, "AWSCURRENT", move_to_version_id=custom.version_id, remove_from_version_id=v2
    )
    assert ref.name == s
    assert c.get_secret_value(s, version_stage="AWSCURRENT").value.reveal() == "three"
    versions = c.list_secret_version_ids(s, include_deprecated=True).to_list()
    assert len(versions) == 3
    stages = {v.version_id: v.version_stages for v in versions}
    assert "AWSCURRENT" in stages[custom.version_id]
    assert "AWSPREVIOUS" in stages[v2]
    described = c.describe_secret(s)
    assert described.version_id_for_stage("AWSCURRENT") == custom.version_id
    with pytest.raises(sdk.ValidationError):
        c.update_secret_version_stage(s, "AWSCURRENT", move_to_version_id=v1)


def test_update_secret(c: sdk.AwsSecretsManagerClient, name: object) -> None:
    s = name("update")  # type: ignore[operator]
    c.create_secret(s, "v1")
    c.update_secret(s, description="new description")
    assert c.describe_secret(s).description == "new description"
    r = c.update_secret(s, value={"rotated": True})
    assert r.version_id
    assert c.get_secret_value(s, version_stage="AWSCURRENT").value.json() == {"rotated": True}
    with pytest.raises(sdk.NotFoundError):
        c.update_secret(f"{uid()}/nope", description="x")


def test_batch_get_secret_value(c: sdk.AwsSecretsManagerClient, name: object) -> None:
    a = name("batch/a")  # type: ignore[operator]
    b = name("batch/b")  # type: ignore[operator]
    c.create_secret(a, "A")
    c.create_secret(b, "B")
    missing = f"{name.base}/batch/missing"  # type: ignore[attr-defined]
    res = c.batch_get_secret_value([b, missing, a])
    assert [(v.name, v.value.reveal()) for v in res.secret_values] == [(b, "B"), (a, "A")]
    assert [e.error_code for e in res.errors] == ["ResourceNotFoundException"]
    prefix = f"{name.base}/batch/"  # type: ignore[attr-defined]
    filtered = c.batch_get_secret_value(filters=[sdk.SecretFilter("name", [prefix])], max_results=1)
    assert sorted(v.name for v in filtered.secret_values) == [a, b]


def test_list_secrets(c: sdk.AwsSecretsManagerClient, name: object) -> None:
    names = [name("list/one"), name("list/two"), name("list/three")]  # type: ignore[operator]
    group = f"{name.base}-list"  # type: ignore[attr-defined]
    for n in names:
        c.create_secret(n, n, tags={"group": group})
    prefix = [sdk.SecretFilter("name", [f"{name.base}/list/"])]  # type: ignore[attr-defined]
    listed = c.list_secrets(filters=prefix, max_results=1).to_list()
    assert sorted(s.name for s in listed) == sorted(names)
    pages = list(c.list_secrets(filters=prefix, max_results=1).pages())
    assert len(pages) >= 3
    by_tag = list(
        c.list_secrets(filters=[sdk.SecretFilter("tag-value", [group])], sort_order="asc")
    )
    assert len(by_tag) == 3
    c.delete_secret(names[0], recovery_window_days=7)
    assert len(c.list_secrets(filters=prefix).to_list()) == 2
    planned = c.list_secrets(filters=prefix, include_planned_deletion=True).to_list()
    assert len(planned) == 3
    deleted = next(s for s in planned if s.name == names[0])
    assert deleted.pending_deletion


def test_delete_and_restore(c: sdk.AwsSecretsManagerClient, name: object) -> None:
    s = name("delete/restore")  # type: ignore[operator]
    c.create_secret(s, "keep")
    deleted = c.delete_secret(s, recovery_window_days=7)
    assert isinstance(deleted.deletion_date, dt.datetime)
    assert c.describe_secret(s).deleted_date is not None
    with pytest.raises(sdk.ConflictError):
        c.get_secret_value(s)
    assert c.restore_secret(s).name == s
    assert c.describe_secret(s).deleted_date is None
    assert c.get_secret_value(s).value.reveal() == "keep"
    f = name("delete/force")  # type: ignore[operator]
    c.create_secret(f, "bye")
    c.delete_secret(f, force_delete_without_recovery=True)
    with pytest.raises(sdk.NotFoundError):
        c.describe_secret(f)
    c.delete_secret(f, force_delete_without_recovery=True)  # AWS + Moto: success when missing
    with pytest.raises(sdk.NotFoundError):
        c.delete_secret(f)
    with pytest.raises(sdk.ValidationError):
        c.delete_secret(f, recovery_window_days=7, force_delete_without_recovery=True)


def test_tags(c: sdk.AwsSecretsManagerClient, name: object) -> None:
    s = name("tags")  # type: ignore[operator]
    c.create_secret(s, "v")
    c.tag_resource(s, {"env": "dev", "owner": "sdk"})
    assert c.describe_secret(s).tags == {"env": "dev", "owner": "sdk"}
    c.untag_resource(s, ["env"])
    assert c.describe_secret(s).tags == {"owner": "sdk"}


def test_resource_policy(
    c: sdk.AwsSecretsManagerClient, name: object, env: dict[str, str], is_moto: bool
) -> None:
    s = name("policy")  # type: ignore[operator]
    c.create_secret(s, "v")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{env['GROW_TEST_ACCOUNT_ID']}:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    assert c.put_resource_policy(s, policy, block_public_policy=True).name == s
    got = c.get_resource_policy(s)
    assert got.policy == policy
    assert got.resource_policy
    assert c.delete_resource_policy(s).name == s
    assert c.get_resource_policy(s).resource_policy is None
    if is_moto:
        # Not implemented in Moto 5.2.4 (API.md section 7): unit tests cover the AWS answer.
        with pytest.raises(sdk.UnsupportedError):
            c.validate_resource_policy(policy, secret_id=s)
    else:
        result = c.validate_resource_policy(policy, secret_id=s)
        assert isinstance(result.policy_validation_passed, bool)


def test_rotation(c: sdk.AwsSecretsManagerClient, name: object, is_moto: bool) -> None:
    if not is_moto:
        pytest.skip("rotation needs a rotation Lambda on real AWS (unit tests + live job)")
    s = name("rotation")  # type: ignore[operator]
    c.create_secret(s, "rot-v1")
    r = c.rotate_secret(s, rules=sdk.RotationRules(automatically_after_days=30))
    assert r.version_id
    d = c.describe_secret(s)
    assert d.rotation_enabled is True
    assert d.rotation_rules is not None
    assert d.rotation_rules.automatically_after_days == 30
    # Moto looks the Lambda up and has none (API.md section 7)
    with pytest.raises(sdk.NotFoundError):
        c.rotate_secret(
            s,
            lambda_arn="arn:aws:lambda:us-east-1:123456789012:function:grow-rotate",
            rules=sdk.RotationRules(schedule_expression="rate(10 days)"),
        )
    assert c.cancel_rotate_secret(s).name == s
    assert c.describe_secret(s).rotation_enabled is False
    with pytest.raises(sdk.NotFoundError):
        c.cancel_rotate_secret(f"{uid()}/rotation-missing")


def test_get_random_password(c: sdk.AwsSecretsManagerClient) -> None:
    p = c.get_random_password(length=40, exclude_punctuation=True, exclude_characters="abc")
    assert isinstance(p, sdk.Secret)
    text = p.reveal()
    assert len(text) == 40
    assert text.isalnum()
    assert not set("abc") & set(text)
    assert text not in str(p)
    assert len(c.get_random_password().reveal()) == 32
    with pytest.raises(sdk.ValidationError):
        c.get_random_password(length=2)


def test_get_json_field(c: sdk.AwsSecretsManagerClient, name: object, env: dict[str, str]) -> None:
    seed = env["GROW_TEST_SEED_JSON_SECRET"]
    assert c.get_json_field(seed, "username") == "seed-user"
    assert c.get_json_field(seed, "port") == 5432
    assert c.get_json_field(seed, "enabled") is True
    assert c.get_json_field(seed, "absent") is None
    s = name("json")  # type: ignore[operator]
    c.create_secret(s, {"db": {"host": "db.local"}})
    assert c.get_json_field(s, "db.host", version_stage="AWSCURRENT") == "db.local"
    with pytest.raises(sdk.ValidationError):
        c.get_json_field(env["GROW_TEST_SEED_BINARY_SECRET"], "x")


def test_secret_cache(c: sdk.AwsSecretsManagerClient, name: object) -> None:
    s = name("cache")  # type: ignore[operator]
    c.create_secret(s, "c1")
    cache = c.secret_cache(ttl_s=60)
    assert cache.get_secret_string(s) == "c1"
    c.put_secret_value(s, "c2")
    assert cache.get_secret_string(s) == "c1"
    assert cache.refresh_now(s).value.reveal() == "c2"
    assert cache.get_secret_binary(s, version_stage="AWSPREVIOUS") == b"c1"
    assert cache.stats().version_changes == 1
    cache.invalidate(s)
    cache.clear()
    assert cache.stats().size == 0
    assert sdk.AwsSecretCache.aws_defaults() == {"ttl_s": 3600.0, "max_entries": 1024}
