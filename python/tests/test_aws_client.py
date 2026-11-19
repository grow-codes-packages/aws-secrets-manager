"""Sync client on boto3 against a local AWS JSON 1.1 server fed with the recorded Moto fixtures."""

from __future__ import annotations

import datetime as dt
import json
import threading
import time
import warnings
from collections.abc import Iterator
from typing import Any

import pytest

import grow_aws_secrets_manager as sdk
from aws_support import (
    SECRET_KEY,
    SESSION_TOKEN,
    AwsMock,
    AwsReply,
    aws_config,
    aws_error,
    reply,
)
from fake_backend import FakeSecretsManager

SEED = "sdkv-0badc0de/app/db"
VID = "11111111-1111-4111-8111-11110badc0de"
VID2 = "22222222-2222-4222-8222-0badc0de0000"


@pytest.fixture
def aws() -> Iterator[AwsMock]:
    mock = AwsMock()
    yield mock
    mock.stop()


@pytest.fixture
def c(aws: AwsMock) -> Iterator[sdk.AwsSecretsManagerClient]:
    with sdk.AwsSecretsManagerClient(aws_config(aws.url)) as client:
        yield client


# --------------------------------------------------------------------------- core


def test_health_ping_server_version(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.defaults["ListSecrets"] = reply("ping.ok")
    assert c.health() == sdk.HealthStatus(True, "ok", {})
    assert c.ping() >= 0
    assert aws.last("ListSecrets").body == {"MaxResults": 1}
    with pytest.raises(sdk.UnsupportedError, match="server version"):
        c.server_version()
    token = sdk.CancelToken()
    token.cancel()
    with pytest.raises(sdk.CancelledError):
        c.server_version(cancel=token)
    assert sdk.API_VERSION == "2017-10-17"


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (
            reply("ping.auth-unknown-key"),
            sdk.HealthStatus(True, "ok", {"auth": "failed", "code": "AUTHENTICATION"}),
        ),
        (
            reply("createSecret.access-denied"),
            sdk.HealthStatus(True, "ok", {"auth": "failed", "code": "PERMISSION_DENIED"}),
        ),
        (
            aws_error("ThrottlingException"),
            sdk.HealthStatus(True, "degraded", {"code": "RATE_LIMITED"}),
        ),
        (
            aws_error("InternalServiceError", 500),
            sdk.HealthStatus(False, "unhealthy", {"httpStatus": "500", "error": "UNAVAILABLE"}),
        ),
        (
            aws_error("ValidationException"),
            sdk.HealthStatus(True, "ok", {"httpStatus": "400", "code": "VALIDATION"}),
        ),
    ],
)
def test_health_variants(aws: AwsMock, answer: AwsReply, expected: sdk.HealthStatus) -> None:
    aws.enqueue("ListSecrets", answer)
    with sdk.AwsSecretsManagerClient(
        aws_config(aws.url, retry=sdk.RetryPolicy(max_retries=3))
    ) as c:
        assert c.health() == expected
    assert aws.ops() == ["ListSecrets"]  # health never retries


def test_health_unreachable_and_timeout(aws: AwsMock) -> None:
    from _support import closed_port_url

    with sdk.AwsSecretsManagerClient(aws_config(closed_port_url())) as c:
        status = c.health()
        assert status.healthy is False
        assert status.status == "unreachable"
    aws.enqueue("ListSecrets", AwsReply(200, {}, delay=1.0))
    with sdk.AwsSecretsManagerClient(aws_config(aws.url, request_timeout=0.2)) as c:
        assert c.health().status == "unreachable"


def test_health_raises_cancel_and_config(aws: AwsMock) -> None:
    c = sdk.AwsSecretsManagerClient(aws_config(aws.url))
    token = sdk.CancelToken()
    token.cancel()
    with pytest.raises(sdk.CancelledError):
        c.health(cancel=token)
    c.close()
    with pytest.raises(sdk.CancelledError, match="closed"):
        c.health()


def test_ping_errors(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue(
        "ListSecrets", reply("ping.auth-bad-signature"), reply("createSecret.access-denied")
    )
    with pytest.raises(sdk.AuthenticationError) as info:
        c.ping()
    assert info.value.http_status == 403
    assert SECRET_KEY not in str(info.value)
    with pytest.raises(sdk.PermissionDeniedError):
        c.ping()


def test_close_is_idempotent_and_closes_owned_clients(aws: AwsMock) -> None:
    aws.defaults["ListSecrets"] = reply("ping.ok")
    c = sdk.AwsSecretsManagerClient(aws_config(aws.url))
    c.health()
    c.ping()
    assert not c.closed
    c.close()
    c.close()
    assert c.closed
    with pytest.raises(sdk.CancelledError, match="client is closed"):
        c.ping()


def test_with_sdk_client_never_closes_it() -> None:
    fake = FakeSecretsManager()
    fake.create_secret(Name="a", SecretString="1")
    c = sdk.AwsSecretsManagerClient.with_sdk_client(fake)
    assert c.sdk is fake
    assert c.get_secret_value("a").value.reveal() == "1"
    assert c.health().healthy
    c.close()
    assert not fake.closed


def test_from_env_builds_a_working_client(aws: AwsMock) -> None:
    aws.defaults["ListSecrets"] = reply("ping.ok")
    env = {
        "GROW_AWS_SECRETS_MANAGER_URL": aws.url,
        "AWS_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "AKIAENV",
        "AWS_SECRET_ACCESS_KEY": SECRET_KEY,
        "AWS_SESSION_TOKEN": SESSION_TOKEN,
    }
    with sdk.AwsSecretsManagerClient.from_env(env) as c:
        assert c.ping() >= 0
        assert SECRET_KEY not in repr(c)
        assert set(c.known_secrets()) == {SECRET_KEY, SESSION_TOKEN}
    seen = aws.last("ListSecrets")
    assert "AKIAENV/" in seen.headers["Authorization"]
    assert seen.headers["X-Amz-Security-Token"] == SESSION_TOKEN


def test_default_config_comes_from_the_environment(
    aws: AwsMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GROW_AWS_SECRETS_MANAGER_URL", aws.url)
    monkeypatch.setenv("GROW_AWS_SECRETS_MANAGER_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAENV")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SECRET_KEY)
    with sdk.AwsSecretsManagerClient() as c:
        assert c.config.url == aws.url


def test_build_errors_are_config_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_CONFIG_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent/grow-config")
    with pytest.raises(sdk.ConfigError, match="no AWS region"):
        sdk.AwsSecretsManagerClient(sdk.AwsSecretsManagerConfig())
    with pytest.raises(sdk.ConfigError):
        sdk.AwsSecretsManagerClient(sdk.AwsSecretsManagerConfig(profile="grow-missing-profile"))
    import grow_aws_secrets_manager.client as client_module

    def broken(*_: Any) -> Any:
        raise RuntimeError("no session for you")

    monkeypatch.setattr(client_module, "build_session", broken)
    with pytest.raises(sdk.ConfigError, match="cannot build the AWS SDK client"):
        sdk.AwsSecretsManagerClient(sdk.AwsSecretsManagerConfig(region="us-east-1"))


# --------------------------------------------------------------------------- transport


def test_user_agent_headers_and_hooks(aws: AwsMock) -> None:
    aws.enqueue("ListSecrets", aws_error("InternalServiceError", 500), reply("ping.ok"))
    events: list[Any] = []
    hooks = sdk.Hooks(on_request=events.append, on_response=events.append, on_error=events.append)
    cfg = aws_config(
        aws.url,
        hooks=hooks,
        headers={"X-Grow-Test": "yes"},
        user_agent_suffix="my-app/1.0",
        retry=sdk.RetryPolicy(max_retries=1),
        session_token=SESSION_TOKEN,
    )
    with sdk.AwsSecretsManagerClient(cfg) as c:
        c.ping()
    seen = aws.seen[-1]
    assert seen.headers["X-Grow-Test"] == "yes"
    assert "grow-codes-aws-secrets-manager/" in seen.headers["User-Agent"]
    assert "(python) my-app/1.0" in seen.headers["User-Agent"]
    kinds = [type(e).__name__ for e in events]
    assert kinds == ["RequestInfo", "ResponseInfo", "RequestInfo", "ResponseInfo"]
    assert [e.attempt for e in events] == [1, 1, 2, 2]
    assert events[1].status == 500
    assert events[3].status == 200
    assert events[3].request_id
    assert events[3].duration_ms >= 0
    assert events[0].headers["Authorization"] == sdk.REDACTED
    assert events[0].headers["X-Amz-Security-Token"] == sdk.REDACTED
    for e in events:
        assert SESSION_TOKEN not in repr(e)


def test_on_error_hook_for_final_errors_and_network_attempts(aws: AwsMock) -> None:
    from _support import closed_port_url

    errors: list[sdk.ErrorInfo] = []
    hooks = sdk.Hooks(on_error=errors.append)
    aws.enqueue("DescribeSecret", reply("describeSecret.not-found"))
    with sdk.AwsSecretsManagerClient(aws_config(aws.url, hooks=hooks)) as c:
        with pytest.raises(sdk.NotFoundError):
            c.describe_secret("missing")
    assert len(errors) == 1
    assert errors[0].will_retry is False
    assert errors[0].attempt == 1
    assert isinstance(errors[0].error, sdk.NotFoundError)
    errors.clear()
    with sdk.AwsSecretsManagerClient(aws_config(closed_port_url(), hooks=hooks)) as c:
        with pytest.raises(sdk.UnavailableError):
            c.ping()
    assert errors
    assert isinstance(errors[0].error, sdk.UnavailableError)


def test_logger_receives_redacted_debug_lines(aws: AwsMock) -> None:
    lines: list[tuple[str, Any]] = []

    class Log:
        def debug(self, msg: str, fields: Any = None) -> None:
            lines.append((msg, fields))

        info = warn = error = debug

    aws.enqueue("ListSecrets", reply("ping.ok"))
    with sdk.AwsSecretsManagerClient(aws_config(aws.url, logger=Log())) as c:
        c.ping()
    assert [m for m, _ in lines] == ["aws request", "aws response"]
    assert SECRET_KEY not in repr(lines)


def test_retries_use_max_retries(aws: AwsMock) -> None:
    aws.enqueue("GetSecretValue", *[aws_error("ThrottlingException")] * 3)
    cfg = aws_config(aws.url, retry=sdk.RetryPolicy(max_retries=2))
    with sdk.AwsSecretsManagerClient(cfg) as c:
        with pytest.raises(sdk.RateLimitError):
            c.get_secret_value("x")
    assert aws.ops() == ["GetSecretValue"] * 3


def test_total_timeout_and_cancel(aws: AwsMock) -> None:
    aws.defaults["GetSecretValue"] = AwsReply(200, {}, delay=0.6)
    with sdk.AwsSecretsManagerClient(aws_config(aws.url, total_timeout=0.1)) as c:
        started = time.monotonic()
        with pytest.raises(sdk.TimeoutError, match="total timeout"):
            c.get_secret_value("x")
        assert time.monotonic() - started < 0.5
    with sdk.AwsSecretsManagerClient(aws_config(aws.url)) as c:
        token = sdk.CancelToken()
        threading.Timer(0.1, token.cancel).start()
        with pytest.raises(sdk.CancelledError):
            c.get_secret_value("x", cancel=token)
        with pytest.raises(sdk.CancelledError):
            c.get_secret_value("x", cancel=token)


def test_tls_and_proxy_settings(aws: AwsMock) -> None:
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    cfg = aws_config(
        "https://secretsmanager.example",
        tls=sdk.TlsConfig(ca_cert_pem=pem, client_cert_path="/c.pem", client_key_path="/k.pem"),
        proxy="http://proxy.local:3128",
    )
    c = sdk.AwsSecretsManagerClient(cfg)
    path = c._tls.path
    assert path is not None
    with open(path, encoding="utf-8") as fh:
        assert fh.read() == pem
    boto_cfg = c.sdk.meta.config
    assert boto_cfg.proxies == {
        "http": "http://proxy.local:3128",
        "https": "http://proxy.local:3128",
    }
    assert boto_cfg.client_cert == ("/c.pem", "/k.pem")
    assert boto_cfg.retries["total_max_attempts"] == 1
    c.close()
    import os

    assert not os.path.exists(path)
    with sdk.AwsSecretsManagerClient(
        aws_config(aws.url, tls=sdk.TlsConfig(ca_cert_path="/etc/ssl/certs/ca-certificates.crt"))
    ) as c2:
        assert c2.sdk.meta.config.proxies == {}
    import grow_aws_secrets_manager._sdk as internals

    internals._insecure_warned = False
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with sdk.AwsSecretsManagerClient(
            aws_config(aws.url, tls=sdk.TlsConfig(insecure_skip_verify=True))
        ) as c3:
            c3.close()
        with sdk.AwsSecretsManagerClient(
            aws_config(aws.url, tls=sdk.TlsConfig(insecure_skip_verify=True))
        ):
            pass
    assert len([w for w in caught if "TLS verification is disabled" in str(w.message)]) == 1


def test_attempt_header_parsing() -> None:
    from grow_aws_secrets_manager._sdk import parse_attempt

    assert parse_attempt("attempt=3; max=4") == 3
    assert parse_attempt(b"ttl=1; attempt=2") == 2
    assert parse_attempt(None) == 1
    assert parse_attempt("attempt=x") == 1


def test_instrument_tolerates_missing_context() -> None:
    from grow_aws_secrets_manager._core.hooks import SdkLogger
    from grow_aws_secrets_manager._sdk import Instrument

    seen: list[Any] = []
    cfg = aws_config("http://x", hooks=sdk.Hooks(on_response=seen.append, on_error=seen.append))
    inst = Instrument(cfg, SdkLogger(), 2)
    inst.response_received(response_dict={"status_code": 200, "headers": {}}, context=None)
    inst.response_received(context={"retries": {"attempt": 1}}, exception=RuntimeError("x"))
    inst.response_received(context={})
    assert isinstance(seen[0], sdk.ResponseInfo)
    assert isinstance(seen[1], sdk.ErrorInfo)
    assert seen[1].will_retry is True
    no_hooks = Instrument(aws_config("http://x"), SdkLogger(), 1)
    no_hooks.response_received(response_dict={"status_code": 200, "headers": {}}, context={})
    no_hooks.response_received(context={}, exception=RuntimeError("x"))


# --------------------------------------------------------------------------- read


def test_get_secret_value_variants(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue(
        "GetSecretValue",
        reply("getSecretValue.ok-string"),
        reply("getSecretValue.ok-binary"),
        reply("getSecretValue.ok-version-stage"),
        reply("getSecretValue.not-found"),
        reply("getSecretValue.marked-deleted"),
    )
    s = c.get_secret_value(SEED)
    assert s.name == SEED
    assert s.binary is False
    assert s.value.version == s.version_id
    assert s.version_stages == ("AWSCURRENT",)
    assert s.created_date is not None
    assert s.created_date.tzinfo == dt.timezone.utc
    assert "REDACTED" in repr(s)
    b = c.get_secret_value("sdkv-0badc0de/app/blob")
    assert b.binary is True
    assert b.value.reveal_bytes() == bytes([0, 1, 2, 0xFE, 0xFF])
    c.get_secret_value(SEED, version_stage="AWSPREVIOUS", version_id=VID)
    assert aws.last("GetSecretValue").body == {
        "SecretId": SEED,
        "VersionId": VID,
        "VersionStage": "AWSPREVIOUS",
    }
    with pytest.raises(sdk.NotFoundError) as nf:
        c.get_secret_value("missing")
    assert nf.value.request_id
    with pytest.raises(sdk.ConflictError) as deleted:
        c.get_secret_value("deleted")
    assert sdk.aws_error_code(deleted.value) == "InvalidRequestException"
    with pytest.raises(sdk.ValidationError, match="must not be empty"):
        c.get_secret_value(" ")


def test_batch_get_secret_value(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue("BatchGetSecretValue", reply("batchGetSecretValue.ids-partial"))
    ids = ["sdkv-0badc0de/app/blob", "sdkv-0badc0de/missing", SEED]
    res = c.batch_get_secret_value(ids)
    assert [v.name for v in res.secret_values] == ["sdkv-0badc0de/app/blob", SEED]
    assert res.errors == (
        sdk.BatchGetError(
            "sdkv-0badc0de/missing",
            "ResourceNotFoundException",
            "Secrets Manager can't find the specified secret.",
        ),
    )
    aws.enqueue(
        "BatchGetSecretValue",
        reply("batchGetSecretValue.filters"),
        reply("batchGetSecretValue.filters-page2"),
    )
    filtered = c.batch_get_secret_value(
        filters=[sdk.SecretFilter("name", ["sdkv-0badc0de/app/"])], max_results=1
    )
    assert len(filtered.secret_values) >= 2
    assert aws.last("BatchGetSecretValue").body["NextToken"]
    assert aws.last("BatchGetSecretValue").body["MaxResults"] == 1
    many = [f"s{i}" for i in range(45)]
    aws.defaults["BatchGetSecretValue"] = AwsReply(200, {"SecretValues": [], "Errors": []})
    aws.enqueue(
        "BatchGetSecretValue",
        AwsReply(200, {"SecretValues": [], "NextToken": "t2"}),
    )
    c.batch_get_secret_value(many)
    sizes = [len(s.body["SecretIdList"]) for s in aws.seen if "SecretIdList" in s.body][-4:]
    assert sizes == [20, 20, 20, 5]
    with pytest.raises(sdk.ValidationError, match="not both"):
        c.batch_get_secret_value(["a"], filters=[sdk.SecretFilter("name", ["a"])])
    with pytest.raises(sdk.ValidationError, match="at least one filter"):
        c.batch_get_secret_value()
    with pytest.raises(sdk.ValidationError, match="list of ids"):
        c.batch_get_secret_value("abc")


def test_describe_and_list(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue("DescribeSecret", reply("describeSecret.ok"))
    d = c.describe_secret(SEED)
    assert d.description == "grow sdk verify"
    assert d.tags == {"team": "sdk", "env": "test"}
    assert d.version_id_for_stage() == "73aafff8-79d7-4072-979c-81f2920c7e30"
    assert d.version_id_for_stage("NOPE") is None
    assert not d.pending_deletion
    assert d.last_accessed_date is None
    aws.enqueue("ListSecrets", reply("listSecrets.page1"), reply("listSecrets.page2"))
    pager = c.list_secrets(
        filters=[sdk.SecretFilter("name", ["sdkv-0badc0de/page/"])],
        max_results=2,
        sort_order="asc",
        include_planned_deletion=False,
    )
    items = pager.to_list()
    assert len(items) >= 3
    first = aws.seen[-2].body
    assert first["Filters"] == [{"Key": "name", "Values": ["sdkv-0badc0de/page/"]}]
    assert first["SortOrder"] == "asc"
    assert first["IncludePlannedDeletion"] is False
    assert aws.seen[-1].body["NextToken"]
    aws.enqueue("ListSecrets", reply("listSecrets.bad-filter"))
    with pytest.raises(sdk.ValidationError):
        list(c.list_secrets(filters=[sdk.SecretFilter("name", ["x"])]))


def test_list_secret_version_ids(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue("ListSecretVersionIds", reply("listSecretVersionIds.ok"))
    versions = c.list_secret_version_ids(SEED, include_deprecated=True, max_results=10).to_list()
    assert len(versions) == 4
    assert versions[1].version_stages == ("AWSCURRENT",)
    assert versions[0].last_accessed_date is not None
    assert aws.last("ListSecretVersionIds").body == {
        "SecretId": SEED,
        "IncludeDeprecated": True,
        "MaxResults": 10,
    }
    aws.enqueue("ListSecretVersionIds", aws_error("ResourceNotFoundException"))
    with pytest.raises(sdk.NotFoundError):
        list(c.list_secret_version_ids("missing"))
    with pytest.raises(sdk.ValidationError):
        c.list_secret_version_ids("")


# --------------------------------------------------------------------------- write


def test_create_secret(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue(
        "CreateSecret",
        reply("createSecret.ok-string"),
        reply("createSecret.no-value"),
        reply("createSecret.exists"),
        reply("createSecret.ok-binary"),
        reply("createSecret.ok-string"),
    )
    r = c.create_secret(
        "app/new",
        "v",
        description="d",
        kms_key_id="alias/k",
        tags={"t": "1"},
        client_request_token="tok-" + "0" * 30,
        add_replica_regions=[sdk.ReplicaRegion("eu-west-1"), sdk.ReplicaRegion("eu-west-2", "k2")],
        force_overwrite_replica_secret=True,
    )
    assert r.version_id
    body = aws.last("CreateSecret").body
    assert body["SecretString"] == "v"
    assert body["Tags"] == [{"Key": "t", "Value": "1"}]
    assert body["AddReplicaRegions"] == [
        {"Region": "eu-west-1"},
        {"Region": "eu-west-2", "KmsKeyId": "k2"},
    ]
    assert body["ForceOverwriteReplicaSecret"] is True
    empty = c.create_secret("app/empty")
    assert empty.version_id is None
    assert "SecretString" not in aws.last("CreateSecret").body
    with pytest.raises(sdk.ConflictError):
        c.create_secret("app/new", "again")
    c.create_secret("app/bin", bytearray(b"\x00\x01"))
    assert aws.last("CreateSecret").body["SecretBinary"] == "AAE="
    c.create_secret("app/obj", {"a": [1, 2]})
    assert json.loads(aws.last("CreateSecret").body["SecretString"]) == {"a": [1, 2]}
    with pytest.raises(sdk.ValidationError, match="JSON-serialisable"):
        c.create_secret("app/bad", {1, 2})


def test_put_update_stage(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue(
        "PutSecretValue", reply("putSecretValue.ok"), reply("putSecretValue.token-reuse-different")
    )
    put = c.put_secret_value(
        SEED, "v2", version_stages=["AWSCURRENT"], client_request_token="t" * 32
    )
    assert put.version_stages == ("AWSCURRENT",)
    assert put.version_id
    assert aws.last("PutSecretValue").body["VersionStages"] == ["AWSCURRENT"]
    with pytest.raises(sdk.ConflictError):
        c.put_secret_value(SEED, sdk.SecretValue(b"\xff"))
    assert aws.last("PutSecretValue").body["SecretBinary"] == "/w=="
    aws.enqueue("UpdateSecret", reply("updateSecret.value"), reply("updateSecret.description"))
    assert c.update_secret(
        SEED, value="v3", kms_key_id="k", client_request_token="u" * 32
    ).version_id
    assert c.update_secret(SEED, description="new").version_id is None
    assert aws.last("UpdateSecret").body == {
        "SecretId": SEED,
        "Description": "new",
        "ClientRequestToken": aws.last("UpdateSecret").body["ClientRequestToken"],
    }
    aws.enqueue(
        "UpdateSecretVersionStage",
        reply("updateSecretVersionStage.move"),
        reply("updateSecretVersionStage.missing-remove"),
    )
    ref = c.update_secret_version_stage(
        SEED, "STAGEX", move_to_version_id=VID, remove_from_version_id=VID2
    )
    assert ref.name == SEED
    with pytest.raises(sdk.ValidationError):
        c.update_secret_version_stage(SEED, "AWSCURRENT", move_to_version_id=VID)
    with pytest.raises(sdk.ValidationError, match="move_to_version_id"):
        c.update_secret_version_stage(SEED, "X")
    with pytest.raises(sdk.ValidationError, match="version_stage"):
        c.update_secret_version_stage(SEED, "", move_to_version_id="v")


def test_delete_and_restore(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue(
        "DeleteSecret",
        reply("deleteSecret.recovery-window"),
        reply("deleteSecret.force"),
        reply("deleteSecret.already-deleted"),
    )
    d = c.delete_secret(SEED, recovery_window_days=7)
    assert d.deletion_date is not None
    assert aws.last("DeleteSecret").body == {"SecretId": SEED, "RecoveryWindowInDays": 7}
    c.delete_secret(SEED, force_delete_without_recovery=True)
    assert aws.last("DeleteSecret").body == {"SecretId": SEED, "ForceDeleteWithoutRecovery": True}
    with pytest.raises(sdk.ConflictError):
        c.delete_secret(SEED)
    for bad in (6, 31, True):
        with pytest.raises(sdk.ValidationError, match="7 to 30"):
            c.delete_secret(SEED, recovery_window_days=bad)
    with pytest.raises(sdk.ValidationError, match="mutually exclusive"):
        c.delete_secret(SEED, recovery_window_days=7, force_delete_without_recovery=True)
    aws.enqueue("RestoreSecret", reply("restoreSecret.ok"), reply("restoreSecret.not-found"))
    assert c.restore_secret(SEED).name
    with pytest.raises(sdk.NotFoundError):
        c.restore_secret("missing")


# --------------------------------------------------------------------------- tags + policy


def test_tags_and_policies(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue("TagResource", reply("tagResource.ok"), reply("tagResource.not-found"))
    c.tag_resource(SEED, {"a": "1"})
    assert aws.last("TagResource").body == {"SecretId": SEED, "Tags": [{"Key": "a", "Value": "1"}]}
    with pytest.raises(sdk.NotFoundError):
        c.tag_resource("missing", {"a": "1"})
    aws.enqueue("UntagResource", reply("untagResource.ok"))
    c.untag_resource(SEED, ["a"])
    assert aws.last("UntagResource").body == {"SecretId": SEED, "TagKeys": ["a"]}
    with pytest.raises(sdk.ValidationError):
        c.untag_resource(SEED, "a")
    policy = {"Version": "2012-10-17", "Statement": []}
    aws.enqueue("PutResourcePolicy", reply("putResourcePolicy.ok"))
    assert c.put_resource_policy(SEED, policy, block_public_policy=True).name
    body = aws.last("PutResourcePolicy").body
    assert json.loads(body["ResourcePolicy"]) == policy
    assert body["BlockPublicPolicy"] is True
    aws.enqueue("GetResourcePolicy", reply("getResourcePolicy.ok"), reply("getResourcePolicy.none"))
    got = c.get_resource_policy(SEED)
    assert got.resource_policy
    assert got.policy is not None
    none = c.get_resource_policy(SEED)
    assert none.resource_policy is None
    assert none.policy is None
    aws.enqueue("DeleteResourcePolicy", reply("deleteResourcePolicy.ok"))
    assert c.delete_resource_policy(SEED).name
    aws.enqueue(
        "ValidateResourcePolicy",
        AwsReply(
            200,
            {
                "PolicyValidationPassed": False,
                "ValidationErrors": [{"CheckName": "c", "ErrorMessage": "m"}],
            },
        ),
        reply("validateResourcePolicy.moto-unsupported"),
    )
    result = c.validate_resource_policy('{"Version":"2012-10-17"}', secret_id=SEED)
    assert result == sdk.ValidateResourcePolicyResult(False, (sdk.PolicyValidationError("c", "m"),))
    assert aws.last("ValidateResourcePolicy").body["SecretId"] == SEED
    with pytest.raises(sdk.UnsupportedError):
        c.validate_resource_policy(policy)


# --------------------------------------------------------------------------- rotation + utils


def test_rotation(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue(
        "RotateSecret", reply("rotateSecret.rules-only"), reply("rotateSecret.lambda-not-found")
    )
    rules = sdk.RotationRules(automatically_after_days=30, duration="3h")
    assert c.rotate_secret(
        SEED, rules=rules, rotate_immediately=False, client_request_token="r" * 32
    ).version_id
    body = aws.last("RotateSecret").body
    assert body["RotationRules"] == {"AutomaticallyAfterDays": 30, "Duration": "3h"}
    assert body["RotateImmediately"] is False
    with pytest.raises(sdk.NotFoundError):
        c.rotate_secret(
            SEED,
            lambda_arn="arn:aws:lambda:us-east-1:123456789012:function:f",
            rules=sdk.RotationRules(schedule_expression="rate(10 days)"),
        )
    assert aws.last("RotateSecret").body["RotationRules"] == {"ScheduleExpression": "rate(10 days)"}
    aws.enqueue(
        "CancelRotateSecret", reply("cancelRotateSecret.ok"), reply("cancelRotateSecret.not-found")
    )
    assert c.cancel_rotate_secret(SEED).name
    with pytest.raises(sdk.NotFoundError):
        c.cancel_rotate_secret("missing")


def test_random_password_and_json_field(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.enqueue(
        "GetRandomPassword", reply("getRandomPassword.ok"), reply("getRandomPassword.too-short")
    )
    p = c.get_random_password(
        length=24,
        exclude_characters="abc",
        exclude_numbers=False,
        exclude_punctuation=True,
        exclude_uppercase=False,
        exclude_lowercase=False,
        include_space=False,
        require_each_included_type=True,
    )
    assert isinstance(p, sdk.Secret)
    assert p.reveal()
    assert p.reveal() not in str(p)
    assert aws.last("GetRandomPassword").body["PasswordLength"] == 24
    with pytest.raises(sdk.ValidationError):
        c.get_random_password(length=2)
    aws.defaults["GetSecretValue"] = reply("getSecretValue.json-seed")
    seed = "grow-bootstrap/seed-json"
    assert c.get_json_field(seed, "username") == "seed-user"
    assert c.get_json_field(seed, "port", version_stage="AWSCURRENT") == 5432
    assert c.get_json_field(seed, "missing") is None
    assert c.get_json_field(seed, "username.deep") is None
    aws.defaults["GetSecretValue"] = AwsReply(
        200, {"ARN": "a", "Name": "n", "SecretString": '{"db": {"host": "h", "a.b": 1}, "a.b": 2}'}
    )
    assert c.get_json_field("n", "db.host") == "h"
    assert c.get_json_field("n", "a.b") == 2
    for body, message in (
        ({"ARN": "a", "Name": "n", "SecretString": "not json"}, "not valid JSON"),
        ({"ARN": "a", "Name": "n", "SecretString": "[1]"}, "not a JSON object"),
        ({"ARN": "a", "Name": "n", "SecretBinary": "AAE="}, "binary"),
    ):
        aws.defaults["GetSecretValue"] = AwsReply(200, body)
        with pytest.raises(sdk.ValidationError, match=message):
            c.get_json_field("n", "x")


def test_secret_cache_factory(aws: AwsMock, c: sdk.AwsSecretsManagerClient) -> None:
    aws.defaults["GetSecretValue"] = reply("getSecretValue.ok-string")
    cache = c.secret_cache(ttl_s=60)
    assert isinstance(cache, sdk.AwsSecretCache)
    assert cache.get_secret_string(SEED)
    assert cache.get_secret_string(SEED)
    assert aws.ops().count("GetSecretValue") == 1
    assert isinstance(c.secrets(), sdk.AwsSecretsManagerSecretsProvider)
