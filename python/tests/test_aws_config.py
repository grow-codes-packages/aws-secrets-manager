"""AwsSecretsManagerConfig: defaults, env precedence, credential layering, validation, repr."""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

import grow_aws_secrets_manager as sdk

KEY = "AKIAGROWTESTKEY00001"
SECRET = "grow-test-secret-key-0001"


def test_defaults_and_effective_url() -> None:
    cfg = sdk.AwsSecretsManagerConfig()
    assert cfg.url == ""
    assert cfg.endpoint is None
    assert cfg.effective_url == "https://secretsmanager.us-east-1.amazonaws.com"
    assert cfg.recovery_window_days == sdk.DEFAULT_RECOVERY_WINDOW_DAYS == 30
    assert cfg.role_session_name == sdk.DEFAULT_ROLE_SESSION_NAME == "grow-sdk"
    regional = sdk.AwsSecretsManagerConfig(region="eu-central-1", url="http://moto:5000")
    assert regional.endpoint == "http://moto:5000"
    assert regional.effective_url == "http://moto:5000"
    assert (
        sdk.AwsSecretsManagerConfig(region="eu-central-1").effective_url
        == "https://secretsmanager.eu-central-1.amazonaws.com"
    )
    blank = sdk.AwsSecretsManagerConfig(region=" ", profile="", role_session_name=" ")
    assert blank.region is None
    assert blank.profile is None
    assert blank.role_session_name == "grow-sdk"


def test_from_env_precedence() -> None:
    env = {
        "GROW_AWS_SECRETS_MANAGER_URL": "http://grow:1",
        "AWS_ENDPOINT_URL_SECRETS_MANAGER": "http://svc:2",
        "AWS_ENDPOINT_URL": "http://all:3",
        "AWS_REGION": "eu-west-1",
        "AWS_DEFAULT_REGION": "us-west-2",
        "AWS_PROFILE": "dev",
        "GROW_AWS_SECRETS_MANAGER_ROLE_ARN": "arn:aws:iam::1:role/r",
        "GROW_AWS_SECRETS_MANAGER_ROLE_SESSION_NAME": "sess",
        "GROW_AWS_SECRETS_MANAGER_EXTERNAL_ID": "ext-1234",
        "GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS": "7",
        "GROW_AWS_SECRETS_MANAGER_REQUEST_TIMEOUT": "5s",
        "GROW_AWS_SECRETS_MANAGER_MAX_RETRIES": "1",
    }
    cfg = sdk.AwsSecretsManagerConfig.from_env(env)
    assert cfg.url == "http://grow:1"
    assert cfg.region == "eu-west-1"
    assert cfg.profile == "dev"
    assert cfg.role_arn == "arn:aws:iam::1:role/r"
    assert cfg.role_session_name == "sess"
    assert cfg.external_id == sdk.Secret("ext-1234")
    assert cfg.recovery_window_days == 7
    assert cfg.request_timeout == 5.0
    assert cfg.retry.max_retries == 1
    del env["GROW_AWS_SECRETS_MANAGER_URL"]
    assert sdk.AwsSecretsManagerConfig.from_env(env).url == "http://svc:2"
    del env["AWS_ENDPOINT_URL_SECRETS_MANAGER"]
    assert sdk.AwsSecretsManagerConfig.from_env(env).url == "http://all:3"
    del env["AWS_REGION"]
    assert sdk.AwsSecretsManagerConfig.from_env(env).region == "us-west-2"
    env["GROW_AWS_SECRETS_MANAGER_REGION"] = "ap-south-1"
    assert sdk.AwsSecretsManagerConfig.from_env(env, region="sa-east-1").region == "sa-east-1"
    assert sdk.AwsSecretsManagerConfig.from_env(env).region == "ap-south-1"
    assert sdk.AwsSecretsManagerConfig.from_env({}).region is None


def test_credentials_come_from_one_layer() -> None:
    aws = {
        "AWS_ACCESS_KEY_ID": "AKIAVENDOR",
        "AWS_SECRET_ACCESS_KEY": "vendor-secret",
        "AWS_SESSION_TOKEN": "vendor-token",
    }
    cfg = sdk.AwsSecretsManagerConfig.from_env(aws)
    assert cfg.access_key_id == "AKIAVENDOR"
    assert cfg.secret_access_key == sdk.Secret("vendor-secret")
    assert cfg.session_token == sdk.Secret("vendor-token")
    grow = {
        **aws,
        "GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID": KEY,
        "GROW_AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY": SECRET,
    }
    cfg = sdk.AwsSecretsManagerConfig.from_env(grow)
    assert cfg.access_key_id == KEY
    assert cfg.secret_access_key == sdk.Secret(SECRET)
    assert cfg.session_token is None  # never mixed with AWS_SESSION_TOKEN
    with pytest.raises(sdk.ConfigError, match="requires secret_access_key"):
        sdk.AwsSecretsManagerConfig.from_env({"GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID": KEY})


def test_explicit_sdk_client_or_credentials_replace_env_credentials() -> None:
    env = {
        "AWS_ACCESS_KEY_ID": KEY,
        "AWS_SECRET_ACCESS_KEY": SECRET,
        "AWS_REGION": "eu-west-1",
        "AWS_PROFILE": "p",
        "GROW_AWS_SECRETS_MANAGER_URL": "http://x:1",
        "GROW_AWS_SECRETS_MANAGER_ROLE_ARN": "arn:aws:iam::1:role/r",
    }
    marker = object()
    cfg = sdk.AwsSecretsManagerConfig.from_env(env, sdk_client=marker)
    assert cfg.sdk_client is marker
    assert cfg.access_key_id is None
    assert cfg.region is None
    assert cfg.url == ""
    assert cfg.profile is None
    assert cfg.role_arn is None
    creds = object()
    cfg = sdk.AwsSecretsManagerConfig.from_env(env, credentials=creds)
    assert cfg.credentials is creds
    assert cfg.access_key_id is None
    assert cfg.region == "eu-west-1"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"region": "EU West"}, "region must look like"),
        ({"secret_access_key": SECRET}, "requires access_key_id"),
        ({"access_key_id": KEY}, "requires secret_access_key"),
        ({"session_token": "t"}, "session_token requires"),
        (
            {"access_key_id": KEY, "secret_access_key": SECRET, "credentials": object()},
            "mutually exclusive",
        ),
        ({"sdk_client": object(), "region": "us-east-1", "url": "http://x"}, "region, url"),
        ({"role_arn": "role/x"}, "must be an ARN"),
        ({"external_id": "e"}, "require role_arn"),
        ({"role_arn": "arn:aws:iam::1:role/r", "role_duration_s": 60}, "between 900"),
        ({"recovery_window_days": 6}, "7 to 30"),
        ({"recovery_window_days": True}, "7 to 30"),
        ({"url": "ftp://x"}, "http or https"),
        ({"connect_timeout": 0}, "positive"),
    ],
)
def test_validation(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(sdk.ConfigError, match=message):
        sdk.AwsSecretsManagerConfig(**kwargs).validate()


def test_role_duration_accepts_timedelta() -> None:
    cfg = sdk.AwsSecretsManagerConfig(
        role_arn="arn:aws:iam::1:role/r", role_duration_s=dt.timedelta(hours=1)
    ).validate()
    assert cfg.role_duration_s == 3600.0


def test_repr_redacts_every_credential() -> None:
    cfg = sdk.AwsSecretsManagerConfig(
        access_key_id=KEY,
        secret_access_key=SECRET,
        session_token="session-token-0001",
        role_arn="arn:aws:iam::1:role/r",
        external_id="external-0001",
    )
    text = repr(cfg)
    for secret in (SECRET, "session-token-0001", "external-0001"):
        assert secret not in text
    assert str(cfg) == text
    assert set(cfg.known_secrets()) == {SECRET, "session-token-0001", "external-0001"}
    with_objects = sdk.AwsSecretsManagerConfig(credentials=object())
    assert "credentials='[REDACTED]'" in repr(with_objects)

    class FakeBoto:
        pass

    assert repr(sdk.AwsSecretsManagerConfig(sdk_client=FakeBoto())).endswith("sdk_client=FakeBoto)")
