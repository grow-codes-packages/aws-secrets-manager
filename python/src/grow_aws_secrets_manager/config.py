"""Configuration for the AWS Secrets Manager client.

Service-owned (generated once by sdk-kit). The Grow configuration maps onto the AWS SDK client
(boto3 / aioboto3, SPEC section 2.3 "Cloud SDK services"): ``url`` is the endpoint override,
the timeouts and ``retry.max_retries`` become the botocore client config, TLS and proxy go to
the botocore HTTP session, and credentials come from explicit fields or the standard AWS chain.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import re
from collections.abc import Mapping
from typing import Any, ClassVar, TypeVar

from ._core import BaseConfig, ConfigError, EnvReader, Secret, to_seconds
from ._core.redaction import REDACTED, safe_repr

__all__ = [
    "AwsSecretsManagerConfig",
    "DEFAULT_RECOVERY_WINDOW_DAYS",
    "DEFAULT_ROLE_SESSION_NAME",
    "URL_PLACEHOLDER",
    "VENDOR_ENV",
]

#: Default recovery window of ``delete_secret`` / ``SecretsProvider.delete`` in days (AWS default).
DEFAULT_RECOVERY_WINDOW_DAYS = 30

#: Default STS session name of the assume-role helper.
DEFAULT_ROLE_SESSION_NAME = "grow-sdk"

#: Stands in for an empty ``url`` (the SDK resolves the regional endpoint) when the common
#: configuration rules are checked.
URL_PLACEHOLDER = "https://secretsmanager.amazonaws.com"

#: Vendor variables read after ``GROW_AWS_SECRETS_MANAGER_<NAME>``, in precedence order.
VENDOR_ENV: Mapping[str, tuple[str, ...]] = {
    "URL": ("AWS_ENDPOINT_URL_SECRETS_MANAGER", "AWS_ENDPOINT_URL"),
    "REGION": ("AWS_REGION", "AWS_DEFAULT_REGION"),
    "ACCESS_KEY_ID": ("AWS_ACCESS_KEY_ID",),
    "SECRET_ACCESS_KEY": ("AWS_SECRET_ACCESS_KEY",),
    "SESSION_TOKEN": ("AWS_SESSION_TOKEN",),
    "PROFILE": ("AWS_PROFILE",),
}

_REGION = re.compile(r"^[a-z0-9-]+$")
_MIN_ROLE_DURATION_S = 900.0
_MAX_ROLE_DURATION_S = 43_200.0

_C = TypeVar("_C", bound="AwsSecretsManagerConfig")


@dataclasses.dataclass(frozen=True, repr=False)
class AwsSecretsManagerConfig(BaseConfig):
    """Immutable settings for :class:`~grow_aws_secrets_manager.AwsSecretsManagerClient`.

    Common fields (``url``, timeouts, ``retry``, ``tls``, ``proxy``, ``headers``,
    ``user_agent_suffix``, ``hooks``, ``logger``) come from :class:`BaseConfig`; durations are
    float seconds (``datetime.timedelta`` accepted). ``url`` is the **endpoint override**: empty
    (the default) lets the AWS SDK resolve ``https://secretsmanager.<region>.amazonaws.com``.

    AWS fields: ``region``, ``access_key_id``, ``secret_access_key`` and ``session_token``
    (stored as :class:`Secret`), ``profile``, ``credentials`` (a botocore credentials object used
    instead of the key fields), ``role_arn`` / ``role_session_name`` / ``external_id`` /
    ``role_duration_s`` (assume a role with STS on top of the base credentials),
    ``recovery_window_days`` (7-30, default 30) and ``sdk_client`` (an existing boto3 / aioboto3
    Secrets Manager client; mutually exclusive with the credential, region and endpoint fields).
    ``repr()`` never shows a credential.

    Environment (``from_env``), explicit value > ``GROW_AWS_SECRETS_MANAGER_<NAME>`` > AWS
    variable > default: ``URL`` (> ``AWS_ENDPOINT_URL_SECRETS_MANAGER`` > ``AWS_ENDPOINT_URL``),
    ``REGION`` (> ``AWS_REGION`` > ``AWS_DEFAULT_REGION``), ``ACCESS_KEY_ID`` /
    ``SECRET_ACCESS_KEY`` / ``SESSION_TOKEN`` (taken as one set from either the ``GROW_*`` or the
    ``AWS_*`` variables, never mixed), ``PROFILE`` (> ``AWS_PROFILE``), ``ROLE_ARN``,
    ``ROLE_SESSION_NAME``, ``EXTERNAL_ID``, ``RECOVERY_WINDOW_DAYS`` and the common
    ``CONNECT_TIMEOUT``, ``REQUEST_TIMEOUT``, ``TOTAL_TIMEOUT``, ``MAX_RETRIES``, ``CA_CERT``,
    ``CLIENT_CERT``, ``CLIENT_KEY``, ``INSECURE_SKIP_VERIFY``, ``PROXY``. Credentials left unset
    use the AWS SDK default chain (environment, shared config / SSO, web identity, container,
    instance metadata).
    """

    ENV_VENDOR: ClassVar[Mapping[str, tuple[str, ...]]] = {"URL": VENDOR_ENV["URL"]}

    url: str = ""
    region: str | None = None
    access_key_id: str | None = None
    secret_access_key: Secret | None = None
    session_token: Secret | None = None
    profile: str | None = None
    credentials: Any = dataclasses.field(default=None, repr=False)
    role_arn: str | None = None
    role_session_name: str = DEFAULT_ROLE_SESSION_NAME
    external_id: Secret | None = None
    role_duration_s: float | None = None
    recovery_window_days: int = DEFAULT_RECOVERY_WINDOW_DAYS
    sdk_client: Any = dataclasses.field(default=None, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        for name in ("region", "access_key_id", "profile", "role_arn"):
            value = getattr(self, name)
            if isinstance(value, str) and not value.strip():
                object.__setattr__(self, name, None)
        if not self.role_session_name or not self.role_session_name.strip():
            object.__setattr__(self, "role_session_name", DEFAULT_ROLE_SESSION_NAME)
        if self.role_duration_s is not None:
            duration: float | _dt.timedelta = self.role_duration_s
            object.__setattr__(self, "role_duration_s", to_seconds(duration))

    @property
    def endpoint(self) -> str | None:
        """The endpoint override passed to the AWS SDK (``None`` = the SDK resolves it)."""
        return self.url or None

    @property
    def effective_url(self) -> str:
        """The override, or the public endpoint of ``region`` (``us-east-1`` when unset)."""
        if self.url:
            return self.url
        return f"https://secretsmanager.{self.region or 'us-east-1'}.amazonaws.com"

    @classmethod
    def _env_values(cls, reader: EnvReader) -> dict[str, Any]:
        values = super()._env_values(reader)
        for field, suffix in (
            ("region", "REGION"),
            ("profile", "PROFILE"),
        ):
            found = reader.string(suffix, VENDOR_ENV[suffix])
            if found is not None:
                values[field] = found
        # Credentials from one layer only: a GROW_* key id never pairs with an AWS_* secret.
        grow_key = reader.string("ACCESS_KEY_ID")
        if grow_key is not None:
            layer: dict[str, str | None] = {
                "access_key_id": grow_key,
                "secret_access_key": reader.string("SECRET_ACCESS_KEY"),
                "session_token": reader.string("SESSION_TOKEN"),
            }
        else:
            vendor = EnvReader(reader._env, prefix="")
            layer = {
                "access_key_id": vendor.string("AWS_ACCESS_KEY_ID"),
                "secret_access_key": vendor.string("AWS_SECRET_ACCESS_KEY"),
                "session_token": vendor.string("AWS_SESSION_TOKEN"),
            }
        for field, value in layer.items():
            if value is not None:
                values[field] = value if field == "access_key_id" else Secret(value)
        for field, suffix in (
            ("role_arn", "ROLE_ARN"),
            ("role_session_name", "ROLE_SESSION_NAME"),
        ):
            found = reader.string(suffix)
            if found is not None:
                values[field] = found
        external_id = reader.string("EXTERNAL_ID")
        if external_id is not None:
            values["external_id"] = Secret(external_id)
        days = reader.int("RECOVERY_WINDOW_DAYS")
        if days is not None:
            values["recovery_window_days"] = days
        return values

    @classmethod
    def from_env(cls: type[_C], env: Mapping[str, str] | None = None, **overrides: Any) -> _C:
        """Build from the environment, then validate.

        Precedence: explicit keyword > ``GROW_AWS_SECRETS_MANAGER_<NAME>`` > AWS variables >
        default. An explicit ``sdk_client`` or ``credentials`` replaces the credentials found in
        the environment (an ``sdk_client`` also drops the environment's region, endpoint,
        profile and role). ``env`` defaults to ``os.environ``; pass a dict in tests.
        """
        values = cls._env_values(EnvReader(env))
        explicit = {k: v for k, v in overrides.items() if v is not None}
        if "sdk_client" in explicit or "credentials" in explicit:
            for key in ("access_key_id", "secret_access_key", "session_token"):
                values.pop(key, None)
            if "sdk_client" in explicit:
                for key in ("region", "url", "profile", "role_arn"):
                    values.pop(key, None)
        values.update(explicit)
        return cls(**values).validate()

    def validate(self: _C) -> _C:
        """Common checks plus the AWS rules; raises :class:`ConfigError`. Returns ``self``."""
        BaseConfig.validate(dataclasses.replace(self, url=self.url or URL_PLACEHOLDER))
        problems: list[str] = []
        if self.region is not None and not _REGION.match(self.region):
            problems.append("region must look like us-east-1")
        if self.access_key_id is not None and not self.secret_access_key:
            problems.append("access_key_id requires secret_access_key")
        if self.access_key_id is None and self.secret_access_key is not None:
            problems.append("secret_access_key requires access_key_id")
        if self.session_token is not None and self.access_key_id is None:
            problems.append("session_token requires access_key_id and secret_access_key")
        if self.credentials is not None and self.access_key_id is not None:
            problems.append(
                "credentials and access_key_id/secret_access_key are mutually exclusive"
            )
        if self.sdk_client is not None:
            clash = [
                name
                for name, value in (
                    ("access_key_id", self.access_key_id),
                    ("credentials", self.credentials),
                    ("profile", self.profile),
                    ("role_arn", self.role_arn),
                    ("region", self.region),
                    ("url", self.endpoint),
                )
                if value is not None
            ]
            if clash:
                problems.append(f"sdk_client is mutually exclusive with {', '.join(clash)}")
        if self.role_arn is not None and not self.role_arn.startswith("arn:"):
            problems.append("role_arn must be an ARN")
        if self.role_arn is None and (self.external_id is not None or self.role_duration_s):
            problems.append("external_id and role_duration_s require role_arn")
        if self.role_duration_s is not None and not (
            _MIN_ROLE_DURATION_S <= self.role_duration_s <= _MAX_ROLE_DURATION_S
        ):
            problems.append("role_duration_s must be between 900 and 43200")
        days = self.recovery_window_days
        if isinstance(days, bool) or not isinstance(days, int) or not 7 <= days <= 30:
            problems.append("recovery_window_days must be an integer from 7 to 30")
        if problems:
            raise ConfigError(f"config: {'; '.join(problems)}")
        return self

    def __repr__(self) -> str:
        text = safe_repr(self)
        extras = []
        if self.credentials is not None:
            extras.append(f"credentials={REDACTED!r}")
        if self.sdk_client is not None:
            extras.append(f"sdk_client={type(self.sdk_client).__name__}")
        if not extras:
            return text
        return f"{text[:-1]}, {', '.join(extras)})"

    __str__ = __repr__
