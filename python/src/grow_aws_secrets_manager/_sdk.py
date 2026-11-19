"""Builds the boto3 / aioboto3 clients from the Grow config and wires the SPEC 2.5 hooks.

Internal module. The AWS SDK signs, serialises, retries (standard mode, ``max_attempts =
max_retries + 1``) and parses; this module maps the Grow settings onto it:

* ``url`` → ``endpoint_url``; ``region`` → ``region_name``;
* ``connect_timeout`` / ``request_timeout`` → botocore ``connect_timeout`` / ``read_timeout``;
* ``proxy`` → botocore ``proxies`` (environment proxies are ignored unless set, SPEC 2.2);
* ``tls`` → ``verify`` (CA bundle path / PEM, or ``False`` for ``insecure_skip_verify``) and
  ``client_cert``;
* User-Agent → ``user_agent_extra`` (``grow-codes-aws-secrets-manager/<version> (python)``);
* ``headers`` and the hooks → botocore ``before-send`` / ``response-received`` events.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import threading
import time
import warnings
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.credentials import AssumeRoleCredentialFetcher, DeferredRefreshableCredentials
from botocore.exceptions import NoCredentialsError

from ._core import (
    ConfigError,
    ErrorInfo,
    RequestInfo,
    ResponseInfo,
    redact_headers,
    redact_url,
    user_agent,
)
from ._core.hooks import SdkLogger, call_hook
from .config import AwsSecretsManagerConfig
from .errors_map import map_aws_error

__all__: list[str] = []

SERVICE = "secretsmanager"
EVENT_ID = "secrets-manager"
#: Upper bound of the health probe timeouts (seconds).
HEALTH_TIMEOUT_S = 5.0

_insecure_warned = False


def parse_attempt(value: Any) -> int:
    """``attempt=2; max=4`` (``amz-sdk-request``) → 2; 1 when absent."""
    text = value.decode() if isinstance(value, bytes) else str(value or "")
    for part in text.split(";"):
        key, _, num = part.strip().partition("=")
        if key == "attempt" and num.isdigit():
            return int(num)
    return 1


class TlsFiles:
    """Owns a temporary CA bundle written from ``tls.ca_cert_pem`` (removed by :meth:`close`)."""

    def __init__(self, cfg: AwsSecretsManagerConfig) -> None:
        self.path: str | None = None
        self._cfg = cfg

    def verify(self) -> bool | str | None:
        """The botocore ``verify`` argument."""
        global _insecure_warned
        tls = self._cfg.tls
        if tls.insecure_skip_verify:
            if not _insecure_warned:
                _insecure_warned = True
                warnings.warn(
                    "grow_aws_secrets_manager: TLS verification is disabled (tests only)",
                    stacklevel=3,
                )
            return False
        if tls.ca_cert_path:
            return tls.ca_cert_path
        if tls.ca_cert_pem:
            if self.path is None:
                fd, path = tempfile.mkstemp(prefix="grow-aws-sm-ca-", suffix=".pem")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(tls.ca_cert_pem)
                self.path = path
            return self.path
        return None

    def close(self) -> None:
        if self.path is not None:
            with contextlib.suppress(OSError):
                os.unlink(self.path)
            self.path = None


def botocore_config(cfg: AwsSecretsManagerConfig, *, health: bool = False) -> BotoConfig:
    """The botocore client config for the Grow settings (``health``: 1 attempt, ≤ 5 s)."""
    connect = cfg.connect_timeout
    read = cfg.request_timeout
    attempts = cfg.retry.max_retries + 1
    if health:
        connect = min(connect, HEALTH_TIMEOUT_S)
        read = min(read, HEALTH_TIMEOUT_S)
        attempts = 1
    proxies: dict[str, str] = {}
    if cfg.proxy:
        proxies = {"http": cfg.proxy, "https": cfg.proxy}
    kwargs: dict[str, Any] = {
        "connect_timeout": connect,
        "read_timeout": read,
        "retries": {"mode": "standard", "total_max_attempts": attempts},
        "user_agent_extra": user_agent(cfg.user_agent_suffix),
        "proxies": proxies,
    }
    if cfg.region:
        kwargs["region_name"] = cfg.region
    if cfg.tls.client_cert_path and cfg.tls.client_key_path:
        kwargs["client_cert"] = (cfg.tls.client_cert_path, cfg.tls.client_key_path)
    return BotoConfig(**kwargs)


def client_kwargs(
    cfg: AwsSecretsManagerConfig, tls: TlsFiles, *, health: bool = False
) -> dict[str, Any]:
    """Keyword arguments of ``session.client("secretsmanager", ...)``."""
    kwargs: dict[str, Any] = {"config": botocore_config(cfg, health=health)}
    if cfg.endpoint:
        kwargs["endpoint_url"] = cfg.endpoint
    if cfg.region:
        kwargs["region_name"] = cfg.region
    verify = tls.verify()
    if verify is not None:
        kwargs["verify"] = verify
    return kwargs


def session_kwargs(cfg: AwsSecretsManagerConfig) -> dict[str, Any]:
    """Keyword arguments of ``boto3.Session`` / ``aioboto3.Session`` (base credentials)."""
    kwargs: dict[str, Any] = {}
    if cfg.access_key_id and cfg.secret_access_key:
        kwargs["aws_access_key_id"] = cfg.access_key_id
        kwargs["aws_secret_access_key"] = cfg.secret_access_key.reveal()
        if cfg.session_token:
            kwargs["aws_session_token"] = cfg.session_token.reveal()
    if cfg.profile:
        kwargs["profile_name"] = cfg.profile
    if cfg.region:
        kwargs["region_name"] = cfg.region
    return kwargs


def assume_role_args(cfg: AwsSecretsManagerConfig) -> dict[str, Any]:
    """``AssumeRole`` extra arguments (session name, external id, duration)."""
    extra: dict[str, Any] = {"RoleSessionName": cfg.role_session_name}
    if cfg.external_id:
        extra["ExternalId"] = cfg.external_id.reveal()
    if cfg.role_duration_s:
        extra["DurationSeconds"] = int(cfg.role_duration_s)
    return extra


def sts_kwargs(cfg: AwsSecretsManagerConfig, tls: TlsFiles) -> dict[str, Any]:
    """Client arguments of the STS client used by the assume-role helper."""
    kwargs: dict[str, Any] = {"config": botocore_config(cfg)}
    if cfg.region:
        kwargs["region_name"] = cfg.region
    verify = tls.verify()
    if verify is not None:
        kwargs["verify"] = verify
    return kwargs


def build_session(cfg: AwsSecretsManagerConfig, tls: TlsFiles) -> boto3.Session:
    """A boto3 session with the configured (or default-chain / assumed-role) credentials."""
    session = boto3.Session(**session_kwargs(cfg))
    if cfg.credentials is not None:
        session._session._credentials = cfg.credentials
    if cfg.role_arn is None:
        return session
    base = session
    role_arn = cfg.role_arn
    extra = assume_role_args(cfg)
    sts = sts_kwargs(cfg, tls)

    def refresh() -> dict[str, Any]:
        source = base.get_credentials()
        if source is None:
            raise NoCredentialsError()

        def creator(service: str, **kw: Any) -> Any:
            return base.client(service, **{**sts, **kw})

        fetcher = AssumeRoleCredentialFetcher(
            client_creator=creator,
            source_credentials=source,
            role_arn=role_arn,
            extra_args=dict(extra),
        )
        result: dict[str, Any] = fetcher.fetch_credentials()
        return result

    assumed = boto3.Session(region_name=cfg.region) if cfg.region else boto3.Session()
    assumed._session._credentials = DeferredRefreshableCredentials(
        refresh_using=refresh, method="assume-role"
    )
    return assumed


class Instrument:
    """botocore event handlers: extra headers, SPEC 2.5 hooks and debug logging."""

    def __init__(self, cfg: AwsSecretsManagerConfig, logger: SdkLogger, max_attempts: int) -> None:
        self._cfg = cfg
        self._log = logger
        self._max = max_attempts
        self._lock = threading.Lock()
        self._starts: dict[tuple[Any, int], tuple[float, str, str]] = {}

    def register(self, events: Any) -> None:
        events.register(f"before-send.{EVENT_ID}", self.before_send)
        events.register(f"response-received.{EVENT_ID}", self.response_received)

    def before_send(self, request: Any, **_: Any) -> None:
        for name, value in self._cfg.headers.items():
            request.headers[name] = value
        headers = {
            str(k): (v.decode("latin-1") if isinstance(v, bytes) else str(v))
            for k, v in request.headers.items()
        }
        attempt = parse_attempt(headers.get("amz-sdk-request"))
        invocation = headers.get("amz-sdk-invocation-id")
        url = redact_url(str(request.url))
        method = str(request.method)
        with self._lock:
            self._starts[(invocation, attempt)] = (time.monotonic(), method, url)
        hooks = self._cfg.hooks
        if hooks is not None:
            call_hook(hooks.on_request, RequestInfo(method, url, redact_headers(headers), attempt))
        self._log.debug("aws request", {"method": method, "url": url, "attempt": attempt})

    def response_received(
        self,
        response_dict: Any = None,
        context: Any = None,
        exception: BaseException | None = None,
        **_: Any,
    ) -> None:
        retries = (context or {}).get("retries") or {}
        attempt = int(retries.get("attempt") or 1)
        with self._lock:
            start = self._starts.pop((retries.get("invocation-id"), attempt), None)
        started, method, url = start or (time.monotonic(), "POST", redact_url(self._cfg.url))
        hooks = self._cfg.hooks
        if response_dict is not None:
            status = int(response_dict.get("status_code") or 0)
            headers = {str(k).lower(): v for k, v in (response_dict.get("headers") or {}).items()}
            duration = (time.monotonic() - started) * 1000.0
            request_id = headers.get("x-amzn-requestid")
            if hooks is not None:
                info = ResponseInfo(method, url, status, duration, attempt, request_id)
                call_hook(hooks.on_response, info)
            self._log.debug(
                "aws response",
                {"status": status, "attempt": attempt, "duration_ms": round(duration, 1)},
            )
        elif exception is not None:
            error = map_aws_error(exception, "request", known_secrets=self._cfg.known_secrets())
            will_retry = error.retryable and attempt < self._max
            if hooks is not None:
                call_hook(hooks.on_error, ErrorInfo(method, url, error, attempt, will_retry))
            self._log.debug("aws request failed", {"code": error.code.value, "attempt": attempt})


def build_async_session(cfg: AwsSecretsManagerConfig, tls: TlsFiles) -> Any:
    """An ``aioboto3.Session`` like :func:`build_session` (``ConfigError`` without aioboto3)."""
    try:
        import aioboto3  # noqa: PLC0415 - optional dependency (extra "async")
        from aiobotocore.credentials import (  # noqa: PLC0415
            AioAssumeRoleCredentialFetcher,
            AioDeferredRefreshableCredentials,
        )
    except ImportError:  # pragma: no cover - the test environment installs the extra
        raise ConfigError(
            "config: the async client needs aioboto3; install grow-aws-secrets-manager[async]"
        ) from None
    session = aioboto3.Session(**session_kwargs(cfg))
    if cfg.credentials is not None:
        session._session._credentials = cfg.credentials
    if cfg.role_arn is None:
        return session
    base = session
    role_arn = cfg.role_arn
    extra = assume_role_args(cfg)
    sts = sts_kwargs(cfg, tls)

    async def refresh() -> dict[str, Any]:
        source = await base._session.get_credentials()
        if source is None:
            raise NoCredentialsError()

        def creator(service: str, **kw: Any) -> Any:
            return base.client(service, **{**sts, **kw})

        fetcher = AioAssumeRoleCredentialFetcher(
            client_creator=creator,
            source_credentials=source,
            role_arn=role_arn,
            extra_args=dict(extra),
        )
        result: dict[str, Any] = await fetcher.fetch_credentials()
        return result

    assumed = aioboto3.Session(region_name=cfg.region) if cfg.region else aioboto3.Session()
    assumed._session._credentials = AioDeferredRefreshableCredentials(
        refresh_using=refresh, method="assume-role"
    )
    return assumed


def instrument(cfg: AwsSecretsManagerConfig, logger: SdkLogger, client: Any, attempts: int) -> None:
    """Registers the :class:`Instrument` handlers on a boto3 / aiobotocore client."""
    Instrument(cfg, logger, attempts).register(client.meta.events)
