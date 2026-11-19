"""AWS Secrets Manager clients (sync on boto3, async on aioboto3).

SPEC section 2.3 "Cloud SDK services": the official AWS SDK is the transport. The clients build
a ``secretsmanager`` client from :class:`AwsSecretsManagerConfig` (region, credentials, endpoint
override, timeouts, standard retries, TLS, proxy, User-Agent, hooks) or wrap one the caller
passes (``sdk_client``), and map every AWS error by its AWS error code to the SDK error classes.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
import time
from collections.abc import Mapping, Sequence
from types import TracebackType
from typing import Any

from . import _ops as ops
from ._core import (
    AwsSecretsManagerError,
    CancelledError,
    CancelToken,
    ConfigError,
    ErrorCode,
    ErrorInfo,
    HealthStatus,
    ResourceRegistry,
    Secret,
    TimeoutError,
    UnsupportedError,
    redact_url,
)
from ._core.hooks import SdkLogger, call_hook
from ._sdk import SERVICE, TlsFiles, build_async_session, build_session, client_kwargs, instrument
from .config import AwsSecretsManagerConfig
from .errors_map import map_aws_error
from .models import (
    BATCH_GET_MAX_IDS,
    AwsSecretValue,
    BatchGetError,
    BatchGetResult,
    DeleteSecretResult,
    PutSecretValueResult,
    ReplicaRegion,
    ResourcePolicyResult,
    RotationRules,
    SecretDescription,
    SecretFilter,
    SecretRef,
    SecretVersion,
    SecretWriteResult,
    SortOrder,
    ValidateResourcePolicyResult,
    next_token,
    order_by_ids,
    parse_policy,
    to_batch_error,
    to_description,
    to_policy_error,
    to_ref,
    to_secret_value,
    to_version,
    to_write_result,
    utc,
)
from .paginator import AsyncPaginator, Paginator
from .provider import AsyncAwsSecretsManagerSecretsProvider, AwsSecretsManagerSecretsProvider
from .secret_cache import AsyncAwsSecretCache, AwsSecretCache

__all__ = ["AwsSecretsManagerClient", "AsyncAwsSecretsManagerClient"]


def _health_from_error(err: AwsSecretsManagerError) -> HealthStatus:
    code = err.code
    if code in (ErrorCode.CANCELLED, ErrorCode.CONFIG):
        raise err
    if code is ErrorCode.RATE_LIMITED:
        return HealthStatus(True, "degraded", {"code": code.value})
    if code in (ErrorCode.AUTHENTICATION, ErrorCode.PERMISSION_DENIED):
        return HealthStatus(True, "ok", {"auth": "failed", "code": code.value})
    if err.http_status is None:
        return HealthStatus(False, "unreachable", {"error": code.value})
    if err.http_status >= 500:
        details = {"httpStatus": str(err.http_status), "error": code.value}
        return HealthStatus(False, "unhealthy", details)
    return HealthStatus(True, "ok", {"httpStatus": str(err.http_status), "code": code.value})


def _unsupported_version(label: str) -> UnsupportedError:
    return UnsupportedError(f"{label}: AWS Secrets Manager does not expose a server version")


def _put_result(out: Mapping[str, Any]) -> PutSecretValueResult:
    return PutSecretValueResult(
        arn=out.get("ARN") or "",
        name=out.get("Name") or "",
        version_id=out.get("VersionId") or "",
        version_stages=tuple(out.get("VersionStages") or ()),
    )


def _delete_result(out: Mapping[str, Any]) -> DeleteSecretResult:
    return DeleteSecretResult(
        arn=out.get("ARN") or "",
        name=out.get("Name") or "",
        deletion_date=utc(out.get("DeletionDate")),
    )


def _policy_result(out: Mapping[str, Any]) -> ResourcePolicyResult:
    text = out.get("ResourcePolicy") or None
    return ResourcePolicyResult(
        arn=out.get("ARN") or "",
        name=out.get("Name") or "",
        resource_policy=text,
        policy=parse_policy(text),
    )


def _validation_result(out: Mapping[str, Any]) -> ValidateResourcePolicyResult:
    return ValidateResourcePolicyResult(
        policy_validation_passed=out.get("PolicyValidationPassed") is True,
        validation_errors=tuple(to_policy_error(e) for e in out.get("ValidationErrors") or ()),
    )


def _password(out: Mapping[str, Any]) -> Secret:
    return Secret(out.get("RandomPassword") or "")


def _attempts(exc: BaseException) -> int:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        retries = (response.get("ResponseMetadata") or {}).get("RetryAttempts")
        if isinstance(retries, int):
            return retries + 1
    return 1


class _Base:
    """State and helpers shared by both clients."""

    config: AwsSecretsManagerConfig

    def _setup(self, config: AwsSecretsManagerConfig | None) -> None:
        if config is None:
            config = AwsSecretsManagerConfig.from_env()
        self.config = config.validate()
        self._resources = ResourceRegistry()
        self._log = SdkLogger(self.config.logger, self.config.known_secrets)
        self._tls = TlsFiles(self.config)
        self._closed = False
        self._owns_sdk = self.config.sdk_client is None

    @property
    def resources(self) -> ResourceRegistry:
        """Background resources (watchers) stopped by ``close()``."""
        return self._resources

    @property
    def closed(self) -> bool:
        """Whether ``close()`` was called."""
        return self._closed

    def known_secrets(self) -> list[str]:
        """Credential values redacted from error messages and logs."""
        return self.config.known_secrets()

    def _map(self, exc: BaseException, call: ops.Call) -> AwsSecretsManagerError:
        mapped = map_aws_error(
            exc,
            call.label,
            known_secrets=self.known_secrets(),
            unsupported_on_html_500=call.unsupported_on_html_500,
        )
        hooks = self.config.hooks
        if mapped.http_status is not None and hooks is not None:
            info = ErrorInfo(
                "POST", redact_url(self.config.effective_url), mapped, _attempts(exc), False
            )
            call_hook(hooks.on_error, info)
        return mapped

    def _closed_error(self, call: ops.Call) -> ConfigError:
        return ConfigError(f"{call.label}: client is closed")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(config={self.config!r})"


class AwsSecretsManagerClient(_Base):
    """Synchronous AWS Secrets Manager client on boto3. Thread-safe; use it as a context manager
    or call :meth:`close`.

    Every I/O method accepts ``cancel=`` (a :class:`CancelToken`): cancelling returns
    :class:`CancelledError` at once (the abandoned AWS call finishes in the background). The
    whole call, retries included, is bounded by ``config.total_timeout``
    (:class:`TimeoutError`).

    Errors are mapped by AWS error code: ``NotFoundError`` (``ResourceNotFoundException``),
    ``ConflictError`` (``ResourceExistsException``, ``InvalidRequestException`` e.g. scheduled
    for deletion), ``ValidationError``, ``PermissionDeniedError``, ``AuthenticationError``,
    ``RateLimitError``, ``UnavailableError``, ``TimeoutError``.
    """

    def __init__(self, config: AwsSecretsManagerConfig | None = None) -> None:
        self._setup(config)
        self._lock = threading.Lock()
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._health_sdk: Any = None
        if not self._owns_sdk:
            self._sdk: Any = self.config.sdk_client
            self._health_sdk = self._sdk
            return
        try:
            self._session = build_session(self.config, self._tls)
            self._sdk = self._session.client(SERVICE, **client_kwargs(self.config, self._tls))
        except Exception as exc:  # noqa: BLE001 - every build failure is a configuration error
            self._tls.close()
            mapped = map_aws_error(exc, "client", known_secrets=self.known_secrets())
            if isinstance(mapped, ConfigError):
                raise mapped from None
            raise ConfigError(
                f"client: cannot build the AWS SDK client: {mapped.message}"
            ) from None
        instrument(self.config, self._log, self._sdk, self.config.retry.max_retries + 1)

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, **overrides: Any
    ) -> AwsSecretsManagerClient:
        """A client from ``GROW_AWS_SECRETS_MANAGER_*`` and the standard AWS variables."""
        return cls(AwsSecretsManagerConfig.from_env(env, **overrides))

    @classmethod
    def with_sdk_client(cls, sdk_client: Any, **options: Any) -> AwsSecretsManagerClient:
        """Wraps an existing boto3 ``secretsmanager`` client; :meth:`close` leaves it open."""
        return cls(AwsSecretsManagerConfig(sdk_client=sdk_client, **options))

    @property
    def sdk(self) -> Any:
        """The underlying boto3 client (escape hatch for operations not wrapped here)."""
        return self._sdk

    # ------------------------------------------------------------------ plumbing
    def _health_client(self) -> Any:
        with self._lock:
            if self._health_sdk is None:
                kwargs = client_kwargs(self.config, self._tls, health=True)
                self._health_sdk = self._session.client(SERVICE, **kwargs)
                instrument(self.config, self._log, self._health_sdk, 1)
            return self._health_sdk

    def _pool(self) -> concurrent.futures.ThreadPoolExecutor:
        with self._lock:
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    thread_name_prefix="grow-aws-secrets-manager"
                )
            return self._executor

    def _invoke(
        self, call: ops.Call, cancel: CancelToken | None, *, health: bool = False
    ) -> dict[str, Any]:
        if self._closed:
            raise self._closed_error(call)
        if cancel is not None:
            cancel.raise_if_cancelled(call.label)
        sdk = self._health_client() if health else self._sdk
        future = self._pool().submit(getattr(sdk, call.method), **call.params)
        done = threading.Event()
        future.add_done_callback(lambda _f: done.set())
        unregister = cancel.on_cancel(done.set) if cancel is not None else None
        try:
            finished = done.wait(self.config.total_timeout)
        finally:
            if unregister is not None:
                unregister()
        if cancel is not None and cancel.cancelled:
            future.cancel()
            raise CancelledError(f"{call.label}: cancelled")
        if not finished:
            future.cancel()
            raise TimeoutError(
                f"{call.label}: total timeout of {self.config.total_timeout:g}s exceeded"
            )
        try:
            result: dict[str, Any] = future.result()
        except Exception as exc:
            raise self._map(exc, call) from exc
        return result

    # ------------------------------------------------------------------ core
    def health(self, *, cancel: CancelToken | None = None) -> HealthStatus:
        """Liveness: a signed ``ListSecrets {MaxResults: 1}``, no retries, ≤ 5 s timeouts.

        ``ok`` when AWS answers (also when the credentials are rejected:
        ``details["auth"] == "failed"``), ``degraded`` when throttled, ``unhealthy`` on HTTP 5xx,
        ``unreachable`` on network errors and timeouts. Raises only :class:`CancelledError` and
        :class:`ConfigError`.
        """
        try:
            self._invoke(ops.health(), cancel, health=True)
        except AwsSecretsManagerError as err:
            return _health_from_error(err)
        return HealthStatus(True, "ok", {})

    def ping(self, *, cancel: CancelToken | None = None) -> float:
        """Authenticated round trip (``ListSecrets {MaxResults: 1}``); latency in milliseconds.

        :class:`AuthenticationError` for unknown keys or bad signatures,
        :class:`PermissionDeniedError` when ``secretsmanager:ListSecrets`` is not allowed.
        """
        started = time.monotonic()
        self._invoke(ops.ping(), cancel)
        return (time.monotonic() - started) * 1000.0

    def server_version(self, *, cancel: CancelToken | None = None) -> str:
        """Always raises :class:`UnsupportedError`: AWS exposes no server version (the API
        contract date is the constant ``API_VERSION``)."""
        if cancel is not None:
            cancel.raise_if_cancelled("server_version")
        raise _unsupported_version("server_version")

    def close(self) -> None:
        """Stops the watchers of the providers from :meth:`secrets` and closes the boto3 client
        this instance built (never a caller-supplied one). Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._resources.stop_all()
        with self._lock:
            executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        if self._owns_sdk:
            for sdk in {id(self._sdk): self._sdk, id(self._health_sdk): self._health_sdk}.values():
                close = getattr(sdk, "close", None)
                if callable(close):
                    close()
        self._tls.close()

    def __enter__(self) -> AwsSecretsManagerClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ------------------------------------------------------------------ category + cache
    def secrets(
        self, *, recovery_window_days: int | None = None
    ) -> AwsSecretsManagerSecretsProvider:
        """The :class:`SecretsProvider` view (SPEC section 3) of this client; ``close()`` stops
        its watchers. ``recovery_window_days`` defaults to ``config.recovery_window_days``."""
        return AwsSecretsManagerSecretsProvider(self, recovery_window_days=recovery_window_days)

    def secret_cache(self, **options: Any) -> AwsSecretCache:
        """A version-stage aware cache with the AWS caching-client semantics (TTL 1 h, 1024
        entries); ``options`` are those of :class:`AwsSecretCache`."""
        return AwsSecretCache(self, **options)

    # ------------------------------------------------------------------ read
    def get_secret_value(
        self,
        secret_id: str,
        *,
        version_id: str | None = None,
        version_stage: str | None = None,
        cancel: CancelToken | None = None,
    ) -> AwsSecretValue:
        """Reads a secret value (``GetSecretValue``), by default the ``AWSCURRENT`` version.

        ``secret_id`` is a name or ARN. :class:`NotFoundError` when the secret, version or stage
        does not exist; :class:`ConflictError` when the secret is scheduled for deletion.
        """
        call = ops.get_secret_value(secret_id, version_id, version_stage)
        return to_secret_value(self._invoke(call, cancel))

    def batch_get_secret_value(
        self,
        secret_ids: Sequence[str] | None = None,
        *,
        filters: Sequence[SecretFilter] | None = None,
        max_results: int | None = None,
        cancel: CancelToken | None = None,
    ) -> BatchGetResult:
        """Reads many secrets at once (``BatchGetSecretValue``).

        Give ``secret_ids`` (lists longer than 20 are split; values come back in request order)
        or ``filters`` (every page is read; ``max_results`` is the page size, 1-20). Per-secret
        failures are returned in ``errors``; the call itself succeeds.
        """
        ids, aws_filters = ops.batch_selector(secret_ids, filters)
        values: list[AwsSecretValue] = []
        errors: list[BatchGetError] = []
        if ids is not None:
            for chunk in ops.chunks(ids, BATCH_GET_MAX_IDS):
                page_values: list[AwsSecretValue] = []
                token: str | None = None
                while True:
                    out = self._invoke(ops.batch_ids(chunk, token), cancel)
                    page_values.extend(to_secret_value(v) for v in out.get("SecretValues") or ())
                    errors.extend(to_batch_error(e) for e in out.get("Errors") or ())
                    token = next_token(out)
                    if token is None:
                        break
                values.extend(order_by_ids(page_values, chunk))
        else:
            assert aws_filters is not None
            token = None
            while True:
                out = self._invoke(ops.batch_filters(aws_filters, max_results, token), cancel)
                values.extend(to_secret_value(v) for v in out.get("SecretValues") or ())
                errors.extend(to_batch_error(e) for e in out.get("Errors") or ())
                token = next_token(out)
                if token is None:
                    break
        return BatchGetResult(tuple(values), tuple(errors))

    def describe_secret(
        self, secret_id: str, *, cancel: CancelToken | None = None
    ) -> SecretDescription:
        """Metadata of a secret (``DescribeSecret``), never the value."""
        return to_description(self._invoke(ops.describe_secret(secret_id), cancel))

    def list_secrets(
        self,
        *,
        filters: Sequence[SecretFilter] | None = None,
        include_planned_deletion: bool | None = None,
        sort_order: SortOrder | None = None,
        max_results: int | None = None,
        cancel: CancelToken | None = None,
    ) -> Paginator[SecretDescription]:
        """Lists secrets (``ListSecrets``) lazily across all pages:
        ``for s in client.list_secrets()`` or ``client.list_secrets().to_list()``."""

        def fetch(token: str | None) -> tuple[list[SecretDescription], str | None]:
            call = ops.list_secrets(
                filters, include_planned_deletion, sort_order, max_results, token
            )
            out = self._invoke(call, cancel)
            return [to_description(s) for s in out.get("SecretList") or ()], next_token(out)

        return Paginator(fetch)

    def list_secret_version_ids(
        self,
        secret_id: str,
        *,
        include_deprecated: bool | None = None,
        max_results: int | None = None,
        cancel: CancelToken | None = None,
    ) -> Paginator[SecretVersion]:
        """Lists the versions of a secret (``ListSecretVersionIds``) lazily across all pages."""
        ops.require_id("list_secret_version_ids", secret_id)

        def fetch(token: str | None) -> tuple[list[SecretVersion], str | None]:
            call = ops.list_secret_version_ids(secret_id, include_deprecated, max_results, token)
            out = self._invoke(call, cancel)
            return [to_version(v) for v in out.get("Versions") or ()], next_token(out)

        return Paginator(fetch)

    # ------------------------------------------------------------------ write
    def create_secret(
        self,
        name: str,
        value: Any = None,
        *,
        description: str | None = None,
        kms_key_id: str | None = None,
        tags: Mapping[str, str] | None = None,
        client_request_token: str | None = None,
        add_replica_regions: Sequence[ReplicaRegion] | None = None,
        force_overwrite_replica_secret: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> SecretWriteResult:
        """Creates a secret (``CreateSecret``).

        ``value``: ``str`` → ``SecretString``, bytes → ``SecretBinary``, other objects → JSON
        ``SecretString``, ``None`` → a secret without a version. :class:`ConflictError` when the
        name exists (or is scheduled for deletion).
        """
        call = ops.create_secret(
            name,
            value,
            description,
            kms_key_id,
            tags,
            client_request_token,
            add_replica_regions,
            force_overwrite_replica_secret,
        )
        return to_write_result(self._invoke(call, cancel))

    def put_secret_value(
        self,
        secret_id: str,
        value: Any,
        *,
        version_stages: Sequence[str] | None = None,
        client_request_token: str | None = None,
        cancel: CancelToken | None = None,
    ) -> PutSecretValueResult:
        """Stores a new version (``PutSecretValue``). By default it becomes ``AWSCURRENT`` (the
        old one becomes ``AWSPREVIOUS``); with ``version_stages`` only those labels move."""
        call = ops.put_secret_value(secret_id, value, version_stages, client_request_token)
        return _put_result(self._invoke(call, cancel))

    def update_secret(
        self,
        secret_id: str,
        *,
        value: Any = None,
        description: str | None = None,
        kms_key_id: str | None = None,
        client_request_token: str | None = None,
        cancel: CancelToken | None = None,
    ) -> SecretWriteResult:
        """Updates description, KMS key and/or value (``UpdateSecret``); a new version is created
        only when ``value`` is given."""
        call = ops.update_secret(secret_id, value, description, kms_key_id, client_request_token)
        return to_write_result(self._invoke(call, cancel))

    def update_secret_version_stage(
        self,
        secret_id: str,
        version_stage: str,
        *,
        move_to_version_id: str | None = None,
        remove_from_version_id: str | None = None,
        cancel: CancelToken | None = None,
    ) -> SecretRef:
        """Moves a stage label between versions (``UpdateSecretVersionStage``). Moving
        ``AWSCURRENT`` needs ``remove_from_version_id`` = the current version."""
        call = ops.update_secret_version_stage(
            secret_id, version_stage, move_to_version_id, remove_from_version_id
        )
        return to_ref(self._invoke(call, cancel))

    def delete_secret(
        self,
        secret_id: str,
        *,
        recovery_window_days: int | None = None,
        force_delete_without_recovery: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> DeleteSecretResult:
        """Schedules deletion (``DeleteSecret``) after ``recovery_window_days`` (7-30, AWS default
        30) or deletes at once with ``force_delete_without_recovery``. Both together →
        :class:`ValidationError`. AWS answers success for a forced delete of a missing secret."""
        call = ops.delete_secret(secret_id, recovery_window_days, force_delete_without_recovery)
        return _delete_result(self._invoke(call, cancel))

    def restore_secret(self, secret_id: str, *, cancel: CancelToken | None = None) -> SecretRef:
        """Cancels a scheduled deletion (``RestoreSecret``); a no-op for a live secret."""
        return to_ref(self._invoke(ops.by_id("restore_secret", secret_id), cancel))

    # ------------------------------------------------------------------ tags + policy
    def tag_resource(
        self, secret_id: str, tags: Mapping[str, str], *, cancel: CancelToken | None = None
    ) -> None:
        """Adds or replaces tags (``TagResource``)."""
        self._invoke(ops.tag_resource(secret_id, tags), cancel)

    def untag_resource(
        self, secret_id: str, tag_keys: Sequence[str], *, cancel: CancelToken | None = None
    ) -> None:
        """Removes tags by key (``UntagResource``)."""
        self._invoke(ops.untag_resource(secret_id, tag_keys), cancel)

    def put_resource_policy(
        self,
        secret_id: str,
        policy: str | Mapping[str, Any],
        *,
        block_public_policy: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> SecretRef:
        """Attaches a resource policy (``PutResourcePolicy``); mappings are JSON-encoded."""
        call = ops.put_resource_policy(secret_id, policy, block_public_policy)
        return to_ref(self._invoke(call, cancel))

    def get_resource_policy(
        self, secret_id: str, *, cancel: CancelToken | None = None
    ) -> ResourcePolicyResult:
        """Reads the resource policy (``GetResourcePolicy``); ``resource_policy`` is ``None``
        when the secret has none, ``policy`` is the parsed object."""
        return _policy_result(self._invoke(ops.by_id("get_resource_policy", secret_id), cancel))

    def delete_resource_policy(
        self, secret_id: str, *, cancel: CancelToken | None = None
    ) -> SecretRef:
        """Removes the resource policy (``DeleteResourcePolicy``)."""
        return to_ref(self._invoke(ops.by_id("delete_resource_policy", secret_id), cancel))

    def validate_resource_policy(
        self,
        policy: str | Mapping[str, Any],
        *,
        secret_id: str | None = None,
        cancel: CancelToken | None = None,
    ) -> ValidateResourcePolicyResult:
        """Checks a policy with IAM Access Analyzer (``ValidateResourcePolicy``). Emulators that
        lack the operation (Moto 5.2.4) raise :class:`UnsupportedError`."""
        call = ops.validate_resource_policy(policy, secret_id)
        return _validation_result(self._invoke(call, cancel))

    # ------------------------------------------------------------------ rotation
    def rotate_secret(
        self,
        secret_id: str,
        *,
        lambda_arn: str | None = None,
        rules: RotationRules | None = None,
        rotate_immediately: bool | None = None,
        client_request_token: str | None = None,
        cancel: CancelToken | None = None,
    ) -> SecretWriteResult:
        """Configures and/or starts rotation (``RotateSecret``). Without ``lambda_arn`` the
        secret's managed or existing rotation function is used."""
        call = ops.rotate_secret(
            secret_id, lambda_arn, rules, rotate_immediately, client_request_token
        )
        return to_write_result(self._invoke(call, cancel))

    def cancel_rotate_secret(
        self, secret_id: str, *, cancel: CancelToken | None = None
    ) -> SecretWriteResult:
        """Turns rotation off and cancels a rotation in progress (``CancelRotateSecret``)."""
        return to_write_result(self._invoke(ops.by_id("cancel_rotate_secret", secret_id), cancel))

    # ------------------------------------------------------------------ utilities
    def get_random_password(
        self,
        *,
        length: int = 32,
        exclude_characters: str | None = None,
        exclude_numbers: bool | None = None,
        exclude_punctuation: bool | None = None,
        exclude_uppercase: bool | None = None,
        exclude_lowercase: bool | None = None,
        include_space: bool | None = None,
        require_each_included_type: bool | None = None,
        cancel: CancelToken | None = None,
    ) -> Secret:
        """Generates a random password (``GetRandomPassword``, length 1-4096, default 32),
        returned as a redacting :class:`Secret`."""
        call = ops.get_random_password(
            length,
            exclude_characters,
            exclude_numbers,
            exclude_punctuation,
            exclude_uppercase,
            exclude_lowercase,
            include_space,
            require_each_included_type,
        )
        return _password(self._invoke(call, cancel))

    def get_json_field(
        self,
        secret_id: str,
        field: str,
        *,
        version_id: str | None = None,
        version_stage: str | None = None,
        cancel: CancelToken | None = None,
    ) -> Any:
        """One field of a JSON secret: an exact key first, otherwise a dot path (``"db.host"``).

        ``None`` when the field is absent; :class:`ValidationError` when the value is binary or
        not a JSON object; :class:`NotFoundError` when the secret is missing.
        """
        secret = self.get_secret_value(
            secret_id, version_id=version_id, version_stage=version_stage, cancel=cancel
        )
        return ops.json_field_of(secret, secret_id, field)


class AsyncAwsSecretsManagerClient(_Base):
    """Asynchronous AWS Secrets Manager client on aioboto3 (extra ``async``), with the same
    methods as :class:`AwsSecretsManagerClient`. Use ``async with`` or call :meth:`aclose`.

    Cancel a call by cancelling its task: the SDK raises :class:`CancelledError` (also an
    :class:`asyncio.CancelledError`). A caller-supplied ``sdk_client`` must be an entered
    aiobotocore ``secretsmanager`` client; ``credentials`` must be aiobotocore credentials.
    """

    def __init__(self, config: AwsSecretsManagerConfig | None = None) -> None:
        self._setup(config)
        self._sdk: Any = None
        self._health_sdk: Any = None
        self._contexts: list[Any] = []
        self._init_lock = asyncio.Lock()
        if not self._owns_sdk:
            self._sdk = self.config.sdk_client
            self._health_sdk = self._sdk
            return
        self._session = build_async_session(self.config, self._tls)

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, **overrides: Any
    ) -> AsyncAwsSecretsManagerClient:
        """A client from ``GROW_AWS_SECRETS_MANAGER_*`` and the standard AWS variables."""
        return cls(AwsSecretsManagerConfig.from_env(env, **overrides))

    @classmethod
    def with_sdk_client(cls, sdk_client: Any, **options: Any) -> AsyncAwsSecretsManagerClient:
        """Wraps an existing (entered) aiobotocore client; :meth:`aclose` leaves it open."""
        return cls(AwsSecretsManagerConfig(sdk_client=sdk_client, **options))

    @property
    def sdk(self) -> Any:
        """The underlying aiobotocore client (``None`` until the first call builds it)."""
        return self._sdk

    # ------------------------------------------------------------------ plumbing
    async def _client(self, health: bool) -> Any:
        current = self._health_sdk if health else self._sdk
        if current is not None:
            return current
        async with self._init_lock:
            current = self._health_sdk if health else self._sdk
            if current is None:
                ctx = self._session.client(
                    SERVICE, **client_kwargs(self.config, self._tls, health=health)
                )
                current = await ctx.__aenter__()
                self._contexts.append(ctx)
                attempts = 1 if health else self.config.retry.max_retries + 1
                instrument(self.config, self._log, current, attempts)
                if health:
                    self._health_sdk = current
                else:
                    self._sdk = current
            return current

    async def _invoke(self, call: ops.Call, *, health: bool = False) -> dict[str, Any]:
        if self._closed:
            raise self._closed_error(call)
        try:
            sdk = await self._client(health)
        except asyncio.CancelledError as exc:
            raise CancelledError(f"{call.label}: cancelled") from exc
        except Exception as exc:
            raise self._map(exc, call) from exc
        task = asyncio.ensure_future(getattr(sdk, call.method)(**call.params))
        task.add_done_callback(_consume)
        try:
            done, _ = await asyncio.wait({task}, timeout=self.config.total_timeout)
        except asyncio.CancelledError as exc:
            task.cancel()
            raise CancelledError(f"{call.label}: cancelled") from exc
        if not done:
            task.cancel()
            raise TimeoutError(
                f"{call.label}: total timeout of {self.config.total_timeout:g}s exceeded"
            )
        try:
            result: dict[str, Any] = task.result()
        except Exception as exc:
            raise self._map(exc, call) from exc
        return result

    # ------------------------------------------------------------------ core
    async def health(self) -> HealthStatus:
        """See :meth:`AwsSecretsManagerClient.health`."""
        try:
            await self._invoke(ops.health(), health=True)
        except AwsSecretsManagerError as err:
            return _health_from_error(err)
        return HealthStatus(True, "ok", {})

    async def ping(self) -> float:
        """See :meth:`AwsSecretsManagerClient.ping`."""
        started = time.monotonic()
        await self._invoke(ops.ping())
        return (time.monotonic() - started) * 1000.0

    async def server_version(self) -> str:
        """Always raises :class:`UnsupportedError` (AWS exposes no server version)."""
        raise _unsupported_version("server_version")

    async def aclose(self) -> None:
        """Stops watchers and closes the aiobotocore clients this instance built. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._resources.stop_all()
        contexts, self._contexts = self._contexts, []
        for ctx in reversed(contexts):
            await ctx.__aexit__(None, None, None)
        self._tls.close()

    close = aclose

    async def __aenter__(self) -> AsyncAwsSecretsManagerClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # ------------------------------------------------------------------ category + cache
    def secrets(
        self, *, recovery_window_days: int | None = None
    ) -> AsyncAwsSecretsManagerSecretsProvider:
        """The async :class:`SecretsProvider` view of this client."""
        return AsyncAwsSecretsManagerSecretsProvider(
            self, recovery_window_days=recovery_window_days
        )

    def secret_cache(self, **options: Any) -> AsyncAwsSecretCache:
        """An async version-stage aware cache (see :class:`AsyncAwsSecretCache`)."""
        return AsyncAwsSecretCache(self, **options)

    # ------------------------------------------------------------------ read
    async def get_secret_value(
        self, secret_id: str, *, version_id: str | None = None, version_stage: str | None = None
    ) -> AwsSecretValue:
        """See :meth:`AwsSecretsManagerClient.get_secret_value`."""
        call = ops.get_secret_value(secret_id, version_id, version_stage)
        return to_secret_value(await self._invoke(call))

    async def batch_get_secret_value(
        self,
        secret_ids: Sequence[str] | None = None,
        *,
        filters: Sequence[SecretFilter] | None = None,
        max_results: int | None = None,
    ) -> BatchGetResult:
        """See :meth:`AwsSecretsManagerClient.batch_get_secret_value`."""
        ids, aws_filters = ops.batch_selector(secret_ids, filters)
        values: list[AwsSecretValue] = []
        errors: list[BatchGetError] = []
        if ids is not None:
            for chunk in ops.chunks(ids, BATCH_GET_MAX_IDS):
                page_values: list[AwsSecretValue] = []
                token: str | None = None
                while True:
                    out = await self._invoke(ops.batch_ids(chunk, token))
                    page_values.extend(to_secret_value(v) for v in out.get("SecretValues") or ())
                    errors.extend(to_batch_error(e) for e in out.get("Errors") or ())
                    token = next_token(out)
                    if token is None:
                        break
                values.extend(order_by_ids(page_values, chunk))
        else:
            assert aws_filters is not None
            token = None
            while True:
                out = await self._invoke(ops.batch_filters(aws_filters, max_results, token))
                values.extend(to_secret_value(v) for v in out.get("SecretValues") or ())
                errors.extend(to_batch_error(e) for e in out.get("Errors") or ())
                token = next_token(out)
                if token is None:
                    break
        return BatchGetResult(tuple(values), tuple(errors))

    async def describe_secret(self, secret_id: str) -> SecretDescription:
        """See :meth:`AwsSecretsManagerClient.describe_secret`."""
        return to_description(await self._invoke(ops.describe_secret(secret_id)))

    def list_secrets(
        self,
        *,
        filters: Sequence[SecretFilter] | None = None,
        include_planned_deletion: bool | None = None,
        sort_order: SortOrder | None = None,
        max_results: int | None = None,
    ) -> AsyncPaginator[SecretDescription]:
        """See :meth:`AwsSecretsManagerClient.list_secrets` (``async for`` / ``to_list()``)."""

        async def fetch(token: str | None) -> tuple[list[SecretDescription], str | None]:
            call = ops.list_secrets(
                filters, include_planned_deletion, sort_order, max_results, token
            )
            out = await self._invoke(call)
            return [to_description(s) for s in out.get("SecretList") or ()], next_token(out)

        return AsyncPaginator(fetch)

    def list_secret_version_ids(
        self,
        secret_id: str,
        *,
        include_deprecated: bool | None = None,
        max_results: int | None = None,
    ) -> AsyncPaginator[SecretVersion]:
        """See :meth:`AwsSecretsManagerClient.list_secret_version_ids`."""
        ops.require_id("list_secret_version_ids", secret_id)

        async def fetch(token: str | None) -> tuple[list[SecretVersion], str | None]:
            call = ops.list_secret_version_ids(secret_id, include_deprecated, max_results, token)
            out = await self._invoke(call)
            return [to_version(v) for v in out.get("Versions") or ()], next_token(out)

        return AsyncPaginator(fetch)

    # ------------------------------------------------------------------ write
    async def create_secret(
        self,
        name: str,
        value: Any = None,
        *,
        description: str | None = None,
        kms_key_id: str | None = None,
        tags: Mapping[str, str] | None = None,
        client_request_token: str | None = None,
        add_replica_regions: Sequence[ReplicaRegion] | None = None,
        force_overwrite_replica_secret: bool | None = None,
    ) -> SecretWriteResult:
        """See :meth:`AwsSecretsManagerClient.create_secret`."""
        call = ops.create_secret(
            name,
            value,
            description,
            kms_key_id,
            tags,
            client_request_token,
            add_replica_regions,
            force_overwrite_replica_secret,
        )
        return to_write_result(await self._invoke(call))

    async def put_secret_value(
        self,
        secret_id: str,
        value: Any,
        *,
        version_stages: Sequence[str] | None = None,
        client_request_token: str | None = None,
    ) -> PutSecretValueResult:
        """See :meth:`AwsSecretsManagerClient.put_secret_value`."""
        call = ops.put_secret_value(secret_id, value, version_stages, client_request_token)
        return _put_result(await self._invoke(call))

    async def update_secret(
        self,
        secret_id: str,
        *,
        value: Any = None,
        description: str | None = None,
        kms_key_id: str | None = None,
        client_request_token: str | None = None,
    ) -> SecretWriteResult:
        """See :meth:`AwsSecretsManagerClient.update_secret`."""
        call = ops.update_secret(secret_id, value, description, kms_key_id, client_request_token)
        return to_write_result(await self._invoke(call))

    async def update_secret_version_stage(
        self,
        secret_id: str,
        version_stage: str,
        *,
        move_to_version_id: str | None = None,
        remove_from_version_id: str | None = None,
    ) -> SecretRef:
        """See :meth:`AwsSecretsManagerClient.update_secret_version_stage`."""
        call = ops.update_secret_version_stage(
            secret_id, version_stage, move_to_version_id, remove_from_version_id
        )
        return to_ref(await self._invoke(call))

    async def delete_secret(
        self,
        secret_id: str,
        *,
        recovery_window_days: int | None = None,
        force_delete_without_recovery: bool | None = None,
    ) -> DeleteSecretResult:
        """See :meth:`AwsSecretsManagerClient.delete_secret`."""
        call = ops.delete_secret(secret_id, recovery_window_days, force_delete_without_recovery)
        return _delete_result(await self._invoke(call))

    async def restore_secret(self, secret_id: str) -> SecretRef:
        """See :meth:`AwsSecretsManagerClient.restore_secret`."""
        return to_ref(await self._invoke(ops.by_id("restore_secret", secret_id)))

    # ------------------------------------------------------------------ tags + policy
    async def tag_resource(self, secret_id: str, tags: Mapping[str, str]) -> None:
        """See :meth:`AwsSecretsManagerClient.tag_resource`."""
        await self._invoke(ops.tag_resource(secret_id, tags))

    async def untag_resource(self, secret_id: str, tag_keys: Sequence[str]) -> None:
        """See :meth:`AwsSecretsManagerClient.untag_resource`."""
        await self._invoke(ops.untag_resource(secret_id, tag_keys))

    async def put_resource_policy(
        self,
        secret_id: str,
        policy: str | Mapping[str, Any],
        *,
        block_public_policy: bool | None = None,
    ) -> SecretRef:
        """See :meth:`AwsSecretsManagerClient.put_resource_policy`."""
        call = ops.put_resource_policy(secret_id, policy, block_public_policy)
        return to_ref(await self._invoke(call))

    async def get_resource_policy(self, secret_id: str) -> ResourcePolicyResult:
        """See :meth:`AwsSecretsManagerClient.get_resource_policy`."""
        return _policy_result(await self._invoke(ops.by_id("get_resource_policy", secret_id)))

    async def delete_resource_policy(self, secret_id: str) -> SecretRef:
        """See :meth:`AwsSecretsManagerClient.delete_resource_policy`."""
        return to_ref(await self._invoke(ops.by_id("delete_resource_policy", secret_id)))

    async def validate_resource_policy(
        self, policy: str | Mapping[str, Any], *, secret_id: str | None = None
    ) -> ValidateResourcePolicyResult:
        """See :meth:`AwsSecretsManagerClient.validate_resource_policy`."""
        call = ops.validate_resource_policy(policy, secret_id)
        return _validation_result(await self._invoke(call))

    # ------------------------------------------------------------------ rotation
    async def rotate_secret(
        self,
        secret_id: str,
        *,
        lambda_arn: str | None = None,
        rules: RotationRules | None = None,
        rotate_immediately: bool | None = None,
        client_request_token: str | None = None,
    ) -> SecretWriteResult:
        """See :meth:`AwsSecretsManagerClient.rotate_secret`."""
        call = ops.rotate_secret(
            secret_id, lambda_arn, rules, rotate_immediately, client_request_token
        )
        return to_write_result(await self._invoke(call))

    async def cancel_rotate_secret(self, secret_id: str) -> SecretWriteResult:
        """See :meth:`AwsSecretsManagerClient.cancel_rotate_secret`."""
        return to_write_result(await self._invoke(ops.by_id("cancel_rotate_secret", secret_id)))

    # ------------------------------------------------------------------ utilities
    async def get_random_password(
        self,
        *,
        length: int = 32,
        exclude_characters: str | None = None,
        exclude_numbers: bool | None = None,
        exclude_punctuation: bool | None = None,
        exclude_uppercase: bool | None = None,
        exclude_lowercase: bool | None = None,
        include_space: bool | None = None,
        require_each_included_type: bool | None = None,
    ) -> Secret:
        """See :meth:`AwsSecretsManagerClient.get_random_password`."""
        call = ops.get_random_password(
            length,
            exclude_characters,
            exclude_numbers,
            exclude_punctuation,
            exclude_uppercase,
            exclude_lowercase,
            include_space,
            require_each_included_type,
        )
        return _password(await self._invoke(call))

    async def get_json_field(
        self,
        secret_id: str,
        field: str,
        *,
        version_id: str | None = None,
        version_stage: str | None = None,
    ) -> Any:
        """See :meth:`AwsSecretsManagerClient.get_json_field`."""
        secret = await self.get_secret_value(
            secret_id, version_id=version_id, version_stage=version_stage
        )
        return ops.json_field_of(secret, secret_id, field)


def _consume(task: asyncio.Future[Any]) -> None:
    """Retrieves the outcome of an abandoned task so asyncio does not log it."""
    if not task.cancelled():
        task.exception()
