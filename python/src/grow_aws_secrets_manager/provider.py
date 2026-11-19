"""``SecretsProvider`` (SPEC section 3) on AWS Secrets Manager (API.md section 3).

Names are flat AWS secret names that may contain ``/``: ``path + "/" + name`` when a path is
given. ``version`` is the AWS ``VersionId``. A secret scheduled for deletion counts as missing.
"""

from __future__ import annotations

import builtins
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from ._core import (
    AwsSecretsManagerError,
    ConflictError,
    ErrorCode,
    NotFoundError,
    ValidationError,
    error_for_code,
)
from ._secrets import (
    AsyncBaseSecretsProvider,
    BaseSecretsProvider,
    DeleteOptions,
    GetOptions,
    SecretMetadata,
    SecretValue,
    SetOptions,
)
from .errors_map import AWS_ERROR_CODES, aws_error_code
from .models import (
    AWSCURRENT,
    BATCH_GET_MAX_IDS,
    BatchGetResult,
    SecretDescription,
    SecretFilter,
    encode_bytes,
)

if TYPE_CHECKING:
    from .client import AsyncAwsSecretsManagerClient, AwsSecretsManagerClient

__all__ = [
    "AwsSecretsManagerSecretsProvider",
    "AsyncAwsSecretsManagerSecretsProvider",
    "full_name",
    "to_metadata",
]

#: Batch error codes that mean "missing" for ``get_many`` (scheduled for deletion = missing).
_MISSING_BATCH_CODES = frozenset({"ResourceNotFoundException", "InvalidRequestException"})


def _trim(path: str) -> str:
    return path.strip("/")


def full_name(name: str, path: str | None) -> str:
    """``path/name`` when a path is given, otherwise ``name``."""
    prefix = _trim(path) if path else ""
    return f"{prefix}/{name}" if prefix else name


def _is_missing(err: AwsSecretsManagerError) -> bool:
    if isinstance(err, NotFoundError):
        return True
    return isinstance(err, ConflictError) and aws_error_code(err) == "InvalidRequestException"


def _iso(value: Any) -> str:
    return str(value.isoformat())


def to_metadata(d: SecretDescription) -> SecretMetadata:
    """A :class:`SecretDescription` as SPEC :class:`SecretMetadata`."""
    extra = {"arn": d.arn, "rotationEnabled": "true" if d.rotation_enabled else "false"}
    if d.description is not None:
        extra["description"] = d.description
    if d.kms_key_id is not None:
        extra["kmsKeyId"] = d.kms_key_id
    if d.next_rotation_date is not None:
        extra["nextRotationDate"] = _iso(d.next_rotation_date)
    if d.deleted_date is not None:
        extra["deletedDate"] = _iso(d.deleted_date)
    if d.primary_region is not None:
        extra["primaryRegion"] = d.primary_region
    slash = d.name.rfind("/")
    return SecretMetadata(
        name=d.name,
        path=d.name[:slash] if slash > 0 else None,
        version=d.version_id_for_stage(AWSCURRENT),
        created_at=d.created_date,
        updated_at=d.last_changed_date,
        tags=dict(d.tags),
        versions=len(d.version_ids_to_stages),
        extra=extra,
    )


def _check_days(days: int) -> int:
    if isinstance(days, bool) or not isinstance(days, int) or not 7 <= days <= 30:
        raise ValidationError("secrets: recovery_window_days must be an integer from 7 to 30")
    return days


def _list_prefix(prefix: str) -> dict[str, Any]:
    return {"filters": [SecretFilter("name", [prefix])]} if prefix else {}


def _keep(
    descriptions: builtins.list[SecretDescription], prefix: str
) -> builtins.list[SecretDescription]:
    # AWS's name filter also matches word prefixes inside names: re-filter by string prefix.
    return [d for d in descriptions if d.name.startswith(prefix) and d.deleted_date is None]


def _direct_children(
    descriptions: builtins.list[SecretDescription], prefix: str
) -> builtins.list[str]:
    return sorted(d.name for d in descriptions if "/" not in d.name[len(prefix) :])


def _collect(
    result: BatchGetResult, by_full: dict[str, str], found: dict[str, SecretValue]
) -> None:
    for e in result.errors:
        if e.error_code in _MISSING_BATCH_CODES:
            continue
        code = AWS_ERROR_CODES.get(e.error_code or "", ErrorCode.UNAVAILABLE)
        raise error_for_code(code)(
            f"secrets.get_many {e.secret_id or ''}: {e.error_code or 'error'}"
        )
    for v in result.secret_values:
        requested = by_full.get(v.name) or by_full.get(v.arn)
        if requested is not None:
            found[requested] = v.value


def _no_cas(name: str, opts: SetOptions) -> None:
    if opts.cas is not None:
        raise ValidationError(
            f"secrets.set {name}: AWS Secrets Manager has no compare-and-set (cas)"
        )


def _no_versions(name: str, opts: DeleteOptions) -> None:
    if opts.versions is not None:
        raise ValidationError(
            f"secrets.delete {name}: AWS Secrets Manager cannot delete single versions; "
            "use update_secret_version_stage"
        )


def _lost_create_race(err: AwsSecretsManagerError) -> bool:
    return isinstance(err, ConflictError) and aws_error_code(err) == "ResourceExistsException"


class AwsSecretsManagerSecretsProvider(BaseSecretsProvider):
    """:class:`SecretsProvider` over AWS Secrets Manager (``client.secrets()``).

    Capabilities: ``write``, ``versions``, ``delete``.

    * ``get(name, version=...)`` reads ``VersionId = version`` (stage labels: use
      ``client.get_secret_value``).
    * ``set`` stores UTF-8 text as ``SecretString`` and other bytes as ``SecretBinary``; it creates
      the secret when missing (with ``description`` / ``tags``) and returns the new VersionId.
      ``cas`` is not supported (:class:`ValidationError`).
    * ``delete`` schedules deletion with the recovery window (default 30 days);
      ``permanent=True`` deletes at once. A name scheduled for deletion cannot be written again
      until it is restored or purged (:class:`ConflictError`).
    * ``list(prefix)`` matches names by string prefix (recursive); ``get_all(path)`` returns the
      secrets directly under ``path`` (non-recursive). ``get_many`` / ``get_all`` use
      ``BatchGetSecretValue`` in chunks of 20.
    """

    #: Capabilities declared to the conformance runner.
    capabilities = frozenset({"write", "versions", "delete"})

    def __init__(
        self, client: AwsSecretsManagerClient, *, recovery_window_days: int | None = None
    ) -> None:
        super().__init__(owner=client.resources)
        self._client = client
        days = (
            client.config.recovery_window_days
            if recovery_window_days is None
            else recovery_window_days
        )
        self._days = _check_days(days)

    @property
    def client(self) -> AwsSecretsManagerClient:
        """The client this provider uses."""
        return self._client

    def _fetch_secret(self, name: str, opts: GetOptions) -> SecretValue | None:
        try:
            out = self._client.get_secret_value(full_name(name, opts.path), version_id=opts.version)
        except AwsSecretsManagerError as err:
            if _is_missing(err):
                return None
            raise
        return out.value

    def _descriptions(self, prefix: str) -> builtins.list[SecretDescription]:
        return _keep(self._client.list_secrets(**_list_prefix(prefix)).to_list(), prefix)

    def _list_secrets(self, path: str | None) -> builtins.list[SecretMetadata]:
        return [to_metadata(d) for d in self._descriptions(path or "")]

    def get_all(self, path: str | None = None) -> dict[str, SecretValue]:
        """Every secret directly under ``path`` (non-recursive), keyed by full name."""
        base = _trim(path) if path else ""
        prefix = f"{base}/" if base else ""
        return self.get_many(_direct_children(self._descriptions(prefix), prefix))

    def get_many(
        self, names: Sequence[str], *, version: str | None = None, path: str | None = None
    ) -> dict[str, SecretValue]:
        """Present secrets in request order (``BatchGetSecretValue`` in chunks of 20; per-name
        reads when a ``version`` is requested)."""
        if version is not None:
            return super().get_many(names, version=version, path=path)
        unique = list(dict.fromkeys(names))
        by_full = {full_name(n, path): n for n in unique}
        found: dict[str, SecretValue] = {}
        ids = list(by_full)
        for i in range(0, len(ids), BATCH_GET_MAX_IDS):
            _collect(
                self._client.batch_get_secret_value(ids[i : i + BATCH_GET_MAX_IDS]), by_full, found
            )
        return {n: found[n] for n in unique if n in found}

    def _put_existing(self, sid: str, value: Any, opts: SetOptions) -> str:
        out = self._client.put_secret_value(sid, value)
        if opts.tags:
            self._client.tag_resource(sid, opts.tags)
        if opts.description is not None:
            self._client.update_secret(sid, description=opts.description)
        return out.version_id

    def _put_secret(self, name: str, data: bytes, opts: SetOptions) -> str:
        _no_cas(name, opts)
        sid = full_name(name, opts.path)
        encoded = encode_bytes(data)
        value = encoded.get("SecretString", encoded.get("SecretBinary"))
        try:
            return self._put_existing(sid, value, opts)
        except NotFoundError:
            pass
        try:
            created = self._client.create_secret(
                sid, value, description=opts.description, tags=opts.tags
            )
        except AwsSecretsManagerError as err:
            if _lost_create_race(err):
                return self._put_existing(sid, value, opts)
            raise
        return created.version_id or ""

    def _describe(self, sid: str) -> SecretDescription | None:
        try:
            d = self._client.describe_secret(sid)
        except AwsSecretsManagerError as err:
            if _is_missing(err):
                return None
            raise
        return None if d.pending_deletion else d

    def _remove_secret(self, name: str, opts: DeleteOptions) -> None:
        _no_versions(name, opts)
        sid = full_name(name, opts.path)
        # Required: a forced delete of a missing secret succeeds on AWS.
        if self._describe(sid) is None:
            raise NotFoundError(f"secrets.delete {sid}: not found")
        if opts.permanent:
            self._client.delete_secret(sid, force_delete_without_recovery=True)
        else:
            self._client.delete_secret(sid, recovery_window_days=self._days)

    def _fetch_metadata(self, name: str, opts: GetOptions) -> SecretMetadata | None:
        d = self._describe(full_name(name, opts.path))
        return None if d is None else to_metadata(d)


class AsyncAwsSecretsManagerSecretsProvider(AsyncBaseSecretsProvider):
    """Async :class:`AwsSecretsManagerSecretsProvider` (``async_client.secrets()``)."""

    #: Capabilities declared to the conformance runner.
    capabilities = frozenset({"write", "versions", "delete"})

    def __init__(
        self, client: AsyncAwsSecretsManagerClient, *, recovery_window_days: int | None = None
    ) -> None:
        super().__init__(owner=client.resources)
        self._client = client
        days = (
            client.config.recovery_window_days
            if recovery_window_days is None
            else recovery_window_days
        )
        self._days = _check_days(days)

    @property
    def client(self) -> AsyncAwsSecretsManagerClient:
        """The client this provider uses."""
        return self._client

    async def _fetch_secret(self, name: str, opts: GetOptions) -> SecretValue | None:
        try:
            out = await self._client.get_secret_value(
                full_name(name, opts.path), version_id=opts.version
            )
        except AwsSecretsManagerError as err:
            if _is_missing(err):
                return None
            raise
        return out.value

    async def _descriptions(self, prefix: str) -> builtins.list[SecretDescription]:
        return _keep(await self._client.list_secrets(**_list_prefix(prefix)).to_list(), prefix)

    async def _list_secrets(self, path: str | None) -> builtins.list[SecretMetadata]:
        return [to_metadata(d) for d in await self._descriptions(path or "")]

    async def get_all(self, path: str | None = None) -> dict[str, SecretValue]:
        """See :meth:`AwsSecretsManagerSecretsProvider.get_all`."""
        base = _trim(path) if path else ""
        prefix = f"{base}/" if base else ""
        return await self.get_many(_direct_children(await self._descriptions(prefix), prefix))

    async def get_many(
        self, names: Sequence[str], *, version: str | None = None, path: str | None = None
    ) -> dict[str, SecretValue]:
        """See :meth:`AwsSecretsManagerSecretsProvider.get_many`."""
        if version is not None:
            return await super().get_many(names, version=version, path=path)
        unique = list(dict.fromkeys(names))
        by_full = {full_name(n, path): n for n in unique}
        found: dict[str, SecretValue] = {}
        ids = list(by_full)
        for i in range(0, len(ids), BATCH_GET_MAX_IDS):
            result = await self._client.batch_get_secret_value(ids[i : i + BATCH_GET_MAX_IDS])
            _collect(result, by_full, found)
        return {n: found[n] for n in unique if n in found}

    async def _put_existing(self, sid: str, value: Any, opts: SetOptions) -> str:
        out = await self._client.put_secret_value(sid, value)
        if opts.tags:
            await self._client.tag_resource(sid, opts.tags)
        if opts.description is not None:
            await self._client.update_secret(sid, description=opts.description)
        return out.version_id

    async def _put_secret(self, name: str, data: bytes, opts: SetOptions) -> str:
        _no_cas(name, opts)
        sid = full_name(name, opts.path)
        encoded = encode_bytes(data)
        value = encoded.get("SecretString", encoded.get("SecretBinary"))
        try:
            return await self._put_existing(sid, value, opts)
        except NotFoundError:
            pass
        try:
            created = await self._client.create_secret(
                sid, value, description=opts.description, tags=opts.tags
            )
        except AwsSecretsManagerError as err:
            if _lost_create_race(err):
                return await self._put_existing(sid, value, opts)
            raise
        return created.version_id or ""

    async def _describe(self, sid: str) -> SecretDescription | None:
        try:
            d = await self._client.describe_secret(sid)
        except AwsSecretsManagerError as err:
            if _is_missing(err):
                return None
            raise
        return None if d.pending_deletion else d

    async def _remove_secret(self, name: str, opts: DeleteOptions) -> None:
        _no_versions(name, opts)
        sid = full_name(name, opts.path)
        if await self._describe(sid) is None:
            raise NotFoundError(f"secrets.delete {sid}: not found")
        if opts.permanent:
            await self._client.delete_secret(sid, force_delete_without_recovery=True)
        else:
            await self._client.delete_secret(sid, recovery_window_days=self._days)

    async def _fetch_metadata(self, name: str, opts: GetOptions) -> SecretMetadata | None:
        d = await self._describe(full_name(name, opts.path))
        return None if d is None else to_metadata(d)
