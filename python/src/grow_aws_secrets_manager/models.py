"""Models of the AWS Secrets Manager API and converters from the boto3 response shapes.

Field names are ``snake_case``; timestamps are tz-aware UTC :class:`datetime.datetime`; secret
values are always wrapped in the redacting :class:`~grow_aws_secrets_manager.SecretValue`.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from ._core import ValidationError
from ._secrets import SecretValue

__all__ = [
    "API_VERSION",
    "AWSCURRENT",
    "AWSPREVIOUS",
    "AWSPENDING",
    "BATCH_GET_MAX_IDS",
    "AwsSecretValue",
    "RotationRules",
    "ReplicationStatus",
    "SecretDescription",
    "SecretVersion",
    "SecretRef",
    "SecretWriteResult",
    "PutSecretValueResult",
    "DeleteSecretResult",
    "ResourcePolicyResult",
    "PolicyValidationError",
    "ValidateResourcePolicyResult",
    "BatchGetError",
    "BatchGetResult",
    "SecretFilter",
    "SecretFilterKey",
    "ReplicaRegion",
    "SortOrder",
]

#: AWS Secrets Manager API version (the API contract date; AWS exposes no server version).
API_VERSION = "2017-10-17"

#: Default version stage.
AWSCURRENT = "AWSCURRENT"
#: Stage of the previous current version.
AWSPREVIOUS = "AWSPREVIOUS"
#: Stage of a version being rotated in.
AWSPENDING = "AWSPENDING"

#: Maximum ids per ``BatchGetSecretValue`` call; longer id lists are split.
BATCH_GET_MAX_IDS = 20

#: ``ListSecrets`` / ``BatchGetSecretValue`` filter keys.
SecretFilterKey = Literal[
    "name", "description", "tag-key", "tag-value", "primary-region", "owning-service", "all"
]

#: ``ListSecrets`` sort order (by creation date).
SortOrder = Literal["asc", "desc"]


@dataclasses.dataclass(frozen=True)
class AwsSecretValue:
    """A secret value read from AWS (``GetSecretValue``, ``BatchGetSecretValue``).

    ``value.version`` is the version id; ``binary`` is true when the secret stores
    ``SecretBinary`` (false for ``SecretString``). ``repr()`` never shows the value.
    """

    arn: str
    name: str
    version_id: str | None
    version_stages: tuple[str, ...]
    created_date: _dt.datetime | None
    binary: bool
    value: SecretValue


@dataclasses.dataclass(frozen=True)
class RotationRules:
    """Rotation schedule: every N days, or a ``rate(…)`` / ``cron(…)`` expression."""

    automatically_after_days: int | None = None
    duration: str | None = None
    schedule_expression: str | None = None


@dataclasses.dataclass(frozen=True)
class ReplicationStatus:
    """Replication status of one replica region."""

    region: str | None = None
    kms_key_id: str | None = None
    status: str | None = None
    status_message: str | None = None
    last_accessed_date: _dt.datetime | None = None


@dataclasses.dataclass(frozen=True)
class SecretDescription:
    """Secret metadata (``DescribeSecret``, ``ListSecrets`` entries). Never contains the value."""

    arn: str
    name: str
    description: str | None = None
    kms_key_id: str | None = None
    rotation_enabled: bool = False
    rotation_lambda_arn: str | None = None
    rotation_rules: RotationRules | None = None
    last_rotated_date: _dt.datetime | None = None
    last_changed_date: _dt.datetime | None = None
    last_accessed_date: _dt.datetime | None = None
    #: Set when the secret is scheduled for deletion.
    deleted_date: _dt.datetime | None = None
    next_rotation_date: _dt.datetime | None = None
    created_date: _dt.datetime | None = None
    primary_region: str | None = None
    owning_service: str | None = None
    tags: Mapping[str, str] = dataclasses.field(default_factory=dict)
    #: Version id → stage labels.
    version_ids_to_stages: Mapping[str, tuple[str, ...]] = dataclasses.field(default_factory=dict)
    replication_status: tuple[ReplicationStatus, ...] = ()

    @property
    def pending_deletion(self) -> bool:
        """True when the secret is scheduled for deletion."""
        return self.deleted_date is not None

    def version_id_for_stage(self, stage: str = AWSCURRENT) -> str | None:
        """The version id that carries ``stage`` (``None`` when no version has it)."""
        for version_id, stages in self.version_ids_to_stages.items():
            if stage in stages:
                return version_id
        return None


@dataclasses.dataclass(frozen=True)
class SecretVersion:
    """One version of a secret (``ListSecretVersionIds``)."""

    version_id: str
    version_stages: tuple[str, ...] = ()
    created_date: _dt.datetime | None = None
    last_accessed_date: _dt.datetime | None = None
    kms_key_ids: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class SecretRef:
    """ARN and name of a secret."""

    arn: str
    name: str


@dataclasses.dataclass(frozen=True)
class SecretWriteResult(SecretRef):
    """Result of writes that may create a version (``version_id`` is None when none was)."""

    version_id: str | None = None


@dataclasses.dataclass(frozen=True)
class PutSecretValueResult(SecretRef):
    """Result of ``put_secret_value``."""

    version_id: str = ""
    version_stages: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class DeleteSecretResult(SecretRef):
    """Result of ``delete_secret``; ``deletion_date`` is when the secret will be (was) purged."""

    deletion_date: _dt.datetime | None = None


@dataclasses.dataclass(frozen=True)
class ResourcePolicyResult(SecretRef):
    """Result of ``get_resource_policy``.

    ``resource_policy`` is the policy JSON text (``None`` without a policy); ``policy`` is the
    parsed object (``None`` when absent or not a JSON object).
    """

    resource_policy: str | None = None
    policy: Mapping[str, Any] | None = None


@dataclasses.dataclass(frozen=True)
class PolicyValidationError:
    """One problem found by ``validate_resource_policy``."""

    check_name: str | None = None
    error_message: str | None = None


@dataclasses.dataclass(frozen=True)
class ValidateResourcePolicyResult:
    """Result of ``validate_resource_policy``."""

    policy_validation_passed: bool
    validation_errors: tuple[PolicyValidationError, ...] = ()


@dataclasses.dataclass(frozen=True)
class BatchGetError:
    """A per-secret failure of ``batch_get_secret_value`` (the call itself succeeded)."""

    secret_id: str | None = None
    #: AWS error code, e.g. ``ResourceNotFoundException``.
    error_code: str | None = None
    message: str | None = None


@dataclasses.dataclass(frozen=True)
class BatchGetResult:
    """Result of ``batch_get_secret_value``: values (request order for ids) and failures."""

    secret_values: tuple[AwsSecretValue, ...] = ()
    errors: tuple[BatchGetError, ...] = ()


@dataclasses.dataclass(frozen=True)
class SecretFilter:
    """A ``ListSecrets`` / ``BatchGetSecretValue`` filter. A value prefixed ``!`` negates it."""

    key: SecretFilterKey
    values: Sequence[str]


@dataclasses.dataclass(frozen=True)
class ReplicaRegion:
    """A replica region for ``create_secret``."""

    region: str
    kms_key_id: str | None = None


# --------------------------------------------------------------------------- converters


def utc(value: Any) -> _dt.datetime | None:
    """A tz-aware UTC datetime from a botocore timestamp (``None`` stays ``None``)."""
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=_dt.timezone.utc)
        return value.astimezone(_dt.timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _dt.datetime.fromtimestamp(value, _dt.timezone.utc)
    return None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def to_aws_tags(tags: Mapping[str, str]) -> list[dict[str, str]]:
    """Tags map → the AWS list form."""
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def from_aws_tags(tags: Any) -> dict[str, str]:
    """The AWS tag list → a map."""
    out: dict[str, str] = {}
    for tag in tags or ():
        key = tag.get("Key")
        if isinstance(key, str):
            out[key] = tag.get("Value") or ""
    return out


def encode_value(value: Any, operation: str) -> dict[str, Any]:
    """``str`` → ``SecretString``, bytes → ``SecretBinary``, other values → JSON text."""
    if isinstance(value, SecretValue):
        return encode_bytes(value.reveal_bytes())
    if isinstance(value, str):
        return {"SecretString": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"SecretBinary": bytes(value)}
    try:
        return {"SecretString": json.dumps(value)}
    except (TypeError, ValueError):
        raise ValidationError(f"{operation}: secret value must be JSON-serialisable") from None


def encode_bytes(data: bytes) -> dict[str, Any]:
    """Raw bytes: valid UTF-8 → ``SecretString``, anything else → ``SecretBinary``."""
    try:
        return {"SecretString": data.decode("utf-8")}
    except UnicodeDecodeError:
        return {"SecretBinary": data}


def policy_text(policy: str | Mapping[str, Any]) -> str:
    """A resource policy as JSON text (mappings are JSON-encoded)."""
    return policy if isinstance(policy, str) else json.dumps(policy)


def parse_policy(text: str | None) -> dict[str, Any] | None:
    """A policy JSON text as a dict (``None`` when absent or not a JSON object)."""
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def to_secret_value(out: Mapping[str, Any]) -> AwsSecretValue:
    """A ``GetSecretValue`` output / ``SecretValueEntry`` → :class:`AwsSecretValue`."""
    binary = out.get("SecretBinary") is not None
    raw: bytes | str = out["SecretBinary"] if binary else (out.get("SecretString") or "")
    version_id = _str(out.get("VersionId"))
    return AwsSecretValue(
        arn=out.get("ARN") or "",
        name=out.get("Name") or "",
        version_id=version_id,
        version_stages=tuple(out.get("VersionStages") or ()),
        created_date=utc(out.get("CreatedDate")),
        binary=binary,
        value=SecretValue(raw, version_id),
    )


def _rules(r: Any) -> RotationRules | None:
    if not isinstance(r, Mapping):
        return None
    return RotationRules(
        automatically_after_days=r.get("AutomaticallyAfterDays"),
        duration=_str(r.get("Duration")),
        schedule_expression=_str(r.get("ScheduleExpression")),
    )


def rules_to_aws(rules: RotationRules) -> dict[str, Any]:
    """:class:`RotationRules` → the AWS ``RotationRules`` shape."""
    out: dict[str, Any] = {}
    if rules.automatically_after_days is not None:
        out["AutomaticallyAfterDays"] = rules.automatically_after_days
    if rules.duration is not None:
        out["Duration"] = rules.duration
    if rules.schedule_expression is not None:
        out["ScheduleExpression"] = rules.schedule_expression
    return out


def to_description(out: Mapping[str, Any]) -> SecretDescription:
    """A ``DescribeSecret`` output or ``SecretListEntry`` → :class:`SecretDescription`."""
    stages: dict[str, tuple[str, ...]] = {}
    for key in ("SecretVersionsToStages", "VersionIdsToStages"):
        for version_id, labels in (out.get(key) or {}).items():
            stages[version_id] = tuple(labels or ())
    replication = tuple(
        ReplicationStatus(
            region=_str(r.get("Region")),
            kms_key_id=_str(r.get("KmsKeyId")),
            status=_str(r.get("Status")),
            status_message=_str(r.get("StatusMessage")),
            last_accessed_date=utc(r.get("LastAccessedDate")),
        )
        for r in out.get("ReplicationStatus") or ()
    )
    return SecretDescription(
        arn=out.get("ARN") or "",
        name=out.get("Name") or "",
        description=_str(out.get("Description")),
        kms_key_id=_str(out.get("KmsKeyId")),
        rotation_enabled=out.get("RotationEnabled") is True,
        rotation_lambda_arn=_str(out.get("RotationLambdaARN")),
        rotation_rules=_rules(out.get("RotationRules")),
        last_rotated_date=utc(out.get("LastRotatedDate")),
        last_changed_date=utc(out.get("LastChangedDate")),
        last_accessed_date=utc(out.get("LastAccessedDate")),
        deleted_date=utc(out.get("DeletedDate")),
        next_rotation_date=utc(out.get("NextRotationDate")),
        created_date=utc(out.get("CreatedDate")),
        primary_region=_str(out.get("PrimaryRegion")),
        owning_service=_str(out.get("OwningService")),
        tags=from_aws_tags(out.get("Tags")),
        version_ids_to_stages=stages,
        replication_status=replication,
    )


def to_version(v: Mapping[str, Any]) -> SecretVersion:
    """A ``ListSecretVersionIds`` entry → :class:`SecretVersion`."""
    return SecretVersion(
        version_id=v.get("VersionId") or "",
        version_stages=tuple(v.get("VersionStages") or ()),
        created_date=utc(v.get("CreatedDate")),
        last_accessed_date=utc(v.get("LastAccessedDate")),
        kms_key_ids=tuple(v.get("KmsKeyIds") or ()),
    )


def to_batch_error(e: Mapping[str, Any]) -> BatchGetError:
    """A ``BatchGetSecretValue`` error entry → :class:`BatchGetError`."""
    return BatchGetError(
        secret_id=_str(e.get("SecretId")),
        error_code=_str(e.get("ErrorCode")),
        message=_str(e.get("Message")),
    )


def to_policy_error(e: Mapping[str, Any]) -> PolicyValidationError:
    """A ``ValidateResourcePolicy`` error entry → :class:`PolicyValidationError`."""
    return PolicyValidationError(
        check_name=_str(e.get("CheckName")), error_message=_str(e.get("ErrorMessage"))
    )


def to_ref(out: Mapping[str, Any]) -> SecretRef:
    return SecretRef(arn=out.get("ARN") or "", name=out.get("Name") or "")


def to_write_result(out: Mapping[str, Any]) -> SecretWriteResult:
    return SecretWriteResult(
        arn=out.get("ARN") or "", name=out.get("Name") or "", version_id=_str(out.get("VersionId"))
    )


def to_filters(filters: Sequence[SecretFilter]) -> list[dict[str, Any]]:
    """Filters → the AWS form."""
    return [{"Key": f.key, "Values": list(f.values)} for f in filters]


def next_token(out: Mapping[str, Any]) -> str | None:
    """The next page token; ``None``, absent and ``""`` all end the list."""
    token = out.get("NextToken")
    return token if isinstance(token, str) and token else None


def order_by_ids(values: Sequence[AwsSecretValue], ids: Sequence[str]) -> list[AwsSecretValue]:
    """Orders batch results like the requested ids (by name, ARN or partial ARN)."""

    def rank(v: AwsSecretValue) -> int:
        for i, sid in enumerate(ids):
            if sid in (v.name, v.arn) or (sid.startswith("arn:") and v.arn.startswith(sid)):
                return i
        return len(ids)

    return sorted(values, key=rank)


def json_field(doc: Mapping[str, Any], field: str) -> Any:
    """An exact key first, then a dot path (``"db.host"``); ``None`` when absent."""
    if field in doc:
        return doc[field]
    current: Any = doc
    for part in field.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current
