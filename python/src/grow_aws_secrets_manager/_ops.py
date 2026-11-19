"""Request builders shared by the sync and async clients (internal).

Each builder validates its input client side and returns a :class:`Call`: the operation label
used in error messages, the boto3 method name and its keyword arguments.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
from typing import Any

from ._core import ValidationError
from .models import (
    AwsSecretValue,
    ReplicaRegion,
    RotationRules,
    SecretFilter,
    encode_value,
    json_field,
    policy_text,
    rules_to_aws,
    to_aws_tags,
    to_filters,
)

__all__: list[str] = []

#: Operations Moto 5.2.4 does not implement (non-JSON HTTP 500 → ``UnsupportedError``).
EMULATOR_GAPS = frozenset({"validate_resource_policy"})


@dataclasses.dataclass(frozen=True)
class Call:
    """One AWS operation: label for messages, boto3 method, keyword arguments."""

    label: str
    method: str
    params: dict[str, Any]

    @property
    def unsupported_on_html_500(self) -> bool:
        return self.method in EMULATOR_GAPS


def require_id(operation: str, secret_id: str) -> None:
    if not isinstance(secret_id, str) or not secret_id.strip():
        raise ValidationError(f"{operation}: secret id must not be empty")


def _put(params: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        params[key] = value


def health() -> Call:
    return Call("health", "list_secrets", {"MaxResults": 1})


def ping() -> Call:
    return Call("ping", "list_secrets", {"MaxResults": 1})


def get_secret_value(secret_id: str, version_id: str | None, version_stage: str | None) -> Call:
    require_id("get_secret_value", secret_id)
    params: dict[str, Any] = {"SecretId": secret_id}
    _put(params, "VersionId", version_id)
    _put(params, "VersionStage", version_stage)
    return Call(f"get_secret_value {secret_id}", "get_secret_value", params)


def batch_selector(
    secret_ids: Sequence[str] | None, filters: Sequence[SecretFilter] | None
) -> tuple[list[str] | None, list[dict[str, Any]] | None]:
    """Validates the ids-or-filters selector of ``batch_get_secret_value``."""
    if isinstance(secret_ids, str):
        raise ValidationError("batch_get_secret_value: secret_ids must be a list of ids")
    if secret_ids is not None and filters:
        raise ValidationError("batch_get_secret_value: give secret ids or filters, not both")
    if secret_ids is not None:
        return list(secret_ids), None
    if not filters:
        raise ValidationError("batch_get_secret_value: give secret ids or at least one filter")
    return None, to_filters(filters)


def batch_ids(chunk: Sequence[str], token: str | None) -> Call:
    params: dict[str, Any] = {"SecretIdList": list(chunk)}
    _put(params, "NextToken", token)
    return Call("batch_get_secret_value", "batch_get_secret_value", params)


def batch_filters(
    filters: list[dict[str, Any]], max_results: int | None, token: str | None
) -> Call:
    params: dict[str, Any] = {"Filters": filters}
    _put(params, "MaxResults", max_results)
    _put(params, "NextToken", token)
    return Call("batch_get_secret_value", "batch_get_secret_value", params)


def describe_secret(secret_id: str) -> Call:
    require_id("describe_secret", secret_id)
    return Call(f"describe_secret {secret_id}", "describe_secret", {"SecretId": secret_id})


def list_secrets(
    filters: Sequence[SecretFilter] | None,
    include_planned_deletion: bool | None,
    sort_order: str | None,
    max_results: int | None,
    token: str | None,
) -> Call:
    params: dict[str, Any] = {}
    if filters:
        params["Filters"] = to_filters(filters)
    _put(params, "IncludePlannedDeletion", include_planned_deletion)
    _put(params, "SortOrder", sort_order)
    _put(params, "MaxResults", max_results)
    _put(params, "NextToken", token)
    return Call("list_secrets", "list_secrets", params)


def list_secret_version_ids(
    secret_id: str, include_deprecated: bool | None, max_results: int | None, token: str | None
) -> Call:
    params: dict[str, Any] = {"SecretId": secret_id}
    _put(params, "IncludeDeprecated", include_deprecated)
    _put(params, "MaxResults", max_results)
    _put(params, "NextToken", token)
    return Call(f"list_secret_version_ids {secret_id}", "list_secret_version_ids", params)


def create_secret(
    name: str,
    value: Any,
    description: str | None,
    kms_key_id: str | None,
    tags: Mapping[str, str] | None,
    client_request_token: str | None,
    add_replica_regions: Sequence[ReplicaRegion] | None,
    force_overwrite_replica_secret: bool | None,
) -> Call:
    require_id("create_secret", name)
    params: dict[str, Any] = {"Name": name}
    if value is not None:
        params.update(encode_value(value, "create_secret"))
    _put(params, "Description", description)
    _put(params, "KmsKeyId", kms_key_id)
    if tags is not None:
        params["Tags"] = to_aws_tags(tags)
    _put(params, "ClientRequestToken", client_request_token)
    if add_replica_regions is not None:
        params["AddReplicaRegions"] = [
            {"Region": r.region, **({"KmsKeyId": r.kms_key_id} if r.kms_key_id else {})}
            for r in add_replica_regions
        ]
    _put(params, "ForceOverwriteReplicaSecret", force_overwrite_replica_secret)
    return Call(f"create_secret {name}", "create_secret", params)


def put_secret_value(
    secret_id: str,
    value: Any,
    version_stages: Sequence[str] | None,
    client_request_token: str | None,
) -> Call:
    require_id("put_secret_value", secret_id)
    params: dict[str, Any] = {"SecretId": secret_id, **encode_value(value, "put_secret_value")}
    if version_stages is not None:
        params["VersionStages"] = list(version_stages)
    _put(params, "ClientRequestToken", client_request_token)
    return Call(f"put_secret_value {secret_id}", "put_secret_value", params)


def update_secret(
    secret_id: str,
    value: Any,
    description: str | None,
    kms_key_id: str | None,
    client_request_token: str | None,
) -> Call:
    require_id("update_secret", secret_id)
    params: dict[str, Any] = {"SecretId": secret_id}
    if value is not None:
        params.update(encode_value(value, "update_secret"))
    _put(params, "Description", description)
    _put(params, "KmsKeyId", kms_key_id)
    _put(params, "ClientRequestToken", client_request_token)
    return Call(f"update_secret {secret_id}", "update_secret", params)


def update_secret_version_stage(
    secret_id: str,
    version_stage: str,
    move_to_version_id: str | None,
    remove_from_version_id: str | None,
) -> Call:
    require_id("update_secret_version_stage", secret_id)
    if not version_stage:
        raise ValidationError("update_secret_version_stage: version_stage must not be empty")
    if move_to_version_id is None and remove_from_version_id is None:
        raise ValidationError(
            "update_secret_version_stage: give move_to_version_id and/or remove_from_version_id"
        )
    params: dict[str, Any] = {"SecretId": secret_id, "VersionStage": version_stage}
    _put(params, "MoveToVersionId", move_to_version_id)
    _put(params, "RemoveFromVersionId", remove_from_version_id)
    return Call(f"update_secret_version_stage {secret_id}", "update_secret_version_stage", params)


def delete_secret(
    secret_id: str, recovery_window_days: int | None, force_delete_without_recovery: bool | None
) -> Call:
    require_id("delete_secret", secret_id)
    days = recovery_window_days
    if days is not None and force_delete_without_recovery:
        raise ValidationError(
            "delete_secret: recovery_window_days and force_delete_without_recovery are "
            "mutually exclusive"
        )
    if days is not None and (
        isinstance(days, bool) or not isinstance(days, int) or not 7 <= days <= 30
    ):
        raise ValidationError("delete_secret: recovery_window_days must be an integer from 7 to 30")
    params: dict[str, Any] = {"SecretId": secret_id}
    _put(params, "RecoveryWindowInDays", days)
    _put(params, "ForceDeleteWithoutRecovery", force_delete_without_recovery)
    return Call(f"delete_secret {secret_id}", "delete_secret", params)


def by_id(method: str, secret_id: str) -> Call:
    """Operations whose only argument is ``SecretId``."""
    require_id(method, secret_id)
    return Call(f"{method} {secret_id}", method, {"SecretId": secret_id})


def tag_resource(secret_id: str, tags: Mapping[str, str]) -> Call:
    require_id("tag_resource", secret_id)
    params = {"SecretId": secret_id, "Tags": to_aws_tags(tags)}
    return Call(f"tag_resource {secret_id}", "tag_resource", params)


def untag_resource(secret_id: str, tag_keys: Sequence[str]) -> Call:
    require_id("untag_resource", secret_id)
    if isinstance(tag_keys, str):
        raise ValidationError("untag_resource: tag_keys must be a list of keys")
    params = {"SecretId": secret_id, "TagKeys": list(tag_keys)}
    return Call(f"untag_resource {secret_id}", "untag_resource", params)


def put_resource_policy(
    secret_id: str, policy: str | Mapping[str, Any], block_public_policy: bool | None
) -> Call:
    require_id("put_resource_policy", secret_id)
    params: dict[str, Any] = {"SecretId": secret_id, "ResourcePolicy": policy_text(policy)}
    _put(params, "BlockPublicPolicy", block_public_policy)
    return Call(f"put_resource_policy {secret_id}", "put_resource_policy", params)


def validate_resource_policy(policy: str | Mapping[str, Any], secret_id: str | None) -> Call:
    params: dict[str, Any] = {"ResourcePolicy": policy_text(policy)}
    _put(params, "SecretId", secret_id)
    return Call("validate_resource_policy", "validate_resource_policy", params)


def rotate_secret(
    secret_id: str,
    lambda_arn: str | None,
    rules: RotationRules | None,
    rotate_immediately: bool | None,
    client_request_token: str | None,
) -> Call:
    require_id("rotate_secret", secret_id)
    params: dict[str, Any] = {"SecretId": secret_id}
    _put(params, "RotationLambdaARN", lambda_arn)
    if rules is not None:
        params["RotationRules"] = rules_to_aws(rules)
    _put(params, "RotateImmediately", rotate_immediately)
    _put(params, "ClientRequestToken", client_request_token)
    return Call(f"rotate_secret {secret_id}", "rotate_secret", params)


def get_random_password(
    length: int,
    exclude_characters: str | None,
    exclude_numbers: bool | None,
    exclude_punctuation: bool | None,
    exclude_uppercase: bool | None,
    exclude_lowercase: bool | None,
    include_space: bool | None,
    require_each_included_type: bool | None,
) -> Call:
    params: dict[str, Any] = {"PasswordLength": length}
    _put(params, "ExcludeCharacters", exclude_characters)
    _put(params, "ExcludeNumbers", exclude_numbers)
    _put(params, "ExcludePunctuation", exclude_punctuation)
    _put(params, "ExcludeUppercase", exclude_uppercase)
    _put(params, "ExcludeLowercase", exclude_lowercase)
    _put(params, "IncludeSpace", include_space)
    _put(params, "RequireEachIncludedType", require_each_included_type)
    return Call("get_random_password", "get_random_password", params)


def json_field_of(secret: AwsSecretValue, secret_id: str, field: str) -> Any:
    """Field of a JSON-object secret; ``None`` when absent; ``ValidationError`` otherwise."""
    if secret.binary:
        raise ValidationError(f"get_json_field {secret_id}: the secret is binary, not JSON")
    try:
        parsed = secret.value.json()
    except ValidationError:
        raise ValidationError(f"get_json_field {secret_id}: the value is not valid JSON") from None
    if not isinstance(parsed, dict):
        raise ValidationError(f"get_json_field {secret_id}: the value is not a JSON object")
    return json_field(parsed, field)


def chunks(ids: Sequence[str], size: int) -> list[list[str]]:
    return [list(ids[i : i + size]) for i in range(0, len(ids), size)]
