//! Models of the AWS Secrets Manager API, request options and converters from the AWS SDK
//! shapes. Secret values are always wrapped in the redacting [`SecretValue`].

use std::collections::BTreeMap;
use std::fmt;
use std::time::SystemTime;

use aws_sdk_secretsmanager::types as sdk;
use aws_smithy_types::DateTime;
use serde_json::Value;

use crate::core::{Error, Result};
use crate::secrets::{SecretData, SecretValue};

/// AWS Secrets Manager API version (the API contract date; AWS exposes no server version).
pub const API_VERSION: &str = "2017-10-17";
/// Default version stage.
pub const AWSCURRENT: &str = "AWSCURRENT";
/// Stage of the previous current version.
pub const AWSPREVIOUS: &str = "AWSPREVIOUS";
/// Stage of a version being rotated in.
pub const AWSPENDING: &str = "AWSPENDING";
/// Maximum ids per `BatchGetSecretValue` call; longer id lists are split.
pub const BATCH_GET_MAX_IDS: usize = 20;

/// A secret value read from AWS (`GetSecretValue`, `BatchGetSecretValue`). `Debug` never shows
/// the value.
#[derive(Clone, PartialEq, Eq)]
pub struct AwsSecretValue {
    /// Full ARN.
    pub arn: String,
    /// Secret name.
    pub name: String,
    /// Version id.
    pub version_id: Option<String>,
    /// Stage labels attached to this version.
    pub version_stages: Vec<String>,
    /// Creation time of this version.
    pub created_date: Option<SystemTime>,
    /// True when the secret stores `SecretBinary`, false for `SecretString`.
    pub binary: bool,
    /// The value (redacting wrapper; `value.version()` is the version id).
    pub value: SecretValue,
}

impl fmt::Debug for AwsSecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSecretValue")
            .field("arn", &self.arn)
            .field("name", &self.name)
            .field("version_id", &self.version_id)
            .field("version_stages", &self.version_stages)
            .field("created_date", &self.created_date)
            .field("binary", &self.binary)
            .field("value", &self.value)
            .finish()
    }
}

/// Rotation schedule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationRules {
    /// Rotate every N days (1–1000).
    pub automatically_after_days: Option<i64>,
    /// Rotation window length, e.g. `"3h"`.
    pub duration: Option<String>,
    /// `rate(…)` or `cron(…)` expression.
    pub schedule_expression: Option<String>,
}

/// Replication status of one replica region.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicationStatus {
    /// Replica region.
    pub region: Option<String>,
    /// KMS key of the replica.
    pub kms_key_id: Option<String>,
    /// `InSync`, `Failed` or `InProgress`.
    pub status: Option<String>,
    /// Status message.
    pub status_message: Option<String>,
    /// Last access of the replica.
    pub last_accessed_date: Option<SystemTime>,
}

/// Secret metadata (`DescribeSecret`, `ListSecrets` entries). Never contains the value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretDescription {
    /// Full ARN.
    pub arn: String,
    /// Secret name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// KMS key id.
    pub kms_key_id: Option<String>,
    /// Whether rotation is enabled.
    pub rotation_enabled: bool,
    /// Rotation Lambda ARN.
    pub rotation_lambda_arn: Option<String>,
    /// Rotation schedule.
    pub rotation_rules: Option<RotationRules>,
    /// Last rotation.
    pub last_rotated_date: Option<SystemTime>,
    /// Last change.
    pub last_changed_date: Option<SystemTime>,
    /// Last access (date only).
    pub last_accessed_date: Option<SystemTime>,
    /// Set when the secret is scheduled for deletion.
    pub deleted_date: Option<SystemTime>,
    /// Next scheduled rotation.
    pub next_rotation_date: Option<SystemTime>,
    /// Creation time.
    pub created_date: Option<SystemTime>,
    /// Primary region of a replicated secret.
    pub primary_region: Option<String>,
    /// Service that manages the secret.
    pub owning_service: Option<String>,
    /// Tags.
    pub tags: BTreeMap<String, String>,
    /// Version id → stage labels.
    pub version_ids_to_stages: BTreeMap<String, Vec<String>>,
    /// Replica status.
    pub replication_status: Vec<ReplicationStatus>,
}

impl SecretDescription {
    /// The version id that carries `stage`.
    pub fn version_with_stage(&self, stage: &str) -> Option<&str> {
        self.version_ids_to_stages
            .iter()
            .find(|(_, stages)| stages.iter().any(|s| s == stage))
            .map(|(id, _)| id.as_str())
    }

    /// The `AWSCURRENT` version id.
    pub fn current_version_id(&self) -> Option<&str> {
        self.version_with_stage(AWSCURRENT)
    }

    /// Whether the secret is scheduled for deletion.
    pub fn pending_deletion(&self) -> bool {
        self.deleted_date.is_some()
    }
}

/// One version of a secret (`ListSecretVersionIds`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretVersion {
    /// Version id.
    pub version_id: String,
    /// Stage labels.
    pub version_stages: Vec<String>,
    /// Creation time.
    pub created_date: Option<SystemTime>,
    /// Last access (date only).
    pub last_accessed_date: Option<SystemTime>,
    /// KMS keys used to encrypt the version.
    pub kms_key_ids: Vec<String>,
}

/// ARN and name of a secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretRef {
    /// Full ARN.
    pub arn: String,
    /// Secret name.
    pub name: String,
}

/// Result of writes that may create a version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretWriteResult {
    /// Full ARN.
    pub arn: String,
    /// Secret name.
    pub name: String,
    /// Id of the new version (`None` when no version was created).
    pub version_id: Option<String>,
}

/// Result of `put_secret_value`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PutSecretValueResult {
    /// Full ARN.
    pub arn: String,
    /// Secret name.
    pub name: String,
    /// Id of the new version.
    pub version_id: String,
    /// Stage labels of the new version.
    pub version_stages: Vec<String>,
}

/// Result of `delete_secret`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteSecretResult {
    /// Full ARN.
    pub arn: String,
    /// Secret name.
    pub name: String,
    /// When the secret will be (or was) deleted.
    pub deletion_date: Option<SystemTime>,
}

/// Result of `get_resource_policy`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResourcePolicyResult {
    /// Full ARN.
    pub arn: String,
    /// Secret name.
    pub name: String,
    /// The policy JSON text, `None` when the secret has no policy.
    pub resource_policy: Option<String>,
    /// The parsed policy, `None` when there is none or it is not a JSON object.
    pub policy: Option<Value>,
}

/// One problem found by `validate_resource_policy`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyValidationError {
    /// Check that failed.
    pub check_name: Option<String>,
    /// Problem description.
    pub error_message: Option<String>,
}

/// Result of `validate_resource_policy`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidateResourcePolicyResult {
    /// Whether the policy passed.
    pub policy_validation_passed: bool,
    /// Problems found.
    pub validation_errors: Vec<PolicyValidationError>,
}

/// A per-secret failure of `batch_get_secret_value` (the call itself succeeded).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchGetError {
    /// The requested id.
    pub secret_id: Option<String>,
    /// AWS error code, e.g. `ResourceNotFoundException`.
    pub error_code: Option<String>,
    /// Vendor message.
    pub message: Option<String>,
}

/// Result of `batch_get_secret_value`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchGetResult {
    /// Values, in request order for the id form.
    pub secret_values: Vec<AwsSecretValue>,
    /// Ids that could not be read.
    pub errors: Vec<BatchGetError>,
}

/// A `ListSecrets` / `BatchGetSecretValue` filter. A value prefixed with `!` negates it (AWS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFilter {
    /// `name`, `description`, `tag-key`, `tag-value`, `primary-region`, `owning-service` or `all`.
    pub key: String,
    /// Values (prefix matches).
    pub values: Vec<String>,
}

impl SecretFilter {
    /// A filter with any key.
    pub fn new<I, S>(key: impl Into<String>, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        SecretFilter {
            key: key.into(),
            values: values.into_iter().map(Into::into).collect(),
        }
    }
    /// `name` filter.
    pub fn name(value: impl Into<String>) -> Self {
        SecretFilter::new("name", [value.into()])
    }
    /// `tag-key` filter.
    pub fn tag_key(value: impl Into<String>) -> Self {
        SecretFilter::new("tag-key", [value.into()])
    }
    /// `tag-value` filter.
    pub fn tag_value(value: impl Into<String>) -> Self {
        SecretFilter::new("tag-value", [value.into()])
    }
    /// `description` filter.
    pub fn description(value: impl Into<String>) -> Self {
        SecretFilter::new("description", [value.into()])
    }
    /// `all` filter (matches any field).
    pub fn all(value: impl Into<String>) -> Self {
        SecretFilter::new("all", [value.into()])
    }
}

/// A replica region for `create_secret`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicaRegion {
    /// Region.
    pub region: String,
    /// KMS key in that region.
    pub kms_key_id: Option<String>,
}

/// What `batch_get_secret_value` reads: explicit ids or filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchGetSelector {
    /// Names or ARNs (split into chunks of 20, results in request order).
    Ids(Vec<String>),
    /// Filters (all pages are read).
    Filters(Vec<SecretFilter>),
}

impl From<Vec<String>> for BatchGetSelector {
    fn from(ids: Vec<String>) -> Self {
        BatchGetSelector::Ids(ids)
    }
}
impl From<&[&str]> for BatchGetSelector {
    fn from(ids: &[&str]) -> Self {
        BatchGetSelector::Ids(ids.iter().map(|s| (*s).to_owned()).collect())
    }
}
impl<const N: usize> From<[&str; N]> for BatchGetSelector {
    fn from(ids: [&str; N]) -> Self {
        BatchGetSelector::Ids(ids.iter().map(|s| (*s).to_owned()).collect())
    }
}
impl From<Vec<SecretFilter>> for BatchGetSelector {
    fn from(filters: Vec<SecretFilter>) -> Self {
        BatchGetSelector::Filters(filters)
    }
}

/// A resource policy: JSON text or a JSON document (encoded before sending).
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDocument {
    /// JSON text sent as is.
    Text(String),
    /// JSON document.
    Json(Value),
}

impl PolicyDocument {
    /// The JSON text.
    pub fn to_text(&self) -> String {
        match self {
            PolicyDocument::Text(t) => t.clone(),
            PolicyDocument::Json(v) => v.to_string(),
        }
    }
}

impl From<&str> for PolicyDocument {
    fn from(v: &str) -> Self {
        PolicyDocument::Text(v.to_owned())
    }
}
impl From<String> for PolicyDocument {
    fn from(v: String) -> Self {
        PolicyDocument::Text(v)
    }
}
impl From<Value> for PolicyDocument {
    fn from(v: Value) -> Self {
        PolicyDocument::Json(v)
    }
}

/// Selects a version by id or by stage label (default `AWSCURRENT`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GetSecretValueOptions {
    /// Version id (`VersionId`).
    pub version_id: Option<String>,
    /// Stage label, e.g. `AWSCURRENT`, `AWSPREVIOUS` or a custom label.
    pub version_stage: Option<String>,
}

impl GetSecretValueOptions {
    /// Reads the version with this id.
    pub fn version_id(id: impl Into<String>) -> Self {
        GetSecretValueOptions {
            version_id: Some(id.into()),
            version_stage: None,
        }
    }
    /// Reads the version with this stage label.
    pub fn version_stage(stage: impl Into<String>) -> Self {
        GetSecretValueOptions {
            version_id: None,
            version_stage: Some(stage.into()),
        }
    }
}

/// Options of `batch_get_secret_value`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchGetOptions {
    /// Page size for the filter form (1–20).
    pub max_results: Option<i32>,
}

/// Options of `list_secrets`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListSecretsOptions {
    /// Filters.
    pub filters: Vec<SecretFilter>,
    /// Include secrets scheduled for deletion.
    pub include_planned_deletion: Option<bool>,
    /// Sort by creation date: `asc` or `desc`.
    pub sort_order: Option<String>,
    /// Page size (1–100).
    pub max_results: Option<i32>,
}

/// Options of `list_secret_version_ids`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListSecretVersionIdsOptions {
    /// Include versions without a stage label (deprecated versions).
    pub include_deprecated: Option<bool>,
    /// Page size (1–100).
    pub max_results: Option<i32>,
}

/// Options of `create_secret`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateSecretOptions {
    /// Description.
    pub description: Option<String>,
    /// KMS key id/ARN/alias (default `aws/secretsmanager`).
    pub kms_key_id: Option<String>,
    /// Tags.
    pub tags: BTreeMap<String, String>,
    /// Idempotency token (32–64 chars, becomes the version id). The SDK fills one when unset.
    pub client_request_token: Option<String>,
    /// Replica regions.
    pub add_replica_regions: Vec<ReplicaRegion>,
    /// Overwrite a secret with the same name in a replica region.
    pub force_overwrite_replica_secret: Option<bool>,
}

/// Options of `put_secret_value`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PutSecretValueOptions {
    /// Stage labels for the new version (default `["AWSCURRENT"]`).
    pub version_stages: Vec<String>,
    /// Idempotency token.
    pub client_request_token: Option<String>,
}

/// Options of `update_secret`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UpdateSecretOptions {
    /// New value (creates a new `AWSCURRENT` version).
    pub value: Option<SecretData>,
    /// New description.
    pub description: Option<String>,
    /// New KMS key.
    pub kms_key_id: Option<String>,
    /// Idempotency token.
    pub client_request_token: Option<String>,
}

/// Options of `update_secret_version_stage`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateSecretVersionStageOptions {
    /// Version that receives the label.
    pub move_to_version_id: Option<String>,
    /// Version that loses the label (required when moving `AWSCURRENT`).
    pub remove_from_version_id: Option<String>,
}

/// Options of `delete_secret`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteSecretOptions {
    /// Days before the secret is purged (7–30; AWS default 30).
    pub recovery_window_days: Option<u32>,
    /// Delete immediately without recovery. Mutually exclusive with `recovery_window_days`.
    pub force_delete_without_recovery: Option<bool>,
}

/// Options of `put_resource_policy`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PutResourcePolicyOptions {
    /// Reject policies that grant public access (AWS default true).
    pub block_public_policy: Option<bool>,
}

/// Options of `validate_resource_policy`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidateResourcePolicyOptions {
    /// Secret the policy would be attached to.
    pub secret_id: Option<String>,
}

/// Options of `rotate_secret`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotateSecretOptions {
    /// Rotation Lambda ARN (omit for managed rotation or to keep the current function).
    pub lambda_arn: Option<String>,
    /// Rotation schedule.
    pub rules: Option<RotationRules>,
    /// Rotate now (AWS default true).
    pub rotate_immediately: Option<bool>,
    /// Idempotency token.
    pub client_request_token: Option<String>,
}

/// Options of `get_random_password`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RandomPasswordOptions {
    /// Length 1–4096 (default 32).
    pub length: Option<i64>,
    /// Characters that must not appear.
    pub exclude_characters: Option<String>,
    /// No digits.
    pub exclude_numbers: Option<bool>,
    /// No punctuation.
    pub exclude_punctuation: Option<bool>,
    /// No upper-case letters.
    pub exclude_uppercase: Option<bool>,
    /// No lower-case letters.
    pub exclude_lowercase: Option<bool>,
    /// Allow spaces.
    pub include_space: Option<bool>,
    /// Include at least one character of every included type (AWS default true).
    pub require_each_included_type: Option<bool>,
}

// ----------------------------------------------------------------------------------------
// converters

pub(crate) fn time(dt: Option<&DateTime>) -> Option<SystemTime> {
    dt.and_then(|d| SystemTime::try_from(*d).ok())
}

pub(crate) fn rfc3339_opt(t: Option<SystemTime>) -> Option<String> {
    t.map(crate::secrets::rfc3339)
}

pub(crate) fn s(v: Option<&str>) -> String {
    v.unwrap_or_default().to_owned()
}

pub(crate) fn o(v: Option<&str>) -> Option<String> {
    v.map(str::to_owned)
}

/// Tags as the AWS list form.
pub(crate) fn to_aws_tags<'a>(
    tags: impl IntoIterator<Item = (&'a String, &'a String)>,
) -> Vec<sdk::Tag> {
    tags.into_iter()
        .map(|(k, v)| sdk::Tag::builder().key(k).value(v).build())
        .collect()
}

/// The AWS tag list as a map.
pub(crate) fn from_aws_tags(tags: &[sdk::Tag]) -> BTreeMap<String, String> {
    tags.iter()
        .filter_map(|t| t.key().map(|k| (k.to_owned(), s(t.value()))))
        .collect()
}

/// Filters as the AWS form.
pub(crate) fn to_aws_filters(filters: &[SecretFilter]) -> Vec<sdk::Filter> {
    filters
        .iter()
        .map(|f| {
            sdk::Filter::builder()
                .key(sdk::FilterNameStringType::from(f.key.as_str()))
                .set_values(Some(f.values.clone()))
                .build()
        })
        .collect()
}

/// `SecretString` / `SecretBinary` of a value: text and JSON as `SecretString`, bytes as
/// `SecretBinary`.
pub(crate) enum Encoded {
    Text(String),
    Binary(Vec<u8>),
}

pub(crate) fn encode_value(value: SecretData) -> Result<Encoded> {
    Ok(match value {
        SecretData::Text(t) => Encoded::Text(t),
        SecretData::Bytes(b) => Encoded::Binary(b),
        SecretData::Json(v) => Encoded::Text(serde_json::to_string(&v)?),
    })
}

/// Raw bytes: valid UTF-8 → `SecretString`, anything else → `SecretBinary`.
pub(crate) fn encode_bytes(bytes: Vec<u8>) -> SecretData {
    match String::from_utf8(bytes) {
        Ok(text) => SecretData::Text(text),
        Err(e) => SecretData::Bytes(e.into_bytes()),
    }
}

pub(crate) fn value_of(
    arn: Option<&str>,
    name: Option<&str>,
    version_id: Option<&str>,
    stages: &[String],
    created: Option<&DateTime>,
    string: Option<&str>,
    binary: Option<&aws_smithy_types::Blob>,
) -> AwsSecretValue {
    let is_binary = binary.is_some();
    let bytes = match (binary, string) {
        (Some(b), _) => b.as_ref().to_vec(),
        (None, Some(t)) => t.as_bytes().to_vec(),
        (None, None) => Vec::new(),
    };
    let mut value = SecretValue::new(bytes);
    if let Some(v) = version_id {
        value = value.with_version(v);
    }
    AwsSecretValue {
        arn: s(arn),
        name: s(name),
        version_id: o(version_id),
        version_stages: stages.to_vec(),
        created_date: time(created),
        binary: is_binary,
        value,
    }
}

pub(crate) fn from_entry(e: &sdk::SecretValueEntry) -> AwsSecretValue {
    value_of(
        e.arn(),
        e.name(),
        e.version_id(),
        e.version_stages(),
        e.created_date(),
        e.secret_string(),
        e.secret_binary(),
    )
}

pub(crate) fn rules_from(r: Option<&sdk::RotationRulesType>) -> Option<RotationRules> {
    r.map(|r| RotationRules {
        automatically_after_days: r.automatically_after_days(),
        duration: o(r.duration()),
        schedule_expression: o(r.schedule_expression()),
    })
}

pub(crate) fn rules_to(r: &RotationRules) -> sdk::RotationRulesType {
    sdk::RotationRulesType::builder()
        .set_automatically_after_days(r.automatically_after_days)
        .set_duration(r.duration.clone())
        .set_schedule_expression(r.schedule_expression.clone())
        .build()
}

fn stages_map<V: AsRef<[String]>>(
    m: Option<&std::collections::HashMap<String, V>>,
) -> BTreeMap<String, Vec<String>> {
    m.map(|m| {
        m.iter()
            .map(|(k, v)| (k.clone(), v.as_ref().to_vec()))
            .collect()
    })
    .unwrap_or_default()
}

pub(crate) fn describe_from_output(
    out: &aws_sdk_secretsmanager::operation::describe_secret::DescribeSecretOutput,
) -> SecretDescription {
    SecretDescription {
        arn: s(out.arn()),
        name: s(out.name()),
        description: o(out.description()),
        kms_key_id: o(out.kms_key_id()),
        rotation_enabled: out.rotation_enabled().unwrap_or(false),
        rotation_lambda_arn: o(out.rotation_lambda_arn()),
        rotation_rules: rules_from(out.rotation_rules()),
        last_rotated_date: time(out.last_rotated_date()),
        last_changed_date: time(out.last_changed_date()),
        last_accessed_date: time(out.last_accessed_date()),
        deleted_date: time(out.deleted_date()),
        next_rotation_date: time(out.next_rotation_date()),
        created_date: time(out.created_date()),
        primary_region: o(out.primary_region()),
        owning_service: o(out.owning_service()),
        tags: from_aws_tags(out.tags()),
        version_ids_to_stages: stages_map(out.version_ids_to_stages()),
        replication_status: out
            .replication_status()
            .iter()
            .map(|r| ReplicationStatus {
                region: o(r.region()),
                kms_key_id: o(r.kms_key_id()),
                status: r.status().map(|s| s.as_str().to_owned()),
                status_message: o(r.status_message()),
                last_accessed_date: time(r.last_accessed_date()),
            })
            .collect(),
    }
}

pub(crate) fn describe_from_list(e: &sdk::SecretListEntry) -> SecretDescription {
    SecretDescription {
        arn: s(e.arn()),
        name: s(e.name()),
        description: o(e.description()),
        kms_key_id: o(e.kms_key_id()),
        rotation_enabled: e.rotation_enabled().unwrap_or(false),
        rotation_lambda_arn: o(e.rotation_lambda_arn()),
        rotation_rules: rules_from(e.rotation_rules()),
        last_rotated_date: time(e.last_rotated_date()),
        last_changed_date: time(e.last_changed_date()),
        last_accessed_date: time(e.last_accessed_date()),
        deleted_date: time(e.deleted_date()),
        next_rotation_date: time(e.next_rotation_date()),
        created_date: time(e.created_date()),
        primary_region: o(e.primary_region()),
        owning_service: o(e.owning_service()),
        tags: from_aws_tags(e.tags()),
        version_ids_to_stages: stages_map(e.secret_versions_to_stages()),
        replication_status: Vec::new(),
    }
}

pub(crate) fn version_from(v: &sdk::SecretVersionsListEntry) -> SecretVersion {
    SecretVersion {
        version_id: s(v.version_id()),
        version_stages: v.version_stages().to_vec(),
        created_date: time(v.created_date()),
        last_accessed_date: time(v.last_accessed_date()),
        kms_key_ids: v.kms_key_ids().to_vec(),
    }
}

pub(crate) fn batch_error_from(e: &sdk::ApiErrorType) -> BatchGetError {
    BatchGetError {
        secret_id: o(e.secret_id()),
        error_code: o(e.error_code()),
        message: o(e.message()),
    }
}

/// Parses a policy JSON text into an object (`None` when absent or not a JSON object).
pub fn parse_policy(text: Option<&str>) -> Option<Value> {
    let parsed: Value = serde_json::from_str(text?).ok()?;
    parsed.is_object().then_some(parsed)
}

/// Whether an AWS `NextToken` means "more pages" (absent and `""` end the list).
pub(crate) fn next_token(token: Option<&str>) -> Option<String> {
    token.filter(|t| !t.is_empty()).map(str::to_owned)
}

/// Exact key first, then a dot path (`"db.host"`). `None` when absent or JSON `null`.
pub fn json_field(doc: &Value, field: &str) -> Option<Value> {
    let obj = doc.as_object()?;
    if let Some(v) = obj.get(field) {
        return (!v.is_null()).then(|| v.clone());
    }
    let mut current = doc;
    for part in field.split('.') {
        current = current.as_object()?.get(part)?;
    }
    (!current.is_null()).then(|| current.clone())
}

/// `VALIDATION` unless `id` is a non-blank string.
pub(crate) fn require_id(operation: &str, id: &str) -> Result<()> {
    if id.trim().is_empty() {
        return Err(Error::validation(format!(
            "{operation}: secret id must not be empty"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_field_rules() {
        let doc = json!({"a.b": 1, "db": {"host": "h", "n": null}, "z": null});
        assert_eq!(json_field(&doc, "a.b"), Some(json!(1)));
        assert_eq!(json_field(&doc, "db.host"), Some(json!("h")));
        assert_eq!(json_field(&doc, "db.n"), None);
        assert_eq!(json_field(&doc, "z"), None);
        assert_eq!(json_field(&doc, "db.host.x"), None);
        assert_eq!(json_field(&doc, "missing"), None);
        assert_eq!(json_field(&json!([1]), "x"), None);
    }

    #[test]
    fn helpers() {
        assert_eq!(parse_policy(Some("{\"a\":1}")), Some(json!({"a": 1})));
        assert_eq!(parse_policy(Some("[1]")), None);
        assert_eq!(parse_policy(Some("nope")), None);
        assert_eq!(parse_policy(None), None);
        assert_eq!(next_token(Some("")), None);
        assert_eq!(next_token(Some("t")).as_deref(), Some("t"));
        assert!(require_id("op", " ").is_err());
        assert!(matches!(encode_bytes(vec![0xff]), SecretData::Bytes(_)));
        assert!(matches!(encode_bytes(b"ok".to_vec()), SecretData::Text(_)));
        assert!(matches!(
            encode_value(SecretData::Json(json!({"a": 1}))).unwrap(),
            Encoded::Text(t) if t == "{\"a\":1}"
        ));
        assert_eq!(PolicyDocument::from(json!({"a": 1})).to_text(), "{\"a\":1}");
        assert_eq!(PolicyDocument::from("x").to_text(), "x");
        assert_eq!(PolicyDocument::from("x".to_owned()).to_text(), "x");
        assert_eq!(SecretFilter::tag_value("v").key, "tag-value");
        assert_eq!(SecretFilter::description("v").key, "description");
        assert_eq!(SecretFilter::all("v").key, "all");
        assert_eq!(SecretFilter::tag_key("v").key, "tag-key");
        assert_eq!(
            BatchGetSelector::from(vec!["a".to_owned()]),
            BatchGetSelector::from(["a"])
        );
        let ids: &[&str] = &["a"];
        assert_eq!(BatchGetSelector::from(ids), BatchGetSelector::from(["a"]));
        let d = SecretDescription {
            version_ids_to_stages: [("v1".to_owned(), vec![AWSCURRENT.to_owned()])].into(),
            ..Default::default()
        };
        assert_eq!(d.current_version_id(), Some("v1"));
        assert!(!d.pending_deletion());
        assert_eq!(
            GetSecretValueOptions::version_id("x").version_id.as_deref(),
            Some("x")
        );
    }
}
