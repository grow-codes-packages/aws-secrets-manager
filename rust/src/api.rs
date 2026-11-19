//! Service operations of [`AwsSecretsManagerClient`]: read, write, tags and policy, rotation and
//! utilities (API.md §2).

use std::collections::BTreeMap;

use aws_sdk_secretsmanager::types::{ReplicaRegionType, SortOrderType};
use aws_smithy_types::Blob;
use futures::FutureExt;

use crate::client::AwsSecretsManagerClient;
use crate::core::{Error, Result, Secret};
use crate::models::*;
use crate::paginator::Paginator;
use crate::secrets::SecretData;

fn op(name: &str, id: &str) -> String {
    format!("{name} {id}")
}

/// Splits an encoded value into the `SecretString` / `SecretBinary` fields.
fn fields(value: Option<SecretData>) -> Result<(Option<String>, Option<Blob>)> {
    Ok(match value.map(encode_value).transpose()? {
        None => (None, None),
        Some(Encoded::Text(t)) => (Some(t), None),
        Some(Encoded::Binary(b)) => (None, Some(Blob::new(b))),
    })
}

/// Orders batch results like the requested ids (by name or ARN).
fn order_by_ids(values: &mut [AwsSecretValue], ids: &[String]) {
    let rank = |v: &AwsSecretValue| {
        ids.iter()
            .position(|id| {
                *id == v.name
                    || *id == v.arn
                    || (id.starts_with("arn:") && v.arn.starts_with(id.as_str()))
            })
            .unwrap_or(ids.len())
    };
    values.sort_by_key(rank);
}

fn write_result(arn: Option<&str>, name: Option<&str>, version: Option<&str>) -> SecretWriteResult {
    SecretWriteResult {
        arn: s(arn),
        name: s(name),
        version_id: o(version),
    }
}

fn secret_ref(arn: Option<&str>, name: Option<&str>) -> SecretRef {
    SecretRef {
        arn: s(arn),
        name: s(name),
    }
}

impl AwsSecretsManagerClient {
    // ------------------------------------------------------------------------------------
    // read

    /// Reads a secret value (`GetSecretValue`), by default the `AWSCURRENT` version.
    /// `secret_id` is a name or ARN. `NOT_FOUND` when the secret, version or stage does not
    /// exist; `CONFLICT` when the secret is scheduled for deletion.
    pub async fn get_secret_value(
        &self,
        secret_id: &str,
        opts: GetSecretValueOptions,
    ) -> Result<AwsSecretValue> {
        require_id("getSecretValue", secret_id)?;
        let op = op("getSecretValue", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let call = sdk
            .get_secret_value()
            .secret_id(secret_id)
            .set_version_id(opts.version_id)
            .set_version_stage(opts.version_stage)
            .send();
        let out = self.run(&op, call).await?;
        Ok(value_of(
            out.arn(),
            out.name(),
            out.version_id(),
            out.version_stages(),
            out.created_date(),
            out.secret_string(),
            out.secret_binary(),
        ))
    }

    /// Reads many secrets at once (`BatchGetSecretValue`). With ids, lists longer than 20 are
    /// split and the values come back in request order; with filters every page is read.
    /// Per-secret failures are returned in `errors` (the call itself succeeds).
    pub async fn batch_get_secret_value(
        &self,
        selector: impl Into<BatchGetSelector>,
        opts: BatchGetOptions,
    ) -> Result<BatchGetResult> {
        let mut result = BatchGetResult::default();
        let sdk = self.sdk_for("batchGetSecretValue").await?;
        match selector.into() {
            BatchGetSelector::Ids(ids) => {
                for chunk in ids.chunks(BATCH_GET_MAX_IDS) {
                    let mut values = Vec::new();
                    let mut token: Option<String> = None;
                    loop {
                        let call = sdk
                            .batch_get_secret_value()
                            .set_secret_id_list(Some(chunk.to_vec()))
                            .set_next_token(token.take())
                            .send();
                        let out = self.run("batchGetSecretValue", call).await?;
                        values.extend(out.secret_values().iter().map(from_entry));
                        result
                            .errors
                            .extend(out.errors().iter().map(batch_error_from));
                        token = next_token(out.next_token());
                        if token.is_none() {
                            break;
                        }
                    }
                    order_by_ids(&mut values, chunk);
                    result.secret_values.extend(values);
                }
            }
            BatchGetSelector::Filters(filters) => {
                if filters.is_empty() {
                    return Err(Error::validation(
                        "batchGetSecretValue: give secret ids or at least one filter",
                    ));
                }
                let mut token: Option<String> = None;
                loop {
                    let call = sdk
                        .batch_get_secret_value()
                        .set_filters(Some(to_aws_filters(&filters)))
                        .set_max_results(opts.max_results)
                        .set_next_token(token.take())
                        .send();
                    let out = self.run("batchGetSecretValue", call).await?;
                    result
                        .secret_values
                        .extend(out.secret_values().iter().map(from_entry));
                    result
                        .errors
                        .extend(out.errors().iter().map(batch_error_from));
                    token = next_token(out.next_token());
                    if token.is_none() {
                        break;
                    }
                }
            }
        }
        Ok(result)
    }

    /// Metadata of a secret (`DescribeSecret`), never the value.
    pub async fn describe_secret(&self, secret_id: &str) -> Result<SecretDescription> {
        require_id("describeSecret", secret_id)?;
        let op = op("describeSecret", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let out = self
            .run(&op, sdk.describe_secret().secret_id(secret_id).send())
            .await?;
        Ok(describe_from_output(&out))
    }

    /// Lists secrets (`ListSecrets`) lazily across all pages:
    /// `client.list_secrets(opts).try_collect().await?` or `.next().await?` item by item.
    pub fn list_secrets(&self, opts: ListSecretsOptions) -> Paginator<SecretDescription> {
        let client = self.clone();
        Paginator::new(move |token| {
            let client = client.clone();
            let opts = opts.clone();
            async move {
                let sdk = client.sdk_for("listSecrets").await?;
                let filters = (!opts.filters.is_empty()).then(|| to_aws_filters(&opts.filters));
                let call = sdk
                    .list_secrets()
                    .set_filters(filters)
                    .set_include_planned_deletion(opts.include_planned_deletion)
                    .set_sort_order(opts.sort_order.as_deref().map(SortOrderType::from))
                    .set_max_results(opts.max_results)
                    .set_next_token(token)
                    .send();
                let out = client.run("listSecrets", call).await?;
                Ok((
                    out.secret_list().iter().map(describe_from_list).collect(),
                    next_token(out.next_token()),
                ))
            }
            .boxed()
        })
    }

    /// Lists the versions of a secret (`ListSecretVersionIds`) lazily across all pages.
    pub fn list_secret_version_ids(
        &self,
        secret_id: &str,
        opts: ListSecretVersionIdsOptions,
    ) -> Paginator<SecretVersion> {
        let client = self.clone();
        let id = secret_id.to_owned();
        Paginator::new(move |token| {
            let client = client.clone();
            let id = id.clone();
            let opts = opts.clone();
            async move {
                require_id("listSecretVersionIds", &id)?;
                let op = op("listSecretVersionIds", &id);
                let sdk = client.sdk_for(&op).await?;
                let call = sdk
                    .list_secret_version_ids()
                    .secret_id(&id)
                    .set_include_deprecated(opts.include_deprecated)
                    .set_max_results(opts.max_results)
                    .set_next_token(token)
                    .send();
                let out = client.run(&op, call).await?;
                Ok((
                    out.versions().iter().map(version_from).collect(),
                    next_token(out.next_token()),
                ))
            }
            .boxed()
        })
    }

    // ------------------------------------------------------------------------------------
    // write

    /// Creates a secret (`CreateSecret`). Text → `SecretString`, bytes → `SecretBinary`, JSON →
    /// JSON `SecretString`, `None` → a secret without a version. `CONFLICT` when the name exists
    /// (or is scheduled for deletion).
    pub async fn create_secret(
        &self,
        name: &str,
        value: Option<SecretData>,
        opts: CreateSecretOptions,
    ) -> Result<SecretWriteResult> {
        require_id("createSecret", name)?;
        let op = op("createSecret", name);
        let (string, binary) = fields(value)?;
        let sdk = self.sdk_for(&op).await?;
        let tags = (!opts.tags.is_empty()).then(|| to_aws_tags(&opts.tags));
        let replicas = (!opts.add_replica_regions.is_empty()).then(|| {
            opts.add_replica_regions
                .iter()
                .map(|r| {
                    ReplicaRegionType::builder()
                        .region(&r.region)
                        .set_kms_key_id(r.kms_key_id.clone())
                        .build()
                })
                .collect()
        });
        let call = sdk
            .create_secret()
            .name(name)
            .set_secret_string(string)
            .set_secret_binary(binary)
            .set_description(opts.description)
            .set_kms_key_id(opts.kms_key_id)
            .set_tags(tags)
            .set_client_request_token(opts.client_request_token)
            .set_add_replica_regions(replicas)
            .set_force_overwrite_replica_secret(opts.force_overwrite_replica_secret)
            .send();
        let out = self.run(&op, call).await?;
        Ok(write_result(out.arn(), out.name(), out.version_id()))
    }

    /// Stores a new version (`PutSecretValue`). By default it becomes `AWSCURRENT` (the old one
    /// becomes `AWSPREVIOUS`); with custom `version_stages` only those labels are attached.
    pub async fn put_secret_value(
        &self,
        secret_id: &str,
        value: impl Into<SecretData>,
        opts: PutSecretValueOptions,
    ) -> Result<PutSecretValueResult> {
        require_id("putSecretValue", secret_id)?;
        let op = op("putSecretValue", secret_id);
        let (string, binary) = fields(Some(value.into()))?;
        let sdk = self.sdk_for(&op).await?;
        let stages = (!opts.version_stages.is_empty()).then_some(opts.version_stages);
        let call = sdk
            .put_secret_value()
            .secret_id(secret_id)
            .set_secret_string(string)
            .set_secret_binary(binary)
            .set_version_stages(stages)
            .set_client_request_token(opts.client_request_token)
            .send();
        let out = self.run(&op, call).await?;
        Ok(PutSecretValueResult {
            arn: s(out.arn()),
            name: s(out.name()),
            version_id: s(out.version_id()),
            version_stages: out.version_stages().to_vec(),
        })
    }

    /// Updates description, KMS key and/or value (`UpdateSecret`). A new version is created
    /// only when a value is given.
    pub async fn update_secret(
        &self,
        secret_id: &str,
        opts: UpdateSecretOptions,
    ) -> Result<SecretWriteResult> {
        require_id("updateSecret", secret_id)?;
        let op = op("updateSecret", secret_id);
        let (string, binary) = fields(opts.value)?;
        let sdk = self.sdk_for(&op).await?;
        let call = sdk
            .update_secret()
            .secret_id(secret_id)
            .set_secret_string(string)
            .set_secret_binary(binary)
            .set_description(opts.description)
            .set_kms_key_id(opts.kms_key_id)
            .set_client_request_token(opts.client_request_token)
            .send();
        let out = self.run(&op, call).await?;
        Ok(write_result(out.arn(), out.name(), out.version_id()))
    }

    /// Moves a stage label between versions (`UpdateSecretVersionStage`). Moving `AWSCURRENT`
    /// needs `remove_from_version_id` = the current version; the old current version gets
    /// `AWSPREVIOUS`.
    pub async fn update_secret_version_stage(
        &self,
        secret_id: &str,
        version_stage: &str,
        opts: UpdateSecretVersionStageOptions,
    ) -> Result<SecretRef> {
        require_id("updateSecretVersionStage", secret_id)?;
        if opts.move_to_version_id.is_none() && opts.remove_from_version_id.is_none() {
            return Err(Error::validation(
                "updateSecretVersionStage: give moveToVersionId and/or removeFromVersionId",
            ));
        }
        let op = op("updateSecretVersionStage", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let call = sdk
            .update_secret_version_stage()
            .secret_id(secret_id)
            .version_stage(version_stage)
            .set_move_to_version_id(opts.move_to_version_id)
            .set_remove_from_version_id(opts.remove_from_version_id)
            .send();
        let out = self.run(&op, call).await?;
        Ok(secret_ref(out.arn(), out.name()))
    }

    /// Schedules deletion (`DeleteSecret`) after `recovery_window_days` (AWS default 30) or
    /// deletes immediately with `force_delete_without_recovery`. Note: AWS answers success for a
    /// forced delete of a secret that does not exist.
    pub async fn delete_secret(
        &self,
        secret_id: &str,
        opts: DeleteSecretOptions,
    ) -> Result<DeleteSecretResult> {
        require_id("deleteSecret", secret_id)?;
        let days = opts.recovery_window_days;
        let force = opts.force_delete_without_recovery;
        if days.is_some() && force == Some(true) {
            return Err(Error::validation(
                "deleteSecret: recoveryWindowDays and forceDeleteWithoutRecovery are mutually exclusive",
            ));
        }
        if let Some(d) = days {
            if !(7..=30).contains(&d) {
                return Err(Error::validation(
                    "deleteSecret: recoveryWindowDays must be an integer from 7 to 30",
                ));
            }
        }
        let op = op("deleteSecret", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let call = sdk
            .delete_secret()
            .secret_id(secret_id)
            .set_recovery_window_in_days(days.map(i64::from))
            .set_force_delete_without_recovery(force)
            .send();
        let out = self.run(&op, call).await?;
        Ok(DeleteSecretResult {
            arn: s(out.arn()),
            name: s(out.name()),
            deletion_date: time(out.deletion_date()),
        })
    }

    /// Cancels a scheduled deletion (`RestoreSecret`). A no-op for a live secret.
    pub async fn restore_secret(&self, secret_id: &str) -> Result<SecretRef> {
        require_id("restoreSecret", secret_id)?;
        let op = op("restoreSecret", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let out = self
            .run(&op, sdk.restore_secret().secret_id(secret_id).send())
            .await?;
        Ok(secret_ref(out.arn(), out.name()))
    }

    // ------------------------------------------------------------------------------------
    // tags and resource policy

    /// Adds or replaces tags (`TagResource`).
    pub async fn tag_resource<I, K, V>(&self, secret_id: &str, tags: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        require_id("tagResource", secret_id)?;
        let tags: BTreeMap<String, String> = tags
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let op = op("tagResource", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let call = sdk
            .tag_resource()
            .secret_id(secret_id)
            .set_tags(Some(to_aws_tags(&tags)))
            .send();
        self.run(&op, call).await?;
        Ok(())
    }

    /// Removes tags by key (`UntagResource`).
    pub async fn untag_resource<I, K>(&self, secret_id: &str, tag_keys: I) -> Result<()>
    where
        I: IntoIterator<Item = K>,
        K: Into<String>,
    {
        require_id("untagResource", secret_id)?;
        let keys: Vec<String> = tag_keys.into_iter().map(Into::into).collect();
        let op = op("untagResource", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let call = sdk
            .untag_resource()
            .secret_id(secret_id)
            .set_tag_keys(Some(keys))
            .send();
        self.run(&op, call).await?;
        Ok(())
    }

    /// Attaches a resource policy (`PutResourcePolicy`); JSON documents are encoded.
    pub async fn put_resource_policy(
        &self,
        secret_id: &str,
        policy: impl Into<PolicyDocument>,
        opts: PutResourcePolicyOptions,
    ) -> Result<SecretRef> {
        require_id("putResourcePolicy", secret_id)?;
        let op = op("putResourcePolicy", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let call = sdk
            .put_resource_policy()
            .secret_id(secret_id)
            .resource_policy(policy.into().to_text())
            .set_block_public_policy(opts.block_public_policy)
            .send();
        let out = self.run(&op, call).await?;
        Ok(secret_ref(out.arn(), out.name()))
    }

    /// Reads the resource policy (`GetResourcePolicy`); `resource_policy` is `None` when there
    /// is none.
    pub async fn get_resource_policy(&self, secret_id: &str) -> Result<ResourcePolicyResult> {
        require_id("getResourcePolicy", secret_id)?;
        let op = op("getResourcePolicy", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let out = self
            .run(&op, sdk.get_resource_policy().secret_id(secret_id).send())
            .await?;
        Ok(ResourcePolicyResult {
            arn: s(out.arn()),
            name: s(out.name()),
            resource_policy: o(out.resource_policy()),
            policy: parse_policy(out.resource_policy()),
        })
    }

    /// Removes the resource policy (`DeleteResourcePolicy`).
    pub async fn delete_resource_policy(&self, secret_id: &str) -> Result<SecretRef> {
        require_id("deleteResourcePolicy", secret_id)?;
        let op = op("deleteResourcePolicy", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let out = self
            .run(
                &op,
                sdk.delete_resource_policy().secret_id(secret_id).send(),
            )
            .await?;
        Ok(secret_ref(out.arn(), out.name()))
    }

    /// Checks a policy with IAM Access Analyzer (`ValidateResourcePolicy`). Emulators that lack
    /// the operation (Moto 5.2.4) answer `UNSUPPORTED`.
    pub async fn validate_resource_policy(
        &self,
        policy: impl Into<PolicyDocument>,
        opts: ValidateResourcePolicyOptions,
    ) -> Result<ValidateResourcePolicyResult> {
        let sdk = self.sdk_for("validateResourcePolicy").await?;
        let call = sdk
            .validate_resource_policy()
            .resource_policy(policy.into().to_text())
            .set_secret_id(opts.secret_id)
            .send();
        let out = self.run("validateResourcePolicy", call).await?;
        Ok(ValidateResourcePolicyResult {
            policy_validation_passed: out.policy_validation_passed(),
            validation_errors: out
                .validation_errors()
                .iter()
                .map(|e| PolicyValidationError {
                    check_name: o(e.check_name()),
                    error_message: o(e.error_message()),
                })
                .collect(),
        })
    }

    // ------------------------------------------------------------------------------------
    // rotation

    /// Configures and/or starts rotation (`RotateSecret`). Without `lambda_arn` the secret's
    /// managed or existing rotation function is used.
    pub async fn rotate_secret(
        &self,
        secret_id: &str,
        opts: RotateSecretOptions,
    ) -> Result<SecretWriteResult> {
        require_id("rotateSecret", secret_id)?;
        let op = op("rotateSecret", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let call = sdk
            .rotate_secret()
            .secret_id(secret_id)
            .set_rotation_lambda_arn(opts.lambda_arn)
            .set_rotation_rules(opts.rules.as_ref().map(rules_to))
            .set_rotate_immediately(opts.rotate_immediately)
            .set_client_request_token(opts.client_request_token)
            .send();
        let out = self.run(&op, call).await?;
        Ok(write_result(out.arn(), out.name(), out.version_id()))
    }

    /// Turns rotation off and cancels a rotation in progress (`CancelRotateSecret`).
    pub async fn cancel_rotate_secret(&self, secret_id: &str) -> Result<SecretWriteResult> {
        require_id("cancelRotateSecret", secret_id)?;
        let op = op("cancelRotateSecret", secret_id);
        let sdk = self.sdk_for(&op).await?;
        let out = self
            .run(&op, sdk.cancel_rotate_secret().secret_id(secret_id).send())
            .await?;
        Ok(write_result(out.arn(), out.name(), out.version_id()))
    }

    // ------------------------------------------------------------------------------------
    // utilities

    /// Generates a random password (`GetRandomPassword`), returned as a redacting [`Secret`].
    pub async fn get_random_password(&self, opts: RandomPasswordOptions) -> Result<Secret> {
        let sdk = self.sdk_for("getRandomPassword").await?;
        let call = sdk
            .get_random_password()
            .password_length(opts.length.unwrap_or(32))
            .set_exclude_characters(opts.exclude_characters)
            .set_exclude_numbers(opts.exclude_numbers)
            .set_exclude_punctuation(opts.exclude_punctuation)
            .set_exclude_uppercase(opts.exclude_uppercase)
            .set_exclude_lowercase(opts.exclude_lowercase)
            .set_include_space(opts.include_space)
            .set_require_each_included_type(opts.require_each_included_type)
            .send();
        let out = self.run("getRandomPassword", call).await?;
        Ok(Secret::new(out.random_password().unwrap_or_default()))
    }

    /// Reads one field of a JSON secret: `GetSecretValue`, parse `SecretString` as a JSON object,
    /// return `field` (an exact key first, otherwise a dot path such as `"db.host"`). `None`
    /// when the field is absent or `null`; `VALIDATION` when the value is binary or not a JSON
    /// object; `NOT_FOUND` when the secret is missing.
    pub async fn get_json_field(
        &self,
        secret_id: &str,
        field: &str,
        opts: GetSecretValueOptions,
    ) -> Result<Option<serde_json::Value>> {
        let secret = self.get_secret_value(secret_id, opts).await?;
        if secret.binary {
            return Err(Error::validation(format!(
                "getJsonField {secret_id}: the secret is binary, not JSON"
            )));
        }
        let parsed: serde_json::Value = secret.value.json().map_err(|_| {
            Error::validation(format!(
                "getJsonField {secret_id}: the value is not valid JSON"
            ))
        })?;
        if !parsed.is_object() {
            return Err(Error::validation(format!(
                "getJsonField {secret_id}: the value is not a JSON object"
            )));
        }
        Ok(json_field(&parsed, field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretValue;

    fn v(name: &str, arn: &str) -> AwsSecretValue {
        AwsSecretValue {
            arn: arn.into(),
            name: name.into(),
            version_id: None,
            version_stages: vec![],
            created_date: None,
            binary: false,
            value: SecretValue::new(b"x".to_vec()),
        }
    }

    #[test]
    fn orders_like_ids() {
        let mut values = vec![
            v("c", "arn:c-x"),
            v("b", "arn:aws:b-1"),
            v("a", "arn:a"),
            v("z", "arn:z"),
        ];
        let ids = vec!["a".to_owned(), "arn:aws:b".to_owned(), "arn:c-x".to_owned()];
        order_by_ids(&mut values, &ids);
        let names: Vec<&str> = values.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c", "z"]);
    }
}
