//! [`SecretsProvider`] (SPEC §3) on AWS Secrets Manager (API.md §3).
//!
//! Names are flat AWS secret names that may contain `/`: `path/name` when a path is given.
//! `version` is the AWS `VersionId`. A secret scheduled for deletion counts as missing.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{self, StreamExt, TryStreamExt};

use crate::aws_error::{aws_error_code, error_code_for_aws};
use crate::client::AwsSecretsManagerClient;
use crate::core::{Error, ErrorCode, Result};
use crate::models::{
    encode_bytes, rfc3339_opt, CreateSecretOptions, DeleteSecretOptions, GetSecretValueOptions,
    ListSecretsOptions, PutSecretValueOptions, SecretDescription, SecretFilter,
    UpdateSecretOptions, BATCH_GET_MAX_IDS,
};
use crate::secrets::{
    watch, DeleteOptions, GetOptions, SecretData, SecretMap, SecretMetadata, SecretValue,
    SecretsProvider, SetOptions, WatchHandle, WatchOptions,
};

/// Concurrent reads of `get_many` with an explicit version.
const READ_CONCURRENCY: usize = 8;

/// Options of [`AwsSecretsManagerClient::secrets_with_options`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AwsSecretsManagerSecretsOptions {
    /// Recovery window of `delete()` in days (default `config.recovery_window_days`, i.e. 30).
    pub recovery_window_days: Option<u32>,
}

/// Batch error codes that mean "missing" for `get_many` (deleted counts as missing).
const MISSING_BATCH_CODES: &[&str] = &["ResourceNotFoundException", "InvalidRequestException"];

fn trim_slashes(path: &str) -> &str {
    path.trim_matches('/')
}

/// `path/name` when a path is given, otherwise `name`.
pub fn full_name(name: &str, path: Option<&str>) -> String {
    match path.map(trim_slashes) {
        Some(p) if !p.is_empty() => format!("{p}/{name}"),
        _ => name.to_owned(),
    }
}

/// Whether `err` means "missing": `NOT_FOUND`, or `InvalidRequestException` (the secret is
/// scheduled for deletion).
pub fn is_missing(err: &Error) -> bool {
    err.is(ErrorCode::NotFound)
        || (err.is(ErrorCode::Conflict) && aws_error_code(err) == Some("InvalidRequestException"))
}

fn check_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(Error::validation("secret name must not be empty"));
    }
    Ok(())
}

/// Converts a description into SPEC metadata.
pub fn to_metadata(d: &SecretDescription) -> SecretMetadata {
    let mut extra = BTreeMap::new();
    extra.insert("arn".to_owned(), d.arn.clone());
    extra.insert("rotationEnabled".to_owned(), d.rotation_enabled.to_string());
    if let Some(v) = &d.description {
        extra.insert("description".to_owned(), v.clone());
    }
    if let Some(v) = &d.kms_key_id {
        extra.insert("kmsKeyId".to_owned(), v.clone());
    }
    if let Some(v) = rfc3339_opt(d.next_rotation_date) {
        extra.insert("nextRotationDate".to_owned(), v);
    }
    if let Some(v) = rfc3339_opt(d.deleted_date) {
        extra.insert("deletedDate".to_owned(), v);
    }
    if let Some(v) = &d.primary_region {
        extra.insert("primaryRegion".to_owned(), v.clone());
    }
    let path = d
        .name
        .rfind('/')
        .filter(|i| *i > 0)
        .map(|i| d.name[..i].to_owned());
    SecretMetadata {
        name: d.name.clone(),
        path,
        version: d.current_version_id().map(str::to_owned),
        created_at: d.created_date,
        updated_at: d.last_changed_date,
        tags: d.tags.clone(),
        versions: Some(d.version_ids_to_stages.len() as u64),
        extra,
    }
}

/// [`SecretsProvider`] over AWS Secrets Manager (`client.secrets()`). Capabilities: `write`,
/// `versions`, `delete`.
///
/// - `get(name, version)` reads `VersionId = version` (stage labels: use
///   [`AwsSecretsManagerClient::get_secret_value`]).
/// - `set` stores text as `SecretString` and other bytes as `SecretBinary`; it creates the secret
///   when missing (with `description`/`tags`) and returns the new `VersionId`. `cas` is not
///   supported (`VALIDATION`).
/// - `delete` schedules deletion with the recovery window (default 30 days); `permanent: true`
///   deletes immediately. A name scheduled for deletion cannot be written again until it is
///   restored or purged (`CONFLICT`).
/// - `list(prefix)` matches names by string prefix (recursive); `get_all(path)` returns the
///   secrets directly under `path` (non-recursive). `get_many` uses `BatchGetSecretValue`.
#[derive(Debug, Clone)]
pub struct AwsSecretsManagerSecretsProvider {
    client: AwsSecretsManagerClient,
    recovery_window_days: u32,
}

impl AwsSecretsManagerSecretsProvider {
    /// Capabilities declared to the conformance runner.
    pub const CAPABILITIES: [&'static str; 3] = ["write", "versions", "delete"];

    pub(crate) fn new(client: AwsSecretsManagerClient, recovery_window_days: u32) -> Self {
        AwsSecretsManagerSecretsProvider {
            client,
            recovery_window_days,
        }
    }

    /// The client this provider uses.
    pub fn client(&self) -> &AwsSecretsManagerClient {
        &self.client
    }

    /// Recovery window of `delete()` in days.
    pub fn recovery_window_days(&self) -> u32 {
        self.recovery_window_days
    }

    /// Polls `name` every `interval` and calls `on_change(new, old)` when its version changes
    /// (including deletion). `close()` of the client stops the watch. See [`watch`].
    pub fn watch<F>(
        &self,
        name: impl Into<String>,
        interval: Duration,
        on_change: F,
        opts: WatchOptions,
    ) -> WatchHandle
    where
        F: Fn(Option<&SecretValue>, Option<&SecretValue>) + Send + Sync + 'static,
    {
        let handle = watch(Arc::new(self.clone()), name, interval, on_change, opts);
        let stop = handle.clone();
        self.client.on_close(move || {
            Box::pin(async move {
                stop.stop_and_wait().await;
            })
        });
        handle
    }

    /// Live secrets whose name starts with `prefix` (re-filtered client side: AWS's name filter
    /// also matches word prefixes inside names).
    async fn list_descriptions(&self, prefix: &str) -> Result<Vec<SecretDescription>> {
        let filters = if prefix.is_empty() {
            Vec::new()
        } else {
            vec![SecretFilter::name(prefix)]
        };
        let all = self
            .client
            .list_secrets(ListSecretsOptions {
                filters,
                ..Default::default()
            })
            .try_collect()
            .await?;
        Ok(all
            .into_iter()
            .filter(|d| d.name.starts_with(prefix) && d.deleted_date.is_none())
            .collect())
    }

    /// `DescribeSecret`; `None` when missing or scheduled for deletion.
    async fn describe(&self, id: &str) -> Result<Option<SecretDescription>> {
        match self.client.describe_secret(id).await {
            Ok(d) if d.deleted_date.is_none() => Ok(Some(d)),
            Ok(_) => Ok(None),
            Err(e) if is_missing(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn put_existing(&self, id: &str, value: SecretData, opts: &SetOptions) -> Result<String> {
        let out = self
            .client
            .put_secret_value(id, value, PutSecretValueOptions::default())
            .await?;
        if !opts.tags.is_empty() {
            self.client.tag_resource(id, opts.tags.clone()).await?;
        }
        if let Some(description) = &opts.description {
            self.client
                .update_secret(
                    id,
                    UpdateSecretOptions {
                        description: Some(description.clone()),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Ok(out.version_id)
    }
}

#[async_trait]
impl SecretsProvider for AwsSecretsManagerSecretsProvider {
    async fn get(&self, name: &str, opts: Option<&GetOptions>) -> Result<Option<SecretValue>> {
        check_name(name)?;
        let default = GetOptions::default();
        let opts = opts.unwrap_or(&default);
        let id = full_name(name, opts.path.as_deref());
        let read = GetSecretValueOptions {
            version_id: opts.version.clone(),
            version_stage: None,
        };
        match self.client.get_secret_value(&id, read).await {
            Ok(v) => Ok(Some(v.value)),
            Err(e) if is_missing(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get_all(&self, path: Option<&str>) -> Result<SecretMap> {
        let base = path.map(trim_slashes).unwrap_or_default();
        let prefix = if base.is_empty() {
            String::new()
        } else {
            format!("{base}/")
        };
        let mut names: Vec<String> = self
            .list_descriptions(&prefix)
            .await?
            .into_iter()
            .map(|d| d.name)
            .filter(|n| !n[prefix.len()..].contains('/'))
            .collect();
        names.sort();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        self.get_many(&refs, None).await
    }

    async fn list(&self, prefix_or_path: Option<&str>) -> Result<Vec<SecretMetadata>> {
        let mut items: Vec<SecretMetadata> = self
            .list_descriptions(prefix_or_path.unwrap_or_default())
            .await?
            .iter()
            .map(to_metadata)
            .collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(items)
    }

    async fn set(
        &self,
        name: &str,
        value: SecretData,
        opts: Option<&SetOptions>,
    ) -> Result<String> {
        check_name(name)?;
        let default = SetOptions::default();
        let opts = opts.unwrap_or(&default);
        if opts.cas.is_some() {
            return Err(Error::validation(format!(
                "secrets.set {name}: AWS Secrets Manager has no compare-and-set (cas)"
            )));
        }
        let id = full_name(name, opts.path.as_deref());
        let value = encode_bytes(value.into_bytes()?);
        match self.put_existing(&id, value.clone(), opts).await {
            Ok(version) => return Ok(version),
            Err(e) if e.is(ErrorCode::NotFound) => {}
            Err(e) => return Err(e),
        }
        let created = self
            .client
            .create_secret(
                &id,
                Some(value.clone()),
                CreateSecretOptions {
                    description: opts.description.clone(),
                    tags: opts.tags.clone(),
                    ..Default::default()
                },
            )
            .await;
        match created {
            Ok(out) => Ok(out.version_id.unwrap_or_default()),
            // Lost a create race: the secret exists now, write the value as a new version.
            Err(e) if aws_error_code(&e) == Some("ResourceExistsException") => {
                self.put_existing(&id, value, opts).await
            }
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, name: &str, opts: Option<&DeleteOptions>) -> Result<()> {
        check_name(name)?;
        let default = DeleteOptions::default();
        let opts = opts.unwrap_or(&default);
        if !opts.versions.is_empty() {
            return Err(Error::validation(format!(
                "secrets.delete {name}: AWS Secrets Manager cannot delete single versions; use update_secret_version_stage"
            )));
        }
        let id = full_name(name, opts.path.as_deref());
        // Required: a forced delete of a missing secret succeeds on AWS.
        if self.describe(&id).await?.is_none() {
            return Err(Error::not_found(format!("secrets.delete {id}: not found")));
        }
        let delete = if opts.permanent {
            DeleteSecretOptions {
                force_delete_without_recovery: Some(true),
                ..Default::default()
            }
        } else {
            DeleteSecretOptions {
                recovery_window_days: Some(self.recovery_window_days),
                ..Default::default()
            }
        };
        self.client.delete_secret(&id, delete).await?;
        Ok(())
    }

    async fn metadata(
        &self,
        name: &str,
        opts: Option<&GetOptions>,
    ) -> Result<Option<SecretMetadata>> {
        check_name(name)?;
        let path = opts.and_then(|o| o.path.as_deref());
        Ok(self
            .describe(&full_name(name, path))
            .await?
            .as_ref()
            .map(to_metadata))
    }

    /// Present secrets in request order (`BatchGetSecretValue` in chunks of 20; per-name reads
    /// when a `version` is requested).
    async fn get_many(&self, names: &[&str], opts: Option<&GetOptions>) -> Result<SecretMap> {
        let mut unique: Vec<&str> = Vec::new();
        let mut seen = BTreeSet::new();
        for n in names {
            check_name(n)?;
            if seen.insert(*n) {
                unique.push(n);
            }
        }
        if opts.is_some_and(|o| o.version.is_some()) {
            let reads: Vec<_> = unique.iter().map(|n| self.get(n, opts)).collect();
            let values: Vec<Option<SecretValue>> = stream::iter(reads)
                .buffered(READ_CONCURRENCY)
                .try_collect()
                .await?;
            return Ok(unique
                .iter()
                .zip(values)
                .filter_map(|(n, v)| v.map(|v| ((*n).to_owned(), v)))
                .collect());
        }
        let path = opts.and_then(|o| o.path.as_deref());
        let by_full: HashMap<String, &str> =
            unique.iter().map(|n| (full_name(n, path), *n)).collect();
        let ids: Vec<String> = unique.iter().map(|n| full_name(n, path)).collect();
        let mut found: HashMap<&str, SecretValue> = HashMap::new();
        for chunk in ids.chunks(BATCH_GET_MAX_IDS) {
            let result = self
                .client
                .batch_get_secret_value(chunk.to_vec(), Default::default())
                .await?;
            for e in &result.errors {
                let code = e.error_code.as_deref().unwrap_or_default();
                if MISSING_BATCH_CODES.contains(&code) {
                    continue;
                }
                let mapped = error_code_for_aws(code).unwrap_or(ErrorCode::Unavailable);
                return Err(Error::new(
                    mapped,
                    format!(
                        "secrets.getMany {}: {}",
                        e.secret_id.as_deref().unwrap_or_default(),
                        if code.is_empty() { "error" } else { code }
                    ),
                ));
            }
            for v in result.secret_values {
                if let Some(requested) = by_full.get(&v.name).or_else(|| by_full.get(&v.arn)) {
                    found.insert(requested, v.value);
                }
            }
        }
        Ok(unique
            .iter()
            .filter_map(|n| found.remove(n).map(|v| ((*n).to_owned(), v)))
            .collect())
    }
}
