// Service-owned (created from the sdk-kit 0.1.0 skeleton).
//! Blocking wrapper (feature `blocking`). Each client owns a current-thread tokio runtime.
//!
//! Do not use it from inside an async runtime (calls would panic); use the async client there.
//! List calls return every page as a `Vec`. For the secrets provider and the cache use
//! [`AwsSecretsManagerClient::block_on`] with the async API.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use crate::core::{Error, HealthStatus, Result, Secret};
use crate::models::*;
use crate::secrets::SecretData;
use crate::{AwsSecretsManagerClient as AsyncClient, AwsSecretsManagerConfig};

/// Blocking client for AWS Secrets Manager with the same methods as the async client.
#[derive(Debug)]
pub struct AwsSecretsManagerClient {
    inner: AsyncClient,
    runtime: tokio::runtime::Runtime,
}

impl AwsSecretsManagerClient {
    /// Creates a client from a configuration.
    pub fn new(config: AwsSecretsManagerConfig) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::config("cannot start the tokio runtime").with_source(e))?;
        let inner = {
            let _guard = runtime.enter();
            AsyncClient::new(config)?
        };
        Ok(AwsSecretsManagerClient { inner, runtime })
    }

    /// Creates a client from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::new(AwsSecretsManagerConfig::from_env()?)
    }

    /// The wrapped async client.
    pub fn async_client(&self) -> &AsyncClient {
        &self.inner
    }

    /// Runs a future of the async API to completion on this client's runtime.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// See [`AsyncClient::health`].
    pub fn health(&self) -> Result<HealthStatus> {
        self.block_on(self.inner.health())
    }

    /// See [`AsyncClient::ping`].
    pub fn ping(&self) -> Result<Duration> {
        self.block_on(self.inner.ping())
    }

    /// See [`AsyncClient::server_version`].
    pub fn server_version(&self) -> Result<String> {
        self.block_on(self.inner.server_version())
    }

    /// See [`AsyncClient::close`]. Idempotent.
    pub fn close(&self) {
        self.block_on(self.inner.close());
    }

    /// See [`AsyncClient::get_secret_value`].
    pub fn get_secret_value(
        &self,
        secret_id: &str,
        opts: GetSecretValueOptions,
    ) -> Result<AwsSecretValue> {
        self.block_on(self.inner.get_secret_value(secret_id, opts))
    }

    /// See [`AsyncClient::batch_get_secret_value`].
    pub fn batch_get_secret_value(
        &self,
        selector: impl Into<BatchGetSelector>,
        opts: BatchGetOptions,
    ) -> Result<BatchGetResult> {
        self.block_on(self.inner.batch_get_secret_value(selector, opts))
    }

    /// See [`AsyncClient::describe_secret`].
    pub fn describe_secret(&self, secret_id: &str) -> Result<SecretDescription> {
        self.block_on(self.inner.describe_secret(secret_id))
    }

    /// See [`AsyncClient::list_secrets`]; returns every page.
    pub fn list_secrets(&self, opts: ListSecretsOptions) -> Result<Vec<SecretDescription>> {
        self.block_on(self.inner.list_secrets(opts).try_collect())
    }

    /// See [`AsyncClient::list_secret_version_ids`]; returns every page.
    pub fn list_secret_version_ids(
        &self,
        secret_id: &str,
        opts: ListSecretVersionIdsOptions,
    ) -> Result<Vec<SecretVersion>> {
        self.block_on(
            self.inner
                .list_secret_version_ids(secret_id, opts)
                .try_collect(),
        )
    }

    /// See [`AsyncClient::create_secret`].
    pub fn create_secret(
        &self,
        name: &str,
        value: Option<SecretData>,
        opts: CreateSecretOptions,
    ) -> Result<SecretWriteResult> {
        self.block_on(self.inner.create_secret(name, value, opts))
    }

    /// See [`AsyncClient::put_secret_value`].
    pub fn put_secret_value(
        &self,
        secret_id: &str,
        value: impl Into<SecretData>,
        opts: PutSecretValueOptions,
    ) -> Result<PutSecretValueResult> {
        self.block_on(self.inner.put_secret_value(secret_id, value, opts))
    }

    /// See [`AsyncClient::update_secret`].
    pub fn update_secret(
        &self,
        secret_id: &str,
        opts: UpdateSecretOptions,
    ) -> Result<SecretWriteResult> {
        self.block_on(self.inner.update_secret(secret_id, opts))
    }

    /// See [`AsyncClient::update_secret_version_stage`].
    pub fn update_secret_version_stage(
        &self,
        secret_id: &str,
        version_stage: &str,
        opts: UpdateSecretVersionStageOptions,
    ) -> Result<SecretRef> {
        self.block_on(
            self.inner
                .update_secret_version_stage(secret_id, version_stage, opts),
        )
    }

    /// See [`AsyncClient::delete_secret`].
    pub fn delete_secret(
        &self,
        secret_id: &str,
        opts: DeleteSecretOptions,
    ) -> Result<DeleteSecretResult> {
        self.block_on(self.inner.delete_secret(secret_id, opts))
    }

    /// See [`AsyncClient::restore_secret`].
    pub fn restore_secret(&self, secret_id: &str) -> Result<SecretRef> {
        self.block_on(self.inner.restore_secret(secret_id))
    }

    /// See [`AsyncClient::tag_resource`].
    pub fn tag_resource(&self, secret_id: &str, tags: BTreeMap<String, String>) -> Result<()> {
        self.block_on(self.inner.tag_resource(secret_id, tags))
    }

    /// See [`AsyncClient::untag_resource`].
    pub fn untag_resource(&self, secret_id: &str, tag_keys: Vec<String>) -> Result<()> {
        self.block_on(self.inner.untag_resource(secret_id, tag_keys))
    }

    /// See [`AsyncClient::put_resource_policy`].
    pub fn put_resource_policy(
        &self,
        secret_id: &str,
        policy: impl Into<PolicyDocument>,
        opts: PutResourcePolicyOptions,
    ) -> Result<SecretRef> {
        self.block_on(self.inner.put_resource_policy(secret_id, policy, opts))
    }

    /// See [`AsyncClient::get_resource_policy`].
    pub fn get_resource_policy(&self, secret_id: &str) -> Result<ResourcePolicyResult> {
        self.block_on(self.inner.get_resource_policy(secret_id))
    }

    /// See [`AsyncClient::delete_resource_policy`].
    pub fn delete_resource_policy(&self, secret_id: &str) -> Result<SecretRef> {
        self.block_on(self.inner.delete_resource_policy(secret_id))
    }

    /// See [`AsyncClient::validate_resource_policy`].
    pub fn validate_resource_policy(
        &self,
        policy: impl Into<PolicyDocument>,
        opts: ValidateResourcePolicyOptions,
    ) -> Result<ValidateResourcePolicyResult> {
        self.block_on(self.inner.validate_resource_policy(policy, opts))
    }

    /// See [`AsyncClient::rotate_secret`].
    pub fn rotate_secret(
        &self,
        secret_id: &str,
        opts: RotateSecretOptions,
    ) -> Result<SecretWriteResult> {
        self.block_on(self.inner.rotate_secret(secret_id, opts))
    }

    /// See [`AsyncClient::cancel_rotate_secret`].
    pub fn cancel_rotate_secret(&self, secret_id: &str) -> Result<SecretWriteResult> {
        self.block_on(self.inner.cancel_rotate_secret(secret_id))
    }

    /// See [`AsyncClient::get_random_password`].
    pub fn get_random_password(&self, opts: RandomPasswordOptions) -> Result<Secret> {
        self.block_on(self.inner.get_random_password(opts))
    }

    /// See [`AsyncClient::get_json_field`].
    pub fn get_json_field(
        &self,
        secret_id: &str,
        field: &str,
        opts: GetSecretValueOptions,
    ) -> Result<Option<serde_json::Value>> {
        self.block_on(self.inner.get_json_field(secret_id, field, opts))
    }
}

impl Drop for AwsSecretsManagerClient {
    fn drop(&mut self) {
        self.inner.shutdown();
    }
}
