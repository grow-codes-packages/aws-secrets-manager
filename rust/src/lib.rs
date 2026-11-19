// Service-owned (created from the sdk-kit 0.1.0 skeleton).
//! # grow-aws-secrets-manager
//!
//! Rust SDK for [AWS Secrets Manager](https://grow-codes-packages.github.io/aws-secrets-manager/)
//! by Grow Codes, built on the official AWS SDK for Rust (`aws-sdk-secretsmanager`).
//!
//! ```no_run
//! # async fn demo() -> grow_aws_secrets_manager::Result<()> {
//! use grow_aws_secrets_manager::secrets::SecretsProvider;
//! use grow_aws_secrets_manager::{AwsSecretsManagerClient, AwsSecretsManagerConfig};
//! use grow_aws_secrets_manager::models::GetSecretValueOptions;
//!
//! let client = AwsSecretsManagerClient::new(AwsSecretsManagerConfig::from_env()?)?;
//! let secret = client.get_secret_value("prod/db", GetSecretValueOptions::default()).await?;
//! println!("version {:?}", secret.version_id); // the value itself prints as [REDACTED]
//! let password = client.get_json_field("prod/db", "password", Default::default()).await?;
//! let provider = client.secrets();
//! let api_key = provider.get_string("prod/api-key", None).await?;
//! # let _ = (password, api_key);
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes and the conformance
//! runner).
//!
//! Not affiliated with or endorsed by Amazon Web Services. AWS and AWS Secrets Manager are
//! trademarks of Amazon.com, Inc. or its affiliates.
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

mod api;
mod aws_error;
mod cache;
mod client;
mod config;
pub mod models;
mod paginator;
mod provider;
mod sdk;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub mod secrets;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::{
    DEFAULT_RECOVERY_WINDOW_DAYS, DEFAULT_ROLE_SESSION_NAME, DEFAULT_URL, VENDOR_PROFILE_VARS,
    VENDOR_REGION_VARS, VENDOR_URL_VARS,
};

pub use crate::client::AwsSecretsManagerClient;

pub use crate::config::AwsSecretsManagerConfig;

pub use crate::config::AwsSecretsManagerConfigBuilder;

pub use crate::aws_error::{
    aws_error_code, error_code_for_aws, error_code_from_body, AwsErrorDetail, AWS_ERROR_CODES,
};
pub use crate::cache::{
    AwsSecretCache, AwsSecretCacheOptions, AwsSecretCacheStats, OnRefreshError, SecretCacheSource,
    AWS_SECRET_CACHE_MAX_ENTRIES, AWS_SECRET_CACHE_TTL,
};
pub use crate::models::{API_VERSION, AWSCURRENT, AWSPENDING, AWSPREVIOUS, BATCH_GET_MAX_IDS};
pub use crate::paginator::Paginator;
pub use crate::provider::{
    full_name, is_missing, to_metadata, AwsSecretsManagerSecretsOptions,
    AwsSecretsManagerSecretsProvider,
};

/// The AWS SDK for Rust crate this package is built on (for `with_sdk_client` and the escape
/// hatch [`AwsSecretsManagerClient::sdk`]).
pub use aws_sdk_secretsmanager;

/// Service-prefixed alias of [`Error`].
pub type AwsSecretsManagerError = Error;
