// Skeleton created by sdk-kit 0.1.0; owned by this repository (edit freely).
//! # grow-aws-secrets-manager
//!
//! Rust SDK for [AWS Secrets Manager](https://grow-codes-packages.github.io/aws-secrets-manager/) by Grow Codes.
//!
//! ```no_run
//! # async fn demo() -> grow_aws_secrets_manager::Result<()> {
//! use grow_aws_secrets_manager::{AwsSecretsManagerClient, AwsSecretsManagerConfig};
//!
//! let client = AwsSecretsManagerClient::new(AwsSecretsManagerConfig::from_env()?)?;
//! let health = client.health().await?;
//! println!("healthy: {}", health.healthy);
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes and the conformance
//! runner)
//! .
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

mod client;
mod config;

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub mod secrets;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::DEFAULT_URL;

pub use crate::client::AwsSecretsManagerClient;

pub use crate::config::AwsSecretsManagerConfig;

pub use crate::config::AwsSecretsManagerConfigBuilder;

/// Service-prefixed alias of [`Error`].
pub type AwsSecretsManagerError = Error;
