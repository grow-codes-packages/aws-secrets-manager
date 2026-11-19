// Created by sdk-kit 0.1.0; owned by this repository.
//! The AWS Secrets Manager Rust SDK: configuration from the standard AWS environment, health and
//! ping, a secret round trip, JSON fields, the `SecretsProvider` and the version-stage aware
//! cache.
//!
//! Against the Docker emulator (Moto) or real AWS:
//!
//! ```sh
//! AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
//! GROW_AWS_SECRETS_MANAGER_URL=http://localhost:5000 cargo run
//! ```

use std::sync::Arc;

use grow_aws_secrets_manager as sdk;
use sdk::core::{ErrorInfo, Hooks};
use sdk::models::{CreateSecretOptions, DeleteSecretOptions, GetSecretValueOptions};
use sdk::secrets::{SecretData, SecretsProvider};
use sdk::{AwsSecretCacheOptions, ErrorCode};

use sdk::AwsSecretsManagerClient as Client;
use sdk::AwsSecretsManagerConfig as Config;

/// Prints every retry.
struct RetryLogger;

impl Hooks for RetryLogger {
    fn on_error(&self, info: &ErrorInfo) {
        if info.will_retry {
            eprintln!("retrying {} (attempt {})", info.url, info.attempt);
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error [{}]: {err}", err.code());
        std::process::exit(1);
    }
}

async fn run() -> sdk::Result<()> {
    // explicit > GROW_AWS_SECRETS_MANAGER_* > AWS_* > defaults; invalid values name the variable,
    // never its value. Unset credentials use the standard AWS chain.
    let config = Config::builder()
        .hooks(Arc::new(RetryLogger))
        .build_from_env()?;
    println!("config: {config:?}"); // credentials print as [REDACTED]

    let client = Client::new(config)?;
    let health = client.health().await?; // never fails for an unreachable service
    println!("health: {} ({})", health.healthy, health.status);
    match client.ping().await {
        Ok(latency) => println!("ping: {} ms", latency.as_millis()),
        Err(e) if e.code() == ErrorCode::Authentication => {
            println!("ping: check the AWS credentials ({e})");
            return Err(e);
        }
        Err(e) => return Err(e),
    }

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = format!("grow-example/{stamp}/db");
    let created = client
        .create_secret(
            &name,
            Some(SecretData::Json(
                serde_json::json!({"username": "app", "password": "s3cr3t"}),
            )),
            CreateSecretOptions {
                description: Some("example".into()),
                tags: [("owner".to_owned(), "example".to_owned())].into(),
                ..Default::default()
            },
        )
        .await?;
    println!("created version: {:?}", created.version_id);

    let user = client
        .get_json_field(&name, "username", GetSecretValueOptions::default())
        .await?;
    println!("username: {user:?}");
    let value = client.get_secret_value(&name, Default::default()).await?;
    println!("value: {}", value.value); // prints SecretValue([REDACTED])

    // SecretsProvider view (SPEC §3)
    let provider = client.secrets();
    let version = provider
        .set(&name, "rotated-by-provider".into(), None)
        .await?;
    println!("provider set version: {version}");
    println!("exists: {}", provider.exists(&name, None).await?);

    // AWS caching-client semantics: TTL 1 h, refresh checks the stage with DescribeSecret
    let cache = client.secret_cache(AwsSecretCacheOptions::default())?;
    println!(
        "cached length: {}",
        cache.get_secret_string(&name, None).await?.len()
    );

    client
        .delete_secret(
            &name,
            DeleteSecretOptions {
                force_delete_without_recovery: Some(true),
                ..Default::default()
            },
        )
        .await?;
    client.close().await;
    Ok(())
}
