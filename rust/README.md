# grow-aws-secrets-manager (Rust)

Rust SDK for AWS Secrets Manager by [Grow Codes](https://grow.codes), built on the official AWS SDK
for Rust (`aws-sdk-secretsmanager`). Async on tokio, with an optional blocking client.

```toml
[dependencies]
grow-aws-secrets-manager = "0.1.0"
# blocking client:   features = ["blocking"]
# test fakes/runner: features = ["testing"] (dev-dependency)
```

```rust,no_run
use grow_aws_secrets_manager::models::GetSecretValueOptions;
use grow_aws_secrets_manager::secrets::SecretsProvider;
use grow_aws_secrets_manager::{AwsSecretsManagerClient, AwsSecretsManagerConfig};

#[tokio::main]
async fn main() -> grow_aws_secrets_manager::Result<()> {
    // explicit > GROW_AWS_SECRETS_MANAGER_* > AWS_* > defaults; credentials default to the AWS chain
    let client = AwsSecretsManagerClient::new(AwsSecretsManagerConfig::from_env()?)?;
    let secret = client.get_secret_value("prod/db", GetSecretValueOptions::default()).await?;
    println!("{:?}", secret.version_id); // secret.value prints as SecretValue([REDACTED])
    let password = client.get_json_field("prod/db", "password", Default::default()).await?;
    let api_key = client.secrets().get_string("prod/api-key", None).await?;
    # let _ = (password, api_key);
    client.close().await;
    Ok(())
}
```

- Every Secrets Manager operation (`get_secret_value`, `batch_get_secret_value`, `list_secrets`
  paginator, `create_secret`, `put_secret_value`, rotation, tags, resource policies,
  `get_random_password`, `get_json_field`), the SPEC `SecretsProvider` (`client.secrets()`) and an
  AWS caching-client compatible `AwsSecretCache` (`client.secret_cache(opts)`).
- Errors: one `Error` enum with `code()`, `http_status()`, `request_id()`, `is_retryable()`,
  `retry_after()`, mapped by AWS error code; `aws_error_code(&err)` gives the AWS code.
  Messages never contain credentials.
- SDK standard retries (`max_attempts = max_retries + 1`), attempt/total timeouts, TLS CA bundle,
  client certificates and explicit proxy on the crate's own `reqwest` connector, request hooks
  from an SDK interceptor, `tracing` debug events. Cancel a call by dropping its future;
  `close()` cancels in-flight calls.
- Wrap an existing SDK client with `AwsSecretsManagerClient::with_sdk_client(client)`; assume a
  role with `.role_arn(..)` (STS assume-role provider).
- MSRV 1.88. Licence Apache-2.0. Not affiliated with AWS. Documentation:
  https://grow-codes-packages.github.io/aws-secrets-manager/

Development: `make deps build lint test coverage license pack docs` (see `Makefile`).
