// Service-owned (created from the sdk-kit 0.1.0 skeleton).
//! `AwsSecretsManagerClient`: entry point of the SDK (SPEC §2.4), built on the official AWS SDK
//! for Rust (`aws-sdk-secretsmanager`, SPEC §2.3 "Cloud SDK services").

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_sdk_secretsmanager::error::{ProvideErrorMetadata, SdkError};
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_types::retry::RetryConfig;
use aws_smithy_types::timeout::TimeoutConfig;
use futures::future::BoxFuture;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

use crate::aws_error::{map_sdk_error, MapOptions};
use crate::cache::{AwsSecretCache, AwsSecretCacheOptions};
use crate::config::AwsSecretsManagerConfig;
use crate::core::lifecycle::CloseGroup;
use crate::core::{Error, ErrorCode, HealthStatus, Result};
use crate::provider::{AwsSecretsManagerSecretsOptions, AwsSecretsManagerSecretsProvider};
use crate::sdk::{build_sdk_client, GrowHttpClient};

/// Upper bound of the health probe timeout.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Async client for AWS Secrets Manager. Cheap to clone (clones share one SDK client).
///
/// The AWS SDK client is built from the configuration on the first call (loading the region,
/// profile and credential chain is asynchronous), or wraps the client given with
/// [`AwsSecretsManagerClient::with_sdk_client`]. Calls are cancelled by dropping their future;
/// [`close`](AwsSecretsManagerClient::close) cancels in-flight calls and rejects new ones with
/// `CANCELLED`.
#[derive(Clone)]
pub struct AwsSecretsManagerClient {
    inner: Arc<Inner>,
}

struct Inner {
    config: AwsSecretsManagerConfig,
    http: Option<GrowHttpClient>,
    sdk: OnceCell<aws_sdk_secretsmanager::Client>,
    known_secrets: Vec<String>,
    closed: AtomicBool,
    close_token: CancellationToken,
    on_close: CloseGroup,
}

impl fmt::Debug for AwsSecretsManagerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSecretsManagerClient")
            .field("config", &self.inner.config)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl AwsSecretsManagerClient {
    /// Creates a client from a configuration (validates it and builds the HTTP client; the AWS
    /// configuration itself is loaded on the first call).
    pub fn new(config: AwsSecretsManagerConfig) -> Result<Self> {
        config.validate()?;
        let sdk = OnceCell::new();
        let http = match config.sdk_client() {
            Some(client) => {
                let _ = sdk.set(client.clone());
                None
            }
            None => Some(GrowHttpClient::new(config.common())?),
        };
        let known_secrets = config.known_secrets();
        Ok(AwsSecretsManagerClient {
            inner: Arc::new(Inner {
                config,
                http,
                sdk,
                known_secrets,
                closed: AtomicBool::new(false),
                close_token: CancellationToken::new(),
                on_close: CloseGroup::new(),
            }),
        })
    }

    /// Creates a client from the process environment (`GROW_AWS_SECRETS_MANAGER_*` and the
    /// standard AWS variables).
    pub fn from_env() -> Result<Self> {
        Self::new(AwsSecretsManagerConfig::from_env()?)
    }

    /// Wraps an existing AWS SDK client; `close()` leaves it usable. Grow hooks, TLS, proxy,
    /// headers and User-Agent settings do not apply to it.
    pub fn with_sdk_client(sdk_client: aws_sdk_secretsmanager::Client) -> Result<Self> {
        Self::new(
            AwsSecretsManagerConfig::builder()
                .sdk_client(sdk_client)
                .build()?,
        )
    }

    /// The configuration in use.
    pub fn config(&self) -> &AwsSecretsManagerConfig {
        &self.inner.config
    }

    /// The underlying AWS SDK client (escape hatch for operations not wrapped here). Builds it
    /// on first use; `CONFIG` when no region can be found.
    pub async fn sdk(&self) -> Result<aws_sdk_secretsmanager::Client> {
        self.sdk_for("sdk").await.cloned()
    }

    /// Registers work that [`AwsSecretsManagerClient::close`] runs (stop watchers, …).
    pub fn on_close<F>(&self, f: F)
    where
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static,
    {
        self.inner.on_close.register(f);
    }

    /// Liveness: a signed `ListSecrets {MaxResults: 1}` with a short timeout (min(request
    /// timeout, 5 s)) and no retries. `ok` when AWS answers (also when the credentials are
    /// rejected: `details.auth = "failed"`), `degraded` when throttled, `unhealthy` on HTTP 5xx,
    /// `unreachable` on network errors. Fails only with `CANCELLED` and `CONFIG`.
    pub async fn health(&self) -> Result<HealthStatus> {
        let timeout = self.config().common().request_timeout().min(HEALTH_TIMEOUT);
        let result = async {
            let sdk = self.sdk_for("health").await?;
            let overrides = aws_sdk_secretsmanager::config::Builder::default()
                .retry_config(RetryConfig::disabled())
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_attempt_timeout(timeout)
                        .operation_timeout(timeout)
                        .build(),
                );
            let call = sdk
                .list_secrets()
                .max_results(1)
                .customize()
                .config_override(overrides)
                .send();
            self.run("health", call).await
        }
        .await;
        let err = match result {
            Ok(_) => return Ok(HealthStatus::healthy("ok")),
            Err(err) => err,
        };
        let code = err.code();
        Ok(match code {
            ErrorCode::Cancelled | ErrorCode::Config => return Err(err),
            ErrorCode::RateLimited => {
                HealthStatus::healthy("degraded").with_detail("code", code.as_str())
            }
            ErrorCode::Authentication | ErrorCode::PermissionDenied => HealthStatus::healthy("ok")
                .with_detail("auth", "failed")
                .with_detail("code", code.as_str()),
            _ => match err.http_status() {
                None => HealthStatus::unhealthy("unreachable").with_detail("error", code.as_str()),
                Some(status) if status >= 500 => HealthStatus::unhealthy("unhealthy")
                    .with_detail("httpStatus", status.to_string())
                    .with_detail("error", code.as_str()),
                Some(status) => HealthStatus::healthy("ok")
                    .with_detail("httpStatus", status.to_string())
                    .with_detail("code", code.as_str()),
            },
        })
    }

    /// Authenticated round trip (`ListSecrets {MaxResults: 1}`); returns the latency.
    /// `AUTHENTICATION` for unknown keys or bad signatures, `PERMISSION_DENIED` when the
    /// principal may not call `secretsmanager:ListSecrets`.
    pub async fn ping(&self) -> Result<Duration> {
        let started = Instant::now();
        let sdk = self.sdk_for("ping").await?;
        self.run("ping", sdk.list_secrets().max_results(1).send())
            .await?;
        Ok(started.elapsed())
    }

    /// Always `UNSUPPORTED`: AWS Secrets Manager exposes no server version (the API contract
    /// date is the constant [`API_VERSION`](crate::API_VERSION)).
    pub async fn server_version(&self) -> Result<String> {
        self.check_open("serverVersion")?;
        Err(Error::unsupported(
            "serverVersion: AWS Secrets Manager does not expose a server version",
        ))
    }

    /// Stops the watchers of the providers created by [`secrets`](Self::secrets), cancels
    /// in-flight calls and rejects new ones with `CANCELLED`. A caller-supplied SDK client stays
    /// usable. Idempotent.
    pub async fn close(&self) {
        self.shutdown();
        self.inner.on_close.close().await;
    }

    /// Whether [`AwsSecretsManagerClient::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// The [`SecretsProvider`](crate::secrets::SecretsProvider) view (SPEC §3) of this client,
    /// with the configured recovery window.
    pub fn secrets(&self) -> AwsSecretsManagerSecretsProvider {
        AwsSecretsManagerSecretsProvider::new(self.clone(), self.config().recovery_window_days())
    }

    /// The provider with options; `VALIDATION` when the recovery window is not 7–30 days.
    pub fn secrets_with_options(
        &self,
        opts: AwsSecretsManagerSecretsOptions,
    ) -> Result<AwsSecretsManagerSecretsProvider> {
        let days = opts
            .recovery_window_days
            .unwrap_or_else(|| self.config().recovery_window_days());
        if !(7..=30).contains(&days) {
            return Err(Error::validation(
                "secrets: recoveryWindowDays must be an integer from 7 to 30",
            ));
        }
        Ok(AwsSecretsManagerSecretsProvider::new(self.clone(), days))
    }

    /// A version-stage aware cache with the AWS caching-client semantics (TTL 1 h,
    /// 1 024 entries by default); `VALIDATION` for invalid options.
    pub fn secret_cache(&self, opts: AwsSecretCacheOptions) -> Result<AwsSecretCache> {
        AwsSecretCache::new(Arc::new(self.clone()), opts)
    }

    // ------------------------------------------------------------------------------------
    // internals

    /// Marks the client closed and cancels in-flight calls (sync part of `close`).
    pub(crate) fn shutdown(&self) {
        if !self.inner.closed.swap(true, Ordering::SeqCst) {
            self.inner.close_token.cancel();
        }
    }

    pub(crate) fn check_open(&self, operation: &str) -> Result<()> {
        if self.is_closed() {
            return Err(Error::cancelled(format!("{operation}: client is closed")));
        }
        Ok(())
    }

    /// The SDK client, built on first use.
    pub(crate) async fn sdk_for(&self, operation: &str) -> Result<&aws_sdk_secretsmanager::Client> {
        self.check_open(operation)?;
        let inner = &self.inner;
        inner
            .sdk
            .get_or_try_init(|| async {
                // `http` is always set when no SDK client was supplied.
                let http = inner
                    .http
                    .clone()
                    .ok_or_else(|| Error::config("no HTTP client"))?;
                build_sdk_client(&inner.config, http).await
            })
            .await
            .map_err(|e| {
                let message = format!("{operation}: {}", e.message());
                e.with_message(message)
            })
    }

    /// Runs an SDK call: cancellation on close and error mapping.
    pub(crate) async fn run<T, E, F>(&self, operation: &str, call: F) -> Result<T>
    where
        F: Future<Output = std::result::Result<T, SdkError<E, HttpResponse>>>,
        E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
    {
        tokio::select! {
            biased;
            _ = self.inner.close_token.cancelled() => {
                Err(Error::cancelled(format!("{operation}: client is closed")))
            }
            result = call => result.map_err(|e| {
                map_sdk_error(operation, e, &MapOptions::for_op(&self.inner.known_secrets, operation))
            }),
        }
    }
}
