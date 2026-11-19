//! Builds the AWS SDK client from the Grow configuration (SPEC §2.3 "Cloud SDK services").
//!
//! - HTTP: the crate's own [`HttpClient`] on `reqwest` + rustls (TLS CA bundle, client
//!   certificate, `insecure_skip_verify`, explicit proxy only, connect timeout). It also adds the
//!   Grow User-Agent and the extra headers after signing.
//! - Retries: SDK standard retry mode with `max_attempts = max_retries + 1` and the Grow backoff
//!   bounds; timeouts: `request_timeout` → attempt timeout, `total_timeout` → operation timeout.
//! - Hooks and `tracing` debug events: an SDK interceptor ([`GrowInterceptor`]) per attempt.
//! - Credentials: static keys, an explicit provider, a profile or the default chain, optionally
//!   wrapped in the STS assume-role provider.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use aws_config::BehaviorVersion;
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_sdk_secretsmanager::config::Region;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::http::{
    HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpClient,
    SharedHttpConnector,
};
use aws_smithy_runtime_api::client::interceptors::context::{
    BeforeTransmitInterceptorContextRef, FinalizerInterceptorContextRef,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::orchestrator::{HttpRequest, HttpResponse, Metadata};
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_runtime_api::client::retries::RequestAttempts;
use aws_smithy_runtime_api::client::runtime_components::{
    RuntimeComponents, RuntimeComponentsBuilder,
};
use aws_smithy_runtime_api::http::StatusCode;
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::config_bag::{ConfigBag, Storable, StoreReplace};
use aws_smithy_types::retry::RetryConfig;
use aws_smithy_types::timeout::TimeoutConfig;
use reqwest::header::{HeaderName, HeaderValue};

use crate::aws_error::{map_response, request_id_of, MapOptions, ResponseParts};
use crate::config::AwsSecretsManagerConfig;
use crate::core::hooks::{guarded, ErrorInfo, RequestInfo, ResponseInfo};
use crate::core::redact::{redact_headers, redact_text, redact_url};
use crate::core::transport::{reqwest_client_builder, user_agent_for};
use crate::core::{CommonConfig, Error, Hooks, Result};

const LOG_TARGET: &str = "grow_aws_secrets_manager::aws";

/// The `reqwest` client with the TLS/proxy/timeout settings of `config` (the shared
/// [`reqwest_client_builder`]) and redirects disabled.
pub(crate) fn build_reqwest(config: &CommonConfig) -> Result<reqwest::Client> {
    reqwest_client_builder(config)?
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::config("cannot build the HTTP client").with_source(e.without_url()))
}

/// The AWS SDK HTTP client: `reqwest` with the Grow TLS/proxy settings, User-Agent and headers.
#[derive(Clone)]
pub(crate) struct GrowHttpClient {
    client: reqwest::Client,
    user_agent: Arc<str>,
    headers: Arc<Vec<(HeaderName, HeaderValue)>>,
}

impl fmt::Debug for GrowHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrowHttpClient")
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

impl GrowHttpClient {
    pub(crate) fn new(config: &CommonConfig) -> Result<Self> {
        let mut headers = Vec::new();
        for (name, value) in config.headers() {
            let n = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Error::config(format!("header name {name:?} is not valid")))?;
            let v = HeaderValue::from_str(value)
                .map_err(|_| Error::config(format!("value of header {name:?} is not valid")))?;
            headers.push((n, v));
        }
        Ok(GrowHttpClient {
            client: build_reqwest(config)?,
            user_agent: user_agent_for(config).into(),
            headers: Arc::new(headers),
        })
    }

    async fn send(self, request: HttpRequest) -> std::result::Result<HttpResponse, ConnectorError> {
        let method = reqwest::Method::from_bytes(request.method().as_bytes())
            .map_err(|e| ConnectorError::other(Box::new(e), None))?;
        let mut builder = self.client.request(method, request.uri());
        let mut ua_seen = false;
        for (name, value) in request.headers() {
            if name.eq_ignore_ascii_case("user-agent") {
                ua_seen = true;
                builder = builder.header(name, format!("{value} {}", self.user_agent));
            } else {
                builder = builder.header(name, value);
            }
        }
        if !ua_seen {
            builder = builder.header("user-agent", &*self.user_agent);
        }
        for (name, value) in self.headers.iter() {
            builder = builder.header(name.clone(), value.clone());
        }
        let body = request.body().bytes().ok_or_else(|| {
            ConnectorError::other("streaming request bodies are not supported".into(), None)
        })?;
        let response = builder
            .body(body.to_vec())
            .send()
            .await
            .map_err(connector_error)?;
        let status = StatusCode::try_from(response.status().as_u16())
            .map_err(|e| ConnectorError::other(Box::new(e), None))?;
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_owned(), v.to_owned()))
            })
            .collect();
        let bytes = response.bytes().await.map_err(connector_error)?;
        let mut out = HttpResponse::new(status, SdkBody::from(bytes));
        for (k, v) in headers {
            out.headers_mut().append(k, v);
        }
        Ok(out)
    }
}

fn connector_error(err: reqwest::Error) -> ConnectorError {
    let timeout = err.is_timeout();
    let connect = err.is_connect();
    let source: BoxError = Box::new(err.without_url());
    if timeout {
        ConnectorError::timeout(source)
    } else if connect {
        ConnectorError::io(source).never_connected()
    } else {
        ConnectorError::io(source)
    }
}

impl HttpConnector for GrowHttpClient {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        HttpConnectorFuture::new(self.clone().send(request))
    }
}

impl HttpClient for GrowHttpClient {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }

    fn validate_base_client_config(
        &self,
        _runtime_components: &RuntimeComponentsBuilder,
        _cfg: &ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        Ok(())
    }
}

/// Request data of the current attempt (the request itself is moved into the connector).
#[derive(Debug, Clone)]
struct AttemptStart {
    started: Instant,
    method: String,
    url: String,
}

impl Storable for AttemptStart {
    type Storer = StoreReplace<Self>;
}

/// SDK interceptor that fires the Grow hooks and `tracing` debug events for every attempt.
pub(crate) struct GrowInterceptor {
    hooks: Option<Arc<dyn Hooks>>,
    known_secrets: Vec<String>,
    max_attempts: u32,
}

impl fmt::Debug for GrowInterceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrowInterceptor")
            .field("hooks", &self.hooks.is_some())
            .finish_non_exhaustive()
    }
}

impl GrowInterceptor {
    pub(crate) fn new(config: &AwsSecretsManagerConfig) -> Self {
        GrowInterceptor {
            hooks: config.common().hooks().cloned(),
            known_secrets: config.known_secrets(),
            max_attempts: config.common().retry().max_retries + 1,
        }
    }

    fn redacted_url(&self, uri: &str) -> String {
        redact_text(&redact_url(uri), &self.known_secrets)
    }
}

fn attempt_of(cfg: &ConfigBag) -> u32 {
    cfg.load::<RequestAttempts>()
        .map(RequestAttempts::attempts)
        .unwrap_or(1)
        .max(1)
}

fn operation_of(cfg: &ConfigBag) -> String {
    cfg.load::<Metadata>()
        .map(|m| m.name().to_owned())
        .unwrap_or_else(|| "request".to_owned())
}

impl Intercept for GrowInterceptor {
    fn name(&self) -> &'static str {
        "GrowInterceptor"
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let request = context.request();
        let attempt = attempt_of(cfg);
        let url = self.redacted_url(request.uri());
        cfg.interceptor_state().store_put(AttemptStart {
            started: Instant::now(),
            method: request.method().to_owned(),
            url: url.clone(),
        });
        ::tracing::debug!(
            target: LOG_TARGET,
            operation = %operation_of(cfg),
            attempt,
            "request"
        );
        if let Some(hooks) = &self.hooks {
            let info = RequestInfo {
                method: request.method().to_owned(),
                url,
                headers: redact_headers(request.headers().iter()),
                attempt,
            };
            guarded(|| hooks.on_request(&info));
        }
        Ok(())
    }

    fn read_after_attempt(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let Some(start) = cfg.load::<AttemptStart>().cloned() else {
            return Ok(());
        };
        let attempt = attempt_of(cfg);
        let operation = operation_of(cfg);
        let duration = start.started.elapsed();
        let max_attempts = cfg
            .load::<RetryConfig>()
            .map(RetryConfig::max_attempts)
            .unwrap_or(self.max_attempts);
        let AttemptStart { method, url, .. } = start;
        let opts = MapOptions::for_op(&self.known_secrets, &operation);
        let failure = match context.response() {
            Some(response) => {
                let status = response.status().as_u16();
                let request_id = request_id_of(response);
                ::tracing::debug!(
                    target: LOG_TARGET,
                    operation = %operation,
                    attempt,
                    status,
                    request_id = request_id.as_deref().unwrap_or(""),
                    "response"
                );
                if let Some(hooks) = &self.hooks {
                    let info = ResponseInfo {
                        method: method.clone(),
                        url: url.clone(),
                        status,
                        duration,
                        attempt,
                        request_id,
                    };
                    guarded(|| hooks.on_response(&info));
                }
                (status >= 400).then(|| {
                    map_response(&operation, ResponseParts::from_response(response), &opts)
                })
            }
            None => match context.output_or_error() {
                Some(Err(err)) => {
                    let text = redact_text(&err.to_string(), &self.known_secrets);
                    ::tracing::debug!(target: LOG_TARGET, operation = %operation, attempt, "request failed");
                    Some(Error::unavailable(format!(
                        "{operation}: request failed: {text}"
                    )))
                }
                _ => None,
            },
        };
        if let (Some(error), Some(hooks)) = (failure, &self.hooks) {
            let will_retry = attempt < max_attempts && error.is_retryable();
            let info = ErrorInfo {
                method,
                url,
                error,
                attempt,
                will_retry,
                retry_delay: None,
            };
            guarded(|| hooks.on_error(&info));
        }
        Ok(())
    }
}

/// Retry settings of the SDK client.
pub(crate) fn retry_config(config: &CommonConfig) -> RetryConfig {
    let policy = config.retry();
    RetryConfig::standard()
        .with_max_attempts(policy.max_retries + 1)
        .with_initial_backoff(policy.initial_backoff)
        .with_max_backoff(policy.max_backoff)
}

/// Timeout settings of the SDK client.
pub(crate) fn timeout_config(config: &CommonConfig) -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(config.connect_timeout())
        .operation_attempt_timeout(config.request_timeout())
        .operation_timeout(config.total_timeout())
        .build()
}

/// Loads the AWS configuration (region, credential chain, optional assume-role) and builds the
/// SDK client. Runs on the first call of the client.
pub(crate) async fn build_sdk_client(
    config: &AwsSecretsManagerConfig,
    http: GrowHttpClient,
) -> Result<aws_sdk_secretsmanager::Client> {
    let common = config.common();
    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .http_client(SharedHttpClient::new(http))
        .retry_config(retry_config(common))
        .timeout_config(timeout_config(common));
    if let Some(region) = config.region() {
        loader = loader.region(Region::new(region.to_owned()));
    }
    if let Some(profile) = config.profile() {
        loader = loader.profile_name(profile);
    }
    if let (Some(id), Some(secret)) = (config.access_key_id(), config.secret_access_key()) {
        loader = loader.credentials_provider(Credentials::new(
            id,
            secret.expose_secret(),
            config.session_token().map(|t| t.expose_secret().to_owned()),
            None,
            "grow-config",
        ));
    } else if let Some(provider) = config.credentials() {
        loader = loader.credentials_provider(provider.clone());
    }
    let sdk_config = loader.load().await;
    if sdk_config.region().is_none() {
        return Err(Error::config(
            "region is not set (GROW_AWS_SECRETS_MANAGER_REGION, AWS_REGION or the profile)",
        ));
    }
    let mut builder = aws_sdk_secretsmanager::config::Builder::from(&sdk_config);
    if let Some(role) = config.role_arn() {
        let mut assume = aws_config::sts::AssumeRoleProvider::builder(role)
            .session_name(config.role_session_name());
        if let Some(id) = config.external_id() {
            assume = assume.external_id(id.expose_secret());
        }
        if let Some(d) = config.role_duration() {
            assume = assume.session_length(d);
        }
        let provider = assume.configure(&sdk_config).build().await;
        builder = builder.credentials_provider(SharedCredentialsProvider::new(provider));
    }
    if let Some(endpoint) = config.endpoint() {
        builder = builder.endpoint_url(endpoint.as_str().trim_end_matches('/'));
    }
    builder = builder.interceptor(GrowInterceptor::new(config));
    Ok(aws_sdk_secretsmanager::Client::from_conf(builder.build()))
}
