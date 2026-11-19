// Taken over from sdk-kit 0.1.0 (header removed): the skeleton tests targeted the demo service;
// these test the AWS Secrets Manager client surface against recorded Moto responses.
//! Client surface: health, ping, serverVersion, close, hooks, User-Agent, retries, timeouts,
//! TLS/proxy settings, credentials and error mapping.

mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::{future, ProvideCredentials};
use grow_aws_secrets_manager as sdk;
use sdk::core::{ErrorCode, ErrorInfo, Hooks, RequestInfo};
use sdk::{AwsSecretsManagerClient as Client, AwsSecretsManagerConfig as Config};
use serde_json::json;
use support::*;
use wiremock::matchers::header;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ca_path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[tokio::test]
async fn client_surface_health_ping_version_close() {
    let server = MockServer::start().await;
    mount(&server, "ping.ok").await;
    let c = client(&server);
    let h = c.health().await.unwrap();
    assert!(h.healthy);
    assert_eq!(h.status, "ok");
    assert!(c.ping().await.unwrap() < Duration::from_secs(5));
    assert_eq!(request_body(&server, 0).await, json!({"MaxResults": 1}));
    let err = c.server_version().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert_eq!(sdk::API_VERSION, "2017-10-17");
    let text = format!("{c:?}");
    assert!(text.contains("[REDACTED]"));
    assert!(!text.contains(SECRET_KEY));
    assert!(c.sdk().await.is_ok());
    assert_eq!(c.config().region(), Some("us-east-1"));
}

#[tokio::test]
async fn core_close_idempotent() {
    let server = MockServer::start().await;
    mount(&server, "ping.ok").await;
    let c = client(&server);
    let closed = Arc::new(AtomicU32::new(0));
    let counter = closed.clone();
    c.on_close(move || {
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
        })
    });
    assert!(!c.is_closed());
    c.close().await;
    c.close().await;
    assert!(c.is_closed());
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
    assert_eq!(
        c.server_version().await.unwrap_err().code(),
        ErrorCode::Cancelled
    );
    assert_eq!(c.health().await.unwrap_err().code(), ErrorCode::Cancelled);
    assert_eq!(
        c.get_secret_value("x", Default::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Cancelled
    );
}

#[tokio::test]
async fn core_cancel_in_flight_on_close() {
    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecrets",
        aws_json(200, json!({"SecretList": []})).set_delay(Duration::from_secs(5)),
    )
    .await;
    let c = client(&server);
    let c2 = c.clone();
    let task = tokio::spawn(async move { c2.ping().await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    c.close().await;
    let err = task.await.unwrap().unwrap_err();
    assert_eq!(err.code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn health_variants() {
    // credentials rejected: the service answered
    let server = MockServer::start().await;
    mount(&server, "ping.auth-unknown-key").await;
    let h = client(&server).health().await.unwrap();
    assert_eq!((h.healthy, h.status.as_str()), (true, "ok"));
    assert_eq!(h.details["auth"], "failed");
    assert_eq!(h.details["code"], "AUTHENTICATION");

    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecrets",
        aws_error(400, "ThrottlingException", "slow down"),
    )
    .await;
    let h = client(&server).health().await.unwrap();
    assert_eq!((h.healthy, h.status.as_str()), (true, "degraded"));

    let server = MockServer::start().await;
    mount_op(&server, "ListSecrets", ResponseTemplate::new(503)).await;
    let h = client(&server).health().await.unwrap();
    assert_eq!((h.healthy, h.status.as_str()), (false, "unhealthy"));
    assert_eq!(h.details["httpStatus"], "503");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "no retries"
    );

    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecrets",
        aws_error(400, "ValidationException", "x"),
    )
    .await;
    let h = client(&server).health().await.unwrap();
    assert_eq!((h.healthy, h.status.as_str()), (true, "ok"));
    assert_eq!(h.details["httpStatus"], "400");

    // slow service: health uses min(request timeout, 5 s)
    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecrets",
        aws_json(200, json!({})).set_delay(Duration::from_secs(3)),
    )
    .await;
    let c = Client::new(
        builder(&server.uri())
            .request_timeout(Duration::from_millis(200))
            .build()
            .unwrap(),
    )
    .unwrap();
    let h = c.health().await.unwrap();
    assert_eq!((h.healthy, h.status.as_str()), (false, "unreachable"));
}

#[tokio::test]
async fn core_health_unreachable() {
    let c = Client::new(builder(&closed_port()).build().unwrap()).unwrap();
    let h = c.health().await.unwrap();
    assert!(!h.healthy);
    assert_eq!(h.status, "unreachable");
    assert!(h.details.contains_key("error"));
    let err = c.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.is_retryable());
    assert!(err.http_status().is_none());
}

#[tokio::test]
async fn ping_authentication_and_permission_errors() {
    for (name, code) in [
        ("ping.auth-unknown-key", ErrorCode::Authentication),
        ("ping.auth-bad-signature", ErrorCode::Authentication),
    ] {
        let server = MockServer::start().await;
        mount(&server, name).await;
        let err = client(&server).ping().await.unwrap_err();
        assert_eq!(err.code(), code, "{name}");
        assert_eq!(err.http_status(), Some(403));
        assert!(!err.message().contains(SECRET_KEY));
        assert!(err.message().starts_with("ping: "), "{}", err.message());
    }
    // AWS shapes
    let cases = [
        ("AccessDeniedException", ErrorCode::PermissionDenied),
        ("UnrecognizedClientException", ErrorCode::Authentication),
        ("ExpiredTokenException", ErrorCode::Authentication),
        ("InternalServiceError", ErrorCode::Unavailable),
        ("InvalidNextTokenException", ErrorCode::Validation),
        ("RequestTimeoutException", ErrorCode::Timeout),
        ("SomethingNew", ErrorCode::Validation),
    ];
    for (aws, code) in cases {
        let server = MockServer::start().await;
        mount_op(&server, "ListSecrets", aws_error(400, aws, "message")).await;
        let err = client(&server).ping().await.unwrap_err();
        assert_eq!(err.code(), code, "{aws}");
        assert_eq!(err.request_id(), Some("req-123"));
    }
}

#[tokio::test]
async fn core_errors_mapping_by_status_without_code() {
    for (status, code) in [
        (401, ErrorCode::Authentication),
        (404, ErrorCode::NotFound),
        (409, ErrorCode::Conflict),
        (413, ErrorCode::Validation),
        (429, ErrorCode::RateLimited),
        (501, ErrorCode::Unsupported),
        (502, ErrorCode::Unavailable),
        (504, ErrorCode::Timeout),
    ] {
        let server = MockServer::start().await;
        mount_op(&server, "ListSecrets", ResponseTemplate::new(status)).await;
        let err = client(&server).ping().await.unwrap_err();
        assert_eq!(err.code(), code, "HTTP {status}");
        assert_eq!(err.http_status(), Some(status));
    }
}

#[tokio::test]
async fn core_retry_503_backoff_and_exhausted() {
    let server = MockServer::start().await;
    Mock::given(header("x-amz-target", "secretsmanager.ListSecrets"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    mount(&server, "ping.ok").await;
    let rec = Recorder::new();
    let c = Client::new(
        builder(&server.uri())
            .retry(fast_retry(3))
            .hooks(rec.clone())
            .build()
            .unwrap(),
    )
    .unwrap();
    c.ping().await.unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
    let attempts: Vec<u32> = rec
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.attempt)
        .collect();
    assert_eq!(attempts, [1, 2, 3]);
    let errors = rec.errors.lock().unwrap().clone();
    assert_eq!(errors.len(), 2);
    assert!(errors.iter().all(|e| e.will_retry));
    assert_eq!(errors[0].error.code(), ErrorCode::Unavailable);

    let server = MockServer::start().await;
    mount_op(&server, "ListSecrets", ResponseTemplate::new(503)).await;
    let c = Client::new(builder(&server.uri()).retry(fast_retry(3)).build().unwrap()).unwrap();
    let err = c.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.is_retryable());
    assert_eq!(err.http_status(), Some(503));
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn core_retry_throttling_and_retry_after() {
    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecrets",
        aws_error(400, "ThrottlingException", "Rate exceeded").insert_header("retry-after", "7"),
    )
    .await;
    let err = client(&server).ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::RateLimited);
    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(Duration::from_secs(7)));
    assert_eq!(
        err.message(),
        "ping: ThrottlingException: Rate exceeded (HTTP 400)"
    );
}

#[tokio::test]
async fn core_timeout_request_and_total() {
    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecrets",
        aws_json(200, json!({})).set_delay(Duration::from_secs(3)),
    )
    .await;
    let c = Client::new(
        builder(&server.uri())
            .request_timeout(Duration::from_millis(150))
            .build()
            .unwrap(),
    )
    .unwrap();
    let err = c.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Timeout);
    assert!(err.is_retryable());

    let c = Client::new(
        builder(&server.uri())
            .total_timeout(Duration::from_millis(200))
            .retry(fast_retry(3))
            .build()
            .unwrap(),
    )
    .unwrap();
    let started = std::time::Instant::now();
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
}

struct PanickingHooks;
impl Hooks for PanickingHooks {
    fn on_request(&self, _info: &RequestInfo) {
        panic!("hook panic");
    }
    fn on_error(&self, _info: &ErrorInfo) {
        panic!("hook panic");
    }
}

#[tokio::test]
async fn core_hooks_and_useragent() {
    let server = MockServer::start().await;
    mount_op(
        &server,
        "GetSecretValue",
        aws_error(400, "ResourceNotFoundException", "nope"),
    )
    .await;
    mount(&server, "ping.ok").await;
    let rec = Recorder::new();
    let c = Client::new(
        builder(&server.uri())
            .session_token("session-token-value-1")
            .hooks(rec.clone())
            .header("x-extra", "yes")
            .user_agent_suffix("myapp/2")
            .build()
            .unwrap(),
    )
    .unwrap();
    c.ping().await.unwrap();
    let req = &server.received_requests().await.unwrap()[0];
    let ua = req.headers.get("user-agent").unwrap().to_str().unwrap();
    assert!(
        ua.contains("grow-codes-aws-secrets-manager/0.1.0 (rust) myapp/2"),
        "{ua}"
    );
    assert_eq!(req.headers.get("x-extra").unwrap(), "yes");
    assert!(req
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("AWS4-HMAC-SHA256"));

    let requests = rec.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].attempt, 1);
    assert_eq!(requests[0].headers["authorization"], "[REDACTED]");
    assert_eq!(requests[0].headers["x-amz-security-token"], "[REDACTED]");
    let responses = rec.responses.lock().unwrap().clone();
    assert_eq!(responses[0].status, 200);
    assert!(responses[0].request_id.is_some());

    let err = c
        .get_secret_value("x", Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    let errors = rec.errors.lock().unwrap().clone();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].error.code(), ErrorCode::NotFound);
    assert!(!errors[0].will_retry);
    let dump = format!(
        "{:?} {:?} {:?}",
        rec.requests.lock().unwrap(),
        rec.responses.lock().unwrap(),
        errors
    );
    assert!(!dump.contains(SECRET_KEY));
    assert!(!dump.contains("session-token-value-1"));

    // panicking hooks never break a call
    let c = Client::new(
        builder(&server.uri())
            .hooks(Arc::new(PanickingHooks))
            .build()
            .unwrap(),
    )
    .unwrap();
    c.ping().await.unwrap();
    assert_eq!(
        c.get_secret_value("x", Default::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );

    // connection failures reach on_error
    let rec = Recorder::new();
    let c = Client::new(builder(&closed_port()).hooks(rec.clone()).build().unwrap()).unwrap();
    assert!(c.ping().await.is_err());
    assert_eq!(rec.errors.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn core_redaction_error_text() {
    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecrets",
        aws_error(
            400,
            "ValidationException",
            &format!("bad   key {SECRET_KEY}  echoed"),
        ),
    )
    .await;
    let err = client(&server).ping().await.unwrap_err();
    assert!(!err.message().contains(SECRET_KEY), "{}", err.message());
    assert!(
        err.message().contains("bad key [REDACTED] echoed"),
        "{}",
        err.message()
    );
    assert!(!format!("{err:?}").contains(SECRET_KEY));
}

#[tokio::test]
async fn proxy_and_tls_settings() {
    // the mock server acts as an HTTP proxy for an unreachable endpoint
    let server = MockServer::start().await;
    mount(&server, "ping.ok").await;
    let c = Client::new(
        builder("http://secretsmanager.invalid:5000")
            .proxy(server.uri())
            .build()
            .unwrap(),
    )
    .unwrap();
    c.ping().await.unwrap();

    let ok = builder(&server.uri())
        .ca_cert_path(ca_path("ca.pem"))
        .common(|b| b.client_cert(ca_path("client.pem"), ca_path("client.key")))
        .insecure_skip_verify(true)
        .build()
        .unwrap();
    Client::new(ok).unwrap();

    for cfg in [
        builder(&server.uri()).ca_cert_path("/nonexistent/ca.pem"),
        builder(&server.uri()).common(|b| b.ca_cert_pem("not a pem")),
        builder(&server.uri()).common(|b| {
            b.ca_cert_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        }),
        builder(&server.uri())
            .common(|b| b.client_cert("/nonexistent/c.pem", ca_path("client.key"))),
        builder(&server.uri())
            .common(|b| b.client_cert(ca_path("client.pem"), "/nonexistent/c.key")),
        builder(&server.uri()).common(|b| b.client_cert(ca_path("ca.pem"), ca_path("ca.pem"))),
        builder(&server.uri()).header("bad header", "x"),
        builder(&server.uri()).header("x-ok", "bad\nvalue"),
    ] {
        let err = Client::new(cfg.build().unwrap()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Config, "{err}");
    }
}

#[derive(Debug)]
struct NoCredentials;
impl ProvideCredentials for NoCredentials {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::ready(Err(CredentialsError::not_loaded(
            "no credentials in test",
        )))
    }
}

#[tokio::test]
async fn credentials_errors() {
    let server = MockServer::start().await;
    mount(&server, "ping.ok").await;
    let c = Client::new(
        Config::builder()
            .url(server.uri())
            .region("us-east-1")
            .credentials_provider(NoCredentials)
            .retry(fast_retry(0))
            .build()
            .unwrap(),
    )
    .unwrap();
    let err = c.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication, "{err}");
    // health: credential failures do not make the service unhealthy
    assert_eq!(c.health().await.unwrap().details["auth"], "failed");
}

#[tokio::test]
async fn wraps_an_existing_sdk_client() {
    let server = MockServer::start().await;
    mount(&server, "ping.ok").await;
    let sdk_conf = sdk::aws_sdk_secretsmanager::Config::builder()
        .behavior_version(sdk::aws_sdk_secretsmanager::config::BehaviorVersion::latest())
        .region(sdk::aws_sdk_secretsmanager::config::Region::new(
            "us-east-1",
        ))
        .endpoint_url(server.uri())
        .credentials_provider(sdk::aws_sdk_secretsmanager::config::Credentials::new(
            ACCESS_KEY, SECRET_KEY, None, None, "test",
        ))
        .http_client(test_http_client().await)
        .build();
    let raw = sdk::aws_sdk_secretsmanager::Client::from_conf(sdk_conf);
    let c = Client::with_sdk_client(raw.clone()).unwrap();
    assert!(c.config().sdk_client().is_some());
    c.ping().await.unwrap();
    assert!(c.health().await.unwrap().healthy);
    c.close().await;
    // the caller's client stays usable
    raw.list_secrets().max_results(1).send().await.unwrap();

    let err = Config::builder()
        .sdk_client(raw)
        .region("us-east-1")
        .url("http://x")
        .build()
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Config);
    assert!(err.message().contains("region, url"), "{}", err.message());
}

/// A plain HTTP client for the caller-built SDK client (the crate builds its own otherwise).
async fn test_http_client() -> sdk::aws_sdk_secretsmanager::config::SharedHttpClient {
    // Reuse the HTTP client of a throwaway Grow client.
    let c = Client::new(builder("http://127.0.0.1:1").build().unwrap()).unwrap();
    c.sdk().await.unwrap().config().http_client().unwrap()
}
