//! Helpers for the AWS service tests: recorded Moto fixtures served by a wiremock server.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use grow_aws_secrets_manager as sdk;
use sdk::core::{ErrorInfo, Hooks, RandomSource, RequestInfo, ResponseInfo, RetryPolicy};
use sdk::{AwsSecretsManagerClient, AwsSecretsManagerConfig, AwsSecretsManagerConfigBuilder};
use serde_json::Value;
use wiremock::matchers::{body_partial_json, header};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const ACCESS_KEY: &str = "AKIDUNITTEST";
pub const SECRET_KEY: &str = "unit-secret-key-0123456789";

/// A recorded fixture (`tests/fixtures/aws/<name>.json`).
pub fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/aws/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("fixture {path}"));
    serde_json::from_str(&text).expect("fixture JSON")
}

/// The `X-Amz-Target` of a fixture.
pub fn target_of(fx: &Value) -> String {
    fx["request"]["headers"]["X-Amz-Target"]
        .as_str()
        .expect("target")
        .to_owned()
}

/// Response template replaying a fixture response.
pub fn replay(fx: &Value) -> ResponseTemplate {
    let resp = &fx["response"];
    let status = resp["status"].as_u64().expect("status") as u16;
    let mut t = ResponseTemplate::new(status);
    if let Some(headers) = resp["headers"].as_object() {
        for (k, v) in headers {
            if matches!(k.as_str(), "content-length" | "status" | "content-type") {
                continue;
            }
            t = t.insert_header(k.as_str(), v.as_str().unwrap_or_default());
        }
    }
    let content_type = resp["headers"]["content-type"]
        .as_str()
        .unwrap_or("application/x-amz-json-1.1")
        .to_owned();
    match &resp["body"] {
        Value::Null => t,
        Value::String(text) => t.set_body_raw(text.clone().into_bytes(), &content_type),
        body => t.set_body_raw(body.to_string().into_bytes(), &content_type),
    }
}

/// A JSON 1.1 response for `target` with `body`.
pub fn aws_json(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_raw(body.to_string().into_bytes(), "application/x-amz-json-1.1")
}

/// An AWS JSON error response.
pub fn aws_error(status: u16, code: &str, message: &str) -> ResponseTemplate {
    aws_json(
        status,
        serde_json::json!({"__type": code, "message": message}),
    )
    .insert_header("x-amzn-requestid", "req-123")
}

/// Mounts a fixture: matched by target (and by `body` when given).
pub async fn mount(server: &MockServer, name: &str) {
    mount_matching(server, name, None).await
}

/// Mounts a fixture for requests whose body contains `body`.
pub async fn mount_matching(server: &MockServer, name: &str, body: Option<Value>) {
    let fx = fixture(name);
    let mut m = Mock::given(header("x-amz-target", target_of(&fx).as_str()));
    if let Some(b) = body {
        m = m.and(body_partial_json(b));
    }
    m.respond_with(replay(&fx)).mount(server).await;
}

/// Mounts `resp` for `operation` (e.g. `"GetSecretValue"`).
pub async fn mount_op(server: &MockServer, operation: &str, resp: ResponseTemplate) {
    Mock::given(header(
        "x-amz-target",
        format!("secretsmanager.{operation}").as_str(),
    ))
    .respond_with(resp)
    .mount(server)
    .await;
}

/// Retry policy with deterministic jitter and short backoffs.
pub fn fast_retry(max_retries: u32) -> RetryPolicy {
    RetryPolicy {
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(20),
        ..RetryPolicy::default()
    }
    .with_random(RandomSource::fixed(0.0))
    .with_max_retries(max_retries)
}

/// Builder pointing at `url` with static test credentials and no retries.
pub fn builder(url: &str) -> AwsSecretsManagerConfigBuilder {
    AwsSecretsManagerConfig::builder()
        .url(url)
        .region("us-east-1")
        .access_key_id(ACCESS_KEY)
        .secret_access_key(SECRET_KEY)
        .retry(fast_retry(0))
}

/// Client pointing at the mock server.
pub fn client(server: &MockServer) -> AwsSecretsManagerClient {
    AwsSecretsManagerClient::new(builder(&server.uri()).build().expect("config")).expect("client")
}

/// A port nobody listens on.
pub fn closed_port() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

/// Hooks that record every call.
#[derive(Default)]
pub struct Recorder {
    pub requests: Mutex<Vec<RequestInfo>>,
    pub responses: Mutex<Vec<ResponseInfo>>,
    pub errors: Mutex<Vec<ErrorInfo>>,
}

impl Recorder {
    pub fn new() -> Arc<Self> {
        Arc::new(Recorder::default())
    }
}

impl Hooks for Recorder {
    fn on_request(&self, info: &RequestInfo) {
        self.requests.lock().unwrap().push(info.clone());
    }
    fn on_response(&self, info: &ResponseInfo) {
        self.responses.lock().unwrap().push(info.clone());
    }
    fn on_error(&self, info: &ErrorInfo) {
        self.errors.lock().unwrap().push(info.clone());
    }
}

/// Body of the n-th request received by the server.
pub async fn request_body(server: &MockServer, n: usize) -> Value {
    let reqs = server.received_requests().await.expect("recording");
    serde_json::from_slice(&reqs[n].body).expect("JSON body")
}

/// Bodies of every request with the given operation.
pub async fn bodies_of(server: &MockServer, operation: &str) -> Vec<Value> {
    let target = format!("secretsmanager.{operation}");
    server
        .received_requests()
        .await
        .expect("recording")
        .iter()
        .filter(|r| {
            r.headers.get("x-amz-target").and_then(|v| v.to_str().ok()) == Some(target.as_str())
        })
        .map(|r| serde_json::from_slice(&r.body).expect("JSON body"))
        .collect()
}
