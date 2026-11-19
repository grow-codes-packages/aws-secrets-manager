// Created by sdk-kit 0.1.0; owned by this repository.
//! Integration suite against the real service (Docker): client round trips and the
//! conformance scenarios for `core` and this service's categories.

use grow_aws_secrets_manager as sdk;
use grow_aws_secrets_manager_integration as support;
use sdk::testing::{ConformanceRunner, CoreHandler};
use sdk::ErrorCode;
use support::{conformance_dir, load_bootstrap_env};

use sdk::blocking::AwsSecretsManagerClient as BlockingClient;

use sdk::AwsSecretsManagerClient as Client;
use sdk::AwsSecretsManagerConfig as Config;

fn client() -> Client {
    load_bootstrap_env();
    Client::new(Config::from_env().expect("config from env")).expect("client")
}

#[tokio::test]
async fn client_round_trip() {
    let c = client();
    let health = c.health().await.expect("health");
    assert!(health.healthy, "service not healthy: {health:?}");
    c.ping().await.expect("authenticated ping");
    let e = c.server_version().await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unsupported, "{e}");
    c.close().await;
    c.close().await;
}

#[test]
fn blocking_round_trip() {
    load_bootstrap_env();
    let c = BlockingClient::from_env().expect("client");
    assert!(c.health().expect("health").healthy);
    c.ping().expect("ping");
    let seed = std::env::var("GROW_TEST_SEED_JSON_SECRET").expect("seed");
    let v = c
        .get_secret_value(&seed, Default::default())
        .expect("seed value");
    assert!(v.value.reveal().unwrap().contains("seed-user"));
    assert!(!c.list_secrets(Default::default()).expect("list").is_empty());
    c.close();
    assert_eq!(c.ping().unwrap_err().code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn conformance() {
    load_bootstrap_env();
    #[allow(unused_mut)]
    let mut runner = ConformanceRunner::new(conformance_dir())
        // AWS Secrets Manager: writes, VersionId versions and deletes. No server version
        // (serverVersion is UNSUPPORTED), so `version` is not declared (docs/compatibility.md).
        .capabilities(sdk::AwsSecretsManagerSecretsProvider::CAPABILITIES)
        .handler(CoreHandler::new(Client::from_env));
    if let Some(provider) = secrets_provider(&client()) {
        let handler = sdk::testing::SecretsHandler::new(move || provider.clone());
        runner = runner.handler(handler);
    }
    let report = runner.run().await.expect("scenarios load");
    println!("{report}");
    report.assert_success();
}

/// The service's `SecretsProvider` for the `secrets` scenarios.
fn secrets_provider(client: &Client) -> Option<std::sync::Arc<dyn sdk::secrets::SecretsProvider>> {
    Some(std::sync::Arc::new(client.secrets()))
}
