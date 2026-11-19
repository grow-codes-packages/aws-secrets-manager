// Taken over from sdk-kit 0.1.0 (header removed): the skeleton test spoke to the demo service;
// this one drives every blocking method against recorded AWS responses.
//! Blocking client (feature `blocking`).
#![cfg(feature = "blocking")]

mod support;

use std::collections::BTreeMap;

use grow_aws_secrets_manager as sdk;
use sdk::core::ErrorCode;
use sdk::models::*;
use serde_json::json;
use support::*;
use wiremock::MockServer;

use sdk::blocking::AwsSecretsManagerClient as Client;
use sdk::AwsSecretsManagerConfig as Config;

#[test]
fn blocking_client() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(async {
        let server = MockServer::start().await;
        // a last page (no NextToken), so list_secrets ends
        mount(&server, "listSecrets.page2").await;
        mount(&server, "getSecretValue.json-seed").await;
        mount(&server, "batchGetSecretValue.ids-partial").await;
        mount(&server, "describeSecret.ok").await;
        mount(&server, "listSecretVersionIds.ok").await;
        mount(&server, "createSecret.ok-string").await;
        mount(&server, "putSecretValue.ok").await;
        mount(&server, "updateSecret.description").await;
        mount(&server, "updateSecretVersionStage.move").await;
        mount(&server, "deleteSecret.recovery-window").await;
        mount(&server, "restoreSecret.ok").await;
        mount(&server, "tagResource.ok").await;
        mount(&server, "untagResource.ok").await;
        mount(&server, "putResourcePolicy.ok").await;
        mount(&server, "getResourcePolicy.ok").await;
        mount(&server, "deleteResourcePolicy.ok").await;
        mount(&server, "validateResourcePolicy.moto-unsupported").await;
        mount(&server, "rotateSecret.rules-only").await;
        mount(&server, "cancelRotateSecret.ok").await;
        mount(&server, "getRandomPassword.ok").await;
        server
    });
    let c = Client::new(builder(&server.uri()).build().unwrap()).unwrap();
    assert!(c.health().unwrap().healthy);
    c.ping().unwrap();
    assert_eq!(
        c.server_version().unwrap_err().code(),
        ErrorCode::Unsupported
    );
    assert!(!c.async_client().is_closed());
    assert_eq!(c.block_on(async { 7 }), 7);

    let id = "grow-bootstrap/seed-json";
    assert!(!c.get_secret_value(id, Default::default()).unwrap().binary);
    assert_eq!(
        c.get_json_field(id, "username", Default::default())
            .unwrap(),
        Some(json!("seed-user"))
    );
    assert_eq!(
        c.batch_get_secret_value(["a"], Default::default())
            .unwrap()
            .errors
            .len(),
        1
    );
    assert!(c.describe_secret(id).is_ok());
    assert!(!c.list_secrets(Default::default()).unwrap().is_empty());
    assert!(!c
        .list_secret_version_ids(id, Default::default())
        .unwrap()
        .is_empty());
    assert!(c
        .create_secret(id, Some("v".into()), Default::default())
        .is_ok());
    assert!(c.put_secret_value(id, "v", Default::default()).is_ok());
    assert!(c
        .update_secret(
            id,
            UpdateSecretOptions {
                description: Some("d".into()),
                ..Default::default()
            }
        )
        .is_ok());
    assert!(c
        .update_secret_version_stage(
            id,
            "X",
            UpdateSecretVersionStageOptions {
                move_to_version_id: Some("v".into()),
                remove_from_version_id: None
            }
        )
        .is_ok());
    assert!(c.delete_secret(id, Default::default()).is_ok());
    assert!(c.restore_secret(id).is_ok());
    c.tag_resource(id, BTreeMap::from([("a".into(), "b".into())]))
        .unwrap();
    c.untag_resource(id, vec!["a".into()]).unwrap();
    assert!(c.put_resource_policy(id, "{}", Default::default()).is_ok());
    assert!(c.get_resource_policy(id).unwrap().resource_policy.is_some());
    assert!(c.delete_resource_policy(id).is_ok());
    assert_eq!(
        c.validate_resource_policy("{}", Default::default())
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported
    );
    assert!(c.rotate_secret(id, Default::default()).is_ok());
    assert!(c.cancel_rotate_secret(id).is_ok());
    assert!(!c
        .get_random_password(Default::default())
        .unwrap()
        .is_empty());

    c.close();
    c.close();
    assert_eq!(c.ping().unwrap_err().code(), ErrorCode::Cancelled);
    let _ = Client::from_env();
    let bad = Config::builder()
        .ca_cert_path("/nonexistent")
        .build()
        .unwrap();
    assert_eq!(Client::new(bad).unwrap_err().code(), ErrorCode::Config);
    drop(c);
    drop(rt);
}
