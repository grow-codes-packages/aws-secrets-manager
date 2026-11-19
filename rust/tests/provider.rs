//! `AwsSecretsManagerSecretsProvider`: the SPEC §3 secrets provider over AWS Secrets Manager.

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use grow_aws_secrets_manager as sdk;
use sdk::secrets::{
    DeleteOptions, GetOptions, SecretData, SecretsProvider, SetOptions, WatchOptions,
};
use sdk::{AwsSecretsManagerSecretsOptions, AwsSecretsManagerSecretsProvider, ErrorCode};
use serde_json::{json, Value};
use support::*;
use wiremock::matchers::{body_partial_json, header};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn entry(name: &str, version: &str, deleted: bool) -> Value {
    let mut e = json!({
        "ARN": format!("arn:aws:secretsmanager:us-east-1:1:secret:{name}-abc"),
        "Name": name,
        "CreatedDate": 1795033095,
        "LastChangedDate": 1795033096,
        "Description": "d",
        "KmsKeyId": "k",
        "PrimaryRegion": "us-east-1",
        "NextRotationDate": 1797625096,
        "Tags": [{"Key": "team", "Value": "sdk"}],
        "SecretVersionsToStages": {version: ["AWSCURRENT"], "old": ["AWSPREVIOUS"]},
    });
    if deleted {
        e["DeletedDate"] = json!(1795033099);
    }
    e
}

fn provider(server: &MockServer) -> AwsSecretsManagerSecretsProvider {
    client(server).secrets()
}

async fn mount_match(server: &MockServer, op: &str, body: Value, resp: ResponseTemplate) {
    Mock::given(header(
        "x-amz-target",
        format!("secretsmanager.{op}").as_str(),
    ))
    .and(body_partial_json(body))
    .respond_with(resp)
    .mount(server)
    .await;
}

#[tokio::test]
async fn get_reads_versions_paths_and_missing() {
    let server = MockServer::start().await;
    mount_match(
        &server,
        "GetSecretValue",
        json!({"SecretId": "app/missing"}),
        aws_error(400, "ResourceNotFoundException", "x"),
    )
    .await;
    mount_match(
        &server,
        "GetSecretValue",
        json!({"SecretId": "app/deleted"}),
        replay(&fixture("getSecretValue.marked-deleted")),
    )
    .await;
    mount_match(
        &server,
        "GetSecretValue",
        json!({"SecretId": "app/denied"}),
        aws_error(400, "AccessDeniedException", "x"),
    )
    .await;
    mount_match(
        &server,
        "GetSecretValue",
        json!({"SecretId": "app/db", "VersionId": "v1"}),
        aws_json(
            200,
            json!({"Name": "app/db", "VersionId": "v1", "SecretString": "old"}),
        ),
    )
    .await;
    mount_match(
        &server,
        "GetSecretValue",
        json!({"SecretId": "app/db"}),
        aws_json(
            200,
            json!({"Name": "app/db", "VersionId": "v2", "SecretString": "{\"n\":5}"}),
        ),
    )
    .await;
    let p = provider(&server);
    assert_eq!(
        AwsSecretsManagerSecretsProvider::CAPABILITIES,
        ["write", "versions", "delete"]
    );
    assert_eq!(p.recovery_window_days(), 30);
    assert!(!p.client().is_closed());

    let v = p.get("app/db", None).await.unwrap().unwrap();
    assert_eq!(v.version(), Some("v2"));
    let path = GetOptions {
        path: Some("/app/".into()),
        version: None,
    };
    assert_eq!(
        p.get_json("db", Some(&path)).await.unwrap().unwrap()["n"],
        5
    );
    let old = GetOptions {
        version: Some("v1".into()),
        path: None,
    };
    assert_eq!(
        p.get_string("app/db", Some(&old)).await.unwrap().as_deref(),
        Some("old")
    );
    assert!(p.get("app/missing", None).await.unwrap().is_none());
    assert!(p.get("app/deleted", None).await.unwrap().is_none());
    assert!(!p.exists("app/missing", None).await.unwrap());
    assert_eq!(
        p.require("app/missing", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        p.get("app/denied", None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        p.get("", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(sdk::full_name("x", Some("")), "x");
    assert_eq!(sdk::full_name("x", None), "x");
}

#[tokio::test]
async fn set_puts_creates_and_handles_races() {
    // existing secret: PutSecretValue (+ TagResource + UpdateSecret)
    let server = MockServer::start().await;
    mount_op(
        &server,
        "PutSecretValue",
        aws_json(
            200,
            json!({"Name": "a", "VersionId": "v9", "VersionStages": ["AWSCURRENT"]}),
        ),
    )
    .await;
    mount_op(&server, "TagResource", aws_json(200, json!({}))).await;
    mount_op(&server, "UpdateSecret", aws_json(200, json!({"Name": "a"}))).await;
    let p = provider(&server);
    let opts = SetOptions {
        path: Some("team".into()),
        tags: BTreeMap::from([("k".into(), "v".into())]),
        description: Some("desc".into()),
        cas: None,
    };
    assert_eq!(p.set("a", "text".into(), Some(&opts)).await.unwrap(), "v9");
    let put = &bodies_of(&server, "PutSecretValue").await[0];
    assert_eq!(put["SecretId"], "team/a");
    assert_eq!(put["SecretString"], "text");
    assert_eq!(
        bodies_of(&server, "TagResource").await[0]["Tags"],
        json!([{"Key": "k", "Value": "v"}])
    );
    assert_eq!(
        bodies_of(&server, "UpdateSecret").await[0]["Description"],
        "desc"
    );
    p.set("b", SecretData::Bytes(vec![0xff, 0x00]), None)
        .await
        .unwrap();
    assert_eq!(
        bodies_of(&server, "PutSecretValue").await[1]["SecretBinary"],
        "/wA="
    );
    p.set("c", SecretData::Json(json!({"a": 1})), None)
        .await
        .unwrap();
    assert_eq!(
        bodies_of(&server, "PutSecretValue").await[2]["SecretString"],
        "{\"a\":1}"
    );
    let cas = SetOptions {
        cas: Some(1),
        ..Default::default()
    };
    assert_eq!(
        p.set("a", "x".into(), Some(&cas)).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        p.set(" ", "x".into(), None).await.unwrap_err().code(),
        ErrorCode::Validation
    );

    // missing secret: CreateSecret with description and tags
    let server = MockServer::start().await;
    mount_op(
        &server,
        "PutSecretValue",
        aws_error(400, "ResourceNotFoundException", "x"),
    )
    .await;
    mount_op(
        &server,
        "CreateSecret",
        aws_json(200, json!({"Name": "n", "VersionId": "v1"})),
    )
    .await;
    let p = provider(&server);
    assert_eq!(p.set("n", "x".into(), Some(&opts)).await.unwrap(), "v1");
    let created = &bodies_of(&server, "CreateSecret").await[0];
    assert_eq!(created["Name"], "team/n");
    assert_eq!(created["Description"], "desc");

    // create race: CreateSecret → ResourceExists → PutSecretValue again
    let server = MockServer::start().await;
    Mock::given(header("x-amz-target", "secretsmanager.PutSecretValue"))
        .respond_with(aws_error(400, "ResourceNotFoundException", "x"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_op(
        &server,
        "PutSecretValue",
        aws_json(200, json!({"Name": "r", "VersionId": "v2"})),
    )
    .await;
    mount_op(
        &server,
        "CreateSecret",
        aws_error(400, "ResourceExistsException", "x"),
    )
    .await;
    assert_eq!(
        provider(&server).set("r", "x".into(), None).await.unwrap(),
        "v2"
    );

    // other errors pass through
    let server = MockServer::start().await;
    mount_op(
        &server,
        "PutSecretValue",
        aws_error(400, "ResourceNotFoundException", "x"),
    )
    .await;
    mount_op(
        &server,
        "CreateSecret",
        aws_error(400, "InvalidRequestException", "pending deletion"),
    )
    .await;
    assert_eq!(
        provider(&server)
            .set("r", "x".into(), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Conflict
    );
    let server = MockServer::start().await;
    mount_op(
        &server,
        "PutSecretValue",
        aws_error(400, "AccessDeniedException", "x"),
    )
    .await;
    assert_eq!(
        provider(&server)
            .set("r", "x".into(), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    let server = MockServer::start().await;
    mount_op(
        &server,
        "PutSecretValue",
        aws_json(200, json!({"Name": "r", "VersionId": "v2"})),
    )
    .await;
    mount_op(
        &server,
        "TagResource",
        aws_error(400, "AccessDeniedException", "x"),
    )
    .await;
    let tags = SetOptions {
        tags: BTreeMap::from([("k".into(), "v".into())]),
        ..Default::default()
    };
    assert!(provider(&server)
        .set("r", "x".into(), Some(&tags))
        .await
        .is_err());
    // create without a version id answers ""
    let server = MockServer::start().await;
    mount_op(
        &server,
        "PutSecretValue",
        aws_error(400, "ResourceNotFoundException", "x"),
    )
    .await;
    mount_op(&server, "CreateSecret", aws_json(200, json!({"Name": "n"}))).await;
    assert_eq!(
        provider(&server).set("n", "x".into(), None).await.unwrap(),
        ""
    );
}

#[tokio::test]
async fn delete_and_metadata() {
    let server = MockServer::start().await;
    mount_match(
        &server,
        "DescribeSecret",
        json!({"SecretId": "gone"}),
        aws_error(400, "ResourceNotFoundException", "x"),
    )
    .await;
    mount_match(
        &server,
        "DescribeSecret",
        json!({"SecretId": "pending"}),
        aws_json(200, entry("pending", "v1", true)),
    )
    .await;
    mount_match(
        &server,
        "DescribeSecret",
        json!({"SecretId": "denied"}),
        aws_error(400, "AccessDeniedException", "x"),
    )
    .await;
    let mut described = entry("app/db", "v1", false);
    described["VersionIdsToStages"] = described["SecretVersionsToStages"].take();
    mount_op(&server, "DescribeSecret", aws_json(200, described)).await;
    mount_op(
        &server,
        "DeleteSecret",
        aws_json(200, json!({"Name": "app/db", "DeletionDate": 1795637897})),
    )
    .await;
    let p = provider(&server);

    let m = p
        .metadata(
            "db",
            Some(&GetOptions {
                path: Some("app".into()),
                version: None,
            }),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(m.name, "app/db");
    assert_eq!(m.path.as_deref(), Some("app"));
    assert_eq!(m.version.as_deref(), Some("v1"));
    assert_eq!(m.versions, Some(2));
    assert_eq!(m.tags["team"], "sdk");
    assert!(m.created_at.is_some() && m.updated_at.is_some());
    for key in [
        "arn",
        "rotationEnabled",
        "description",
        "kmsKeyId",
        "nextRotationDate",
        "primaryRegion",
    ] {
        assert!(m.extra.contains_key(key), "{key}");
    }
    assert!(p.metadata("gone", None).await.unwrap().is_none());
    assert!(p.metadata("pending", None).await.unwrap().is_none());
    assert_eq!(
        p.metadata("denied", None).await.unwrap_err().code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        p.metadata("", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );

    p.delete("app/db", None).await.unwrap();
    assert_eq!(
        bodies_of(&server, "DeleteSecret").await[0],
        json!({"SecretId": "app/db", "RecoveryWindowInDays": 30})
    );
    p.delete(
        "db",
        Some(&DeleteOptions {
            path: Some("app".into()),
            permanent: true,
            versions: vec![],
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        bodies_of(&server, "DeleteSecret").await[1],
        json!({"SecretId": "app/db", "ForceDeleteWithoutRecovery": true})
    );
    let short = client(&server)
        .secrets_with_options(AwsSecretsManagerSecretsOptions {
            recovery_window_days: Some(7),
        })
        .unwrap();
    short.delete("app/db", None).await.unwrap();
    assert_eq!(
        bodies_of(&server, "DeleteSecret").await[2]["RecoveryWindowInDays"],
        7
    );
    assert_eq!(
        p.delete("gone", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        p.delete("pending", None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let versions = DeleteOptions {
        versions: vec!["v1".into()],
        ..Default::default()
    };
    assert_eq!(
        p.delete("app/db", Some(&versions))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    assert_eq!(
        p.delete("", None).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(bodies_of(&server, "DeleteSecret").await.len(), 3);
    let err = client(&server)
        .secrets_with_options(AwsSecretsManagerSecretsOptions {
            recovery_window_days: Some(3),
        })
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
}

#[tokio::test]
async fn list_get_all_and_get_many() {
    let server = MockServer::start().await;
    let list = json!({"SecretList": [
        entry("app/z", "vz", false),
        entry("app/a", "va", false),
        entry("app/nested/x", "vx", false),
        entry("app/deleted", "vd", true),
        entry("application/word-match", "vw", false),
    ]});
    mount_op(&server, "ListSecrets", aws_json(200, list)).await;
    mount_op(
        &server,
        "BatchGetSecretValue",
        aws_json(200, json!({
            "SecretValues": [
                {"Name": "app/z", "ARN": "arn:z", "VersionId": "vz", "SecretString": "Z"},
                {"Name": "app/a", "ARN": "arn:a", "VersionId": "va", "SecretString": "A"}
            ],
            "Errors": [{"SecretId": "app/missing", "ErrorCode": "ResourceNotFoundException", "Message": "x"}]
        })),
    )
    .await;
    let p = provider(&server);

    let items = p.list(Some("app/")).await.unwrap();
    let names: Vec<&str> = items.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["app/a", "app/nested/x", "app/z"]);
    assert_eq!(
        bodies_of(&server, "ListSecrets").await[0]["Filters"],
        json!([{"Key": "name", "Values": ["app/"]}])
    );
    let all = p.list(None).await.unwrap();
    assert_eq!(all.len(), 4);
    assert!(bodies_of(&server, "ListSecrets").await[1]
        .get("Filters")
        .is_none());

    let map = p.get_all(Some("/app/")).await.unwrap();
    let names: Vec<&str> = map.names().collect();
    assert_eq!(names, ["app/a", "app/z"]);
    assert_eq!(map.get("app/a").unwrap().reveal().unwrap(), "A");
    let batch = &bodies_of(&server, "BatchGetSecretValue").await[0];
    assert_eq!(batch["SecretIdList"], json!(["app/a", "app/z"]));

    let many = p
        .get_many(
            &["z", "missing", "a", "z"],
            Some(&GetOptions {
                path: Some("app".into()),
                version: None,
            }),
        )
        .await
        .unwrap();
    let names: Vec<&str> = many.names().collect();
    assert_eq!(
        names,
        ["z", "a"],
        "request order, missing omitted, duplicates once"
    );
    assert_eq!(
        p.get_many(&["ok", ""], None).await.unwrap_err().code(),
        ErrorCode::Validation
    );

    let root = p.get_all(None).await.unwrap();
    assert_eq!(
        root.len(),
        0,
        "batch answers with names that were not requested"
    );

    // per-secret errors other than "missing" fail the call
    let server = MockServer::start().await;
    mount_op(
        &server,
        "BatchGetSecretValue",
        aws_json(200, json!({"SecretValues": [], "Errors": [{"SecretId": "s", "ErrorCode": "AccessDeniedException"}, {"SecretId": "t"}]})),
    )
    .await;
    let err = provider(&server).get_many(&["s"], None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    let server = MockServer::start().await;
    mount_op(
        &server,
        "BatchGetSecretValue",
        aws_json(
            200,
            json!({"SecretValues": [], "Errors": [{"SecretId": "t"}]}),
        ),
    )
    .await;
    let err = provider(&server).get_many(&["t"], None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);

    // with a version: one GetSecretValue per name
    let server = MockServer::start().await;
    mount_match(
        &server,
        "GetSecretValue",
        json!({"SecretId": "m"}),
        aws_error(400, "ResourceNotFoundException", "x"),
    )
    .await;
    mount_op(
        &server,
        "GetSecretValue",
        aws_json(
            200,
            json!({"Name": "a", "VersionId": "v1", "SecretString": "A"}),
        ),
    )
    .await;
    let p = provider(&server);
    let v = GetOptions {
        version: Some("v1".into()),
        path: None,
    };
    let many = p.get_many(&["a", "m"], Some(&v)).await.unwrap();
    assert_eq!(many.names().collect::<Vec<_>>(), ["a"]);
    assert_eq!(bodies_of(&server, "GetSecretValue").await.len(), 2);
    assert!(bodies_of(&server, "BatchGetSecretValue").await.is_empty());
}

#[tokio::test]
async fn watch_reports_changes_and_stops_on_close() {
    let server = MockServer::start().await;
    Mock::given(header("x-amz-target", "secretsmanager.GetSecretValue"))
        .respond_with(aws_json(
            200,
            json!({"Name": "w", "VersionId": "v1", "SecretString": "one"}),
        ))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    mount_op(
        &server,
        "GetSecretValue",
        aws_json(
            200,
            json!({"Name": "w", "VersionId": "v2", "SecretString": "two"}),
        ),
    )
    .await;
    let c = client(&server);
    let p = c.secrets();
    let changes = Arc::new(AtomicU32::new(0));
    let seen = changes.clone();
    let handle = p.watch(
        "w",
        Duration::from_millis(30),
        move |new, old| {
            assert_eq!(new.unwrap().version(), Some("v2"));
            assert_eq!(old.unwrap().version(), Some("v1"));
            seen.fetch_add(1, Ordering::SeqCst);
        },
        WatchOptions::default(),
    );
    for _ in 0..100 {
        if changes.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(changes.load(Ordering::SeqCst), 1);
    c.close().await;
    assert!(handle.is_stopped());
}

#[tokio::test]
async fn load_env_uses_get_all() {
    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecrets",
        aws_json(
            200,
            json!({"SecretList": [entry("cfg/db-url", "v", false)]}),
        ),
    )
    .await;
    mount_op(
        &server,
        "BatchGetSecretValue",
        aws_json(200, json!({"SecretValues": [{"Name": "cfg/db-url", "ARN": "arn:x", "SecretString": "postgres://x"}]})),
    )
    .await;
    let p = provider(&server);
    let mut sink: std::collections::HashMap<String, String> = Default::default();
    let set = sdk::secrets::load_env_into(
        &p,
        &sdk::secrets::EnvSource::Path("cfg".into()),
        &sdk::secrets::LoadEnvOptions {
            prefix: "APP_".into(),
            ..Default::default()
        },
        &mut sink,
    )
    .await
    .unwrap();
    assert_eq!(set.len(), 1);
    assert_eq!(
        sink.values().next().map(String::as_str),
        Some("postgres://x")
    );
}
