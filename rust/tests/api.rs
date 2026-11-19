//! Service operations against recorded Moto responses (fixtures) and AWS-shaped errors.

mod support;

use std::collections::BTreeMap;

use grow_aws_secrets_manager as sdk;
use sdk::models::*;
use sdk::secrets::SecretData;
use sdk::{aws_error_code, ErrorCode};
use serde_json::json;
use support::*;
use wiremock::MockServer;

const DB: &str = "sdkv-0badc0de/app/db";
const BLOB: &str = "sdkv-0badc0de/app/blob";

#[tokio::test]
async fn get_secret_value_string_binary_and_versions() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "getSecretValue.ok-version-id",
        Some(json!({"VersionId": "11111111-1111-4111-8111-11110badc0de"})),
    )
    .await;
    mount_matching(
        &server,
        "getSecretValue.ok-version-stage",
        Some(json!({"VersionStage": "AWSPREVIOUS"})),
    )
    .await;
    mount_matching(
        &server,
        "getSecretValue.ok-binary",
        Some(json!({"SecretId": BLOB})),
    )
    .await;
    mount_matching(
        &server,
        "getSecretValue.not-found",
        Some(json!({"SecretId": "sdkv-0badc0de/missing"})),
    )
    .await;
    mount_matching(
        &server,
        "getSecretValue.marked-deleted",
        Some(json!({"SecretId": "deleted"})),
    )
    .await;
    mount_matching(
        &server,
        "getSecretValue.ok-string",
        Some(json!({"SecretId": DB})),
    )
    .await;
    let c = client(&server);

    let v = c.get_secret_value(DB, Default::default()).await.unwrap();
    assert_eq!(v.name, DB);
    assert!(v.arn.starts_with("arn:aws:secretsmanager:"));
    assert!(!v.binary);
    assert!(v.version_stages.contains(&AWSCURRENT.to_owned()));
    assert!(v.created_date.is_some());
    assert_eq!(v.value.version(), v.version_id.as_deref());
    assert!(!v.value.reveal().unwrap().is_empty());
    assert!(!format!("{v:?}").contains(v.value.reveal().unwrap()));

    let b = c.get_secret_value(BLOB, Default::default()).await.unwrap();
    assert!(b.binary);
    assert_eq!(b.value.reveal_bytes(), &[0, 1, 2, 0xfe, 0xff]);

    let by_id = c
        .get_secret_value(
            DB,
            GetSecretValueOptions::version_id("11111111-1111-4111-8111-11110badc0de"),
        )
        .await
        .unwrap();
    assert!(by_id.version_id.is_some());
    assert_eq!(
        request_body(&server, 2).await["VersionId"],
        "11111111-1111-4111-8111-11110badc0de"
    );
    let prev = c
        .get_secret_value(DB, GetSecretValueOptions::version_stage(AWSPREVIOUS))
        .await
        .unwrap();
    assert!(prev.version_stages.contains(&AWSPREVIOUS.to_owned()));

    let err = c
        .get_secret_value("sdkv-0badc0de/missing", Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(err.http_status(), Some(404));
    assert!(err.request_id().is_some());
    assert!(
        err.message()
            .starts_with("getSecretValue sdkv-0badc0de/missing: ResourceNotFoundException"),
        "{}",
        err.message()
    );
    assert_eq!(aws_error_code(&err), Some("ResourceNotFoundException"));
    assert!(!err.is_retryable());

    let err = c
        .get_secret_value("deleted", Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    assert!(sdk::is_missing(&err));

    let err = c
        .get_secret_value(" ", Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
}

#[tokio::test]
async fn get_json_field_paths_and_errors() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "getSecretValue.ok-binary",
        Some(json!({"SecretId": BLOB})),
    )
    .await;
    mount_matching(
        &server,
        "getSecretValue.ok-string",
        Some(json!({"SecretId": DB})),
    )
    .await;
    mount_op(
        &server,
        "GetSecretValue",
        aws_json(200, json!({"ARN": "arn:x", "Name": "j", "VersionId": "v", "SecretString": "{\"db\":{\"port\":5432},\"user\":\"u\",\"n\":null}"})),
    )
    .await;
    let c = client(&server);
    assert_eq!(
        c.get_json_field("j", "user", Default::default())
            .await
            .unwrap(),
        Some(json!("u"))
    );
    assert_eq!(
        c.get_json_field("j", "db.port", Default::default())
            .await
            .unwrap(),
        Some(json!(5432))
    );
    assert_eq!(
        c.get_json_field("j", "n", Default::default())
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        c.get_json_field("j", "nope", Default::default())
            .await
            .unwrap(),
        None
    );
    let err = c
        .get_json_field(BLOB, "x", Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    let err = c
        .get_json_field(DB, "x", Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);

    let server = MockServer::start().await;
    mount_op(
        &server,
        "GetSecretValue",
        aws_json(200, json!({"Name": "a", "SecretString": "[1,2]"})),
    )
    .await;
    let err = client(&server)
        .get_json_field("a", "x", Default::default())
        .await
        .unwrap_err();
    assert!(err.message().contains("not a JSON object"));
}

#[tokio::test]
async fn batch_get_by_ids_and_filters() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "batchGetSecretValue.filters-page2",
        Some(json!({"NextToken": "2"})),
    )
    .await;
    mount_matching(
        &server,
        "batchGetSecretValue.filters",
        Some(json!({"MaxResults": 2})),
    )
    .await;
    mount_matching(&server, "batchGetSecretValue.ids-partial", None).await;
    let c = client(&server);

    let ids = [BLOB, "sdkv-0badc0de/missing", DB];
    let r = c
        .batch_get_secret_value(ids, Default::default())
        .await
        .unwrap();
    let names: Vec<&str> = r.secret_values.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, [BLOB, DB], "request order");
    assert_eq!(r.errors.len(), 1);
    assert_eq!(
        r.errors[0].error_code.as_deref(),
        Some("ResourceNotFoundException")
    );
    assert_eq!(
        r.errors[0].secret_id.as_deref(),
        Some("sdkv-0badc0de/missing")
    );

    let r = c
        .batch_get_secret_value(
            vec![SecretFilter::name("sdkv-0badc0de/page/")],
            BatchGetOptions {
                max_results: Some(2),
            },
        )
        .await
        .unwrap();
    let names: Vec<&str> = r.secret_values.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "sdkv-0badc0de/page/p1",
            "sdkv-0badc0de/page/p2",
            "sdkv-0badc0de/page/p3"
        ]
    );

    let err = c
        .batch_get_secret_value(Vec::<SecretFilter>::new(), Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
}

#[tokio::test]
async fn batch_get_splits_more_than_20_ids_and_follows_tokens() {
    let server = MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::header("x-amz-target", "secretsmanager.BatchGetSecretValue"))
        .and(wiremock::matchers::body_partial_json(json!({"NextToken": "t2"})))
        .respond_with(aws_json(200, json!({"SecretValues": [{"Name": "s0", "ARN": "arn:s0", "SecretString": "0"}], "Errors": []})))
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::header("x-amz-target", "secretsmanager.BatchGetSecretValue"))
        .respond_with(aws_json(200, json!({"SecretValues": [{"Name": "s1", "ARN": "arn:s1", "SecretString": "1"}], "Errors": [], "NextToken": "t2"})))
        .mount(&server)
        .await;
    let c = client(&server);
    let ids: Vec<String> = (0..21).map(|i| format!("s{i}")).collect();
    let r = c
        .batch_get_secret_value(ids, Default::default())
        .await
        .unwrap();
    let bodies = bodies_of(&server, "BatchGetSecretValue").await;
    assert_eq!(bodies.len(), 4, "2 chunks × 2 pages");
    assert_eq!(bodies[0]["SecretIdList"].as_array().unwrap().len(), 20);
    assert_eq!(bodies[2]["SecretIdList"].as_array().unwrap().len(), 1);
    let names: Vec<&str> = r.secret_values.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, ["s0", "s1", "s1", "s0"]);
}

#[tokio::test]
async fn describe_and_list() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "describeSecret.not-found",
        Some(json!({"SecretId": "missing"})),
    )
    .await;
    mount(&server, "describeSecret.ok").await;
    mount_matching(
        &server,
        "listSecrets.page2",
        Some(json!({"NextToken": "2"})),
    )
    .await;
    mount_matching(
        &server,
        "listSecrets.bad-filter",
        Some(json!({"Filters": [{"Key": "bogus"}]})),
    )
    .await;
    mount(&server, "listSecrets.page1").await;
    let c = client(&server);

    let d = c.describe_secret(DB).await.unwrap();
    assert_eq!(d.name, DB);
    assert_eq!(d.description.as_deref(), Some("grow sdk verify"));
    assert_eq!(d.tags.get("team").map(String::as_str), Some("sdk"));
    assert!(d.current_version_id().is_some());
    assert!(d.version_ids_to_stages.len() >= 3);
    assert!(!d.pending_deletion());
    assert_eq!(
        c.describe_secret("missing").await.unwrap_err().code(),
        ErrorCode::NotFound
    );

    let opts = ListSecretsOptions {
        filters: vec![SecretFilter::name("sdkv-0badc0de/page/")],
        max_results: Some(2),
        include_planned_deletion: Some(false),
        sort_order: Some("asc".into()),
    };
    let all = c.list_secrets(opts.clone()).try_collect().await.unwrap();
    let names: Vec<&str> = all.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "sdkv-0badc0de/page/p1",
            "sdkv-0badc0de/page/p2",
            "sdkv-0badc0de/page/p3"
        ]
    );
    let first = &bodies_of(&server, "ListSecrets").await[0];
    assert_eq!(first["SortOrder"], "asc");
    assert_eq!(first["IncludePlannedDeletion"], false);

    // item by item and page by page
    let mut p = c.list_secrets(opts.clone());
    assert!(format!("{p:?}").contains("Paginator"));
    assert_eq!(
        p.next().await.unwrap().unwrap().name,
        "sdkv-0badc0de/page/p1"
    );
    let rest = p.next_page().await.unwrap().unwrap();
    assert_eq!(rest.len(), 1, "buffered item first");
    assert_eq!(p.next_page().await.unwrap().unwrap().len(), 1);
    assert!(p.next_page().await.unwrap().is_none());
    assert!(p.next().await.unwrap().is_none());

    use futures::StreamExt;
    let items: Vec<_> = c.list_secrets(opts).into_stream().collect().await;
    assert_eq!(items.len(), 3);

    let bad = ListSecretsOptions {
        filters: vec![SecretFilter::new("bogus", ["x"])],
        ..Default::default()
    };
    let errs: Vec<_> = c.list_secrets(bad.clone()).into_stream().collect().await;
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].as_ref().unwrap_err().code(), ErrorCode::Validation);
    assert_eq!(
        c.list_secrets(bad).try_collect().await.unwrap_err().code(),
        ErrorCode::Validation
    );
}

#[tokio::test]
async fn list_secret_version_ids_pages() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "listSecretVersionIds.page",
        Some(json!({"MaxResults": 1})),
    )
    .await;
    mount(&server, "listSecretVersionIds.ok").await;
    let c = client(&server);
    let versions = c
        .list_secret_version_ids(
            DB,
            ListSecretVersionIdsOptions {
                include_deprecated: Some(true),
                max_results: None,
            },
        )
        .try_collect()
        .await
        .unwrap();
    assert!(versions.len() >= 3);
    assert!(versions
        .iter()
        .any(|v| v.version_stages.contains(&AWSCURRENT.to_owned())));
    assert!(versions[0].created_date.is_some());
    // Moto sends NextToken "" → one page only
    let paged = c
        .list_secret_version_ids(
            DB,
            ListSecretVersionIdsOptions {
                include_deprecated: None,
                max_results: Some(1),
            },
        )
        .try_collect()
        .await
        .unwrap();
    assert_eq!(paged.len(), versions.len());
    assert_eq!(bodies_of(&server, "ListSecretVersionIds").await.len(), 2);
    let err = c
        .list_secret_version_ids("", Default::default())
        .try_collect()
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);

    // AWS shape of a missing secret, and Moto's 500
    let server = MockServer::start().await;
    mount_op(
        &server,
        "ListSecretVersionIds",
        aws_error(400, "ResourceNotFoundException", "missing"),
    )
    .await;
    let err = client(&server)
        .list_secret_version_ids("x", Default::default())
        .try_collect()
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(err.request_id(), Some("req-123"));
    let server = MockServer::start().await;
    mount(&server, "listSecretVersionIds.not-found-moto-500").await;
    let err = client(&server)
        .list_secret_version_ids("x", Default::default())
        .try_collect()
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
}

#[tokio::test]
async fn create_secret_variants() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "createSecret.exists",
        Some(json!({"Name": "exists"})),
    )
    .await;
    mount_matching(
        &server,
        "createSecret.access-denied",
        Some(json!({"Name": "denied"})),
    )
    .await;
    mount_matching(
        &server,
        "createSecret.no-value",
        Some(json!({"Name": "sdkv-0badc0de/empty"})),
    )
    .await;
    mount_matching(
        &server,
        "createSecret.ok-binary",
        Some(json!({"Name": BLOB})),
    )
    .await;
    mount(&server, "createSecret.ok-string").await;
    let c = client(&server);

    let out = c
        .create_secret(
            DB,
            Some("hello-0badc0de".into()),
            CreateSecretOptions {
                description: Some("grow sdk verify".into()),
                kms_key_id: Some("alias/aws/secretsmanager".into()),
                tags: BTreeMap::from([("team".into(), "sdk".into())]),
                client_request_token: Some("11111111-1111-4111-8111-11110badc0de".into()),
                add_replica_regions: vec![ReplicaRegion {
                    region: "eu-west-1".into(),
                    kms_key_id: Some("k".into()),
                }],
                force_overwrite_replica_secret: Some(false),
            },
        )
        .await
        .unwrap();
    assert_eq!(out.name, DB);
    assert_eq!(
        out.version_id.as_deref(),
        Some("11111111-1111-4111-8111-11110badc0de")
    );
    let body = &bodies_of(&server, "CreateSecret").await[0];
    assert_eq!(body["SecretString"], "hello-0badc0de");
    assert_eq!(body["Tags"], json!([{"Key": "team", "Value": "sdk"}]));
    assert_eq!(
        body["AddReplicaRegions"],
        json!([{"Region": "eu-west-1", "KmsKeyId": "k"}])
    );
    assert_eq!(
        body["ClientRequestToken"],
        "11111111-1111-4111-8111-11110badc0de"
    );

    let out = c
        .create_secret(
            BLOB,
            Some(SecretData::Bytes(vec![0, 1, 2, 0xfe, 0xff])),
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(out.name, BLOB);
    let body = &bodies_of(&server, "CreateSecret").await[1];
    assert_eq!(body["SecretBinary"], "AAEC/v8=");
    assert!(body.get("SecretString").is_none());

    let out = c
        .create_secret("sdkv-0badc0de/empty", None, Default::default())
        .await
        .unwrap();
    assert!(out.version_id.is_none());

    c.create_secret(
        "json",
        Some(SecretData::Json(json!({"a": 1}))),
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        bodies_of(&server, "CreateSecret").await[3]["SecretString"],
        "{\"a\":1}"
    );

    let err = c
        .create_secret("exists", Some("x".into()), Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    assert_eq!(aws_error_code(&err), Some("ResourceExistsException"));
    let err = c
        .create_secret("denied", Some("x".into()), Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert_eq!(err.http_status(), Some(403));
    assert!(c.create_secret("", None, Default::default()).await.is_err());
}

#[tokio::test]
async fn put_update_stage_delete_restore() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "putSecretValue.not-found",
        Some(json!({"SecretId": "missing"})),
    )
    .await;
    mount_matching(
        &server,
        "putSecretValue.custom-stage",
        Some(json!({"VersionStages": ["STAGEX"]})),
    )
    .await;
    mount(&server, "putSecretValue.ok").await;
    mount_matching(
        &server,
        "updateSecret.value",
        Some(json!({"SecretString": "v3-0badc0de"})),
    )
    .await;
    mount(&server, "updateSecret.description").await;
    mount_matching(
        &server,
        "updateSecretVersionStage.missing-remove",
        Some(json!({"SecretId": "bad"})),
    )
    .await;
    mount(&server, "updateSecretVersionStage.move").await;
    mount_matching(
        &server,
        "deleteSecret.already-deleted",
        Some(json!({"SecretId": "again"})),
    )
    .await;
    mount_matching(
        &server,
        "deleteSecret.force",
        Some(json!({"ForceDeleteWithoutRecovery": true})),
    )
    .await;
    mount(&server, "deleteSecret.recovery-window").await;
    mount_matching(
        &server,
        "restoreSecret.not-found",
        Some(json!({"SecretId": "missing"})),
    )
    .await;
    mount(&server, "restoreSecret.ok").await;
    let c = client(&server);

    let out = c
        .put_secret_value(DB, "v2-0badc0de", Default::default())
        .await
        .unwrap();
    assert_eq!(out.version_stages, [AWSCURRENT]);
    assert!(!out.version_id.is_empty());
    let out = c
        .put_secret_value(
            DB,
            "staged",
            PutSecretValueOptions {
                version_stages: vec!["STAGEX".into()],
                client_request_token: Some("t".repeat(32)),
            },
        )
        .await
        .unwrap();
    assert_eq!(out.version_stages, ["STAGEX"]);
    c.put_secret_value(DB, vec![1u8, 2], Default::default())
        .await
        .unwrap();
    assert_eq!(
        bodies_of(&server, "PutSecretValue").await[2]["SecretBinary"],
        "AQI="
    );
    assert_eq!(
        c.put_secret_value("missing", "x", Default::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );

    let out = c
        .update_secret(
            DB,
            UpdateSecretOptions {
                value: Some("v3-0badc0de".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(out.version_id.is_some());
    let out = c
        .update_secret(
            DB,
            UpdateSecretOptions {
                description: Some("d".into()),
                kms_key_id: Some("k".into()),
                client_request_token: Some("t".repeat(32)),
                value: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(out.name, DB);

    let r = c
        .update_secret_version_stage(
            DB,
            "STAGEX",
            UpdateSecretVersionStageOptions {
                move_to_version_id: Some("v".into()),
                remove_from_version_id: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(r.name, DB);
    let err = c
        .update_secret_version_stage(DB, "STAGEX", Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    let err = c
        .update_secret_version_stage(
            "bad",
            AWSCURRENT,
            UpdateSecretVersionStageOptions {
                move_to_version_id: Some("v".into()),
                remove_from_version_id: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);

    let d = c
        .delete_secret(
            BLOB,
            DeleteSecretOptions {
                recovery_window_days: Some(7),
                force_delete_without_recovery: None,
            },
        )
        .await
        .unwrap();
    assert!(d.deletion_date.is_some());
    let d = c
        .delete_secret(
            BLOB,
            DeleteSecretOptions {
                recovery_window_days: None,
                force_delete_without_recovery: Some(true),
            },
        )
        .await
        .unwrap();
    assert_eq!(d.name, BLOB);
    let err = c
        .delete_secret("again", Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    let both = DeleteSecretOptions {
        recovery_window_days: Some(7),
        force_delete_without_recovery: Some(true),
    };
    assert_eq!(
        c.delete_secret(BLOB, both).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    let bad = DeleteSecretOptions {
        recovery_window_days: Some(3),
        force_delete_without_recovery: None,
    };
    assert_eq!(
        c.delete_secret(BLOB, bad).await.unwrap_err().code(),
        ErrorCode::Validation
    );
    assert_eq!(
        bodies_of(&server, "DeleteSecret").await.len(),
        3,
        "client-side checks send nothing"
    );

    assert_eq!(c.restore_secret(BLOB).await.unwrap().name, BLOB);
    assert_eq!(
        c.restore_secret("missing").await.unwrap_err().code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn tags_and_policies() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "tagResource.not-found",
        Some(json!({"SecretId": "missing"})),
    )
    .await;
    mount(&server, "tagResource.ok").await;
    mount_matching(
        &server,
        "untagResource.not-found",
        Some(json!({"SecretId": "missing"})),
    )
    .await;
    mount(&server, "untagResource.ok").await;
    mount_matching(
        &server,
        "putResourcePolicy.not-found",
        Some(json!({"SecretId": "missing"})),
    )
    .await;
    mount(&server, "putResourcePolicy.ok").await;
    mount_matching(
        &server,
        "getResourcePolicy.none",
        Some(json!({"SecretId": "none"})),
    )
    .await;
    mount(&server, "getResourcePolicy.ok").await;
    mount(&server, "deleteResourcePolicy.ok").await;
    mount(&server, "validateResourcePolicy.moto-unsupported").await;
    let c = client(&server);

    c.tag_resource(DB, [("team", "sdk"), ("env", "test")])
        .await
        .unwrap();
    assert_eq!(
        bodies_of(&server, "TagResource").await[0]["Tags"],
        json!([{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "sdk"}])
    );
    assert_eq!(
        c.tag_resource("missing", [("a", "b")])
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    c.untag_resource(DB, ["env"]).await.unwrap();
    assert_eq!(
        bodies_of(&server, "UntagResource").await[0]["TagKeys"],
        json!(["env"])
    );
    assert_eq!(
        c.untag_resource("missing", ["a"]).await.unwrap_err().code(),
        ErrorCode::NotFound
    );

    let policy = json!({"Version": "2012-10-17", "Statement": []});
    let r = c
        .put_resource_policy(
            DB,
            policy.clone(),
            PutResourcePolicyOptions {
                block_public_policy: Some(true),
            },
        )
        .await
        .unwrap();
    assert_eq!(r.name, DB);
    let body = &bodies_of(&server, "PutResourcePolicy").await[0];
    assert_eq!(body["ResourcePolicy"], policy.to_string());
    assert_eq!(body["BlockPublicPolicy"], true);
    assert_eq!(
        c.put_resource_policy("missing", "{}", Default::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );

    let p = c.get_resource_policy(DB).await.unwrap();
    assert!(p.resource_policy.as_deref().unwrap().contains("2012-10-17"));
    assert_eq!(p.policy.as_ref().unwrap()["Version"], "2012-10-17");
    let none = c.get_resource_policy("none").await.unwrap();
    assert!(none.resource_policy.is_none() && none.policy.is_none());
    assert_eq!(c.delete_resource_policy(DB).await.unwrap().name, DB);

    let err = c
        .validate_resource_policy(
            "{}",
            ValidateResourcePolicyOptions {
                secret_id: Some(DB.into()),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert_eq!(err.http_status(), Some(500));

    // the AWS answer
    let server = MockServer::start().await;
    mount_op(
        &server,
        "ValidateResourcePolicy",
        aws_json(200, json!({"PolicyValidationPassed": false, "ValidationErrors": [{"CheckName": "c", "ErrorMessage": "m"}]})),
    )
    .await;
    let r = client(&server)
        .validate_resource_policy(policy, Default::default())
        .await
        .unwrap();
    assert!(!r.policy_validation_passed);
    assert_eq!(r.validation_errors[0].check_name.as_deref(), Some("c"));
    assert_eq!(r.validation_errors[0].error_message.as_deref(), Some("m"));
}

#[tokio::test]
async fn rotation_and_random_password() {
    let server = MockServer::start().await;
    mount_matching(
        &server,
        "rotateSecret.lambda-not-found",
        Some(
            json!({"RotationLambdaARN": "arn:aws:lambda:us-east-1:123456789012:function:missing"}),
        ),
    )
    .await;
    mount(&server, "rotateSecret.rules-only").await;
    mount_matching(
        &server,
        "cancelRotateSecret.not-found",
        Some(json!({"SecretId": "missing"})),
    )
    .await;
    mount(&server, "cancelRotateSecret.ok").await;
    mount_matching(
        &server,
        "getRandomPassword.too-short",
        Some(json!({"PasswordLength": 2})),
    )
    .await;
    mount(&server, "getRandomPassword.ok").await;
    let c = client(&server);

    let r = c
        .rotate_secret(
            DB,
            RotateSecretOptions {
                rules: Some(RotationRules {
                    automatically_after_days: Some(30),
                    duration: Some("2h".into()),
                    schedule_expression: None,
                }),
                rotate_immediately: Some(true),
                client_request_token: Some("t".repeat(32)),
                lambda_arn: None,
            },
        )
        .await
        .unwrap();
    assert!(r.version_id.is_some());
    let body = &bodies_of(&server, "RotateSecret").await[0];
    assert_eq!(
        body["RotationRules"],
        json!({"AutomaticallyAfterDays": 30, "Duration": "2h"})
    );
    let err = c
        .rotate_secret(
            DB,
            RotateSecretOptions {
                lambda_arn: Some("arn:aws:lambda:us-east-1:123456789012:function:missing".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(c.cancel_rotate_secret(DB).await.unwrap().name, DB);
    assert_eq!(
        c.cancel_rotate_secret("missing").await.unwrap_err().code(),
        ErrorCode::NotFound
    );

    let pw = c
        .get_random_password(RandomPasswordOptions {
            length: Some(24),
            exclude_punctuation: Some(true),
            require_each_included_type: Some(true),
            exclude_characters: Some("O0".into()),
            exclude_numbers: Some(false),
            exclude_uppercase: Some(false),
            exclude_lowercase: Some(false),
            include_space: Some(false),
        })
        .await
        .unwrap();
    assert_eq!(pw.expose_secret().len(), 24);
    assert_eq!(format!("{pw:?}"), "[REDACTED]");
    let err = c
        .get_random_password(RandomPasswordOptions {
            length: Some(2),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Validation);
    c.get_random_password(Default::default()).await.unwrap();
    assert_eq!(
        bodies_of(&server, "GetRandomPassword").await[2]["PasswordLength"],
        32
    );
}
