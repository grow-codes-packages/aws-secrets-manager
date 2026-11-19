//! Every public function against the real service (Moto in Docker), each with a round trip.
//!
//! Emulator notes (docs/compatibility.md): `validate_resource_policy` is not implemented by
//! Moto (answers UNSUPPORTED); `GetSecretValue` without a stage is stale after an AWSCURRENT
//! move, so reads after moves name the stage explicitly.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use grow_aws_secrets_manager as sdk;
use grow_aws_secrets_manager_integration::load_bootstrap_env;
use sdk::models::*;
use sdk::secrets::{
    DeleteOptions, GetOptions, LoadEnvOptions, SecretData, SecretsProvider, SetOptions,
    WatchOptions,
};
use sdk::{
    AwsSecretCacheOptions, AwsSecretsManagerClient as Client, AwsSecretsManagerConfig as Config,
    ErrorCode,
};
use serde_json::json;

fn client() -> Client {
    load_bootstrap_env();
    Client::from_env().expect("client from env")
}

fn run_prefix() -> String {
    format!("grow-it-rust/{}", sdk::testing::run_id())
}

fn force() -> DeleteSecretOptions {
    DeleteSecretOptions {
        force_delete_without_recovery: Some(true),
        ..Default::default()
    }
}

fn current() -> GetSecretValueOptions {
    GetSecretValueOptions::version_stage(AWSCURRENT)
}

#[tokio::test]
async fn read_write_round_trips() {
    let c = client();
    let p = run_prefix();
    let db = format!("{p}/app/db");
    let blob = format!("{p}/app/blob");
    let empty = format!("{p}/empty");

    // create (text, binary, no value) → read back
    let created = c
        .create_secret(
            &db,
            Some("v1".into()),
            CreateSecretOptions {
                description: Some("grow it".into()),
                kms_key_id: Some("alias/aws/secretsmanager".into()),
                tags: BTreeMap::from([("team".into(), "sdk".into())]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let v1 = created.version_id.clone().unwrap();
    let got = c.get_secret_value(&db, Default::default()).await.unwrap();
    assert_eq!(got.value.reveal().unwrap(), "v1");
    assert_eq!(got.version_id.as_deref(), Some(v1.as_str()));
    let d = c.describe_secret(&db).await.unwrap();
    assert_eq!(d.description.as_deref(), Some("grow it"));
    assert_eq!(d.tags["team"], "sdk");
    assert_eq!(d.current_version_id(), Some(v1.as_str()));

    c.create_secret(
        &blob,
        Some(SecretData::Bytes(vec![0, 1, 2, 0xfe, 0xff])),
        Default::default(),
    )
    .await
    .unwrap();
    let b = c.get_secret_value(&blob, Default::default()).await.unwrap();
    assert!(b.binary);
    assert_eq!(b.value.reveal_bytes(), &[0, 1, 2, 0xfe, 0xff]);

    let e = c
        .create_secret(&empty, None, Default::default())
        .await
        .unwrap();
    assert!(e.version_id.is_none());
    assert_eq!(
        c.get_secret_value(&empty, Default::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        c.create_secret(&db, Some("x".into()), Default::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Conflict
    );

    // put → AWSCURRENT moves, old becomes AWSPREVIOUS
    let put = c
        .put_secret_value(&db, "v2", Default::default())
        .await
        .unwrap();
    assert_eq!(put.version_stages, [AWSCURRENT]);
    assert_eq!(
        c.get_secret_value(&db, current())
            .await
            .unwrap()
            .value
            .reveal()
            .unwrap(),
        "v2"
    );
    let prev = c
        .get_secret_value(&db, GetSecretValueOptions::version_stage(AWSPREVIOUS))
        .await
        .unwrap();
    assert_eq!(prev.value.reveal().unwrap(), "v1");
    // custom stage only
    let staged = c
        .put_secret_value(
            &db,
            "staged",
            PutSecretValueOptions {
                version_stages: vec!["STAGEX".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let sx = c
        .get_secret_value(&db, GetSecretValueOptions::version_stage("STAGEX"))
        .await
        .unwrap();
    assert_eq!(sx.version_id.as_deref(), Some(staged.version_id.as_str()));
    assert_eq!(
        c.get_secret_value(&db, current())
            .await
            .unwrap()
            .value
            .reveal()
            .unwrap(),
        "v2"
    );

    // update value + description
    let upd = c
        .update_secret(
            &db,
            UpdateSecretOptions {
                value: Some("v3".into()),
                description: Some("updated".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let v3 = upd.version_id.clone().unwrap();
    assert_eq!(
        c.get_secret_value(&db, current())
            .await
            .unwrap()
            .value
            .reveal()
            .unwrap(),
        "v3"
    );
    assert_eq!(
        c.describe_secret(&db).await.unwrap().description.as_deref(),
        Some("updated")
    );

    // move AWSCURRENT back to v1
    c.update_secret_version_stage(
        &db,
        AWSCURRENT,
        UpdateSecretVersionStageOptions {
            move_to_version_id: Some(v1.clone()),
            remove_from_version_id: Some(v3.clone()),
        },
    )
    .await
    .unwrap();
    let now = c.get_secret_value(&db, current()).await.unwrap();
    assert_eq!(now.version_id.as_deref(), Some(v1.as_str()));
    assert_eq!(now.value.reveal().unwrap(), "v1");
    let by_id = c
        .get_secret_value(&db, GetSecretValueOptions::version_id(v3.clone()))
        .await
        .unwrap();
    assert_eq!(by_id.value.reveal().unwrap(), "v3");

    // versions
    let versions = c
        .list_secret_version_ids(
            &db,
            ListSecretVersionIdsOptions {
                include_deprecated: Some(true),
                ..Default::default()
            },
        )
        .try_collect()
        .await
        .unwrap();
    for id in [&v1, &v3, &staged.version_id] {
        assert!(versions.iter().any(|v| &v.version_id == id), "{id} listed");
    }

    // batch get by ids (one missing) and by filters
    let missing = format!("{p}/missing");
    let r = c
        .batch_get_secret_value(
            vec![blob.clone(), missing.clone(), db.clone()],
            Default::default(),
        )
        .await
        .unwrap();
    let names: Vec<&str> = r.secret_values.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, [blob.as_str(), db.as_str()]);
    assert_eq!(r.errors.len(), 1);
    assert_eq!(r.errors[0].secret_id.as_deref(), Some(missing.as_str()));
    let r = c
        .batch_get_secret_value(
            vec![SecretFilter::name(format!("{p}/app/"))],
            BatchGetOptions {
                max_results: Some(1),
            },
        )
        .await
        .unwrap();
    assert_eq!(r.secret_values.len(), 2);

    // list with a name filter, item by item
    let mut listed = c.list_secrets(ListSecretsOptions {
        filters: vec![SecretFilter::name(format!("{p}/"))],
        max_results: Some(1),
        ..Default::default()
    });
    let mut names = Vec::new();
    while let Some(d) = listed.next().await.unwrap() {
        names.push(d.name);
    }
    names.sort();
    assert_eq!(names, [blob.clone(), db.clone(), empty.clone()]);

    // json field helper on the bootstrap seed
    let seed = std::env::var("GROW_TEST_SEED_JSON_SECRET").unwrap();
    assert_eq!(
        c.get_json_field(&seed, "username", Default::default())
            .await
            .unwrap(),
        Some(json!("seed-user"))
    );
    assert_eq!(
        c.get_json_field(&seed, "port", Default::default())
            .await
            .unwrap(),
        Some(json!(5432))
    );
    assert_eq!(
        c.get_json_field(&seed, "nope", Default::default())
            .await
            .unwrap(),
        None
    );
    let seed_bin = std::env::var("GROW_TEST_SEED_BINARY_SECRET").unwrap();
    assert_eq!(
        c.get_json_field(&seed_bin, "x", Default::default())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Validation
    );
    let seed_arn = std::env::var("GROW_TEST_SEED_BINARY_SECRET_ARN").unwrap();
    assert_eq!(
        c.get_secret_value(&seed_arn, Default::default())
            .await
            .unwrap()
            .value
            .reveal_bytes(),
        &[0, 1, 2, 0xfe, 0xff]
    );

    // delete with a window → pending (CONFLICT), restore, then purge
    let deleted = c
        .delete_secret(
            &blob,
            DeleteSecretOptions {
                recovery_window_days: Some(7),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(deleted.deletion_date.is_some());
    let err = c
        .get_secret_value(&blob, Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Conflict);
    assert!(sdk::is_missing(&err));
    assert!(c.describe_secret(&blob).await.unwrap().pending_deletion());
    c.restore_secret(&blob).await.unwrap();
    assert!(c.get_secret_value(&blob, Default::default()).await.is_ok());
    for id in [&db, &blob, &empty] {
        c.delete_secret(id, force()).await.unwrap();
    }
    assert_eq!(
        c.describe_secret(&db).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    c.close().await;
}

#[tokio::test]
async fn tags_policy_rotation_and_utilities() {
    let c = client();
    let id = format!("{}/ops", run_prefix());
    c.create_secret(&id, Some("v".into()), Default::default())
        .await
        .unwrap();

    c.tag_resource(&id, [("team", "sdk"), ("env", "it")])
        .await
        .unwrap();
    let tags = c.describe_secret(&id).await.unwrap().tags;
    assert_eq!((tags["team"].as_str(), tags["env"].as_str()), ("sdk", "it"));
    c.untag_resource(&id, ["env"]).await.unwrap();
    let tags = c.describe_secret(&id).await.unwrap().tags;
    assert!(!tags.contains_key("env") && tags.contains_key("team"));

    let account = std::env::var("GROW_TEST_ACCOUNT_ID").unwrap_or_else(|_| "123456789012".into());
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": format!("arn:aws:iam::{account}:root")},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*"
        }]
    });
    c.put_resource_policy(&id, policy.clone(), Default::default())
        .await
        .unwrap();
    let got = c.get_resource_policy(&id).await.unwrap();
    assert_eq!(got.policy.as_ref(), Some(&policy));
    c.delete_resource_policy(&id).await.unwrap();
    assert!(c
        .get_resource_policy(&id)
        .await
        .unwrap()
        .resource_policy
        .is_none());
    match c.validate_resource_policy(policy, Default::default()).await {
        Ok(r) => assert!(r.policy_validation_passed),
        Err(e) => assert_eq!(e.code(), ErrorCode::Unsupported, "{e}"),
    }

    let rotated = c
        .rotate_secret(
            &id,
            RotateSecretOptions {
                rules: Some(RotationRules {
                    automatically_after_days: Some(30),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(rotated.version_id.is_some());
    let d = c.describe_secret(&id).await.unwrap();
    assert!(d.rotation_enabled);
    assert_eq!(d.rotation_rules.unwrap().automatically_after_days, Some(30));
    // No Lambda runtime in the emulator: NOT_FOUND, but Moto records the ARN, which
    // CancelRotateSecret needs.
    let err = c
        .rotate_secret(
            &id,
            RotateSecretOptions {
                lambda_arn: Some(format!(
                    "arn:aws:lambda:us-east-1:{account}:function:grow-rotate"
                )),
                rules: Some(RotationRules {
                    schedule_expression: Some("rate(10 days)".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
    c.cancel_rotate_secret(&id).await.unwrap();
    assert_eq!(
        c.cancel_rotate_secret(&format!("{id}-missing"))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    assert!(!c.describe_secret(&id).await.unwrap().rotation_enabled);

    let pw = c
        .get_random_password(RandomPasswordOptions {
            length: Some(24),
            exclude_punctuation: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(pw.expose_secret().chars().count(), 24);
    assert!(pw
        .expose_secret()
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric()));
    assert_eq!(format!("{pw:?}"), "[REDACTED]");
    assert_eq!(
        c.get_random_password(RandomPasswordOptions {
            length: Some(2),
            ..Default::default()
        })
        .await
        .unwrap_err()
        .code(),
        ErrorCode::Validation
    );

    c.delete_secret(&id, force()).await.unwrap();
    c.close().await;
}

#[tokio::test]
async fn auth_permission_cache_and_sdk_escape_hatch() {
    let c = client();
    let id = format!("{}/cached", run_prefix());
    c.create_secret(&id, Some("one".into()), Default::default())
        .await
        .unwrap();

    // read-only principal: reads work, writes are PERMISSION_DENIED
    let ro = Client::new(
        Config::builder()
            .access_key_id(std::env::var("GROW_TEST_READONLY_ACCESS_KEY_ID").unwrap())
            .secret_access_key(std::env::var("GROW_TEST_READONLY_SECRET_ACCESS_KEY").unwrap())
            .build_from_env()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        ro.get_secret_value(&id, Default::default())
            .await
            .unwrap()
            .value
            .reveal()
            .unwrap(),
        "one"
    );
    let err = ro
        .create_secret(&format!("{id}-ro"), Some("x".into()), Default::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied, "{err}");

    // unknown key → AUTHENTICATION; health still reports the service as up
    let bad = Client::new(
        Config::builder()
            .access_key_id("AKIDDOESNOTEXIST")
            .secret_access_key("wrong-secret-key-value")
            .build_from_env()
            .unwrap(),
    )
    .unwrap();
    let err = bad.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication, "{err}");
    assert!(!err.message().contains("wrong-secret-key-value"));
    let h = bad.health().await.unwrap();
    assert!(h.healthy);
    assert_eq!(h.details["auth"], "failed");

    // AWS caching semantics: a stage move is seen after refresh_now
    let cache = c.secret_cache(AwsSecretCacheOptions::default()).unwrap();
    assert_eq!(cache.get_secret_string(&id, None).await.unwrap(), "one");
    c.put_secret_value(&id, "two", Default::default())
        .await
        .unwrap();
    assert_eq!(
        cache.get_secret_string(&id, None).await.unwrap(),
        "one",
        "cached"
    );
    assert_eq!(
        cache
            .refresh_now(&id, None)
            .await
            .unwrap()
            .value
            .reveal()
            .unwrap(),
        "two"
    );
    assert_eq!(cache.get_secret_binary(&id, None).await.unwrap(), b"two");
    assert_eq!(cache.stats().version_changes, 1);

    // the SDK escape hatch, and wrapping an existing SDK client
    let raw = c.sdk().await.unwrap();
    let out = raw.describe_secret().secret_id(&id).send().await.unwrap();
    assert_eq!(out.name(), Some(id.as_str()));
    let wrapped = Client::with_sdk_client(raw.clone()).unwrap();
    wrapped.ping().await.unwrap();
    wrapped.close().await;
    raw.describe_secret().secret_id(&id).send().await.unwrap();

    c.delete_secret(&id, force()).await.unwrap();
    c.close().await;
}

#[tokio::test]
async fn provider_round_trips_and_watch() {
    let c = client();
    let p = c.secrets();
    let base = run_prefix();
    let tags = BTreeMap::from([("owner".to_owned(), "it".to_owned())]);
    let opts = SetOptions {
        path: Some(base.clone()),
        tags,
        description: Some("provider".into()),
        cas: None,
    };
    let v1 = p.set("cfg", "one".into(), Some(&opts)).await.unwrap();
    let full = format!("{base}/cfg");
    let at = GetOptions {
        path: Some(base.clone()),
        version: None,
    };
    assert_eq!(
        p.get_string("cfg", Some(&at)).await.unwrap().as_deref(),
        Some("one")
    );
    let meta = p.metadata(&full, None).await.unwrap().unwrap();
    assert_eq!(meta.version.as_deref(), Some(v1.as_str()));
    assert_eq!(meta.tags["owner"], "it");
    assert_eq!(meta.extra["description"], "provider");

    // watch sees the next version
    let changes = Arc::new(AtomicU32::new(0));
    let seen = changes.clone();
    let handle = p.watch(
        full.clone(),
        Duration::from_millis(200),
        move |_new, _old| {
            seen.fetch_add(1, Ordering::SeqCst);
        },
        WatchOptions::default(),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let v2 = p
        .set(&full, SecretData::Json(json!({"a": 1})), None)
        .await
        .unwrap();
    assert_ne!(v1, v2);
    for _ in 0..50 {
        if changes.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(changes.load(Ordering::SeqCst) >= 1, "watch saw the change");
    assert_eq!(p.get_json(&full, None).await.unwrap().unwrap()["a"], 1);
    let old = GetOptions {
        version: Some(v1.clone()),
        path: None,
    };
    assert_eq!(
        p.get_string(&full, Some(&old)).await.unwrap().as_deref(),
        Some("one")
    );

    p.set(&format!("{base}/nested/deep"), vec![0xffu8, 0].into(), None)
        .await
        .unwrap();
    let all = p.get_all(Some(&base)).await.unwrap();
    assert_eq!(all.names().collect::<Vec<_>>(), [full.as_str()]);
    let listed = p.list(Some(&format!("{base}/"))).await.unwrap();
    assert_eq!(listed.len(), 2);
    let many = p
        .get_many(
            &[
                &full,
                &format!("{base}/nope"),
                &format!("{base}/nested/deep"),
            ],
            None,
        )
        .await
        .unwrap();
    assert_eq!(many.len(), 2);
    assert_eq!(
        many.get(&format!("{base}/nested/deep"))
            .unwrap()
            .reveal_bytes(),
        &[0xff, 0]
    );
    let env_prefix = format!("GROWIT_{}_", sdk::testing::run_id().to_uppercase());
    let set = p
        .load_env(
            &base.as_str().into(),
            &LoadEnvOptions {
                prefix: env_prefix.clone(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(set.len(), 1);
    assert_eq!(
        std::env::var(format!("{env_prefix}CFG")).unwrap(),
        "{\"a\":1}"
    );

    // delete with the recovery window, then the name reads as missing
    p.delete(&full, None).await.unwrap();
    assert!(p.get(&full, None).await.unwrap().is_none());
    assert!(p.metadata(&full, None).await.unwrap().is_none());
    assert_eq!(
        p.delete(&full, None).await.unwrap_err().code(),
        ErrorCode::NotFound
    );
    let permanent = DeleteOptions {
        permanent: true,
        ..Default::default()
    };
    p.delete(&format!("{base}/nested/deep"), Some(&permanent))
        .await
        .unwrap();
    c.restore_secret(&full).await.unwrap();
    c.delete_secret(&full, force()).await.unwrap();

    c.close().await;
    assert!(handle.is_stopped(), "close() stops the watch");
}
