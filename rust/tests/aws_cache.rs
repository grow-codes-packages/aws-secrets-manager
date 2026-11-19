//! `AwsSecretCache`: AWS caching-client semantics with a fake source and a manual clock.

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use grow_aws_secrets_manager as sdk;
use sdk::core::clock::ManualClock;
use sdk::models::AwsSecretValue;
use sdk::secrets::{SecretCache, SecretValue, SecretsProvider};
use sdk::{AwsSecretCache, AwsSecretCacheOptions, Error, ErrorCode, Result, SecretCacheSource};
use serde_json::json;
use support::*;
use wiremock::MockServer;

#[derive(Default)]
struct Fake {
    /// stage → (version id, value)
    stages: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
    gets: AtomicU32,
    describes: AtomicU32,
    fail_describe: Mutex<bool>,
    fail_get: Mutex<bool>,
}

impl Fake {
    fn set(&self, stage: &str, version: &str, value: &[u8]) {
        self.stages
            .lock()
            .unwrap()
            .insert(stage.into(), (version.into(), value.to_vec()));
    }
}

#[async_trait]
impl SecretCacheSource for Fake {
    async fn fetch_value(&self, secret_id: &str, stage: &str) -> Result<AwsSecretValue> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(5)).await;
        if *self.fail_get.lock().unwrap() {
            return Err(Error::unavailable("down"));
        }
        let (version, value) = self
            .stages
            .lock()
            .unwrap()
            .get(stage)
            .cloned()
            .ok_or_else(|| Error::not_found("no such stage"))?;
        Ok(AwsSecretValue {
            arn: format!("arn:{secret_id}"),
            name: secret_id.into(),
            version_id: Some(version.clone()),
            version_stages: vec![stage.into()],
            created_date: None,
            binary: false,
            value: SecretValue::new(value).with_version(version),
        })
    }

    async fn fetch_version_stages(
        &self,
        _secret_id: &str,
    ) -> Result<BTreeMap<String, Vec<String>>> {
        self.describes.fetch_add(1, Ordering::SeqCst);
        if *self.fail_describe.lock().unwrap() {
            return Err(Error::unavailable("down"));
        }
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (stage, (version, _)) in self.stages.lock().unwrap().iter() {
            out.entry(version.clone()).or_default().push(stage.clone());
        }
        Ok(out)
    }
}

fn cache(fake: &Arc<Fake>, clock: &ManualClock, max: usize) -> AwsSecretCache<Fake> {
    AwsSecretCache::new(
        fake.clone(),
        AwsSecretCacheOptions {
            max_entries: max,
            clock: Arc::new(clock.clone()),
            ..Default::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn hits_refresh_checks_and_version_changes() {
    let fake = Arc::new(Fake::default());
    fake.set("AWSCURRENT", "v1", b"one");
    let clock = ManualClock::new();
    let c = cache(&fake, &clock, 10);
    assert_eq!(c.get_secret_string("s", None).await.unwrap(), "one");
    assert_eq!(c.get_secret_binary("s", None).await.unwrap(), b"one");
    assert_eq!(fake.gets.load(Ordering::SeqCst), 1);

    // expired, same version: DescribeSecret only
    clock.advance(Duration::from_secs(3601));
    assert_eq!(c.get_secret_string("s", None).await.unwrap(), "one");
    assert_eq!(
        (
            fake.gets.load(Ordering::SeqCst),
            fake.describes.load(Ordering::SeqCst)
        ),
        (1, 1)
    );

    // expired, stage moved: fetch the new version
    fake.set("AWSCURRENT", "v2", b"two");
    clock.advance(Duration::from_secs(3601));
    assert_eq!(c.get_secret_string("s", None).await.unwrap(), "two");
    assert_eq!(fake.gets.load(Ordering::SeqCst), 2);

    // stages are cached separately
    fake.set("AWSPREVIOUS", "v1", b"one");
    assert_eq!(
        c.get_secret_string("s", Some("AWSPREVIOUS")).await.unwrap(),
        "one"
    );
    let stats = c.stats();
    assert_eq!(stats.misses, 2);
    assert_eq!(stats.hits, 3);
    assert_eq!(stats.refreshes, 2);
    assert_eq!(stats.version_changes, 1);
    assert_eq!(stats.size, 2);
    assert!(format!("{c:?}").contains("AwsSecretCache"));

    // refresh_now forces a check
    fake.set("AWSCURRENT", "v3", b"three");
    assert_eq!(
        c.refresh_now("s", None)
            .await
            .unwrap()
            .value
            .reveal()
            .unwrap(),
        "three"
    );
    assert_eq!(
        c.refresh_now("other", None)
            .await
            .unwrap()
            .value
            .reveal()
            .unwrap(),
        "three"
    );

    c.invalidate("s");
    assert_eq!(c.stats().size, 1);
    c.clear();
    assert_eq!(c.stats().size, 0);
}

#[tokio::test]
async fn refresh_failures_serve_cached_value_with_backoff() {
    let fake = Arc::new(Fake::default());
    fake.set("AWSCURRENT", "v1", b"one");
    let clock = ManualClock::new();
    let errors = Arc::new(AtomicU32::new(0));
    let seen = errors.clone();
    let c = AwsSecretCache::new(
        fake.clone(),
        AwsSecretCacheOptions {
            clock: Arc::new(clock.clone()),
            on_refresh_error: Some(Arc::new(move |_e: &Error| {
                seen.fetch_add(1, Ordering::SeqCst);
                panic!("callback panics are ignored");
            })),
            ..Default::default()
        },
    )
    .unwrap();
    c.get_secret_value("s", None).await.unwrap();
    *fake.fail_describe.lock().unwrap() = true;
    clock.advance(Duration::from_secs(3601));
    assert_eq!(c.get_secret_string("s", None).await.unwrap(), "one");
    assert_eq!(errors.load(Ordering::SeqCst), 1);
    // within the 1 s retry delay: no new check
    c.get_secret_value("s", None).await.unwrap();
    assert_eq!(fake.describes.load(Ordering::SeqCst), 1);
    clock.advance(Duration::from_millis(1100));
    c.get_secret_value("s", None).await.unwrap();
    assert_eq!(fake.describes.load(Ordering::SeqCst), 2);
    // second failure: 2 s delay
    clock.advance(Duration::from_millis(1100));
    c.get_secret_value("s", None).await.unwrap();
    assert_eq!(fake.describes.load(Ordering::SeqCst), 2);
    *fake.fail_describe.lock().unwrap() = false;
    // a moved stage whose fetch fails also serves the cached value
    fake.set("AWSCURRENT", "v2", b"two");
    *fake.fail_get.lock().unwrap() = true;
    clock.advance(Duration::from_secs(5));
    assert_eq!(c.get_secret_string("s", None).await.unwrap(), "one");
    // a first read that fails returns the error
    assert_eq!(
        c.get_secret_value("new", None).await.unwrap_err().code(),
        ErrorCode::Unavailable
    );
}

#[tokio::test]
async fn lru_eviction_and_coalescing() {
    let fake = Arc::new(Fake::default());
    fake.set("AWSCURRENT", "v1", b"one");
    let clock = ManualClock::new();
    let c = Arc::new(cache(&fake, &clock, 2));
    c.get_secret_value("a", None).await.unwrap();
    c.get_secret_value("b", None).await.unwrap();
    c.get_secret_value("a", None).await.unwrap();
    c.get_secret_value("c", None).await.unwrap();
    assert_eq!(c.stats().evictions, 1);
    assert_eq!(c.stats().size, 2);
    let before = fake.gets.load(Ordering::SeqCst);
    c.get_secret_value("a", None).await.unwrap();
    assert_eq!(
        fake.gets.load(Ordering::SeqCst),
        before,
        "a was recently used"
    );

    // concurrent first reads of one key share one fetch
    let gets = fake.gets.load(Ordering::SeqCst);
    let tasks: Vec<_> = (0..5)
        .map(|_| {
            let c = c.clone();
            tokio::spawn(async move { c.get_secret_value("z", None).await.unwrap() })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(fake.gets.load(Ordering::SeqCst), gets + 1);
}

#[tokio::test]
async fn options_validation_and_defaults() {
    let fake = Arc::new(Fake::default());
    for opts in [
        AwsSecretCacheOptions {
            ttl: Duration::ZERO,
            ..Default::default()
        },
        AwsSecretCacheOptions {
            max_entries: 0,
            ..Default::default()
        },
        AwsSecretCacheOptions {
            version_stage: " ".into(),
            ..Default::default()
        },
    ] {
        assert_eq!(
            AwsSecretCache::new(fake.clone(), opts).unwrap_err().code(),
            ErrorCode::Validation
        );
    }
    let d = AwsSecretCacheOptions::default();
    assert_eq!(d.ttl, Duration::from_secs(3600));
    assert_eq!(d.max_entries, 1024);
    assert_eq!(d.version_stage, "AWSCURRENT");
    assert!(format!("{d:?}").contains("3600"));
    let preset = AwsSecretCache::aws_defaults();
    assert_eq!(
        (preset.ttl, preset.max_entries),
        (sdk::AWS_SECRET_CACHE_TTL, sdk::AWS_SECRET_CACHE_MAX_ENTRIES)
    );
}

#[tokio::test]
async fn client_source_and_generic_cache_preset() {
    let server = MockServer::start().await;
    mount_op(
        &server,
        "GetSecretValue",
        aws_json(200, json!({"Name": "s", "ARN": "arn:s", "VersionId": "v1", "VersionStages": ["AWSCURRENT"], "SecretString": "one"})),
    )
    .await;
    mount_op(
        &server,
        "DescribeSecret",
        aws_json(
            200,
            json!({"Name": "s", "ARN": "arn:s", "VersionIdsToStages": {"v1": ["AWSCURRENT"]}}),
        ),
    )
    .await;
    let c = client(&server);
    let clock = ManualClock::new();
    let cache = c
        .secret_cache(AwsSecretCacheOptions {
            clock: Arc::new(clock.clone()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(cache.get_secret_string("s", None).await.unwrap(), "one");
    clock.advance(Duration::from_secs(3601));
    assert_eq!(cache.get_secret_string("s", None).await.unwrap(), "one");
    assert_eq!(
        bodies_of(&server, "GetSecretValue").await[0]["VersionStage"],
        "AWSCURRENT"
    );
    assert_eq!(bodies_of(&server, "DescribeSecret").await.len(), 1);
    assert_eq!(bodies_of(&server, "GetSecretValue").await.len(), 1);

    // the generic SecretCache with the AWS preset over the provider
    let generic = SecretCache::with_options(Arc::new(c.secrets()), AwsSecretCache::aws_defaults());
    assert_eq!(
        generic.get_string("s", None).await.unwrap().as_deref(),
        Some("one")
    );
    assert_eq!(
        generic.get_string("s", None).await.unwrap().as_deref(),
        Some("one")
    );
    assert_eq!(generic.stats().hits, 1);
}
