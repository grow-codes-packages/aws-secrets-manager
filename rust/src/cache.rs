//! A version-stage aware secret cache with the semantics of the AWS caching clients
//! (`aws-secretsmanager-caching-*`, DECISIONS.md #3): entries per `(secret_id, version_stage)`,
//! default TTL 1 h and 1 024 entries; on expiry `DescribeSecret` checks whether the stage moved
//! to another version and `GetSecretValue` runs only when it did.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::client::AwsSecretsManagerClient;
use crate::core::clock::{Clock, SystemClock};
use crate::core::{Error, Result};
use crate::models::{AwsSecretValue, GetSecretValueOptions, AWSCURRENT};
use crate::secrets::SecretCacheOptions;

/// TTL of the AWS caching clients (1 h).
pub const AWS_SECRET_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Capacity of the AWS caching clients (1 024 entries).
pub const AWS_SECRET_CACHE_MAX_ENTRIES: usize = 1024;

/// Initial delay before retrying a failed refresh (doubles per failure, capped at the TTL).
const REFRESH_RETRY: Duration = Duration::from_secs(1);

/// The client operations the cache needs ([`AwsSecretsManagerClient`] implements it; tests can
/// pass a fake).
#[async_trait]
pub trait SecretCacheSource: Send + Sync {
    /// `GetSecretValue` of `secret_id` at `version_stage`.
    async fn fetch_value(&self, secret_id: &str, version_stage: &str) -> Result<AwsSecretValue>;
    /// `DescribeSecret` of `secret_id`: version id → stage labels.
    async fn fetch_version_stages(
        &self,
        secret_id: &str,
    ) -> Result<std::collections::BTreeMap<String, Vec<String>>>;
}

#[async_trait]
impl SecretCacheSource for AwsSecretsManagerClient {
    async fn fetch_value(&self, secret_id: &str, version_stage: &str) -> Result<AwsSecretValue> {
        self.get_secret_value(
            secret_id,
            GetSecretValueOptions::version_stage(version_stage),
        )
        .await
    }

    async fn fetch_version_stages(
        &self,
        secret_id: &str,
    ) -> Result<std::collections::BTreeMap<String, Vec<String>>> {
        Ok(self.describe_secret(secret_id).await?.version_ids_to_stages)
    }
}

/// Callback for refresh failures.
pub type OnRefreshError = Arc<dyn Fn(&Error) + Send + Sync>;

/// Options of [`AwsSecretCache`].
#[derive(Clone)]
pub struct AwsSecretCacheOptions {
    /// Refresh interval (default 1 h).
    pub ttl: Duration,
    /// LRU capacity (default 1 024).
    pub max_entries: usize,
    /// Default stage label (default `AWSCURRENT`).
    pub version_stage: String,
    /// Time source.
    pub clock: Arc<dyn Clock>,
    /// Called when a refresh fails and the cached value is served instead.
    pub on_refresh_error: Option<OnRefreshError>,
}

impl Default for AwsSecretCacheOptions {
    fn default() -> Self {
        AwsSecretCacheOptions {
            ttl: AWS_SECRET_CACHE_TTL,
            max_entries: AWS_SECRET_CACHE_MAX_ENTRIES,
            version_stage: AWSCURRENT.to_owned(),
            clock: Arc::new(SystemClock),
            on_refresh_error: None,
        }
    }
}

impl fmt::Debug for AwsSecretCacheOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSecretCacheOptions")
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .field("version_stage", &self.version_stage)
            .finish_non_exhaustive()
    }
}

/// Counters reported by [`AwsSecretCache::stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AwsSecretCacheStats {
    /// Reads served from a cached entry (including those that triggered a refresh check).
    pub hits: u64,
    /// Reads without a cached entry.
    pub misses: u64,
    /// Expired entries checked with `DescribeSecret`.
    pub refreshes: u64,
    /// Refreshes that fetched a new version.
    pub version_changes: u64,
    /// Entries evicted because the cache was full.
    pub evictions: u64,
    /// Current number of entries.
    pub size: usize,
}

type Key = (String, String);

struct Entry {
    value: AwsSecretValue,
    checked_at: Option<Instant>,
    failures: u32,
    used: u64,
}

#[derive(Default)]
struct State {
    entries: HashMap<Key, Entry>,
    tick: u64,
    stats: AwsSecretCacheStats,
}

/// Version-stage aware cache in front of an [`AwsSecretsManagerClient`]
/// (`client.secret_cache(opts)`). Reads are coalesced per `(secret_id, stage)`. A refresh that
/// fails keeps serving the cached value and retries with exponential backoff (AWS caching-client
/// behaviour); a first read that fails returns the error.
pub struct AwsSecretCache<S: ?Sized = AwsSecretsManagerClient> {
    source: Arc<S>,
    opts: AwsSecretCacheOptions,
    state: Mutex<State>,
    flights: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>>,
}

impl<S: ?Sized> fmt::Debug for AwsSecretCache<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSecretCache")
            .field("opts", &self.opts)
            .field("stats", &self.stats())
            .finish()
    }
}

impl AwsSecretCache {
    /// The AWS caching-client defaults (TTL 1 h, 1 024 entries) as options of the generic
    /// [`SecretCache`](crate::secrets::SecretCache).
    pub fn aws_defaults() -> SecretCacheOptions {
        SecretCacheOptions {
            ttl: AWS_SECRET_CACHE_TTL,
            max_entries: AWS_SECRET_CACHE_MAX_ENTRIES,
            ..SecretCacheOptions::default()
        }
    }
}

impl<S: SecretCacheSource + ?Sized> AwsSecretCache<S> {
    /// A cache over `source`; `VALIDATION` when the TTL is zero, `max_entries` is 0 or the stage
    /// is blank.
    pub fn new(source: Arc<S>, opts: AwsSecretCacheOptions) -> Result<Self> {
        if opts.ttl.is_zero() {
            return Err(Error::validation("AwsSecretCache: ttl must be > 0"));
        }
        if opts.max_entries < 1 {
            return Err(Error::validation("AwsSecretCache: maxEntries must be >= 1"));
        }
        if opts.version_stage.trim().is_empty() {
            return Err(Error::validation(
                "AwsSecretCache: versionStage must not be empty",
            ));
        }
        Ok(AwsSecretCache {
            source,
            opts,
            state: Mutex::new(State::default()),
            flights: Mutex::new(HashMap::new()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn key(&self, secret_id: &str, stage: Option<&str>) -> Key {
        (
            secret_id.to_owned(),
            stage.unwrap_or(&self.opts.version_stage).to_owned(),
        )
    }

    fn next_check_after(&self, failures: u32) -> Duration {
        if failures == 0 {
            return self.opts.ttl;
        }
        let factor = 1u32.checked_shl(failures - 1).unwrap_or(u32::MAX);
        REFRESH_RETRY.saturating_mul(factor).min(self.opts.ttl)
    }

    /// `Some(value)` when the entry exists and is fresh.
    fn fresh(&self, key: &Key) -> Option<AwsSecretValue> {
        let now = self.opts.clock.now();
        let st = self.lock();
        let e = st.entries.get(key)?;
        let checked = e.checked_at?;
        (now.saturating_duration_since(checked) < self.next_check_after(e.failures))
            .then(|| e.value.clone())
    }

    fn store(&self, key: Key, value: AwsSecretValue) {
        let now = self.opts.clock.now();
        let mut st = self.lock();
        st.tick += 1;
        let used = st.tick;
        st.entries.insert(
            key,
            Entry {
                value,
                checked_at: Some(now),
                failures: 0,
                used,
            },
        );
        while st.entries.len() > self.opts.max_entries {
            let oldest = st
                .entries
                .iter()
                .min_by_key(|(_, e)| e.used)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                st.entries.remove(&k);
                st.stats.evictions += 1;
            }
        }
    }

    fn flight(&self, key: &Key) -> Arc<tokio::sync::Mutex<()>> {
        let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(flights.entry(key.clone()).or_default())
    }

    fn end_flight(&self, key: &Key, flight: Arc<tokio::sync::Mutex<()>>) {
        let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
        // The map and this function hold a reference each: nobody else waits.
        if Arc::strong_count(&flight) <= 2 {
            flights.remove(key);
        }
    }

    /// The cached value of `secret_id` at `version_stage` (default: the cache's stage).
    pub async fn get_secret_value(
        &self,
        secret_id: &str,
        version_stage: Option<&str>,
    ) -> Result<AwsSecretValue> {
        let key = self.key(secret_id, version_stage);
        {
            let mut st = self.lock();
            st.tick += 1;
            let tick = st.tick;
            match st.entries.get_mut(&key) {
                Some(e) => {
                    e.used = tick;
                    st.stats.hits += 1;
                }
                None => st.stats.misses += 1,
            }
        }
        if let Some(v) = self.fresh(&key) {
            return Ok(v);
        }
        let flight = self.flight(&key);
        let result = {
            let _guard = flight.lock().await;
            self.load(&key).await
        };
        self.end_flight(&key, flight);
        result
    }

    async fn load(&self, key: &Key) -> Result<AwsSecretValue> {
        // Another task may have loaded the entry while this one waited.
        if let Some(v) = self.fresh(key) {
            return Ok(v);
        }
        let cached = self.lock().entries.get(key).map(|e| e.value.clone());
        let Some(cached) = cached else {
            let value = self.source.fetch_value(&key.0, &key.1).await?;
            self.store(key.clone(), value.clone());
            return Ok(value);
        };
        self.lock().stats.refreshes += 1;
        let refreshed = async {
            let stages = self.source.fetch_version_stages(&key.0).await?;
            let current = stages
                .iter()
                .find(|(_, s)| s.contains(&key.1))
                .map(|(id, _)| id.as_str());
            if current.is_some() && current == cached.version_id.as_deref() {
                return Ok(cached.clone());
            }
            let value = self.source.fetch_value(&key.0, &key.1).await?;
            self.lock().stats.version_changes += 1;
            Ok::<_, Error>(value)
        }
        .await;
        match refreshed {
            Ok(value) => {
                self.store(key.clone(), value.clone());
                Ok(value)
            }
            Err(err) => {
                let now = self.opts.clock.now();
                if let Some(e) = self.lock().entries.get_mut(key) {
                    e.failures += 1;
                    e.checked_at = Some(now);
                }
                if let Some(cb) = &self.opts.on_refresh_error {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cb(&err)));
                }
                Ok(cached)
            }
        }
    }

    /// The value as text (`SecretString`, or UTF-8 of the binary; `VALIDATION` otherwise).
    pub async fn get_secret_string(
        &self,
        secret_id: &str,
        version_stage: Option<&str>,
    ) -> Result<String> {
        let v = self.get_secret_value(secret_id, version_stage).await?;
        v.value.reveal().map(str::to_owned)
    }

    /// The value as bytes.
    pub async fn get_secret_binary(
        &self,
        secret_id: &str,
        version_stage: Option<&str>,
    ) -> Result<Vec<u8>> {
        let v = self.get_secret_value(secret_id, version_stage).await?;
        Ok(v.value.reveal_bytes().to_vec())
    }

    /// Forces a refresh check now (and a fetch when the stage moved); returns the value.
    pub async fn refresh_now(
        &self,
        secret_id: &str,
        version_stage: Option<&str>,
    ) -> Result<AwsSecretValue> {
        let key = self.key(secret_id, version_stage);
        if let Some(e) = self.lock().entries.get_mut(&key) {
            e.checked_at = None;
            e.failures = 0;
        }
        self.get_secret_value(secret_id, version_stage).await
    }

    /// Drops every cached stage of `secret_id`.
    pub fn invalidate(&self, secret_id: &str) {
        self.lock().entries.retain(|k, _| k.0 != secret_id);
    }

    /// Drops every entry.
    pub fn clear(&self) {
        self.lock().entries.clear();
    }
}

impl<S: ?Sized> AwsSecretCache<S> {
    /// Counters and current size.
    pub fn stats(&self) -> AwsSecretCacheStats {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        AwsSecretCacheStats {
            size: st.entries.len(),
            ..st.stats
        }
    }
}
