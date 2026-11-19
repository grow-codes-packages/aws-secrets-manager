# AWS secret cache

`client.secretCache()` returns an `AwsSecretCache` with the semantics of the AWS caching clients
(`aws-secretsmanager-caching-*`): one entry per **(secret id, version stage)**, TTL **1 hour**,
**1 024** entries (LRU), stage `AWSCURRENT` by default. When an entry is older than the TTL the
cache calls `DescribeSecret` and only calls `GetSecretValue` again when the stage now points at a
different version. Concurrent misses for the same key share one call; a failed refresh serves the
cached value and retries with backoff (`onRefreshError` hook).

| Function | Notes |
| - | - |
| `getSecretValue(id, {versionStage?})` | the cached `AwsSecretValue` |
| `getSecretString(id, {versionStage?})` | the text (`VALIDATION` for a binary secret) |
| `getSecretBinary(id, {versionStage?})` | the bytes (UTF-8 bytes of a text secret) |
| `refreshNow(id, {versionStage?})` | reloads now, ignoring the TTL |
| `invalidate(id)` / `clear()` | drops one secret (every stage) / everything |
| `stats()` | `{hits, misses, refreshes, versionChanges, evictions, size}` |

Options: `ttl` (TypeScript `ttlMs`, Python `ttl_s`), `maxEntries`, `versionStage`, `clock`,
`onRefreshError`.

The generic [SecretCache](../secrets.md) of the shared Secrets interface (TTL 60 s, 1 000 entries,
refresh-ahead, stale-while-revalidate) is also available over the [provider](secrets-provider.md);
`awsDefaults()` (TypeScript `AwsSecretCache.awsDefaults()` / `AWS_SECRET_CACHE_DEFAULTS`, Rust
`AwsSecretCache::aws_defaults()`, Go `AWSCacheOptions()`, Python `AwsSecretCache.aws_defaults()`,
Java `AwsSecretCache.awsDefaults()`) gives it the AWS preset (TTL 1 h, 1 024 entries).

=== "TypeScript"

    ```ts
    import { AwsSecretCache, SecretCache } from "@grow-codes/aws-secrets-manager";

    const cache = client.secretCache(); // or client.secretCache({ ttlMs: 300_000 })
    const db = JSON.parse(await cache.getSecretString("app/db"));
    const previous = await cache.getSecretValue("app/db", { versionStage: "AWSPREVIOUS" });
    await cache.refreshNow("app/db");
    console.log(cache.stats());

    const generic = new SecretCache(client.secrets(), AwsSecretCache.awsDefaults());
    ```

=== "Rust"

    ```rust
    use std::sync::Arc;
    use grow_aws_secrets_manager::secrets::SecretCache;
    use grow_aws_secrets_manager::{AwsSecretCache, AwsSecretCacheOptions};

    let cache = client.secret_cache(AwsSecretCacheOptions::default())?;
    let db = cache.get_secret_string("app/db", None).await?;
    let previous = cache.get_secret_value("app/db", Some("AWSPREVIOUS")).await?;
    cache.refresh_now("app/db", None).await?;
    println!("{:?}", cache.stats());

    let generic = SecretCache::with_options(Arc::new(client.secrets()), AwsSecretCache::aws_defaults());
    ```

=== "Go"

    ```go
    cache, err := client.SecretCache(nil) // or &asm.AWSSecretCacheOptions{TTL: 5 * time.Minute}
    db, err := cache.GetSecretString(ctx, "app/db", nil)
    previous, err := cache.GetSecretValue(ctx, "app/db", &asm.CacheGetOptions{VersionStage: asm.StagePrevious})
    _, err = cache.RefreshNow(ctx, "app/db", nil)
    fmt.Printf("%+v\n", cache.Stats())

    p, err := client.Secrets()
    generic := asm.NewSecretCache(p, asm.AWSCacheOptions())
    ```

=== "Python"

    ```python
    import grow_aws_secrets_manager as sdk

    cache = client.secret_cache()  # or client.secret_cache(ttl_s=300)
    db = cache.get_secret_string("app/db")
    previous = cache.get_secret_value("app/db", version_stage=sdk.AWSPREVIOUS)
    cache.refresh_now("app/db")
    print(cache.stats())

    generic = sdk.SecretCache(client.secrets(), **sdk.AwsSecretCache.aws_defaults())
    ```

=== "Java"

    ```java
    AwsSecretCache cache = client.secretCache();
    String db = cache.getSecretString("app/db");
    AwsSecretValue previous = cache.getSecretValue("app/db", "AWSPREVIOUS");
    cache.refreshNow("app/db");
    System.out.println(cache.stats());

    SecretCache generic = new SecretCache(client.secrets(), AwsSecretCache.awsDefaults());
    ```
