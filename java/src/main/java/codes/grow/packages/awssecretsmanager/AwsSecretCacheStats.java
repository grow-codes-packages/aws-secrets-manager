package codes.grow.packages.awssecretsmanager;

/**
 * Counters reported by {@link AwsSecretCache#stats()}.
 *
 * @param hits reads served from an entry (fresh or refreshed)
 * @param misses reads that found no entry
 * @param refreshes expired entries checked with {@code DescribeSecret}
 * @param versionChanges refreshes that fetched a new version
 * @param evictions entries dropped by the LRU limit
 * @param size current number of entries
 */
public record AwsSecretCacheStats(
    long hits, long misses, long refreshes, long versionChanges, long evictions, int size) {}
