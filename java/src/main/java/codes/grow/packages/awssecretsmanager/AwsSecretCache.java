package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.ValidationException;
import codes.grow.packages.awssecretsmanager.secrets.SecretCache;
import java.time.Clock;
import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Version-stage aware secret cache with the semantics of the AWS caching clients ({@code
 * aws-secretsmanager-caching-*}, DECISIONS.md #3): entries per (secretId, versionStage), default
 * TTL 1 h and 1 024 entries (LRU). On expiry {@code DescribeSecret} checks whether the stage moved
 * to another version and {@code GetSecretValue} runs only when it did. Concurrent reads of the same
 * entry are coalesced. A refresh that fails keeps serving the cached value and retries with
 * exponential backoff (1 s doubling, capped at the TTL); a first read that fails throws.
 *
 * <p>Create one with {@link AwsSecretsManagerClient#secretCache()}.
 */
public final class AwsSecretCache {
  /** Initial delay before retrying a failed refresh. */
  static final Duration REFRESH_RETRY = Duration.ofSeconds(1);

  /** The client operations the cache needs. */
  public interface Source {
    /**
     * Reads a secret value.
     *
     * @param secretId name or ARN
     * @param options version selection
     * @return the value
     */
    AwsSecretValue getSecretValue(String secretId, GetSecretValueOptions options);

    /**
     * Reads secret metadata.
     *
     * @param secretId name or ARN
     * @return the metadata
     */
    SecretDescription describeSecret(String secretId);
  }

  private static final class Entry {
    final String secretId;
    final AwsSecretValue value;
    final long checkedAt;
    final int failures;

    Entry(String secretId, AwsSecretValue value, long checkedAt, int failures) {
      this.secretId = secretId;
      this.value = value;
      this.checkedAt = checkedAt;
      this.failures = failures;
    }
  }

  private final Source source;
  private final Options options;
  private final LinkedHashMap<List<String>, Entry> entries = new LinkedHashMap<>(16, 0.75f, true);
  private final Map<List<String>, CompletableFuture<AwsSecretValue>> inflight =
      new ConcurrentHashMap<>();
  private long hits;
  private long misses;
  private long refreshes;
  private long versionChanges;
  private long evictions;

  /**
   * Creates a cache in front of a source (usually a client).
   *
   * @param source the source
   * @param options cache options
   */
  public AwsSecretCache(Source source, Options options) {
    this.source = Objects.requireNonNull(source, "source");
    this.options = Objects.requireNonNull(options, "options");
  }

  AwsSecretCache(AwsSecretsManagerClient client, Options options) {
    this(
        new Source() {
          @Override
          public AwsSecretValue getSecretValue(String secretId, GetSecretValueOptions o) {
            return client.getSecretValue(secretId, o);
          }

          @Override
          public SecretDescription describeSecret(String secretId) {
            return client.describeSecret(secretId);
          }
        },
        options);
  }

  /**
   * Returns the AWS caching-client defaults (TTL 1 h, 1 024 entries) as options of the generic
   * {@link SecretCache}, which keeps the SPEC defaults otherwise.
   *
   * @return the preset
   */
  public static SecretCache.Options awsDefaults() {
    return SecretCache.Options.builder()
        .ttl(Options.DEFAULT_TTL)
        .maxEntries(Options.DEFAULT_MAX_ENTRIES)
        .build();
  }

  /**
   * Returns the options.
   *
   * @return the options
   */
  public Options options() {
    return options;
  }

  /**
   * Returns the cached value at the default stage.
   *
   * @param secretId name or ARN
   * @return the value
   */
  public AwsSecretValue getSecretValue(String secretId) {
    return getSecretValue(secretId, options.versionStage());
  }

  /**
   * Returns the cached value of {@code secretId} at a stage.
   *
   * @param secretId name or ARN
   * @param versionStage stage label
   * @return the value
   */
  public AwsSecretValue getSecretValue(String secretId, String versionStage) {
    List<String> key = List.of(secretId, versionStage);
    Entry entry;
    synchronized (this) {
      entry = entries.get(key);
      if (entry != null) {
        hits++;
        if (now() - entry.checkedAt < nextCheckAfter(entry)) {
          return entry.value;
        }
      } else {
        misses++;
      }
    }
    if (entry != null) {
      Entry stale = entry;
      return coalesce(key, () -> refresh(key, stale, versionStage));
    }
    return coalesce(
        key,
        () -> {
          AwsSecretValue v =
              source.getSecretValue(secretId, GetSecretValueOptions.ofVersionStage(versionStage));
          store(key, new Entry(secretId, v, now(), 0));
          return v;
        });
  }

  /**
   * Returns the value as text ({@code SecretString}, or UTF-8 of the binary).
   *
   * @param secretId name or ARN
   * @return the text
   */
  public String getSecretString(String secretId) {
    return getSecretValue(secretId).value().reveal();
  }

  /**
   * Returns the value at a stage as text.
   *
   * @param secretId name or ARN
   * @param versionStage stage label
   * @return the text
   */
  public String getSecretString(String secretId, String versionStage) {
    return getSecretValue(secretId, versionStage).value().reveal();
  }

  /**
   * Returns the value as bytes.
   *
   * @param secretId name or ARN
   * @return the bytes
   */
  public byte[] getSecretBinary(String secretId) {
    return getSecretValue(secretId).value().revealBytes();
  }

  /**
   * Returns the value at a stage as bytes.
   *
   * @param secretId name or ARN
   * @param versionStage stage label
   * @return the bytes
   */
  public byte[] getSecretBinary(String secretId, String versionStage) {
    return getSecretValue(secretId, versionStage).value().revealBytes();
  }

  /**
   * Forces a refresh check now (and a fetch when the stage moved).
   *
   * @param secretId name or ARN
   * @return the value
   */
  public AwsSecretValue refreshNow(String secretId) {
    return refreshNow(secretId, options.versionStage());
  }

  /**
   * Forces a refresh check of a stage now.
   *
   * @param secretId name or ARN
   * @param versionStage stage label
   * @return the value
   */
  public AwsSecretValue refreshNow(String secretId, String versionStage) {
    List<String> key = List.of(secretId, versionStage);
    synchronized (this) {
      Entry entry = entries.get(key);
      if (entry != null) {
        entries.put(key, new Entry(secretId, entry.value, Long.MIN_VALUE / 2, 0));
      }
    }
    return getSecretValue(secretId, versionStage);
  }

  /**
   * Drops every cached stage of {@code secretId}.
   *
   * @param secretId name or ARN
   */
  public synchronized void invalidate(String secretId) {
    entries.values().removeIf(e -> e.secretId.equals(secretId));
  }

  /** Drops every entry. */
  public synchronized void clear() {
    entries.clear();
  }

  /**
   * Returns the counters and the current size.
   *
   * @return the statistics
   */
  public synchronized AwsSecretCacheStats stats() {
    return new AwsSecretCacheStats(
        hits, misses, refreshes, versionChanges, evictions, entries.size());
  }

  private long now() {
    return options.clock().millis();
  }

  private long nextCheckAfter(Entry entry) {
    long ttl = options.ttl().toMillis();
    if (entry.failures == 0) {
      return ttl;
    }
    long backoff = REFRESH_RETRY.toMillis() << Math.min(30, entry.failures - 1);
    return Math.min(ttl, backoff);
  }

  private AwsSecretValue refresh(List<String> key, Entry entry, String stage) {
    synchronized (this) {
      refreshes++;
    }
    try {
      SecretDescription d = source.describeSecret(entry.secretId);
      String current = d.versionWithStage(stage).orElse(null);
      AwsSecretValue value = entry.value;
      if (current == null || !current.equals(entry.value.versionId())) {
        value = source.getSecretValue(entry.secretId, GetSecretValueOptions.ofVersionStage(stage));
        synchronized (this) {
          versionChanges++;
        }
      }
      store(key, new Entry(entry.secretId, value, now(), 0));
      return value;
    } catch (RuntimeException e) {
      synchronized (this) {
        if (entries.containsKey(key)) {
          entries.put(key, new Entry(entry.secretId, entry.value, now(), entry.failures + 1));
        }
      }
      Consumer<Throwable> handler = options.onRefreshError();
      if (handler != null) {
        try {
          handler.accept(e);
        } catch (RuntimeException ignored) {
          // a failing handler must not break the read
        }
      }
      return entry.value;
    }
  }

  private synchronized void store(List<String> key, Entry entry) {
    entries.put(key, entry);
    Iterator<List<String>> it = entries.keySet().iterator();
    while (entries.size() > options.maxEntries() && it.hasNext()) {
      it.next();
      it.remove();
      evictions++;
    }
  }

  private AwsSecretValue coalesce(List<String> key, Supplier<AwsSecretValue> load) {
    CompletableFuture<AwsSecretValue> mine = new CompletableFuture<>();
    CompletableFuture<AwsSecretValue> pending = inflight.putIfAbsent(key, mine);
    if (pending != null) {
      try {
        return pending.join();
      } catch (CompletionException e) {
        if (e.getCause() instanceof RuntimeException) {
          throw (RuntimeException) e.getCause();
        }
        throw e;
      }
    }
    try {
      AwsSecretValue v = load.get();
      mine.complete(v);
      return v;
    } catch (RuntimeException e) {
      mine.completeExceptionally(e);
      throw e;
    } finally {
      inflight.remove(key, mine);
    }
  }

  /** Options of {@link AwsSecretCache}. */
  public static final class Options {
    /** Default refresh interval (1 h, the AWS caching-client default). */
    public static final Duration DEFAULT_TTL = Duration.ofHours(1);

    /** Default LRU capacity (1 024, the AWS caching-client default). */
    public static final int DEFAULT_MAX_ENTRIES = 1024;

    private final Duration ttl;
    private final int maxEntries;
    private final String versionStage;
    private final Clock clock;
    private final Consumer<Throwable> onRefreshError;

    private Options(Builder b) {
      this.ttl = b.ttl;
      this.maxEntries = b.maxEntries;
      this.versionStage = b.versionStage;
      this.clock = b.clock;
      this.onRefreshError = b.onRefreshError;
    }

    /**
     * Starts a builder with the AWS defaults.
     *
     * @return a new builder
     */
    public static Builder builder() {
      return new Builder();
    }

    /**
     * Returns the refresh interval.
     *
     * @return the TTL
     */
    public Duration ttl() {
      return ttl;
    }

    /**
     * Returns the LRU capacity.
     *
     * @return the maximum number of entries
     */
    public int maxEntries() {
      return maxEntries;
    }

    /**
     * Returns the default stage label.
     *
     * @return the stage
     */
    public String versionStage() {
      return versionStage;
    }

    /**
     * Returns the clock.
     *
     * @return the clock
     */
    public Clock clock() {
      return clock;
    }

    /**
     * Returns the handler of failed refreshes.
     *
     * @return the handler, or null
     */
    public Consumer<Throwable> onRefreshError() {
      return onRefreshError;
    }

    /** Builder of {@link Options}. */
    public static final class Builder {
      private Duration ttl = DEFAULT_TTL;
      private int maxEntries = DEFAULT_MAX_ENTRIES;
      private String versionStage = AwsSecretsManagerClient.AWSCURRENT;
      private Clock clock = Clock.systemUTC();
      private Consumer<Throwable> onRefreshError;

      private Builder() {}

      /**
       * Sets the refresh interval (default 1 h).
       *
       * @param ttl positive duration
       * @return this builder
       */
      public Builder ttl(Duration ttl) {
        this.ttl = ttl;
        return this;
      }

      /**
       * Sets the LRU capacity (default 1 024).
       *
       * @param maxEntries at least 1
       * @return this builder
       */
      public Builder maxEntries(int maxEntries) {
        this.maxEntries = maxEntries;
        return this;
      }

      /**
       * Sets the default stage label (default {@code AWSCURRENT}).
       *
       * @param versionStage stage
       * @return this builder
       */
      public Builder versionStage(String versionStage) {
        this.versionStage = versionStage;
        return this;
      }

      /**
       * Sets the clock (tests).
       *
       * @param clock clock
       * @return this builder
       */
      public Builder clock(Clock clock) {
        this.clock = clock;
        return this;
      }

      /**
       * Sets a handler called when a refresh fails and the cached value is served instead.
       *
       * @param handler handler
       * @return this builder
       */
      public Builder onRefreshError(Consumer<Throwable> handler) {
        this.onRefreshError = handler;
        return this;
      }

      /**
       * Builds and validates the options.
       *
       * @return the options
       * @throws ValidationException when a value is out of range
       */
      public Options build() {
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
          throw new ValidationException("AwsSecretCache: ttl must be > 0");
        }
        if (maxEntries < 1) {
          throw new ValidationException("AwsSecretCache: maxEntries must be >= 1");
        }
        if (versionStage == null || versionStage.isBlank()) {
          throw new ValidationException("AwsSecretCache: versionStage must not be empty");
        }
        Objects.requireNonNull(clock, "clock");
        return new Options(this);
      }
    }
  }
}
