package codes.grow.packages.awssecretsmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.awssecretsmanager.core.NotFoundException;
import codes.grow.packages.awssecretsmanager.core.UnavailableException;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import codes.grow.packages.awssecretsmanager.secrets.SecretCache;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** AWS caching-client semantics with a fake source and clock. */
class AwsSecretCacheTest {
  /** A settable clock. */
  static final class MutableClock extends Clock {
    volatile long millis = 1_000_000;

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return Instant.ofEpochMilli(millis);
    }

    void advance(Duration d) {
      millis += d.toMillis();
    }
  }

  /** In-memory source: (id, stage) to value, with call counters. */
  static final class FakeSource implements AwsSecretCache.Source {
    final Map<String, String> current = new ConcurrentHashMap<>();
    final Map<String, String> versions = new ConcurrentHashMap<>();
    final AtomicInteger gets = new AtomicInteger();
    final AtomicInteger describes = new AtomicInteger();
    volatile RuntimeException fail;
    volatile CountDownLatch gate;

    void put(String id, String stage, String version, String value) {
      current.put(id + "|" + stage, version);
      versions.put(version, value);
    }

    @Override
    public AwsSecretValue getSecretValue(String secretId, GetSecretValueOptions options) {
      gets.incrementAndGet();
      CountDownLatch g = gate;
      if (g != null) {
        try {
          g.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      if (fail != null) {
        throw fail;
      }
      String version = current.get(secretId + "|" + options.versionStage());
      if (version == null) {
        throw new NotFoundException("missing");
      }
      return Models.secretValue(
          "arn:" + secretId,
          secretId,
          version,
          List.of(options.versionStage()),
          null,
          versions.get(version),
          null);
    }

    @Override
    public SecretDescription describeSecret(String secretId) {
      describes.incrementAndGet();
      if (fail != null) {
        throw fail;
      }
      Map<String, List<String>> stages = new ConcurrentHashMap<>();
      current.forEach(
          (k, v) -> {
            if (k.startsWith(secretId + "|")) {
              stages
                  .computeIfAbsent(v, x -> new ArrayList<>())
                  .add(k.substring(k.indexOf('|') + 1));
            }
          });
      return new SecretDescription(
          "arn:" + secretId,
          secretId,
          null,
          null,
          false,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          Map.of(),
          stages,
          List.of());
    }
  }

  private final MutableClock clock = new MutableClock();
  private final FakeSource source = new FakeSource();

  private AwsSecretCache cache(int maxEntries, List<Throwable> refreshErrors) {
    return new AwsSecretCache(
        source,
        AwsSecretCache.Options.builder()
            .ttl(Duration.ofMinutes(10))
            .maxEntries(maxEntries)
            .clock(clock)
            .onRefreshError(refreshErrors::add)
            .build());
  }

  @Test
  void servesCachedValuesAndRefreshesOnlyWhenTheStageMoved() {
    source.put("s", "AWSCURRENT", "v1", "one");
    List<Throwable> errors = new ArrayList<>();
    AwsSecretCache c = cache(10, errors);
    assertThat(c.getSecretString("s")).isEqualTo("one");
    assertThat(c.getSecretString("s")).isEqualTo("one");
    assertThat(source.gets.get()).isEqualTo(1);
    clock.advance(Duration.ofMinutes(11));
    assertThat(c.getSecretString("s")).isEqualTo("one");
    assertThat(source.describes.get()).isEqualTo(1);
    assertThat(source.gets.get()).isEqualTo(1);
    source.put("s", "AWSCURRENT", "v2", "two");
    source.put("s", "AWSPREVIOUS", "v1", "one");
    clock.advance(Duration.ofMinutes(11));
    assertThat(c.getSecretValue("s").versionId()).isEqualTo("v2");
    assertThat(c.getSecretString("s", "AWSPREVIOUS")).isEqualTo("one");
    assertThat(c.getSecretBinary("s")).isEqualTo("two".getBytes(StandardCharsets.UTF_8));
    assertThat(c.getSecretBinary("s", "AWSPREVIOUS"))
        .isEqualTo("one".getBytes(StandardCharsets.UTF_8));
    AwsSecretCacheStats st = c.stats();
    assertThat(st.refreshes()).isEqualTo(2);
    assertThat(st.versionChanges()).isEqualTo(1);
    assertThat(st.size()).isEqualTo(2);
    assertThat(st.misses()).isEqualTo(2);
    assertThat(errors).isEmpty();
  }

  @Test
  void refreshNowInvalidateClearAndEviction() {
    source.put("a", "AWSCURRENT", "a1", "A");
    source.put("b", "AWSCURRENT", "b1", "B");
    AwsSecretCache c = cache(1, new ArrayList<>());
    c.getSecretValue("a");
    c.getSecretValue("b");
    assertThat(c.stats().evictions()).isEqualTo(1);
    assertThat(c.stats().size()).isEqualTo(1);
    source.put("b", "AWSCURRENT", "b2", "B2");
    assertThat(c.refreshNow("b").value().reveal()).isEqualTo("B2");
    assertThat(c.refreshNow("a").value().reveal()).isEqualTo("A"); // not cached: plain read
    c.invalidate("a");
    assertThat(c.stats().size()).isZero();
    c.getSecretValue("b");
    c.clear();
    assertThat(c.stats().size()).isZero();
    assertThat(c.options().maxEntries()).isEqualTo(1);
  }

  @Test
  void failedRefreshServesStaleAndBacksOff() {
    source.put("s", "AWSCURRENT", "v1", "one");
    List<Throwable> errors = new ArrayList<>();
    AwsSecretCache c = cache(10, errors);
    c.getSecretValue("s");
    clock.advance(Duration.ofMinutes(11));
    source.fail = new UnavailableException("down");
    assertThat(c.getSecretString("s")).isEqualTo("one");
    assertThat(errors).hasSize(1);
    // within the 1 s backoff no new refresh
    assertThat(c.getSecretString("s")).isEqualTo("one");
    assertThat(source.describes.get()).isEqualTo(1);
    clock.advance(Duration.ofSeconds(2));
    assertThat(c.getSecretString("s")).isEqualTo("one");
    assertThat(source.describes.get()).isEqualTo(2);
    source.fail = null;
    clock.advance(Duration.ofSeconds(5));
    assertThat(c.getSecretString("s")).isEqualTo("one");
    assertThat(source.describes.get()).isEqualTo(3);
    // a throwing handler is ignored
    AwsSecretCache noisy =
        new AwsSecretCache(
            source,
            AwsSecretCache.Options.builder()
                .clock(clock)
                .onRefreshError(
                    e -> {
                      throw new IllegalStateException("x");
                    })
                .build());
    noisy.getSecretValue("s");
    clock.advance(Duration.ofHours(2));
    source.fail = new UnavailableException("down");
    assertThat(noisy.getSecretString("s")).isEqualTo("one");
    // a first read that fails throws
    assertThatThrownBy(() -> noisy.getSecretValue("other"))
        .isInstanceOf(UnavailableException.class);
    source.fail = null;
    assertThatThrownBy(() -> noisy.getSecretValue("other")).isInstanceOf(NotFoundException.class);
    // stage gone -> fetch again (and fail when the stage is missing)
    AwsSecretCache plain =
        new AwsSecretCache(source, AwsSecretCache.Options.builder().clock(clock).build());
    source.put("t", "AWSCURRENT", "t1", "T");
    plain.getSecretValue("t");
    source.current.remove("t|AWSCURRENT");
    clock.advance(Duration.ofHours(2));
    assertThat(plain.getSecretString("t")).isEqualTo("T");
  }

  @Test
  void concurrentReadsAreCoalesced() throws Exception {
    source.put("s", "AWSCURRENT", "v1", "one");
    AwsSecretCache c = cache(10, new ArrayList<>());
    source.gate = new CountDownLatch(1);
    List<Thread> threads = new ArrayList<>();
    List<String> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
    for (int i = 0; i < 4; i++) {
      Thread t = new Thread(() -> seen.add(c.getSecretString("s")));
      threads.add(t);
      t.start();
    }
    Thread.sleep(200);
    source.gate.countDown();
    for (Thread t : threads) {
      t.join(5000);
    }
    assertThat(seen).containsOnly("one").hasSize(4);
    assertThat(source.gets.get()).isEqualTo(1);
    // a coalesced failure reaches every waiter
    source.gate = new CountDownLatch(1);
    source.fail = new UnavailableException("down");
    List<Throwable> failures = new java.util.concurrent.CopyOnWriteArrayList<>();
    List<Thread> failing = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      Thread t =
          new Thread(
              () -> {
                try {
                  c.getSecretValue("x");
                } catch (RuntimeException e) {
                  failures.add(e);
                }
              });
      failing.add(t);
      t.start();
    }
    Thread.sleep(200);
    source.gate.countDown();
    for (Thread t : failing) {
      t.join(5000);
    }
    assertThat(failures).hasSize(3).allMatch(e -> e instanceof UnavailableException);
  }

  @Test
  void optionsValidationAndPresets() {
    assertThatThrownBy(() -> AwsSecretCache.Options.builder().ttl(Duration.ZERO).build())
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> AwsSecretCache.Options.builder().ttl(null).build())
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> AwsSecretCache.Options.builder().ttl(Duration.ofSeconds(-1)).build())
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> AwsSecretCache.Options.builder().maxEntries(0).build())
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> AwsSecretCache.Options.builder().versionStage(" ").build())
        .isInstanceOf(ValidationException.class);
    assertThatThrownBy(() -> AwsSecretCache.Options.builder().versionStage(null).build())
        .isInstanceOf(ValidationException.class);
    AwsSecretCache.Options o = AwsSecretCache.Options.builder().versionStage("AWSPENDING").build();
    assertThat(o.ttl()).isEqualTo(Duration.ofHours(1));
    assertThat(o.maxEntries()).isEqualTo(1024);
    assertThat(o.versionStage()).isEqualTo("AWSPENDING");
    assertThat(o.clock()).isNotNull();
    assertThat(o.onRefreshError()).isNull();
    SecretCache.Options aws = AwsSecretCache.awsDefaults();
    assertThat(aws.ttl()).isEqualTo(Duration.ofHours(1));
    assertThat(aws.maxEntries()).isEqualTo(1024);
  }

  @Test
  void clientCacheUsesGetSecretValueAndDescribeSecret() {
    try (AwsMock mock = new AwsMock();
        AwsSecretsManagerClient client = mock.client()) {
      mock.fixture("getSecretValue.ok-string")
          .fixture("describeSecret.ok")
          .fixture("getSecretValue.ok-string");
      AwsSecretCache c = client.secretCache();
      assertThat(c.getSecretString("sdkv-0badc0de/app/db")).isEqualTo("hello-0badc0de");
      assertThat(mock.last("GetSecretValue").get("VersionStage").asText()).isEqualTo("AWSCURRENT");
      // describe says AWSCURRENT is now another version -> fetch again
      c.refreshNow("sdkv-0badc0de/app/db");
      assertThat(mock.count("DescribeSecret")).isEqualTo(1);
      assertThat(mock.count("GetSecretValue")).isEqualTo(2);
      AwsSecretCache custom =
          client.secretCache(AwsSecretCache.Options.builder().ttl(Duration.ofSeconds(5)).build());
      assertThat(custom.options().ttl()).isEqualTo(Duration.ofSeconds(5));
    }
  }
}
