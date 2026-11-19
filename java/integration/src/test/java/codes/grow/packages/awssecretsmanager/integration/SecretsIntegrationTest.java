package codes.grow.packages.awssecretsmanager.integration;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.awssecretsmanager.AwsSecretCache;
import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
import codes.grow.packages.awssecretsmanager.AwsSecretsManagerSecretsProvider;
import codes.grow.packages.awssecretsmanager.core.NotFoundException;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import codes.grow.packages.awssecretsmanager.secrets.DeleteOptions;
import codes.grow.packages.awssecretsmanager.secrets.EnvLoader;
import codes.grow.packages.awssecretsmanager.secrets.GetOptions;
import codes.grow.packages.awssecretsmanager.secrets.LoadEnvOptions;
import codes.grow.packages.awssecretsmanager.secrets.SecretCache;
import codes.grow.packages.awssecretsmanager.secrets.SecretMetadata;
import codes.grow.packages.awssecretsmanager.secrets.SecretValue;
import codes.grow.packages.awssecretsmanager.secrets.SetOptions;
import codes.grow.packages.awssecretsmanager.secrets.WatchHandle;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * SecretsProvider (category interface) against the real service, beyond the conformance runner:
 * paths, versions, binary values, tags and description, permanent delete, watch, getAll, loadEnv.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SecretsIntegrationTest {
  private AwsSecretsManagerClient c;
  private AwsSecretsManagerSecretsProvider p;
  private String base;

  @BeforeAll
  void start() {
    Map<String, String> env = Env.load();
    c = Env.client(env);
    p = c.secrets();
    base = Env.uid(env, "javap");
  }

  @AfterAll
  void stop() {
    if (c != null) {
      List<String> names = new ArrayList<>();
      p.list(base + "/").forEach(m -> names.add(m.name()));
      Env.purge(c, names);
      c.close();
    }
  }

  @Test
  void setGetWithPathAndVersionsAndMetadata() {
    String v1 =
        p.set("db", "one", SetOptions.builder().path(base).description("desc").tag("a", "1").build());
    String v2 = p.set(base + "/db", "two", SetOptions.builder().tag("b", "2").build());
    assertNotEquals(v1, v2);
    assertEquals(Optional.of("two"), p.getString("db", GetOptions.builder().path("/" + base + "/").build()));
    assertEquals("one", p.get(base + "/db", GetOptions.builder().version(v1).build()).orElseThrow().reveal());
    SecretMetadata meta = p.metadata(base + "/db").orElseThrow();
    assertEquals(Optional.of(v2), meta.version());
    assertEquals(2, meta.versions().getAsInt());
    assertEquals(Map.of("a", "1", "b", "2"), meta.tags());
    assertEquals("desc", meta.extra().get("description"));
    assertEquals(Optional.of(base), meta.path());
  }

  @Test
  void binaryGetManyGetAllLoadEnvAndList() throws Exception {
    p.set(base + "/bin", new byte[] {(byte) 0xff, (byte) 0xfe});
    assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xfe}, p.get(base + "/bin").orElseThrow().revealBytes());
    p.set(base + "/env/user", "u");
    p.set(base + "/env/pass", "p");
    p.set(base + "/env/nested/deep", "d");
    Map<String, SecretValue> many =
        p.getMany(List.of(base + "/env/user", base + "/none", base + "/env/pass"));
    assertEquals(List.of(base + "/env/user", base + "/env/pass"), new ArrayList<>(many.keySet()));
    Map<String, SecretValue> all = p.getAllAsync(base + "/env").get(30, TimeUnit.SECONDS);
    assertEquals(
        List.of(base + "/env/pass", base + "/env/user"),
        all.keySet().stream().sorted().collect(Collectors.toList()));
    Map<String, String> target = new HashMap<>();
    Map<String, String> set =
        p.loadEnv(
            base + "/env",
            LoadEnvOptions.builder().target(EnvLoader.map(target)).prefix("APP_").build());
    assertEquals(List.of("APP_PASS", "APP_USER"), set.keySet().stream().sorted().collect(Collectors.toList()));
    assertEquals("u", target.get("APP_USER"));
    List<String> listed = p.list(base + "/env/").stream().map(SecretMetadata::name).collect(Collectors.toList());
    assertEquals(List.of(base + "/env/nested/deep", base + "/env/pass", base + "/env/user"), listed);
  }

  @Test
  void softDeleteHidesThePermanentDeletePurges() {
    p.set(base + "/soft", "x");
    p.delete(base + "/soft");
    assertTrue(p.get(base + "/soft").isEmpty());
    assertTrue(p.metadata(base + "/soft").isEmpty());
    assertThrows(NotFoundException.class, () -> p.delete(base + "/soft"));
    c.restoreSecret(base + "/soft");
    assertEquals(Optional.of("x"), p.getString(base + "/soft"));
    p.delete(base + "/soft", DeleteOptions.builder().permanent(true).build());
    assertThrows(NotFoundException.class, () -> c.describeSecret(base + "/soft"));
    assertThrows(ValidationException.class, () -> p.set(base + "/cas", "x", SetOptions.builder().cas(0).build()));
  }

  @Test
  void watchReportsANewVersionAndTheCachesServeValues() throws Exception {
    String key = base + "/watched";
    p.set(key, "w1");
    try (SecretCache cache = new SecretCache(p, AwsSecretCache.awsDefaults())) {
      assertEquals(Optional.of("w1"), cache.getString(key));
      List<String> seen = new CopyOnWriteArrayList<>();
      WatchHandle handle =
          p.watch(key, Duration.ofMillis(200), (next, prev) -> seen.add(next.map(SecretValue::reveal).orElse(null)));
      Thread.sleep(1000); // the first poll records the current version
      p.set(key, "w2");
      for (int i = 0; i < 50 && seen.isEmpty(); i++) {
        Thread.sleep(100);
      }
      handle.stop();
      assertEquals(List.of("w2"), seen);
      assertEquals(Optional.of("w1"), cache.getString(key));
    }
  }
}
