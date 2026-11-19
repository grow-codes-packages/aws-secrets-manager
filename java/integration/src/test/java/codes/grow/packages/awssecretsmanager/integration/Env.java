package codes.grow.packages.awssecretsmanager.integration;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
import codes.grow.packages.awssecretsmanager.DeleteSecretOptions;
import codes.grow.packages.awssecretsmanager.core.EnvReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Map;

/** Environment of the Docker suite: {@code /bootstrap/env} plus the compose variables. */
final class Env {
  private static final SecureRandom RANDOM = new SecureRandom();

  private Env() {}

  /** The merged environment; skips the test when the Docker harness is not present. */
  static Map<String, String> load() {
    try {
      Map<String, String> env = ConformanceTest.environment();
      String urlVariable = EnvReader.DEFAULT_PREFIX + "URL";
      assumeTrue(env.containsKey(urlVariable), urlVariable + " is not set; use docker/compose.yml");
      return env;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** A required variable. */
  static String get(Map<String, String> env, String name) {
    String v = env.get(name);
    if (v == null || v.isEmpty()) {
      throw new IllegalStateException(name + " must be set (see /bootstrap/env)");
    }
    return v;
  }

  /** True when the service is the Moto emulator. */
  static boolean isMoto(Map<String, String> env) {
    return "moto".equals(env.get("GROW_TEST_EMULATOR"));
  }

  /** A client from the environment (bootstrap admin credentials). */
  static AwsSecretsManagerClient client(Map<String, String> env) {
    return AwsSecretsManagerClient.builder().fromEnv(EnvReader.of(env)).build();
  }

  /** A unique name prefix for this run: {@code java-<run>-<random>}. */
  static String uid(Map<String, String> env, String prefix) {
    String run = env.getOrDefault("GROW_TEST_RUN_ID", "local").replaceAll("[^A-Za-z0-9]", "");
    run = run.substring(0, Math.min(8, run.length())).toLowerCase(java.util.Locale.ROOT);
    StringBuilder sb = new StringBuilder(prefix).append('-').append(run).append('-');
    for (int i = 0; i < 8; i++) {
      sb.append(Character.forDigit(RANDOM.nextInt(16), 16));
    }
    return sb.toString();
  }

  /** Force-deletes secrets created by a test (ignores failures). */
  static void purge(AwsSecretsManagerClient c, Collection<String> names) {
    for (String n : names) {
      try {
        c.deleteSecret(n, DeleteSecretOptions.builder().forceDeleteWithoutRecovery(true).build());
      } catch (RuntimeException ignored) {
        // best effort
      }
    }
  }
}
