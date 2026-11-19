package codes.grow.packages.awssecretsmanager.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
import codes.grow.packages.awssecretsmanager.core.AuthenticationException;
import codes.grow.packages.awssecretsmanager.core.ConfigException;
import codes.grow.packages.awssecretsmanager.core.EnvReader;
import codes.grow.packages.awssecretsmanager.core.HealthStatus;
import codes.grow.packages.awssecretsmanager.core.PermissionDeniedException;
import codes.grow.packages.awssecretsmanager.core.RetryPolicy;
import codes.grow.packages.awssecretsmanager.core.UnsupportedException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

/** Core client functions against the real service: health, ping, serverVersion, close. */
class ClientIntegrationTest {
  @Test
  void healthAndPing() throws Exception {
    Map<String, String> env = Env.load();
    try (AwsSecretsManagerClient c = Env.client(env)) {
      HealthStatus h = c.health();
      assertEquals(new HealthStatus(true, "ok", Map.of()), h);
      assertFalse(c.ping().isNegative());
      assertTrue(c.healthAsync().get(30, TimeUnit.SECONDS).healthy());
      assertFalse(c.pingAsync().get(30, TimeUnit.SECONDS).isNegative());
    }
  }

  @Test
  void wrongCredentialsAreAuthenticationErrorsAndNeverLeak() {
    Map<String, String> env = Env.load();
    String wrongSecret = "wrong-secret-for-integration-0123456789";
    for (String key : new String[] {"AKIAUNKNOWNKEY000000", Env.get(env, "AWS_ACCESS_KEY_ID")}) {
      try (AwsSecretsManagerClient c =
          AwsSecretsManagerClient.builder()
              .fromEnv(EnvReader.of(env))
              .credentials(key, wrongSecret)
              .retry(RetryPolicy.none())
              .build()) {
        AuthenticationException e = assertThrows(AuthenticationException.class, c::ping);
        assertEquals(403, e.httpStatus().getAsInt());
        assertFalse(e.getMessage().contains(wrongSecret));
        HealthStatus h = c.health();
        assertTrue(h.healthy());
        assertEquals("failed", h.details().get("auth"));
      }
    }
  }

  @Test
  void readOnlyPrincipalGetsPermissionDeniedOnWrites() {
    Map<String, String> env = Env.load();
    try (AwsSecretsManagerClient c =
        AwsSecretsManagerClient.builder()
            .fromEnv(EnvReader.of(env))
            .credentials(
                Env.get(env, "GROW_TEST_READONLY_ACCESS_KEY_ID"),
                Env.get(env, "GROW_TEST_READONLY_SECRET_ACCESS_KEY"))
            .retry(RetryPolicy.none())
            .build()) {
      assertFalse(c.ping().isNegative());
      assertThrows(PermissionDeniedException.class, () -> c.createSecret("java-readonly-denied", "v"));
    }
  }

  @Test
  void serverVersionIsUnsupportedAndCloseIsIdempotent() {
    Map<String, String> env = Env.load();
    AwsSecretsManagerClient c = Env.client(env);
    assertThrows(UnsupportedException.class, c::serverVersion);
    ExecutionException e =
        assertThrows(ExecutionException.class, () -> c.serverVersionAsync().get(30, TimeUnit.SECONDS));
    assertInstanceOf(UnsupportedException.class, e.getCause());
    assertEquals("2017-10-17", AwsSecretsManagerClient.API_VERSION);
    c.close();
    c.close();
    assertTrue(c.isClosed());
    assertThrows(ConfigException.class, c::ping);
  }

  @Test
  void wrapsACallerSuppliedSdkClient() {
    Map<String, String> env = Env.load();
    SecretsManagerClient sdk =
        SecretsManagerClient.builder()
            .region(Region.of(Env.get(env, "AWS_REGION")))
            .endpointOverride(URI.create(Env.get(env, "GROW_AWS_SECRETS_MANAGER_URL")))
            .credentialsProvider(
                StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(
                        Env.get(env, "AWS_ACCESS_KEY_ID"), Env.get(env, "AWS_SECRET_ACCESS_KEY"))))
            .build();
    try {
      AwsSecretsManagerClient c = AwsSecretsManagerClient.withSdkClient(sdk);
      assertSame(sdk, c.sdk());
      assertFalse(c.ping().isNegative());
      c.close();
      // still usable: close never closes a caller-supplied client
      try (AwsSecretsManagerClient again = AwsSecretsManagerClient.builder().sdkClient(sdk).build()) {
        assertTrue(again.ping().compareTo(Duration.ZERO) >= 0);
      }
    } finally {
      sdk.close();
    }
  }
}
