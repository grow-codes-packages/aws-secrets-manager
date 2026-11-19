package codes.grow.packages.awssecretsmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import codes.grow.packages.awssecretsmanager.core.AuthenticationException;
import codes.grow.packages.awssecretsmanager.core.AwsSecretsManagerException;
import codes.grow.packages.awssecretsmanager.core.CancelledException;
import codes.grow.packages.awssecretsmanager.core.ConfigException;
import codes.grow.packages.awssecretsmanager.core.EnvReader;
import codes.grow.packages.awssecretsmanager.core.ErrorCode;
import codes.grow.packages.awssecretsmanager.core.HealthStatus;
import codes.grow.packages.awssecretsmanager.core.Hooks;
import codes.grow.packages.awssecretsmanager.core.Logger;
import codes.grow.packages.awssecretsmanager.core.MockServer;
import codes.grow.packages.awssecretsmanager.core.RateLimitException;
import codes.grow.packages.awssecretsmanager.core.RetryPolicy;
import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.core.TimeoutException;
import codes.grow.packages.awssecretsmanager.core.UnsupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

/** Core client functions: health, ping, serverVersion, close, hooks, async, credentials. */
class AwsSecretsManagerClientTest {
  private static final String EMPTY_LIST = "{\"SecretList\":[]}";
  private AwsMock mock;

  @BeforeEach
  void start() {
    mock = new AwsMock();
  }

  @AfterEach
  void stop() {
    mock.close();
  }

  private static RetryPolicy fastRetries(int n) {
    return RetryPolicy.builder()
        .maxRetries(n)
        .initialBackoff(Duration.ofMillis(1))
        .maxBackoff(Duration.ofMillis(5))
        .build();
  }

  @Test
  void healthPingAndServerVersion() {
    mock.fixture("ping.ok").fixture("ping.ok");
    try (AwsSecretsManagerClient c = mock.client()) {
      HealthStatus h = c.health();
      assertThat(h).isEqualTo(new HealthStatus(true, "ok", Map.of()));
      assertThat(c.ping()).isGreaterThanOrEqualTo(Duration.ZERO);
      assertThat(mock.last("ListSecrets").get("MaxResults").asInt()).isEqualTo(1);
      assertThatThrownBy(c::serverVersion).isInstanceOf(UnsupportedException.class);
      assertThat(AwsSecretsManagerClient.API_VERSION).isEqualTo("2017-10-17");
      assertThat(c.sdk()).isNotNull();
      assertThat(c.toString())
          .contains("AwsSecretsManagerClient")
          .doesNotContain(AwsMock.SECRET_KEY);
    }
  }

  @Test
  void authFailuresAreAuthenticationAndHealthStaysOk() {
    mock.fixture("ping.auth-unknown-key").fixture("ping.auth-bad-signature");
    mock.fixture("ping.auth-unknown-key");
    try (AwsSecretsManagerClient c = mock.client()) {
      assertThatThrownBy(c::ping)
          .isInstanceOf(AuthenticationException.class)
          .satisfies(
              e -> {
                assertThat(((AwsSecretsManagerException) e).httpStatus()).hasValue(403);
                assertThat(e.getMessage()).doesNotContain(AwsMock.SECRET_KEY);
              });
      assertThatThrownBy(c::ping).isInstanceOf(AuthenticationException.class);
      HealthStatus h = c.health();
      assertThat(h.healthy()).isTrue();
      assertThat(h.details())
          .containsEntry("auth", "failed")
          .containsEntry("code", "AUTHENTICATION");
    }
  }

  @Test
  void healthStatesForThrottleServerErrorsOtherClientErrorsAndNetwork() {
    mock.error("ListSecrets", 400, "ThrottlingException");
    mock.json("ListSecrets", 500, "<html>boom</html>", "Content-Type", "text/html");
    mock.error("ListSecrets", 400, "ValidationException");
    try (AwsSecretsManagerClient c = mock.builder().retry(fastRetries(3)).build()) {
      assertThat(c.health().status()).isEqualTo("degraded");
      HealthStatus down = c.health();
      assertThat(down.healthy()).isFalse();
      assertThat(down.status()).isEqualTo("unhealthy");
      assertThat(down.details()).containsEntry("httpStatus", "500");
      // the health probe never retries
      assertThat(mock.count("ListSecrets")).isEqualTo(2);
      HealthStatus other = c.health();
      assertThat(other.healthy()).isTrue();
      assertThat(other.details()).containsEntry("httpStatus", "400");
    }
    try (AwsSecretsManagerClient c =
        AwsSecretsManagerClient.builder()
            .url("http://127.0.0.1:1")
            .region("us-east-1")
            .credentials("AKID", "secret-value")
            .retry(RetryPolicy.none())
            .build()) {
      HealthStatus h = c.health();
      assertThat(h.status()).isEqualTo("unreachable");
      assertThatThrownBy(c::ping)
          .isInstanceOf(AwsSecretsManagerException.class)
          .satisfies(
              e ->
                  assertThat(((AwsSecretsManagerException) e).code())
                      .isEqualTo(ErrorCode.UNAVAILABLE));
    }
  }

  @Test
  void closeIsIdempotentAndLaterCallsFail() throws Exception {
    AwsSecretsManagerClient c = mock.client();
    AwsSecretsManagerSecretsProvider p = c.secrets();
    AtomicReference<Boolean> closedResource = new AtomicReference<>(false);
    c.register(() -> closedResource.set(true));
    c.register(
        () -> {
          throw new IllegalStateException("ignored");
        });
    mock.fixture("ping.ok");
    c.health(); // builds the health client so close releases it too
    c.close();
    c.close();
    assertThat(c.isClosed()).isTrue();
    assertThat(closedResource.get()).isTrue();
    assertThatThrownBy(c::ping).isInstanceOf(CancelledException.class);
    assertThatThrownBy(c::health).isInstanceOf(CancelledException.class);
    assertThatThrownBy(c::serverVersion).isInstanceOf(CancelledException.class);
    assertThatThrownBy(c::secrets).isInstanceOf(CancelledException.class);
    assertThatThrownBy(() -> p.get("x")).isInstanceOf(CancelledException.class);
  }

  @Test
  void retriesHooksUserAgentHeadersAndLogger() {
    List<Hooks.RequestInfo> requests = new CopyOnWriteArrayList<>();
    List<Hooks.ResponseInfo> responses = new CopyOnWriteArrayList<>();
    List<Hooks.ErrorInfo> errors = new CopyOnWriteArrayList<>();
    List<String> logs = new CopyOnWriteArrayList<>();
    Hooks hooks =
        new Hooks() {
          @Override
          public void onRequest(RequestInfo info) {
            requests.add(info);
            throw new IllegalStateException("hooks must not break calls");
          }

          @Override
          public void onResponse(ResponseInfo info) {
            responses.add(info);
          }

          @Override
          public void onError(ErrorInfo info) {
            errors.add(info);
          }
        };
    Logger logger =
        new Logger() {
          @Override
          public void debug(String message, Map<String, Object> fields) {
            logs.add(message + fields);
          }
        };
    mock.json("ListSecrets", 503, "{\"__type\":\"ServiceUnavailable\",\"message\":\"later\"}");
    mock.json("ListSecrets", 200, EMPTY_LIST, "x-amzn-RequestId", "rid-1");
    mock.error("GetSecretValue", 400, "ResourceNotFoundException");
    try (AwsSecretsManagerClient c =
        mock.builder()
            .retry(fastRetries(2))
            .hooks(hooks)
            .logger(logger)
            .header("X-Extra", "yes")
            .userAgentSuffix("my-app/1.0")
            .build()) {
      c.ping();
      assertThat(requests).extracting(Hooks.RequestInfo::attempt).containsExactly(1, 2);
      assertThat(responses).extracting(Hooks.ResponseInfo::status).containsExactly(503, 200);
      assertThat(responses.get(1).requestId()).contains("rid-1");
      Map<String, List<String>> headers = requests.get(0).headers();
      String auth =
          headers.entrySet().stream()
              .filter(e -> e.getKey().equalsIgnoreCase("Authorization"))
              .findFirst()
              .orElseThrow()
              .getValue()
              .get(0);
      assertThat(auth).isEqualTo("[REDACTED]");
      MockServer.Recorded last = mock.server.requests().get(1);
      assertThat(last.header("User-Agent"))
          .contains("grow-codes-aws-secrets-manager/")
          .contains("(java)")
          .contains("my-app/1.0");
      assertThat(last.header("X-Extra")).isEqualTo("yes");
      assertThat(logs)
          .anyMatch(l -> l.startsWith("request"))
          .anyMatch(l -> l.startsWith("response"));
      assertThat(logs.toString()).doesNotContain(AwsMock.SECRET_KEY);
      assertThatThrownBy(() -> c.getSecretValue("missing"))
          .isInstanceOf(AwsSecretsManagerException.class);
      assertThat(errors).hasSize(1);
      assertThat(errors.get(0).error().code()).isEqualTo(ErrorCode.NOT_FOUND);
      assertThat(errors.get(0).willRetry()).isFalse();
    }
  }

  @Test
  void rateLimitCarriesRetryAfter() {
    mock.json(
        "ListSecrets",
        400,
        "{\"__type\":\"ThrottlingException\",\"message\":\"slow down\"}",
        "Retry-After",
        "2");
    try (AwsSecretsManagerClient c = mock.client()) {
      assertThatThrownBy(c::ping)
          .isInstanceOf(RateLimitException.class)
          .satisfies(
              e -> {
                AwsSecretsManagerException ex = (AwsSecretsManagerException) e;
                assertThat(ex.retryable()).isTrue();
                assertThat(ex.retryAfter()).contains(Duration.ofSeconds(2));
              });
    }
  }

  @Test
  void requestAndTotalTimeouts() {
    MockServer.Responder slow =
        ex -> {
          Thread.sleep(1500);
          AwsMock.respond(ex, 200, EMPTY_LIST);
        };
    mock.on("ListSecrets", slow).on("ListSecrets", slow);
    try (AwsSecretsManagerClient c =
        mock.builder().requestTimeout(Duration.ofMillis(200)).build()) {
      assertThatThrownBy(c::ping)
          .isInstanceOf(TimeoutException.class)
          .hasMessageContaining("request timed out");
    }
    try (AwsSecretsManagerClient c =
        mock.builder()
            .requestTimeout(Duration.ofSeconds(5))
            .totalTimeout(Duration.ofMillis(300))
            .build()) {
      assertThatThrownBy(c::ping)
          .isInstanceOf(TimeoutException.class)
          .hasMessageContaining("total timeout of 300 ms");
    }
  }

  @Test
  void asyncVariantsAndCancellation() throws Exception {
    mock.fixture("ping.ok").fixture("ping.ok").fixture("getSecretValue.ok-string");
    try (AwsSecretsManagerClient c = mock.client()) {
      assertThat(c.healthAsync().get(5, TimeUnit.SECONDS).healthy()).isTrue();
      assertThat(c.pingAsync().get(5, TimeUnit.SECONDS)).isGreaterThanOrEqualTo(Duration.ZERO);
      assertThat(c.getSecretValueAsync("sdkv-0badc0de/app/db").get(5, TimeUnit.SECONDS).name())
          .isEqualTo("sdkv-0badc0de/app/db");
      CompletableFuture<String> version = c.serverVersionAsync();
      assertThatThrownBy(() -> version.get(5, TimeUnit.SECONDS))
          .isInstanceOf(ExecutionException.class)
          .hasCauseInstanceOf(UnsupportedException.class);
      mock.on(
          "GetSecretValue",
          ex -> {
            Thread.sleep(3000);
            AwsMock.respond(ex, 200, "{}");
          });
      CompletableFuture<AwsSecretValue> slow = c.getSecretValueAsync("s");
      Thread.sleep(200);
      assertThat(slow.cancel(true)).isTrue();
      assertThat(slow.isCancelled()).isTrue();
    }
  }

  @Test
  void interruptingABlockingCallRaisesCancelled() throws Exception {
    mock.on(
        "GetSecretValue",
        ex -> {
          Thread.sleep(3000);
          AwsMock.respond(ex, 200, "{}");
        });
    try (AwsSecretsManagerClient c = mock.client()) {
      AtomicReference<Throwable> thrown = new AtomicReference<>();
      Thread t =
          new Thread(
              () -> {
                try {
                  c.getSecretValue("s");
                } catch (RuntimeException e) {
                  thrown.set(e);
                }
              });
      t.start();
      Thread.sleep(300);
      t.interrupt();
      t.join(5000);
      assertThat(thrown.get()).isInstanceOf(CancelledException.class);
    }
  }

  @Test
  void everyAsyncVariantDelegates() throws Exception {
    String db = "sdkv-0badc0de/app/db";
    mock.fixture("getSecretValue.ok-string")
        .fixture("batchGetSecretValue.ids-partial")
        .fixture("batchGetSecretValue.ids-partial")
        .fixture("describeSecret.ok")
        .fixture("listSecrets.filter-word")
        .fixture("listSecretVersionIds.ok")
        .fixture("createSecret.ok-string")
        .fixture("putSecretValue.ok")
        .fixture("updateSecret.description")
        .fixture("updateSecretVersionStage.move")
        .fixture("deleteSecret.recovery-window")
        .fixture("restoreSecret.ok")
        .fixture("tagResource.ok")
        .fixture("untagResource.ok")
        .fixture("putResourcePolicy.ok")
        .fixture("getResourcePolicy.ok")
        .fixture("deleteResourcePolicy.ok")
        .fixture("rotateSecret.rules-only")
        .fixture("cancelRotateSecret.ok")
        .fixture("getRandomPassword.ok")
        .fixture("getSecretValue.json-seed");
    mock.json("ValidateResourcePolicy", 200, "{\"PolicyValidationPassed\":true}");
    try (AwsSecretsManagerClient c = mock.client()) {
      assertThat(c.getSecretValueAsync(db, GetSecretValueOptions.none()).get().name())
          .isEqualTo(db);
      assertThat(c.batchGetSecretValueAsync(List.of(db)).get().errors()).hasSize(1);
      assertThat(
              c.batchGetSecretValueAsync(BatchGetSelector.ids(db), BatchGetOptions.none())
                  .get()
                  .secretValues())
          .hasSize(2);
      assertThat(c.describeSecretAsync(db).get().name()).isEqualTo(db);
      assertThat(c.listSecretsAsync(ListSecretsOptions.none()).get()).isEmpty();
      assertThat(c.listSecretVersionIdsAsync(db, ListSecretVersionIdsOptions.none()).get())
          .hasSize(4);
      assertThat(c.createSecretAsync(db, "v", CreateSecretOptions.none()).get().name())
          .isEqualTo(db);
      assertThat(c.putSecretValueAsync(db, "v", PutSecretValueOptions.none()).get().versionId())
          .isNotEmpty();
      assertThat(
              c.updateSecretAsync(db, UpdateSecretOptions.builder().description("d").build())
                  .get()
                  .name())
          .isEqualTo(db);
      assertThat(
              c.updateSecretVersionStageAsync(
                      db, "S", new UpdateSecretVersionStageOptions("v", null))
                  .get()
                  .name())
          .isEqualTo(db);
      assertThat(c.deleteSecretAsync("b", DeleteSecretOptions.none()).get().deletionDate())
          .isNotNull();
      assertThat(c.restoreSecretAsync("b").get().name()).endsWith("blob");
      c.tagResourceAsync(db, Map.of("a", "b")).get();
      c.untagResourceAsync(db, List.of("a")).get();
      assertThat(c.putResourcePolicyAsync(db, "{}", PutResourcePolicyOptions.none()).get().name())
          .isEqualTo(db);
      assertThat(c.getResourcePolicyAsync(db).get().resourcePolicy()).isNotNull();
      assertThat(c.deleteResourcePolicyAsync(db).get().name()).isEqualTo(db);
      assertThat(
              c.validateResourcePolicyAsync("{}", ValidateResourcePolicyOptions.none())
                  .get()
                  .policyValidationPassed())
          .isTrue();
      assertThat(c.rotateSecretAsync(db, RotateSecretOptions.none()).get().versionId()).isNotNull();
      assertThat(c.cancelRotateSecretAsync(db).get().versionId()).isNotNull();
      assertThat(c.getRandomPasswordAsync(RandomPasswordOptions.none()).get().reveal())
          .isNotEmpty();
      assertThat(
              c.getJsonFieldAsync("grow-bootstrap/seed-json", "port", GetSecretValueOptions.none())
                  .get())
          .isPresent();
    }
  }

  @Test
  void wrapsACallerSuppliedSdkClient() {
    mock.fixture("ping.ok").fixture("ping.ok").fixture("ping.ok");
    SecretsManagerClient sdk =
        SecretsManagerClient.builder()
            .region(Region.US_EAST_1)
            .endpointOverride(java.net.URI.create(mock.url()))
            .credentialsProvider(
                StaticCredentialsProvider.create(AwsBasicCredentials.create("AKID", "sdk-secret")))
            .build();
    try {
      AwsSecretsManagerClient c = AwsSecretsManagerClient.withSdkClient(sdk);
      assertThat(c.sdk()).isSameAs(sdk);
      assertThat(c.ping()).isGreaterThanOrEqualTo(Duration.ZERO);
      assertThat(c.health().healthy()).isTrue();
      c.close();
      // still usable: close never closes a caller-supplied client
      assertThat(AwsSecretsManagerClient.builder().sdkClient(sdk).build().ping())
          .isGreaterThanOrEqualTo(Duration.ZERO);
      assertThatThrownBy(
              () -> AwsSecretsManagerClient.builder().sdkClient(sdk).region("us-east-1").build())
          .isInstanceOf(ConfigException.class)
          .hasMessageContaining("sdkClient is mutually exclusive with region");
    } finally {
      sdk.close();
    }
  }

  @Test
  void assumesARoleWithSts() {
    String sts =
        "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleResult>"
            + "<Credentials><AccessKeyId>ASIATEMPKEY</AccessKeyId><SecretAccessKey>temp-secret</SecretAccessKey>"
            + "<SessionToken>temp-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>"
            + "<AssumedRoleUser><Arn>arn:aws:sts::1:assumed-role/r/grow-sdk</Arn><AssumedRoleId>AROA:grow-sdk</AssumedRoleId>"
            + "</AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>"
            + "</AssumeRoleResponse>";
    mock.always(
        "STS",
        ex -> {
          ex.getResponseHeaders().add("Content-Type", "text/xml");
          AwsMock.respond(ex, 200, sts);
        });
    mock.fixture("ping.ok");
    System.setProperty("aws.endpointUrlSts", mock.url());
    try (AwsSecretsManagerClient c =
        mock.builder()
            .roleArn("arn:aws:iam::123456789012:role/r")
            .externalId("ext-1")
            .roleDuration(Duration.ofSeconds(900))
            .build()) {
      c.ping();
      MockServer.Recorded stsCall = mock.server.requests().get(0);
      assertThat(stsCall.body())
          .contains("Action=AssumeRole")
          .contains("RoleSessionName=grow-sdk")
          .contains("ExternalId=ext-1")
          .contains("DurationSeconds=900");
      MockServer.Recorded listCall = mock.server.requests().get(1);
      assertThat(listCall.header("Authorization")).contains("Credential=ASIATEMPKEY/");
      assertThat(listCall.header("X-Amz-Security-Token")).isEqualTo("temp-token");
    } finally {
      System.clearProperty("aws.endpointUrlSts");
    }
  }

  @Test
  void profileCredentialsAndRegion(@TempDir Path dir) throws Exception {
    Path credentials = dir.resolve("credentials");
    Path config = dir.resolve("config");
    Files.writeString(
        credentials,
        "[grow]\naws_access_key_id = AKIAPROFILEKEY\naws_secret_access_key = profile-secret\n");
    Files.writeString(config, "[profile grow]\nregion = eu-west-2\n");
    System.setProperty("aws.sharedCredentialsFile", credentials.toString());
    System.setProperty("aws.configFile", config.toString());
    System.setProperty("aws.disableEc2Metadata", "true");
    try {
      mock.fixture("ping.ok");
      try (AwsSecretsManagerClient c =
          AwsSecretsManagerClient.builder()
              .url(mock.url())
              .profile("grow")
              .retry(RetryPolicy.none())
              .build()) {
        c.ping();
        assertThat(mock.server.requests().get(0).header("Authorization"))
            .contains("Credential=AKIAPROFILEKEY/")
            .contains("/eu-west-2/secretsmanager/");
      }
      assumeTrue(
          System.getenv("AWS_REGION") == null && System.getenv("AWS_DEFAULT_REGION") == null);
      Files.writeString(config, "[profile other]\nregion = eu-west-2\n");
      assertThatThrownBy(
              () -> AwsSecretsManagerClient.builder().url(mock.url()).profile("grow").build())
          .isInstanceOf(ConfigException.class)
          .hasMessageContaining("region is not set");
    } finally {
      System.clearProperty("aws.sharedCredentialsFile");
      System.clearProperty("aws.configFile");
      System.clearProperty("aws.disableEc2Metadata");
    }
  }

  @Test
  void explicitCredentialsProviderAndSessionToken() {
    mock.fixture("ping.ok").fixture("ping.ok");
    try (AwsSecretsManagerClient c =
        AwsSecretsManagerClient.builder()
            .url(mock.url())
            .region("us-east-1")
            .credentials(
                StaticCredentialsProvider.create(
                    AwsBasicCredentials.create("AKIAPROVIDER", "p-secret")))
            .build()) {
      c.ping();
      assertThat(mock.server.requests().get(0).header("Authorization"))
          .contains("Credential=AKIAPROVIDER/");
    }
    try (AwsSecretsManagerClient c =
        AwsSecretsManagerClient.builder()
            .url(mock.url())
            .region("us-east-1")
            .accessKeyId("ASIASESSION")
            .secretAccessKey(Secret.of("s-secret"))
            .sessionToken(Secret.of("session-token-value"))
            .build()) {
      c.ping();
      assertThat(mock.server.requests().get(1).header("X-Amz-Security-Token"))
          .isEqualTo("session-token-value");
    }
  }

  @Test
  void proxyRoutesRequestsThroughTheProxy() {
    mock.always("ListSecrets", ex -> AwsMock.respond(ex, 200, EMPTY_LIST));
    try (AwsSecretsManagerClient c =
        AwsSecretsManagerClient.builder()
            .url("http://secretsmanager.example.invalid")
            .region("us-east-1")
            .credentials("AKID", "secret-value")
            .proxy(mock.url().replace("http://", "http://user:pa%20ss@"))
            .connectTimeout(Duration.ofSeconds(2))
            .retry(RetryPolicy.none())
            .build()) {
      c.ping();
      assertThat(mock.server.requests().get(0).uri())
          .startsWith("http://secretsmanager.example.invalid");
    }
    try (AwsSecretsManagerClient c =
        AwsSecretsManagerClient.builder()
            .url("http://secretsmanager.example.invalid")
            .region("us-east-1")
            .credentials("AKID", "secret-value")
            .proxy(mock.url())
            .build()) {
      c.ping();
    }
  }

  @Test
  void builderFromEnvAndFactories() {
    Map<String, String> env =
        Map.of(
            "GROW_AWS_SECRETS_MANAGER_URL", mock.url(),
            "AWS_REGION", "us-east-1",
            "AWS_ACCESS_KEY_ID", "AKIDENV",
            "AWS_SECRET_ACCESS_KEY", "env-secret");
    mock.fixture("ping.ok");
    try (AwsSecretsManagerClient c =
        AwsSecretsManagerClient.builder()
            .fromEnv(EnvReader.of(env))
            .connectTimeout(Duration.ofSeconds(3))
            .totalTimeout(Duration.ofSeconds(30))
            .roleSessionName("s")
            .recoveryWindowDays(7)
            .tls(codes.grow.packages.awssecretsmanager.core.TlsOptions.defaults())
            .build()) {
      c.ping();
      assertThat(c.config().recoveryWindowDays()).isEqualTo(7);
      assertThat(c.config().accessKeyId()).contains("AKIDENV");
    }
    assertThatThrownBy(
            () ->
                AwsSecretsManagerClient.create(
                    AwsSecretsManagerConfig.builder().url("ftp://x").build()))
        .isInstanceOf(ConfigException.class);
  }
}
