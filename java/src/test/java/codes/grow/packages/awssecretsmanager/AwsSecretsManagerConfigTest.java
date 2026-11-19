package codes.grow.packages.awssecretsmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.awssecretsmanager.core.ConfigException;
import codes.grow.packages.awssecretsmanager.core.EnvReader;
import codes.grow.packages.awssecretsmanager.core.RetryPolicy;
import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.core.TlsOptions;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

/** Configuration defaults, environment precedence and validation (API.md section 5). */
class AwsSecretsManagerConfigTest {
  @Test
  void defaults() {
    AwsSecretsManagerConfig c = AwsSecretsManagerConfig.builder().build();
    assertThat(c.endpoint()).isEmpty();
    assertThat(c.url()).isEqualTo("https://secretsmanager.us-east-1.amazonaws.com");
    assertThat(c.connectTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(c.requestTimeout()).isEqualTo(Duration.ofSeconds(30));
    assertThat(c.totalTimeout()).isEqualTo(Duration.ofSeconds(120));
    assertThat(c.retry().maxRetries()).isEqualTo(RetryPolicy.DEFAULT_MAX_RETRIES);
    assertThat(c.tls().isCustom()).isFalse();
    assertThat(c.proxy()).isEmpty();
    assertThat(c.headers()).isEmpty();
    assertThat(c.userAgentSuffix()).isEmpty();
    assertThat(c.hooks()).isNotNull();
    assertThat(c.logger()).isNotNull();
    assertThat(c.region()).isEmpty();
    assertThat(c.accessKeyId()).isEmpty();
    assertThat(c.secretAccessKey()).isEmpty();
    assertThat(c.sessionToken()).isEmpty();
    assertThat(c.profile()).isEmpty();
    assertThat(c.credentials()).isEmpty();
    assertThat(c.roleArn()).isEmpty();
    assertThat(c.roleSessionName()).isEqualTo("grow-sdk");
    assertThat(c.externalId()).isEmpty();
    assertThat(c.roleDuration()).isEmpty();
    assertThat(c.recoveryWindowDays()).isEqualTo(30);
    assertThat(c.sdkClient()).isEmpty();
    assertThat(c.knownSecrets()).isEmpty();
    assertThat(AwsSecretsManagerConfig.builder().region("eu-west-1").build().url())
        .isEqualTo("https://secretsmanager.eu-west-1.amazonaws.com");
  }

  @Test
  void environmentPrecedence() {
    Map<String, String> env = new HashMap<>();
    env.put("AWS_ENDPOINT_URL", "http://generic:1");
    env.put("AWS_ENDPOINT_URL_SECRETS_MANAGER", "http://service:2");
    env.put("AWS_DEFAULT_REGION", "eu-west-1");
    env.put("AWS_REGION", "eu-west-2");
    env.put("AWS_PROFILE", "vendor");
    env.put("AWS_ACCESS_KEY_ID", "AKIAVENDOR");
    env.put("AWS_SECRET_ACCESS_KEY", "vendor-secret");
    env.put("AWS_SESSION_TOKEN", "vendor-token");
    AwsSecretsManagerConfig vendor = AwsSecretsManagerConfig.fromEnv(env);
    assertThat(vendor.endpoint()).contains("http://service:2");
    assertThat(vendor.region()).contains("eu-west-2");
    assertThat(vendor.profile()).contains("vendor");
    assertThat(vendor.accessKeyId()).contains("AKIAVENDOR");
    assertThat(vendor.sessionToken().map(Secret::reveal)).contains("vendor-token");
    assertThat(vendor.knownSecrets()).containsExactly("vendor-secret", "vendor-token");

    env.put("GROW_AWS_SECRETS_MANAGER_URL", "http://grow:3");
    env.put("GROW_AWS_SECRETS_MANAGER_REGION", "ap-south-1");
    env.put("GROW_AWS_SECRETS_MANAGER_PROFILE", "grow");
    env.put("GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID", "AKIAGROW");
    env.put("GROW_AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY", "grow-secret");
    env.put("GROW_AWS_SECRETS_MANAGER_ROLE_ARN", "arn:aws:iam::1:role/r");
    env.put("GROW_AWS_SECRETS_MANAGER_ROLE_SESSION_NAME", "sess");
    env.put("GROW_AWS_SECRETS_MANAGER_EXTERNAL_ID", "ext");
    env.put("GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS", "7");
    env.put("GROW_AWS_SECRETS_MANAGER_CONNECT_TIMEOUT", "2s");
    env.put("GROW_AWS_SECRETS_MANAGER_REQUEST_TIMEOUT", "3s");
    env.put("GROW_AWS_SECRETS_MANAGER_TOTAL_TIMEOUT", "4s");
    env.put("GROW_AWS_SECRETS_MANAGER_MAX_RETRIES", "1");
    env.put("GROW_AWS_SECRETS_MANAGER_PROXY", "http://proxy:3128");
    env.put("GROW_AWS_SECRETS_MANAGER_INSECURE_SKIP_VERIFY", "true");
    AwsSecretsManagerConfig grow = AwsSecretsManagerConfig.fromEnv(env);
    assertThat(grow.endpoint()).contains("http://grow:3");
    assertThat(grow.region()).contains("ap-south-1");
    assertThat(grow.profile()).contains("grow");
    assertThat(grow.accessKeyId()).contains("AKIAGROW");
    // the GROW_* key never pairs with the AWS_* session token
    assertThat(grow.sessionToken()).isEmpty();
    assertThat(grow.roleArn()).contains("arn:aws:iam::1:role/r");
    assertThat(grow.roleSessionName()).isEqualTo("sess");
    assertThat(grow.externalId()).contains("ext");
    assertThat(grow.recoveryWindowDays()).isEqualTo(7);
    assertThat(grow.connectTimeout()).isEqualTo(Duration.ofSeconds(2));
    assertThat(grow.requestTimeout()).isEqualTo(Duration.ofSeconds(3));
    assertThat(grow.totalTimeout()).isEqualTo(Duration.ofSeconds(4));
    assertThat(grow.retry().maxRetries()).isEqualTo(1);
    assertThat(grow.proxy()).contains("http://proxy:3128");
    assertThat(grow.tls().insecureSkipVerify()).isTrue();

    // explicit values win, in any order relative to fromEnv
    AwsSecretsManagerConfig explicit =
        AwsSecretsManagerConfig.builder()
            .fromEnv(EnvReader.of(env))
            .url("http://explicit:4")
            .region("us-west-2")
            .accessKeyId("AKIAEXPLICIT")
            .secretAccessKey("explicit-secret")
            .retry(RetryPolicy.none())
            .tls(TlsOptions.defaults())
            .proxy("http://p:1")
            .recoveryWindowDays(10)
            .roleSessionName("mine")
            .externalId("x")
            .connectTimeout(Duration.ofSeconds(1))
            .requestTimeout(Duration.ofSeconds(1))
            .totalTimeout(Duration.ofSeconds(1))
            .build();
    assertThat(explicit.endpoint()).contains("http://explicit:4");
    assertThat(explicit.accessKeyId()).contains("AKIAEXPLICIT");
    assertThat(explicit.recoveryWindowDays()).isEqualTo(10);
    assertThat(explicit.retry().maxRetries()).isZero();
  }

  @Test
  void explicitCredentialsOrSdkClientIgnoreEnvironmentCredentials() {
    Map<String, String> env =
        Map.of(
            "AWS_ACCESS_KEY_ID", "AKIAVENDOR",
            "AWS_SECRET_ACCESS_KEY", "vendor-secret",
            "AWS_REGION", "eu-west-1",
            "GROW_AWS_SECRETS_MANAGER_URL", "http://grow:3",
            "GROW_AWS_SECRETS_MANAGER_ROLE_ARN", "arn:aws:iam::1:role/r",
            "AWS_PROFILE", "p",
            "GROW_AWS_SECRETS_MANAGER_CA_CERT", "/tmp/ca.pem",
            "GROW_AWS_SECRETS_MANAGER_CLIENT_CERT", "/tmp/c.pem",
            "GROW_AWS_SECRETS_MANAGER_CLIENT_KEY", "/tmp/k.pem");
    AwsSecretsManagerConfig withProvider =
        AwsSecretsManagerConfig.builder()
            .credentials(AnonymousCredentialsProvider.create())
            .fromEnv(EnvReader.of(env))
            .build();
    assertThat(withProvider.accessKeyId()).isEmpty();
    assertThat(withProvider.region()).contains("eu-west-1");
    assertThat(withProvider.tls().caCertPath()).contains(Paths.get("/tmp/ca.pem"));
    try (SecretsManagerClient sdk =
        SecretsManagerClient.builder()
            .region(Region.US_EAST_1)
            .credentialsProvider(AnonymousCredentialsProvider.create())
            .build()) {
      AwsSecretsManagerConfig wrapped =
          AwsSecretsManagerConfig.builder().fromEnv(EnvReader.of(env)).sdkClient(sdk).build();
      assertThat(wrapped.sdkClient()).contains(sdk);
      assertThat(wrapped.accessKeyId()).isEmpty();
      assertThat(wrapped.region()).isEmpty();
      assertThat(wrapped.endpoint()).isEmpty();
      assertThat(wrapped.roleArn()).isEmpty();
      assertThat(wrapped.profile()).isEmpty();
      assertThat(wrapped.toString()).contains("sdkClient=SecretsManagerClient");
      assertThatThrownBy(
              () ->
                  AwsSecretsManagerConfig.builder()
                      .sdkClient(sdk)
                      .accessKeyId("a")
                      .secretAccessKey("b")
                      .credentials(AnonymousCredentialsProvider.create())
                      .profile("p")
                      .roleArn("arn:x")
                      .region("us-east-1")
                      .url("http://x")
                      .build())
          .isInstanceOf(ConfigException.class)
          .hasMessageContaining("accessKeyId, credentials, profile, roleArn, region, url");
    }
  }

  @Test
  void invalidEnvironmentValuesNameTheVariable() {
    assertThatThrownBy(
            () ->
                AwsSecretsManagerConfig.fromEnv(
                    Map.of("GROW_AWS_SECRETS_MANAGER_MAX_RETRIES", "-1")))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("GROW_AWS_SECRETS_MANAGER_MAX_RETRIES");
    assertThatThrownBy(
            () ->
                AwsSecretsManagerConfig.fromEnv(
                    Map.of("GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS", "many")))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("RECOVERY_WINDOW_DAYS");
  }

  @Test
  void validationRules() {
    assertInvalid(AwsSecretsManagerConfig.builder().url("ftp://x"), "url must be");
    assertInvalid(AwsSecretsManagerConfig.builder().url("http://bad host"), "url must be");
    assertInvalid(
        AwsSecretsManagerConfig.builder().connectTimeout(Duration.ZERO), "connectTimeout");
    assertInvalid(
        AwsSecretsManagerConfig.builder().requestTimeout(Duration.ofSeconds(-1)), "requestTimeout");
    assertInvalid(AwsSecretsManagerConfig.builder().totalTimeout(Duration.ZERO), "totalTimeout");
    assertInvalid(
        AwsSecretsManagerConfig.builder()
            .tls(TlsOptions.builder().clientCertPath(Paths.get("c")).build()),
        "tls client certificate");
    assertInvalid(AwsSecretsManagerConfig.builder().proxy("not a url"), "proxy");
    assertInvalid(AwsSecretsManagerConfig.builder().region("EU West"), "region");
    assertInvalid(AwsSecretsManagerConfig.builder().accessKeyId("a"), "accessKeyId requires");
    assertInvalid(
        AwsSecretsManagerConfig.builder().secretAccessKey(Secret.of("s")),
        "secretAccessKey requires");
    assertInvalid(AwsSecretsManagerConfig.builder().sessionToken("t"), "sessionToken requires");
    assertInvalid(
        AwsSecretsManagerConfig.builder()
            .accessKeyId("a")
            .secretAccessKey("s")
            .credentials(AnonymousCredentialsProvider.create()),
        "mutually exclusive");
    assertInvalid(AwsSecretsManagerConfig.builder().roleArn("role"), "roleArn must be an ARN");
    assertInvalid(
        AwsSecretsManagerConfig.builder().roleDuration(Duration.ofSeconds(899)), "roleDuration");
    assertInvalid(
        AwsSecretsManagerConfig.builder().roleDuration(Duration.ofHours(13)), "roleDuration");
    assertInvalid(AwsSecretsManagerConfig.builder().recoveryWindowDays(6), "recoveryWindowDays");
    assertInvalid(AwsSecretsManagerConfig.builder().recoveryWindowDays(31), "recoveryWindowDays");
    AwsSecretsManagerConfig ok =
        AwsSecretsManagerConfig.builder()
            .roleArn("arn:aws:iam::1:role/r")
            .roleDuration(Duration.ofHours(1))
            .url(" ")
            .accessKeyId("AKIA")
            .sessionToken((String) null)
            .secretAccessKey((String) null)
            .secretAccessKey("s3cr3t-value")
            .sessionToken(Secret.of("t0ken-value"))
            .build();
    assertThat(ok.endpoint()).isEmpty();
    assertThat(ok.roleDuration()).contains(Duration.ofHours(1));
  }

  private static void assertInvalid(AwsSecretsManagerConfig.Builder b, String text) {
    assertThatThrownBy(b::build).isInstanceOf(ConfigException.class).hasMessageContaining(text);
  }

  @Test
  void toStringRedactsCredentials() {
    AwsSecretsManagerConfig c =
        AwsSecretsManagerConfig.builder()
            .url("http://user:pw@host:5000")
            .region("us-east-1")
            .accessKeyId("AKIAEXAMPLE")
            .secretAccessKey("super-secret-key")
            .sessionToken("super-session-token")
            .externalId("external-xyz")
            .roleArn("arn:aws:iam::1:role/r")
            .roleDuration(Duration.ofHours(1))
            .proxy("http://u:p@proxy:1")
            .header("Authorization", "Bearer abc")
            .userAgentSuffix("app/1")
            .build();
    String s = c.toString();
    assertThat(s)
        .doesNotContain("super-secret-key")
        .doesNotContain("super-session-token")
        .doesNotContain("external-xyz")
        .doesNotContain("Bearer abc")
        .contains("AKIAEXAMPLE")
        .contains("[REDACTED]");
    assertThat(c.knownSecrets()).containsExactly("super-secret-key", "super-session-token");
    Secret cleared = Secret.of("gone-secret");
    cleared.clear();
    assertThat(
            AwsSecretsManagerConfig.builder()
                .accessKeyId("a")
                .secretAccessKey(cleared)
                .credentials(null)
                .build()
                .knownSecrets())
        .isEmpty();
    assertThat(
            AwsSecretsManagerConfig.builder()
                .credentials(AnonymousCredentialsProvider.create())
                .build()
                .toString())
        .contains("credentials=[REDACTED]");
  }
}
