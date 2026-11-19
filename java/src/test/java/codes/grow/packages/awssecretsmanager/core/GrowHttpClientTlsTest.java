package codes.grow.packages.awssecretsmanager.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
import java.nio.file.Path;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The package's SDK HTTP client honours the Grow TLS options (CA bundle, insecure mode). */
class GrowHttpClientTlsTest {
  static TestCerts server;
  static MockServer https;

  @BeforeAll
  static void setUp(@TempDir Path dir) throws Exception {
    server = TestCerts.generate(dir, "server", "RSA");
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    KeyStore ks = server.keyStore;
    kmf.init(ks, "changeit".toCharArray());
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(kmf.getKeyManagers(), null, null);
    https = MockServer.startTls(ctx, false);
    https.fallback(ex -> MockServer.send(ex, 200, "{\"SecretList\":[]}"));
  }

  @AfterAll
  static void tearDown() {
    https.close();
  }

  private static AwsSecretsManagerClient.Builder builder() {
    return AwsSecretsManagerClient.builder()
        .url(https.url())
        .region("us-east-1")
        .credentials("AKID", "tls-secret")
        .retry(RetryPolicy.none());
  }

  @Test
  void trustsTheConfiguredCa() {
    try (AwsSecretsManagerClient c =
        builder().tls(TlsOptions.builder().caCertPem(server.certPem).build()).build()) {
      assertThat(c.ping()).isNotNull();
    }
  }

  @Test
  void insecureSkipVerifyAcceptsAnyCertificate() {
    java.util.List<String> warnings = new java.util.ArrayList<>();
    try (AwsSecretsManagerClient c =
        builder()
            .tls(TlsOptions.builder().insecureSkipVerify(true).build())
            .logger(
                new Logger() {
                  @Override
                  public void warn(String message, java.util.Map<String, Object> fields) {
                    warnings.add(message);
                  }
                })
            .build()) {
      assertThat(c.ping()).isNotNull();
      assertThat(warnings).hasSize(1);
    }
  }

  @Test
  void rejectsAnUnknownCertificate() {
    try (AwsSecretsManagerClient c = builder().build()) {
      assertThatThrownBy(c::ping).isInstanceOf(AwsSecretsManagerException.class);
    }
  }
}
