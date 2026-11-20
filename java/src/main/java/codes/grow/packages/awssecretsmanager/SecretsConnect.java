// Service-owned: generated once by sdk-kit, then maintained in this repository.
package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.UnsupportedException;
import codes.grow.packages.awssecretsmanager.secrets.ConfigLoader.SecretsBootstrap;
import codes.grow.packages.awssecretsmanager.secrets.ConfigLoader.SecretsConnection;
import codes.grow.packages.awssecretsmanager.secrets.SecretsProvider;
import java.util.Map;

/** Connector of {@code ConfigLoader.load()} for AWS Secrets Manager. */
public final class SecretsConnect {
  private SecretsConnect() {}

  /**
   * Builds {@code AwsSecretsManagerClient.fromEnv()} and returns its {@code secrets()} provider.
   * Services that log in (AppRole, ...) replace this method.
   *
   * @param bootstrap parsed GROW_SECRETS_* bootstrap
   * @param env environment the bootstrap was read from
   * @return the connection
   */
  public static SecretsConnection connect(SecretsBootstrap bootstrap, Map<String, String> env) {
    AwsSecretsManagerClient client = AwsSecretsManagerClient.fromEnv();
    try {
      Object provider = client.getClass().getMethod("secrets").invoke(client);
      return new SecretsConnection((SecretsProvider) provider, null, client::close);
    } catch (ReflectiveOperationException | ClassCastException e) {
      client.close();
      throw new UnsupportedException(
          "loadConfig: AwsSecretsManagerClient has no secrets() provider");
    }
  }
}
