package codes.grow.packages.awssecretsmanager.integration;

import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
import codes.grow.packages.awssecretsmanager.AwsSecretsManagerSecretsProvider;
import codes.grow.packages.awssecretsmanager.core.EnvReader;
import codes.grow.packages.awssecretsmanager.testing.ConformanceRunner;

/**
 * Conformance targets of this service (owned by the service repository).
 *
 * <p>{@code core} is the client; {@code secrets} is the {@code SecretsProvider} view. AWS exposes
 * no server version, so the {@code version} capability is not declared (docs/compatibility.md);
 * {@code write}, {@code versions} and {@code delete} are supported.
 */
final class Factories {
  /** Capabilities the deployment under test offers (see the scenario {@code requires}). */
  static final String[] CAPABILITIES =
      AwsSecretsManagerSecretsProvider.CAPABILITIES.toArray(new String[0]);

  private Factories() {}

  static void register(ConformanceRunner.Builder runner, EnvReader env) {
    runner.target("core", scenario -> AwsSecretsManagerClient.builder().fromEnv(env).build());
    runner.target(
        "secrets", scenario -> AwsSecretsManagerClient.builder().fromEnv(env).build().secrets());
  }
}
