// Created by sdk-kit 0.1.0; owned by this repository.
package codes.grow.packages.awssecretsmanager.examples;

import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
import codes.grow.packages.awssecretsmanager.core.AuthenticationException;
import codes.grow.packages.awssecretsmanager.core.HealthStatus;
import codes.grow.packages.awssecretsmanager.core.UnsupportedException;

/** Basics: configuration from the environment, health, ping, server version and errors. */
public final class BasicExample {
  private BasicExample() {}

  /**
   * Runs the example.
   *
   * @param args unused
   */
  public static void main(String[] args) {
    // Reads GROW_AWS_SECRETS_MANAGER_* and the standard AWS variables (AWS_REGION, AWS_ACCESS_KEY_ID,
    // AWS_SECRET_ACCESS_KEY, AWS_PROFILE, AWS_ENDPOINT_URL_SECRETS_MANAGER) plus timeouts, TLS, proxy.
    try (var client = AwsSecretsManagerClient.fromEnv()) {
      HealthStatus health = client.health(); // never throws for an unreachable service
      System.out.println("health: " + health);
      if (!health.healthy()) {
        return;
      }
      try {
        System.out.println("ping: " + client.ping().toMillis() + " ms");
      } catch (AuthenticationException e) {
        // messages never contain credentials
        System.out.println("bad credentials: " + e.getMessage());
      }
      try {
        System.out.println("server version: " + client.serverVersion());
      } catch (UnsupportedException e) {
        System.out.println("AWS exposes no server version (API " + AwsSecretsManagerClient.API_VERSION + ")");
      }
    }
  }
}
