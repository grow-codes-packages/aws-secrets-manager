// Owned by this repository.
package codes.grow.packages.awssecretsmanager.examples;

import codes.grow.packages.awssecretsmanager.AwsSecretCache;
import codes.grow.packages.awssecretsmanager.AwsSecretValue;
import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
import codes.grow.packages.awssecretsmanager.AwsSecretsManagerSecretsProvider;
import codes.grow.packages.awssecretsmanager.BatchGetResult;
import codes.grow.packages.awssecretsmanager.CreateSecretOptions;
import codes.grow.packages.awssecretsmanager.DeleteSecretOptions;
import codes.grow.packages.awssecretsmanager.GetSecretValueOptions;
import codes.grow.packages.awssecretsmanager.ListSecretsOptions;
import codes.grow.packages.awssecretsmanager.RandomPasswordOptions;
import codes.grow.packages.awssecretsmanager.SecretDescription;
import codes.grow.packages.awssecretsmanager.SecretFilter;
import codes.grow.packages.awssecretsmanager.UpdateSecretOptions;
import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.secrets.DeleteOptions;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * AWS Secrets Manager walkthrough: create, read, version, tag, batch read, list, JSON fields, the
 * random password generator, the AWS-style cache and the {@code SecretsProvider} view. Everything
 * it creates lives under {@code grow-example/<random>/} and is force-deleted at the end.
 */
public final class AwsSecretsManagerExample {
  private AwsSecretsManagerExample() {}

  /**
   * Runs the example.
   *
   * @param args unused
   */
  public static void main(String[] args) {
    String base = "grow-example/" + UUID.randomUUID().toString().substring(0, 8);
    String db = base + "/db";
    try (AwsSecretsManagerClient client = AwsSecretsManagerClient.fromEnv()) {
      try {
        // a strong password from AWS, kept in the redacting Secret type
        Secret password =
            client.getRandomPassword(
                RandomPasswordOptions.builder().length(24).excludePunctuation(true).build());
        client.createSecret(
            db,
            Map.of("username", "app", "password", password.reveal(), "port", 5432),
            CreateSecretOptions.builder().description("example").tags(Map.of("team", "sdk")).build());

        // read it back: the value prints as [REDACTED]
        AwsSecretValue value = client.getSecretValue(db);
        System.out.println("read " + value.name() + " version " + value.versionId() + ": " + value.value());
        System.out.println(
            "port = " + client.getJsonField(db, "port").map(Object::toString).orElse("?"));

        // a new version becomes AWSCURRENT, the old one AWSPREVIOUS
        client.updateSecret(db, UpdateSecretOptions.builder().description("rotated by hand").build());
        client.putSecretValue(db, Map.of("username", "app", "password", "next", "port", 5432));
        AwsSecretValue previous = client.getSecretValue(db, GetSecretValueOptions.ofVersionStage("AWSPREVIOUS"));
        System.out.println("previous version: " + previous.versionId());

        // tags, metadata, listing and batch reads
        client.tagResource(db, Map.of("env", "dev"));
        SecretDescription d = client.describeSecret(db);
        System.out.println("tags: " + d.tags() + ", versions: " + d.versionIdsToStages().keySet());
        for (SecretDescription s :
            client.listSecrets(ListSecretsOptions.builder().filters(List.of(SecretFilter.name(base + "/"))).build())) {
          System.out.println("listed: " + s.name());
        }
        BatchGetResult batch = client.batchGetSecretValue(List.of(db, base + "/missing"));
        System.out.println("batch: " + batch.secretValues().size() + " value(s), " + batch.errors().size() + " error(s)");

        // AWS caching-client semantics: TTL 1 h, refresh only when AWSCURRENT moves
        AwsSecretCache cache = client.secretCache();
        String user = cache.getSecretValue(db).value().jsonNode().get("username").asText();
        System.out.println("cached username: " + user);
        System.out.println("cache: " + cache.stats());

        // the category interface (SecretsProvider): paths, typed getters, soft delete
        try (AwsSecretsManagerSecretsProvider secrets = client.secrets()) {
          secrets.set(base + "/feature-flag", "true");
          System.out.println("flag: " + secrets.getBool(base + "/feature-flag").orElse(false));
          secrets.delete(base + "/feature-flag", DeleteOptions.builder().permanent(true).build());
        }
      } finally {
        for (String name : List.of(db, base + "/feature-flag")) {
          try {
            client.deleteSecret(name, DeleteSecretOptions.builder().forceDeleteWithoutRecovery(true).build());
          } catch (RuntimeException ignored) {
            // already gone
          }
        }
      }
    }
  }
}
