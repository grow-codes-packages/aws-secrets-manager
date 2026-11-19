package codes.grow.packages.awssecretsmanager;

import java.time.Instant;

/**
 * Result of {@code deleteSecret}.
 *
 * @param arn full ARN
 * @param name secret name
 * @param deletionDate when the secret will be (or was) deleted, or {@code null}
 */
public record DeleteSecretResult(String arn, String name, Instant deletionDate) {}
