package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.secrets.SecretValue;
import java.time.Instant;
import java.util.List;

/**
 * A secret value read from AWS ({@code GetSecretValue}, {@code BatchGetSecretValue}). {@link
 * #toString()} never prints the value.
 *
 * @param arn full ARN
 * @param name secret name
 * @param versionId version id, or {@code null}
 * @param versionStages stage labels attached to this version
 * @param createdDate creation time of this version, or {@code null}
 * @param binary true when the secret stores {@code SecretBinary}, false for {@code SecretString}
 * @param value the redacting value ({@code value.version()} is the version id)
 */
public record AwsSecretValue(
    String arn,
    String name,
    String versionId,
    List<String> versionStages,
    Instant createdDate,
    boolean binary,
    SecretValue value) {
  /** Copies the stage list. */
  public AwsSecretValue {
    versionStages = List.copyOf(versionStages);
  }
}
