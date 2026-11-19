package codes.grow.packages.awssecretsmanager;

import java.time.Instant;
import java.util.List;

/**
 * One version of a secret ({@code ListSecretVersionIds}).
 *
 * @param versionId version id
 * @param versionStages stage labels
 * @param createdDate creation time, or {@code null}
 * @param lastAccessedDate last access, or {@code null}
 * @param kmsKeyIds KMS keys that encrypt this version
 */
public record SecretVersion(
    String versionId,
    List<String> versionStages,
    Instant createdDate,
    Instant lastAccessedDate,
    List<String> kmsKeyIds) {
  /** Copies the lists. */
  public SecretVersion {
    versionStages = List.copyOf(versionStages);
    kmsKeyIds = List.copyOf(kmsKeyIds);
  }
}
