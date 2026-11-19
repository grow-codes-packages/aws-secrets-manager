package codes.grow.packages.awssecretsmanager;

import java.util.Optional;

/**
 * Result of writes that may create a version.
 *
 * @param arn full ARN
 * @param name secret name
 * @param versionId id of the new version, or {@code null} when no version was created
 */
public record SecretWriteResult(String arn, String name, String versionId) {
  /**
   * Returns the id of the new version.
   *
   * @return the version id, or empty
   */
  public Optional<String> version() {
    return Optional.ofNullable(versionId);
  }
}
