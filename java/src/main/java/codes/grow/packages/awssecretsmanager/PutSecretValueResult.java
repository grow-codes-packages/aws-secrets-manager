package codes.grow.packages.awssecretsmanager;

import java.util.List;

/**
 * Result of {@code putSecretValue}.
 *
 * @param arn full ARN
 * @param name secret name
 * @param versionId id of the new version
 * @param versionStages stage labels of the new version
 */
public record PutSecretValueResult(
    String arn, String name, String versionId, List<String> versionStages) {
  /** Copies the stage list. */
  public PutSecretValueResult {
    versionStages = List.copyOf(versionStages);
  }
}
