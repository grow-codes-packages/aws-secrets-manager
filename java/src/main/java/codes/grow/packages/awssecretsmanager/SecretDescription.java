package codes.grow.packages.awssecretsmanager;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Secret metadata ({@code DescribeSecret}, {@code ListSecrets} entries). Never contains the value.
 * Optional components are {@code null} when AWS omits them.
 *
 * @param arn full ARN
 * @param name secret name
 * @param description description
 * @param kmsKeyId KMS key
 * @param rotationEnabled whether rotation is on
 * @param rotationLambdaArn rotation Lambda
 * @param rotationRules rotation schedule
 * @param lastRotatedDate last rotation
 * @param lastChangedDate last change
 * @param lastAccessedDate last access (day precision)
 * @param deletedDate set when the secret is scheduled for deletion
 * @param nextRotationDate next scheduled rotation
 * @param createdDate creation time
 * @param primaryRegion primary region of a replicated secret
 * @param owningService service that manages the secret
 * @param tags tags as a map
 * @param versionIdsToStages version id to stage labels
 * @param replicationStatus replica regions
 */
public record SecretDescription(
    String arn,
    String name,
    String description,
    String kmsKeyId,
    boolean rotationEnabled,
    String rotationLambdaArn,
    RotationRules rotationRules,
    Instant lastRotatedDate,
    Instant lastChangedDate,
    Instant lastAccessedDate,
    Instant deletedDate,
    Instant nextRotationDate,
    Instant createdDate,
    String primaryRegion,
    String owningService,
    Map<String, String> tags,
    Map<String, List<String>> versionIdsToStages,
    List<ReplicationStatus> replicationStatus) {
  /** Copies the collections. */
  public SecretDescription {
    tags = Collections.unmodifiableMap(new LinkedHashMap<>(tags));
    Map<String, List<String>> stages = new LinkedHashMap<>();
    versionIdsToStages.forEach((k, v) -> stages.put(k, List.copyOf(v)));
    versionIdsToStages = Collections.unmodifiableMap(stages);
    replicationStatus = List.copyOf(replicationStatus);
  }

  /**
   * Returns the version id that carries a stage label.
   *
   * @param stage stage label such as {@code AWSCURRENT}
   * @return the version id, or empty
   */
  public Optional<String> versionWithStage(String stage) {
    for (Map.Entry<String, List<String>> e : versionIdsToStages.entrySet()) {
      if (e.getValue().contains(stage)) {
        return Optional.of(e.getKey());
      }
    }
    return Optional.empty();
  }

  /**
   * Returns the id of the {@code AWSCURRENT} version.
   *
   * @return the version id, or empty for a secret without a value
   */
  public Optional<String> currentVersionId() {
    return versionWithStage(AwsSecretsManagerClient.AWSCURRENT);
  }

  /**
   * Returns whether the secret is scheduled for deletion.
   *
   * @return true when {@link #deletedDate()} is set
   */
  public boolean pendingDeletion() {
    return deletedDate != null;
  }
}
