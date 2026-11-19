package codes.grow.packages.awssecretsmanager;

import java.util.Objects;

/**
 * A replica region of {@code createSecret}.
 *
 * @param region region name
 * @param kmsKeyId KMS key of the replica, or {@code null} for the default
 */
public record ReplicaRegion(String region, String kmsKeyId) {
  /** Validates the region. */
  public ReplicaRegion {
    Objects.requireNonNull(region, "region");
  }

  /**
   * Creates a replica region with the default KMS key.
   *
   * @param region region name
   * @return the replica region
   */
  public static ReplicaRegion of(String region) {
    return new ReplicaRegion(region, null);
  }
}
