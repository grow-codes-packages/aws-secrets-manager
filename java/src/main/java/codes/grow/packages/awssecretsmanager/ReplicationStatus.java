package codes.grow.packages.awssecretsmanager;

import java.time.Instant;

/**
 * Replication status of one replica region. Components are {@code null} when AWS omits them.
 *
 * @param region replica region
 * @param kmsKeyId KMS key of the replica
 * @param status {@code InSync}, {@code Failed} or {@code InProgress}
 * @param statusMessage status text
 * @param lastAccessedDate last access of the replica
 */
public record ReplicationStatus(
    String region,
    String kmsKeyId,
    String status,
    String statusMessage,
    Instant lastAccessedDate) {}
