package codes.grow.packages.awssecretsmanager;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Options of {@code createSecret}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param description Description of the secret.
 * @param kmsKeyId KMS key id, ARN or alias (default {@code aws/secretsmanager}).
 * @param tags Tags of the secret.
 * @param clientRequestToken Idempotency token (32–64 characters, becomes the version id); the AWS
 *     SDK fills one when unset.
 * @param addReplicaRegions Regions to replicate the secret to.
 * @param forceOverwriteReplicaSecret Whether an existing secret of the same name in a replica
 *     region is overwritten.
 */
public record CreateSecretOptions(
    String description,
    String kmsKeyId,
    Map<String, String> tags,
    String clientRequestToken,
    List<ReplicaRegion> addReplicaRegions,
    Boolean forceOverwriteReplicaSecret) {
  /** Copies collections so the options stay immutable. */
  public CreateSecretOptions {
    tags = tags == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(tags));
    addReplicaRegions = addReplicaRegions == null ? null : List.copyOf(addReplicaRegions);
  }

  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static CreateSecretOptions none() {
    return new CreateSecretOptions(null, null, null, null, null, null);
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns a builder pre-filled with these options.
   *
   * @return a new builder
   */
  public Builder toBuilder() {
    Builder b = new Builder();
    b.description = description;
    b.kmsKeyId = kmsKeyId;
    b.tags = tags;
    b.clientRequestToken = clientRequestToken;
    b.addReplicaRegions = addReplicaRegions;
    b.forceOverwriteReplicaSecret = forceOverwriteReplicaSecret;
    return b;
  }

  /** Builder of {@link CreateSecretOptions}. */
  public static final class Builder {
    private String description;
    private String kmsKeyId;
    private Map<String, String> tags;
    private String clientRequestToken;
    private List<ReplicaRegion> addReplicaRegions;
    private Boolean forceOverwriteReplicaSecret;

    private Builder() {}

    /**
     * Sets description of the secret.
     *
     * @param description the value
     * @return this builder
     */
    public Builder description(String description) {
      this.description = description;
      return this;
    }

    /**
     * Sets kMS key id, ARN or alias (default {@code aws/secretsmanager}).
     *
     * @param kmsKeyId the value
     * @return this builder
     */
    public Builder kmsKeyId(String kmsKeyId) {
      this.kmsKeyId = kmsKeyId;
      return this;
    }

    /**
     * Sets tags of the secret.
     *
     * @param tags the value
     * @return this builder
     */
    public Builder tags(Map<String, String> tags) {
      this.tags = tags;
      return this;
    }

    /**
     * Sets idempotency token (32–64 characters, becomes the version id); the AWS SDK fills one when
     * unset.
     *
     * @param clientRequestToken the value
     * @return this builder
     */
    public Builder clientRequestToken(String clientRequestToken) {
      this.clientRequestToken = clientRequestToken;
      return this;
    }

    /**
     * Sets regions to replicate the secret to.
     *
     * @param addReplicaRegions the value
     * @return this builder
     */
    public Builder addReplicaRegions(List<ReplicaRegion> addReplicaRegions) {
      this.addReplicaRegions = addReplicaRegions;
      return this;
    }

    /**
     * Sets whether an existing secret of the same name in a replica region is overwritten.
     *
     * @param forceOverwriteReplicaSecret the value
     * @return this builder
     */
    public Builder forceOverwriteReplicaSecret(Boolean forceOverwriteReplicaSecret) {
      this.forceOverwriteReplicaSecret = forceOverwriteReplicaSecret;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public CreateSecretOptions build() {
      return new CreateSecretOptions(
          description,
          kmsKeyId,
          tags,
          clientRequestToken,
          addReplicaRegions,
          forceOverwriteReplicaSecret);
    }
  }
}
