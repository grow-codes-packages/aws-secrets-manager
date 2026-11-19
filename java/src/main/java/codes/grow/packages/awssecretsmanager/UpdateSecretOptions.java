package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code updateSecret}; a new version is created only when a value is given.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param value New value: {@code String} → {@code SecretString}, {@code byte[]} → {@code
 *     SecretBinary}, anything else JSON-encoded.
 * @param description New description.
 * @param kmsKeyId New KMS key id, ARN or alias.
 * @param clientRequestToken Idempotency token; the AWS SDK fills one when unset.
 */
public record UpdateSecretOptions(
    Object value, String description, String kmsKeyId, String clientRequestToken) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static UpdateSecretOptions none() {
    return new UpdateSecretOptions(null, null, null, null);
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
    b.value = value;
    b.description = description;
    b.kmsKeyId = kmsKeyId;
    b.clientRequestToken = clientRequestToken;
    return b;
  }

  /** Builder of {@link UpdateSecretOptions}. */
  public static final class Builder {
    private Object value;
    private String description;
    private String kmsKeyId;
    private String clientRequestToken;

    private Builder() {}

    /**
     * Sets new value: {@code String} → {@code SecretString}, {@code byte[]} → {@code SecretBinary},
     * anything else JSON-encoded.
     *
     * @param value the value
     * @return this builder
     */
    public Builder value(Object value) {
      this.value = value;
      return this;
    }

    /**
     * Sets new description.
     *
     * @param description the value
     * @return this builder
     */
    public Builder description(String description) {
      this.description = description;
      return this;
    }

    /**
     * Sets new KMS key id, ARN or alias.
     *
     * @param kmsKeyId the value
     * @return this builder
     */
    public Builder kmsKeyId(String kmsKeyId) {
      this.kmsKeyId = kmsKeyId;
      return this;
    }

    /**
     * Sets idempotency token; the AWS SDK fills one when unset.
     *
     * @param clientRequestToken the value
     * @return this builder
     */
    public Builder clientRequestToken(String clientRequestToken) {
      this.clientRequestToken = clientRequestToken;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public UpdateSecretOptions build() {
      return new UpdateSecretOptions(value, description, kmsKeyId, clientRequestToken);
    }
  }
}
