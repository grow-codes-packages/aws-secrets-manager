package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code updateSecretVersionStage}; at least one field is required.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param moveToVersionId Version that receives the label.
 * @param removeFromVersionId Version that loses the label (required when moving {@code
 *     AWSCURRENT}).
 */
public record UpdateSecretVersionStageOptions(String moveToVersionId, String removeFromVersionId) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static UpdateSecretVersionStageOptions none() {
    return new UpdateSecretVersionStageOptions(null, null);
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
    b.moveToVersionId = moveToVersionId;
    b.removeFromVersionId = removeFromVersionId;
    return b;
  }

  /** Builder of {@link UpdateSecretVersionStageOptions}. */
  public static final class Builder {
    private String moveToVersionId;
    private String removeFromVersionId;

    private Builder() {}

    /**
     * Sets version that receives the label.
     *
     * @param moveToVersionId the value
     * @return this builder
     */
    public Builder moveToVersionId(String moveToVersionId) {
      this.moveToVersionId = moveToVersionId;
      return this;
    }

    /**
     * Sets version that loses the label (required when moving {@code AWSCURRENT}).
     *
     * @param removeFromVersionId the value
     * @return this builder
     */
    public Builder removeFromVersionId(String removeFromVersionId) {
      this.removeFromVersionId = removeFromVersionId;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public UpdateSecretVersionStageOptions build() {
      return new UpdateSecretVersionStageOptions(moveToVersionId, removeFromVersionId);
    }
  }
}
