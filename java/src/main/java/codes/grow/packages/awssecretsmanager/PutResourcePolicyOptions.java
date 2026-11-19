package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code putResourcePolicy}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param blockPublicPolicy Whether policies that grant public access are rejected (AWS default
 *     true).
 */
public record PutResourcePolicyOptions(Boolean blockPublicPolicy) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static PutResourcePolicyOptions none() {
    return new PutResourcePolicyOptions(null);
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
    b.blockPublicPolicy = blockPublicPolicy;
    return b;
  }

  /** Builder of {@link PutResourcePolicyOptions}. */
  public static final class Builder {
    private Boolean blockPublicPolicy;

    private Builder() {}

    /**
     * Sets whether policies that grant public access are rejected (AWS default true).
     *
     * @param blockPublicPolicy the value
     * @return this builder
     */
    public Builder blockPublicPolicy(Boolean blockPublicPolicy) {
      this.blockPublicPolicy = blockPublicPolicy;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public PutResourcePolicyOptions build() {
      return new PutResourcePolicyOptions(blockPublicPolicy);
    }
  }
}
