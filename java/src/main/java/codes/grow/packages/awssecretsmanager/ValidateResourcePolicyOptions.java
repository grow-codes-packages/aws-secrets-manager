package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code validateResourcePolicy}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param secretId Secret the policy would be attached to.
 */
public record ValidateResourcePolicyOptions(String secretId) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static ValidateResourcePolicyOptions none() {
    return new ValidateResourcePolicyOptions(null);
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
    b.secretId = secretId;
    return b;
  }

  /** Builder of {@link ValidateResourcePolicyOptions}. */
  public static final class Builder {
    private String secretId;

    private Builder() {}

    /**
     * Sets secret the policy would be attached to.
     *
     * @param secretId the value
     * @return this builder
     */
    public Builder secretId(String secretId) {
      this.secretId = secretId;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public ValidateResourcePolicyOptions build() {
      return new ValidateResourcePolicyOptions(secretId);
    }
  }
}
