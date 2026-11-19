package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code rotateSecret}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param lambdaArn Rotation Lambda ARN (omit for managed rotation or to keep the current function).
 * @param rules Rotation schedule.
 * @param rotateImmediately Whether to rotate now (AWS default true).
 * @param clientRequestToken Idempotency token; the AWS SDK fills one when unset.
 */
public record RotateSecretOptions(
    String lambdaArn, RotationRules rules, Boolean rotateImmediately, String clientRequestToken) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static RotateSecretOptions none() {
    return new RotateSecretOptions(null, null, null, null);
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
    b.lambdaArn = lambdaArn;
    b.rules = rules;
    b.rotateImmediately = rotateImmediately;
    b.clientRequestToken = clientRequestToken;
    return b;
  }

  /** Builder of {@link RotateSecretOptions}. */
  public static final class Builder {
    private String lambdaArn;
    private RotationRules rules;
    private Boolean rotateImmediately;
    private String clientRequestToken;

    private Builder() {}

    /**
     * Sets rotation Lambda ARN (omit for managed rotation or to keep the current function).
     *
     * @param lambdaArn the value
     * @return this builder
     */
    public Builder lambdaArn(String lambdaArn) {
      this.lambdaArn = lambdaArn;
      return this;
    }

    /**
     * Sets rotation schedule.
     *
     * @param rules the value
     * @return this builder
     */
    public Builder rules(RotationRules rules) {
      this.rules = rules;
      return this;
    }

    /**
     * Sets whether to rotate now (AWS default true).
     *
     * @param rotateImmediately the value
     * @return this builder
     */
    public Builder rotateImmediately(Boolean rotateImmediately) {
      this.rotateImmediately = rotateImmediately;
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
    public RotateSecretOptions build() {
      return new RotateSecretOptions(lambdaArn, rules, rotateImmediately, clientRequestToken);
    }
  }
}
