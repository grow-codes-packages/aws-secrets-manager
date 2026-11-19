package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code deleteSecret}: a recovery window or an immediate delete, never both.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param recoveryWindowDays Days before the secret is purged (7–30; AWS default 30).
 * @param forceDeleteWithoutRecovery Whether the secret is deleted immediately without recovery.
 */
public record DeleteSecretOptions(Integer recoveryWindowDays, Boolean forceDeleteWithoutRecovery) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static DeleteSecretOptions none() {
    return new DeleteSecretOptions(null, null);
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
    b.recoveryWindowDays = recoveryWindowDays;
    b.forceDeleteWithoutRecovery = forceDeleteWithoutRecovery;
    return b;
  }

  /** Builder of {@link DeleteSecretOptions}. */
  public static final class Builder {
    private Integer recoveryWindowDays;
    private Boolean forceDeleteWithoutRecovery;

    private Builder() {}

    /**
     * Sets days before the secret is purged (7–30; AWS default 30).
     *
     * @param recoveryWindowDays the value
     * @return this builder
     */
    public Builder recoveryWindowDays(Integer recoveryWindowDays) {
      this.recoveryWindowDays = recoveryWindowDays;
      return this;
    }

    /**
     * Sets whether the secret is deleted immediately without recovery.
     *
     * @param forceDeleteWithoutRecovery the value
     * @return this builder
     */
    public Builder forceDeleteWithoutRecovery(Boolean forceDeleteWithoutRecovery) {
      this.forceDeleteWithoutRecovery = forceDeleteWithoutRecovery;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public DeleteSecretOptions build() {
      return new DeleteSecretOptions(recoveryWindowDays, forceDeleteWithoutRecovery);
    }
  }
}
