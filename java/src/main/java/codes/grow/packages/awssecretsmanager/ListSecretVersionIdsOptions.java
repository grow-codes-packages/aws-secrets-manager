package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code listSecretVersionIds}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param includeDeprecated Whether versions without a stage label (deprecated versions) are listed.
 * @param maxResults Page size (1–100).
 */
public record ListSecretVersionIdsOptions(Boolean includeDeprecated, Integer maxResults) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static ListSecretVersionIdsOptions none() {
    return new ListSecretVersionIdsOptions(null, null);
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
    b.includeDeprecated = includeDeprecated;
    b.maxResults = maxResults;
    return b;
  }

  /** Builder of {@link ListSecretVersionIdsOptions}. */
  public static final class Builder {
    private Boolean includeDeprecated;
    private Integer maxResults;

    private Builder() {}

    /**
     * Sets whether versions without a stage label (deprecated versions) are listed.
     *
     * @param includeDeprecated the value
     * @return this builder
     */
    public Builder includeDeprecated(Boolean includeDeprecated) {
      this.includeDeprecated = includeDeprecated;
      return this;
    }

    /**
     * Sets page size (1–100).
     *
     * @param maxResults the value
     * @return this builder
     */
    public Builder maxResults(Integer maxResults) {
      this.maxResults = maxResults;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public ListSecretVersionIdsOptions build() {
      return new ListSecretVersionIdsOptions(includeDeprecated, maxResults);
    }
  }
}
