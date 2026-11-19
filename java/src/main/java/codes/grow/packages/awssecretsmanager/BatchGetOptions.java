package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code batchGetSecretValue}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param maxResults Page size for the filter form (1–20).
 */
public record BatchGetOptions(Integer maxResults) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static BatchGetOptions none() {
    return new BatchGetOptions(null);
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
    b.maxResults = maxResults;
    return b;
  }

  /** Builder of {@link BatchGetOptions}. */
  public static final class Builder {
    private Integer maxResults;

    private Builder() {}

    /**
     * Sets page size for the filter form (1–20).
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
    public BatchGetOptions build() {
      return new BatchGetOptions(maxResults);
    }
  }
}
