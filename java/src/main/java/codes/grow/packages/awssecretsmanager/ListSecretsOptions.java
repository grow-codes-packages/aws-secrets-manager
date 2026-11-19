package codes.grow.packages.awssecretsmanager;

import java.util.List;

/**
 * Options of {@code listSecrets}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param filters Filters; a value prefixed with {@code !} negates it (AWS).
 * @param includePlannedDeletion Whether secrets scheduled for deletion are listed (default false).
 * @param sortOrder Sort by creation date: {@code asc} or {@code desc}.
 * @param maxResults Page size (1–100).
 */
public record ListSecretsOptions(
    List<SecretFilter> filters,
    Boolean includePlannedDeletion,
    String sortOrder,
    Integer maxResults) {
  /** Copies collections so the options stay immutable. */
  public ListSecretsOptions {
    filters = filters == null ? null : List.copyOf(filters);
  }

  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static ListSecretsOptions none() {
    return new ListSecretsOptions(null, null, null, null);
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
    b.filters = filters;
    b.includePlannedDeletion = includePlannedDeletion;
    b.sortOrder = sortOrder;
    b.maxResults = maxResults;
    return b;
  }

  /** Builder of {@link ListSecretsOptions}. */
  public static final class Builder {
    private List<SecretFilter> filters;
    private Boolean includePlannedDeletion;
    private String sortOrder;
    private Integer maxResults;

    private Builder() {}

    /**
     * Sets filters; a value prefixed with {@code !} negates it (AWS).
     *
     * @param filters the value
     * @return this builder
     */
    public Builder filters(List<SecretFilter> filters) {
      this.filters = filters;
      return this;
    }

    /**
     * Sets whether secrets scheduled for deletion are listed (default false).
     *
     * @param includePlannedDeletion the value
     * @return this builder
     */
    public Builder includePlannedDeletion(Boolean includePlannedDeletion) {
      this.includePlannedDeletion = includePlannedDeletion;
      return this;
    }

    /**
     * Sets sort by creation date: {@code asc} or {@code desc}.
     *
     * @param sortOrder the value
     * @return this builder
     */
    public Builder sortOrder(String sortOrder) {
      this.sortOrder = sortOrder;
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
    public ListSecretsOptions build() {
      return new ListSecretsOptions(filters, includePlannedDeletion, sortOrder, maxResults);
    }
  }
}
