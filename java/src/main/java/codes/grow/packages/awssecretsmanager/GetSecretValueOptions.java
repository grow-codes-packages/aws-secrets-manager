package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code getSecretValue} and {@code getJsonField}: selects a version by id or by stage
 * label (default {@code AWSCURRENT}).
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param versionId Version id ({@code VersionId}).
 * @param versionStage Stage label, e.g. {@code AWSCURRENT}, {@code AWSPREVIOUS} or a custom label.
 */
public record GetSecretValueOptions(String versionId, String versionStage) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static GetSecretValueOptions none() {
    return new GetSecretValueOptions(null, null);
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
    b.versionId = versionId;
    b.versionStage = versionStage;
    return b;
  }

  /**
   * Selects a version by id.
   *
   * @param versionId the version id
   * @return the options
   */
  public static GetSecretValueOptions ofVersionId(String versionId) {
    return new GetSecretValueOptions(versionId, null);
  }

  /**
   * Selects a version by stage label.
   *
   * @param versionStage the stage label
   * @return the options
   */
  public static GetSecretValueOptions ofVersionStage(String versionStage) {
    return new GetSecretValueOptions(null, versionStage);
  }

  /** Builder of {@link GetSecretValueOptions}. */
  public static final class Builder {
    private String versionId;
    private String versionStage;

    private Builder() {}

    /**
     * Sets version id ({@code VersionId}).
     *
     * @param versionId the value
     * @return this builder
     */
    public Builder versionId(String versionId) {
      this.versionId = versionId;
      return this;
    }

    /**
     * Sets stage label, e.g. {@code AWSCURRENT}, {@code AWSPREVIOUS} or a custom label.
     *
     * @param versionStage the value
     * @return this builder
     */
    public Builder versionStage(String versionStage) {
      this.versionStage = versionStage;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public GetSecretValueOptions build() {
      return new GetSecretValueOptions(versionId, versionStage);
    }
  }
}
