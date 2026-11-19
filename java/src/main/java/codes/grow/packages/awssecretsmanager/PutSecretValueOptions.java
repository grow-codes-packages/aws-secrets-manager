package codes.grow.packages.awssecretsmanager;

import java.util.List;

/**
 * Options of {@code putSecretValue}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param versionStages Stage labels of the new version (default {@code [AWSCURRENT]}).
 * @param clientRequestToken Idempotency token (becomes the version id); the AWS SDK fills one when
 *     unset.
 */
public record PutSecretValueOptions(List<String> versionStages, String clientRequestToken) {
  /** Copies collections so the options stay immutable. */
  public PutSecretValueOptions {
    versionStages = versionStages == null ? null : List.copyOf(versionStages);
  }

  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static PutSecretValueOptions none() {
    return new PutSecretValueOptions(null, null);
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
    b.versionStages = versionStages;
    b.clientRequestToken = clientRequestToken;
    return b;
  }

  /** Builder of {@link PutSecretValueOptions}. */
  public static final class Builder {
    private List<String> versionStages;
    private String clientRequestToken;

    private Builder() {}

    /**
     * Sets stage labels of the new version (default {@code [AWSCURRENT]}).
     *
     * @param versionStages the value
     * @return this builder
     */
    public Builder versionStages(List<String> versionStages) {
      this.versionStages = versionStages;
      return this;
    }

    /**
     * Sets idempotency token (becomes the version id); the AWS SDK fills one when unset.
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
    public PutSecretValueOptions build() {
      return new PutSecretValueOptions(versionStages, clientRequestToken);
    }
  }
}
