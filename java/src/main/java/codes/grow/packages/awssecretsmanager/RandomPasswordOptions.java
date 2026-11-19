package codes.grow.packages.awssecretsmanager;

/**
 * Options of {@code getRandomPassword}.
 *
 * <p>Every component is optional: {@code null} means "not set" (the AWS default applies).
 *
 * @param length Password length 1–4096 (default 32).
 * @param excludeCharacters Characters that must not appear.
 * @param excludeNumbers Whether digits are excluded.
 * @param excludePunctuation Whether punctuation is excluded.
 * @param excludeUppercase Whether uppercase letters are excluded.
 * @param excludeLowercase Whether lowercase letters are excluded.
 * @param includeSpace Whether the space character may appear.
 * @param requireEachIncludedType Whether at least one character of every included type is required
 *     (AWS default true).
 */
public record RandomPasswordOptions(
    Integer length,
    String excludeCharacters,
    Boolean excludeNumbers,
    Boolean excludePunctuation,
    Boolean excludeUppercase,
    Boolean excludeLowercase,
    Boolean includeSpace,
    Boolean requireEachIncludedType) {
  /**
   * Returns options with every field unset.
   *
   * @return empty options
   */
  public static RandomPasswordOptions none() {
    return new RandomPasswordOptions(null, null, null, null, null, null, null, null);
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
    b.length = length;
    b.excludeCharacters = excludeCharacters;
    b.excludeNumbers = excludeNumbers;
    b.excludePunctuation = excludePunctuation;
    b.excludeUppercase = excludeUppercase;
    b.excludeLowercase = excludeLowercase;
    b.includeSpace = includeSpace;
    b.requireEachIncludedType = requireEachIncludedType;
    return b;
  }

  /** Builder of {@link RandomPasswordOptions}. */
  public static final class Builder {
    private Integer length;
    private String excludeCharacters;
    private Boolean excludeNumbers;
    private Boolean excludePunctuation;
    private Boolean excludeUppercase;
    private Boolean excludeLowercase;
    private Boolean includeSpace;
    private Boolean requireEachIncludedType;

    private Builder() {}

    /**
     * Sets password length 1–4096 (default 32).
     *
     * @param length the value
     * @return this builder
     */
    public Builder length(Integer length) {
      this.length = length;
      return this;
    }

    /**
     * Sets characters that must not appear.
     *
     * @param excludeCharacters the value
     * @return this builder
     */
    public Builder excludeCharacters(String excludeCharacters) {
      this.excludeCharacters = excludeCharacters;
      return this;
    }

    /**
     * Sets whether digits are excluded.
     *
     * @param excludeNumbers the value
     * @return this builder
     */
    public Builder excludeNumbers(Boolean excludeNumbers) {
      this.excludeNumbers = excludeNumbers;
      return this;
    }

    /**
     * Sets whether punctuation is excluded.
     *
     * @param excludePunctuation the value
     * @return this builder
     */
    public Builder excludePunctuation(Boolean excludePunctuation) {
      this.excludePunctuation = excludePunctuation;
      return this;
    }

    /**
     * Sets whether uppercase letters are excluded.
     *
     * @param excludeUppercase the value
     * @return this builder
     */
    public Builder excludeUppercase(Boolean excludeUppercase) {
      this.excludeUppercase = excludeUppercase;
      return this;
    }

    /**
     * Sets whether lowercase letters are excluded.
     *
     * @param excludeLowercase the value
     * @return this builder
     */
    public Builder excludeLowercase(Boolean excludeLowercase) {
      this.excludeLowercase = excludeLowercase;
      return this;
    }

    /**
     * Sets whether the space character may appear.
     *
     * @param includeSpace the value
     * @return this builder
     */
    public Builder includeSpace(Boolean includeSpace) {
      this.includeSpace = includeSpace;
      return this;
    }

    /**
     * Sets whether at least one character of every included type is required (AWS default true).
     *
     * @param requireEachIncludedType the value
     * @return this builder
     */
    public Builder requireEachIncludedType(Boolean requireEachIncludedType) {
      this.requireEachIncludedType = requireEachIncludedType;
      return this;
    }

    /**
     * Builds the options.
     *
     * @return the options
     */
    public RandomPasswordOptions build() {
      return new RandomPasswordOptions(
          length,
          excludeCharacters,
          excludeNumbers,
          excludePunctuation,
          excludeUppercase,
          excludeLowercase,
          includeSpace,
          requireEachIncludedType);
    }
  }
}
