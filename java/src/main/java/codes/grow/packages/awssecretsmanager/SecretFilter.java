package codes.grow.packages.awssecretsmanager;

import java.util.List;
import java.util.Objects;

/**
 * A {@code ListSecrets} / {@code BatchGetSecretValue} filter. A value prefixed with {@code !}
 * negates it (AWS).
 *
 * @param key filter key, one of the constants of this record
 * @param values values to match
 */
public record SecretFilter(String key, List<String> values) {
  /** Name filter key (prefix match). */
  public static final String NAME = "name";

  /** Description filter key. */
  public static final String DESCRIPTION = "description";

  /** Tag key filter key. */
  public static final String TAG_KEY = "tag-key";

  /** Tag value filter key. */
  public static final String TAG_VALUE = "tag-value";

  /** Primary region filter key. */
  public static final String PRIMARY_REGION = "primary-region";

  /** Owning service filter key. */
  public static final String OWNING_SERVICE = "owning-service";

  /** Filter key matching every field. */
  public static final String ALL = "all";

  /** Validates and copies the values. */
  public SecretFilter {
    Objects.requireNonNull(key, "key");
    values = List.copyOf(values);
  }

  /**
   * Creates a filter.
   *
   * @param key filter key
   * @param values values
   * @return the filter
   */
  public static SecretFilter of(String key, String... values) {
    return new SecretFilter(key, List.of(values));
  }

  /**
   * Creates a name filter.
   *
   * @param values name prefixes
   * @return the filter
   */
  public static SecretFilter name(String... values) {
    return of(NAME, values);
  }
}
