package codes.grow.packages.awssecretsmanager;

import java.util.List;

/**
 * Selects the secrets of {@code batchGetSecretValue}: a list of ids (names or ARNs) or filters,
 * never both.
 *
 * @param ids secret ids, or {@code null}
 * @param filters filters, or {@code null}
 */
public record BatchGetSelector(List<String> ids, List<SecretFilter> filters) {
  /** Copies the lists. */
  public BatchGetSelector {
    ids = ids == null ? null : List.copyOf(ids);
    filters = filters == null ? null : List.copyOf(filters);
  }

  /**
   * Selects by ids.
   *
   * @param ids names or ARNs
   * @return the selector
   */
  public static BatchGetSelector ids(List<String> ids) {
    return new BatchGetSelector(ids, null);
  }

  /**
   * Selects by ids.
   *
   * @param ids names or ARNs
   * @return the selector
   */
  public static BatchGetSelector ids(String... ids) {
    return new BatchGetSelector(List.of(ids), null);
  }

  /**
   * Selects by filters.
   *
   * @param filters filters
   * @return the selector
   */
  public static BatchGetSelector filters(List<SecretFilter> filters) {
    return new BatchGetSelector(null, filters);
  }

  /**
   * Selects by filters.
   *
   * @param filters filters
   * @return the selector
   */
  public static BatchGetSelector filters(SecretFilter... filters) {
    return new BatchGetSelector(null, List.of(filters));
  }
}
