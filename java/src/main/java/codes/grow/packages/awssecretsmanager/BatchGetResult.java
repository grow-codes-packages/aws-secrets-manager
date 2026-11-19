package codes.grow.packages.awssecretsmanager;

import java.util.List;

/**
 * Result of {@code batchGetSecretValue}.
 *
 * @param secretValues values, in request order for the id form
 * @param errors ids that could not be read
 */
public record BatchGetResult(List<AwsSecretValue> secretValues, List<BatchGetError> errors) {
  /** Copies the lists. */
  public BatchGetResult {
    secretValues = List.copyOf(secretValues);
    errors = List.copyOf(errors);
  }
}
