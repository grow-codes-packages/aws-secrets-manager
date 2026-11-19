package codes.grow.packages.awssecretsmanager;

import java.util.List;

/**
 * Result of {@code validateResourcePolicy}.
 *
 * @param policyValidationPassed whether the policy passed every check
 * @param validationErrors problems found
 */
public record ValidateResourcePolicyResult(
    boolean policyValidationPassed, List<PolicyValidationError> validationErrors) {
  /** Copies the list. */
  public ValidateResourcePolicyResult {
    validationErrors = List.copyOf(validationErrors);
  }
}
