package codes.grow.packages.awssecretsmanager;

/**
 * One problem found by {@code validateResourcePolicy}.
 *
 * @param checkName name of the check, or {@code null}
 * @param errorMessage description, or {@code null}
 */
public record PolicyValidationError(String checkName, String errorMessage) {}
