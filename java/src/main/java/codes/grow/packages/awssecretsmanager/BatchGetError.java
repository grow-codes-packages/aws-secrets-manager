package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.ErrorCode;

/**
 * A per-secret failure of {@code batchGetSecretValue} (the call itself succeeded).
 *
 * @param secretId the requested id, or {@code null}
 * @param errorCode AWS error code, e.g. {@code ResourceNotFoundException}, or {@code null}
 * @param message AWS message, or {@code null}
 */
public record BatchGetError(String secretId, String errorCode, String message) {
  /**
   * Returns the canonical error code of {@link #errorCode()}.
   *
   * @return the code ({@code UNAVAILABLE} for unknown codes)
   */
  public ErrorCode code() {
    return AwsErrors.codeFor(errorCode).orElse(ErrorCode.UNAVAILABLE);
  }

  @Override
  public String toString() {
    return "BatchGetError{secretId=" + secretId + ", errorCode=" + errorCode + "}";
  }
}
