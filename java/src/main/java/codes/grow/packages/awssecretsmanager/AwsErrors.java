package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.AwsSecretsManagerException;
import codes.grow.packages.awssecretsmanager.core.ErrorCode;
import codes.grow.packages.awssecretsmanager.core.Redaction;
import codes.grow.packages.awssecretsmanager.core.RetryPolicy;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.AbortedException;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;

/**
 * Maps AWS SDK errors to the SPEC section 2.1 error classes by <b>AWS error code</b> (AWS JSON
 * services answer HTTP 400 for throttling and access denied, so status mapping alone is wrong; see
 * API.md section 1.1). The HTTP status is only the fallback.
 */
public final class AwsErrors {
  /** AWS error code to canonical code. */
  public static final Map<String, ErrorCode> CODES =
      Map.ofEntries(
          Map.entry("ResourceNotFoundException", ErrorCode.NOT_FOUND),
          Map.entry("ResourceExistsException", ErrorCode.CONFLICT),
          Map.entry("PreconditionNotMetException", ErrorCode.CONFLICT),
          Map.entry("InvalidRequestException", ErrorCode.CONFLICT),
          Map.entry("InvalidParameterException", ErrorCode.VALIDATION),
          Map.entry("InvalidParameterValue", ErrorCode.VALIDATION),
          Map.entry("ValidationException", ErrorCode.VALIDATION),
          Map.entry("InvalidNextTokenException", ErrorCode.VALIDATION),
          Map.entry("MalformedPolicyDocumentException", ErrorCode.VALIDATION),
          Map.entry("PublicPolicyException", ErrorCode.VALIDATION),
          Map.entry("LimitExceededException", ErrorCode.VALIDATION),
          Map.entry("EncryptionFailure", ErrorCode.VALIDATION),
          Map.entry("DecryptionFailure", ErrorCode.VALIDATION),
          Map.entry("SerializationException", ErrorCode.VALIDATION),
          Map.entry("AccessDeniedException", ErrorCode.PERMISSION_DENIED),
          Map.entry("AccessDenied", ErrorCode.PERMISSION_DENIED),
          Map.entry("UnrecognizedClientException", ErrorCode.AUTHENTICATION),
          Map.entry("InvalidClientTokenId", ErrorCode.AUTHENTICATION),
          Map.entry("InvalidSignatureException", ErrorCode.AUTHENTICATION),
          Map.entry("SignatureDoesNotMatch", ErrorCode.AUTHENTICATION),
          Map.entry("IncompleteSignature", ErrorCode.AUTHENTICATION),
          Map.entry("IncompleteSignatureException", ErrorCode.AUTHENTICATION),
          Map.entry("MissingAuthenticationToken", ErrorCode.AUTHENTICATION),
          Map.entry("MissingAuthenticationTokenException", ErrorCode.AUTHENTICATION),
          Map.entry("ExpiredToken", ErrorCode.AUTHENTICATION),
          Map.entry("ExpiredTokenException", ErrorCode.AUTHENTICATION),
          Map.entry("InvalidAccessKeyId", ErrorCode.AUTHENTICATION),
          Map.entry("ThrottlingException", ErrorCode.RATE_LIMITED),
          Map.entry("Throttling", ErrorCode.RATE_LIMITED),
          Map.entry("TooManyRequestsException", ErrorCode.RATE_LIMITED),
          Map.entry("RequestLimitExceeded", ErrorCode.RATE_LIMITED),
          Map.entry("InternalServiceError", ErrorCode.UNAVAILABLE),
          Map.entry("InternalServiceErrorException", ErrorCode.UNAVAILABLE),
          Map.entry("InternalFailure", ErrorCode.UNAVAILABLE),
          Map.entry("ServiceUnavailable", ErrorCode.UNAVAILABLE),
          Map.entry("ServiceUnavailableException", ErrorCode.UNAVAILABLE),
          Map.entry("RequestTimeout", ErrorCode.TIMEOUT),
          Map.entry("RequestTimeoutException", ErrorCode.TIMEOUT));

  /**
   * Operations some emulators do not implement: an HTTP 500/501 without an AWS error code maps to
   * {@code UNSUPPORTED} for them (Moto 5.2.4 {@code ValidateResourcePolicy}).
   */
  static final Set<String> EMULATOR_GAPS = Set.of("validateResourcePolicy");

  /** Markers of an authentication failure in a 403 body without a parseable error code. */
  private static final List<String> AUTH_MARKERS =
      List.of(
          "InvalidClientTokenId", "SignatureDoesNotMatch", "security token", "UnrecognizedClient");

  private static final Pattern XML_CODE = Pattern.compile("<Code>\\s*([^<\\s]+)\\s*</Code>");
  private static final Pattern JSON_TYPE =
      Pattern.compile("\"(?:__type|code)\"\\s*:\\s*\"([^\"]+)\"");

  private AwsErrors() {}

  /**
   * Returns the canonical code of an AWS error code.
   *
   * @param awsCode AWS error code such as {@code ResourceNotFoundException}, may be null
   * @return the code, or empty when unknown
   */
  public static Optional<ErrorCode> codeFor(String awsCode) {
    return awsCode == null ? Optional.empty() : Optional.ofNullable(CODES.get(awsCode));
  }

  /**
   * Returns the AWS error code behind an error (the error itself or one of its causes).
   *
   * @param error any throwable, may be null
   * @return the AWS error code, or empty when the error did not come from an AWS error response
   */
  public static Optional<String> awsErrorCode(Throwable error) {
    Throwable t = error;
    for (int depth = 0; depth < 10 && t != null; depth++) {
      if (t instanceof AwsServiceException) {
        return Optional.ofNullable(codeOf((AwsServiceException) t));
      }
      t = t.getCause();
    }
    return Optional.empty();
  }

  /**
   * Extracts an error code from an XML ({@code <Code>}) or JSON ({@code __type}) error body.
   *
   * @param text body text, may be null
   * @return the code, or empty
   */
  public static Optional<String> codeFromBody(String text) {
    if (text == null || text.isEmpty()) {
      return Optional.empty();
    }
    Matcher xml = XML_CODE.matcher(text);
    if (xml.find()) {
      return Optional.of(xml.group(1));
    }
    Matcher json = JSON_TYPE.matcher(text);
    if (json.find()) {
      String raw = json.group(1);
      String code = raw.substring(raw.lastIndexOf('#') + 1);
      int colon = code.indexOf(':');
      return Optional.of(colon < 0 ? code : code.substring(0, colon));
    }
    return Optional.empty();
  }

  private static String codeOf(AwsServiceException e) {
    AwsErrorDetails d = e.awsErrorDetails();
    String parsed = d == null ? null : d.errorCode();
    if (parsed != null && !parsed.isBlank() && !parsed.chars().allMatch(Character::isDigit)) {
      return parsed;
    }
    return codeFromBody(rawBody(d)).orElse(null);
  }

  private static String rawBody(AwsErrorDetails d) {
    if (d == null || d.rawResponse() == null) {
      return "";
    }
    return d.rawResponse().asUtf8String();
  }

  /**
   * Converts anything the AWS SDK throws into an SDK exception with the message {@code
   * "<operation>: <AwsCode>: <redacted vendor text> (HTTP <status>)"}. Known secret values are
   * redacted; request bodies never appear.
   *
   * @param error the error
   * @param operation Grow operation, e.g. {@code "getSecretValue app/db"}
   * @param knownSecrets values to redact
   * @param totalTimeout the configured total timeout (for the message), may be null
   * @return the mapped exception (an SDK exception is returned unchanged)
   */
  public static AwsSecretsManagerException map(
      Throwable error, String operation, Collection<String> knownSecrets, Duration totalTimeout) {
    Throwable err = unwrap(error);
    if (err instanceof AwsSecretsManagerException) {
      return (AwsSecretsManagerException) err;
    }
    if (err instanceof AwsServiceException) {
      return mapService((AwsServiceException) err, operation, knownSecrets);
    }
    for (Throwable t = err; t != null; t = t.getCause()) {
      if (t instanceof ApiCallTimeoutException) {
        String limit = totalTimeout == null ? "" : " of " + totalTimeout.toMillis() + " ms";
        return AwsSecretsManagerException.of(
            ErrorCode.TIMEOUT,
            operation + ": total timeout" + limit + " exceeded",
            null,
            null,
            null,
            err);
      }
      if (t instanceof ApiCallAttemptTimeoutException
          || t instanceof HttpTimeoutException
          || t instanceof SocketTimeoutException) {
        return AwsSecretsManagerException.of(
            ErrorCode.TIMEOUT, operation + ": request timed out", null, null, null, err);
      }
      if (t instanceof AbortedException
          || t instanceof InterruptedException
          || t instanceof InterruptedIOException
          || t instanceof CancellationException) {
        return AwsSecretsManagerException.of(
            ErrorCode.CANCELLED, operation + ": cancelled", null, null, null, err);
      }
      if (t.getCause() == t) {
        break;
      }
    }
    String text = String.valueOf(err.getMessage());
    String lower = text.toLowerCase(Locale.ROOT);
    if (lower.contains("unable to load region") || lower.contains("region must be specified")) {
      return AwsSecretsManagerException.of(
          ErrorCode.CONFIG,
          operation + ": no AWS region configured (set region or AWS_REGION)",
          null,
          null,
          null,
          err);
    }
    if (lower.contains("unable to load credentials") || lower.contains("credentials provider")) {
      return AwsSecretsManagerException.of(
          ErrorCode.AUTHENTICATION,
          operation + ": no usable AWS credentials found",
          null,
          null,
          null,
          err);
    }
    Throwable root = err;
    while (root.getCause() != null && root.getCause() != root) {
      root = root.getCause();
    }
    if (root instanceof ConnectException || root instanceof UnknownHostException) {
      return AwsSecretsManagerException.of(
          ErrorCode.UNAVAILABLE,
          operation + ": network error: " + root.getClass().getSimpleName(),
          null,
          null,
          null,
          err);
    }
    return AwsSecretsManagerException.of(
        ErrorCode.UNAVAILABLE,
        operation + ": service unavailable: " + clean(text, knownSecrets),
        null,
        null,
        null,
        err);
  }

  private static Throwable unwrap(Throwable t) {
    Throwable cur = t;
    while ((cur instanceof CompletionException || cur instanceof ExecutionException)
        && cur.getCause() != null) {
      cur = cur.getCause();
    }
    return cur;
  }

  private static AwsSecretsManagerException mapService(
      AwsServiceException e, String operation, Collection<String> knownSecrets) {
    int status = e.statusCode();
    AwsErrorDetails d = e.awsErrorDetails();
    String raw = rawBody(d);
    String awsCode = codeOf(e);
    ErrorCode code = awsCode == null ? null : CODES.get(awsCode);
    if (code == null) {
      code = fallback(operation, status, raw, awsCode);
    }
    String vendor =
        d == null || d.errorMessage() == null ? "" : clean(d.errorMessage(), knownSecrets);
    String reason;
    if (awsCode == null) {
      reason = reasonFor(code);
    } else if (vendor.isEmpty() || vendor.equals(awsCode)) {
      reason = awsCode;
    } else {
      reason = awsCode + ": " + vendor;
    }
    Duration retryAfter = null;
    if (code == ErrorCode.RATE_LIMITED && d != null && d.sdkHttpResponse() != null) {
      retryAfter =
          d.sdkHttpResponse()
              .firstMatchingHeader("Retry-After")
              .flatMap(v -> RetryPolicy.parseRetryAfter(v, Instant.now()))
              .orElse(null);
    }
    String suffix = status > 0 ? " (HTTP " + status + ")" : "";
    return AwsSecretsManagerException.of(
        code,
        operation + ": " + reason + suffix,
        status > 0 ? status : null,
        e.requestId(),
        retryAfter,
        e);
  }

  private static ErrorCode fallback(String operation, int status, String raw, String awsCode) {
    String op = operation.split(" ", 2)[0];
    if (status == 403) {
      for (String marker : AUTH_MARKERS) {
        if (raw.contains(marker)) {
          return ErrorCode.AUTHENTICATION;
        }
      }
      return ErrorCode.PERMISSION_DENIED;
    }
    if ((status == 500 || status == 501) && awsCode == null && EMULATOR_GAPS.contains(op)) {
      return ErrorCode.UNSUPPORTED;
    }
    if (status < 400) {
      return ErrorCode.UNAVAILABLE;
    }
    return ErrorCode.forStatus(status);
  }

  private static String clean(String text, Collection<String> knownSecrets) {
    String collapsed = text.replaceAll("\\s+", " ").trim();
    return Redaction.truncate(
        Redaction.redactText(collapsed, knownSecrets), Redaction.MAX_VENDOR_TEXT);
  }

  static String reasonFor(ErrorCode code) {
    switch (code) {
      case AUTHENTICATION:
        return "authentication failed";
      case PERMISSION_DENIED:
        return "permission denied";
      case NOT_FOUND:
        return "not found";
      case CONFLICT:
        return "conflict";
      case RATE_LIMITED:
        return "rate limited";
      case VALIDATION:
        return "invalid request";
      case TIMEOUT:
        return "timed out";
      case UNSUPPORTED:
        return "operation not supported by this server";
      default:
        return "service unavailable";
    }
  }
}
