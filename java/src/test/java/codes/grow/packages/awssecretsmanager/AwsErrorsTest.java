package codes.grow.packages.awssecretsmanager;

import static org.assertj.core.api.Assertions.assertThat;

import codes.grow.packages.awssecretsmanager.core.AwsSecretsManagerException;
import codes.grow.packages.awssecretsmanager.core.ErrorCode;
import codes.grow.packages.awssecretsmanager.core.NotFoundException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.AbortedException;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

/** Error mapping by AWS error code (API.md section 1.1). */
class AwsErrorsTest {
  private static final List<String> SECRETS = List.of("leaky-secret-value");

  private static AwsServiceException service(int status, String code, String message, String raw) {
    AwsErrorDetails.Builder d =
        AwsErrorDetails.builder()
            .errorCode(code)
            .errorMessage(message)
            .sdkHttpResponse(SdkHttpResponse.builder().statusCode(status).build());
    if (raw != null) {
      d.rawResponse(SdkBytes.fromUtf8String(raw));
    }
    return SecretsManagerException.builder()
        .statusCode(status)
        .requestId("rid")
        .awsErrorDetails(d.build())
        .message(message)
        .build();
  }

  private static AwsSecretsManagerException map(Throwable t) {
    return AwsErrors.map(t, "op x", SECRETS, Duration.ofSeconds(7));
  }

  @Test
  void mapsEveryKnownCodeRegardlessOfStatus() {
    AwsErrors.CODES.forEach(
        (code, expected) -> {
          AwsSecretsManagerException e = map(service(400, code, "m", null));
          assertThat(e.code()).as(code).isEqualTo(expected);
          assertThat(e.getMessage()).isEqualTo("op x: " + code + ": m (HTTP 400)");
          assertThat(e.requestId()).contains("rid");
        });
    assertThat(AwsErrors.codeFor(null)).isEmpty();
    assertThat(AwsErrors.codeFor("Nope")).isEmpty();
  }

  @Test
  void fallsBackToTheStatusAndTheBody() {
    String xmlAuth =
        "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>";
    assertThat(map(service(403, null, null, xmlAuth)).code()).isEqualTo(ErrorCode.AUTHENTICATION);
    assertThat(map(service(403, "403", null, "The security token included is invalid")).code())
        .isEqualTo(ErrorCode.AUTHENTICATION);
    assertThat(map(service(403, null, null, "<Code>Other</Code>")).code())
        .isEqualTo(ErrorCode.PERMISSION_DENIED);
    assertThat(map(service(403, null, null, null)).code()).isEqualTo(ErrorCode.PERMISSION_DENIED);
    assertThat(map(service(404, "Unknown", "x", null)).code()).isEqualTo(ErrorCode.NOT_FOUND);
    assertThat(map(service(429, null, null, "")).code()).isEqualTo(ErrorCode.RATE_LIMITED);
    assertThat(map(service(502, null, null, "<html>")).getMessage())
        .isEqualTo("op x: service unavailable (HTTP 502)");
    assertThat(map(service(0, null, null, null)).code()).isEqualTo(ErrorCode.UNAVAILABLE);
    assertThat(map(service(0, null, null, null)).httpStatus()).isEmpty();
    assertThat(map(service(400, "Weird", "Weird", null)).getMessage())
        .isEqualTo("op x: Weird (HTTP 400)");
    assertThat(map(service(400, "Weird", null, null)).getMessage())
        .isEqualTo("op x: Weird (HTTP 400)");
    AwsSecretsManagerException json =
        map(
            service(
                400,
                null,
                null,
                "{\"__type\":\"com.amazonaws.secretsmanager#ResourceNotFoundException:x\"}"));
    assertThat(json.code()).isEqualTo(ErrorCode.NOT_FOUND);
    // unsupported only for emulator gaps without an AWS error code
    assertThat(
            AwsErrors.map(
                    service(500, null, null, "<html>"), "validateResourcePolicy", SECRETS, null)
                .code())
        .isEqualTo(ErrorCode.UNSUPPORTED);
    assertThat(
            AwsErrors.map(service(501, null, null, ""), "validateResourcePolicy", SECRETS, null)
                .code())
        .isEqualTo(ErrorCode.UNSUPPORTED);
    assertThat(AwsErrors.map(service(500, null, null, "<html>"), "ping", SECRETS, null).code())
        .isEqualTo(ErrorCode.UNAVAILABLE);
    assertThat(
            AwsErrors.map(
                    service(500, "InternalServiceError", "x", null),
                    "validateResourcePolicy",
                    SECRETS,
                    null)
                .code())
        .isEqualTo(ErrorCode.UNAVAILABLE);
  }

  @Test
  void bodyCodeParsing() {
    assertThat(AwsErrors.codeFromBody(null)).isEmpty();
    assertThat(AwsErrors.codeFromBody("")).isEmpty();
    assertThat(AwsErrors.codeFromBody("plain")).isEmpty();
    assertThat(AwsErrors.codeFromBody("<Code> AccessDenied </Code>")).contains("AccessDenied");
    assertThat(AwsErrors.codeFromBody("{\"code\":\"Throttling\"}")).contains("Throttling");
  }

  @Test
  void messagesAreRedactedCollapsedAndTruncated() {
    AwsSecretsManagerException e =
        map(
            service(
                400,
                "ValidationException",
                "bad   value\n leaky-secret-value " + "x".repeat(400),
                null));
    assertThat(e.getMessage())
        .doesNotContain("leaky-secret-value")
        .contains("bad value [REDACTED]");
    assertThat(e.getMessage().length()).isLessThan(400);
  }

  @Test
  void awsErrorCodeWalksCauses() {
    AwsSecretsManagerException mapped = map(service(400, "ResourceExistsException", "m", null));
    assertThat(AwsErrors.awsErrorCode(mapped)).contains("ResourceExistsException");
    assertThat(AwsErrors.awsErrorCode(new NotFoundException("x"))).isEmpty();
    assertThat(AwsErrors.awsErrorCode(null)).isEmpty();
    assertThat(AwsErrors.awsErrorCode(SecretsManagerException.builder().statusCode(400).build()))
        .isEmpty();
  }

  @Test
  void clientSideFailures() {
    assertThat(map(ApiCallTimeoutException.create(7000)).getMessage())
        .isEqualTo("op x: total timeout of 7000 ms exceeded");
    assertThat(AwsErrors.map(ApiCallTimeoutException.create(1), "op", SECRETS, null).getMessage())
        .isEqualTo("op: total timeout exceeded");
    assertThat(map(ApiCallAttemptTimeoutException.create(5)).code()).isEqualTo(ErrorCode.TIMEOUT);
    assertThat(map(SdkClientException.create("io", new SocketTimeoutException("read"))).code())
        .isEqualTo(ErrorCode.TIMEOUT);
    assertThat(map(AbortedException.create("x")).code()).isEqualTo(ErrorCode.CANCELLED);
    assertThat(map(SdkClientException.create("io", new InterruptedIOException("i"))).code())
        .isEqualTo(ErrorCode.CANCELLED);
    assertThat(map(new CancellationException()).code()).isEqualTo(ErrorCode.CANCELLED);
    assertThat(
            map(SdkClientException.create("Unable to load region from any of the providers"))
                .code())
        .isEqualTo(ErrorCode.CONFIG);
    assertThat(
            map(SdkClientException.create("Unable to load credentials from any of the providers"))
                .code())
        .isEqualTo(ErrorCode.AUTHENTICATION);
    assertThat(map(SdkClientException.create("x", new ConnectException("refused"))).getMessage())
        .isEqualTo("op x: network error: ConnectException");
    assertThat(map(SdkClientException.create("x", new UnknownHostException("h"))).code())
        .isEqualTo(ErrorCode.UNAVAILABLE);
    AwsSecretsManagerException other = map(new IllegalStateException("boom leaky-secret-value"));
    assertThat(other.code()).isEqualTo(ErrorCode.UNAVAILABLE);
    assertThat(other.getMessage()).isEqualTo("op x: service unavailable: boom [REDACTED]");
    NotFoundException nf = new NotFoundException("x");
    assertThat(map(nf)).isSameAs(nf);
    assertThat(map(new CompletionException(new ExecutionException(nf)))).isSameAs(nf);
    assertThat(AwsErrors.reasonFor(ErrorCode.CANCELLED)).isEqualTo("service unavailable");
    for (ErrorCode c : ErrorCode.values()) {
      assertThat(AwsErrors.reasonFor(c)).isNotEmpty();
    }
  }
}
