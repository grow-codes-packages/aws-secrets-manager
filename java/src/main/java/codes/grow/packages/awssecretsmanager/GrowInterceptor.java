package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.Hooks;
import codes.grow.packages.awssecretsmanager.core.Logger;
import codes.grow.packages.awssecretsmanager.core.Redaction;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttribute;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.interceptor.SdkExecutionAttribute;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.SdkHttpResponse;

/**
 * Fires the Grow {@code onRequest} / {@code onResponse} hooks for every HTTP attempt the AWS SDK
 * makes (headers redacted) and logs each attempt at debug level without values. A hook or logger
 * that throws never breaks the call.
 */
final class GrowInterceptor implements ExecutionInterceptor {
  private static final ExecutionAttribute<AtomicInteger> ATTEMPTS =
      new ExecutionAttribute<>("GrowAwsSecretsManagerAttempts");
  private static final ExecutionAttribute<Long> STARTED =
      new ExecutionAttribute<>("GrowAwsSecretsManagerAttemptStart");

  /** Attempts of the last call made on this thread (read by the client for {@code onError}). */
  static final ThreadLocal<Integer> LAST_ATTEMPTS = ThreadLocal.withInitial(() -> 1);

  private final Hooks hooks;
  private final Logger logger;

  GrowInterceptor(Hooks hooks, Logger logger) {
    this.hooks = hooks;
    this.logger = logger;
  }

  @Override
  public void beforeExecution(Context.BeforeExecution context, ExecutionAttributes attrs) {
    attrs.putAttribute(ATTEMPTS, new AtomicInteger());
  }

  @Override
  public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes attrs) {
    int attempt = attempts(attrs).incrementAndGet();
    attrs.putAttribute(STARTED, System.nanoTime());
    SdkHttpRequest r = context.httpRequest();
    String url = Redaction.redactUrl(r.getUri().toString());
    Map<String, List<String>> headers = Redaction.redactHeaderLists(r.headers());
    safe(() -> hooks.onRequest(new Hooks.RequestInfo(r.method().name(), url, headers, attempt)));
    safe(
        () ->
            logger.debug(
                "request", Map.of("operation", operation(attrs), "attempt", attempt, "url", url)));
  }

  @Override
  public void afterTransmission(Context.AfterTransmission context, ExecutionAttributes attrs) {
    int attempt = attempts(attrs).get();
    Long start = attrs.getAttribute(STARTED);
    long ms = start == null ? 0 : (System.nanoTime() - start) / 1_000_000;
    SdkHttpRequest r = context.httpRequest();
    SdkHttpResponse res = context.httpResponse();
    String url = Redaction.redactUrl(r.getUri().toString());
    Optional<String> requestId = requestId(res);
    safe(
        () ->
            hooks.onResponse(
                new Hooks.ResponseInfo(
                    r.method().name(), url, res.statusCode(), ms, attempt, requestId)));
    Map<String, Object> fields = new LinkedHashMap<>();
    fields.put("operation", operation(attrs));
    fields.put("status", res.statusCode());
    fields.put("attempt", attempt);
    fields.put("durationMs", ms);
    requestId.ifPresent(id -> fields.put("requestId", id));
    safe(() -> logger.debug("response", fields));
  }

  @Override
  public void afterExecution(Context.AfterExecution context, ExecutionAttributes attrs) {
    LAST_ATTEMPTS.set(Math.max(1, attempts(attrs).get()));
  }

  @Override
  public void onExecutionFailure(Context.FailedExecution context, ExecutionAttributes attrs) {
    LAST_ATTEMPTS.set(Math.max(1, attempts(attrs).get()));
  }

  static Optional<String> requestId(SdkHttpResponse res) {
    return res.firstMatchingHeader("x-amzn-RequestId")
        .or(() -> res.firstMatchingHeader("x-amz-request-id"));
  }

  private static AtomicInteger attempts(ExecutionAttributes attrs) {
    AtomicInteger n = attrs.getAttribute(ATTEMPTS);
    if (n == null) {
      n = new AtomicInteger();
      attrs.putAttribute(ATTEMPTS, n);
    }
    return n;
  }

  private static String operation(ExecutionAttributes attrs) {
    String op = attrs.getAttribute(SdkExecutionAttribute.OPERATION_NAME);
    return op == null ? "" : op;
  }

  static void safe(Runnable r) {
    try {
      r.run();
    } catch (RuntimeException ignored) {
      // hooks and loggers must never break a call
    }
  }
}
