package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.AuthenticationException;
import codes.grow.packages.awssecretsmanager.core.AwsSecretsManagerException;
import codes.grow.packages.awssecretsmanager.core.CancelledException;
import codes.grow.packages.awssecretsmanager.core.ConfigException;
import codes.grow.packages.awssecretsmanager.core.ConflictException;
import codes.grow.packages.awssecretsmanager.core.EnvReader;
import codes.grow.packages.awssecretsmanager.core.ErrorCode;
import codes.grow.packages.awssecretsmanager.core.HealthStatus;
import codes.grow.packages.awssecretsmanager.core.Hooks;
import codes.grow.packages.awssecretsmanager.core.Logger;
import codes.grow.packages.awssecretsmanager.core.NotFoundException;
import codes.grow.packages.awssecretsmanager.core.PermissionDeniedException;
import codes.grow.packages.awssecretsmanager.core.Redaction;
import codes.grow.packages.awssecretsmanager.core.RetryPolicy;
import codes.grow.packages.awssecretsmanager.core.SdkInfo;
import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.core.TlsOptions;
import codes.grow.packages.awssecretsmanager.core.UnsupportedException;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.client.config.SdkAdvancedClientOption;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.retries.api.BackoffStrategy;
import software.amazon.awssdk.retries.api.RetryStrategy;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.BatchGetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.BatchGetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.CancelRotateSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.DeleteResourcePolicyResponse;
import software.amazon.awssdk.services.secretsmanager.model.DeleteSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DeleteSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.GetRandomPasswordRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetResourcePolicyResponse;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretVersionIdsRequest;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretVersionIdsResponse;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsRequest;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsResponse;
import software.amazon.awssdk.services.secretsmanager.model.PutResourcePolicyResponse;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ReplicaRegionType;
import software.amazon.awssdk.services.secretsmanager.model.RestoreSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.RotateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.RotateSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretValueEntry;
import software.amazon.awssdk.services.secretsmanager.model.UpdateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.UpdateSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.UpdateSecretVersionStageResponse;
import software.amazon.awssdk.services.secretsmanager.model.ValidateResourcePolicyResponse;
import software.amazon.awssdk.services.secretsmanager.model.ValidationErrorsEntry;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.utils.SdkAutoCloseable;

/**
 * Client for AWS Secrets Manager, built on the official AWS SDK for Java v2 (SPEC section 2.3
 * "Cloud SDK services").
 *
 * <p>It builds a {@link SecretsManagerClient} from the Grow configuration (region, credentials,
 * optional assume-role, endpoint override, timeouts, retries, TLS, proxy, headers, User-Agent,
 * hooks) or wraps one the caller passes ({@link #withSdkClient(SecretsManagerClient)}).
 * Thread-safe; create one per account and region and close it when done.
 *
 * <pre>{@code
 * try (AwsSecretsManagerClient client = AwsSecretsManagerClient.fromEnv()) {
 *   AwsSecretValue db = client.getSecretValue("prod/db");
 *   String password = client.getJsonField("prod/db", "password").map(JsonNode::asText).orElseThrow();
 * }
 * }</pre>
 *
 * <p>Every I/O method has a blocking form and an {@code …Async} form returning {@link
 * CompletableFuture}; cancelling the future interrupts the call ({@link CancelledException}).
 * Errors are mapped by AWS error code to the {@link AwsSecretsManagerException} subclasses.
 */
public final class AwsSecretsManagerClient implements AutoCloseable {
  /** AWS Secrets Manager API version (the API contract date; AWS exposes no server version). */
  public static final String API_VERSION = "2017-10-17";

  /** Default version stage. */
  public static final String AWSCURRENT = "AWSCURRENT";

  /** Stage of the previous current version. */
  public static final String AWSPREVIOUS = "AWSPREVIOUS";

  /** Stage of a version being rotated in. */
  public static final String AWSPENDING = "AWSPENDING";

  /** Maximum ids per {@code BatchGetSecretValue} call; longer id lists are split. */
  public static final int BATCH_GET_MAX_IDS = 20;

  /** Upper bound of the health probe timeout. */
  static final Duration HEALTH_TIMEOUT = Duration.ofSeconds(5);

  private static final AtomicInteger THREADS = new AtomicInteger();
  private static final ExecutorService EXECUTOR =
      Executors.newCachedThreadPool(
          r -> {
            Thread t = new Thread(r, "grow-aws-secrets-manager-" + THREADS.incrementAndGet());
            t.setDaemon(true);
            return t;
          });

  private final AwsSecretsManagerConfig config;
  private final SecretsManagerClient sdk;
  private final boolean ownsSdk;
  private final HttpClient jdk;
  private final AwsCredentialsProvider credentials;
  private final Region region;
  private final List<SdkAutoCloseable> owned = new ArrayList<>();
  private final Set<AwsSecretsManagerSecretsProvider> providers = ConcurrentHashMap.newKeySet();
  private final List<AutoCloseable> resources = new ArrayList<>();
  private final AtomicBoolean closed = new AtomicBoolean();
  private volatile SecretsManagerClient healthSdk;

  private AwsSecretsManagerClient(AwsSecretsManagerConfig config) {
    this.config = config;
    Optional<SecretsManagerClient> supplied = config.sdkClient();
    if (supplied.isPresent()) {
      this.sdk = supplied.get();
      this.ownsSdk = false;
      this.jdk = null;
      this.credentials = null;
      this.region = null;
      return;
    }
    this.ownsSdk = true;
    this.jdk = GrowHttpClient.jdkClient(config);
    this.region = resolveRegion(config);
    SdkHttpClient http = GrowHttpClient.of(jdk, config.requestTimeout());
    this.credentials = buildCredentials(config, http, region, owned);
    this.sdk = buildSdk(http, retryStrategy(config.retry()), config.totalTimeout());
  }

  private static Region resolveRegion(AwsSecretsManagerConfig config) {
    if (config.region().isPresent()) {
      return Region.of(config.region().get());
    }
    try {
      DefaultAwsRegionProviderChain.Builder b = DefaultAwsRegionProviderChain.builder();
      config.profile().ifPresent(b::profileName);
      return b.build().getRegion();
    } catch (SdkException e) {
      throw new ConfigException(
          "config: region is not set (GROW_AWS_SECRETS_MANAGER_REGION, AWS_REGION or the profile)",
          e);
    }
  }

  private static AwsCredentialsProvider buildCredentials(
      AwsSecretsManagerConfig config,
      SdkHttpClient http,
      Region region,
      List<SdkAutoCloseable> owned) {
    AwsCredentialsProvider base = null;
    if (config.accessKeyId().isPresent() && config.secretAccessKey().isPresent()) {
      String key = config.accessKeyId().get();
      String secret = config.secretAccessKey().get().reveal();
      base =
          StaticCredentialsProvider.create(
              config.sessionToken().isPresent()
                  ? AwsSessionCredentials.create(key, secret, config.sessionToken().get().reveal())
                  : AwsBasicCredentials.create(key, secret));
    } else if (config.credentials().isPresent()) {
      base = config.credentials().get();
    } else if (config.profile().isPresent()) {
      base = ProfileCredentialsProvider.create(config.profile().get());
    }
    if (config.roleArn().isEmpty()) {
      return base;
    }
    StsClient sts =
        StsClient.builder()
            .httpClient(http)
            .region(region)
            .credentialsProvider(base != null ? base : DefaultCredentialsProvider.builder().build())
            .build();
    owned.add(sts);
    StsAssumeRoleCredentialsProvider provider =
        StsAssumeRoleCredentialsProvider.builder()
            .stsClient(sts)
            .refreshRequest(
                r -> {
                  r.roleArn(config.roleArn().get()).roleSessionName(config.roleSessionName());
                  config.externalId().ifPresent(r::externalId);
                  config.roleDuration().ifPresent(d -> r.durationSeconds((int) d.toSeconds()));
                })
            .asyncCredentialUpdateEnabled(false)
            .build();
    owned.add(provider);
    return provider;
  }

  private static RetryStrategy retryStrategy(RetryPolicy policy) {
    if (policy.maxRetries() == 0) {
      return AwsRetryStrategy.doNotRetry();
    }
    BackoffStrategy backoff =
        BackoffStrategy.exponentialDelay(policy.initialBackoff(), policy.maxBackoff());
    return AwsRetryStrategy.standardRetryStrategy().toBuilder()
        .maxAttempts(policy.maxRetries() + 1)
        .backoffStrategy(backoff)
        .throttlingBackoffStrategy(backoff)
        .circuitBreakerEnabled(false)
        .build();
  }

  private SecretsManagerClient buildSdk(SdkHttpClient http, RetryStrategy retry, Duration total) {
    String ua = SdkInfo.userAgent() + config.userAgentSuffix().map(s -> " " + s).orElse("");
    ClientOverrideConfiguration.Builder o =
        ClientOverrideConfiguration.builder()
            .retryStrategy(retry)
            .apiCallTimeout(total)
            .addExecutionInterceptor(new GrowInterceptor(config.hooks(), config.logger()))
            .putAdvancedOption(SdkAdvancedClientOption.USER_AGENT_SUFFIX, ua);
    config.headers().forEach(o::putHeader);
    var b =
        SecretsManagerClient.builder()
            .httpClient(http)
            .region(region)
            .overrideConfiguration(o.build());
    if (credentials != null) {
      b.credentialsProvider(credentials);
    }
    config.endpoint().ifPresent(e -> b.endpointOverride(URI.create(e)));
    return b.build();
  }

  /**
   * Creates a client.
   *
   * @param config validated configuration
   * @return a new client
   * @throws ConfigException when the configuration is invalid or no region can be resolved
   */
  public static AwsSecretsManagerClient create(AwsSecretsManagerConfig config) {
    config.validate();
    return new AwsSecretsManagerClient(config);
  }

  /**
   * Creates a client from {@code GROW_AWS_SECRETS_MANAGER_*} and the standard AWS environment
   * variables.
   *
   * @return a new client
   */
  public static AwsSecretsManagerClient fromEnv() {
    return create(AwsSecretsManagerConfig.fromEnv());
  }

  /**
   * Wraps an existing AWS SDK client; {@link #close()} leaves it open.
   *
   * @param sdkClient the client
   * @return a new client
   */
  public static AwsSecretsManagerClient withSdkClient(SecretsManagerClient sdkClient) {
    return create(AwsSecretsManagerConfig.builder().sdkClient(sdkClient).build());
  }

  /**
   * Starts a client builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the configuration.
   *
   * @return the configuration
   */
  public AwsSecretsManagerConfig config() {
    return config;
  }

  /**
   * Returns the underlying AWS SDK client (escape hatch for operations not wrapped here).
   *
   * @return the SDK client
   */
  public SecretsManagerClient sdk() {
    return sdk;
  }

  /**
   * Registers a resource (watcher, cache) closed with the client.
   *
   * @param resource the resource
   */
  public void register(AutoCloseable resource) {
    synchronized (resources) {
      resources.add(resource);
    }
  }

  // ---------------------------------------------------------------------------------------
  // core

  /**
   * Liveness: a signed {@code ListSecrets {MaxResults: 1}} with a short timeout (at most 5 s) and
   * no retries. {@code ok} when AWS answers (also when the credentials are rejected: {@code
   * details.auth = "failed"}), {@code degraded} when throttled, {@code unhealthy} on HTTP 5xx,
   * {@code unreachable} on network errors.
   *
   * @return the health status
   * @throws CancelledException when interrupted
   * @throws ConfigException when the client is closed
   */
  public HealthStatus health() {
    Duration probe =
        config.requestTimeout().compareTo(HEALTH_TIMEOUT) < 0
            ? config.requestTimeout()
            : HEALTH_TIMEOUT;
    try {
      call(
          "health",
          () ->
              healthClient()
                  .listSecrets(
                      ListSecretsRequest.builder()
                          .maxResults(1)
                          .overrideConfiguration(o -> o.apiCallTimeout(probe))
                          .build()));
      return new HealthStatus(true, "ok", Map.of());
    } catch (AwsSecretsManagerException e) {
      ErrorCode code = e.code();
      switch (code) {
        case CANCELLED:
        case CONFIG:
          throw e;
        case RATE_LIMITED:
          return new HealthStatus(true, "degraded", Map.of("code", code.wireValue()));
        case AUTHENTICATION:
        case PERMISSION_DENIED:
          return new HealthStatus(true, "ok", Map.of("auth", "failed", "code", code.wireValue()));
        default:
          if (e.httpStatus().isEmpty()) {
            return new HealthStatus(false, "unreachable", Map.of("error", code.wireValue()));
          }
          String status = String.valueOf(e.httpStatus().getAsInt());
          if (e.httpStatus().getAsInt() >= 500) {
            return new HealthStatus(
                false, "unhealthy", Map.of("httpStatus", status, "error", code.wireValue()));
          }
          return new HealthStatus(
              true, "ok", Map.of("httpStatus", status, "code", code.wireValue()));
      }
    }
  }

  /**
   * Asynchronous {@link #health()}.
   *
   * @return a future with the health status
   */
  public CompletableFuture<HealthStatus> healthAsync() {
    return async(this::health);
  }

  /**
   * Authenticated round trip ({@code ListSecrets {MaxResults: 1}}).
   *
   * @return the latency
   * @throws AuthenticationException for unknown keys or bad signatures
   * @throws PermissionDeniedException when the principal may not call {@code
   *     secretsmanager:ListSecrets}
   */
  public Duration ping() {
    long start = System.nanoTime();
    call("ping", () -> sdk.listSecrets(r -> r.maxResults(1)));
    return Duration.ofNanos(System.nanoTime() - start);
  }

  /**
   * Asynchronous {@link #ping()}.
   *
   * @return a future with the latency
   */
  public CompletableFuture<Duration> pingAsync() {
    return async(this::ping);
  }

  /**
   * Always throws: AWS Secrets Manager exposes no server version (the API contract date is the
   * constant {@link #API_VERSION}).
   *
   * @return never returns
   * @throws UnsupportedException always
   */
  public String serverVersion() {
    ensureOpen("serverVersion");
    throw new UnsupportedException(
        "serverVersion: AWS Secrets Manager does not expose a server version");
  }

  /**
   * Asynchronous {@link #serverVersion()} (always fails with {@link UnsupportedException}).
   *
   * @return a failed future
   */
  public CompletableFuture<String> serverVersionAsync() {
    return async(this::serverVersion);
  }

  /**
   * Returns whether {@link #close()} was called.
   *
   * @return true once closed
   */
  public boolean isClosed() {
    return closed.get();
  }

  /**
   * Stops the watchers of every provider created by {@link #secrets()}, closes registered resources
   * and the SDK client this instance built (never a caller-supplied one). Idempotent; later calls
   * fail with {@link ConfigException}.
   */
  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    for (AwsSecretsManagerSecretsProvider p : List.copyOf(providers)) {
      p.close();
    }
    providers.clear();
    List<AutoCloseable> copy;
    synchronized (resources) {
      copy = new ArrayList<>(resources);
      resources.clear();
    }
    for (AutoCloseable r : copy) {
      try {
        r.close();
      } catch (Exception ignored) {
        // best effort: close must not throw
      }
    }
    if (ownsSdk) {
      sdk.close();
      SecretsManagerClient h = healthSdk;
      if (h != null) {
        h.close();
      }
      for (SdkAutoCloseable c : owned) {
        c.close();
      }
    }
  }

  // ---------------------------------------------------------------------------------------
  // category interface

  /**
   * Returns the {@code SecretsProvider} view (SPEC section 3) of this client. {@link #close()} of
   * the client stops its watchers.
   *
   * @return a new provider
   */
  public AwsSecretsManagerSecretsProvider secrets() {
    return secrets(AwsSecretsManagerSecretsOptions.none());
  }

  /**
   * Returns the {@code SecretsProvider} view with options.
   *
   * @param options provider options
   * @return a new provider
   */
  public AwsSecretsManagerSecretsProvider secrets(AwsSecretsManagerSecretsOptions options) {
    ensureOpen("secrets");
    AwsSecretsManagerSecretsProvider[] holder = new AwsSecretsManagerSecretsProvider[1];
    holder[0] =
        new AwsSecretsManagerSecretsProvider(this, options, () -> providers.remove(holder[0]));
    providers.add(holder[0]);
    return holder[0];
  }

  /**
   * Returns a version-stage aware cache with the AWS caching-client semantics (TTL 1 h, 1 024
   * entries).
   *
   * @return a new cache
   */
  public AwsSecretCache secretCache() {
    return new AwsSecretCache(this, AwsSecretCache.Options.builder().build());
  }

  /**
   * Returns a version-stage aware cache with options.
   *
   * @param options cache options
   * @return a new cache
   */
  public AwsSecretCache secretCache(AwsSecretCache.Options options) {
    return new AwsSecretCache(this, options);
  }

  // ---------------------------------------------------------------------------------------
  // read

  /**
   * Reads the {@code AWSCURRENT} value of a secret ({@code GetSecretValue}).
   *
   * @param secretId name or ARN
   * @return the value
   * @throws NotFoundException when the secret does not exist or has no value
   * @throws ConflictException when the secret is scheduled for deletion
   */
  public AwsSecretValue getSecretValue(String secretId) {
    return getSecretValue(secretId, GetSecretValueOptions.none());
  }

  /**
   * Reads a secret value ({@code GetSecretValue}) by version id or stage label.
   *
   * @param secretId name or ARN
   * @param options version selection
   * @return the value
   * @throws NotFoundException when the secret, version or stage does not exist
   * @throws ConflictException when the secret is scheduled for deletion
   */
  public AwsSecretValue getSecretValue(String secretId, GetSecretValueOptions options) {
    requireId("getSecretValue", secretId);
    GetSecretValueResponse out =
        call(
            "getSecretValue " + secretId,
            () ->
                sdk.getSecretValue(
                    r ->
                        r.secretId(secretId)
                            .versionId(options.versionId())
                            .versionStage(options.versionStage())));
    return Models.secretValue(
        out.arn(),
        out.name(),
        out.versionId(),
        out.versionStages(),
        out.createdDate(),
        out.secretString(),
        out.secretBinary());
  }

  /**
   * Asynchronous {@link #getSecretValue(String)}.
   *
   * @param secretId name or ARN
   * @return a future with the value
   */
  public CompletableFuture<AwsSecretValue> getSecretValueAsync(String secretId) {
    return async(() -> getSecretValue(secretId));
  }

  /**
   * Asynchronous {@link #getSecretValue(String, GetSecretValueOptions)}.
   *
   * @param secretId name or ARN
   * @param options version selection
   * @return a future with the value
   */
  public CompletableFuture<AwsSecretValue> getSecretValueAsync(
      String secretId, GetSecretValueOptions options) {
    return async(() -> getSecretValue(secretId, options));
  }

  /**
   * Reads many secrets by id ({@code BatchGetSecretValue}); lists longer than 20 ids are split and
   * the values come back in request order. Per-secret failures are returned in {@code errors}.
   *
   * @param ids names or ARNs
   * @return the values and per-secret errors
   */
  public BatchGetResult batchGetSecretValue(List<String> ids) {
    return batchGetSecretValue(BatchGetSelector.ids(ids), BatchGetOptions.none());
  }

  /**
   * Reads many secrets ({@code BatchGetSecretValue}) by ids or by filters with the default page
   * size.
   *
   * @param selector ids or filters
   * @return the values and per-secret errors
   */
  public BatchGetResult batchGetSecretValue(BatchGetSelector selector) {
    return batchGetSecretValue(selector, BatchGetOptions.none());
  }

  /**
   * Reads many secrets ({@code BatchGetSecretValue}) by ids or by filters (every page is read).
   *
   * @param selector ids or filters
   * @param options page size of the filter form
   * @return the values and per-secret errors
   * @throws ValidationException when both or neither ids and filters are given
   */
  public BatchGetResult batchGetSecretValue(BatchGetSelector selector, BatchGetOptions options) {
    List<AwsSecretValue> values = new ArrayList<>();
    List<BatchGetError> errors = new ArrayList<>();
    if (selector.ids() != null && selector.filters() != null) {
      throw new ValidationException("batchGetSecretValue: give secret ids or filters, not both");
    }
    if (selector.ids() != null) {
      List<String> ids = selector.ids();
      for (int i = 0; i < ids.size(); i += BATCH_GET_MAX_IDS) {
        List<String> chunk = ids.subList(i, Math.min(ids.size(), i + BATCH_GET_MAX_IDS));
        List<AwsSecretValue> page = new ArrayList<>();
        String token = null;
        do {
          String t = token;
          BatchGetSecretValueResponse out =
              call(
                  "batchGetSecretValue",
                  () -> sdk.batchGetSecretValue(r -> r.secretIdList(chunk).nextToken(t)));
          collect(out, page, errors);
          token = more(out.nextToken());
        } while (token != null);
        values.addAll(orderByIds(page, chunk));
      }
      return new BatchGetResult(values, errors);
    }
    if (selector.filters() == null || selector.filters().isEmpty()) {
      throw new ValidationException("batchGetSecretValue: give secret ids or at least one filter");
    }
    String token = null;
    do {
      BatchGetSecretValueRequest req =
          BatchGetSecretValueRequest.builder()
              .filters(Models.toAwsFilters(selector.filters()))
              .maxResults(options.maxResults())
              .nextToken(token)
              .build();
      BatchGetSecretValueResponse out =
          call("batchGetSecretValue", () -> sdk.batchGetSecretValue(req));
      collect(out, values, errors);
      token = more(out.nextToken());
    } while (token != null);
    return new BatchGetResult(values, errors);
  }

  private static void collect(
      BatchGetSecretValueResponse out, List<AwsSecretValue> values, List<BatchGetError> errors) {
    for (SecretValueEntry e : out.secretValues()) {
      values.add(
          Models.secretValue(
              e.arn(),
              e.name(),
              e.versionId(),
              e.versionStages(),
              e.createdDate(),
              e.secretString(),
              e.secretBinary()));
    }
    out.errors().forEach(e -> errors.add(Models.batchError(e)));
  }

  /**
   * Asynchronous {@link #batchGetSecretValue(List)}.
   *
   * @param ids names or ARNs
   * @return a future with the result
   */
  public CompletableFuture<BatchGetResult> batchGetSecretValueAsync(List<String> ids) {
    return async(() -> batchGetSecretValue(ids));
  }

  /**
   * Asynchronous {@link #batchGetSecretValue(BatchGetSelector, BatchGetOptions)}.
   *
   * @param selector ids or filters
   * @param options page size
   * @return a future with the result
   */
  public CompletableFuture<BatchGetResult> batchGetSecretValueAsync(
      BatchGetSelector selector, BatchGetOptions options) {
    return async(() -> batchGetSecretValue(selector, options));
  }

  /**
   * Reads the metadata of a secret ({@code DescribeSecret}), never the value.
   *
   * @param secretId name or ARN
   * @return the metadata
   * @throws NotFoundException when the secret does not exist
   */
  public SecretDescription describeSecret(String secretId) {
    requireId("describeSecret", secretId);
    return Models.describe(
        call("describeSecret " + secretId, () -> sdk.describeSecret(r -> r.secretId(secretId))));
  }

  /**
   * Asynchronous {@link #describeSecret(String)}.
   *
   * @param secretId name or ARN
   * @return a future with the metadata
   */
  public CompletableFuture<SecretDescription> describeSecretAsync(String secretId) {
    return async(() -> describeSecret(secretId));
  }

  /**
   * Lists every secret ({@code ListSecrets}) lazily across all pages.
   *
   * @return a paginator
   */
  public Paginator<SecretDescription> listSecrets() {
    return listSecrets(ListSecretsOptions.none());
  }

  /**
   * Lists secrets ({@code ListSecrets}) lazily across all pages: iterate it, or call {@link
   * Paginator#toList()}.
   *
   * @param options filters, planned deletions, sort order, page size
   * @return a paginator
   */
  public Paginator<SecretDescription> listSecrets(ListSecretsOptions options) {
    return new Paginator<>(
        token -> {
          ListSecretsRequest.Builder b =
              ListSecretsRequest.builder()
                  .includePlannedDeletion(options.includePlannedDeletion())
                  .sortOrder(options.sortOrder())
                  .maxResults(options.maxResults())
                  .nextToken(token);
          if (options.filters() != null && !options.filters().isEmpty()) {
            b.filters(Models.toAwsFilters(options.filters()));
          }
          ListSecretsRequest req = b.build();
          ListSecretsResponse out = call("listSecrets", () -> sdk.listSecrets(req));
          List<SecretDescription> items = new ArrayList<>();
          out.secretList().forEach(e -> items.add(Models.describe(e)));
          return new Paginator.Page<>(items, more(out.nextToken()));
        });
  }

  /**
   * Asynchronous {@link #listSecrets(ListSecretsOptions)}: collects every page.
   *
   * @param options list options
   * @return a future with every secret
   */
  public CompletableFuture<List<SecretDescription>> listSecretsAsync(ListSecretsOptions options) {
    return async(() -> listSecrets(options).toList());
  }

  /**
   * Lists the versions of a secret ({@code ListSecretVersionIds}) lazily across all pages.
   *
   * @param secretId name or ARN
   * @return a paginator
   */
  public Paginator<SecretVersion> listSecretVersionIds(String secretId) {
    return listSecretVersionIds(secretId, ListSecretVersionIdsOptions.none());
  }

  /**
   * Lists the versions of a secret ({@code ListSecretVersionIds}) lazily across all pages.
   *
   * @param secretId name or ARN
   * @param options deprecated versions, page size
   * @return a paginator
   */
  public Paginator<SecretVersion> listSecretVersionIds(
      String secretId, ListSecretVersionIdsOptions options) {
    requireId("listSecretVersionIds", secretId);
    return new Paginator<>(
        token -> {
          ListSecretVersionIdsRequest req =
              ListSecretVersionIdsRequest.builder()
                  .secretId(secretId)
                  .includeDeprecated(options.includeDeprecated())
                  .maxResults(options.maxResults())
                  .nextToken(token)
                  .build();
          ListSecretVersionIdsResponse out =
              call("listSecretVersionIds " + secretId, () -> sdk.listSecretVersionIds(req));
          List<SecretVersion> items = new ArrayList<>();
          out.versions().forEach(v -> items.add(Models.version(v)));
          return new Paginator.Page<>(items, more(out.nextToken()));
        });
  }

  /**
   * Asynchronous {@link #listSecretVersionIds(String, ListSecretVersionIdsOptions)}: collects every
   * page.
   *
   * @param secretId name or ARN
   * @param options list options
   * @return a future with every version
   */
  public CompletableFuture<List<SecretVersion>> listSecretVersionIdsAsync(
      String secretId, ListSecretVersionIdsOptions options) {
    return async(() -> listSecretVersionIds(secretId, options).toList());
  }

  // ---------------------------------------------------------------------------------------
  // write

  /**
   * Creates a secret ({@code CreateSecret}).
   *
   * @param name secret name
   * @param value {@code String} → {@code SecretString}, {@code byte[]} → {@code SecretBinary},
   *     other objects → JSON {@code SecretString}, {@code null} → a secret without a version
   * @return ARN, name and the new version id
   * @throws ConflictException when the name exists or is scheduled for deletion
   */
  public SecretWriteResult createSecret(String name, Object value) {
    return createSecret(name, value, CreateSecretOptions.none());
  }

  /**
   * Creates a secret ({@code CreateSecret}) with description, KMS key, tags, idempotency token or
   * replica regions.
   *
   * @param name secret name
   * @param value the value, or {@code null} for a secret without a version
   * @param options create options
   * @return ARN, name and the new version id
   * @throws ConflictException when the name exists or is scheduled for deletion
   */
  public SecretWriteResult createSecret(String name, Object value, CreateSecretOptions options) {
    requireId("createSecret", name);
    CreateSecretRequest.Builder b =
        CreateSecretRequest.builder()
            .name(name)
            .description(options.description())
            .kmsKeyId(options.kmsKeyId())
            .clientRequestToken(options.clientRequestToken())
            .forceOverwriteReplicaSecret(options.forceOverwriteReplicaSecret());
    if (value != null) {
      Models.Encoded e = Models.encodeValue("createSecret " + name, value);
      b.secretString(e.string()).secretBinary(e.binary());
    }
    if (options.tags() != null) {
      b.tags(Models.toAwsTags(options.tags()));
    }
    if (options.addReplicaRegions() != null) {
      List<ReplicaRegionType> regions = new ArrayList<>();
      for (ReplicaRegion r : options.addReplicaRegions()) {
        regions.add(ReplicaRegionType.builder().region(r.region()).kmsKeyId(r.kmsKeyId()).build());
      }
      b.addReplicaRegions(regions);
    }
    CreateSecretRequest req = b.build();
    CreateSecretResponse out = call("createSecret " + name, () -> sdk.createSecret(req));
    return new SecretWriteResult(Models.nz(out.arn()), Models.nz(out.name()), out.versionId());
  }

  /**
   * Asynchronous {@link #createSecret(String, Object, CreateSecretOptions)}.
   *
   * @param name secret name
   * @param value the value
   * @param options create options
   * @return a future with the result
   */
  public CompletableFuture<SecretWriteResult> createSecretAsync(
      String name, Object value, CreateSecretOptions options) {
    return async(() -> createSecret(name, value, options));
  }

  /**
   * Stores a new version that becomes {@code AWSCURRENT} ({@code PutSecretValue}); the old current
   * version becomes {@code AWSPREVIOUS}.
   *
   * @param secretId name or ARN
   * @param value the value (see {@link #createSecret(String, Object)})
   * @return the new version
   * @throws NotFoundException when the secret does not exist
   */
  public PutSecretValueResult putSecretValue(String secretId, Object value) {
    return putSecretValue(secretId, value, PutSecretValueOptions.none());
  }

  /**
   * Stores a new version ({@code PutSecretValue}); with custom {@code versionStages} only those
   * labels are attached.
   *
   * @param secretId name or ARN
   * @param value the value
   * @param options stages and idempotency token
   * @return the new version
   * @throws NotFoundException when the secret does not exist
   * @throws ConflictException when the token was used with a different value
   */
  public PutSecretValueResult putSecretValue(
      String secretId, Object value, PutSecretValueOptions options) {
    requireId("putSecretValue", secretId);
    Models.Encoded e = Models.encodeValue("putSecretValue " + secretId, value);
    PutSecretValueRequest req =
        PutSecretValueRequest.builder()
            .secretId(secretId)
            .secretString(e.string())
            .secretBinary(e.binary())
            .versionStages(options.versionStages())
            .clientRequestToken(options.clientRequestToken())
            .build();
    PutSecretValueResponse out = call("putSecretValue " + secretId, () -> sdk.putSecretValue(req));
    return new PutSecretValueResult(
        Models.nz(out.arn()),
        Models.nz(out.name()),
        Models.nz(out.versionId()),
        out.versionStages());
  }

  /**
   * Asynchronous {@link #putSecretValue(String, Object, PutSecretValueOptions)}.
   *
   * @param secretId name or ARN
   * @param value the value
   * @param options put options
   * @return a future with the new version
   */
  public CompletableFuture<PutSecretValueResult> putSecretValueAsync(
      String secretId, Object value, PutSecretValueOptions options) {
    return async(() -> putSecretValue(secretId, value, options));
  }

  /**
   * Updates description, KMS key and/or value ({@code UpdateSecret}); a new version is created only
   * when a value is given.
   *
   * @param secretId name or ARN
   * @param options what to change
   * @return ARN, name and the new version id (absent without a value)
   * @throws NotFoundException when the secret does not exist
   */
  public SecretWriteResult updateSecret(String secretId, UpdateSecretOptions options) {
    requireId("updateSecret", secretId);
    UpdateSecretRequest.Builder b =
        UpdateSecretRequest.builder()
            .secretId(secretId)
            .description(options.description())
            .kmsKeyId(options.kmsKeyId())
            .clientRequestToken(options.clientRequestToken());
    if (options.value() != null) {
      Models.Encoded e = Models.encodeValue("updateSecret " + secretId, options.value());
      b.secretString(e.string()).secretBinary(e.binary());
    }
    UpdateSecretRequest req = b.build();
    UpdateSecretResponse out = call("updateSecret " + secretId, () -> sdk.updateSecret(req));
    return new SecretWriteResult(Models.nz(out.arn()), Models.nz(out.name()), out.versionId());
  }

  /**
   * Asynchronous {@link #updateSecret(String, UpdateSecretOptions)}.
   *
   * @param secretId name or ARN
   * @param options what to change
   * @return a future with the result
   */
  public CompletableFuture<SecretWriteResult> updateSecretAsync(
      String secretId, UpdateSecretOptions options) {
    return async(() -> updateSecret(secretId, options));
  }

  /**
   * Moves a stage label between versions ({@code UpdateSecretVersionStage}). Moving {@code
   * AWSCURRENT} needs {@code removeFromVersionId} = the current version; the old current version
   * gets {@code AWSPREVIOUS}.
   *
   * @param secretId name or ARN
   * @param versionStage the label
   * @param options source and/or target version (at least one)
   * @return ARN and name
   * @throws ValidationException when neither version is given or AWS rejects the move
   */
  public SecretRef updateSecretVersionStage(
      String secretId, String versionStage, UpdateSecretVersionStageOptions options) {
    requireId("updateSecretVersionStage", secretId);
    if (options.moveToVersionId() == null && options.removeFromVersionId() == null) {
      throw new ValidationException(
          "updateSecretVersionStage: give moveToVersionId and/or removeFromVersionId");
    }
    UpdateSecretVersionStageResponse out =
        call(
            "updateSecretVersionStage " + secretId,
            () ->
                sdk.updateSecretVersionStage(
                    r ->
                        r.secretId(secretId)
                            .versionStage(versionStage)
                            .moveToVersionId(options.moveToVersionId())
                            .removeFromVersionId(options.removeFromVersionId())));
    return new SecretRef(Models.nz(out.arn()), Models.nz(out.name()));
  }

  /**
   * Asynchronous {@link #updateSecretVersionStage(String, String,
   * UpdateSecretVersionStageOptions)}.
   *
   * @param secretId name or ARN
   * @param versionStage the label
   * @param options versions
   * @return a future with ARN and name
   */
  public CompletableFuture<SecretRef> updateSecretVersionStageAsync(
      String secretId, String versionStage, UpdateSecretVersionStageOptions options) {
    return async(() -> updateSecretVersionStage(secretId, versionStage, options));
  }

  /**
   * Schedules deletion with the AWS default recovery window of 30 days ({@code DeleteSecret}).
   *
   * @param secretId name or ARN
   * @return ARN, name and deletion date
   * @throws NotFoundException when the secret does not exist
   */
  public DeleteSecretResult deleteSecret(String secretId) {
    return deleteSecret(secretId, DeleteSecretOptions.none());
  }

  /**
   * Schedules deletion after {@code recoveryWindowDays} or deletes immediately with {@code
   * forceDeleteWithoutRecovery} ({@code DeleteSecret}). AWS answers success for a forced delete of
   * a secret that does not exist.
   *
   * @param secretId name or ARN
   * @param options recovery window or force (never both)
   * @return ARN, name and deletion date
   * @throws ValidationException when both options are given or the window is outside 7–30
   */
  public DeleteSecretResult deleteSecret(String secretId, DeleteSecretOptions options) {
    requireId("deleteSecret", secretId);
    Integer days = options.recoveryWindowDays();
    Boolean force = options.forceDeleteWithoutRecovery();
    if (days != null && Boolean.TRUE.equals(force)) {
      throw new ValidationException(
          "deleteSecret: recoveryWindowDays and forceDeleteWithoutRecovery are mutually exclusive");
    }
    if (days != null && (days < 7 || days > 30)) {
      throw new ValidationException(
          "deleteSecret: recoveryWindowDays must be an integer from 7 to 30");
    }
    DeleteSecretRequest req =
        DeleteSecretRequest.builder()
            .secretId(secretId)
            .recoveryWindowInDays(days == null ? null : days.longValue())
            .forceDeleteWithoutRecovery(force)
            .build();
    DeleteSecretResponse out = call("deleteSecret " + secretId, () -> sdk.deleteSecret(req));
    return new DeleteSecretResult(Models.nz(out.arn()), Models.nz(out.name()), out.deletionDate());
  }

  /**
   * Asynchronous {@link #deleteSecret(String, DeleteSecretOptions)}.
   *
   * @param secretId name or ARN
   * @param options delete options
   * @return a future with the result
   */
  public CompletableFuture<DeleteSecretResult> deleteSecretAsync(
      String secretId, DeleteSecretOptions options) {
    return async(() -> deleteSecret(secretId, options));
  }

  /**
   * Cancels a scheduled deletion ({@code RestoreSecret}); a no-op for a live secret.
   *
   * @param secretId name or ARN
   * @return ARN and name
   * @throws NotFoundException when the secret does not exist
   */
  public SecretRef restoreSecret(String secretId) {
    requireId("restoreSecret", secretId);
    RestoreSecretResponse out =
        call("restoreSecret " + secretId, () -> sdk.restoreSecret(r -> r.secretId(secretId)));
    return new SecretRef(Models.nz(out.arn()), Models.nz(out.name()));
  }

  /**
   * Asynchronous {@link #restoreSecret(String)}.
   *
   * @param secretId name or ARN
   * @return a future with ARN and name
   */
  public CompletableFuture<SecretRef> restoreSecretAsync(String secretId) {
    return async(() -> restoreSecret(secretId));
  }

  // ---------------------------------------------------------------------------------------
  // tags and resource policy

  /**
   * Adds or replaces tags ({@code TagResource}).
   *
   * @param secretId name or ARN
   * @param tags tags to set
   * @throws NotFoundException when the secret does not exist
   */
  public void tagResource(String secretId, Map<String, String> tags) {
    requireId("tagResource", secretId);
    call(
        "tagResource " + secretId,
        () -> sdk.tagResource(r -> r.secretId(secretId).tags(Models.toAwsTags(tags))));
  }

  /**
   * Asynchronous {@link #tagResource(String, Map)}.
   *
   * @param secretId name or ARN
   * @param tags tags
   * @return a future completed when done
   */
  public CompletableFuture<Void> tagResourceAsync(String secretId, Map<String, String> tags) {
    return async(
        () -> {
          tagResource(secretId, tags);
          return null;
        });
  }

  /**
   * Removes tags by key ({@code UntagResource}).
   *
   * @param secretId name or ARN
   * @param tagKeys keys to remove
   * @throws NotFoundException when the secret does not exist
   */
  public void untagResource(String secretId, List<String> tagKeys) {
    requireId("untagResource", secretId);
    call(
        "untagResource " + secretId,
        () -> sdk.untagResource(r -> r.secretId(secretId).tagKeys(tagKeys)));
  }

  /**
   * Asynchronous {@link #untagResource(String, List)}.
   *
   * @param secretId name or ARN
   * @param tagKeys keys
   * @return a future completed when done
   */
  public CompletableFuture<Void> untagResourceAsync(String secretId, List<String> tagKeys) {
    return async(
        () -> {
          untagResource(secretId, tagKeys);
          return null;
        });
  }

  /**
   * Attaches a resource policy ({@code PutResourcePolicy}).
   *
   * @param secretId name or ARN
   * @param policy JSON text, or an object that is JSON-encoded
   * @return ARN and name
   * @throws NotFoundException when the secret does not exist
   */
  public SecretRef putResourcePolicy(String secretId, Object policy) {
    return putResourcePolicy(secretId, policy, PutResourcePolicyOptions.none());
  }

  /**
   * Attaches a resource policy ({@code PutResourcePolicy}).
   *
   * @param secretId name or ARN
   * @param policy JSON text, or an object that is JSON-encoded
   * @param options public-policy check
   * @return ARN and name
   * @throws NotFoundException when the secret does not exist
   */
  public SecretRef putResourcePolicy(
      String secretId, Object policy, PutResourcePolicyOptions options) {
    requireId("putResourcePolicy", secretId);
    String text = Models.policyText("putResourcePolicy " + secretId, policy);
    PutResourcePolicyResponse out =
        call(
            "putResourcePolicy " + secretId,
            () ->
                sdk.putResourcePolicy(
                    r ->
                        r.secretId(secretId)
                            .resourcePolicy(text)
                            .blockPublicPolicy(options.blockPublicPolicy())));
    return new SecretRef(Models.nz(out.arn()), Models.nz(out.name()));
  }

  /**
   * Asynchronous {@link #putResourcePolicy(String, Object, PutResourcePolicyOptions)}.
   *
   * @param secretId name or ARN
   * @param policy the policy
   * @param options options
   * @return a future with ARN and name
   */
  public CompletableFuture<SecretRef> putResourcePolicyAsync(
      String secretId, Object policy, PutResourcePolicyOptions options) {
    return async(() -> putResourcePolicy(secretId, policy, options));
  }

  /**
   * Reads the resource policy ({@code GetResourcePolicy}).
   *
   * @param secretId name or ARN
   * @return the policy text and parsed object ({@code null} when there is none)
   * @throws NotFoundException when the secret does not exist
   */
  public ResourcePolicyResult getResourcePolicy(String secretId) {
    requireId("getResourcePolicy", secretId);
    GetResourcePolicyResponse out =
        call(
            "getResourcePolicy " + secretId,
            () -> sdk.getResourcePolicy(r -> r.secretId(secretId)));
    String text = out.resourcePolicy();
    return new ResourcePolicyResult(
        Models.nz(out.arn()), Models.nz(out.name()), text, Models.parsePolicy(text));
  }

  /**
   * Asynchronous {@link #getResourcePolicy(String)}.
   *
   * @param secretId name or ARN
   * @return a future with the policy
   */
  public CompletableFuture<ResourcePolicyResult> getResourcePolicyAsync(String secretId) {
    return async(() -> getResourcePolicy(secretId));
  }

  /**
   * Removes the resource policy ({@code DeleteResourcePolicy}).
   *
   * @param secretId name or ARN
   * @return ARN and name
   * @throws NotFoundException when the secret does not exist
   */
  public SecretRef deleteResourcePolicy(String secretId) {
    requireId("deleteResourcePolicy", secretId);
    DeleteResourcePolicyResponse out =
        call(
            "deleteResourcePolicy " + secretId,
            () -> sdk.deleteResourcePolicy(r -> r.secretId(secretId)));
    return new SecretRef(Models.nz(out.arn()), Models.nz(out.name()));
  }

  /**
   * Asynchronous {@link #deleteResourcePolicy(String)}.
   *
   * @param secretId name or ARN
   * @return a future with ARN and name
   */
  public CompletableFuture<SecretRef> deleteResourcePolicyAsync(String secretId) {
    return async(() -> deleteResourcePolicy(secretId));
  }

  /**
   * Checks a policy with IAM Access Analyzer ({@code ValidateResourcePolicy}).
   *
   * @param policy JSON text or an object
   * @return whether it passed and the problems found
   * @throws UnsupportedException on emulators that lack the operation (Moto 5.2.4)
   */
  public ValidateResourcePolicyResult validateResourcePolicy(Object policy) {
    return validateResourcePolicy(policy, ValidateResourcePolicyOptions.none());
  }

  /**
   * Checks a policy with IAM Access Analyzer ({@code ValidateResourcePolicy}).
   *
   * @param policy JSON text or an object
   * @param options the secret the policy would be attached to
   * @return whether it passed and the problems found
   * @throws UnsupportedException on emulators that lack the operation (Moto 5.2.4)
   */
  public ValidateResourcePolicyResult validateResourcePolicy(
      Object policy, ValidateResourcePolicyOptions options) {
    String text = Models.policyText("validateResourcePolicy", policy);
    ValidateResourcePolicyResponse out =
        call(
            "validateResourcePolicy",
            () ->
                sdk.validateResourcePolicy(
                    r -> r.resourcePolicy(text).secretId(options.secretId())));
    List<PolicyValidationError> errors = new ArrayList<>();
    for (ValidationErrorsEntry e : out.validationErrors()) {
      errors.add(new PolicyValidationError(e.checkName(), e.errorMessage()));
    }
    return new ValidateResourcePolicyResult(
        Boolean.TRUE.equals(out.policyValidationPassed()), errors);
  }

  /**
   * Asynchronous {@link #validateResourcePolicy(Object, ValidateResourcePolicyOptions)}.
   *
   * @param policy the policy
   * @param options options
   * @return a future with the result
   */
  public CompletableFuture<ValidateResourcePolicyResult> validateResourcePolicyAsync(
      Object policy, ValidateResourcePolicyOptions options) {
    return async(() -> validateResourcePolicy(policy, options));
  }

  // ---------------------------------------------------------------------------------------
  // rotation

  /**
   * Configures and/or starts rotation ({@code RotateSecret}). Without {@code lambdaArn} the
   * secret's managed or existing rotation function is used.
   *
   * @param secretId name or ARN
   * @param options Lambda, schedule, immediacy, idempotency token
   * @return ARN, name and the new version id
   * @throws NotFoundException when the secret (or the Lambda) does not exist
   * @throws ConflictException when a rotation is already in progress
   */
  public SecretWriteResult rotateSecret(String secretId, RotateSecretOptions options) {
    requireId("rotateSecret", secretId);
    RotateSecretRequest.Builder b =
        RotateSecretRequest.builder()
            .secretId(secretId)
            .rotationLambdaARN(options.lambdaArn())
            .rotateImmediately(options.rotateImmediately())
            .clientRequestToken(options.clientRequestToken());
    if (options.rules() != null) {
      b.rotationRules(Models.toAwsRules(options.rules()));
    }
    RotateSecretRequest req = b.build();
    RotateSecretResponse out = call("rotateSecret " + secretId, () -> sdk.rotateSecret(req));
    return new SecretWriteResult(Models.nz(out.arn()), Models.nz(out.name()), out.versionId());
  }

  /**
   * Asynchronous {@link #rotateSecret(String, RotateSecretOptions)}.
   *
   * @param secretId name or ARN
   * @param options rotation options
   * @return a future with the result
   */
  public CompletableFuture<SecretWriteResult> rotateSecretAsync(
      String secretId, RotateSecretOptions options) {
    return async(() -> rotateSecret(secretId, options));
  }

  /**
   * Turns rotation off and cancels a rotation in progress ({@code CancelRotateSecret}).
   *
   * @param secretId name or ARN
   * @return ARN, name and the version id of the cancelled rotation
   * @throws NotFoundException when the secret does not exist
   */
  public SecretWriteResult cancelRotateSecret(String secretId) {
    requireId("cancelRotateSecret", secretId);
    CancelRotateSecretResponse out =
        call(
            "cancelRotateSecret " + secretId,
            () -> sdk.cancelRotateSecret(r -> r.secretId(secretId)));
    return new SecretWriteResult(Models.nz(out.arn()), Models.nz(out.name()), out.versionId());
  }

  /**
   * Asynchronous {@link #cancelRotateSecret(String)}.
   *
   * @param secretId name or ARN
   * @return a future with the result
   */
  public CompletableFuture<SecretWriteResult> cancelRotateSecretAsync(String secretId) {
    return async(() -> cancelRotateSecret(secretId));
  }

  // ---------------------------------------------------------------------------------------
  // utilities

  /**
   * Generates a 32-character random password ({@code GetRandomPassword}).
   *
   * @return the password as a redacting {@link Secret}
   */
  public Secret getRandomPassword() {
    return getRandomPassword(RandomPasswordOptions.none());
  }

  /**
   * Generates a random password ({@code GetRandomPassword}).
   *
   * @param options length and character classes
   * @return the password as a redacting {@link Secret}
   * @throws ValidationException when the options cannot be satisfied
   */
  public Secret getRandomPassword(RandomPasswordOptions options) {
    GetRandomPasswordRequest req =
        GetRandomPasswordRequest.builder()
            .passwordLength(options.length() == null ? 32L : options.length().longValue())
            .excludeCharacters(options.excludeCharacters())
            .excludeNumbers(options.excludeNumbers())
            .excludePunctuation(options.excludePunctuation())
            .excludeUppercase(options.excludeUppercase())
            .excludeLowercase(options.excludeLowercase())
            .includeSpace(options.includeSpace())
            .requireEachIncludedType(options.requireEachIncludedType())
            .build();
    String password = call("getRandomPassword", () -> sdk.getRandomPassword(req)).randomPassword();
    return Secret.of(password == null ? "" : password);
  }

  /**
   * Asynchronous {@link #getRandomPassword(RandomPasswordOptions)}.
   *
   * @param options password options
   * @return a future with the password
   */
  public CompletableFuture<Secret> getRandomPasswordAsync(RandomPasswordOptions options) {
    return async(() -> getRandomPassword(options));
  }

  /**
   * Reads one field of a JSON secret ({@code AWSCURRENT}).
   *
   * @param secretId name or ARN
   * @param field exact key, or a dot path such as {@code db.host}
   * @return the field, or empty when absent or JSON {@code null}
   * @throws ValidationException when the value is binary or not a JSON object
   * @throws NotFoundException when the secret does not exist
   */
  public Optional<JsonNode> getJsonField(String secretId, String field) {
    return getJsonField(secretId, field, GetSecretValueOptions.none());
  }

  /**
   * Reads one field of a JSON secret: {@code GetSecretValue}, parse {@code SecretString} as a JSON
   * object, return {@code field} (an exact key first, otherwise a dot path).
   *
   * @param secretId name or ARN
   * @param field exact key or dot path
   * @param options version selection
   * @return the field, or empty when absent or JSON {@code null}
   * @throws ValidationException when the value is binary or not a JSON object
   * @throws NotFoundException when the secret does not exist
   */
  public Optional<JsonNode> getJsonField(
      String secretId, String field, GetSecretValueOptions options) {
    AwsSecretValue secret = getSecretValue(secretId, options);
    if (secret.binary()) {
      throw new ValidationException(
          "getJsonField " + secretId + ": the secret is binary, not JSON");
    }
    JsonNode parsed;
    try {
      parsed = secret.value().jsonNode();
    } catch (RuntimeException e) {
      throw new ValidationException("getJsonField " + secretId + ": the value is not valid JSON");
    }
    if (parsed == null || !parsed.isObject()) {
      throw new ValidationException(
          "getJsonField " + secretId + ": the value is not a JSON object");
    }
    return jsonField(parsed, field);
  }

  /**
   * Asynchronous {@link #getJsonField(String, String, GetSecretValueOptions)}.
   *
   * @param secretId name or ARN
   * @param field exact key or dot path
   * @param options version selection
   * @return a future with the field
   */
  public CompletableFuture<Optional<JsonNode>> getJsonFieldAsync(
      String secretId, String field, GetSecretValueOptions options) {
    return async(() -> getJsonField(secretId, field, options));
  }

  /** Exact key first, then a dot path. */
  static Optional<JsonNode> jsonField(JsonNode obj, String field) {
    if (obj.has(field)) {
      return present(obj.get(field));
    }
    JsonNode current = obj;
    for (String part : field.split("\\.", -1)) {
      if (current == null || !current.isObject() || !current.has(part)) {
        return Optional.empty();
      }
      current = current.get(part);
    }
    return present(current);
  }

  private static Optional<JsonNode> present(JsonNode n) {
    return n == null || n.isNull() ? Optional.empty() : Optional.of(n);
  }

  // ---------------------------------------------------------------------------------------
  // internals

  private SecretsManagerClient healthClient() {
    if (!ownsSdk) {
      return sdk;
    }
    SecretsManagerClient h = healthSdk;
    if (h == null) {
      synchronized (this) {
        h = healthSdk;
        if (h == null) {
          Duration probe =
              config.requestTimeout().compareTo(HEALTH_TIMEOUT) < 0
                  ? config.requestTimeout()
                  : HEALTH_TIMEOUT;
          h =
              buildSdk(
                  GrowHttpClient.of(jdk, probe),
                  AwsRetryStrategy.doNotRetry(),
                  config.totalTimeout());
          healthSdk = h;
        }
      }
    }
    return h;
  }

  private void ensureOpen(String operation) {
    if (closed.get()) {
      throw new ConfigException(operation + ": client is closed");
    }
  }

  private static void requireId(String operation, String id) {
    if (id == null || id.isBlank()) {
      throw new ValidationException(operation + ": secret id must not be empty");
    }
  }

  private static String more(String token) {
    return token == null || token.isEmpty() ? null : token;
  }

  /** Orders batch results like the requested ids (by name or ARN, partial ARNs as prefix). */
  static List<AwsSecretValue> orderByIds(List<AwsSecretValue> values, List<String> ids) {
    List<AwsSecretValue> out = new ArrayList<>(values);
    out.sort(Comparator.comparingInt(v -> rank(v, ids)));
    return out;
  }

  private static int rank(AwsSecretValue v, List<String> ids) {
    for (int i = 0; i < ids.size(); i++) {
      String id = ids.get(i);
      if (id.equals(v.name())
          || id.equals(v.arn())
          || (id.startsWith("arn:") && v.arn().startsWith(id))) {
        return i;
      }
    }
    return ids.size();
  }

  /** Sends one SDK call with the closed check, error mapping and the {@code onError} hook. */
  private <T> T call(String operation, Supplier<T> fn) {
    ensureOpen(operation);
    try {
      return fn.get();
    } catch (AwsSecretsManagerException e) {
      throw e;
    } catch (RuntimeException e) {
      AwsSecretsManagerException mapped =
          AwsErrors.map(e, operation, config.knownSecrets(), config.totalTimeout());
      if (ownsSdk) {
        int attempts = GrowInterceptor.LAST_ATTEMPTS.get();
        String url = Redaction.redactUrl(config.url());
        GrowInterceptor.safe(
            () ->
                config.hooks().onError(new Hooks.ErrorInfo("POST", url, mapped, attempts, false)));
      }
      throw mapped;
    }
  }

  private static <T> CompletableFuture<T> async(Supplier<T> fn) {
    CancellableFuture<T> f = new CancellableFuture<>();
    f.task =
        EXECUTOR.submit(
            () -> {
              try {
                f.complete(fn.get());
              } catch (Throwable t) {
                f.completeExceptionally(t);
              }
            });
    return f;
  }

  /** A future whose {@code cancel} also interrupts the running call. */
  private static final class CancellableFuture<T> extends CompletableFuture<T> {
    private volatile Future<?> task;

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
      boolean cancelled = super.cancel(mayInterruptIfRunning);
      Future<?> t = task;
      if (t != null) {
        t.cancel(true);
      }
      return cancelled;
    }
  }

  @Override
  public String toString() {
    return "AwsSecretsManagerClient{" + config + "}";
  }

  /** Builder that configures and creates a client in one chain. */
  public static final class Builder {
    private final AwsSecretsManagerConfig.Builder config = AwsSecretsManagerConfig.builder();

    private Builder() {}

    /**
     * Fills unset fields from an environment reader when {@link #build()} runs.
     *
     * @param env reader, e.g. {@link EnvReader#system()}
     * @return this builder
     */
    public Builder fromEnv(EnvReader env) {
      config.fromEnv(env);
      return this;
    }

    /**
     * Sets the endpoint override.
     *
     * @param url URL
     * @return this builder
     */
    public Builder url(String url) {
      config.url(url);
      return this;
    }

    /**
     * Sets the AWS region.
     *
     * @param region region
     * @return this builder
     */
    public Builder region(String region) {
      config.region(region);
      return this;
    }

    /**
     * Sets static credentials.
     *
     * @param accessKeyId key id
     * @param secretAccessKey secret key
     * @return this builder
     */
    public Builder credentials(String accessKeyId, String secretAccessKey) {
      config.accessKeyId(accessKeyId).secretAccessKey(secretAccessKey);
      return this;
    }

    /**
     * Sets the static access key id.
     *
     * @param accessKeyId key id
     * @return this builder
     */
    public Builder accessKeyId(String accessKeyId) {
      config.accessKeyId(accessKeyId);
      return this;
    }

    /**
     * Sets the static secret access key.
     *
     * @param secretAccessKey key
     * @return this builder
     */
    public Builder secretAccessKey(Secret secretAccessKey) {
      config.secretAccessKey(secretAccessKey);
      return this;
    }

    /**
     * Sets the session token.
     *
     * @param sessionToken token
     * @return this builder
     */
    public Builder sessionToken(Secret sessionToken) {
      config.sessionToken(sessionToken);
      return this;
    }

    /**
     * Sets the shared config profile.
     *
     * @param profile profile
     * @return this builder
     */
    public Builder profile(String profile) {
      config.profile(profile);
      return this;
    }

    /**
     * Sets an AWS SDK credentials provider.
     *
     * @param credentials provider
     * @return this builder
     */
    public Builder credentials(AwsCredentialsProvider credentials) {
      config.credentials(credentials);
      return this;
    }

    /**
     * Assumes an IAM role with STS.
     *
     * @param roleArn role ARN
     * @return this builder
     */
    public Builder roleArn(String roleArn) {
      config.roleArn(roleArn);
      return this;
    }

    /**
     * Sets the STS role session name.
     *
     * @param name session name
     * @return this builder
     */
    public Builder roleSessionName(String name) {
      config.roleSessionName(name);
      return this;
    }

    /**
     * Sets the STS external id.
     *
     * @param externalId external id
     * @return this builder
     */
    public Builder externalId(String externalId) {
      config.externalId(externalId);
      return this;
    }

    /**
     * Sets the assumed-role session duration.
     *
     * @param duration duration
     * @return this builder
     */
    public Builder roleDuration(Duration duration) {
      config.roleDuration(duration);
      return this;
    }

    /**
     * Sets the recovery window of deletes.
     *
     * @param days 7–30
     * @return this builder
     */
    public Builder recoveryWindowDays(int days) {
      config.recoveryWindowDays(days);
      return this;
    }

    /**
     * Wraps an existing AWS SDK client.
     *
     * @param sdkClient client
     * @return this builder
     */
    public Builder sdkClient(SecretsManagerClient sdkClient) {
      config.sdkClient(sdkClient);
      return this;
    }

    /**
     * Sets the connect timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      config.connectTimeout(d);
      return this;
    }

    /**
     * Sets the per-attempt timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      config.requestTimeout(d);
      return this;
    }

    /**
     * Sets the total timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      config.totalTimeout(d);
      return this;
    }

    /**
     * Sets the retry policy.
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      config.retry(retry);
      return this;
    }

    /**
     * Sets the TLS options.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      config.tls(tls);
      return this;
    }

    /**
     * Sets the proxy URL.
     *
     * @param proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      config.proxy(proxy);
      return this;
    }

    /**
     * Adds a header.
     *
     * @param name name
     * @param value value
     * @return this builder
     */
    public Builder header(String name, String value) {
      config.header(name, value);
      return this;
    }

    /**
     * Sets the user agent suffix.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      config.userAgentSuffix(suffix);
      return this;
    }

    /**
     * Sets hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      config.hooks(hooks);
      return this;
    }

    /**
     * Sets the logger.
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      config.logger(logger);
      return this;
    }

    /**
     * Builds the configuration and the client.
     *
     * @return a new client
     * @throws ConfigException when the configuration is invalid
     */
    public AwsSecretsManagerClient build() {
      return create(config.build());
    }
  }
}
