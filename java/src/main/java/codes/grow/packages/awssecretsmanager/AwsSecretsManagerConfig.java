package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.ConfigException;
import codes.grow.packages.awssecretsmanager.core.EnvReader;
import codes.grow.packages.awssecretsmanager.core.Hooks;
import codes.grow.packages.awssecretsmanager.core.Logger;
import codes.grow.packages.awssecretsmanager.core.Redaction;
import codes.grow.packages.awssecretsmanager.core.RetryPolicy;
import codes.grow.packages.awssecretsmanager.core.Secret;
import codes.grow.packages.awssecretsmanager.core.TlsOptions;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

/**
 * Immutable configuration of a {@link AwsSecretsManagerClient} (SPEC section 2.2 plus the AWS
 * fields of API.md section 5).
 *
 * <p>Build one with {@link #builder()} or read it from the environment with {@link #fromEnv()}.
 * Precedence: explicit builder value &gt; {@code GROW_AWS_SECRETS_MANAGER_<NAME>} &gt; the standard
 * AWS variables ({@code AWS_REGION}, {@code AWS_ACCESS_KEY_ID}, {@code
 * AWS_ENDPOINT_URL_SECRETS_MANAGER}, ...) &gt; defaults. Credentials left unset use the AWS SDK
 * default credential chain. {@link #toString()} never prints credentials.
 */
public final class AwsSecretsManagerConfig {
  /** Default recovery window of deletes in days (the AWS default). */
  public static final int DEFAULT_RECOVERY_WINDOW_DAYS = 30;

  /** Default STS role session name of the assume-role helper. */
  public static final String DEFAULT_ROLE_SESSION_NAME = "grow-sdk";

  /** Vendor variables read for the endpoint after {@code GROW_AWS_SECRETS_MANAGER_URL}. */
  static final String[] URL_VENDOR_VARS = {"AWS_ENDPOINT_URL_SECRETS_MANAGER", "AWS_ENDPOINT_URL"};

  /** Vendor variables read for the region after {@code GROW_AWS_SECRETS_MANAGER_REGION}. */
  static final String[] REGION_VENDOR_VARS = {"AWS_REGION", "AWS_DEFAULT_REGION"};

  /** Vendor variable read for the profile after {@code GROW_AWS_SECRETS_MANAGER_PROFILE}. */
  static final String[] PROFILE_VENDOR_VARS = {"AWS_PROFILE"};

  /** An environment variable name that never exists: reads only the vendor variables. */
  private static final String VENDOR_ONLY = "\0";

  private static final Pattern REGION = Pattern.compile("[a-z0-9-]+");
  private static final Duration MIN_ROLE_DURATION = Duration.ofSeconds(900);
  private static final Duration MAX_ROLE_DURATION = Duration.ofSeconds(43_200);

  private final String endpoint;
  private final Duration connectTimeout;
  private final Duration requestTimeout;
  private final Duration totalTimeout;
  private final RetryPolicy retry;
  private final TlsOptions tls;
  private final String proxy;
  private final Map<String, String> headers;
  private final String userAgentSuffix;
  private final Hooks hooks;
  private final Logger logger;
  private final String region;
  private final String accessKeyId;
  private final Secret secretAccessKey;
  private final Secret sessionToken;
  private final String profile;
  private final AwsCredentialsProvider credentials;
  private final String roleArn;
  private final String roleSessionName;
  private final String externalId;
  private final Duration roleDuration;
  private final int recoveryWindowDays;
  private final SecretsManagerClient sdkClient;

  private AwsSecretsManagerConfig(Builder b) {
    this.endpoint = blankToNull(b.url);
    this.connectTimeout = b.connectTimeout != null ? b.connectTimeout : Duration.ofSeconds(10);
    this.requestTimeout = b.requestTimeout != null ? b.requestTimeout : Duration.ofSeconds(30);
    this.totalTimeout = b.totalTimeout != null ? b.totalTimeout : Duration.ofSeconds(120);
    this.retry = b.retry != null ? b.retry : RetryPolicy.defaults();
    this.tls = b.tls != null ? b.tls : TlsOptions.defaults();
    this.proxy = blankToNull(b.proxy);
    this.headers = Map.copyOf(b.headers);
    this.userAgentSuffix = blankToNull(b.userAgentSuffix);
    this.hooks = b.hooks != null ? b.hooks : Hooks.NONE;
    this.logger = b.logger != null ? b.logger : Logger.NOOP;
    this.region = blankToNull(b.region);
    this.accessKeyId = blankToNull(b.accessKeyId);
    this.secretAccessKey = b.secretAccessKey;
    this.sessionToken = b.sessionToken;
    this.profile = blankToNull(b.profile);
    this.credentials = b.credentials;
    this.roleArn = blankToNull(b.roleArn);
    String session = blankToNull(b.roleSessionName);
    this.roleSessionName = session != null ? session : DEFAULT_ROLE_SESSION_NAME;
    this.externalId = blankToNull(b.externalId);
    this.roleDuration = b.roleDuration;
    this.recoveryWindowDays =
        b.recoveryWindowDays != null ? b.recoveryWindowDays : DEFAULT_RECOVERY_WINDOW_DAYS;
    this.sdkClient = b.sdkClient;
  }

  private static String blankToNull(String s) {
    return s == null || s.isBlank() ? null : s;
  }

  /**
   * Starts an empty builder (every field at its default).
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Reads the configuration from the process environment.
   *
   * @return the validated configuration
   * @throws ConfigException when a variable holds an invalid value (the message names the variable,
   *     never the value)
   */
  public static AwsSecretsManagerConfig fromEnv() {
    return builder().fromEnv(EnvReader.system()).build();
  }

  /**
   * Reads the configuration from an explicit variable map (tests).
   *
   * @param env variable map
   * @return the validated configuration
   */
  public static AwsSecretsManagerConfig fromEnv(Map<String, String> env) {
    return builder().fromEnv(EnvReader.of(env)).build();
  }

  /**
   * Checks every rule: URL scheme, positive timeouts, TLS pairs, region format, credential pairs,
   * exclusive options, role ARN and duration, recovery window.
   *
   * @throws ConfigException listing every violated rule
   */
  public void validate() {
    List<String> problems = new ArrayList<>();
    if (endpoint != null && !isHttpUrl(endpoint)) {
      problems.add("url must be an absolute http or https URL");
    }
    requirePositive(problems, "connectTimeout", connectTimeout);
    requirePositive(problems, "requestTimeout", requestTimeout);
    requirePositive(problems, "totalTimeout", totalTimeout);
    try {
      tls.validate();
    } catch (ConfigException e) {
      problems.add("tls client certificate and key must be set together");
    }
    if (proxy != null && !isHttpUrl(proxy)) {
      problems.add("proxy must be an absolute URL such as http://host:3128");
    }
    if (region != null && !REGION.matcher(region).matches()) {
      problems.add("region must look like us-east-1");
    }
    if (accessKeyId != null && secretAccessKey == null) {
      problems.add("accessKeyId requires secretAccessKey");
    }
    if (accessKeyId == null && secretAccessKey != null) {
      problems.add("secretAccessKey requires accessKeyId");
    }
    if (sessionToken != null && accessKeyId == null) {
      problems.add("sessionToken requires accessKeyId and secretAccessKey");
    }
    if (credentials != null && accessKeyId != null) {
      problems.add("credentials and accessKeyId/secretAccessKey are mutually exclusive");
    }
    if (sdkClient != null) {
      List<String> clash = new ArrayList<>();
      addIf(clash, "accessKeyId", accessKeyId);
      addIf(clash, "credentials", credentials);
      addIf(clash, "profile", profile);
      addIf(clash, "roleArn", roleArn);
      addIf(clash, "region", region);
      addIf(clash, "url", endpoint);
      if (!clash.isEmpty()) {
        problems.add("sdkClient is mutually exclusive with " + String.join(", ", clash));
      }
    }
    if (roleArn != null && !roleArn.startsWith("arn:")) {
      problems.add("roleArn must be an ARN");
    }
    if (roleDuration != null
        && (roleDuration.compareTo(MIN_ROLE_DURATION) < 0
            || roleDuration.compareTo(MAX_ROLE_DURATION) > 0)) {
      problems.add("roleDuration must be between 900 s and 43200 s");
    }
    if (recoveryWindowDays < 7 || recoveryWindowDays > 30) {
      problems.add("recoveryWindowDays must be an integer from 7 to 30");
    }
    if (!problems.isEmpty()) {
      throw new ConfigException("invalid configuration: " + String.join("; ", problems));
    }
  }

  private static void addIf(List<String> out, String name, Object value) {
    if (value != null) {
      out.add(name);
    }
  }

  private static boolean isHttpUrl(String url) {
    try {
      URI u = new URI(url);
      String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
      return (scheme.equals("http") || scheme.equals("https")) && u.getHost() != null;
    } catch (URISyntaxException e) {
      return false;
    }
  }

  private static void requirePositive(List<String> problems, String name, Duration d) {
    if (d.isZero() || d.isNegative()) {
      problems.add(name + " must be positive");
    }
  }

  /**
   * Returns the effective endpoint: the override when set, otherwise the public AWS endpoint of the
   * region ({@code us-east-1} when the region is left to the SDK). Informational.
   *
   * @return the URL
   */
  public String url() {
    if (endpoint != null) {
      return endpoint;
    }
    return "https://secretsmanager." + (region != null ? region : "us-east-1") + ".amazonaws.com";
  }

  /**
   * Returns the explicit endpoint override passed to the AWS SDK.
   *
   * @return the endpoint, or empty when the SDK resolves it
   */
  public Optional<String> endpoint() {
    return Optional.ofNullable(endpoint);
  }

  /**
   * Returns the connect timeout (default 10 s).
   *
   * @return the timeout
   */
  public Duration connectTimeout() {
    return connectTimeout;
  }

  /**
   * Returns the per-attempt timeout (default 30 s).
   *
   * @return the timeout
   */
  public Duration requestTimeout() {
    return requestTimeout;
  }

  /**
   * Returns the total timeout per call including retries (default 120 s).
   *
   * @return the timeout
   */
  public Duration totalTimeout() {
    return totalTimeout;
  }

  /**
   * Returns the retry policy; the AWS SDK standard retry strategy uses {@code maxRetries + 1}
   * attempts and the policy's backoff bounds.
   *
   * @return the policy
   */
  public RetryPolicy retry() {
    return retry;
  }

  /**
   * Returns the TLS options.
   *
   * @return the options
   */
  public TlsOptions tls() {
    return tls;
  }

  /**
   * Returns the explicit proxy URL.
   *
   * @return the proxy, or empty
   */
  public Optional<String> proxy() {
    return Optional.ofNullable(proxy);
  }

  /**
   * Returns the extra request headers.
   *
   * @return immutable map
   */
  public Map<String, String> headers() {
    return headers;
  }

  /**
   * Returns the text appended to the {@code User-Agent}.
   *
   * @return the suffix, or empty
   */
  public Optional<String> userAgentSuffix() {
    return Optional.ofNullable(userAgentSuffix);
  }

  /**
   * Returns the hooks.
   *
   * @return the hooks
   */
  public Hooks hooks() {
    return hooks;
  }

  /**
   * Returns the logger (silent by default).
   *
   * @return the logger
   */
  public Logger logger() {
    return logger;
  }

  /**
   * Returns the AWS region.
   *
   * @return the region, or empty when the SDK chain (environment, shared config) decides
   */
  public Optional<String> region() {
    return Optional.ofNullable(region);
  }

  /**
   * Returns the static access key id.
   *
   * @return the key id, or empty
   */
  public Optional<String> accessKeyId() {
    return Optional.ofNullable(accessKeyId);
  }

  /**
   * Returns the static secret access key.
   *
   * @return the key, or empty
   */
  public Optional<Secret> secretAccessKey() {
    return Optional.ofNullable(secretAccessKey);
  }

  /**
   * Returns the session token of temporary credentials.
   *
   * @return the token, or empty
   */
  public Optional<Secret> sessionToken() {
    return Optional.ofNullable(sessionToken);
  }

  /**
   * Returns the shared config profile.
   *
   * @return the profile, or empty
   */
  public Optional<String> profile() {
    return Optional.ofNullable(profile);
  }

  /**
   * Returns the explicit AWS SDK credentials provider.
   *
   * @return the provider, or empty
   */
  public Optional<AwsCredentialsProvider> credentials() {
    return Optional.ofNullable(credentials);
  }

  /**
   * Returns the IAM role assumed with STS on top of the base credentials.
   *
   * @return the role ARN, or empty
   */
  public Optional<String> roleArn() {
    return Optional.ofNullable(roleArn);
  }

  /**
   * Returns the STS role session name (default {@value #DEFAULT_ROLE_SESSION_NAME}).
   *
   * @return the session name
   */
  public String roleSessionName() {
    return roleSessionName;
  }

  /**
   * Returns the STS external id.
   *
   * @return the external id, or empty
   */
  public Optional<String> externalId() {
    return Optional.ofNullable(externalId);
  }

  /**
   * Returns the assumed-role session duration.
   *
   * @return the duration, or empty for the role's default
   */
  public Optional<Duration> roleDuration() {
    return Optional.ofNullable(roleDuration);
  }

  /**
   * Returns the recovery window of deletes in days (7–30, default 30).
   *
   * @return the window
   */
  public int recoveryWindowDays() {
    return recoveryWindowDays;
  }

  /**
   * Returns the caller-supplied AWS SDK client.
   *
   * @return the client, or empty when the package builds its own
   */
  public Optional<SecretsManagerClient> sdkClient() {
    return Optional.ofNullable(sdkClient);
  }

  /**
   * Returns the credential values that must never appear in messages or logs.
   *
   * @return the known secret values
   */
  public List<String> knownSecrets() {
    List<String> out = new ArrayList<>();
    for (Secret s : new Secret[] {secretAccessKey, sessionToken}) {
      if (s != null && !s.isCleared() && !s.isEmpty()) {
        out.add(s.reveal());
      }
    }
    return out;
  }

  @Override
  public String toString() {
    return "AwsSecretsManagerConfig{url="
        + Redaction.redactUrl(url())
        + ", endpoint="
        + (endpoint == null ? "null" : Redaction.redactUrl(endpoint))
        + ", region="
        + region
        + ", accessKeyId="
        + accessKeyId
        + ", secretAccessKey="
        + (secretAccessKey == null ? "null" : Redaction.REDACTED)
        + ", sessionToken="
        + (sessionToken == null ? "null" : Redaction.REDACTED)
        + ", profile="
        + profile
        + ", credentials="
        + (credentials == null ? "null" : Redaction.REDACTED)
        + ", roleArn="
        + roleArn
        + ", roleSessionName="
        + roleSessionName
        + ", externalId="
        + (externalId == null ? "null" : Redaction.REDACTED)
        + ", roleDuration="
        + roleDuration
        + ", recoveryWindowDays="
        + recoveryWindowDays
        + ", sdkClient="
        + (sdkClient == null ? "null" : "SecretsManagerClient")
        + ", connectTimeout="
        + connectTimeout
        + ", requestTimeout="
        + requestTimeout
        + ", totalTimeout="
        + totalTimeout
        + ", retry="
        + retry
        + ", tls="
        + tls
        + ", proxy="
        + (proxy == null ? "null" : Redaction.redactUrl(proxy))
        + ", headers="
        + Redaction.redactHeaders(headers)
        + ", userAgentSuffix="
        + userAgentSuffix
        + "}";
  }

  /**
   * Builder of the configuration.
   *
   * <p>Fields that are not set explicitly take the environment (when {@link #fromEnv(EnvReader)}
   * was called, in any order) or the default.
   */
  public static final class Builder {
    private String url;
    private Duration connectTimeout;
    private Duration requestTimeout;
    private Duration totalTimeout;
    private RetryPolicy retry;
    private TlsOptions tls;
    private String proxy;
    private final Map<String, String> headers = new LinkedHashMap<>();
    private String userAgentSuffix;
    private Hooks hooks;
    private Logger logger;
    private String region;
    private String accessKeyId;
    private Secret secretAccessKey;
    private Secret sessionToken;
    private String profile;
    private AwsCredentialsProvider credentials;
    private String roleArn;
    private String roleSessionName;
    private String externalId;
    private Duration roleDuration;
    private Integer recoveryWindowDays;
    private SecretsManagerClient sdkClient;
    private EnvReader env;

    private Builder() {}

    /**
     * Fills every field that is not set explicitly from the environment when {@link #build()} runs:
     * {@code GROW_AWS_SECRETS_MANAGER_*} first, then the standard AWS variables. The key id, secret
     * key and session token are taken as one set from one layer (a {@code GROW_*} key id never
     * pairs with an {@code AWS_*} secret). With an explicit {@link #sdkClient} or {@link
     * #credentials}, credentials from the environment are ignored; with {@link #sdkClient} also the
     * region, endpoint, profile and role.
     *
     * @param env environment reader
     * @return this builder
     */
    public Builder fromEnv(EnvReader env) {
      this.env = env;
      return this;
    }

    private void applyEnv(EnvReader e) {
      boolean ownClient = sdkClient == null;
      if (url == null && ownClient) {
        url = e.string("URL", URL_VENDOR_VARS).orElse(null);
      }
      if (connectTimeout == null) {
        connectTimeout = e.duration("CONNECT_TIMEOUT").orElse(null);
      }
      if (requestTimeout == null) {
        requestTimeout = e.duration("REQUEST_TIMEOUT").orElse(null);
      }
      if (totalTimeout == null) {
        totalTimeout = e.duration("TOTAL_TIMEOUT").orElse(null);
      }
      if (retry == null && e.integer("MAX_RETRIES").isPresent()) {
        int n = e.integer("MAX_RETRIES").getAsInt();
        if (n < 0) {
          String variable = EnvReader.DEFAULT_PREFIX + "MAX_RETRIES";
          throw new ConfigException("config: invalid value in " + variable + " (expected >= 0)");
        }
        retry = RetryPolicy.builder().maxRetries(n).build();
      }
      if (tls == null) {
        TlsOptions.Builder t = TlsOptions.builder();
        e.string("CA_CERT").ifPresent(p -> t.caCertPath(Paths.get(p)));
        e.string("CLIENT_CERT").ifPresent(p -> t.clientCertPath(Paths.get(p)));
        e.string("CLIENT_KEY").ifPresent(p -> t.clientKeyPath(Paths.get(p)));
        e.bool("INSECURE_SKIP_VERIFY").ifPresent(t::insecureSkipVerify);
        tls = t.build();
      }
      if (proxy == null) {
        proxy = e.string("PROXY").orElse(null);
      }
      if (ownClient) {
        if (region == null) {
          region = e.string("REGION", REGION_VENDOR_VARS).orElse(null);
        }
        if (profile == null) {
          profile = e.string("PROFILE", PROFILE_VENDOR_VARS).orElse(null);
        }
        if (roleArn == null) {
          roleArn = e.string("ROLE_ARN").orElse(null);
        }
      }
      boolean explicitCredentials =
          accessKeyId != null
              || secretAccessKey != null
              || sessionToken != null
              || credentials != null
              || !ownClient;
      if (!explicitCredentials) {
        Optional<String> growKey = e.string("ACCESS_KEY_ID");
        if (growKey.isPresent()) {
          accessKeyId = growKey.get();
          secretAccessKey = e.string("SECRET_ACCESS_KEY").map(Secret::of).orElse(null);
          sessionToken = e.string("SESSION_TOKEN").map(Secret::of).orElse(null);
        } else {
          accessKeyId = e.string(VENDOR_ONLY, "AWS_ACCESS_KEY_ID").orElse(null);
          secretAccessKey =
              e.string(VENDOR_ONLY, "AWS_SECRET_ACCESS_KEY").map(Secret::of).orElse(null);
          sessionToken = e.string(VENDOR_ONLY, "AWS_SESSION_TOKEN").map(Secret::of).orElse(null);
        }
      }
      if (roleSessionName == null) {
        roleSessionName = e.string("ROLE_SESSION_NAME").orElse(null);
      }
      if (externalId == null) {
        externalId = e.string("EXTERNAL_ID").orElse(null);
      }
      if (recoveryWindowDays == null && e.integer("RECOVERY_WINDOW_DAYS").isPresent()) {
        recoveryWindowDays = e.integer("RECOVERY_WINDOW_DAYS").getAsInt();
      }
    }

    /**
     * Sets the endpoint override, e.g. {@code http://localhost:5000} for an emulator. Unset: the
     * AWS SDK resolves {@code https://secretsmanager.<region>.amazonaws.com}.
     *
     * @param url {@code http} or {@code https} URL
     * @return this builder
     */
    public Builder url(String url) {
      this.url = url;
      return this;
    }

    /**
     * Sets the connect timeout (default 10 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      this.connectTimeout = d;
      return this;
    }

    /**
     * Sets the per-attempt timeout (default 30 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      this.requestTimeout = d;
      return this;
    }

    /**
     * Sets the total timeout per call including retries (default 120 s).
     *
     * @param d positive duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      this.totalTimeout = d;
      return this;
    }

    /**
     * Sets the retry policy (default {@link RetryPolicy#defaults()}).
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      this.retry = retry;
      return this;
    }

    /**
     * Sets the TLS options; environment TLS variables are then ignored.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      this.tls = tls;
      return this;
    }

    /**
     * Sets an explicit proxy URL; environment proxies ({@code HTTPS_PROXY}) are never used.
     *
     * @param proxy proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      this.proxy = proxy;
      return this;
    }

    /**
     * Adds a header sent with every request.
     *
     * @param name header name
     * @param value header value
     * @return this builder
     */
    public Builder header(String name, String value) {
      this.headers.put(name, value);
      return this;
    }

    /**
     * Sets the text appended to the {@code User-Agent}.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      this.userAgentSuffix = suffix;
      return this;
    }

    /**
     * Sets request hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      this.hooks = hooks;
      return this;
    }

    /**
     * Sets the logger (default silent).
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      this.logger = logger;
      return this;
    }

    /**
     * Sets the AWS region.
     *
     * @param region region such as {@code eu-central-1}
     * @return this builder
     */
    public Builder region(String region) {
      this.region = region;
      return this;
    }

    /**
     * Sets the static access key id (requires {@link #secretAccessKey(String)}).
     *
     * @param accessKeyId key id
     * @return this builder
     */
    public Builder accessKeyId(String accessKeyId) {
      this.accessKeyId = accessKeyId;
      return this;
    }

    /**
     * Sets the static secret access key.
     *
     * @param secretAccessKey key
     * @return this builder
     */
    public Builder secretAccessKey(String secretAccessKey) {
      this.secretAccessKey = secretAccessKey == null ? null : Secret.of(secretAccessKey);
      return this;
    }

    /**
     * Sets the static secret access key.
     *
     * @param secretAccessKey key
     * @return this builder
     */
    public Builder secretAccessKey(Secret secretAccessKey) {
      this.secretAccessKey = secretAccessKey;
      return this;
    }

    /**
     * Sets the session token of temporary credentials.
     *
     * @param sessionToken token
     * @return this builder
     */
    public Builder sessionToken(String sessionToken) {
      this.sessionToken = sessionToken == null ? null : Secret.of(sessionToken);
      return this;
    }

    /**
     * Sets the session token of temporary credentials.
     *
     * @param sessionToken token
     * @return this builder
     */
    public Builder sessionToken(Secret sessionToken) {
      this.sessionToken = sessionToken;
      return this;
    }

    /**
     * Selects a shared config / credentials profile.
     *
     * @param profile profile name
     * @return this builder
     */
    public Builder profile(String profile) {
      this.profile = profile;
      return this;
    }

    /**
     * Uses an AWS SDK credentials provider instead of the key fields or the default chain.
     *
     * @param credentials provider
     * @return this builder
     */
    public Builder credentials(AwsCredentialsProvider credentials) {
      this.credentials = credentials;
      return this;
    }

    /**
     * Assumes this IAM role with STS on top of the base credentials.
     *
     * @param roleArn role ARN
     * @return this builder
     */
    public Builder roleArn(String roleArn) {
      this.roleArn = roleArn;
      return this;
    }

    /**
     * Sets the STS role session name (default {@value
     * AwsSecretsManagerConfig#DEFAULT_ROLE_SESSION_NAME}).
     *
     * @param name session name
     * @return this builder
     */
    public Builder roleSessionName(String name) {
      this.roleSessionName = name;
      return this;
    }

    /**
     * Sets the STS external id.
     *
     * @param externalId external id
     * @return this builder
     */
    public Builder externalId(String externalId) {
      this.externalId = externalId;
      return this;
    }

    /**
     * Sets the assumed-role session duration (900 s – 43 200 s; default: the role's default).
     *
     * @param duration duration
     * @return this builder
     */
    public Builder roleDuration(Duration duration) {
      this.roleDuration = duration;
      return this;
    }

    /**
     * Sets the recovery window of deletes in days (7–30, default 30).
     *
     * @param days window
     * @return this builder
     */
    public Builder recoveryWindowDays(int days) {
      this.recoveryWindowDays = days;
      return this;
    }

    /**
     * Wraps an existing AWS SDK client instead of building one. Mutually exclusive with the
     * credential, region, profile, role and endpoint fields; {@code close()} never closes it and
     * the Grow timeouts, retries, TLS, proxy, headers, hooks and User-Agent do not apply to it.
     *
     * @param sdkClient the client
     * @return this builder
     */
    public Builder sdkClient(SecretsManagerClient sdkClient) {
      this.sdkClient = sdkClient;
      return this;
    }

    /**
     * Builds and validates the configuration.
     *
     * @return the configuration
     * @throws ConfigException when a rule is violated
     */
    public AwsSecretsManagerConfig build() {
      if (env != null) {
        applyEnv(env);
      }
      AwsSecretsManagerConfig c = new AwsSecretsManagerConfig(this);
      c.validate();
      return c;
    }
  }
}
