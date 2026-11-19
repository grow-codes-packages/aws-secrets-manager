# Configuration

`AwsSecretsManagerConfig` holds every setting of a client. It is **immutable** after construction,
validated when it is built (invalid values raise a `CONFIG` error) and its string/debug form
**redacts every credential**. The AWS fields (region, credentials, profile, assume role, endpoint
override, recovery window, existing SDK client) are listed under
[Functions → Service configuration](functions.md#service-configuration); this page covers the
settings shared by every Grow Codes SDK and how they map onto the AWS SDK client.

## Common settings

| Setting | Default | Environment variable |
| - | - | - |
| `url` — endpoint override | none: the AWS SDK resolves `https://secretsmanager.<region>.amazonaws.com` | `GROW_AWS_SECRETS_MANAGER_URL`, `AWS_ENDPOINT_URL_SECRETS_MANAGER`, `AWS_ENDPOINT_URL` |
| `connectTimeout` — connection setup | 10 s | `GROW_AWS_SECRETS_MANAGER_CONNECT_TIMEOUT` |
| `requestTimeout` — per attempt (headers + body) | 30 s | `GROW_AWS_SECRETS_MANAGER_REQUEST_TIMEOUT` |
| `totalTimeout` — whole call incl. retries and backoff | 120 s | `GROW_AWS_SECRETS_MANAGER_TOTAL_TIMEOUT` |
| `retry` — retry policy (below); AWS SDK `maxAttempts = maxRetries + 1` | 3 retries | `GROW_AWS_SECRETS_MANAGER_MAX_RETRIES` |
| `tls.caCertPath` / `tls.caCertPem` — extra CA | none | `GROW_AWS_SECRETS_MANAGER_CA_CERT` (path) |
| `tls.clientCertPath` + `tls.clientKeyPath` — mutual TLS | none | `GROW_AWS_SECRETS_MANAGER_CLIENT_CERT`, `GROW_AWS_SECRETS_MANAGER_CLIENT_KEY` |
| `tls.insecureSkipVerify` — tests only, logs a warning once | `false` | `GROW_AWS_SECRETS_MANAGER_INSECURE_SKIP_VERIFY` |
| `proxy` — proxy URL | none (environment proxies are **ignored**) | `GROW_AWS_SECRETS_MANAGER_PROXY` |
| `headers` — extra request headers | `{}` | — |
| `userAgentSuffix` — appended to the User-Agent | none | — |
| `hooks` — request/response callbacks ([Hooks](hooks.md)) | none | — |
| `logger` — diagnostic logger ([Hooks](hooks.md)) | silent | — |

Every request sends the AWS SDK User-Agent with the suffix
`grow-codes-aws-secrets-manager/<version> (<language>)` (not when you pass your own `sdkClient`).

## From the environment

`fromEnv` resolves each setting with this precedence:

1. the value passed in code (overrides),
2. `GROW_AWS_SECRETS_MANAGER_<NAME>`,
3. the standard AWS variables (see [Functions](functions.md#service-configuration)), in their documented order,
4. the default — for region and credentials the AWS SDK default chain (shared config, SSO, web
   identity, container and instance roles).

Parsing rules:

- **Durations** accept integer milliseconds (`1500`) or Go-style units: `500ms`, `10s`, `2m`, `1h`,
  combinations such as `1m30s`.
- **Booleans** accept `true/false`, `1/0`, `yes/no`, `on/off` (any case).
- An **empty** variable counts as unset.
- A present but **invalid** value raises a `CONFIG` error that names the variable, never its value.

=== "TypeScript"

    ```ts
    import { AwsSecretsManagerClient, AwsSecretsManagerConfig } from "@grow-codes/aws-secrets-manager";

    // Environment only
    const client = AwsSecretsManagerClient.fromEnv();

    // Environment with explicit overrides (explicit values win)
    const config = AwsSecretsManagerConfig.fromEnv({ requestTimeoutMs: 5_000 });

    // Everything in code
    const explicit = new AwsSecretsManagerConfig({
      region: "eu-central-1",
      profile: "ops", // or accessKeyId + secretAccessKey, credentials, roleArn …
      connectTimeoutMs: 5_000,
      requestTimeoutMs: 15_000,
      totalTimeoutMs: 60_000,
      retry: { maxRetries: 5, initialBackoffMs: 200 },
      tls: { caCertPath: "/etc/ssl/internal-ca.pem" },
      proxy: "http://proxy.internal:3128",
      headers: { "x-team": "payments" },
      userAgentSuffix: "my-app/1.4",
    });
    const custom = new AwsSecretsManagerClient(explicit);
    console.log(String(explicit)); // credentials shown as [REDACTED]
    ```

=== "Rust"

    ```rust
    use std::time::Duration;
    use grow_aws_secrets_manager::{AwsSecretsManagerClient, AwsSecretsManagerConfig, RetryPolicy};

    // Environment only
    let client = AwsSecretsManagerClient::from_env()?;

    // Environment with explicit overrides (explicit values win)
    let config = AwsSecretsManagerConfig::builder()
        .request_timeout(Duration::from_secs(5))
        .build_from_env()?;

    // Everything in code
    let explicit = AwsSecretsManagerConfig::builder()
        .region("eu-central-1")
        .profile("ops") // or access_key_id + secret_access_key, credentials_provider, role_arn …
        .connect_timeout(Duration::from_secs(5))
        .request_timeout(Duration::from_secs(15))
        .total_timeout(Duration::from_secs(60))
        .retry(RetryPolicy::default().with_max_retries(5))
        .ca_cert_path("/etc/ssl/internal-ca.pem")
        .proxy("http://proxy.internal:3128")
        .header("x-team", "payments")
        .user_agent_suffix("my-app/1.4")
        .build()?;
    let custom = AwsSecretsManagerClient::new(explicit)?;
    println!("{:?}", custom.config()); // credentials shown as [REDACTED]
    ```

=== "Go"

    ```go
    // Environment only
    client, err := awssecretsmanager.NewClientFromEnv()

    // Everything in code: zero values mean "use the default"
    cfg := awssecretsmanager.Config{
        CommonConfig: awssecretsmanager.CommonConfig{
            ConnectTimeout:  5 * time.Second,
            RequestTimeout:  15 * time.Second,
            TotalTimeout:    time.Minute,
            Retry:           &awssecretsmanager.RetryPolicy{MaxRetries: 5, InitialBackoff: 200 * time.Millisecond},
            TLS:             awssecretsmanager.TLSConfig{CACertPath: "/etc/ssl/internal-ca.pem"},
            Proxy:           "http://proxy.internal:3128",
            Headers:         map[string]string{"x-team": "payments"},
            UserAgentSuffix: "my-app/1.4",
        },
        Region:  "eu-central-1",
        Profile: "ops", // or AccessKeyID + SecretAccessKey, Credentials, RoleARN …
    }
    if err := cfg.Validate(); err != nil {
        log.Fatal(err) // errors.Is(err, awssecretsmanager.ErrConfig)
    }
    custom, err := awssecretsmanager.NewClient(cfg)

    // Environment with explicit overrides (explicit values win; nil env = process environment)
    merged, err := awssecretsmanager.ConfigFromEnvWith(awssecretsmanager.Config{
        CommonConfig: awssecretsmanager.CommonConfig{RequestTimeout: 5 * time.Second},
    }, nil)
    fmt.Println(merged) // credentials shown as [REDACTED]
    ```

=== "Python"

    ```python
    from grow_aws_secrets_manager import RetryPolicy, TlsConfig, AwsSecretsManagerClient, AwsSecretsManagerConfig

    # Environment only
    client = AwsSecretsManagerClient.from_env()

    # Environment with explicit overrides (explicit values win)
    config = AwsSecretsManagerConfig.from_env(request_timeout=5.0)

    # Everything in code: durations are float seconds (datetime.timedelta also works)
    explicit = AwsSecretsManagerConfig(
        region="eu-central-1",
        profile="ops",  # or access_key_id + secret_access_key, credentials, role_arn …
        connect_timeout=5.0,
        request_timeout=15.0,
        total_timeout=60.0,
        retry=RetryPolicy(max_retries=5, initial_backoff=0.2),
        tls=TlsConfig(ca_cert_path="/etc/ssl/internal-ca.pem"),
        proxy="http://proxy.internal:3128",
        headers={"x-team": "payments"},
        user_agent_suffix="my-app/1.4",
    )
    custom = AwsSecretsManagerClient(explicit)
    print(repr(explicit))  # credentials shown as [REDACTED]
    ```

=== "Java"

    ```java
    import java.time.Duration;
    import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
    import codes.grow.packages.awssecretsmanager.AwsSecretsManagerConfig;
    import codes.grow.packages.awssecretsmanager.core.RetryPolicy;

    // Environment only
    AwsSecretsManagerClient client = AwsSecretsManagerClient.fromEnv();

    // Everything in code
    AwsSecretsManagerConfig config = AwsSecretsManagerConfig.builder()
        .region("eu-central-1")
        .profile("ops") // or accessKeyId + secretAccessKey, credentials, roleArn …
        .connectTimeout(Duration.ofSeconds(5))
        .requestTimeout(Duration.ofSeconds(15))
        .totalTimeout(Duration.ofMinutes(1))
        .retry(RetryPolicy.builder().maxRetries(5).initialBackoff(Duration.ofMillis(200)).build())
        .proxy("http://proxy.internal:3128")
        .header("x-team", "payments")
        .userAgentSuffix("my-app/1.4")
        .build();
    AwsSecretsManagerClient custom = AwsSecretsManagerClient.create(config);
    System.out.println(config); // credentials shown as [REDACTED]
    ```

## Retry policy

| Field | Default | Meaning |
| - | - | - |
| `maxRetries` | 3 | retries after the first attempt (so up to 4 attempts) |
| `initialBackoff` | 100 ms | backoff cap of the first retry |
| `maxBackoff` | 10 s | cap of every backoff |
| `multiplier` | 2 | growth of the cap per retry |
| `maxRetryAfter` | 60 s | longest server-requested `Retry-After` the client waits for |

Backoff for retry *n* (0-based) is **full jitter**: a random wait between 0 and
`min(maxBackoff, initialBackoff × multiplier^n)`.

Retries are executed by the **AWS SDK** in its standard retry mode with
`maxAttempts = maxRetries + 1` (throttling, transient 5xx and connection errors; the AWS SDKs mark
every Secrets Manager call as safe to retry because writes carry an idempotency token). Go and
Java use the backoff of this policy for the SDK retryer; TypeScript, Rust and Python use the AWS
SDK's own backoff. `RATE_LIMITED` errors carry `retryAfter` when AWS sends `Retry-After`. Set
`maxRetries` to 0 to turn retries off. `health()` never retries.

## Timeouts and cancellation

- `connectTimeout` bounds connection setup, `requestTimeout` each attempt, `totalTimeout` the whole
  call including backoff sleeps. An exhausted timeout raises `TIMEOUT`.
- Cancellation is honoured during requests and backoff sleeps and raises `CANCELLED`:
  TypeScript `{ signal }` (`AbortSignal`), Rust dropping the future, Go `ctx`, Python `cancel=`
  (`CancelToken`) or task cancellation, Java `…Async` futures (`cancel(true)`).

## TLS and proxies

- Add a private CA with `tls.caCertPath` (or the PEM text in `tls.caCertPem`).
- Mutual TLS needs `tls.clientCertPath` and `tls.clientKeyPath` together.
- `tls.insecureSkipVerify` disables certificate checks. Use it for local tests only; the client
  logs a warning once.
- `HTTP_PROXY`/`HTTPS_PROXY` are **ignored** so that credentials never leave through an unexpected
  proxy. Set `proxy` (or `GROW_AWS_SECRETS_MANAGER_PROXY`) to use one.
