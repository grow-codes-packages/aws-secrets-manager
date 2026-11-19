# Client setup

`AwsSecretsManagerClient` builds an AWS SDK Secrets Manager client from the Grow configuration or
wraps one you already have. The [shared client page](../client.md) covers `health`, `ping`,
`serverVersion` and `close` in general; this page covers what is specific to AWS.

| Function | Notes |
| - | - |
| `new AwsSecretsManagerClient(options)` / `AwsSecretsManagerClient::new(config)` / `NewClient(cfg)` / `AwsSecretsManagerClient(config)` / `create(config)` + `builder()` | region, credentials, endpoint override (`url`), assume-role helper, timeouts, retries, proxy, TLS CA / client certificate, extra headers and the User-Agent suffix `grow-codes-aws-secrets-manager/<version> (<language>)` are applied to the AWS SDK client |
| `fromEnv()` | `GROW_AWS_SECRETS_MANAGER_*` > standard `AWS_*` variables > AWS SDK default chain ([configuration](../functions.md#service-configuration)) |
| `withSdkClient(client)` / config `sdkClient` | wraps an existing AWS SDK client; `close()` never closes it and the Grow transport settings (hooks per attempt, TLS, proxy, User-Agent) do not apply to it |
| assume-role helper (`roleArn`, `roleSessionName` = `grow-sdk`, `externalId`, `roleDuration`) | wraps the base credentials in the AWS SDK's STS assume-role provider (TypeScript `fromTemporaryCredentials`, Rust `AssumeRoleProvider`, Go `stscreds`, Python botocore refreshable credentials, Java `StsAssumeRoleCredentialsProvider`) |
| `health()` | signed `ListSecrets {MaxResults: 1}`, timeout `min(requestTimeout, 5 s)`, **no retries**. `ok` when AWS answers — also when the credentials are rejected (`details.auth = "failed"`, the service is reachable; credentials are `ping()`'s job) or for any other 4xx (`details.httpStatus`); `degraded` when throttled; `unhealthy` on HTTP 5xx; `unreachable` on network errors and timeouts. Raises only `CANCELLED` (also on a closed client) and `CONFIG` |
| `ping()` | the same call with retries; returns the latency. Unknown key or bad signature → `AUTHENTICATION`; no `secretsmanager:ListSecrets` permission → `PERMISSION_DENIED` |
| `serverVersion()` | always `UNSUPPORTED`: AWS exposes no server version. The API contract date is the constant `API_VERSION` (`2017-10-17`) |
| `close()` | idempotent; stops the watchers of every provider created by `secrets()` and releases the SDK client this instance built. Every later call raises `CANCELLED` ("client is closed") |

=== "TypeScript"

    ```ts
    import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
    import { AwsSecretsManagerClient } from "@grow-codes/aws-secrets-manager";

    // From the environment (GROW_AWS_SECRETS_MANAGER_* > AWS_* > AWS SDK chain)
    const client = AwsSecretsManagerClient.fromEnv();

    // Explicit: region, profile and an assumed role
    const ops = new AwsSecretsManagerClient({
      region: "eu-central-1",
      profile: "ops",
      roleArn: "arn:aws:iam::123456789012:role/app-secrets",
      externalId: "grow",
      roleDurationMs: 3_600_000,
    });

    // Wrap an existing AWS SDK client (close() leaves it open)
    const wrapped = new AwsSecretsManagerClient({
      sdkClient: new SecretsManagerClient({ region: "us-east-1" }),
    });

    console.log(await client.health(), await client.ping());
    await Promise.all([client.close(), ops.close(), wrapped.close()]);
    ```

=== "Rust"

    ```rust
    use std::time::Duration;
    use grow_aws_secrets_manager::{AwsSecretsManagerClient, AwsSecretsManagerConfig};

    let client = AwsSecretsManagerClient::from_env()?;

    let config = AwsSecretsManagerConfig::builder()
        .region("eu-central-1")
        .profile("ops")
        .role_arn("arn:aws:iam::123456789012:role/app-secrets")
        .external_id("grow")
        .role_duration(Duration::from_secs(3600))
        .build()?;
    let ops = AwsSecretsManagerClient::new(config)?;

    let sdk_config = aws_config::load_from_env().await;
    let wrapped = AwsSecretsManagerClient::with_sdk_client(
        aws_sdk_secretsmanager::Client::new(&sdk_config),
    )?;

    println!("{:?} {:?}", client.health().await?, client.ping().await?);
    client.close().await;
    ops.close().await;
    wrapped.close().await;
    ```

=== "Go"

    ```go
    import (
        "github.com/aws/aws-sdk-go-v2/config"
        "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
        asm "github.com/grow-codes-packages/aws-secrets-manager/go"
    )

    client, err := asm.NewClientFromEnv()

    ops, err := asm.NewClient(asm.Config{
        Region:       "eu-central-1",
        Profile:      "ops",
        RoleARN:      "arn:aws:iam::123456789012:role/app-secrets",
        ExternalID:   "grow",
        RoleDuration: time.Hour,
    })

    awsCfg, err := config.LoadDefaultConfig(ctx)
    wrapped, err := asm.NewClient(asm.Config{SDKClient: secretsmanager.NewFromConfig(awsCfg)})

    health, err := client.Health(ctx)
    latency, err := client.Ping(ctx)
    defer client.Close()
    ```

=== "Python"

    ```python
    import boto3
    from grow_aws_secrets_manager import AwsSecretsManagerClient, AwsSecretsManagerConfig

    client = AwsSecretsManagerClient.from_env()

    ops = AwsSecretsManagerClient(AwsSecretsManagerConfig(
        region="eu-central-1",
        profile="ops",
        role_arn="arn:aws:iam::123456789012:role/app-secrets",
        external_id="grow",
        role_duration_s=3600,
    ))

    wrapped = AwsSecretsManagerClient.with_sdk_client(boto3.client("secretsmanager"))

    print(client.health(), client.ping())
    for c in (client, ops, wrapped):
        c.close()
    ```

    The async client `AsyncAwsSecretsManagerClient` (aioboto3) needs the optional extra:
    `pip install "grow-aws-secrets-manager[async]"`.

=== "Java"

    ```java
    import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;
    import java.time.Duration;
    import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

    try (AwsSecretsManagerClient client = AwsSecretsManagerClient.fromEnv();
        AwsSecretsManagerClient ops =
            AwsSecretsManagerClient.builder()
                .region("eu-central-1")
                .profile("ops")
                .roleArn("arn:aws:iam::123456789012:role/app-secrets")
                .externalId("grow")
                .roleDuration(Duration.ofHours(1))
                .build();
        SecretsManagerClient sdk = SecretsManagerClient.create();
        AwsSecretsManagerClient wrapped = AwsSecretsManagerClient.withSdkClient(sdk)) {
      System.out.println(client.health() + " " + client.ping());
    }
    ```
