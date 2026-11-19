# Grow Codes SDK for AWS Secrets Manager

[![CI](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/grow-codes-packages/aws-secrets-manager?sort=semver)](https://github.com/grow-codes-packages/aws-secrets-manager/releases)
[![Docs](https://img.shields.io/badge/docs-grow--codes--packages.github.io-blue)](https://grow-codes-packages.github.io/aws-secrets-manager/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [![npm](https://img.shields.io/npm/v/@grow-codes/aws-secrets-manager)](https://www.npmjs.com/package/@grow-codes/aws-secrets-manager) | [![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-typescript.json)](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml) |
| Rust | [![crates.io](https://img.shields.io/crates/v/grow-aws-secrets-manager)](https://crates.io/crates/grow-aws-secrets-manager) [![docs.rs](https://img.shields.io/docsrs/grow-aws-secrets-manager)](https://docs.rs/grow-aws-secrets-manager) | [![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-rust.json)](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml) |
| Go | [![Go Reference](https://pkg.go.dev/badge/github.com/grow-codes-packages/aws-secrets-manager/go.svg)](https://pkg.go.dev/github.com/grow-codes-packages/aws-secrets-manager/go) | [![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-go.json)](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml) |
| Python | [![PyPI](https://img.shields.io/pypi/v/grow-aws-secrets-manager)](https://pypi.org/project/grow-aws-secrets-manager/) | [![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-python.json)](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml) |
| Java | [![Maven Central](https://img.shields.io/maven-central/v/codes.grow.packages/aws-secrets-manager)](https://central.sonatype.com/artifact/codes.grow.packages/aws-secrets-manager) | [![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-java.json)](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml) |

Open-source client libraries for [AWS Secrets Manager](#trademarks-and-disclaimer) in **TypeScript,
Rust, Go, Python and Java** — one API, five idiomatic packages, built on the official AWS SDK of each
language and tested against the AWS API emulator Moto in Docker.

- **Official AWS SDKs underneath**: `@aws-sdk/client-secrets-manager` v3, `aws-sdk-secretsmanager`,
  AWS SDK for Go v2, `boto3` / `aioboto3` and AWS SDK for Java v2 — SigV4, the standard credential
  chain (env, SSO, profiles, web identity, ECS/EC2 roles) and an assume-role helper.
- **The whole Secrets Manager API**: values (string and binary), batch reads, describe, list with
  auto-pagination, versions and stage labels, delete/restore, tags, resource policies, rotation,
  random passwords and JSON field helpers.
- **AWS caching-client semantics**: a version-stage aware cache (TTL 1 h, 1 024 entries) that asks
  `DescribeSecret` before it re-reads a value.
- **Secrets**: the provider API shared by every Grow Codes secrets SDK — typed getters, `loadEnv`,
  change watching and a TTL cache with refresh-ahead.
- **One error model** (`AwsSecretsManagerError` with canonical codes, mapped by AWS error code),
  timeouts, retries and cancellation in every language; credentials and values are redacted in
  `toString`, logs, hooks and error messages.

## Contents

- [Supported service version](#supported-service-version)
- [Install](#install)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Function overview](#function-overview)
- [Testing with Docker](#testing-with-docker)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [Security](#security)
- [Licence](#licence)
- [Trademarks and disclaimer](#trademarks-and-disclaimer)
- [About Grow Codes](#about-grow-codes)

## Supported service version

AWS Secrets Manager is a managed service; the packages target its API version **`2017-10-17`**
(constant `API_VERSION`). CI runs every function against **`motoserver/moto:5.2.4`** (pinned by
digest), with IAM authentication enabled, and an optional live job against an AWS sandbox account.
What the emulator cannot serve is unit-tested; see [Compatibility](#compatibility) and
[docs/compatibility.md](docs/compatibility.md).

## Install

| Language | Package | Install |
| - | - | - |
| TypeScript (Node.js ≥ 22.12) | `@grow-codes/aws-secrets-manager` | `npm install @grow-codes/aws-secrets-manager` |
| Rust (MSRV 1.88) | `grow-aws-secrets-manager` | `cargo add grow-aws-secrets-manager` |
| Go (1.26+) | `github.com/grow-codes-packages/aws-secrets-manager/go` | `go get github.com/grow-codes-packages/aws-secrets-manager/go` |
| Python (≥ 3.10) | `grow-aws-secrets-manager` | `pip install grow-aws-secrets-manager` (async client: `pip install "grow-aws-secrets-manager[async]"`) |
| Java (17+) | `codes.grow.packages:aws-secrets-manager` | see below |

Maven:

```xml
<dependency>
  <groupId>codes.grow.packages</groupId>
  <artifactId>aws-secrets-manager</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
implementation("codes.grow.packages:aws-secrets-manager:0.1.0")
```

## Quickstart

Every package reads its configuration from the environment (see [Configuration](#configuration))
or from an explicit config object. Credentials come from the standard AWS chain unless you set
them. The examples check the service, verify the credentials and read a JSON secret.

```sh
export AWS_REGION=eu-central-1
export AWS_PROFILE=dev                 # or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, SSO, IAM role …
# export GROW_AWS_SECRETS_MANAGER_URL=http://127.0.0.1:5000   # Moto / LocalStack instead of AWS
```

### TypeScript

```ts
import { AwsSecretsManagerClient } from "@grow-codes/aws-secrets-manager";

const client = AwsSecretsManagerClient.fromEnv();
try {
  const health = await client.health(); // never throws for an unreachable service
  console.log(health.healthy, health.status);
  console.log("latency ms:", await client.ping());
  const secret = await client.getSecretValue("prod/app/db"); // value prints as [REDACTED]
  const host = await client.getJsonField("prod/app/db", "host");
  console.log(secret.versionId, secret.versionStages, host);
} finally {
  await client.close();
}
```

### Rust

```rust
use grow_aws_secrets_manager::AwsSecretsManagerClient;

#[tokio::main]
async fn main() -> grow_aws_secrets_manager::Result<()> {
    let client = AwsSecretsManagerClient::from_env()?;
    let health = client.health().await?;
    println!("{} {}", health.healthy, health.status);
    println!("latency: {:?}", client.ping().await?);
    let secret = client.get_secret_value("prod/app/db", Default::default()).await?;
    let host = client.get_json_field("prod/app/db", "host", Default::default()).await?;
    println!("{:?} {:?} {:?}", secret.version_id, secret.version_stages, host);
    client.close().await;
    Ok(())
}
```

### Go

```go
package main

import (
	"context"
	"fmt"
	"log"

	asm "github.com/grow-codes-packages/aws-secrets-manager/go"
)

func main() {
	ctx := context.Background()
	client, err := asm.NewClientFromEnv()
	if err != nil {
		log.Fatal(err) // CONFIG error naming the variable, never its value
	}
	defer client.Close()

	health, err := client.Health(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(health.Healthy, health.Status)
	secret, err := client.GetSecretValue(ctx, "prod/app/db", nil)
	if err != nil {
		log.Fatal(err) // errors.Is(err, asm.ErrNotFound) for a missing secret
	}
	host, _, err := client.GetJSONField(ctx, "prod/app/db", "host", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret.VersionID, secret.VersionStages, host)
}
```

### Python

```python
from grow_aws_secrets_manager import AwsSecretsManagerClient

with AwsSecretsManagerClient.from_env() as client:
    health = client.health()
    print(health.healthy, health.status)
    print("latency ms:", client.ping())
    secret = client.get_secret_value("prod/app/db")  # value prints as [REDACTED]
    host = client.get_json_field("prod/app/db", "host")
    print(secret.version_id, secret.version_stages, host)
```

Async code uses `AsyncAwsSecretsManagerClient` (aioboto3, extra `[async]`) with the same methods
(`async with`, `await client.get_secret_value(…)`).

### Java

```java
import codes.grow.packages.awssecretsmanager.AwsSecretValue;
import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;

try (AwsSecretsManagerClient client = AwsSecretsManagerClient.fromEnv()) {
    var health = client.health();
    System.out.println(health.healthy() + " " + health.status());
    System.out.println("latency: " + client.ping());
    AwsSecretValue secret = client.getSecretValue("prod/app/db"); // value prints as [REDACTED]
    var host = client.getJsonField("prod/app/db", "host");
    System.out.println(secret.versionId() + " " + secret.versionStages() + " " + host);
}
```

Every I/O method also has an async variant in Java (`getSecretValueAsync`, …) and takes a
cancellation signal / context in TypeScript, Go and Python. More complete programs live in
[examples/](examples/) — one folder per language.

## Configuration

All settings can be passed in code or through environment variables. Precedence: **explicit value >
`GROW_AWS_SECRETS_MANAGER_*` variable > standard AWS variable > AWS SDK default chain / default.** A
present but invalid value raises a `ConfigError` that names the variable (never its value).

| Setting | Environment variable | Default |
| - | - | - |
| `url` — endpoint override (emulator, VPC endpoint) | `GROW_AWS_SECRETS_MANAGER_URL`, `AWS_ENDPOINT_URL_SECRETS_MANAGER`, `AWS_ENDPOINT_URL` | none: the AWS SDK resolves `https://secretsmanager.<region>.amazonaws.com` |
| `region` | `GROW_AWS_SECRETS_MANAGER_REGION`, `AWS_REGION`, `AWS_DEFAULT_REGION` | AWS SDK chain (profile region); none → `CONFIG` |
| `accessKeyId` | `GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID`, `AWS_ACCESS_KEY_ID` | AWS default credential chain |
| `secretAccessKey` | `GROW_AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY` (same layer as the key id) | AWS default credential chain |
| `sessionToken` | `GROW_AWS_SECRETS_MANAGER_SESSION_TOKEN`, `AWS_SESSION_TOKEN` (same layer as the key id) | none |
| `profile` | `GROW_AWS_SECRETS_MANAGER_PROFILE`, `AWS_PROFILE` | AWS SDK default |
| `credentials` — an AWS SDK credentials provider | — | none |
| `roleArn` — assume a role with STS | `GROW_AWS_SECRETS_MANAGER_ROLE_ARN` | none |
| `roleSessionName` | `GROW_AWS_SECRETS_MANAGER_ROLE_SESSION_NAME` | `grow-sdk` |
| `externalId` | `GROW_AWS_SECRETS_MANAGER_EXTERNAL_ID` | none |
| `roleDuration` (900 s – 12 h) | — | the role's default |
| `recoveryWindowDays` — `SecretsProvider.delete` window | `GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS` | 30 (7–30) |
| `sdkClient` — use an existing AWS SDK client | — | none (the SDK builds one) |
| `connectTimeout` | `GROW_AWS_SECRETS_MANAGER_CONNECT_TIMEOUT` | 10 s |
| `requestTimeout` (per attempt) | `GROW_AWS_SECRETS_MANAGER_REQUEST_TIMEOUT` | 30 s |
| `totalTimeout` (including retries) | `GROW_AWS_SECRETS_MANAGER_TOTAL_TIMEOUT` | 120 s |
| `retry.maxRetries` (AWS SDK `maxAttempts = maxRetries + 1`, standard mode) | `GROW_AWS_SECRETS_MANAGER_MAX_RETRIES` | 3 |
| `tls.caCertPath` | `GROW_AWS_SECRETS_MANAGER_CA_CERT` | system roots |
| `tls.clientCertPath` / `tls.clientKeyPath` | `GROW_AWS_SECRETS_MANAGER_CLIENT_CERT` / `GROW_AWS_SECRETS_MANAGER_CLIENT_KEY` | none |
| `tls.insecureSkipVerify` (tests only) | `GROW_AWS_SECRETS_MANAGER_INSECURE_SKIP_VERIFY` | `false` |
| `proxy` | `GROW_AWS_SECRETS_MANAGER_PROXY` | none (environment proxies are ignored) |
| `headers`, `userAgentSuffix`, `hooks`, `logger` | — | none |

Static credentials are read **as one set**: when `GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID` is set,
the secret key and session token come from `GROW_AWS_SECRETS_MANAGER_*` only, never from `AWS_*`.
`sdkClient` is mutually exclusive with the credential, region and endpoint settings. Durations
accept milliseconds (`1500`) or units (`500ms`, `10s`, `1m30s`); booleans accept
`true/false/1/0/yes/no/on/off`. Field names follow each language's convention
(`request_timeout` in Python and Rust, `RequestTimeout` in Go, `roleDurationMs` / `role_duration_s`
for durations in TypeScript / Python). The full reference is in the
[documentation](https://grow-codes-packages.github.io/aws-secrets-manager/).

## Function overview

<!-- service:function-overview — the service fills this section; keep the heading. -->

The same functions exist in every language, named per language convention (`getSecretValue` in
TypeScript and Java, `get_secret_value` in Python and Rust, `GetSecretValue` in Go with `ctx`
first). All service functions are on the client; the portable provider is `client.secrets()` and
the AWS-style cache `client.secretCache()`. Each area links to its documentation page with full
examples in all five languages.

| Area | Functions | Description |
| - | - | - |
| [Client](docs/functions/client-setup.md) | `new` / `fromEnv` / `builder` / `withSdkClient`, `health`, `ping`, `serverVersion`, `close` | builds or wraps the AWS SDK client (region, credentials, endpoint, assume role); signed `ListSecrets` probe (`health` never throws for an unreachable service, auth failures count as reachable); `serverVersion` is always `UNSUPPORTED`; `close` is idempotent, later calls raise `CANCELLED` |
| [Read](docs/functions/read.md) | `getSecretValue`, `batchGetSecretValue`, `describeSecret`, `listSecrets`, `listSecretVersionIds` | values by version id or stage (string or binary, redacting wrapper); batch reads split into chunks of 20 and returned in request order; metadata; auto-paginating list iterators |
| [Write](docs/functions/write.md) | `createSecret`, `putSecretValue`, `updateSecret`, `updateSecretVersionStage`, `deleteSecret`, `restoreSecret` | text, bytes or JSON objects; stage labels; delete with a 7–30 day recovery window (AWS default 30) or `forceDeleteWithoutRecovery`, validated client side |
| [Tags + policy](docs/functions/tags-policy.md) | `tagResource`, `untagResource`, `putResourcePolicy`, `getResourcePolicy`, `deleteResourcePolicy`, `validateResourcePolicy` | tags as maps; policies as JSON text or objects (parsed on read) |
| [Rotation](docs/functions/rotation.md) | `rotateSecret`, `cancelRotateSecret` | Lambda rotation, `automaticallyAfterDays` or schedule expressions |
| [Utilities](docs/functions/utilities.md) | `getRandomPassword`, `getJsonField` | AWS-generated passwords as a redacting `Secret`; one field of a JSON secret (exact key or dot path) |
| [AWS secret cache](docs/functions/secret-cache.md) | `secretCache()` → `getSecretValue`, `getSecretString`, `getSecretBinary`, `refreshNow`, `invalidate`, `clear`, `stats`; `awsDefaults()` | AWS caching-client semantics: per (secret, stage), TTL 1 h, 1 024 entries, `DescribeSecret` version check |
| [Secrets (SecretsProvider)](docs/functions/secrets-provider.md) | `get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll`, `list`, `set`, `delete`, `metadata`, `loadEnv`, `watch`, `SecretCache` | the interface shared by every Grow Codes secrets SDK; `set` creates or adds a version, `delete` uses the recovery window unless `permanent` |

### Read

`getSecretValue`, `batchGetSecretValue`, `describeSecret`, `listSecrets`, `listSecretVersionIds` —
[documentation](docs/functions/read.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const s = await client.getSecretValue("app/db", { versionStage: "AWSPREVIOUS" });
const batch = await client.batchGetSecretValue(["app/db", "app/api"]);
for await (const meta of client.listSecrets({ filters: [{ key: "name", values: ["app/"] }] })) console.log(meta.name);
const versions = await client.listSecretVersionIds("app/db").toArray();
```

**Rust**

```rust
let s = client.get_secret_value("app/db", GetSecretValueOptions { version_stage: Some("AWSPREVIOUS".into()), ..Default::default() }).await?;
let batch = client.batch_get_secret_value(["app/db", "app/api"], Default::default()).await?;
let all = client.list_secrets(ListSecretsOptions { filters: vec![SecretFilter::name("app/")], ..Default::default() }).try_collect().await?;
let versions = client.list_secret_version_ids("app/db", Default::default()).try_collect().await?;
```

**Go**

```go
s, err := client.GetSecretValue(ctx, "app/db", &asm.GetSecretValueOptions{VersionStage: asm.StagePrevious})
batch, err := client.BatchGetSecretValue(ctx, asm.BatchGetSelector{SecretIDs: []string{"app/db", "app/api"}}, nil)
for meta, err := range client.ListSecrets(ctx, &asm.ListSecretsOptions{Filters: []asm.SecretFilter{{Key: asm.FilterName, Values: []string{"app/"}}}}) {
	if err != nil {
		return err
	}
	fmt.Println(meta.Name)
}
```

**Python**

```python
s = client.get_secret_value("app/db", version_stage=sdk.AWSPREVIOUS)
batch = client.batch_get_secret_value(["app/db", "app/api"])
names = [m.name for m in client.list_secrets(filters=[sdk.SecretFilter("name", ["app/"])])]
versions = client.list_secret_version_ids("app/db").to_list()
```

**Java**

```java
AwsSecretValue s = client.getSecretValue("app/db", GetSecretValueOptions.ofVersionStage("AWSPREVIOUS"));
BatchGetResult batch = client.batchGetSecretValue(List.of("app/db", "app/api"));
List<SecretDescription> all = client.listSecrets(ListSecretsOptions.builder().filters(List.of(SecretFilter.name("app/"))).build()).toList();
List<SecretVersion> versions = client.listSecretVersionIds("app/db").toList();
```

</details>

### Write

`createSecret`, `putSecretValue`, `updateSecret`, `updateSecretVersionStage`, `deleteSecret`,
`restoreSecret` — [documentation](docs/functions/write.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
await client.createSecret("app/db", { user: "app", password: "s3cret" }, { tags: { team: "platform" } });
const v2 = await client.putSecretValue("app/db", { user: "app", password: "rotated" });
await client.updateSecret("app/db", { description: "database login" });
await client.deleteSecret("app/db", { recoveryWindowDays: 7 });
await client.restoreSecret("app/db");
```

**Rust**

```rust
client.create_secret("app/db", Some(json!({"user": "app", "password": "s3cret"}).into()), CreateSecretOptions::default()).await?;
let v2 = client.put_secret_value("app/db", json!({"user": "app", "password": "rotated"}), Default::default()).await?;
client.update_secret("app/db", UpdateSecretOptions { description: Some("database login".into()), ..Default::default() }).await?;
client.delete_secret("app/db", DeleteSecretOptions { recovery_window_days: Some(7), ..Default::default() }).await?;
client.restore_secret("app/db").await?;
```

**Go**

```go
_, err := client.CreateSecret(ctx, "app/db", map[string]any{"user": "app", "password": "s3cret"}, &asm.CreateSecretOptions{Tags: map[string]string{"team": "platform"}})
v2, err := client.PutSecretValue(ctx, "app/db", map[string]any{"user": "app", "password": "rotated"}, nil)
_, err = client.UpdateSecret(ctx, "app/db", asm.UpdateSecretOptions{Description: "database login"})
_, err = client.DeleteSecret(ctx, "app/db", &asm.DeleteSecretOptions{RecoveryWindowDays: 7})
_, err = client.RestoreSecret(ctx, "app/db")
```

**Python**

```python
client.create_secret("app/db", {"user": "app", "password": "s3cret"}, tags={"team": "platform"})
v2 = client.put_secret_value("app/db", {"user": "app", "password": "rotated"})
client.update_secret("app/db", description="database login")
client.delete_secret("app/db", recovery_window_days=7)
client.restore_secret("app/db")
```

**Java**

```java
client.createSecret("app/db", Map.of("user", "app", "password", "s3cret"), CreateSecretOptions.builder().tags(Map.of("team", "platform")).build());
PutSecretValueResult v2 = client.putSecretValue("app/db", Map.of("user", "app", "password", "rotated"));
client.updateSecret("app/db", UpdateSecretOptions.builder().description("database login").build());
client.deleteSecret("app/db", DeleteSecretOptions.builder().recoveryWindowDays(7).build());
client.restoreSecret("app/db");
```

</details>

### Tags and resource policy

`tagResource`, `untagResource`, `putResourcePolicy`, `getResourcePolicy`, `deleteResourcePolicy`,
`validateResourcePolicy` — [documentation](docs/functions/tags-policy.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
await client.tagResource("app/db", { env: "prod" });
await client.untagResource("app/db", ["env"]);
await client.putResourcePolicy("app/db", policy, { blockPublicPolicy: true });
const { policy: current } = await client.getResourcePolicy("app/db");
const check = await client.validateResourcePolicy(policy);
await client.deleteResourcePolicy("app/db");
```

**Rust**

```rust
client.tag_resource("app/db", [("env", "prod")]).await?;
client.untag_resource("app/db", ["env"]).await?;
client.put_resource_policy("app/db", policy.clone(), PutResourcePolicyOptions { block_public_policy: Some(true) }).await?;
let current = client.get_resource_policy("app/db").await?;
let check = client.validate_resource_policy(policy, Default::default()).await?;
client.delete_resource_policy("app/db").await?;
```

**Go**

```go
err := client.TagResource(ctx, "app/db", map[string]string{"env": "prod"})
err = client.UntagResource(ctx, "app/db", []string{"env"})
_, err = client.PutResourcePolicy(ctx, "app/db", policy, &asm.PutResourcePolicyOptions{BlockPublicPolicy: aws.Bool(true)})
current, err := client.GetResourcePolicy(ctx, "app/db")
check, err := client.ValidateResourcePolicy(ctx, policy, nil)
_, err = client.DeleteResourcePolicy(ctx, "app/db")
```

**Python**

```python
client.tag_resource("app/db", {"env": "prod"})
client.untag_resource("app/db", ["env"])
client.put_resource_policy("app/db", policy, block_public_policy=True)
current = client.get_resource_policy("app/db").policy
check = client.validate_resource_policy(policy)
client.delete_resource_policy("app/db")
```

**Java**

```java
client.tagResource("app/db", Map.of("env", "prod"));
client.untagResource("app/db", List.of("env"));
client.putResourcePolicy("app/db", policy, PutResourcePolicyOptions.builder().blockPublicPolicy(true).build());
ResourcePolicyResult current = client.getResourcePolicy("app/db");
ValidateResourcePolicyResult check = client.validateResourcePolicy(policy);
client.deleteResourcePolicy("app/db");
```

</details>

### Rotation

`rotateSecret`, `cancelRotateSecret` — [documentation](docs/functions/rotation.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
await client.rotateSecret("app/db", { lambdaArn, rules: { automaticallyAfterDays: 30 } });
await client.cancelRotateSecret("app/db");
```

**Rust**

```rust
client.rotate_secret("app/db", RotateSecretOptions {
    lambda_arn: Some(lambda_arn), rules: Some(RotationRules { automatically_after_days: Some(30), ..Default::default() }), ..Default::default()
}).await?;
client.cancel_rotate_secret("app/db").await?;
```

**Go**

```go
_, err := client.RotateSecret(ctx, "app/db", &asm.RotateSecretOptions{LambdaARN: lambdaARN, Rules: &asm.RotationRules{AutomaticallyAfterDays: 30}})
_, err = client.CancelRotateSecret(ctx, "app/db")
```

**Python**

```python
client.rotate_secret("app/db", lambda_arn=lambda_arn, rules=sdk.RotationRules(automatically_after_days=30))
client.cancel_rotate_secret("app/db")
```

**Java**

```java
client.rotateSecret("app/db", RotateSecretOptions.builder().lambdaArn(lambdaArn).rules(RotationRules.everyDays(30)).build());
client.cancelRotateSecret("app/db");
```

</details>

### Utilities

`getRandomPassword`, `getJsonField` — [documentation](docs/functions/utilities.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const password = await client.getRandomPassword({ length: 24, excludePunctuation: true }); // Secret
const host = await client.getJsonField("app/db", "db.host");
```

**Rust**

```rust
let password = client.get_random_password(RandomPasswordOptions { length: Some(24), exclude_punctuation: Some(true), ..Default::default() }).await?;
let host = client.get_json_field("app/db", "db.host", Default::default()).await?;
```

**Go**

```go
password, err := client.GetRandomPassword(ctx, &asm.RandomPasswordOptions{Length: 24, ExcludePunctuation: true})
host, ok, err := client.GetJSONField(ctx, "app/db", "db.host", nil)
```

**Python**

```python
password = client.get_random_password(length=24, exclude_punctuation=True)
host = client.get_json_field("app/db", "db.host")
```

**Java**

```java
Secret password = client.getRandomPassword(RandomPasswordOptions.builder().length(24).excludePunctuation(true).build());
Optional<JsonNode> host = client.getJsonField("app/db", "db.host");
```

</details>

### AWS secret cache

`secretCache()` → `getSecretValue`, `getSecretString`, `getSecretBinary`, `refreshNow`,
`invalidate`, `clear`, `stats` — [documentation](docs/functions/secret-cache.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const cache = client.secretCache();
const db = JSON.parse(await cache.getSecretString("app/db"));
```

**Rust**

```rust
let cache = client.secret_cache(AwsSecretCacheOptions::default())?;
let db = cache.get_secret_string("app/db", None).await?;
```

**Go**

```go
cache, err := client.SecretCache(nil)
db, err := cache.GetSecretString(ctx, "app/db", nil)
```

**Python**

```python
cache = client.secret_cache()
db = cache.get_secret_string("app/db")
```

**Java**

```java
AwsSecretCache cache = client.secretCache();
String db = cache.getSecretString("app/db");
```

</details>

### Secrets (SecretsProvider)

`get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll`,
`list`, `set`, `delete`, `metadata`, `loadEnv`, `watch`, `SecretCache` —
[documentation](docs/functions/secrets-provider.md)

<details><summary>Example in all five languages</summary>

**TypeScript**

```ts
const p = client.secrets();
await p.set("app/db/password", "s3cret");
const pw = await p.require("app/db/password");
const names = (await p.list("app/db/")).map((m) => m.name);
```

**Rust**

```rust
let p = client.secrets(); // use grow_aws_secrets_manager::secrets::SecretsProvider
p.set("app/db/password", "s3cret".into(), None).await?;
let pw = p.require("app/db/password", None).await?;
let names = p.list(Some("app/db/")).await?;
```

**Go**

```go
p, err := client.Secrets()
_, err = p.Set(ctx, "app/db/password", "s3cret", nil)
pw, err := p.Require(ctx, "app/db/password", nil)
names, err := p.List(ctx, "app/db/")
```

**Python**

```python
p = client.secrets()
p.set("app/db/password", "s3cret")
pw = p.require("app/db/password")
names = [m.name for m in p.list("app/db/")]
```

**Java**

```java
AwsSecretsManagerSecretsProvider p = client.secrets();
p.set("app/db/password", "s3cret");
SecretValue pw = p.require("app/db/password");
List<SecretMetadata> names = p.list("app/db/");
```

</details>

<!-- /service:function-overview -->

## Testing with Docker

The integration suite runs every public function against the AWS API emulator
**`motoserver/moto:5.2.4`** in Docker, with IAM authentication enabled. Each language package is
packed and installed into a separate consumer project first, so the tests use the package exactly
as you would.

`docker/compose.service.yml` starts Moto (test-only, Apache-2.0) and a one-shot `curl` bootstrap
(`curl --aws-sigv4`) that creates an admin IAM user and key, a read-only user (for
`PERMISSION_DENIED` round trips) and two seed secrets (JSON and binary), then writes the test
credentials to `/bootstrap/env`. No real AWS credentials are involved.

```sh
make test-docker                     # all five languages
make test-docker LANGS="go python"   # a subset
```

No host ports are published and every run uses its own Compose project, so runs never collide; the
stack is always removed afterwards (`docker compose down -v`). Unit tests need no Docker:
`make test` or `make coverage`.

## Compatibility

| | TypeScript | Rust | Go | Python | Java |
| - | - | - | - | - | - |
| Runtime | Node.js ≥ 22.12, ESM + CJS | stable, MSRV 1.88 | 1.26, 1.27 | 3.10 – 3.14 | 17, 21, 25 |
| AWS SDK | `@aws-sdk/client-secrets-manager` v3 | `aws-sdk-secretsmanager` 1.x | AWS SDK for Go v2 | `boto3` (+ `aioboto3`) | AWS SDK for Java v2 |
| Async | `Promise` + `AbortSignal` | `async` (tokio), `blocking` feature | `context.Context` | sync + `asyncio` (extra `[async]`) | sync + `CompletableFuture` |
| Emulator in CI | `motoserver/moto:5.2.4` | `motoserver/moto:5.2.4` | `motoserver/moto:5.2.4` | `motoserver/moto:5.2.4` | `motoserver/moto:5.2.4` |

Moto 5.2.4 does not implement `ValidateResourcePolicy` (the SDK raises `UNSUPPORTED` for its HTML
500), has no Lambda runtime for real rotation, needs a recorded Lambda ARN before
`CancelRotateSecret`, and fails a whole `BatchGetSecretValue` call when a secret's `AWSCURRENT`
label was moved. These parts, the assume-role helper (STS), throttling and the exact AWS error
shapes are unit-tested; the list with reasons, the error mapping and the parity decisions shared by
all five packages are in [docs/compatibility.md](docs/compatibility.md).

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) first. All five languages keep the same API; a change lands in all of them
together. Parts of this repository are generated by
[sdk-kit](https://github.com/grow-codes-packages/sdk-kit) and changed there.

## Security

Please report vulnerabilities privately to [opensource@grow.codes](mailto:opensource@grow.codes).
See [SECURITY.md](SECURITY.md).

## Licence

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attributions
(the AWS SDKs used by each package, Moto for tests).

## Trademarks and disclaimer

This is an independent, community-maintained project. It is **not affiliated with, endorsed or
sponsored by its owner (Amazon.com, Inc. or its affiliates)**. Amazon Web Services, AWS and AWS Secrets Manager
are trademarks of Amazon.com, Inc. or its affiliates; they are used here only to name the service
this SDK connects to. AWS Secrets Manager is a proprietary managed service; this SDK contains no
AWS service code and talks to it only through the official, Apache-2.0 licensed AWS SDKs.

The software is provided "AS IS", without warranties or conditions of any kind. Grow Codes is not
responsible for any damage, data loss, security incident, outage or cost (including AWS charges)
that results from using it. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## About Grow Codes

This SDK is built and maintained by [Grow Codes](https://grow.codes). Grow Codes publishes the
client libraries it builds as open source in the
[grow-codes-packages](https://github.com/grow-codes-packages) organisation, generated from one
shared kit so that every service and every language behaves the same way. Learn more at
[grow.codes](https://grow.codes).
