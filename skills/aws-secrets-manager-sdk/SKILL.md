---
name: aws-secrets-manager-sdk
description: Add and use the Grow Codes SDK for AWS Secrets Manager (`aws-secrets-manager`) in TypeScript, Rust, Go, Python or Java projects. Use when code must read or write AWS Secrets Manager secrets - installing @grow-codes/aws-secrets-manager, the grow-aws-secrets-manager crate or PyPI package, the Go module github.com/grow-codes-packages/aws-secrets-manager/go or Maven codes.grow.packages:aws-secrets-manager, configuring it with AWS_* or GROW_AWS_SECRETS_MANAGER_* variables (region, profile, keys, assume role, endpoint override for Moto/LocalStack), getSecretValue/batch reads/versions/stages/rotation/resource policies, the AWS-style secret cache, the portable SecretsProvider, handling AwsSecretsManagerError codes, testing with the bundled fakes, or running the Docker (Moto) integration suite of this repository.
---

# AWS Secrets Manager SDK (Grow Codes)

One API for AWS Secrets Manager in five languages (categories: secrets), built on the official AWS
SDK of each language. Pick the package for the project's language, configure it from the
environment, and handle errors by their canonical code.

## 1. Add the package

| Language | Command | Import |
| - | - | - |
| TypeScript | `npm install @grow-codes/aws-secrets-manager` | `import { AwsSecretsManagerClient } from "@grow-codes/aws-secrets-manager"` |
| Rust | `cargo add grow-aws-secrets-manager` (add `tokio` with `macros,rt-multi-thread`; `serde_json` for JSON values) | `use grow_aws_secrets_manager::AwsSecretsManagerClient;` |
| Go | `go get github.com/grow-codes-packages/aws-secrets-manager/go` | `asm "github.com/grow-codes-packages/aws-secrets-manager/go"` (package `awssecretsmanager`) |
| Python | `pip install grow-aws-secrets-manager`; async client: `pip install "grow-aws-secrets-manager[async]"` (aioboto3) | `from grow_aws_secrets_manager import AwsSecretsManagerClient` |
| Java | Maven `codes.grow.packages:aws-secrets-manager` (Gradle `implementation("codes.grow.packages:aws-secrets-manager:<version>")`) | `import codes.grow.packages.awssecretsmanager.AwsSecretsManagerClient;` |

Check the latest version in the README badges before pinning one.

## 2. Configure

Prefer environment configuration so no credential is written into code. With nothing set the AWS
SDK default credential chain is used (env keys, SSO / shared config profiles, web identity, ECS and
EC2 instance roles) — on AWS compute usually only the region is needed:

```sh
export AWS_REGION=eu-central-1
export AWS_PROFILE=dev                         # or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (never committed)
export GROW_AWS_SECRETS_MANAGER_ROLE_ARN=arn:aws:iam::123456789012:role/app-secrets   # optional assume-role
export GROW_AWS_SECRETS_MANAGER_URL=http://localhost:5000                           # only for Moto/LocalStack
```

Precedence: explicit config value > `GROW_AWS_SECRETS_MANAGER_*` > standard AWS variables > AWS SDK
chain / default.

| Setting | Variables |
| - | - |
| endpoint override | `GROW_AWS_SECRETS_MANAGER_URL`, `AWS_ENDPOINT_URL_SECRETS_MANAGER`, `AWS_ENDPOINT_URL` |
| region | `GROW_AWS_SECRETS_MANAGER_REGION`, `AWS_REGION`, `AWS_DEFAULT_REGION` |
| static keys (one set, never mixed) | `GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` / `_SESSION_TOKEN`, else `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` |
| profile | `GROW_AWS_SECRETS_MANAGER_PROFILE`, `AWS_PROFILE` |
| assume role | `GROW_AWS_SECRETS_MANAGER_ROLE_ARN`, `_ROLE_SESSION_NAME` (default `grow-sdk`), `_EXTERNAL_ID`; duration in code (`roleDurationMs` / `role_duration` / `RoleDuration` / `role_duration_s` / `roleDuration`) |
| provider delete window | `GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS` (default 30, 7–30) |
| common | `…_CONNECT_TIMEOUT`, `…_REQUEST_TIMEOUT`, `…_TOTAL_TIMEOUT` (`10s`, `1500`), `…_MAX_RETRIES`, `…_CA_CERT`, `…_CLIENT_CERT`, `…_CLIENT_KEY`, `…_PROXY` (environment proxies are ignored unless set) |

An existing AWS SDK client can be wrapped instead (`sdkClient` / `withSdkClient` /
`with_sdk_client` / Go `Config.SDKClient`); `close()` then leaves it open.

## 3. Use

Create one client per process and close it on shutdown (TypeScript `await client.close()`, Rust
`client.close().await`, Go `defer client.Close()`, Python `with …`/`close()`, Java
try-with-resources). Calls on a closed client raise `CANCELLED`.

- `health()` never throws for an unreachable service (signed `ListSecrets`, no retries, ≤ 5 s);
  rejected credentials still count as reachable (`details.auth = "failed"`). Check `healthy`.
- `ping()` verifies credentials: `AUTHENTICATION` (unknown key, bad signature) or
  `PERMISSION_DENIED` (no `secretsmanager:ListSecrets`).
- `serverVersion()` always raises `UNSUPPORTED` (AWS has no server version; `API_VERSION` is
  `2017-10-17`).
- Errors carry `code` (`CONFIG`, `AUTHENTICATION`, `PERMISSION_DENIED`, `NOT_FOUND`, `CONFLICT`,
  `RATE_LIMITED`, `VALIDATION`, `UNAVAILABLE`, `TIMEOUT`, `UNSUPPORTED`, `CANCELLED`), `retryable`,
  `httpStatus` and `requestId`, mapped from the **AWS error code** (AWS answers 400 for throttling
  and access denied). Branch on the code, not on the message text. Go:
  `errors.Is(err, asm.ErrNotFound)`. A secret scheduled for deletion is `CONFLICT`
  (`InvalidRequestException`); the original AWS code: Go `asm.AWSErrorCode(err)`, Rust/Python
  `aws_error_code(err)`, Java `AwsErrors.awsErrorCode(err)`.
- Retries are done by the AWS SDK (standard mode, `maxAttempts = maxRetries + 1`).

### Secrets (portable provider API)

Prefer the provider when the code only reads and writes secret values: it is the same in every
Grow Codes secrets SDK. Get it with `client.secrets()` (Go `client.Secrets()`, which also returns an
error). Names are AWS secret names (`app/db/password`; `path` + name are joined with `/`).

Read with `get`/`getString`/`getJson`/`require` (missing or scheduled for deletion →
`null`/`None`/`nil`, `require` → `NOT_FOUND`), write with `set` (creates the secret or adds a
version, returns the `VersionId`), list with `list(prefix)`, load into the environment with
`loadEnv`, watch with `watch`. `delete` uses a 30-day recovery window (a name in its window cannot
be re-created until restored) — pass `permanent: true` for throw-away names. Values are
`SecretValue` objects: call `reveal()` only where the plain value is needed and never log it.

```ts
const db = await client.secrets().require("app/db/password");               // TypeScript
```

```python
db = client.secrets().require("app/db/password")                             # Python
```

```go
p, _ := client.Secrets(); db, err := p.Require(ctx, "app/db/password", nil)   // Go
```

```rust
let db = client.secrets().require("app/db/password", None).await?;          // Rust (use grow_aws_secrets_manager::secrets::SecretsProvider)
```

```java
SecretValue db = client.secrets().require("app/db/password");                // Java
```

<!-- service:skill-usage — the service adds its own functions and examples here. -->

### AWS Secrets Manager API (service functions)

Same names in every language, all on the client (camelCase in TypeScript/Java, snake_case in
Rust/Python, PascalCase with `ctx` first in Go):

| Need | Function |
| - | - |
| read a value (string or binary, by version id or stage) | `getSecretValue(id, {versionId, versionStage})` → `{arn, name, versionId, versionStages, createdDate, binary, value}` |
| one field of a JSON secret | `getJsonField(id, "db.host")` (exact key, else dot path; absent → null) |
| many values | `batchGetSecretValue(ids)` (chunks of 20, request order) or `batchGetSecretValue({filters})`; per-secret failures in `errors` |
| metadata, list, versions | `describeSecret`, `listSecrets({filters, includePlannedDeletion})`, `listSecretVersionIds` (lazy paginators) |
| create / new version / update | `createSecret(name, value, {description, kmsKeyId, tags})`, `putSecretValue(id, value, {versionStages})`, `updateSecret` — text → `SecretString`, bytes → `SecretBinary`, objects → JSON |
| move a stage (promote / roll back) | `updateSecretVersionStage(id, "AWSCURRENT", {moveToVersionId, removeFromVersionId})` |
| delete / restore | `deleteSecret(id, {recoveryWindowDays: 7..30} \| {forceDeleteWithoutRecovery: true})`, `restoreSecret` |
| tags, resource policy | `tagResource(id, map)`, `untagResource(id, keys)`, `put/get/deleteResourcePolicy`, `validateResourcePolicy` |
| rotation | `rotateSecret(id, {lambdaArn, rules: {automaticallyAfterDays \| scheduleExpression}})`, `cancelRotateSecret` |
| password | `getRandomPassword({length: 32, excludePunctuation, …})` → redacting `Secret` |
| hot-path reads with AWS caching-client semantics | `client.secretCache()` → `getSecretValue/getSecretString/getSecretBinary(id, stage?)`, `refreshNow`, `invalidate`, `stats` (TTL 1 h, 1 024 entries, `DescribeSecret` version check) |

Full examples for every function: `docs/functions/*.md`.

## 4. Test code that uses the SDK

Use the in-memory fakes from the testing module instead of a real AWS Secrets Manager in unit tests:
TypeScript `@grow-codes/aws-secrets-manager/testing`, Rust feature `testing`, Go package `testkit`, Python
`grow_aws_secrets_manager.testing`, Java `codes.grow.packages.awssecretsmanager.testing`. For tests
against an emulator, point `GROW_AWS_SECRETS_MANAGER_URL` at Moto (`motoserver/moto:5.2.4`); Moto
lacks `ValidateResourcePolicy` (→ `UNSUPPORTED`) and Lambda rotation, and reads without a stage are
stale after an `AWSCURRENT` move (read with `versionStage: "AWSCURRENT"`). See
`docs/compatibility.md`.

## 5. Work on this repository

Read `AGENTS.md` first. Short version: the five languages keep the same API; files with the
`Generated by sdk-kit` header are changed in sdk-kit, not here; `make lint coverage` must pass
(≥ 90 % lines and branches); `make test-docker LANGS="<lang>"` runs the integration suite against
`motoserver/moto:5.2.4` with IAM auth on (bootstrap writes `/bootstrap/env`).
