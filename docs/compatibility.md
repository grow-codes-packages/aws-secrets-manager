# Compatibility

## Runtimes

| Language | Supported | Tested in CI | AWS SDK |
| - | - | - | - |
| TypeScript | Node.js ≥ 22.12, ESM and CommonJS | Node 22, 24 | `@aws-sdk/client-secrets-manager` v3 (+ `@aws-sdk/credential-providers`) |
| Rust | MSRV 1.88, edition 2021, tokio | stable, 1.88 | `aws-sdk-secretsmanager` 1.x + `aws-config` (no default features; own `reqwest`/rustls HTTP client) |
| Go | Go ≥ 1.26 | 1.26, 1.27 | AWS SDK for Go v2 (`service/secretsmanager`, `config`, `credentials/stscreds`) |
| Python | ≥ 3.10 | 3.10, 3.13, 3.14 | `boto3` (sync); `aioboto3` for `AsyncAwsSecretsManagerClient` via the optional extra `[async]` |
| Java | ≥ 17 (Java 17 bytecode) | Temurin 17, 21, 25 | AWS SDK for Java v2 (`secretsmanager`, `sts`) with an own `java.net.http` `SdkHttpClient` |

The Python async extra pins boto3/botocore to the window aioboto3 supports
(`pip install "grow-aws-secrets-manager[async]"`); sync-only users keep an unpinned `boto3`.

## AWS Secrets Manager versions

The packages target the AWS Secrets Manager API `2017-10-17` (constant `API_VERSION`). AWS exposes no
server version, so `serverVersion()` raises `UNSUPPORTED` in every language. The Docker suite runs
against the emulator **`motoserver/moto:5.2.4`** (Apache-2.0, test-only, never bundled) with IAM
authentication enabled; LocalStack needs an auth token since 2026.03 and is not used. An optional
live job against an AWS sandbox account is gated on repository secrets.

## Functions the emulator cannot serve

Every public function is called against Moto in the Docker suite of each language. These parts
cannot be served by Moto 5.2.4; the Docker suites assert Moto's documented answer and the AWS
behaviour is covered by unit tests replaying recorded AWS wire shapes:

| Function / case | Languages | Reason | Covered by |
| - | - | - | - |
| `validateResourcePolicy` result | all | not implemented in Moto 5.2.4: HTTP 500 with an HTML body. The SDK maps that answer (for this operation only) to `UNSUPPORTED` | unit tests of the AWS response; Docker asserts `UNSUPPORTED` |
| `rotateSecret` with a Lambda ARN (real rotation steps) | all | no Lambda runtime in the fixture (it would need Docker-in-Docker); Moto answers `ResourceNotFoundException` → `NOT_FOUND`. Rules-only rotation works and is verified | unit tests; Docker asserts `NOT_FOUND` |
| `cancelRotateSecret` | all | Moto only accepts it after a Lambda ARN has been recorded on the secret (the failed `rotateSecret` call above records it) | Docker (after the Lambda call), unit tests |
| assume-role helper | all | STS is not part of the fixture | unit tests against a mocked STS endpoint |
| `RATE_LIMITED` (`ThrottlingException`, `Retry-After`) | all | not emulated | unit tests |
| AWS-exact error statuses (400 JSON for not-found, access denied and auth errors) | all | Moto answers 404 for not-found and 403 **XML** for IAM errors; the mapping is by AWS error code, so both shapes are tested | unit tests (AWS shapes), Docker (Moto shapes) |
| BatchGet 20-id limit, `ListSecretVersionIds` paging and not-found | all | Moto does not enforce the limit (chunking is unit-tested), ignores `MaxResults` and answers HTTP 500 for a missing secret | unit tests |

## Moto 5.2.4 differences from AWS

Recorded as fixtures in the prep and handled in the integration tests:

- `BatchGetSecretValue` **fails the whole call** for a secret whose `AWSCURRENT` label was moved,
  instead of reporting it in `Errors`; the suites read such secrets one by one.
- `GetSecretValue` **without** a stage still returns the old version after `AWSCURRENT` was moved
  with `updateSecretVersionStage`; with `versionStage: "AWSCURRENT"` it is correct, so the suites
  read back with an explicit stage. After a rules-only rotation `GetSecretValue(VersionStage =
  AWSCURRENT)` can answer `NOT_FOUND`; rotation tests use their own secret.
- `UpdateSecret` without `ClientRequestToken` → `ResourceExistsException` (the AWS SDKs always fill
  the token, so only raw callers hit this).
- Not validated by Moto: `SecretString` and `SecretBinary` together, malformed resource policies,
  `BlockPublicPolicy`, KMS key ids, more than 20 ids in `BatchGetSecretValue`.
- The `name` filter matches string prefixes only (AWS also matches word prefixes); the provider's
  `list` always re-filters client side.
- `NextToken` may be `null` or `""` at the end of a list; both end the paginators.
- Moto error messages contain doubled text and runs of spaces — the tests assert codes, never
  messages.

## Error mapping

AWS JSON services answer HTTP 400 for throttling and access denied, so errors are mapped by **AWS
error code** first and by HTTP status only as a fallback (same table in all five languages):

| AWS error code(s) | Code |
| - | - |
| `ResourceNotFoundException` | `NOT_FOUND` |
| `ResourceExistsException`, `PreconditionNotMetException`, `InvalidRequestException` (e.g. scheduled for deletion, rotation in progress) | `CONFLICT` |
| `InvalidParameterException`, `InvalidParameterValue`, `ValidationException`, `InvalidNextTokenException`, `MalformedPolicyDocumentException`, `PublicPolicyException`, `LimitExceededException`, `EncryptionFailure`, `DecryptionFailure`, `SerializationException` | `VALIDATION` |
| `AccessDeniedException`, `AccessDenied` | `PERMISSION_DENIED` |
| `UnrecognizedClientException`, `InvalidClientTokenId`, `InvalidAccessKeyId`, `InvalidSignatureException`, `SignatureDoesNotMatch`, `IncompleteSignature(Exception)`, `MissingAuthenticationToken(Exception)`, `ExpiredToken(Exception)`, missing credentials | `AUTHENTICATION` |
| `ThrottlingException`, `Throttling`, `TooManyRequestsException`, `RequestLimitExceeded` | `RATE_LIMITED` (retryable, honours `Retry-After`) |
| `InternalServiceError(Exception)`, `InternalFailure`, `ServiceUnavailable(Exception)`, HTTP 5xx | `UNAVAILABLE` (retryable) |
| `RequestTimeout(Exception)`, SDK timeouts, the total timeout | `TIMEOUT` |
| HTTP 403 without a recognised code (Moto's XML) | `AUTHENTICATION` when the body mentions `InvalidClientTokenId`, `SignatureDoesNotMatch` or `security token`, else `PERMISSION_DENIED` |
| HTTP 500 HTML for `validateResourcePolicy` | `UNSUPPORTED` |
| caller cancellation, any call on a closed client | `CANCELLED` |

The AWS message is redacted and shortened before it becomes part of `error.message`
(`"<operation>: <AwsCode>: <text> (HTTP <status>)"`). The AWS error code stays available: Go
`AWSErrorCode(err)`, Rust `aws_error_code(&err)`, Python `aws_error_code(err)`, Java
`AwsErrors.awsErrorCode(err)`, TypeScript through `err.cause` (the AWS SDK exception, `name` = the
code).

## Skipped conformance scenarios

| Scenario | Reason |
| - | - |
| `core.health` → `serverVersion` step | skipped by the runner because the service has no `version` capability (`serverVersion()` is always `UNSUPPORTED`) |

All `secrets.*` scenarios (`roundtrip`, `missing`, `bulk`, `redaction`) run with the capabilities
`write`, `versions`, `delete` in all five languages.

## Parity decisions

Binding for all five packages (recorded during the GRO-1370 integration):

- Transport is the official AWS SDK of each language (SPEC exception for cloud SDK services): the
  Grow config maps onto it, retries use the AWS SDK standard mode with
  `maxAttempts = maxRetries + 1`, the Grow hooks fire per attempt where the package owns the HTTP
  client.
- Environment: `GROW_AWS_SECRETS_MANAGER_*` > `AWS_*` > AWS SDK chain; static credentials come from
  one layer only (a `GROW_*` key id is never paired with an `AWS_*` secret key).
- `health()`: probe timeout `min(requestTimeout, 5 s)`, no retries; authentication and permission
  failures and any other 4xx count as `ok` (with details); details carry canonical codes.
- `deleteSecret`: window and force together, or a window outside 7–30, are rejected client side;
  without options AWS applies its 30-day default. `SecretsProvider.delete` uses the
  `recoveryWindowDays` setting (default 30) unless `permanent: true`.
- `getJsonField`: an exact key wins over a dot path; JSON `null` counts as absent.
- `getRandomPassword`: default length 32.
- `SecretCache`: the service exports the AWS-semantics `AwsSecretCache` (TTL 1 h, 1 024 entries,
  stage-aware) and an `awsDefaults()` preset for the generic SPEC cache (whose own defaults stay
  60 s / 1 000).
- Any call on a closed client raises `CANCELLED` ("client is closed").

## Language differences

The API is the same in every language; only the conventions differ (naming, durations, async
model).

- Java cannot change the process environment, so `loadEnv` sets **system properties** instead and
  returns the names it set.
- Go has no optional arguments: zero values mean "not set" (`RecoveryWindowDays: 0`, `Length: 0` →
  32), pointers are used where `false` must be sent (`RotateImmediately`, `BlockPublicPolicy`,
  `RequireEachIncludedType`). Go validates `getRandomPassword` length (1–4096) and a batch read
  without ids or filters client side; the other languages let AWS reject them with the same
  `VALIDATION` code. A batch read with an empty id list returns an empty result in TypeScript,
  Rust, Python and Java.
- Go list calls return `iter.Seq2[T, error]`; the other languages return a paginator object.
- Java `updateSecretVersionStage` rejects a call with neither `moveToVersionId` nor
  `removeFromVersionId` before sending it (AWS answers `VALIDATION` for it as well).
- Python async needs the `[async]` extra (aioboto3); the sync client only needs `boto3`.
- With a caller-supplied AWS SDK client (`sdkClient` / `withSdkClient`), the Grow TLS, proxy,
  User-Agent and per-attempt hooks do not apply — they are properties of the HTTP client that the
  caller built.
