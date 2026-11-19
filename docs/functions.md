# Functions

The AWS Secrets Manager API of this SDK. Every function exists in all five languages with the same
behaviour; the module pages show each one with an example per language. Names follow each
language's convention (`createSecret` in TypeScript and Java, `create_secret` in Rust and Python,
`CreateSecret` in Go with `ctx` first).

!!! info "Built on the official AWS SDKs"
    Every package calls AWS through the official AWS SDK of its language
    (`@aws-sdk/client-secrets-manager` v3, `aws-sdk-secretsmanager`, AWS SDK for Go v2,
    `boto3` / `aioboto3`, AWS SDK for Java v2). The AWS SDK signs (SigV4), serialises and retries;
    this SDK maps the Grow configuration onto it (timeouts, retries with
    `maxAttempts = maxRetries + 1`, endpoint, proxy, TLS, User-Agent, hooks), wraps every value in
    a redacting type and maps AWS error **codes** to the canonical error classes. The underlying
    AWS SDK client is available as an escape hatch (`client.sdk`, `client.SDK()`, `client.sdk()`).

| Module | Functions | AWS operations | Page |
| - | - | - | - |
| Client | `AwsSecretsManagerClient` (`new` / `fromEnv` / `builder` / `withSdkClient`), `health`, `ping`, `serverVersion` (always `UNSUPPORTED`), `close`, assume-role helper | `ListSecrets {MaxResults: 1}` | [Client setup](functions/client-setup.md) |
| Read | `getSecretValue`, `batchGetSecretValue`, `describeSecret`, `listSecrets`, `listSecretVersionIds` | `GetSecretValue`, `BatchGetSecretValue`, `DescribeSecret`, `ListSecrets`, `ListSecretVersionIds` | [Read](functions/read.md) |
| Write | `createSecret`, `putSecretValue`, `updateSecret`, `updateSecretVersionStage`, `deleteSecret`, `restoreSecret` | same names | [Write](functions/write.md) |
| Tags + resource policy | `tagResource`, `untagResource`, `putResourcePolicy`, `getResourcePolicy`, `deleteResourcePolicy`, `validateResourcePolicy` | same names | [Tags and policy](functions/tags-policy.md) |
| Rotation | `rotateSecret`, `cancelRotateSecret` | same names | [Rotation](functions/rotation.md) |
| Utilities | `getRandomPassword`, `getJsonField` | `GetRandomPassword`, `GetSecretValue` + JSON | [Utilities](functions/utilities.md) |
| AWS secret cache | `secretCache()` → `AwsSecretCache` (`getSecretValue`, `getSecretString`, `getSecretBinary`, `refreshNow`, `invalidate`, `clear`, `stats`), `awsDefaults()` preset | `GetSecretValue`, `DescribeSecret` | [AWS secret cache](functions/secret-cache.md) |
| SecretsProvider | `secrets()` → the shared [Secrets](secrets.md) interface: `get`, `getString`, `getJson`, `getNumber`, `getBool`, `require`, `exists`, `getMany`, `getAll`, `list`, `set`, `delete`, `metadata`, `loadEnv`, `watch`, `SecretCache` | see the page | [Secrets over AWS](functions/secrets-provider.md) |

List calls return a lazy **paginator** that follows `NextToken` (TypeScript `for await` /
`toArray()`, Rust `Paginator` with `next` / `try_collect` / `into_stream`, Go `iter.Seq2`, Python
`Paginator` / `AsyncPaginator` with `to_list()`, Java `Paginator` = `Iterable` with `toList()` /
`stream()`).

Every function is called against the Moto emulator (`motoserver/moto:5.2.4`) in the Docker suite of
each language. What Moto cannot serve (and is therefore unit-tested against the recorded AWS wire
shapes) is listed in [Compatibility](compatibility.md).

## Service configuration

| Setting | Default | Environment variables (precedence order) |
| - | - | - |
| `url` — endpoint override (Moto, LocalStack, VPC endpoint) | none: the AWS SDK resolves `https://secretsmanager.<region>.amazonaws.com` | `GROW_AWS_SECRETS_MANAGER_URL`, `AWS_ENDPOINT_URL_SECRETS_MANAGER`, `AWS_ENDPOINT_URL` |
| `region` | AWS SDK chain (shared config profile) | `GROW_AWS_SECRETS_MANAGER_REGION`, `AWS_REGION`, `AWS_DEFAULT_REGION` |
| `accessKeyId` / `secretAccessKey` / `sessionToken` — static credentials, read **as one set** | AWS default credential chain (env, SSO/shared config, web identity, container, IMDS) | `GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID` + `_SECRET_ACCESS_KEY` + `_SESSION_TOKEN`, otherwise `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_SESSION_TOKEN` |
| `profile` — shared config / credentials profile | AWS SDK default | `GROW_AWS_SECRETS_MANAGER_PROFILE`, `AWS_PROFILE` |
| `credentials` — an AWS SDK credentials provider object | none | — (code only) |
| `roleArn` — assume this role with STS on top of the base credentials | none | `GROW_AWS_SECRETS_MANAGER_ROLE_ARN` (no `AWS_ROLE_ARN` fallback: that one belongs to web identity in the AWS chain) |
| `roleSessionName` | `grow-sdk` | `GROW_AWS_SECRETS_MANAGER_ROLE_SESSION_NAME` |
| `externalId` | none | `GROW_AWS_SECRETS_MANAGER_EXTERNAL_ID` |
| `roleDuration` — assumed-role session length (900 s – 12 h) | the role's default | — (TypeScript `roleDurationMs`, Python `role_duration_s`, Rust/Go/Java `Duration`) |
| `recoveryWindowDays` — recovery window of `SecretsProvider.delete` | `30` (7–30) | `GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS` |
| `sdkClient` — an existing AWS SDK Secrets Manager client | none: the SDK builds one | — (code only; mutually exclusive with the credential, region and endpoint settings) |

A GROW key id is never paired with an AWS secret key: when
`GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID` is set, the secret key and session token are read only from
`GROW_AWS_SECRETS_MANAGER_*`. A key id without a secret key (or the other way round) is a
`CONFIG` error. The common settings (timeouts, retries, TLS, proxy, headers, hooks, logger) are
described in [Configuration](configuration.md); their environment variables use the same
`GROW_AWS_SECRETS_MANAGER_` prefix.
