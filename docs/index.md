# AWS Secrets Manager SDK

[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)
[![CI](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](license.md)

One API for **AWS Secrets Manager** in five languages: TypeScript, Rust, Go, Python and Java. Every package
has the same functions, options, defaults, error codes and behaviour, tested against the AWS API emulator
`motoserver/moto:5.2.4` in Docker.

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [`@grow-codes/aws-secrets-manager`](https://www.npmjs.com/package/@grow-codes/aws-secrets-manager) | ![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-typescript.json) |
| Rust | [`grow-aws-secrets-manager`](https://crates.io/crates/grow-aws-secrets-manager) | ![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-rust.json) |
| Go | [`github.com/grow-codes-packages/aws-secrets-manager/go`](https://pkg.go.dev/github.com/grow-codes-packages/aws-secrets-manager/go) | ![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-go.json) |
| Python | [`grow-aws-secrets-manager`](https://pypi.org/project/grow-aws-secrets-manager/) | ![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-python.json) |
| Java | [`codes.grow.packages:aws-secrets-manager`](https://central.sonatype.com/artifact/codes.grow.packages/aws-secrets-manager) | ![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-java.json) |

## What you get

- **Built on the official AWS SDKs** (`@aws-sdk/client-secrets-manager`, `aws-sdk-secretsmanager`,
  AWS SDK for Go v2, `boto3` / `aioboto3`, AWS SDK for Java v2): SigV4, the standard credential
  chain, SSO, IAM roles and an assume-role helper, with the Grow configuration mapped onto them
  ([Client setup](functions/client-setup.md)).
- **The whole AWS Secrets Manager API**: read, batch read, describe and list with auto-pagination,
  create, new versions, stage labels, delete/restore, tags, resource policies, rotation, random
  passwords and JSON fields ([Functions](functions.md)).
- **AWS caching-client semantics**: a version-stage aware cache (TTL 1 h, 1 024 entries) that
  checks `DescribeSecret` before re-reading a value ([AWS secret cache](functions/secret-cache.md)).
- **Secrets**: the portable provider API shared by every Grow Codes secrets SDK — typed getters,
  bulk reads, `loadEnv`, watch and a TTL cache ([Secrets over AWS](functions/secrets-provider.md)).
- **Configuration** from code or `GROW_AWS_SECRETS_MANAGER_*` / standard `AWS_*` environment
  variables, immutable and validated ([Configuration](configuration.md)).
- **Typed errors** mapped by AWS error code to one set of codes across languages
  ([Error handling](errors.md)); timeouts, retries and cancellation in every language.
- **Redaction everywhere**: credentials and secret values never appear in errors, logs, hooks or
  `toString` ([Redaction](redaction.md)).

Start with [Install](install.md) and the [Quickstart](quickstart.md).

!!! note "Independent project"
    This SDK is made by [Grow Codes](https://grow.codes). AWS Secrets Manager is a trademark of
    Amazon.com, Inc. or its affiliates. This project is not affiliated with or endorsed by Amazon.com, Inc. or its affiliates. See
    [License & disclaimer](license.md).
