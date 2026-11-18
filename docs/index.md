# AWS Secrets Manager SDK

[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)
[![CI](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/aws-secrets-manager/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](license.md)

One API for **AWS Secrets Manager** in five languages: TypeScript, Rust, Go, Python and Java. Every package
has the same functions, options, defaults, error codes and behaviour, tested against a real
`motoserver/moto:5.2.4` in Docker.

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [`@grow-codes/aws-secrets-manager`](https://www.npmjs.com/package/@grow-codes/aws-secrets-manager) | ![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-typescript.json) |
| Rust | [`grow-aws-secrets-manager`](https://crates.io/crates/grow-aws-secrets-manager) | ![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-rust.json) |
| Go | [`github.com/grow-codes-packages/aws-secrets-manager/go`](https://pkg.go.dev/github.com/grow-codes-packages/aws-secrets-manager/go) | ![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-go.json) |
| Python | [`grow-aws-secrets-manager`](https://pypi.org/project/grow-aws-secrets-manager/) | ![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-python.json) |
| Java | [`codes.grow.packages:aws-secrets-manager`](https://central.sonatype.com/artifact/codes.grow.packages/aws-secrets-manager) | ![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/aws-secrets-manager/badges/coverage-java.json) |

## What you get

- **Client** with health, authenticated ping and server version ([Client](client.md)).
- **Configuration** from code or `GROW_AWS_SECRETS_MANAGER_*` / vendor environment variables, immutable
  and validated ([Configuration](configuration.md)).
- **Retries** with full-jitter backoff and `Retry-After`, connect/request/total timeouts and
  cancellation in every language.
- **Typed errors** with one set of codes across languages ([Error handling](errors.md)).
- **Redaction everywhere**: credentials never appear in errors, logs, hooks or `toString`
  ([Redaction](redaction.md)).
- **Secrets**: typed getters, bulk reads, `loadEnv`, watch and a TTL cache ([Secrets](secrets.md)).
- **Service functions** for the AWS Secrets Manager API ([Functions](functions.md)).

Start with [Install](install.md) and the [Quickstart](quickstart.md).

!!! note "Independent project"
    This SDK is made by [Grow Codes](https://grow.codes). AWS Secrets Manager is a trademark of
    Amazon.com, Inc. or its affiliates. This project is not affiliated with or endorsed by Amazon.com, Inc. or its affiliates. See
    [License & disclaimer](license.md).
