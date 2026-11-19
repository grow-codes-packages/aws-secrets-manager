# Troubleshooting

## The client cannot connect

- `health()` returns `healthy: false, status: "unreachable"`: the endpoint cannot be reached. With
  no `url` set the AWS SDK uses `https://secretsmanager.<region>.amazonaws.com` — check the region
  and outbound HTTPS (VPC endpoints, firewalls). With an override, check
  `GROW_AWS_SECRETS_MANAGER_URL` / `AWS_ENDPOINT_URL_SECRETS_MANAGER` (inside Docker, `127.0.0.1` is
  the container itself).
- `CONFIG` "no AWS region configured": set `region`, `GROW_AWS_SECRETS_MANAGER_REGION`,
  `AWS_REGION` or a region in the shared config profile.
- Calls fail with `UNAVAILABLE` after several seconds: the AWS SDK retried with backoff. Lower
  `maxRetries` or `totalTimeout` to fail faster.
- Behind a corporate proxy: `HTTP_PROXY`/`HTTPS_PROXY` are **ignored** on purpose. Set `proxy`
  (or `GROW_AWS_SECRETS_MANAGER_PROXY`).

## `CONFIG` errors

The message names the setting or environment variable, never its value. Typical causes: a URL
without `http://` or `https://`, a duration such as `10 sec` (use `10s` or `10000`), a client
certificate without its key, `MAX_RETRIES` below 0.

## `AUTHENTICATION` or `PERMISSION_DENIED`

- `ping()` is the quickest credential check: one signed `ListSecrets` call. `health()` stays
  `ok` with `details.auth = "failed"` when only the credentials are wrong.
- `AUTHENTICATION`: unknown access key, wrong secret key, expired session token or no credentials
  found in the AWS chain. Check which layer is used: explicit config >
  `GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID` (+ its own secret key and session token) >
  `AWS_ACCESS_KEY_ID` > profile / SSO / role. A `GROW_*` key id is never combined with an `AWS_*`
  secret key.
- `PERMISSION_DENIED`: the principal lacks the IAM action (for example
  `secretsmanager:GetSecretValue`, `kms:Decrypt` for a customer-managed key) or a resource policy
  denies it. With `roleArn`, the base credentials also need `sts:AssumeRole` (and the right
  `externalId`).
- The SDK never prints credentials, so `toString()` of the config shows `[REDACTED]` even when keys
  are set.

## `CONFLICT` on reads or creates

- `getSecretValue` → `CONFLICT`: the secret is scheduled for deletion (`InvalidRequestException`);
  `restoreSecret` it or wait for the recovery window to end. The provider reports such a secret as
  missing.
- `createSecret` → `CONFLICT`: the name exists, possibly in its recovery window. Use
  `forceDeleteWithoutRecovery` / `permanent: true` for names you want to re-create at once.

## TLS errors

- Self-signed or private CA: set `tls.caCertPath` (`GROW_AWS_SECRETS_MANAGER_CA_CERT`).
- Mutual TLS: set both `tls.clientCertPath` and `tls.clientKeyPath`.
- `tls.insecureSkipVerify` only for local tests.

## `RATE_LIMITED`

AWS throttled the calls (`ThrottlingException`). Use the [AWS secret cache](functions/secret-cache.md)
for hot paths. The AWS SDK retries throttled calls with backoff; when the retries are used up the
error is `RATE_LIMITED` (retryable, with `retryAfter` when AWS sent `Retry-After`) so your code can
schedule a later attempt.

## `TIMEOUT`

`requestTimeout` (30 s) bounds one attempt and `totalTimeout` (120 s) the whole call including
retries. Raise them for slow operations, or pass a per-call deadline (signal, ctx, cancel token,
future timeout).

## See what the client does

Turn on the [logger](hooks.md#logger) or add [hooks](hooks.md#hooks): both see every attempt with
redacted headers and URLs.

## Docker integration tests fail

- Run one language: `make test-docker LANGS=go`.
- In CI, download the `compose-logs-<lang>` artifact of the failed job.
- Locally, the stack is removed after each run; rerun with Docker logs open
  (`docker compose -f docker/compose.yml logs -f`) in a second terminal.

## Still stuck?

Open an issue with the language, package version, AWS region (or emulator version) and a minimal reproduction
(with secrets removed): <https://github.com/grow-codes-packages/aws-secrets-manager/issues>.
