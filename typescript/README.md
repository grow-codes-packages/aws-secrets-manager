# @grow-codes/aws-secrets-manager

TypeScript SDK for [AWS Secrets Manager](https://grow-codes-packages.github.io/aws-secrets-manager/) by Grow Codes.
Node.js 22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/aws-secrets-manager
```

```ts
import { AwsSecretsManagerClient } from "@grow-codes/aws-secrets-manager";

// Reads GROW_AWS_SECRETS_MANAGER_URL, GROW_AWS_SECRETS_MANAGER_TOKEN, timeouts, TLS and proxy settings.
const client = AwsSecretsManagerClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "ok", details: {} }
  console.log(`ping: ${(await client.ping()).toFixed(1)} ms`);
} finally {
  await client.close();
}
```

Every error is a `AwsSecretsManagerError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Test helpers (in-memory fakes and the conformance runner) live in
`@grow-codes/aws-secrets-manager/testing`.

Documentation: https://grow-codes-packages.github.io/aws-secrets-manager/ · Licence: Apache-2.0.
AWS Secrets Manager is a trademark of Amazon.com, Inc. or its affiliates; this package is not affiliated with or endorsed by it.
