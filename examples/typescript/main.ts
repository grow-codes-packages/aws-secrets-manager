// AWS Secrets Manager with the Grow Codes TypeScript SDK: configuration from the standard AWS
// environment, health/ping, create → read → new version → JSON field → cache → SecretsProvider,
// error handling, and cleanup.
//
//   (cd ../../typescript && npm install && npm run build)   # or use the published package
//   npm install
//   AWS_REGION=eu-central-1 AWS_PROFILE=dev npm start          # real AWS (creates and deletes one secret)
//   GROW_AWS_SECRETS_MANAGER_URL=http://127.0.0.1:5000 AWS_REGION=us-east-1 \
//     AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... npm start   # Moto / LocalStack

import { randomBytes } from "node:crypto";
import {
  AwsSecretsManagerClient,
  AwsSecretsManagerError,
} from "@grow-codes/aws-secrets-manager";

const client = AwsSecretsManagerClient.fromEnv({
  // Warnings only; the default logger is silent.
  logger: { debug() {}, info() {}, warn: console.warn, error: console.error },
  hooks: {
    onError(info) {
      if (info.willRetry) console.error(`retrying (attempt ${info.attempt})`);
    },
  },
});
console.log(`config: ${client.config}`); // credentials print as [REDACTED]

const name = `grow-sdk-example/${randomBytes(4).toString("hex")}/db`;
try {
  const health = await client.health(); // never throws for an unreachable service
  console.log("health:", health);
  console.log(
    `ping: ${(await client.ping({ signal: AbortSignal.timeout(10_000) })).toFixed(1)} ms`,
  );

  // Create a JSON secret with a generated password (the password is a redacting Secret).
  const password = await client.getRandomPassword({
    length: 24,
    excludePunctuation: true,
  });
  const created = await client.createSecret(
    name,
    { username: "app", password: password.reveal(), host: "db.internal" },
    {
      description: "Grow SDK example",
      tags: { "grow:purpose": "sdk-example" },
    },
  );
  console.log(`created ${created.name} version ${created.versionId}`);

  // Read it back: the value is a SecretValue that prints as [REDACTED].
  const secret = await client.getSecretValue(name);
  console.log(
    `value: ${secret.value}, stages: ${secret.versionStages.join(",")}`,
  );
  console.log("host:", await client.getJsonField(name, "host"));

  // A new version becomes AWSCURRENT; the old one is AWSPREVIOUS.
  await client.putSecretValue(name, {
    username: "app",
    password: "rotated",
    host: "db.internal",
  });
  const previous = await client.getSecretValue(name, {
    versionStage: "AWSPREVIOUS",
  });
  console.log("previous version:", previous.versionId);

  // Version-stage aware cache with the AWS caching-client defaults (TTL 1 h).
  const cache = client.secretCache();
  console.log(
    "cached username:",
    JSON.parse(await cache.getSecretString(name)).username,
  );

  // The category interface shared by every Grow secrets SDK.
  const secrets = client.secrets();
  const listed = await secrets.list(name.slice(0, name.lastIndexOf("/") + 1));
  console.log(
    "listed:",
    listed.map((m) => `${m.name}@${m.version}`),
  );
} catch (err) {
  if (err instanceof AwsSecretsManagerError) {
    // Canonical code + HTTP status + request id; the message never contains credentials.
    console.error(`${err.code}: ${err.message}`, {
      httpStatus: err.httpStatus,
      requestId: err.requestId,
    });
    process.exitCode = 1;
  } else {
    throw err;
  }
} finally {
  // Clean up immediately (no recovery window) and release the client.
  await client
    .deleteSecret(name, { forceDeleteWithoutRecovery: true })
    .catch(() => undefined);
  await client.close();
}
