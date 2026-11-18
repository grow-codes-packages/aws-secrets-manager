// Shared helpers for the integration tests (real AWS Secrets Manager API served by Moto from
// docker/compose.yml, or real AWS when the environment points there).

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  AwsSecretsManagerClient,
  type AwsSecretsManagerConfigOptions,
} from "@grow-codes/aws-secrets-manager";
import { loadBootstrapEnv, runId } from "./env.ts";

loadBootstrapEnv();

/** A required variable from /bootstrap/env (fails the test when missing). */
export function env(name: string): string {
  const value = process.env[name];
  assert.ok(value !== undefined && value !== "", `${name} must be set (see /bootstrap/env)`);
  return value;
}

/** True when the service is the Moto emulator (some AWS features are not emulated). */
export const isMoto = process.env.GROW_TEST_EMULATOR === "moto";

/** A unique name prefix for this run: `ts-<run>-<random>/`. */
export function uid(prefix = "ts"): string {
  const run = runId
    .replace(/[^a-z0-9]/gi, "")
    .slice(0, 8)
    .toLowerCase();
  return `${prefix}-${run}-${randomBytes(4).toString("hex")}`;
}

/** A client from the environment (bootstrap admin credentials). */
export function client(options: AwsSecretsManagerConfigOptions = {}): AwsSecretsManagerClient {
  return AwsSecretsManagerClient.fromEnv(options);
}

/** Runs `fn` with a client and always closes it. */
export async function withClient<T>(
  c: AwsSecretsManagerClient,
  fn: (c: AwsSecretsManagerClient) => Promise<T>,
): Promise<T> {
  try {
    return await fn(c);
  } finally {
    await c.close();
  }
}

/** Force-deletes secrets created by a test (ignores missing ones). */
export async function purge(c: AwsSecretsManagerClient, names: readonly string[]): Promise<void> {
  for (const name of names) {
    await c.deleteSecret(name, { forceDeleteWithoutRecovery: true }).catch(() => undefined);
  }
}
