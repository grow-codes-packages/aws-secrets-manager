// Core client functions against the real service: health, ping (incl. auth failures),
// serverVersion, close, fromEnv and the caller-supplied SDK client.

import assert from "node:assert/strict";
import { test } from "node:test";
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import {
  API_VERSION,
  AwsSecretsManagerClient,
  AwsSecretsManagerError,
} from "@grow-codes/aws-secrets-manager";
import { client, env, withClient } from "./helpers.ts";

test("health reports a healthy service", async () => {
  await withClient(client(), async (c) => {
    const health = await c.health();
    assert.equal(health.healthy, true, JSON.stringify(health));
    assert.equal(health.status, "ok");
    assert.deepEqual(health.details, {});
  });
});

test("ping succeeds with the bootstrap credentials", async () => {
  await withClient(client(), async (c) => {
    const latency = await c.ping();
    assert.equal(typeof latency, "number");
    assert.ok(latency >= 0);
  });
});

test("ping with an unknown key or a wrong secret raises AUTHENTICATION and never leaks it", async () => {
  const wrongSecret = "wrong-secret-for-integration-0123456789";
  for (const options of [
    { accessKeyId: "AKIAUNKNOWNKEY000000", secretAccessKey: wrongSecret },
    { accessKeyId: env("AWS_ACCESS_KEY_ID"), secretAccessKey: wrongSecret },
  ]) {
    await withClient(client({ ...options, retry: { maxRetries: 0 } }), async (c) => {
      await assert.rejects(c.ping(), (err: unknown) => {
        assert.ok(err instanceof AwsSecretsManagerError);
        assert.equal(err.code, "AUTHENTICATION");
        assert.equal(err.httpStatus, 403);
        assert.ok(!err.message.includes(wrongSecret));
        return true;
      });
      // the service answered, so health stays healthy and reports the auth failure
      const health = await c.health();
      assert.equal(health.healthy, true);
      assert.equal(health.details.auth, "failed");
    });
  }
});

test("a read-only principal gets PERMISSION_DENIED on writes", async () => {
  const ro = client({
    accessKeyId: env("GROW_TEST_READONLY_ACCESS_KEY_ID"),
    secretAccessKey: env("GROW_TEST_READONLY_SECRET_ACCESS_KEY"),
    retry: { maxRetries: 0 },
  });
  await withClient(ro, async (c) => {
    assert.ok((await c.ping()) >= 0);
    await assert.rejects(c.createSecret("ts-readonly-denied", "v"), { code: "PERMISSION_DENIED" });
  });
});

test("serverVersion is UNSUPPORTED; close is idempotent", async () => {
  const c = client();
  await assert.rejects(c.serverVersion(), { code: "UNSUPPORTED" });
  assert.equal(API_VERSION, "2017-10-17");
  await c.close();
  await c.close();
  await assert.rejects(c.ping(), { code: "CANCELLED" });
});

test("wraps a caller-supplied AWS SDK client", async () => {
  const sdk = new SecretsManagerClient({
    region: env("AWS_REGION"),
    endpoint: env("GROW_AWS_SECRETS_MANAGER_URL"),
  });
  const c = AwsSecretsManagerClient.withSdkClient(sdk);
  try {
    assert.ok((await c.ping()) >= 0);
    assert.equal(c.sdk, sdk);
  } finally {
    await c.close();
    // still usable: close() never destroys a caller-supplied client
    assert.ok((await new AwsSecretsManagerClient({ sdkClient: sdk }).ping()) >= 0);
    sdk.destroy();
  }
});
