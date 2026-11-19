// Every service-specific function against the real service, each with a round-trip assertion
// (write -> read back). Moto gaps (API.md §7) assert the documented emulator behaviour.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import {
  type AwsSecretsManagerClient,
  NotFoundError,
  Secret,
  UnsupportedError,
} from "@grow-codes/aws-secrets-manager";
import { client, env, isMoto, purge, uid } from "./helpers.ts";

let c: AwsSecretsManagerClient;
const base = uid();
const created: string[] = [];
const name = (leaf: string): string => {
  const n = `${base}/${leaf}`;
  created.push(n);
  return n;
};

before(() => {
  c = client();
});

after(async () => {
  await purge(c, created);
  await c.close();
});

test("getSecretValue reads the bootstrap seeds (string + binary, by name and ARN)", async () => {
  const json = await c.getSecretValue(env("GROW_TEST_SEED_JSON_SECRET"));
  assert.equal(json.binary, false);
  assert.equal(json.value.json<{ username: string }>().username, "seed-user");
  assert.ok(json.versionStages.includes("AWSCURRENT"));
  assert.ok(json.createdDate instanceof Date);
  const byArn = await c.getSecretValue(env("GROW_TEST_SEED_JSON_SECRET_ARN"));
  assert.equal(byArn.versionId, json.versionId);
  const bin = await c.getSecretValue(env("GROW_TEST_SEED_BINARY_SECRET"));
  assert.equal(bin.binary, true);
  assert.deepEqual([...bin.value.revealBytes()], [0x00, 0x01, 0x02, 0xfe, 0xff]);
  assert.ok(!String(bin).includes("seed"));
  await assert.rejects(c.getSecretValue(`${base}/missing`), NotFoundError);
});

test("createSecret (string, bytes, object, no value) -> getSecretValue / describeSecret", async () => {
  const s = name("create/string");
  const r = await c.createSecret(s, "s3cr3t", { description: "made by ts", tags: { team: "sdk" } });
  assert.equal(r.name, s);
  assert.ok(r.versionId);
  assert.equal((await c.getSecretValue(s)).value.reveal(), "s3cr3t");
  const b = name("create/bytes");
  await c.createSecret(b, new Uint8Array([7, 0, 255]));
  assert.deepEqual([...(await c.getSecretValue(b)).value.revealBytes()], [7, 0, 255]);
  const o = name("create/object");
  await c.createSecret(o, { a: 1, b: "two" });
  assert.deepEqual((await c.getSecretValue(o)).value.json(), { a: 1, b: "two" });
  const e = name("create/empty");
  const empty = await c.createSecret(e, undefined, { kmsKeyId: "alias/aws/secretsmanager" });
  assert.equal(empty.versionId, undefined);
  await assert.rejects(c.getSecretValue(e), NotFoundError);
  const d = await c.describeSecret(s);
  assert.equal(d.description, "made by ts");
  assert.deepEqual(d.tags, { team: "sdk" });
  assert.equal(d.rotationEnabled, false);
  await assert.rejects(c.createSecret(s, "again"), { code: "CONFLICT" });
});

test("putSecretValue, versions, stages and updateSecretVersionStage", async () => {
  const s = name("versions");
  const v1 = (await c.createSecret(s, "one")).versionId!;
  const put = await c.putSecretValue(s, "two");
  assert.deepEqual(put.versionStages, ["AWSCURRENT"]);
  const v2 = put.versionId;
  assert.equal((await c.getSecretValue(s, { versionStage: "AWSPREVIOUS" })).value.reveal(), "one");
  const custom = await c.putSecretValue(s, "three", { versionStages: ["STAGED"] });
  assert.equal((await c.getSecretValue(s, { versionStage: "STAGED" })).value.reveal(), "three");
  assert.equal((await c.getSecretValue(s, { versionStage: "AWSCURRENT" })).value.reveal(), "two");
  assert.equal((await c.getSecretValue(s, { versionId: v1 })).versionId, v1);
  // promote the staged version to AWSCURRENT (read back with an explicit stage: Moto quirk)
  await c.updateSecretVersionStage(s, "AWSCURRENT", {
    moveToVersionId: custom.versionId,
    removeFromVersionId: v2,
  });
  const current = await c.getSecretValue(s, { versionStage: "AWSCURRENT" });
  assert.equal(current.value.reveal(), "three");
  const versions = await c.listSecretVersionIds(s, { includeDeprecated: true }).toArray();
  assert.equal(versions.length, 3);
  const byId = new Map(versions.map((v) => [v.versionId, v.versionStages]));
  assert.ok(byId.get(custom.versionId)?.includes("AWSCURRENT"));
  assert.ok(byId.get(v2)?.includes("AWSPREVIOUS"));
  const stages = (await c.describeSecret(s)).versionIdsToStages;
  assert.ok(stages[custom.versionId]?.includes("AWSCURRENT"));
  await assert.rejects(c.updateSecretVersionStage(s, "AWSCURRENT", { moveToVersionId: v1 }), {
    code: "VALIDATION",
  });
});

test("updateSecret changes description and value", async () => {
  const s = name("update");
  await c.createSecret(s, "v1");
  await c.updateSecret(s, { description: "new description" });
  assert.equal((await c.describeSecret(s)).description, "new description");
  const r = await c.updateSecret(s, { value: { rotated: true } });
  assert.ok(r.versionId);
  assert.deepEqual((await c.getSecretValue(s, { versionStage: "AWSCURRENT" })).value.json(), {
    rotated: true,
  });
  await assert.rejects(c.updateSecret(`${base}/nope`, { description: "x" }), NotFoundError);
});

test("batchGetSecretValue by ids (partial errors) and by filters", async () => {
  const a = name("batch/a");
  const b = name("batch/b");
  await c.createSecret(a, "A");
  await c.createSecret(b, "B");
  const res = await c.batchGetSecretValue([b, `${base}/batch/missing`, a]);
  assert.deepEqual(
    res.secretValues.map((v) => [v.name, v.value.reveal()]),
    [
      [b, "B"],
      [a, "A"],
    ],
  );
  assert.equal(res.errors.length, 1);
  assert.equal(res.errors[0]?.errorCode, "ResourceNotFoundException");
  const filtered = await c.batchGetSecretValue(
    { filters: [{ key: "name", values: [`${base}/batch/`] }] },
    { maxResults: 1 },
  );
  assert.deepEqual(filtered.secretValues.map((v) => v.name).sort(), [a, b]);
});

test("listSecrets paginates with filters; includePlannedDeletion shows scheduled deletions", async () => {
  const names = [name("list/one"), name("list/two"), name("list/three")];
  for (const n of names) await c.createSecret(n, n, { tags: { group: `${base}-list` } });
  const listed = await c
    .listSecrets({ filters: [{ key: "name", values: [`${base}/list/`] }], maxResults: 1 })
    .toArray();
  assert.deepEqual(listed.map((s) => s.name).sort(), [...names].sort());
  const byTag = await c
    .listSecrets({ filters: [{ key: "tag-value", values: [`${base}-list`] }], sortOrder: "asc" })
    .toArray();
  assert.equal(byTag.length, 3);
  await c.deleteSecret(names[0]!, { recoveryWindowDays: 7 });
  const live = await c
    .listSecrets({ filters: [{ key: "name", values: [`${base}/list/`] }] })
    .toArray();
  assert.equal(live.length, 2);
  const planned = await c
    .listSecrets({
      filters: [{ key: "name", values: [`${base}/list/`] }],
      includePlannedDeletion: true,
    })
    .toArray();
  assert.equal(planned.length, 3);
  assert.ok(planned.find((s) => s.name === names[0])?.deletedDate instanceof Date);
});

test("deleteSecret (window / force) and restoreSecret", async () => {
  const s = name("delete/restore");
  await c.createSecret(s, "keep");
  const del = await c.deleteSecret(s, { recoveryWindowDays: 7 });
  assert.ok(del.deletionDate instanceof Date);
  assert.ok((await c.describeSecret(s)).deletedDate instanceof Date);
  await assert.rejects(c.getSecretValue(s), { code: "CONFLICT" });
  await c.restoreSecret(s);
  assert.equal((await c.describeSecret(s)).deletedDate, undefined);
  assert.equal((await c.getSecretValue(s)).value.reveal(), "keep");
  const f = name("delete/force");
  await c.createSecret(f, "bye");
  await c.deleteSecret(f, { forceDeleteWithoutRecovery: true });
  await assert.rejects(c.describeSecret(f), NotFoundError);
  // AWS and Moto answer success for a forced delete of a missing secret
  await c.deleteSecret(f, { forceDeleteWithoutRecovery: true });
  await assert.rejects(c.deleteSecret(f), NotFoundError);
});

test("tagResource / untagResource round trip", async () => {
  const s = name("tags");
  await c.createSecret(s, "v");
  await c.tagResource(s, { env: "dev", owner: "sdk" });
  assert.deepEqual((await c.describeSecret(s)).tags, { env: "dev", owner: "sdk" });
  await c.untagResource(s, ["env"]);
  assert.deepEqual((await c.describeSecret(s)).tags, { owner: "sdk" });
});

test("put / get / delete resource policy; validateResourcePolicy", async () => {
  const s = name("policy");
  await c.createSecret(s, "v");
  const policy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { AWS: `arn:aws:iam::${env("GROW_TEST_ACCOUNT_ID")}:root` },
        Action: "secretsmanager:GetSecretValue",
        Resource: "*",
      },
    ],
  };
  await c.putResourcePolicy(s, policy, { blockPublicPolicy: true });
  const got = await c.getResourcePolicy(s);
  assert.deepEqual(got.policy, policy);
  await c.deleteResourcePolicy(s);
  assert.equal((await c.getResourcePolicy(s)).resourcePolicy, undefined);
  if (isMoto) {
    // Not implemented in Moto 5.2.4 (API.md §7): unit tests cover the AWS answer.
    await assert.rejects(c.validateResourcePolicy(policy, { secretId: s }), UnsupportedError);
  } else {
    const v = await c.validateResourcePolicy(policy, { secretId: s });
    assert.equal(typeof v.policyValidationPassed, "boolean");
  }
});

test("rotateSecret (rules only, then Lambda) and cancelRotateSecret", async (t) => {
  if (!isMoto) {
    t.skip("rotation needs a rotation Lambda on real AWS (unit tests + live job)");
    return;
  }
  const s = name("rotation");
  await c.createSecret(s, "rot-v1");
  const r = await c.rotateSecret(s, { rules: { automaticallyAfterDays: 30 } });
  assert.ok(r.versionId);
  const d = await c.describeSecret(s);
  assert.equal(d.rotationEnabled, true);
  assert.equal(d.rotationRules?.automaticallyAfterDays, 30);
  // Moto looks the Lambda up and has none (API.md §7); it keeps the ARN on the secret.
  await assert.rejects(
    c.rotateSecret(s, {
      lambdaArn: "arn:aws:lambda:us-east-1:123456789012:function:grow-rotate",
      rules: { scheduleExpression: "rate(10 days)" },
    }),
    NotFoundError,
  );
  await c.cancelRotateSecret(s);
  assert.equal((await c.describeSecret(s)).rotationEnabled, false);
  await assert.rejects(c.cancelRotateSecret(`${base}/rotation-missing`), NotFoundError);
});

test("getRandomPassword honours its options", async () => {
  const p = await c.getRandomPassword({
    length: 40,
    excludePunctuation: true,
    excludeCharacters: "abc",
  });
  assert.ok(p instanceof Secret);
  const text = p.reveal();
  assert.equal(text.length, 40);
  assert.match(text, /^[A-Za-z0-9]+$/);
  assert.ok(!/[abc]/.test(text));
  assert.ok(!String(p).includes(text));
  const d = await c.getRandomPassword();
  assert.equal(d.reveal().length, 32);
  await assert.rejects(c.getRandomPassword({ length: 2 }), { code: "VALIDATION" });
});

test("getJsonField reads fields of the JSON seed and of a nested secret", async () => {
  const seed = env("GROW_TEST_SEED_JSON_SECRET");
  assert.equal(await c.getJsonField(seed, "username"), "seed-user");
  assert.equal(await c.getJsonField(seed, "port"), 5432);
  assert.equal(await c.getJsonField(seed, "enabled"), true);
  assert.equal(await c.getJsonField(seed, "absent"), null);
  const s = name("json");
  await c.createSecret(s, { db: { host: "db.local" } });
  assert.equal(await c.getJsonField(s, "db.host", { versionStage: "AWSCURRENT" }), "db.local");
  await assert.rejects(c.getJsonField(env("GROW_TEST_SEED_BINARY_SECRET"), "x"), {
    code: "VALIDATION",
  });
});

test("secretCache serves cached values and picks up a new AWSCURRENT on refresh", async () => {
  const s = name("cache");
  await c.createSecret(s, "c1");
  const cache = c.secretCache({ ttlMs: 60_000 });
  assert.equal(await cache.getSecretString(s), "c1");
  await c.putSecretValue(s, "c2");
  assert.equal(await cache.getSecretString(s), "c1");
  assert.equal((await cache.refreshNow(s)).value.reveal(), "c2");
  assert.equal(await cache.getSecretString(s, { versionStage: "AWSPREVIOUS" }), "c1");
  assert.equal(cache.stats().versionChanges, 1);
});
