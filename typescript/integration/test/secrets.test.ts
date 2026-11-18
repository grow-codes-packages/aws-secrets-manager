// SecretsProvider (category interface) against the real service, beyond the conformance runner:
// paths, versions, binary values, tags/description, permanent delete, watch, getAll/loadEnv.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import {
  type AwsSecretsManagerClient,
  type AwsSecretsManagerSecretsProvider,
  SecretCache,
  AWS_SECRET_CACHE_DEFAULTS,
} from "@grow-codes/aws-secrets-manager";
import { client, purge, uid } from "./helpers.ts";

let c: AwsSecretsManagerClient;
let p: AwsSecretsManagerSecretsProvider;
const base = uid("tsp");

before(() => {
  c = client();
  p = c.secrets();
});

after(async () => {
  const names = (await p.list(`${base}/`)).map((m) => m.name);
  await purge(c, names);
  await c.close();
});

test("set/get with path and versions; metadata", async () => {
  const v1 = await p.set("db", "one", { path: base, description: "desc", tags: { a: "1" } });
  const v2 = await p.set(`${base}/db`, "two", { tags: { b: "2" } });
  assert.notEqual(v1, v2);
  assert.equal(await p.getString("db", { path: `/${base}/` }), "two");
  assert.equal((await p.get(`${base}/db`, { version: v1 }))?.reveal(), "one");
  const meta = await p.metadata(`${base}/db`);
  assert.equal(meta?.version, v2);
  assert.equal(meta?.versions, 2);
  assert.deepEqual(meta?.tags, { a: "1", b: "2" });
  assert.equal(meta?.extra.description, "desc");
  assert.equal(meta?.path, base);
});

test("binary values, getMany order, getAll non-recursive, loadEnv, list", async () => {
  await p.set(`${base}/bin`, new Uint8Array([0xff, 0xfe]));
  assert.deepEqual([...((await p.get(`${base}/bin`))?.revealBytes() ?? [])], [0xff, 0xfe]);
  await p.set(`${base}/env/user`, "u");
  await p.set(`${base}/env/pass`, "p");
  await p.set(`${base}/env/nested/deep`, "d");
  const many = await p.getMany([`${base}/env/user`, `${base}/none`, `${base}/env/pass`]);
  assert.deepEqual([...many.keys()], [`${base}/env/user`, `${base}/env/pass`]);
  const all = await p.getAll(`${base}/env`);
  assert.deepEqual([...all.keys()].sort(), [`${base}/env/pass`, `${base}/env/user`]);
  const target: Record<string, string | undefined> = {};
  const set = await p.loadEnv(`${base}/env`, { env: target, prefix: "APP_" });
  assert.deepEqual(Object.keys(set).sort(), ["APP_PASS", "APP_USER"]);
  assert.equal(target.APP_USER, "u");
  const listed = await p.list(`${base}/env/`);
  assert.deepEqual(
    listed.map((m) => m.name),
    [`${base}/env/nested/deep`, `${base}/env/pass`, `${base}/env/user`],
  );
});

test("delete with recovery window hides the secret; permanent delete purges it", async () => {
  await p.set(`${base}/soft`, "x");
  await p.delete(`${base}/soft`);
  assert.equal(await p.get(`${base}/soft`), null);
  assert.equal(await p.metadata(`${base}/soft`), null);
  await assert.rejects(p.delete(`${base}/soft`), { code: "NOT_FOUND" });
  await c.restoreSecret(`${base}/soft`);
  assert.equal(await p.getString(`${base}/soft`), "x");
  await p.delete(`${base}/soft`, { permanent: true });
  await assert.rejects(c.describeSecret(`${base}/soft`), { code: "NOT_FOUND" });
  await assert.rejects(p.set(`${base}/cas`, "x", { cas: 0 }), { code: "VALIDATION" });
});

test("watch reports a new version; SecretCache with the AWS preset", async () => {
  const key = `${base}/watched`;
  await p.set(key, "w1");
  const cache = new SecretCache(p, AWS_SECRET_CACHE_DEFAULTS);
  assert.equal(await cache.getString(key), "w1");
  const seen: (string | null)[] = [];
  const handle = p.watch(key, 200, (next) => {
    seen.push(next?.reveal() ?? null);
  });
  await handle.ready;
  await p.set(key, "w2");
  for (let i = 0; i < 50 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 100));
  handle.stop();
  assert.deepEqual(seen, ["w2"]);
  assert.equal(await cache.getString(key), "w1");
});
