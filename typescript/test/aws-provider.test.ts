import { afterEach, describe, expect, it } from "vitest";
import {
  AwsSecretsManagerClient,
  AwsSecretsManagerSecretsProvider,
  ConflictError,
  NotFoundError,
  SecretCache,
  AWS_SECRET_CACHE_DEFAULTS,
  ValidationError,
  fullName,
  toMetadata,
} from "../src/index.js";
import { awsError, bodyOf, clientFor } from "./support/aws.js";
import { type FakeAsm, startFakeAsm } from "./support/fake-asm.js";

let fake: FakeAsm;
const clients: AwsSecretsManagerClient[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await fake.close();
});

async function provider(
  options: Parameters<AwsSecretsManagerClient["secrets"]>[0] = {},
): Promise<AwsSecretsManagerSecretsProvider> {
  fake = await startFakeAsm();
  const client = clientFor(fake);
  clients.push(client);
  return client.secrets(options);
}

describe("AwsSecretsManagerSecretsProvider", () => {
  it("set creates then versions; get, typed getters, metadata", async () => {
    const p = await provider();
    const v1 = await p.set("app/db", "one", { description: "d", tags: { team: "a" } });
    expect(v1).toBeTruthy();
    expect(bodyOf(fake.calls("CreateSecret")[0]!)).toMatchObject({
      Name: "app/db",
      SecretString: "one",
      Description: "d",
      Tags: [{ Key: "team", Value: "a" }],
    });
    const v2 = await p.set("app/db", "two", { tags: { env: "dev" }, description: "d2" });
    expect(v2).not.toBe(v1);
    expect(fake.calls("TagResource")).toHaveLength(1);
    expect(fake.calls("UpdateSecret")).toHaveLength(1);
    expect((await p.get("app/db"))?.reveal()).toBe("two");
    expect((await p.get("app/db"))?.version).toBe(v2);
    expect((await p.get("app/db", { version: v1 }))?.reveal()).toBe("one");
    expect(await p.getString("db", { path: "/app/" })).toBe("two");
    const meta = await p.metadata("app/db");
    expect(meta).toMatchObject({
      name: "app/db",
      path: "app",
      version: v2,
      versions: 2,
      tags: { team: "a", env: "dev" },
      extra: { description: "d2", rotationEnabled: "false" },
    });
    expect(meta?.createdAt).toBeInstanceOf(Date);
    expect(meta?.updatedAt).toBeInstanceOf(Date);
    expect(await p.metadata("missing")).toBeNull();
    expect(await p.get("missing")).toBeNull();
    expect(AwsSecretsManagerSecretsProvider.capabilities).toEqual(["write", "versions", "delete"]);
    expect(p.client).toBeInstanceOf(AwsSecretsManagerClient);
  });

  it("set stores bytes as SecretBinary and objects as JSON text", async () => {
    const p = await provider();
    await p.set("bin", new Uint8Array([0xff, 0x00]));
    expect(bodyOf(fake.calls("CreateSecret")[0]!)).toMatchObject({ SecretBinary: "/wA=" });
    expect([...((await p.get("bin"))?.revealBytes() ?? [])]).toEqual([0xff, 0]);
    await p.set("obj", { a: 1 });
    expect(await p.getJson("obj")).toEqual({ a: 1 });
    await p.set("utf8-bytes", new TextEncoder().encode("héllo"));
    expect(bodyOf(fake.calls("CreateSecret")[2]!)).toMatchObject({ SecretString: "héllo" });
  });

  it("set rejects cas and retries after a create race", async () => {
    const p = await provider();
    await expect(p.set("a", "v", { cas: 1 })).rejects.toBeInstanceOf(ValidationError);
    let first = true;
    fake.override("PutSecretValue", () => {
      if (!first) return undefined;
      first = false;
      return awsError("ResourceNotFoundException");
    });
    await p.set("raced", "v0");
    fake.override("PutSecretValue", undefined);
    first = true;
    fake.override("PutSecretValue", () => {
      if (!first) return undefined;
      first = false;
      return awsError("ResourceNotFoundException");
    });
    const v = await p.set("raced", "v1");
    expect(v).toBeTruthy();
    expect((await p.get("raced"))?.reveal()).toBe("v1");
    fake.override("PutSecretValue", () => awsError("ResourceNotFoundException"));
    fake.override("CreateSecret", () => awsError("AccessDeniedException"));
    await expect(p.set("denied", "v")).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    fake.override("PutSecretValue", () => awsError("ThrottlingException"));
    await expect(p.set("x", "v")).rejects.toMatchObject({ code: "RATE_LIMITED" });
  });

  it("delete: recovery window by default, permanent, NOT_FOUND for missing and pending", async () => {
    const p = await provider({ recoveryWindowDays: 7 });
    await p.set("gone", "v");
    await p.delete("gone");
    expect(bodyOf(fake.calls("DeleteSecret")[0]!)).toEqual({
      SecretId: "gone",
      RecoveryWindowInDays: 7,
    });
    expect(await p.get("gone")).toBeNull();
    expect(await p.exists("gone")).toBe(false);
    expect(await p.metadata("gone")).toBeNull();
    await expect(p.delete("gone")).rejects.toBeInstanceOf(NotFoundError);
    await expect(p.set("gone", "again")).rejects.toBeInstanceOf(ConflictError);
    await p.set("purge", "v");
    await p.delete("purge", { permanent: true });
    expect(bodyOf(fake.calls("DeleteSecret")[1]!)).toEqual({
      SecretId: "purge",
      ForceDeleteWithoutRecovery: true,
    });
    await expect(p.delete("never")).rejects.toBeInstanceOf(NotFoundError);
    await expect(p.delete("purge", { versions: ["v1"] })).rejects.toBeInstanceOf(ValidationError);
    fake.override("DescribeSecret", () => awsError("AccessDeniedException"));
    await expect(p.delete("x")).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    fake.override("GetSecretValue", () => awsError("AccessDeniedException"));
    await expect(p.get("x")).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("uses config.recoveryWindowDays and validates the option", async () => {
    fake = await startFakeAsm();
    const client = clientFor(fake, { recoveryWindowDays: 12 });
    clients.push(client);
    const p = client.secrets();
    await p.set("x", "v");
    await p.delete("x");
    expect(bodyOf(fake.calls("DeleteSecret")[0]!)).toMatchObject({ RecoveryWindowInDays: 12 });
    expect(() => client.secrets({ recoveryWindowDays: 1 })).toThrow(ValidationError);
  });

  it("list (prefix, sorted, word-prefix re-filtered), getAll non-recursive, getMany batched", async () => {
    const p = await provider();
    for (const n of ["app/b", "app/a", "app/sub/c", "apple", "other/app/x", "top"]) {
      await p.set(n, `v-${n}`);
    }
    await p.set("app/old", "v");
    await p.delete("app/old");
    const listed = await p.list("app/");
    expect(listed.map((m) => m.name)).toEqual(["app/a", "app/b", "app/sub/c"]);
    expect(listed[0]?.extra.arn).toMatch(/^arn:/);
    expect((await p.list()).length).toBe(6);
    expect(bodyOf(fake.calls("ListSecrets")[0]!)).toMatchObject({
      Filters: [{ Key: "name", Values: ["app/"] }],
    });
    const all = await p.getAll("/app/");
    expect([...all.keys()]).toEqual(["app/a", "app/b"]);
    expect([...(await p.getAll()).keys()]).toEqual(["apple", "top"]);
    const many = await p.getMany(["app/b", "nope", "app/a", "app/b", "app/old"]);
    expect([...many.keys()]).toEqual(["app/b", "app/a"]);
    expect([...(await p.getMany(["a", "b"], { path: "app" })).keys()]).toEqual(["a", "b"]);
    const env: Record<string, string | undefined> = {};
    expect(await p.loadEnv("app", { env, prefix: "X_" })).toEqual({ X_A: "app/a", X_B: "app/b" });
    expect(env.X_A).toBe("v-app/a");
  });

  it("getMany with a version reads one by one; batch errors other than missing raise", async () => {
    const p = await provider();
    const v1 = await p.set("a", "1");
    await p.set("a", "2");
    const byVersion = await p.getMany(["a"], { version: v1 });
    expect(byVersion.get("a")?.reveal()).toBe("1");
    fake.override("BatchGetSecretValue", () => ({
      status: 200,
      headers: { "content-type": "application/x-amz-json-1.1" },
      body: JSON.stringify({
        SecretValues: [],
        Errors: [{ SecretId: "a", ErrorCode: "DecryptionFailure", Message: "kms" }],
      }),
    }));
    await expect(p.getMany(["a"])).rejects.toMatchObject({ code: "VALIDATION" });
    fake.override("BatchGetSecretValue", () => ({
      status: 200,
      headers: { "content-type": "application/x-amz-json-1.1" },
      body: JSON.stringify({ SecretValues: [], Errors: [{ Message: "?" }] }),
    }));
    await expect(p.getMany(["a"])).rejects.toMatchObject({ code: "UNAVAILABLE" });
  });

  it("getMany splits more than 20 names", async () => {
    const p = await provider();
    const names = Array.from({ length: 25 }, (_, i) => `n${String(i)}`);
    for (const n of names.slice(0, 3)) await p.set(n, n);
    const got = await p.getMany(names);
    expect([...got.keys()]).toEqual(["n0", "n1", "n2"]);
    expect(fake.calls("BatchGetSecretValue")).toHaveLength(2);
  });

  it("watch sees new versions; cache with the AWS preset in front of the provider", async () => {
    const p = await provider();
    await p.set("w", "1");
    const cache = new SecretCache(p, AWS_SECRET_CACHE_DEFAULTS);
    expect((await cache.get("w"))?.reveal()).toBe("1");
    expect((await cache.get("w"))?.reveal()).toBe("1");
    expect(cache.stats().hits).toBe(1);
    const seen: string[] = [];
    const h = p.watch("w", 20, (n) => {
      seen.push(n?.reveal() ?? "null");
    });
    await h.ready;
    await p.set("w", "2");
    for (let i = 0; i < 50 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
    h.stop();
    expect(seen).toContain("2");
    await p.close();
  });

  it("helpers: fullName and toMetadata", () => {
    expect(fullName("a", undefined)).toBe("a");
    expect(fullName("a", "//p/q//")).toBe("p/q/a");
    expect(fullName("a", "/")).toBe("a");
    const m = toMetadata({
      arn: "arn",
      name: "flat",
      rotationEnabled: true,
      kmsKeyId: "k",
      nextRotationDate: new Date(0),
      deletedDate: new Date(1000),
      primaryRegion: "eu-west-1",
      tags: {},
      versionIdsToStages: { v1: ["AWSPREVIOUS"] },
      replicationStatus: [],
    });
    expect(m).toEqual({
      name: "flat",
      tags: {},
      versions: 1,
      extra: {
        arn: "arn",
        rotationEnabled: "true",
        kmsKeyId: "k",
        nextRotationDate: "1970-01-01T00:00:00.000Z",
        deletedDate: "1970-01-01T00:00:01.000Z",
        primaryRegion: "eu-west-1",
      },
    });
  });
});
