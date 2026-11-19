import { afterEach, describe, expect, it } from "vitest";
import {
  AWS_SECRET_CACHE_DEFAULTS,
  AwsSecretCache,
  type AwsSecretValue,
  AwsSecretsManagerClient,
  NotFoundError,
  SecretValue,
  ValidationError,
} from "../src/index.js";
import { clientFor } from "./support/aws.js";
import { type FakeAsm, startFakeAsm } from "./support/fake-asm.js";

function value(versionId: string, text: string, stage = "AWSCURRENT"): AwsSecretValue {
  return {
    arn: "arn",
    name: "s",
    versionId,
    versionStages: [stage],
    binary: false,
    value: new SecretValue(text, versionId),
  };
}

class Source {
  current = value("v1", "one");
  stages: Record<string, string[]> = { v1: ["AWSCURRENT"] };
  gets = 0;
  describes = 0;
  failDescribe = false;
  async getSecretValue(_id: string, options?: { versionStage?: string }): Promise<AwsSecretValue> {
    this.gets++;
    await Promise.resolve();
    if (options?.versionStage === "MISSING") throw new NotFoundError("missing");
    return this.current;
  }
  async describeSecret(): Promise<{ versionIdsToStages: Record<string, string[]> }> {
    this.describes++;
    await Promise.resolve();
    if (this.failDescribe) throw new Error("describe failed");
    return { versionIdsToStages: this.stages };
  }
}

describe("AwsSecretCache", () => {
  it("defaults and validation", () => {
    expect(AwsSecretCache.awsDefaults()).toEqual({ ttlMs: 3_600_000, maxEntries: 1024 });
    expect(AWS_SECRET_CACHE_DEFAULTS).toEqual({ ttlMs: 3_600_000, maxEntries: 1024 });
    const s = new Source();
    expect(() => new AwsSecretCache(s, { ttlMs: 0 })).toThrow(ValidationError);
    expect(() => new AwsSecretCache(s, { maxEntries: 0 })).toThrow(ValidationError);
    expect(() => new AwsSecretCache(s, { versionStage: " " })).toThrow(ValidationError);
  });

  it("caches per stage, refreshes with DescribeSecret and fetches only on version change", async () => {
    let now = 0;
    const s = new Source();
    const cache = new AwsSecretCache(s, { ttlMs: 1000, clock: () => now });
    const [a, b] = await Promise.all([cache.getSecretValue("s"), cache.getSecretValue("s")]);
    expect(a.value.reveal()).toBe("one");
    expect(b).toBe(a);
    expect(s.gets).toBe(1);
    expect(await cache.getSecretString("s")).toBe("one");
    expect([...(await cache.getSecretBinary("s"))]).toEqual([...new TextEncoder().encode("one")]);
    expect(s.gets).toBe(1);
    now = 1500;
    expect(await cache.getSecretString("s")).toBe("one");
    expect(s.describes).toBe(1);
    expect(s.gets).toBe(1);
    s.current = value("v2", "two");
    s.stages = { v1: ["AWSPREVIOUS"], v2: ["AWSCURRENT"] };
    now = 3000;
    expect(await cache.getSecretString("s")).toBe("two");
    expect(s.gets).toBe(2);
    await cache.getSecretValue("s", { versionStage: "AWSPREVIOUS" });
    expect(cache.stats()).toMatchObject({ refreshes: 2, versionChanges: 1, size: 2 });
    expect(cache.stats().hits).toBeGreaterThan(0);
    expect(cache.stats().misses).toBe(3);
  });

  it("a stage that disappeared refetches; a failing refresh serves stale with backoff", async () => {
    let now = 0;
    const errors: unknown[] = [];
    const s = new Source();
    const cache = new AwsSecretCache(s, {
      ttlMs: 10_000,
      clock: () => now,
      onRefreshError: (e) => {
        errors.push(e);
        throw new Error("ignored");
      },
    });
    await cache.getSecretValue("s");
    s.stages = {};
    now = 20_000;
    await cache.getSecretValue("s");
    expect(s.gets).toBe(2);
    s.failDescribe = true;
    now = 40_000;
    expect(await cache.getSecretString("s")).toBe("one");
    expect(errors).toHaveLength(1);
    now = 40_500; // within the 1 s backoff: no new attempt
    await cache.getSecretValue("s");
    expect(s.describes).toBe(2);
    now = 41_500;
    await cache.getSecretValue("s");
    expect(s.describes).toBe(3);
    s.failDescribe = false;
    const fresh = await cache.refreshNow("s");
    expect(fresh.value.reveal()).toBe("one");
    expect(s.describes).toBe(4);
    expect((await cache.refreshNow("other")).name).toBe("s");
  });

  it("first-read errors propagate; LRU eviction; invalidate and clear", async () => {
    const s = new Source();
    const cache = new AwsSecretCache(s, { maxEntries: 2, versionStage: "AWSCURRENT" });
    await expect(cache.getSecretValue("s", { versionStage: "MISSING" })).rejects.toBeInstanceOf(
      NotFoundError,
    );
    await cache.getSecretValue("a");
    await cache.getSecretValue("b");
    await cache.getSecretValue("c");
    expect(cache.stats()).toMatchObject({ evictions: 1, size: 2 });
    cache.invalidate("c");
    expect(cache.stats().size).toBe(1);
    cache.clear();
    expect(cache.stats().size).toBe(0);
  });

  describe("with a client", () => {
    let fake: FakeAsm;
    const clients: AwsSecretsManagerClient[] = [];
    afterEach(async () => {
      await Promise.all(clients.splice(0).map((c) => c.close()));
      await fake.close();
    });

    it("client.secretCache() reads through GetSecretValue with an explicit stage", async () => {
      fake = await startFakeAsm();
      const client = clientFor(fake);
      clients.push(client);
      await client.createSecret("cached", "v1");
      const cache = client.secretCache({ ttlMs: 60_000 });
      expect(await cache.getSecretString("cached", { signal: new AbortController().signal })).toBe(
        "v1",
      );
      expect(await cache.getSecretString("cached")).toBe("v1");
      expect(fake.calls("GetSecretValue")).toHaveLength(1);
      expect(JSON.parse(fake.calls("GetSecretValue")[0]!.body)).toEqual({
        SecretId: "cached",
        VersionStage: "AWSCURRENT",
      });
      await client.putSecretValue("cached", "v2");
      expect((await cache.refreshNow("cached")).value.reveal()).toBe("v2");
    });
  });
});
