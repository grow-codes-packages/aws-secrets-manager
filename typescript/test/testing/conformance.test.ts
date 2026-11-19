import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AwsSecretsManagerSecretsProvider } from "../../src/index.js";
import {
  type ConformanceOptions,
  conformanceCases,
  formatReport,
  runConformance,
} from "../../src/testing/index.js";
import { type AwsMock, clientFor, fixture, startAws } from "../support/aws.js";
import { type FakeAsm, startFakeAsm } from "../support/fake-asm.js";

const scenariosDir = fileURLToPath(new URL("../../../conformance/scenarios/", import.meta.url));
let server: AwsMock;
let fake: FakeAsm;

beforeAll(async () => {
  server = await startAws({ ListSecrets: fixture("ping.ok") });
  fake = await startFakeAsm();
});

afterAll(async () => {
  await server.close();
  await fake.close();
});

function options(): ConformanceOptions {
  return {
    scenariosDir,
    categories: ["core", "secrets"],
    factories: {
      core: () => clientFor(server),
      secrets: () => clientFor(fake).secrets(),
    },
    // serverVersion is not supported by AWS (no "version" capability).
    capabilities: { core: [], secrets: [...AwsSecretsManagerSecretsProvider.capabilities] },
  };
}

describe("conformance (core + secrets) against local AWS mocks", () => {
  it("every scenario passes; only the serverVersion step is skipped", async () => {
    const report = await runConformance(options());
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.results.map((r) => r.id)).toContain("core.health");
    expect(report.results.map((r) => r.id)).toContain("secrets.roundtrip");
  });

  for (const c of conformanceCases(options())) {
    it.skipIf(c.skip !== undefined)(`case ${c.id}`, async () => {
      expect((await c.run()).status).toBe("passed");
    });
  }
});
