// Runs the shared conformance scenarios (conformance/scenarios) against the real service:
// core (client) and secrets (SecretsProvider). serverVersion is not offered by AWS, so core
// declares no "version" capability (docs/compatibility.md).

import assert from "node:assert/strict";
import { before, test } from "node:test";
import {
  AwsSecretsManagerClient,
  AwsSecretsManagerSecretsProvider,
} from "@grow-codes/aws-secrets-manager";
import { formatReport, runConformance } from "@grow-codes/aws-secrets-manager/testing";
import { loadBootstrapEnv, scenariosDir } from "./env.ts";

before(() => {
  loadBootstrapEnv();
});

test("conformance: core", async () => {
  const report = await runConformance({
    scenariosDir,
    categories: ["core"],
    factories: { core: () => AwsSecretsManagerClient.fromEnv() },
    capabilities: { core: [] },
  });
  console.log(formatReport(report));
  assert.equal(report.failed, 0, formatReport(report));
  assert.ok(report.passed > 0);
});

test("conformance: secrets", async () => {
  const clients: AwsSecretsManagerClient[] = [];
  try {
    const report = await runConformance({
      scenariosDir,
      categories: ["secrets"],
      factories: {
        secrets: () => {
          const client = AwsSecretsManagerClient.fromEnv();
          clients.push(client);
          return client.secrets();
        },
      },
      capabilities: { secrets: [...AwsSecretsManagerSecretsProvider.capabilities] },
    });
    console.log(formatReport(report));
    assert.equal(report.failed, 0, formatReport(report));
    assert.equal(report.skipped, 0, formatReport(report));
  } finally {
    await Promise.all(clients.map((c) => c.close()));
  }
});
