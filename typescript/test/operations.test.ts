import { afterEach, describe, expect, it } from "vitest";
import {
  AwsSecretsManagerClient,
  ConflictError,
  NotFoundError,
  Secret,
  SecretValue,
  UnsupportedError,
  ValidationError,
} from "../src/index.js";
import { type AwsMock, awsError, bodyOf, clientFor, fixture, ok, startAws } from "./support/aws.js";

const mocks: AwsMock[] = [];
const clients: AwsSecretsManagerClient[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await Promise.all(mocks.splice(0).map((m) => m.close()));
});

async function setup(
  routes: Parameters<typeof startAws>[0],
): Promise<{ mock: AwsMock; client: AwsSecretsManagerClient }> {
  const mock = await startAws(routes);
  mocks.push(mock);
  const client = clientFor(mock);
  clients.push(client);
  return { mock, client };
}

describe("read operations", () => {
  it("getSecretValue: string value with version and stage", async () => {
    const { mock, client } = await setup({ GetSecretValue: fixture("getSecretValue.ok-string") });
    const v = await client.getSecretValue("sdkv-0badc0de/app/db", { versionStage: "AWSCURRENT" });
    expect(v.binary).toBe(false);
    expect(v.name).toBe("sdkv-0badc0de/app/db");
    expect(v.arn).toMatch(/^arn:aws:secretsmanager:/);
    expect(v.versionStages).toContain("AWSCURRENT");
    expect(v.createdDate).toBeInstanceOf(Date);
    expect(v.value).toBeInstanceOf(SecretValue);
    expect(v.value.version).toBe(v.versionId);
    expect(v.value.reveal().length).toBeGreaterThan(0);
    expect(JSON.stringify(v)).not.toContain(v.value.reveal());
    expect(bodyOf(mock.calls("GetSecretValue")[0]!)).toEqual({
      SecretId: "sdkv-0badc0de/app/db",
      VersionStage: "AWSCURRENT",
    });
  });

  it("getSecretValue: binary, version id, not found, pending deletion", async () => {
    const { mock, client } = await setup({
      GetSecretValue: [
        fixture("getSecretValue.ok-binary"),
        fixture("getSecretValue.ok-version-id"),
        fixture("getSecretValue.not-found"),
        fixture("getSecretValue.marked-deleted"),
      ],
    });
    const bin = await client.getSecretValue("x");
    expect(bin.binary).toBe(true);
    expect([...bin.value.revealBytes()]).toEqual([0, 1, 2, 254, 255]);
    await client.getSecretValue("x", { versionId: "v-1" });
    expect(bodyOf(mock.calls("GetSecretValue")[1]!)).toMatchObject({ VersionId: "v-1" });
    const nf = await client.getSecretValue("x").catch((e: unknown) => e);
    expect(nf).toBeInstanceOf(NotFoundError);
    expect((nf as NotFoundError).httpStatus).toBe(404);
    expect((nf as NotFoundError).requestId).toBeTruthy();
    expect((nf as Error).message).toMatch(/^getSecretValue x: ResourceNotFoundException/);
    await expect(client.getSecretValue("x")).rejects.toBeInstanceOf(ConflictError);
    await expect(client.getSecretValue(" ")).rejects.toBeInstanceOf(ValidationError);
  });

  it("batchGetSecretValue by ids: partial errors, request order, chunks of 20", async () => {
    const { mock, client } = await setup({
      BatchGetSecretValue: (req) => {
        const ids = (bodyOf(req).SecretIdList as string[]) ?? [];
        return ok({
          SecretValues: ids
            .filter((id) => !id.endsWith("missing"))
            .reverse()
            .map((id, i) => ({
              ARN: `arn:aws:secretsmanager:us-east-1:1:secret:${id}-abc`,
              Name: id,
              VersionId: `v${String(i)}`,
              VersionStages: ["AWSCURRENT"],
              SecretString: `value-${id}`,
              CreatedDate: 1795033096,
            })),
          Errors: ids
            .filter((id) => id.endsWith("missing"))
            .map((id) => ({ SecretId: id, ErrorCode: "ResourceNotFoundException", Message: "m" })),
          NextToken: null,
        });
      },
    });
    const ids = Array.from({ length: 23 }, (_, i) => `s${String(i).padStart(2, "0")}`);
    ids.push("zz-missing");
    const res = await client.batchGetSecretValue(ids);
    expect(mock.calls("BatchGetSecretValue")).toHaveLength(2);
    expect(res.secretValues.map((v) => v.name)).toEqual(ids.slice(0, 23));
    expect(res.errors).toEqual([
      { secretId: "zz-missing", errorCode: "ResourceNotFoundException", message: "m" },
    ]);
  });

  it("batchGetSecretValue by ids follows NextToken within a chunk", async () => {
    const { client } = await setup({
      BatchGetSecretValue: [
        ok({
          SecretValues: [{ ARN: "arn:b", Name: "b", SecretString: "2" }],
          NextToken: "t1",
        }),
        ok({ SecretValues: [{ ARN: "arn:a", Name: "a", SecretString: "1" }], NextToken: "" }),
      ],
    });
    const res = await client.batchGetSecretValue(["a", "b"]);
    expect(res.secretValues.map((v) => v.name)).toEqual(["a", "b"]);
  });

  it("batchGetSecretValue by filters paginates; recorded fixtures", async () => {
    const { mock, client } = await setup({
      BatchGetSecretValue: [
        fixture("batchGetSecretValue.filters"),
        fixture("batchGetSecretValue.filters-page2"),
      ],
    });
    const res = await client.batchGetSecretValue(
      { filters: [{ key: "name", values: ["sdkv-0badc0de/batch/"] }] },
      { maxResults: 2 },
    );
    expect(res.secretValues.length).toBeGreaterThanOrEqual(2);
    const first = bodyOf(mock.calls("BatchGetSecretValue")[0]!);
    expect(first).toMatchObject({
      Filters: [{ Key: "name", Values: ["sdkv-0badc0de/batch/"] }],
      MaxResults: 2,
    });
    expect(bodyOf(mock.calls("BatchGetSecretValue")[1]!).NextToken).toBeTruthy();
    await expect(client.batchGetSecretValue({ filters: [] })).rejects.toBeInstanceOf(
      ValidationError,
    );
  });

  it("batchGetSecretValue recorded partial and both-forms answers", async () => {
    const { client } = await setup({
      BatchGetSecretValue: [
        fixture("batchGetSecretValue.ids-partial"),
        fixture("batchGetSecretValue.both"),
      ],
    });
    const res = await client.batchGetSecretValue(["sdkv-0badc0de/batch/b1", "missing"]);
    expect(res.errors.length).toBe(1);
    expect(res.secretValues.length).toBeGreaterThan(0);
    await expect(client.batchGetSecretValue(["a"])).rejects.toBeInstanceOf(ValidationError);
  });

  it("describeSecret maps every field", async () => {
    const { client } = await setup({
      DescribeSecret: [
        fixture("describeSecret.ok"),
        ok({
          ARN: "arn:x",
          Name: "full",
          Description: "d",
          KmsKeyId: "k",
          RotationEnabled: true,
          RotationLambdaARN: "arn:lambda",
          RotationRules: {
            AutomaticallyAfterDays: 7,
            Duration: "2h",
            ScheduleExpression: "rate(7 days)",
          },
          LastRotatedDate: 1,
          LastChangedDate: 2,
          LastAccessedDate: 3,
          DeletedDate: 4,
          NextRotationDate: 5,
          CreatedDate: 6,
          PrimaryRegion: "eu-west-1",
          OwningService: "rds",
          Tags: [{ Key: "a", Value: "1" }, { Key: "b" }],
          VersionIdsToStages: { v1: ["AWSCURRENT"] },
          ReplicationStatus: [
            {
              Region: "eu-central-1",
              KmsKeyId: "k2",
              Status: "InSync",
              StatusMessage: "ok",
              LastAccessedDate: 7,
            },
          ],
        }),
        fixture("describeSecret.not-found"),
      ],
    });
    const d = await client.describeSecret("sdkv-0badc0de/app/db");
    expect(d.name).toBe("sdkv-0badc0de/app/db");
    expect(Object.keys(d.versionIdsToStages).length).toBeGreaterThan(0);
    const full = await client.describeSecret("full");
    expect(full).toMatchObject({
      description: "d",
      kmsKeyId: "k",
      rotationEnabled: true,
      rotationLambdaArn: "arn:lambda",
      rotationRules: {
        automaticallyAfterDays: 7,
        duration: "2h",
        scheduleExpression: "rate(7 days)",
      },
      primaryRegion: "eu-west-1",
      owningService: "rds",
      tags: { a: "1", b: "" },
      versionIdsToStages: { v1: ["AWSCURRENT"] },
      replicationStatus: [
        { region: "eu-central-1", kmsKeyId: "k2", status: "InSync", statusMessage: "ok" },
      ],
    });
    expect(full.deletedDate).toEqual(new Date(4000));
    expect(full.replicationStatus[0]?.lastAccessedDate).toEqual(new Date(7000));
    await expect(client.describeSecret("missing")).rejects.toBeInstanceOf(NotFoundError);
  });

  it("listSecrets auto-paginates with filters, sort order and planned deletion", async () => {
    const { mock, client } = await setup({
      ListSecrets: [fixture("listSecrets.page1"), fixture("listSecrets.page2")],
    });
    const all = await client
      .listSecrets({
        filters: [{ key: "name", values: ["sdkv-0badc0de/page/"] }],
        includePlannedDeletion: true,
        sortOrder: "asc",
        maxResults: 2,
      })
      .toArray();
    expect(all.length).toBeGreaterThanOrEqual(3);
    expect(all[0]?.name).toBe("sdkv-0badc0de/page/p1");
    const first = bodyOf(mock.calls("ListSecrets")[0]!);
    expect(first).toMatchObject({ IncludePlannedDeletion: true, SortOrder: "asc", MaxResults: 2 });
    expect(bodyOf(mock.calls("ListSecrets")[1]!).NextToken).toBeTruthy();
  });

  it("listSecrets iterates lazily and supports pages()", async () => {
    const { mock, client } = await setup({
      ListSecrets: [
        ok({ SecretList: [{ ARN: "a1", Name: "a" }], NextToken: "n1" }),
        ok({ SecretList: [{ ARN: "b1", Name: "b" }], NextToken: "n1" }),
      ],
    });
    const names: string[] = [];
    for await (const s of client.listSecrets()) names.push(s.name);
    // a repeated token stops the walk instead of looping forever
    expect(names).toEqual(["a", "b"]);
    expect(bodyOf(mock.calls("ListSecrets")[0]!)).toEqual({});
  });

  it("listSecrets recorded filter and error fixtures", async () => {
    const { client } = await setup({
      ListSecrets: [
        fixture("listSecrets.filter-tag"),
        fixture("listSecrets.include-planned-deletion"),
        fixture("listSecrets.bad-filter"),
      ],
    });
    expect((await client.listSecrets().toArray()).length).toBeGreaterThan(0);
    const planned = await client.listSecrets({ includePlannedDeletion: true }).toArray();
    expect(planned.some((s) => s.deletedDate !== undefined)).toBe(true);
    await expect(client.listSecrets().toArray()).rejects.toBeInstanceOf(ValidationError);
  });

  it("listSecretVersionIds paginates (empty-string token ends) and maps versions", async () => {
    const { mock, client } = await setup({
      ListSecretVersionIds: [
        ok({
          ARN: "arn",
          Name: "n",
          Versions: [
            { VersionId: "v1", VersionStages: ["AWSPREVIOUS"], CreatedDate: 1, KmsKeyIds: ["k"] },
          ],
          NextToken: "t",
        }),
        fixture("listSecretVersionIds.ok"),
      ],
    });
    const versions = await client
      .listSecretVersionIds("n", { includeDeprecated: true, maxResults: 1 })
      .toArray();
    expect(versions[0]).toEqual({
      versionId: "v1",
      versionStages: ["AWSPREVIOUS"],
      createdDate: new Date(1000),
      kmsKeyIds: ["k"],
    });
    expect(versions.length).toBeGreaterThan(1);
    expect(bodyOf(mock.calls("ListSecretVersionIds")[0]!)).toMatchObject({
      SecretId: "n",
      IncludeDeprecated: true,
      MaxResults: 1,
    });
  });

  it("listSecretVersionIds: AWS not-found shape and Moto's 500", async () => {
    const { client } = await setup({
      ListSecretVersionIds: [
        awsError("ResourceNotFoundException"),
        fixture("listSecretVersionIds.not-found-moto-500"),
      ],
    });
    await expect(client.listSecretVersionIds("x").toArray()).rejects.toBeInstanceOf(NotFoundError);
    await expect(client.listSecretVersionIds("x").toArray()).rejects.toMatchObject({
      code: "UNAVAILABLE",
      httpStatus: 500,
    });
  });
});

describe("write operations", () => {
  it("createSecret encodes string, bytes, objects and no value", async () => {
    const { mock, client } = await setup({
      CreateSecret: [
        fixture("createSecret.ok-string"),
        fixture("createSecret.ok-binary"),
        fixture("createSecret.ok-string"),
        fixture("createSecret.no-value"),
      ],
    });
    const r = await client.createSecret("app/db", "s3cr3t", {
      description: "d",
      kmsKeyId: "alias/k",
      tags: { team: "a" },
      clientRequestToken: "t".repeat(32),
      addReplicaRegions: [{ region: "eu-west-1", kmsKeyId: "k" }, { region: "eu-north-1" }],
      forceOverwriteReplicaSecret: false,
    });
    expect(r.arn).toMatch(/^arn:/);
    expect(r.versionId).toBeTruthy();
    expect(bodyOf(mock.calls("CreateSecret")[0]!)).toEqual({
      Name: "app/db",
      SecretString: "s3cr3t",
      Description: "d",
      KmsKeyId: "alias/k",
      Tags: [{ Key: "team", Value: "a" }],
      ClientRequestToken: "t".repeat(32),
      AddReplicaRegions: [{ Region: "eu-west-1", KmsKeyId: "k" }, { Region: "eu-north-1" }],
      ForceOverwriteReplicaSecret: false,
    });
    await client.createSecret("app/blob", new Uint8Array([0, 1, 2]));
    expect(bodyOf(mock.calls("CreateSecret")[1]!)).toMatchObject({ SecretBinary: "AAEC" });
    await client.createSecret("app/json", { a: 1 });
    expect(bodyOf(mock.calls("CreateSecret")[2]!)).toMatchObject({ SecretString: '{"a":1}' });
    const empty = await client.createSecret("app/empty", undefined);
    expect(empty.versionId).toBeUndefined();
    expect(bodyOf(mock.calls("CreateSecret")[3]!)).not.toHaveProperty("SecretString");
    // the SDK fills an idempotency token when none is given
    expect(bodyOf(mock.calls("CreateSecret")[1]!).ClientRequestToken).toBeTruthy();
  });

  it("createSecret errors: exists, pending deletion, access denied, unserialisable", async () => {
    const { client } = await setup({
      CreateSecret: [
        fixture("createSecret.exists"),
        fixture("createSecret.pending-deletion"),
        fixture("createSecret.access-denied"),
      ],
    });
    await expect(client.createSecret("a", "v")).rejects.toBeInstanceOf(ConflictError);
    await expect(client.createSecret("a", "v")).rejects.toBeInstanceOf(ConflictError);
    await expect(client.createSecret("a", "v")).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
      httpStatus: 403,
    });
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    await expect(client.createSecret("a", cyclic)).rejects.toBeInstanceOf(ValidationError);
  });

  it("putSecretValue: default and custom stages, token reuse, not found", async () => {
    const { mock, client } = await setup({
      PutSecretValue: [
        fixture("putSecretValue.ok"),
        fixture("putSecretValue.custom-stage"),
        fixture("putSecretValue.token-reuse-different"),
        fixture("putSecretValue.not-found"),
      ],
    });
    const r = await client.putSecretValue("app/db", "v2");
    expect(r.versionStages).toContain("AWSCURRENT");
    expect(r.versionId).toBeTruthy();
    const c = await client.putSecretValue("app/db", new Uint8Array([9]), {
      versionStages: ["CUSTOM"],
      clientRequestToken: "c".repeat(32),
    });
    expect(c.versionStages).toEqual(["STAGEX"]);
    expect(bodyOf(mock.calls("PutSecretValue")[1]!)).toMatchObject({
      SecretBinary: "CQ==",
      VersionStages: ["CUSTOM"],
      ClientRequestToken: "c".repeat(32),
    });
    await expect(client.putSecretValue("app/db", "x")).rejects.toBeInstanceOf(ConflictError);
    await expect(client.putSecretValue("nope", "x")).rejects.toBeInstanceOf(NotFoundError);
  });

  it("updateSecret: description only, value, not found", async () => {
    const { mock, client } = await setup({
      UpdateSecret: [
        fixture("updateSecret.description"),
        fixture("updateSecret.value"),
        fixture("updateSecret.not-found"),
      ],
    });
    const d = await client.updateSecret("app/db", { description: "new", kmsKeyId: "k" });
    expect(d.name).toBeTruthy();
    expect(bodyOf(mock.calls("UpdateSecret")[0]!)).toMatchObject({
      Description: "new",
      KmsKeyId: "k",
    });
    const v = await client.updateSecret("app/db", {
      value: "v3",
      clientRequestToken: "u".repeat(32),
    });
    expect(v.versionId).toBeTruthy();
    await expect(client.updateSecret("nope", { description: "x" })).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  it("updateSecretVersionStage: move, promote, missing remove", async () => {
    const { mock, client } = await setup({
      UpdateSecretVersionStage: [
        fixture("updateSecretVersionStage.move"),
        fixture("updateSecretVersionStage.promote-current"),
        fixture("updateSecretVersionStage.missing-remove"),
      ],
    });
    const r = await client.updateSecretVersionStage("app/db", "CUSTOM", { moveToVersionId: "v1" });
    expect(r.arn).toMatch(/^arn:/);
    await client.updateSecretVersionStage("app/db", "AWSCURRENT", {
      moveToVersionId: "v2",
      removeFromVersionId: "v1",
    });
    expect(bodyOf(mock.calls("UpdateSecretVersionStage")[1]!)).toEqual({
      SecretId: "app/db",
      VersionStage: "AWSCURRENT",
      MoveToVersionId: "v2",
      RemoveFromVersionId: "v1",
    });
    await expect(
      client.updateSecretVersionStage("app/db", "AWSCURRENT", { moveToVersionId: "v2" }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(client.updateSecretVersionStage("app/db", "X")).rejects.toBeInstanceOf(
      ValidationError,
    );
  });

  it("deleteSecret: window, force, force on missing, errors and client-side checks", async () => {
    const { mock, client } = await setup({
      DeleteSecret: [
        fixture("deleteSecret.recovery-window"),
        fixture("deleteSecret.force"),
        fixture("deleteSecret.force-missing"),
        fixture("deleteSecret.not-found"),
        fixture("deleteSecret.already-deleted"),
        fixture("deleteSecret.bad-window"),
      ],
    });
    const w = await client.deleteSecret("a", { recoveryWindowDays: 7 });
    expect(w.deletionDate).toBeInstanceOf(Date);
    expect(bodyOf(mock.calls("DeleteSecret")[0]!)).toEqual({
      SecretId: "a",
      RecoveryWindowInDays: 7,
    });
    await client.deleteSecret("a", { forceDeleteWithoutRecovery: true });
    expect(bodyOf(mock.calls("DeleteSecret")[1]!)).toMatchObject({
      ForceDeleteWithoutRecovery: true,
    });
    await client.deleteSecret("missing", { forceDeleteWithoutRecovery: true });
    await expect(client.deleteSecret("missing")).rejects.toBeInstanceOf(NotFoundError);
    await expect(client.deleteSecret("a")).rejects.toBeInstanceOf(ConflictError);
    await expect(client.deleteSecret("a")).rejects.toBeInstanceOf(ValidationError);
    await expect(
      client.deleteSecret("a", { recoveryWindowDays: 7, forceDeleteWithoutRecovery: true }),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(client.deleteSecret("a", { recoveryWindowDays: 3 })).rejects.toBeInstanceOf(
      ValidationError,
    );
    expect(mock.calls("DeleteSecret")).toHaveLength(6);
  });

  it("deleteSecret without DeletionDate", async () => {
    const { client } = await setup({ DeleteSecret: ok({ ARN: "a", Name: "n" }) });
    expect(await client.deleteSecret("n")).toEqual({ arn: "a", name: "n" });
  });

  it("restoreSecret: ok, live secret no-op, not found", async () => {
    const { client } = await setup({
      RestoreSecret: [
        fixture("restoreSecret.ok"),
        fixture("restoreSecret.not-deleted"),
        fixture("restoreSecret.not-found"),
      ],
    });
    expect((await client.restoreSecret("a")).arn).toMatch(/^arn:/);
    expect((await client.restoreSecret("a")).name).toBeTruthy();
    await expect(client.restoreSecret("a")).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe("tags and resource policy", () => {
  it("tagResource / untagResource", async () => {
    const { mock, client } = await setup({
      TagResource: [fixture("tagResource.ok"), fixture("tagResource.not-found")],
      UntagResource: [fixture("untagResource.ok"), fixture("untagResource.not-found")],
    });
    await client.tagResource("a", { env: "dev", team: "x" });
    expect(bodyOf(mock.calls("TagResource")[0]!)).toEqual({
      SecretId: "a",
      Tags: [
        { Key: "env", Value: "dev" },
        { Key: "team", Value: "x" },
      ],
    });
    await expect(client.tagResource("b", { a: "1" })).rejects.toBeInstanceOf(NotFoundError);
    await client.untagResource("a", ["env"]);
    expect(bodyOf(mock.calls("UntagResource")[0]!)).toEqual({ SecretId: "a", TagKeys: ["env"] });
    await expect(client.untagResource("b", ["x"])).rejects.toBeInstanceOf(NotFoundError);
  });

  it("put/get/delete resource policy", async () => {
    const policy = {
      Version: "2012-10-17",
      Statement: [
        { Effect: "Allow", Principal: { AWS: "arn:aws:iam::1:root" }, Action: "*", Resource: "*" },
      ],
    };
    const { mock, client } = await setup({
      PutResourcePolicy: [
        fixture("putResourcePolicy.ok"),
        fixture("putResourcePolicy.malformed-accepted"),
        fixture("putResourcePolicy.not-found"),
        awsError("MalformedPolicyDocumentException"),
        awsError("PublicPolicyException"),
      ],
      GetResourcePolicy: [
        fixture("getResourcePolicy.ok"),
        fixture("getResourcePolicy.none"),
        ok({ ARN: "a", Name: "n", ResourcePolicy: "not json" }),
      ],
      DeleteResourcePolicy: fixture("deleteResourcePolicy.ok"),
    });
    const put = await client.putResourcePolicy("a", policy, { blockPublicPolicy: true });
    expect(put.arn).toMatch(/^arn:/);
    expect(bodyOf(mock.calls("PutResourcePolicy")[0]!)).toEqual({
      SecretId: "a",
      ResourcePolicy: JSON.stringify(policy),
      BlockPublicPolicy: true,
    });
    await client.putResourcePolicy("a", "{not json");
    await expect(client.putResourcePolicy("missing", "{}")).rejects.toBeInstanceOf(NotFoundError);
    await expect(client.putResourcePolicy("a", "{}")).rejects.toBeInstanceOf(ValidationError);
    await expect(client.putResourcePolicy("a", "{}")).rejects.toBeInstanceOf(ValidationError);
    const got = await client.getResourcePolicy("a");
    expect(got.resourcePolicy).toBeTruthy();
    expect(got.policy).toHaveProperty("Statement");
    const none = await client.getResourcePolicy("a");
    expect(none.resourcePolicy).toBeUndefined();
    expect(none.policy).toBeUndefined();
    const bad = await client.getResourcePolicy("a");
    expect(bad).toEqual({ arn: "a", name: "n", resourcePolicy: "not json" });
    expect((await client.deleteResourcePolicy("a")).arn).toMatch(/^arn:/);
  });

  it("validateResourcePolicy: AWS answers, malformed document, Moto 500 → UNSUPPORTED", async () => {
    const { mock, client } = await setup({
      ValidateResourcePolicy: [
        ok({ PolicyValidationPassed: true, ValidationErrors: [] }),
        ok({
          PolicyValidationPassed: false,
          ValidationErrors: [{ CheckName: "PUBLIC", ErrorMessage: "too open" }, {}],
        }),
        awsError("MalformedPolicyDocumentException"),
        fixture("validateResourcePolicy.moto-unsupported"),
      ],
    });
    expect(
      await client.validateResourcePolicy({ Version: "2012-10-17" }, { secretId: "a" }),
    ).toEqual({ policyValidationPassed: true, validationErrors: [] });
    expect(bodyOf(mock.calls("ValidateResourcePolicy")[0]!)).toEqual({
      ResourcePolicy: '{"Version":"2012-10-17"}',
      SecretId: "a",
    });
    expect(await client.validateResourcePolicy("{}")).toEqual({
      policyValidationPassed: false,
      validationErrors: [{ checkName: "PUBLIC", errorMessage: "too open" }, {}],
    });
    await expect(client.validateResourcePolicy("{")).rejects.toBeInstanceOf(ValidationError);
    await expect(client.validateResourcePolicy("{}")).rejects.toBeInstanceOf(UnsupportedError);
  });
});

describe("rotation", () => {
  it("rotateSecret: rules only, Lambda, Lambda not found, in progress", async () => {
    const { mock, client } = await setup({
      RotateSecret: [
        fixture("rotateSecret.rules-only"),
        ok({ ARN: "arn", Name: "n", VersionId: "v9" }),
        fixture("rotateSecret.lambda-not-found"),
        awsError("InvalidRequestException", "rotation in progress"),
      ],
    });
    const r = await client.rotateSecret("a", {
      rules: { automaticallyAfterDays: 30 },
      rotateImmediately: true,
    });
    expect(r.versionId).toBeTruthy();
    expect(bodyOf(mock.calls("RotateSecret")[0]!)).toMatchObject({
      RotationRules: { AutomaticallyAfterDays: 30 },
      RotateImmediately: true,
    });
    await client.rotateSecret("a", {
      lambdaArn: "arn:aws:lambda:us-east-1:1:function:rot",
      rules: { scheduleExpression: "rate(10 days)", duration: "2h" },
      clientRequestToken: "r".repeat(32),
    });
    expect(bodyOf(mock.calls("RotateSecret")[1]!)).toEqual({
      SecretId: "a",
      RotationLambdaARN: "arn:aws:lambda:us-east-1:1:function:rot",
      RotationRules: { ScheduleExpression: "rate(10 days)", Duration: "2h" },
      ClientRequestToken: "r".repeat(32),
    });
    await expect(client.rotateSecret("a", { lambdaArn: "arn:x" })).rejects.toBeInstanceOf(
      NotFoundError,
    );
    await expect(client.rotateSecret("a")).rejects.toBeInstanceOf(ConflictError);
  });

  it("cancelRotateSecret: ok and not found", async () => {
    const { client } = await setup({
      CancelRotateSecret: [
        fixture("cancelRotateSecret.ok"),
        fixture("cancelRotateSecret.not-found"),
      ],
    });
    expect((await client.cancelRotateSecret("a")).arn).toMatch(/^arn:/);
    await expect(client.cancelRotateSecret("a")).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe("utilities", () => {
  it("getRandomPassword returns a redacting Secret and passes every option", async () => {
    const { mock, client } = await setup({
      GetRandomPassword: [
        fixture("getRandomPassword.ok"),
        fixture("getRandomPassword.exclude-chars"),
        fixture("getRandomPassword.too-short"),
        ok({}),
      ],
    });
    const p = await client.getRandomPassword();
    expect(p).toBeInstanceOf(Secret);
    expect(p.reveal().length).toBeGreaterThan(8);
    expect(String(p)).not.toContain(p.reveal());
    expect(bodyOf(mock.calls("GetRandomPassword")[0]!)).toEqual({ PasswordLength: 32 });
    await client.getRandomPassword({
      length: 20,
      excludeCharacters: "abc",
      excludeNumbers: true,
      excludePunctuation: true,
      excludeUppercase: false,
      excludeLowercase: false,
      includeSpace: false,
      requireEachIncludedType: true,
    });
    expect(bodyOf(mock.calls("GetRandomPassword")[1]!)).toEqual({
      PasswordLength: 20,
      ExcludeCharacters: "abc",
      ExcludeNumbers: true,
      ExcludePunctuation: true,
      ExcludeUppercase: false,
      ExcludeLowercase: false,
      IncludeSpace: false,
      RequireEachIncludedType: true,
    });
    await expect(client.getRandomPassword({ length: 1 })).rejects.toBeInstanceOf(ValidationError);
    expect((await client.getRandomPassword()).reveal()).toBe("");
  });

  it("getJsonField: exact key, dot path, absent, binary, not JSON, not object", async () => {
    const { client } = await setup({
      GetSecretValue: [
        fixture("getSecretValue.json-seed"),
        ok({
          ARN: "a",
          Name: "n",
          SecretString: '{"db":{"host":"h","port":5},"a.b":1,"nul":null}',
        }),
        ok({
          ARN: "a",
          Name: "n",
          SecretString: '{"db":{"host":"h","port":5},"a.b":1,"nul":null}',
        }),
        ok({
          ARN: "a",
          Name: "n",
          SecretString: '{"db":{"host":"h","port":5},"a.b":1,"nul":null}',
        }),
        ok({
          ARN: "a",
          Name: "n",
          SecretString: '{"db":{"host":"h","port":5},"a.b":1,"nul":null}',
        }),
        ok({
          ARN: "a",
          Name: "n",
          SecretString: '{"db":{"host":"h","port":5},"a.b":1,"nul":null}',
        }),
        fixture("getSecretValue.ok-binary"),
        ok({ ARN: "a", Name: "n", SecretString: "plain" }),
        ok({ ARN: "a", Name: "n", SecretString: "[1,2]" }),
        fixture("getSecretValue.not-found"),
      ],
    });
    expect(await client.getJsonField("seed", "username")).toBe("seed-user");
    expect(await client.getJsonField("n", "db.host", { versionStage: "AWSCURRENT" })).toBe("h");
    expect(await client.getJsonField("n", "a.b")).toBe(1);
    expect(await client.getJsonField("n", "db.missing")).toBeNull();
    expect(await client.getJsonField("n", "db.port.deeper")).toBeNull();
    expect(await client.getJsonField("n", "nul")).toBeNull();
    await expect(client.getJsonField("n", "x")).rejects.toBeInstanceOf(ValidationError);
    await expect(client.getJsonField("n", "x")).rejects.toBeInstanceOf(ValidationError);
    await expect(client.getJsonField("n", "x")).rejects.toBeInstanceOf(ValidationError);
    await expect(client.getJsonField("n", "x")).rejects.toBeInstanceOf(NotFoundError);
  });
});
