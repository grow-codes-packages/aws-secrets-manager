// Unit-test support: a tiny stateful AWS Secrets Manager (AWS JSON 1.1 shapes, AWS status codes)
// for provider and conformance unit tests. Real-service behaviour is covered by the Docker suite.

import { randomUUID } from "node:crypto";
import { type MockServer, type RecordedRequest, startServer } from "../helpers/server.js";
import { type AwsMock, awsError, bodyOf, ok, operationOf } from "./aws.js";
import type { MockResponse } from "../helpers/server.js";

interface Version {
  id: string;
  stages: string[];
  string?: string;
  binary?: string;
  created: number;
}

interface Stored {
  name: string;
  arn: string;
  description?: string;
  tags: Record<string, string>;
  versions: Version[];
  created: number;
  changed: number;
  deleted?: number;
}

export interface FakeAsm extends AwsMock {
  store: Map<string, Stored>;
  /** Overrides one operation (e.g. to inject an error). */
  override(
    operation: string,
    fn: ((req: RecordedRequest) => MockResponse | undefined) | undefined,
  ): void;
}

let clock = 1_795_000_000;

export async function startFakeAsm(): Promise<FakeAsm> {
  const store = new Map<string, Stored>();
  const overrides = new Map<string, (req: RecordedRequest) => MockResponse | undefined>();
  const find = (id: unknown): Stored | undefined => {
    const key = String(id);
    return store.get(key) ?? [...store.values()].find((s) => s.arn === key);
  };
  const missing = (): MockResponse =>
    awsError("ResourceNotFoundException", "Secrets Manager can't find the specified secret.");
  const describe = (s: Stored): Record<string, unknown> => ({
    ARN: s.arn,
    Name: s.name,
    ...(s.description === undefined ? {} : { Description: s.description }),
    CreatedDate: s.created,
    LastChangedDate: s.changed,
    ...(s.deleted === undefined ? {} : { DeletedDate: s.deleted }),
    Tags: Object.entries(s.tags).map(([Key, Value]) => ({ Key, Value })),
    VersionIdsToStages: Object.fromEntries(
      s.versions.filter((v) => v.stages.length > 0).map((v) => [v.id, v.stages]),
    ),
  });
  const value = (s: Stored, v: Version): Record<string, unknown> => ({
    ARN: s.arn,
    Name: s.name,
    VersionId: v.id,
    VersionStages: v.stages,
    CreatedDate: v.created,
    ...(v.binary === undefined ? { SecretString: v.string } : { SecretBinary: v.binary }),
  });
  const addVersion = (
    s: Stored,
    body: Record<string, unknown>,
    stages = ["AWSCURRENT"],
  ): Version => {
    if (stages.includes("AWSCURRENT")) {
      for (const v of s.versions) {
        v.stages = v.stages.filter((x) => x !== "AWSPREVIOUS");
        if (v.stages.includes("AWSCURRENT")) {
          v.stages = [...v.stages.filter((x) => x !== "AWSCURRENT"), "AWSPREVIOUS"];
        }
      }
    }
    const version: Version = {
      id: typeof body.ClientRequestToken === "string" ? body.ClientRequestToken : randomUUID(),
      stages,
      created: ++clock,
      ...(typeof body.SecretBinary === "string"
        ? { binary: body.SecretBinary }
        : { string: typeof body.SecretString === "string" ? body.SecretString : "" }),
    };
    s.versions.push(version);
    s.changed = clock;
    return version;
  };

  const handle = (req: RecordedRequest): MockResponse => {
    const op = operationOf(req);
    const custom = overrides.get(op)?.(req);
    if (custom !== undefined) return custom;
    const b = bodyOf(req);
    const s = find(b.SecretId);
    switch (op) {
      case "CreateSecret": {
        const name = String(b.Name);
        if (store.has(name)) return awsError("ResourceExistsException", "exists");
        const created: Stored = {
          name,
          arn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:${name}-AbCdEf`,
          tags: Object.fromEntries(
            ((b.Tags as { Key: string; Value: string }[] | undefined) ?? []).map((t) => [
              t.Key,
              t.Value,
            ]),
          ),
          versions: [],
          created: ++clock,
          changed: clock,
          ...(typeof b.Description === "string" ? { description: b.Description } : {}),
        };
        store.set(name, created);
        const hasValue = b.SecretString !== undefined || b.SecretBinary !== undefined;
        const v = hasValue ? addVersion(created, b) : undefined;
        return ok({
          ARN: created.arn,
          Name: name,
          ...(v === undefined ? {} : { VersionId: v.id }),
        });
      }
      case "PutSecretValue": {
        if (s === undefined) return missing();
        if (s.deleted !== undefined)
          return awsError("InvalidRequestException", "marked for deletion");
        const v = addVersion(s, b, (b.VersionStages as string[] | undefined) ?? ["AWSCURRENT"]);
        return ok({ ARN: s.arn, Name: s.name, VersionId: v.id, VersionStages: v.stages });
      }
      case "GetSecretValue": {
        if (s === undefined) return missing();
        if (s.deleted !== undefined)
          return awsError("InvalidRequestException", "marked for deletion");
        const v =
          typeof b.VersionId === "string"
            ? s.versions.find((x) => x.id === b.VersionId)
            : s.versions.find((x) =>
                x.stages.includes(
                  typeof b.VersionStage === "string" ? b.VersionStage : "AWSCURRENT",
                ),
              );
        return v === undefined ? missing() : ok(value(s, v));
      }
      case "BatchGetSecretValue": {
        const ids = (b.SecretIdList as string[] | undefined) ?? [];
        const values: unknown[] = [];
        const errors: unknown[] = [];
        for (const id of ids) {
          const x = find(id);
          const v = x?.versions.find((y) => y.stages.includes("AWSCURRENT"));
          if (x === undefined || v === undefined) {
            errors.push({ SecretId: id, ErrorCode: "ResourceNotFoundException", Message: "m" });
          } else if (x.deleted !== undefined) {
            errors.push({ SecretId: id, ErrorCode: "InvalidRequestException", Message: "m" });
          } else {
            values.push(value(x, v));
          }
        }
        return ok({ SecretValues: values, Errors: errors });
      }
      case "DescribeSecret":
        return s === undefined ? missing() : ok(describe(s));
      case "ListSecrets": {
        const filters = (b.Filters as { Key: string; Values: string[] }[] | undefined) ?? [];
        const prefix = filters.find((f) => f.Key === "name")?.Values[0] ?? "";
        const list = [...store.values()]
          .filter((x) => x.name.startsWith(prefix) || x.name.includes(`/${prefix}`))
          .filter((x) => b.IncludePlannedDeletion === true || x.deleted === undefined)
          .sort((a, c) => a.created - c.created);
        const start = typeof b.NextToken === "string" ? Number(b.NextToken) : 0;
        const size = typeof b.MaxResults === "number" ? b.MaxResults : 2;
        const page = list.slice(start, start + size);
        const next = start + size < list.length ? String(start + size) : null;
        return ok({ SecretList: page.map(describe), NextToken: next });
      }
      case "DeleteSecret": {
        if (s === undefined) {
          return b.ForceDeleteWithoutRecovery === true
            ? ok({ ARN: "arn", Name: String(b.SecretId), DeletionDate: clock })
            : missing();
        }
        if (b.ForceDeleteWithoutRecovery === true) store.delete(s.name);
        else s.deleted = ++clock;
        return ok({ ARN: s.arn, Name: s.name, DeletionDate: clock });
      }
      case "RestoreSecret":
        if (s === undefined) return missing();
        delete s.deleted;
        return ok({ ARN: s.arn, Name: s.name });
      case "TagResource":
        if (s === undefined) return missing();
        for (const t of b.Tags as { Key: string; Value: string }[]) s.tags[t.Key] = t.Value;
        return ok({});
      case "UpdateSecret":
        if (s === undefined) return missing();
        if (typeof b.Description === "string") s.description = b.Description;
        return ok({ ARN: s.arn, Name: s.name });
      case "ListSecretVersionIds":
        if (s === undefined) return missing();
        return ok({
          ARN: s.arn,
          Name: s.name,
          Versions: s.versions.map((v) => ({
            VersionId: v.id,
            VersionStages: v.stages,
            CreatedDate: v.created,
          })),
        });
      default:
        return awsError("UnknownOperationException", op);
    }
  };
  const server: MockServer = await startServer(handle);
  return Object.assign(server, {
    store,
    calls: (operation: string) => server.requests.filter((r) => operationOf(r) === operation),
    override: (
      operation: string,
      fn: ((req: RecordedRequest) => MockResponse | undefined) | undefined,
    ) => {
      if (fn === undefined) overrides.delete(operation);
      else overrides.set(operation, fn);
    },
  });
}
