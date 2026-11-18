// Service-owned: camelCase models of the AWS Secrets Manager API and converters from the AWS SDK
// shapes. Secret values are always wrapped in the redacting {@link SecretValue}.

import type {
  APIErrorType,
  DescribeSecretResponse,
  ReplicationStatusType,
  RotationRulesType,
  SecretListEntry,
  SecretValueEntry,
  SecretVersionsListEntry,
  Tag,
  ValidationErrorsEntry,
} from "@aws-sdk/client-secrets-manager";
import { ValidationError } from "./core/index.js";
import { SecretValue } from "./secrets/index.js";
import type { SecretInput } from "./secrets/index.js";

/** AWS Secrets Manager API version (the API contract date; AWS exposes no server version). */
export const API_VERSION = "2017-10-17";

/** Default version stage. */
export const AWSCURRENT = "AWSCURRENT";
/** Stage of the previous current version. */
export const AWSPREVIOUS = "AWSPREVIOUS";
/** Stage of a version being rotated in. */
export const AWSPENDING = "AWSPENDING";

/** Maximum ids per `BatchGetSecretValue` call; longer id lists are split. */
export const BATCH_GET_MAX_IDS = 20;

/** Per-call options of every I/O method. */
export interface CallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Selects a version by id or by stage label (default `AWSCURRENT`). */
export interface VersionSelector {
  /** Version id (`VersionId`). */
  versionId?: string;
  /** Stage label, e.g. `AWSCURRENT`, `AWSPREVIOUS` or a custom label. */
  versionStage?: string;
}

/** A secret value read from AWS (`GetSecretValue`, `BatchGetSecretValue`). */
export interface AwsSecretValue {
  /** Full ARN. */
  arn: string;
  /** Secret name. */
  name: string;
  /** Version id. */
  versionId?: string;
  /** Stage labels attached to this version. */
  versionStages: string[];
  /** Creation time of this version. */
  createdDate?: Date;
  /** True when the secret stores `SecretBinary`, false for `SecretString`. */
  binary: boolean;
  /** The value (redacting wrapper; `value.version` is the version id). */
  value: SecretValue;
}

/** Rotation schedule. */
export interface RotationRules {
  /** Rotate every N days (1–1000). */
  automaticallyAfterDays?: number;
  /** Rotation window length, e.g. `"3h"`. */
  duration?: string;
  /** `rate(…)` or `cron(…)` expression. */
  scheduleExpression?: string;
}

/** Replication status of one replica region. */
export interface ReplicationStatus {
  region?: string;
  kmsKeyId?: string;
  status?: string;
  statusMessage?: string;
  lastAccessedDate?: Date;
}

/** Secret metadata (`DescribeSecret`, `ListSecrets` entries). Never contains the value. */
export interface SecretDescription {
  arn: string;
  name: string;
  description?: string;
  kmsKeyId?: string;
  rotationEnabled: boolean;
  rotationLambdaArn?: string;
  rotationRules?: RotationRules;
  lastRotatedDate?: Date;
  lastChangedDate?: Date;
  lastAccessedDate?: Date;
  /** Set when the secret is scheduled for deletion. */
  deletedDate?: Date;
  nextRotationDate?: Date;
  createdDate?: Date;
  primaryRegion?: string;
  owningService?: string;
  /** Tags as a map. */
  tags: Record<string, string>;
  /** Version id → stage labels. */
  versionIdsToStages: Record<string, string[]>;
  replicationStatus: ReplicationStatus[];
}

/** One version of a secret (`ListSecretVersionIds`). */
export interface SecretVersion {
  versionId: string;
  versionStages: string[];
  createdDate?: Date;
  lastAccessedDate?: Date;
  kmsKeyIds: string[];
}

/** ARN and name of a secret. */
export interface SecretRef {
  arn: string;
  name: string;
}

/** Result of writes that may create a version. */
export interface SecretWriteResult extends SecretRef {
  /** Id of the new version (absent when no version was created). */
  versionId?: string;
}

/** Result of `putSecretValue`. */
export interface PutSecretValueResult extends SecretRef {
  versionId: string;
  versionStages: string[];
}

/** Result of `deleteSecret`. */
export interface DeleteSecretResult extends SecretRef {
  /** When the secret will be (or was) deleted. */
  deletionDate?: Date;
}

/** Result of `getResourcePolicy`. */
export interface ResourcePolicyResult extends SecretRef {
  /** The policy JSON text, absent when the secret has no policy. */
  resourcePolicy?: string;
  /** The parsed policy, absent when there is none or it is not valid JSON. */
  policy?: Record<string, unknown>;
}

/** One problem found by `validateResourcePolicy`. */
export interface PolicyValidationError {
  checkName?: string;
  errorMessage?: string;
}

/** Result of `validateResourcePolicy`. */
export interface ValidateResourcePolicyResult {
  policyValidationPassed: boolean;
  validationErrors: PolicyValidationError[];
}

/** A per-secret failure of `batchGetSecretValue` (the call itself succeeded). */
export interface BatchGetError {
  secretId?: string;
  /** AWS error code, e.g. `ResourceNotFoundException`. */
  errorCode?: string;
  message?: string;
}

/** Result of `batchGetSecretValue`. */
export interface BatchGetResult {
  /** Values, in request order for the id form. */
  secretValues: AwsSecretValue[];
  /** Ids that could not be read. */
  errors: BatchGetError[];
}

/** `ListSecrets` / `BatchGetSecretValue` filter keys. */
export type SecretFilterKey =
  "name" | "description" | "tag-key" | "tag-value" | "primary-region" | "owning-service" | "all";

/** A `ListSecrets` filter. A value prefixed with `!` negates it (AWS). */
export interface SecretFilter {
  key: SecretFilterKey;
  values: string[];
}

/** A replica region for `createSecret`. */
export interface ReplicaRegion {
  region: string;
  kmsKeyId?: string;
}

/** Converts tags to the AWS list form. */
export function toAwsTags(tags: Readonly<Record<string, string>>): Tag[] {
  return Object.entries(tags).map(([Key, Value]) => ({ Key, Value }));
}

/** Converts the AWS tag list to a map. */
export function fromAwsTags(tags: readonly Tag[] | undefined | null): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tags ?? []) if (t.Key !== undefined) out[t.Key] = t.Value ?? "";
  return out;
}

/**
 * Encodes a value for `SecretString`/`SecretBinary`: strings as `SecretString`, bytes as
 * `SecretBinary`, objects as JSON `SecretString`.
 */
export function encodeValue(
  value: SecretInput,
): { SecretString: string } | { SecretBinary: Uint8Array } {
  if (typeof value === "string") return { SecretString: value };
  if (value instanceof Uint8Array) return { SecretBinary: value };
  let json: string | undefined;
  try {
    json = JSON.stringify(value);
  } catch {
    json = undefined;
  }
  if (json === undefined) throw new ValidationError("secret value must be JSON-serialisable");
  return { SecretString: json };
}

/** Encodes raw bytes: valid UTF-8 → `SecretString`, anything else → `SecretBinary`. */
export function encodeBytes(
  bytes: Uint8Array,
): { SecretString: string } | { SecretBinary: Uint8Array } {
  try {
    return { SecretString: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch {
    return { SecretBinary: bytes };
  }
}

function opt<K extends string, V>(key: K, value: V | undefined | null): { [P in K]?: V } {
  return (value === undefined || value === null ? {} : { [key]: value }) as { [P in K]?: V };
}

/** The fields of a `GetSecretValue` output that {@link toSecretValue} reads. */
export interface ValueShape {
  ARN?: string | undefined;
  Name?: string | undefined;
  VersionId?: string | undefined;
  VersionStages?: string[] | undefined;
  CreatedDate?: Date | undefined;
  SecretString?: string | undefined;
  SecretBinary?: Uint8Array | undefined;
}

/** Converts a `GetSecretValue` output / `SecretValueEntry`. */
export function toSecretValue(out: ValueShape | SecretValueEntry): AwsSecretValue {
  const binary = out.SecretBinary !== undefined;
  const raw: string | Uint8Array = binary
    ? (out.SecretBinary as Uint8Array)
    : (out.SecretString ?? "");
  return {
    arn: out.ARN ?? "",
    name: out.Name ?? "",
    ...opt("versionId", out.VersionId),
    versionStages: [...(out.VersionStages ?? [])],
    ...opt("createdDate", out.CreatedDate),
    binary,
    value: new SecretValue(raw, out.VersionId ?? undefined),
  };
}

function toRotationRules(r: RotationRulesType | undefined | null): RotationRules | undefined {
  if (r === undefined || r === null) return undefined;
  return {
    ...opt("automaticallyAfterDays", r.AutomaticallyAfterDays),
    ...opt("duration", r.Duration),
    ...opt("scheduleExpression", r.ScheduleExpression),
  };
}

function toReplication(r: ReplicationStatusType): ReplicationStatus {
  return {
    ...opt("region", r.Region),
    ...opt("kmsKeyId", r.KmsKeyId),
    ...opt("status", r.Status),
    ...opt("statusMessage", r.StatusMessage),
    ...opt("lastAccessedDate", r.LastAccessedDate),
  };
}

/** Converts a `DescribeSecret` output or a `SecretListEntry`. */
export function toDescription(
  out: Omit<SecretListEntry, "Tags"> &
    Omit<DescribeSecretResponse, "Tags"> & { Tags?: Tag[] | undefined },
): SecretDescription {
  const stages: Record<string, string[]> = {};
  for (const [id, list] of Object.entries(out.SecretVersionsToStages ?? {})) stages[id] = [...list];
  for (const [id, list] of Object.entries(out.VersionIdsToStages ?? {})) stages[id] = [...list];
  return {
    arn: out.ARN ?? "",
    name: out.Name ?? "",
    ...opt("description", out.Description),
    ...opt("kmsKeyId", out.KmsKeyId),
    rotationEnabled: out.RotationEnabled === true,
    ...opt("rotationLambdaArn", out.RotationLambdaARN),
    ...opt("rotationRules", toRotationRules(out.RotationRules)),
    ...opt("lastRotatedDate", out.LastRotatedDate),
    ...opt("lastChangedDate", out.LastChangedDate),
    ...opt("lastAccessedDate", out.LastAccessedDate),
    ...opt("deletedDate", out.DeletedDate),
    ...opt("nextRotationDate", out.NextRotationDate),
    ...opt("createdDate", out.CreatedDate),
    ...opt("primaryRegion", out.PrimaryRegion),
    ...opt("owningService", out.OwningService),
    tags: fromAwsTags(out.Tags),
    versionIdsToStages: stages,
    replicationStatus: (out.ReplicationStatus ?? []).map(toReplication),
  };
}

/** Converts a `ListSecretVersionIds` entry. */
export function toVersion(v: SecretVersionsListEntry): SecretVersion {
  return {
    versionId: v.VersionId ?? "",
    versionStages: [...(v.VersionStages ?? [])],
    ...opt("createdDate", v.CreatedDate),
    ...opt("lastAccessedDate", v.LastAccessedDate),
    kmsKeyIds: [...(v.KmsKeyIds ?? [])],
  };
}

/** Converts a `BatchGetSecretValue` error entry. */
export function toBatchError(e: APIErrorType): BatchGetError {
  return {
    ...opt("secretId", e.SecretId),
    ...opt("errorCode", e.ErrorCode),
    ...opt("message", e.Message),
  };
}

/** Converts a `ValidateResourcePolicy` error entry. */
export function toPolicyError(e: ValidationErrorsEntry): PolicyValidationError {
  return { ...opt("checkName", e.CheckName), ...opt("errorMessage", e.ErrorMessage) };
}

/** Parses a policy JSON text into an object (`undefined` when absent or not a JSON object). */
export function parsePolicy(text: string | undefined): Record<string, unknown> | undefined {
  if (text === undefined || text === "") return undefined;
  try {
    const parsed: unknown = JSON.parse(text);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Converts filters to the AWS form. */
export function toAwsFilters(
  filters: readonly SecretFilter[],
): { Key: SecretFilterKey; Values: string[] }[] {
  return filters.map((f) => ({ Key: f.key, Values: [...f.values] }));
}

/** Whether an AWS `NextToken` means "more pages" (`null`, absent and `""` end the list). */
export function hasMore(token: string | undefined | null): token is string {
  return token !== undefined && token !== null && token !== "";
}
