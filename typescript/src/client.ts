// Service-owned: the AWS Secrets Manager client, built on the official AWS SDK v3
// (`@aws-sdk/client-secrets-manager`, SPEC §2.3 "Cloud SDK services").

import {
  BatchGetSecretValueCommand,
  type BatchGetSecretValueCommandInput,
  CancelRotateSecretCommand,
  CreateSecretCommand,
  type CreateSecretCommandInput,
  DeleteResourcePolicyCommand,
  DeleteSecretCommand,
  type DeleteSecretCommandInput,
  DescribeSecretCommand,
  GetRandomPasswordCommand,
  type GetRandomPasswordCommandInput,
  GetResourcePolicyCommand,
  GetSecretValueCommand,
  ListSecretVersionIdsCommand,
  ListSecretsCommand,
  PutResourcePolicyCommand,
  PutSecretValueCommand,
  RestoreSecretCommand,
  RotateSecretCommand,
  type RotateSecretCommandInput,
  SecretsManagerClient,
  type SecretsManagerClientConfig,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateSecretCommand,
  type UpdateSecretCommandInput,
  UpdateSecretVersionStageCommand,
  ValidateResourcePolicyCommand,
} from "@aws-sdk/client-secrets-manager";
import { fromIni, fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@smithy/types";
import type { Dispatcher } from "undici";
import { AwsSecretsManagerConfig, type AwsSecretsManagerConfigOptions } from "./config.js";
import {
  type AwsSecretsManagerError,
  CancelledError,
  ErrorCode,
  type HealthStatus,
  Secret,
  TimeoutError,
  UnsupportedError,
  ValidationError,
  healthStatus,
  safeCall,
  throwIfAborted,
} from "./core/index.js";
import { mapAwsError } from "./errors-map.js";
import { GrowHttpHandler } from "./http-handler.js";
import {
  type AwsSecretValue,
  BATCH_GET_MAX_IDS,
  type BatchGetError,
  type BatchGetResult,
  type CallOptions,
  type DeleteSecretResult,
  type PutSecretValueResult,
  type ReplicaRegion,
  type ResourcePolicyResult,
  type RotationRules,
  type SecretDescription,
  type SecretFilter,
  type SecretRef,
  type SecretVersion,
  type SecretWriteResult,
  type ValidateResourcePolicyResult,
  type VersionSelector,
  encodeValue,
  hasMore,
  parsePolicy,
  toAwsFilters,
  toAwsTags,
  toBatchError,
  toDescription,
  toPolicyError,
  toSecretValue,
  toVersion,
} from "./models.js";
import { Paginator } from "./paginator.js";
import { AwsSecretCache, type AwsSecretCacheOptions } from "./secret-cache.js";
import {
  AwsSecretsManagerSecretsProvider,
  type AwsSecretsManagerSecretsOptions,
} from "./provider.js";
import type { SecretInput } from "./secrets/index.js";

export type { CallOptions } from "./models.js";

/** Test seams. Not part of the stable API. */
export interface ClientInternals {
  /** Replaces the undici dispatcher built from the TLS/proxy settings (e.g. `MockAgent`). */
  dispatcher?: Dispatcher;
}

/** Options of {@link AwsSecretsManagerClient.getSecretValue} and {@link AwsSecretsManagerClient.getJsonField}. */
export interface GetSecretValueOptions extends CallOptions, VersionSelector {}

/** Options of {@link AwsSecretsManagerClient.batchGetSecretValue}. */
export interface BatchGetOptions extends CallOptions {
  /** Page size for the filter form (1–20). */
  maxResults?: number;
}

/** Options of {@link AwsSecretsManagerClient.listSecrets}. */
export interface ListSecretsOptions extends CallOptions {
  filters?: readonly SecretFilter[];
  /** Include secrets scheduled for deletion (default false). */
  includePlannedDeletion?: boolean;
  /** Sort by creation date. */
  sortOrder?: "asc" | "desc";
  /** Page size (1–100). */
  maxResults?: number;
}

/** Options of {@link AwsSecretsManagerClient.listSecretVersionIds}. */
export interface ListSecretVersionIdsOptions extends CallOptions {
  /** Include versions without a stage label (deprecated versions). */
  includeDeprecated?: boolean;
  /** Page size (1–100). */
  maxResults?: number;
}

/** Options of {@link AwsSecretsManagerClient.createSecret}. */
export interface CreateSecretOptions extends CallOptions {
  description?: string;
  /** KMS key id/ARN/alias (default `aws/secretsmanager`). */
  kmsKeyId?: string;
  tags?: Readonly<Record<string, string>>;
  /** Idempotency token (32–64 chars, becomes the version id). The SDK fills one when unset. */
  clientRequestToken?: string;
  addReplicaRegions?: readonly ReplicaRegion[];
  forceOverwriteReplicaSecret?: boolean;
}

/** Options of {@link AwsSecretsManagerClient.putSecretValue}. */
export interface PutSecretValueOptions extends CallOptions {
  /** Stage labels for the new version (default `["AWSCURRENT"]`). */
  versionStages?: readonly string[];
  clientRequestToken?: string;
}

/** Options of {@link AwsSecretsManagerClient.updateSecret}. */
export interface UpdateSecretOptions extends CallOptions {
  /** New value (creates a new `AWSCURRENT` version). */
  value?: SecretInput;
  description?: string;
  kmsKeyId?: string;
  clientRequestToken?: string;
}

/** Options of {@link AwsSecretsManagerClient.updateSecretVersionStage}. */
export interface UpdateSecretVersionStageOptions extends CallOptions {
  /** Version that receives the label. */
  moveToVersionId?: string;
  /** Version that loses the label (required when moving `AWSCURRENT`). */
  removeFromVersionId?: string;
}

/** Options of {@link AwsSecretsManagerClient.deleteSecret}. */
export interface DeleteSecretOptions extends CallOptions {
  /** Days before the secret is purged (7–30; AWS default 30). */
  recoveryWindowDays?: number;
  /** Delete immediately without recovery. Mutually exclusive with `recoveryWindowDays`. */
  forceDeleteWithoutRecovery?: boolean;
}

/** Options of {@link AwsSecretsManagerClient.putResourcePolicy}. */
export interface PutResourcePolicyOptions extends CallOptions {
  /** Reject policies that grant public access (AWS default true). */
  blockPublicPolicy?: boolean;
}

/** Options of {@link AwsSecretsManagerClient.validateResourcePolicy}. */
export interface ValidateResourcePolicyOptions extends CallOptions {
  /** Secret the policy would be attached to. */
  secretId?: string;
}

/** Options of {@link AwsSecretsManagerClient.rotateSecret}. */
export interface RotateSecretOptions extends CallOptions {
  /** Rotation Lambda ARN (omit for managed rotation or to keep the current function). */
  lambdaArn?: string;
  rules?: RotationRules;
  /** Rotate now (AWS default true). */
  rotateImmediately?: boolean;
  clientRequestToken?: string;
}

/** Options of {@link AwsSecretsManagerClient.getRandomPassword}. */
export interface RandomPasswordOptions extends CallOptions {
  /** Length 1–4096 (default 32). */
  length?: number;
  /** Characters that must not appear. */
  excludeCharacters?: string;
  excludeNumbers?: boolean;
  excludePunctuation?: boolean;
  excludeUppercase?: boolean;
  excludeLowercase?: boolean;
  includeSpace?: boolean;
  /** Include at least one character of every included type (AWS default true). */
  requireEachIncludedType?: boolean;
}

/** Operations Moto 5.2.4 does not implement (non-JSON HTTP 500 → `UnsupportedError`). */
const EMULATOR_GAPS: ReadonlySet<string> = new Set(["validateResourcePolicy"]);

/** Upper bound of the health probe timeout. */
const HEALTH_TIMEOUT_MS = 5_000;

/** Structural type of an AWS SDK command whose output is `Out`. */
type CommandLike<Out> = {
  resolveMiddleware: (...args: never[]) => (args: never) => Promise<{ output: Out }>;
};

type SendOptions = CallOptions & { requestTimeout?: number; sdk?: SecretsManagerClient };

/**
 * Client for AWS Secrets Manager on the official AWS SDK v3. Builds a `SecretsManagerClient` from
 * the Grow config (region, credentials, endpoint, timeouts, retries, TLS, proxy, User-Agent,
 * hooks) or wraps one the caller passes (`sdkClient`).
 */
export class AwsSecretsManagerClient {
  /** The immutable configuration. */
  readonly config: AwsSecretsManagerConfig;
  readonly #sdk: SecretsManagerClient;
  readonly #ownsSdk: boolean;
  readonly #handler: GrowHttpHandler | undefined;
  readonly #sdkConfig: SecretsManagerClientConfig | undefined;
  #healthSdk: SecretsManagerClient | undefined;
  readonly #providers = new Set<AwsSecretsManagerSecretsProvider>();
  #closed = false;

  /** Accepts a {@link AwsSecretsManagerConfig} or plain options. */
  constructor(config: AwsSecretsManagerConfigOptions = {}, internals: ClientInternals = {}) {
    const cfg = AwsSecretsManagerConfig.from(config);
    this.config = cfg;
    if (cfg.sdkClient !== undefined) {
      this.#sdk = cfg.sdkClient;
      this.#ownsSdk = false;
      return;
    }
    const handler = new GrowHttpHandler({
      config: cfg,
      ...(internals.dispatcher === undefined ? {} : { dispatcher: internals.dispatcher }),
    });
    this.#handler = handler;
    const credentials = buildCredentials(cfg, handler);
    this.#sdkConfig = {
      maxAttempts: cfg.retry.maxRetries + 1,
      retryMode: "standard",
      requestHandler: handler,
      ...(cfg.region === undefined ? {} : { region: cfg.region }),
      ...(cfg.endpoint === undefined ? {} : { endpoint: cfg.endpoint }),
      ...(cfg.profile === undefined ? {} : { profile: cfg.profile }),
      ...(credentials === undefined ? {} : { credentials }),
    };
    this.#sdk = new SecretsManagerClient(this.#sdkConfig);
    this.#ownsSdk = true;
  }

  /** Builds a client from `GROW_AWS_SECRETS_MANAGER_*` and the standard AWS environment variables. */
  static fromEnv(overrides: AwsSecretsManagerConfigOptions = {}): AwsSecretsManagerClient {
    return new AwsSecretsManagerClient(AwsSecretsManagerConfig.fromEnv(overrides));
  }

  /** Wraps an existing AWS SDK client; `close()` leaves it open. */
  static withSdkClient(
    sdkClient: SecretsManagerClient,
    options: Omit<AwsSecretsManagerConfigOptions, "sdkClient"> = {},
  ): AwsSecretsManagerClient {
    return new AwsSecretsManagerClient({ ...options, sdkClient });
  }

  /** The underlying AWS SDK client (escape hatch for operations not wrapped here). */
  get sdk(): SecretsManagerClient {
    return this.#sdk;
  }

  /** Whether {@link close} was called. */
  get closed(): boolean {
    return this.#closed;
  }

  // ---------------------------------------------------------------------------------------
  // core

  /**
   * Liveness: a signed `ListSecrets {MaxResults: 1}` with a short timeout and no retries.
   * `ok` when AWS answers (also when the credentials are rejected: `details.auth = "failed"`),
   * `degraded` when throttled, `unhealthy` on HTTP 5xx, `unreachable` on network errors.
   * Throws only `CancelledError` (also on a closed client) and `ConfigError`.
   */
  async health(options: CallOptions = {}): Promise<HealthStatus> {
    try {
      await this.#send("health", new ListSecretsCommand({ MaxResults: 1 }), {
        ...options,
        requestTimeout: Math.min(this.config.requestTimeoutMs, HEALTH_TIMEOUT_MS),
        sdk: this.#healthClient(),
      });
      return healthStatus("ok", {}, true);
    } catch (err) {
      const e = err as AwsSecretsManagerError;
      switch (e.code) {
        case ErrorCode.Cancelled:
        case ErrorCode.Config:
          throw e;
        case ErrorCode.RateLimited:
          return healthStatus("degraded", { code: e.code }, true);
        case ErrorCode.Authentication:
        case ErrorCode.PermissionDenied:
          return healthStatus("ok", { auth: "failed", code: e.code }, true);
        default:
          if (e.httpStatus === undefined) {
            return healthStatus("unreachable", { error: e.code }, false);
          }
          if (e.httpStatus >= 500) {
            return healthStatus("unhealthy", { httpStatus: e.httpStatus, error: e.code }, false);
          }
          return healthStatus("ok", { httpStatus: e.httpStatus, code: e.code }, true);
      }
    }
  }

  /**
   * Authenticated round trip (`ListSecrets {MaxResults: 1}`); returns the latency in ms.
   * `AuthenticationError` for unknown keys or bad signatures, `PermissionDeniedError` when the
   * principal may not call `secretsmanager:ListSecrets`.
   */
  async ping(options: CallOptions = {}): Promise<number> {
    const start = performance.now();
    await this.#send("ping", new ListSecretsCommand({ MaxResults: 1 }), options);
    return performance.now() - start;
  }

  /**
   * Always throws {@link UnsupportedError}: AWS Secrets Manager exposes no server version (the API
   * contract date is the constant `API_VERSION`).
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async serverVersion(options: CallOptions = {}): Promise<string> {
    throwIfAborted(options.signal, "serverVersion");
    throw new UnsupportedError(
      "serverVersion: AWS Secrets Manager does not expose a server version",
    );
  }

  /**
   * Stops every watcher of the providers created by {@link secrets} and destroys the SDK client
   * this instance built (never a caller-supplied one). Idempotent.
   */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await Promise.all([...this.#providers].map((p) => p.close()));
    this.#providers.clear();
    if (this.#ownsSdk) {
      this.#sdk.destroy();
      this.#healthSdk?.destroy();
    }
    this.#handler?.destroy();
  }

  // ---------------------------------------------------------------------------------------
  // category interface

  /**
   * The {@link SecretsProvider} view (SPEC §3) of this client. `close()` of the client stops its
   * watchers.
   */
  secrets(options: AwsSecretsManagerSecretsOptions = {}): AwsSecretsManagerSecretsProvider {
    const provider: AwsSecretsManagerSecretsProvider = new AwsSecretsManagerSecretsProvider(
      this,
      options,
      () => this.#providers.delete(provider),
    );
    this.#providers.add(provider);
    return provider;
  }

  /** A version-stage aware cache with the AWS caching-client semantics (TTL 1 h, 1 024 entries). */
  secretCache(options: AwsSecretCacheOptions = {}): AwsSecretCache {
    return new AwsSecretCache(this, options);
  }

  // ---------------------------------------------------------------------------------------
  // read

  /**
   * Reads a secret value (`GetSecretValue`), by default the `AWSCURRENT` version. `secretId` is a
   * name or ARN. `NotFoundError` when the secret, version or stage does not exist; `ConflictError`
   * when the secret is scheduled for deletion.
   */
  async getSecretValue(
    secretId: string,
    options: GetSecretValueOptions = {},
  ): Promise<AwsSecretValue> {
    requireId("getSecretValue", secretId);
    const out = await this.#send(
      `getSecretValue ${secretId}`,
      new GetSecretValueCommand({
        SecretId: secretId,
        ...(options.versionId === undefined ? {} : { VersionId: options.versionId }),
        ...(options.versionStage === undefined ? {} : { VersionStage: options.versionStage }),
      }),
      options,
    );
    return toSecretValue(out);
  }

  /**
   * Reads many secrets at once (`BatchGetSecretValue`). With a list of ids, lists longer than 20
   * are split and the values come back in request order; with `{ filters }` every page is read.
   * Per-secret failures are returned in `errors` (the call itself succeeds).
   */
  async batchGetSecretValue(
    selector: readonly string[] | { filters: readonly SecretFilter[] },
    options: BatchGetOptions = {},
  ): Promise<BatchGetResult> {
    const secretValues: AwsSecretValue[] = [];
    const errors: BatchGetError[] = [];
    if (Array.isArray(selector)) {
      const ids = selector as readonly string[];
      for (let i = 0; i < ids.length; i += BATCH_GET_MAX_IDS) {
        const chunk = ids.slice(i, i + BATCH_GET_MAX_IDS);
        const pageValues: AwsSecretValue[] = [];
        let token: string | undefined;
        do {
          const out = await this.#send(
            "batchGetSecretValue",
            new BatchGetSecretValueCommand({
              SecretIdList: [...chunk],
              ...(token === undefined ? {} : { NextToken: token }),
            }),
            options,
          );
          pageValues.push(...(out.SecretValues ?? []).map(toSecretValue));
          errors.push(...(out.Errors ?? []).map(toBatchError));
          token = hasMore(out.NextToken) ? out.NextToken : undefined;
        } while (token !== undefined);
        secretValues.push(...orderByIds(pageValues, chunk));
      }
      return { secretValues, errors };
    }
    const filters = (selector as { filters?: readonly SecretFilter[] }).filters;
    if (filters === undefined || filters.length === 0) {
      throw new ValidationError("batchGetSecretValue: give secret ids or at least one filter");
    }
    let token: string | undefined;
    do {
      const input: BatchGetSecretValueCommandInput = {
        Filters: toAwsFilters(filters),
        ...(options.maxResults === undefined ? {} : { MaxResults: options.maxResults }),
        ...(token === undefined ? {} : { NextToken: token }),
      };
      const out = await this.#send(
        "batchGetSecretValue",
        new BatchGetSecretValueCommand(input),
        options,
      );
      secretValues.push(...(out.SecretValues ?? []).map(toSecretValue));
      errors.push(...(out.Errors ?? []).map(toBatchError));
      token = hasMore(out.NextToken) ? out.NextToken : undefined;
    } while (token !== undefined);
    return { secretValues, errors };
  }

  /** Metadata of a secret (`DescribeSecret`), never the value. */
  async describeSecret(secretId: string, options: CallOptions = {}): Promise<SecretDescription> {
    requireId("describeSecret", secretId);
    const out = await this.#send(
      `describeSecret ${secretId}`,
      new DescribeSecretCommand({ SecretId: secretId }),
      options,
    );
    return toDescription(out);
  }

  /**
   * Lists secrets (`ListSecrets`) lazily across all pages: `for await (const s of
   * client.listSecrets())` or `await client.listSecrets().toArray()`.
   */
  listSecrets(options: ListSecretsOptions = {}): Paginator<SecretDescription> {
    return new Paginator(async (token) => {
      const out = await this.#send(
        "listSecrets",
        new ListSecretsCommand({
          ...(options.filters === undefined || options.filters.length === 0
            ? {}
            : { Filters: toAwsFilters(options.filters) }),
          ...(options.includePlannedDeletion === undefined
            ? {}
            : { IncludePlannedDeletion: options.includePlannedDeletion }),
          ...(options.sortOrder === undefined ? {} : { SortOrder: options.sortOrder }),
          ...(options.maxResults === undefined ? {} : { MaxResults: options.maxResults }),
          ...(token === undefined ? {} : { NextToken: token }),
        }),
        options,
      );
      return {
        items: (out.SecretList ?? []).map(toDescription),
        nextToken: hasMore(out.NextToken) ? out.NextToken : undefined,
      };
    });
  }

  /** Lists the versions of a secret (`ListSecretVersionIds`) lazily across all pages. */
  listSecretVersionIds(
    secretId: string,
    options: ListSecretVersionIdsOptions = {},
  ): Paginator<SecretVersion> {
    requireId("listSecretVersionIds", secretId);
    return new Paginator(async (token) => {
      const out = await this.#send(
        `listSecretVersionIds ${secretId}`,
        new ListSecretVersionIdsCommand({
          SecretId: secretId,
          ...(options.includeDeprecated === undefined
            ? {}
            : { IncludeDeprecated: options.includeDeprecated }),
          ...(options.maxResults === undefined ? {} : { MaxResults: options.maxResults }),
          ...(token === undefined ? {} : { NextToken: token }),
        }),
        options,
      );
      return {
        items: (out.Versions ?? []).map(toVersion),
        nextToken: hasMore(out.NextToken) ? out.NextToken : undefined,
      };
    });
  }

  // ---------------------------------------------------------------------------------------
  // write

  /**
   * Creates a secret (`CreateSecret`). `value`: string → `SecretString`, bytes → `SecretBinary`,
   * object → JSON `SecretString`, `undefined`/`null` → a secret without a version.
   * `ConflictError` when the name exists (or is scheduled for deletion).
   */
  async createSecret(
    name: string,
    value: SecretInput | null | undefined,
    options: CreateSecretOptions = {},
  ): Promise<SecretWriteResult> {
    requireId("createSecret", name);
    const input: CreateSecretCommandInput = {
      Name: name,
      ...(value === undefined || value === null ? {} : encodeValue(value)),
      ...(options.description === undefined ? {} : { Description: options.description }),
      ...(options.kmsKeyId === undefined ? {} : { KmsKeyId: options.kmsKeyId }),
      ...(options.tags === undefined ? {} : { Tags: toAwsTags(options.tags) }),
      ...(options.clientRequestToken === undefined
        ? {}
        : { ClientRequestToken: options.clientRequestToken }),
      ...(options.addReplicaRegions === undefined
        ? {}
        : {
            AddReplicaRegions: options.addReplicaRegions.map((r) => ({
              Region: r.region,
              ...(r.kmsKeyId === undefined ? {} : { KmsKeyId: r.kmsKeyId }),
            })),
          }),
      ...(options.forceOverwriteReplicaSecret === undefined
        ? {}
        : { ForceOverwriteReplicaSecret: options.forceOverwriteReplicaSecret }),
    };
    const out = await this.#send(`createSecret ${name}`, new CreateSecretCommand(input), options);
    return writeResult(out);
  }

  /**
   * Stores a new version (`PutSecretValue`). By default it becomes `AWSCURRENT` (the old one
   * becomes `AWSPREVIOUS`); with custom `versionStages` only those labels are attached.
   */
  async putSecretValue(
    secretId: string,
    value: SecretInput,
    options: PutSecretValueOptions = {},
  ): Promise<PutSecretValueResult> {
    requireId("putSecretValue", secretId);
    const out = await this.#send(
      `putSecretValue ${secretId}`,
      new PutSecretValueCommand({
        SecretId: secretId,
        ...encodeValue(value),
        ...(options.versionStages === undefined
          ? {}
          : { VersionStages: [...options.versionStages] }),
        ...(options.clientRequestToken === undefined
          ? {}
          : { ClientRequestToken: options.clientRequestToken }),
      }),
      options,
    );
    return {
      arn: out.ARN ?? "",
      name: out.Name ?? "",
      versionId: out.VersionId ?? "",
      versionStages: [...(out.VersionStages ?? [])],
    };
  }

  /**
   * Updates description, KMS key and/or value (`UpdateSecret`). A new version is created only
   * when `value` is given.
   */
  async updateSecret(
    secretId: string,
    options: UpdateSecretOptions = {},
  ): Promise<SecretWriteResult> {
    requireId("updateSecret", secretId);
    const input: UpdateSecretCommandInput = {
      SecretId: secretId,
      ...(options.value === undefined ? {} : encodeValue(options.value)),
      ...(options.description === undefined ? {} : { Description: options.description }),
      ...(options.kmsKeyId === undefined ? {} : { KmsKeyId: options.kmsKeyId }),
      ...(options.clientRequestToken === undefined
        ? {}
        : { ClientRequestToken: options.clientRequestToken }),
    };
    const out = await this.#send(
      `updateSecret ${secretId}`,
      new UpdateSecretCommand(input),
      options,
    );
    return writeResult(out);
  }

  /**
   * Moves a stage label between versions (`UpdateSecretVersionStage`). Moving `AWSCURRENT` needs
   * `removeFromVersionId` = the current version; the old current version gets `AWSPREVIOUS`.
   */
  async updateSecretVersionStage(
    secretId: string,
    versionStage: string,
    options: UpdateSecretVersionStageOptions = {},
  ): Promise<SecretRef> {
    requireId("updateSecretVersionStage", secretId);
    if (options.moveToVersionId === undefined && options.removeFromVersionId === undefined) {
      throw new ValidationError(
        "updateSecretVersionStage: give moveToVersionId and/or removeFromVersionId",
      );
    }
    const out = await this.#send(
      `updateSecretVersionStage ${secretId}`,
      new UpdateSecretVersionStageCommand({
        SecretId: secretId,
        VersionStage: versionStage,
        ...(options.moveToVersionId === undefined
          ? {}
          : { MoveToVersionId: options.moveToVersionId }),
        ...(options.removeFromVersionId === undefined
          ? {}
          : { RemoveFromVersionId: options.removeFromVersionId }),
      }),
      options,
    );
    return { arn: out.ARN ?? "", name: out.Name ?? "" };
  }

  /**
   * Schedules deletion (`DeleteSecret`) after `recoveryWindowDays` (AWS default 30) or deletes
   * immediately with `forceDeleteWithoutRecovery`. Note: AWS answers success for a forced delete
   * of a secret that does not exist.
   */
  async deleteSecret(
    secretId: string,
    options: DeleteSecretOptions = {},
  ): Promise<DeleteSecretResult> {
    requireId("deleteSecret", secretId);
    const { recoveryWindowDays: days, forceDeleteWithoutRecovery: force } = options;
    if (days !== undefined && force === true) {
      throw new ValidationError(
        "deleteSecret: recoveryWindowDays and forceDeleteWithoutRecovery are mutually exclusive",
      );
    }
    if (days !== undefined && !(Number.isInteger(days) && days >= 7 && days <= 30)) {
      throw new ValidationError("deleteSecret: recoveryWindowDays must be an integer from 7 to 30");
    }
    const input: DeleteSecretCommandInput = {
      SecretId: secretId,
      ...(days === undefined ? {} : { RecoveryWindowInDays: days }),
      ...(force === undefined ? {} : { ForceDeleteWithoutRecovery: force }),
    };
    const out = await this.#send(
      `deleteSecret ${secretId}`,
      new DeleteSecretCommand(input),
      options,
    );
    return {
      arn: out.ARN ?? "",
      name: out.Name ?? "",
      ...(out.DeletionDate === undefined ? {} : { deletionDate: out.DeletionDate }),
    };
  }

  /** Cancels a scheduled deletion (`RestoreSecret`). A no-op for a live secret. */
  async restoreSecret(secretId: string, options: CallOptions = {}): Promise<SecretRef> {
    requireId("restoreSecret", secretId);
    const out = await this.#send(
      `restoreSecret ${secretId}`,
      new RestoreSecretCommand({ SecretId: secretId }),
      options,
    );
    return { arn: out.ARN ?? "", name: out.Name ?? "" };
  }

  // ---------------------------------------------------------------------------------------
  // tags and resource policy

  /** Adds or replaces tags (`TagResource`). */
  async tagResource(
    secretId: string,
    tags: Readonly<Record<string, string>>,
    options: CallOptions = {},
  ): Promise<void> {
    requireId("tagResource", secretId);
    await this.#send(
      `tagResource ${secretId}`,
      new TagResourceCommand({ SecretId: secretId, Tags: toAwsTags(tags) }),
      options,
    );
  }

  /** Removes tags by key (`UntagResource`). */
  async untagResource(
    secretId: string,
    tagKeys: readonly string[],
    options: CallOptions = {},
  ): Promise<void> {
    requireId("untagResource", secretId);
    await this.#send(
      `untagResource ${secretId}`,
      new UntagResourceCommand({ SecretId: secretId, TagKeys: [...tagKeys] }),
      options,
    );
  }

  /** Attaches a resource policy (`PutResourcePolicy`); objects are JSON-encoded. */
  async putResourcePolicy(
    secretId: string,
    policy: string | object,
    options: PutResourcePolicyOptions = {},
  ): Promise<SecretRef> {
    requireId("putResourcePolicy", secretId);
    const out = await this.#send(
      `putResourcePolicy ${secretId}`,
      new PutResourcePolicyCommand({
        SecretId: secretId,
        ResourcePolicy: typeof policy === "string" ? policy : JSON.stringify(policy),
        ...(options.blockPublicPolicy === undefined
          ? {}
          : { BlockPublicPolicy: options.blockPublicPolicy }),
      }),
      options,
    );
    return { arn: out.ARN ?? "", name: out.Name ?? "" };
  }

  /** Reads the resource policy (`GetResourcePolicy`); `resourcePolicy` is absent when there is none. */
  async getResourcePolicy(
    secretId: string,
    options: CallOptions = {},
  ): Promise<ResourcePolicyResult> {
    requireId("getResourcePolicy", secretId);
    const out = await this.#send(
      `getResourcePolicy ${secretId}`,
      new GetResourcePolicyCommand({ SecretId: secretId }),
      options,
    );
    const text = out.ResourcePolicy ?? undefined;
    const policy = parsePolicy(text);
    return {
      arn: out.ARN ?? "",
      name: out.Name ?? "",
      ...(text === undefined ? {} : { resourcePolicy: text }),
      ...(policy === undefined ? {} : { policy }),
    };
  }

  /** Removes the resource policy (`DeleteResourcePolicy`). */
  async deleteResourcePolicy(secretId: string, options: CallOptions = {}): Promise<SecretRef> {
    requireId("deleteResourcePolicy", secretId);
    const out = await this.#send(
      `deleteResourcePolicy ${secretId}`,
      new DeleteResourcePolicyCommand({ SecretId: secretId }),
      options,
    );
    return { arn: out.ARN ?? "", name: out.Name ?? "" };
  }

  /**
   * Checks a policy with IAM Access Analyzer (`ValidateResourcePolicy`). Emulators that lack the
   * operation (Moto 5.2.4) raise `UnsupportedError`.
   */
  async validateResourcePolicy(
    policy: string | object,
    options: ValidateResourcePolicyOptions = {},
  ): Promise<ValidateResourcePolicyResult> {
    const out = await this.#send(
      "validateResourcePolicy",
      new ValidateResourcePolicyCommand({
        ResourcePolicy: typeof policy === "string" ? policy : JSON.stringify(policy),
        ...(options.secretId === undefined ? {} : { SecretId: options.secretId }),
      }),
      options,
    );
    return {
      policyValidationPassed: out.PolicyValidationPassed === true,
      validationErrors: (out.ValidationErrors ?? []).map(toPolicyError),
    };
  }

  // ---------------------------------------------------------------------------------------
  // rotation

  /**
   * Configures and/or starts rotation (`RotateSecret`). Without `lambdaArn` the secret's managed
   * or existing rotation function is used.
   */
  async rotateSecret(
    secretId: string,
    options: RotateSecretOptions = {},
  ): Promise<SecretWriteResult> {
    requireId("rotateSecret", secretId);
    const rules = options.rules;
    const input: RotateSecretCommandInput = {
      SecretId: secretId,
      ...(options.lambdaArn === undefined ? {} : { RotationLambdaARN: options.lambdaArn }),
      ...(rules === undefined
        ? {}
        : {
            RotationRules: {
              ...(rules.automaticallyAfterDays === undefined
                ? {}
                : { AutomaticallyAfterDays: rules.automaticallyAfterDays }),
              ...(rules.duration === undefined ? {} : { Duration: rules.duration }),
              ...(rules.scheduleExpression === undefined
                ? {}
                : { ScheduleExpression: rules.scheduleExpression }),
            },
          }),
      ...(options.rotateImmediately === undefined
        ? {}
        : { RotateImmediately: options.rotateImmediately }),
      ...(options.clientRequestToken === undefined
        ? {}
        : { ClientRequestToken: options.clientRequestToken }),
    };
    const out = await this.#send(
      `rotateSecret ${secretId}`,
      new RotateSecretCommand(input),
      options,
    );
    return writeResult(out);
  }

  /** Turns rotation off and cancels a rotation in progress (`CancelRotateSecret`). */
  async cancelRotateSecret(
    secretId: string,
    options: CallOptions = {},
  ): Promise<SecretWriteResult> {
    requireId("cancelRotateSecret", secretId);
    const out = await this.#send(
      `cancelRotateSecret ${secretId}`,
      new CancelRotateSecretCommand({ SecretId: secretId }),
      options,
    );
    return writeResult(out);
  }

  // ---------------------------------------------------------------------------------------
  // utilities

  /** Generates a random password (`GetRandomPassword`), returned as a redacting {@link Secret}. */
  async getRandomPassword(options: RandomPasswordOptions = {}): Promise<Secret> {
    const input: GetRandomPasswordCommandInput = {
      PasswordLength: options.length ?? 32,
      ...(options.excludeCharacters === undefined
        ? {}
        : { ExcludeCharacters: options.excludeCharacters }),
      ...(options.excludeNumbers === undefined ? {} : { ExcludeNumbers: options.excludeNumbers }),
      ...(options.excludePunctuation === undefined
        ? {}
        : { ExcludePunctuation: options.excludePunctuation }),
      ...(options.excludeUppercase === undefined
        ? {}
        : { ExcludeUppercase: options.excludeUppercase }),
      ...(options.excludeLowercase === undefined
        ? {}
        : { ExcludeLowercase: options.excludeLowercase }),
      ...(options.includeSpace === undefined ? {} : { IncludeSpace: options.includeSpace }),
      ...(options.requireEachIncludedType === undefined
        ? {}
        : { RequireEachIncludedType: options.requireEachIncludedType }),
    };
    const out = await this.#send("getRandomPassword", new GetRandomPasswordCommand(input), options);
    return new Secret(out.RandomPassword ?? "");
  }

  /**
   * Reads one field of a JSON secret: `GetSecretValue`, parse `SecretString` as a JSON object,
   * return `field` (an exact key first, otherwise a dot path such as `"db.host"`). `null` when
   * the field is absent; `ValidationError` when the value is binary or not a JSON object;
   * `NotFoundError` when the secret is missing.
   */
  async getJsonField(
    secretId: string,
    field: string,
    options: GetSecretValueOptions = {},
  ): Promise<unknown> {
    const secret = await this.getSecretValue(secretId, options);
    if (secret.binary) {
      throw new ValidationError(`getJsonField ${secretId}: the secret is binary, not JSON`);
    }
    let parsed: unknown;
    try {
      parsed = secret.value.json();
    } catch {
      throw new ValidationError(`getJsonField ${secretId}: the value is not valid JSON`);
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new ValidationError(`getJsonField ${secretId}: the value is not a JSON object`);
    }
    return jsonField(parsed as Record<string, unknown>, field);
  }

  // ---------------------------------------------------------------------------------------
  // internals

  /** Known credential values for redaction. @internal */
  knownSecrets(): string[] {
    return this.config.knownSecrets();
  }

  #healthClient(): SecretsManagerClient {
    if (this.#sdkConfig === undefined) return this.#sdk;
    this.#healthSdk ??= new SecretsManagerClient({ ...this.#sdkConfig, maxAttempts: 1 });
    return this.#healthSdk;
  }

  /** Sends a command with cancellation, the total timeout and error mapping. */
  async #send<Out>(
    operation: string,
    command: CommandLike<Out>,
    options: SendOptions = {},
  ): Promise<Out> {
    if (this.#closed) throw new CancelledError(`${operation}: client is closed`);
    const signal = options.signal;
    if (signal?.aborted === true) throw new CancelledError(`${operation}: cancelled`);
    const total = new AbortController();
    const timer = setTimeout(() => {
      total.abort();
    }, this.config.totalTimeoutMs);
    timer.unref();
    const abortSignal =
      signal === undefined ? total.signal : AbortSignal.any([signal, total.signal]);
    const sdk = options.sdk ?? this.#sdk;
    try {
      const send = sdk.send.bind(sdk) as (
        c: unknown,
        o: { abortSignal: AbortSignal; requestTimeout?: number },
      ) => Promise<Out>;
      return await send(command, {
        abortSignal,
        ...(options.requestTimeout === undefined ? {} : { requestTimeout: options.requestTimeout }),
      });
    } catch (err) {
      let mapped: AwsSecretsManagerError;
      if (isAborted(signal)) {
        mapped = new CancelledError(`${operation}: cancelled`, { cause: err });
      } else if (total.signal.aborted) {
        mapped = new TimeoutError(
          `${operation}: total timeout of ${String(this.config.totalTimeoutMs)} ms exceeded`,
          { cause: err },
        );
      } else {
        mapped = mapAwsError(err, operation, {
          knownSecrets: this.knownSecrets(),
          unsupportedOnHtml500: EMULATOR_GAPS.has(operation.split(" ")[0] ?? ""),
        });
      }
      if (mapped.httpStatus !== undefined) {
        safeCall(this.config.hooks?.onError, {
          method: "POST",
          url: this.config.url,
          error: mapped,
          attempt: attemptsOf(err),
          willRetry: false,
        });
      }
      throw mapped;
    } finally {
      clearTimeout(timer);
    }
  }
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function attemptsOf(err: unknown): number {
  const attempts = (err as { $metadata?: { attempts?: number } }).$metadata?.attempts;
  return typeof attempts === "number" && attempts > 0 ? attempts : 1;
}

function requireId(operation: string, id: string): void {
  if (typeof id !== "string" || id.trim() === "") {
    throw new ValidationError(`${operation}: secret id must not be empty`);
  }
}

function writeResult(out: {
  ARN?: string | undefined;
  Name?: string | undefined;
  VersionId?: string | undefined;
}): SecretWriteResult {
  return {
    arn: out.ARN ?? "",
    name: out.Name ?? "",
    ...(out.VersionId === undefined ? {} : { versionId: out.VersionId }),
  };
}

/** Orders batch results like the requested ids (by name or ARN). */
function orderByIds(values: AwsSecretValue[], ids: readonly string[]): AwsSecretValue[] {
  const rank = (v: AwsSecretValue): number => {
    const i = ids.findIndex(
      (id) => id === v.name || id === v.arn || (id.startsWith("arn:") && v.arn.startsWith(id)),
    );
    return i === -1 ? ids.length : i;
  };
  return [...values].sort((a, b) => rank(a) - rank(b));
}

/** Exact key first, then a dot path. */
export function jsonField(obj: Record<string, unknown>, field: string): unknown {
  if (Object.hasOwn(obj, field)) return obj[field] ?? null;
  let current: unknown = obj;
  for (const part of field.split(".")) {
    if (typeof current !== "object" || current === null || Array.isArray(current)) return null;
    if (!Object.hasOwn(current, part)) return null;
    current = (current as Record<string, unknown>)[part];
  }
  return current ?? null;
}

function buildCredentials(
  cfg: AwsSecretsManagerConfig,
  handler: GrowHttpHandler,
): AwsCredentialIdentity | AwsCredentialIdentityProvider | undefined {
  let base: AwsCredentialIdentity | AwsCredentialIdentityProvider | undefined;
  if (cfg.accessKeyId !== undefined && cfg.secretAccessKey !== undefined) {
    base = {
      accessKeyId: cfg.accessKeyId,
      secretAccessKey: cfg.secretAccessKey.reveal(),
      ...(cfg.sessionToken === undefined ? {} : { sessionToken: cfg.sessionToken.reveal() }),
    };
  } else if (cfg.credentials !== undefined) {
    base = cfg.credentials;
  } else if (cfg.profile !== undefined) {
    base = fromIni({ profile: cfg.profile });
  }
  if (cfg.roleArn === undefined) return base;
  return fromTemporaryCredentials({
    params: {
      RoleArn: cfg.roleArn,
      RoleSessionName: cfg.roleSessionName,
      ...(cfg.externalId === undefined ? {} : { ExternalId: cfg.externalId }),
      ...(cfg.roleDurationMs === undefined
        ? {}
        : { DurationSeconds: Math.floor(cfg.roleDurationMs / 1000) }),
    },
    ...(base === undefined ? {} : { masterCredentials: base }),
    clientConfig: {
      requestHandler: handler,
      ...(cfg.region === undefined ? {} : { region: cfg.region }),
    },
  });
}
