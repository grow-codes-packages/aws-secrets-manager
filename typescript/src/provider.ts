// Service-owned. SecretsProvider (SPEC §3) on AWS Secrets Manager (API.md §3).
//
// Names are flat AWS secret names that may contain "/": `path` + "/" + `name` when a path is
// given. `version` is the AWS VersionId. A secret scheduled for deletion counts as missing.

import type { AwsSecretsManagerClient } from "./client.js";
import {
  ErrorCode,
  NotFoundError,
  ValidationError,
  errorForCode,
  isAwsSecretsManagerError,
  throwIfAborted,
} from "./core/index.js";
import { AWS_ERROR_CODES } from "./errors-map.js";
import { BATCH_GET_MAX_IDS, type SecretDescription, encodeBytes } from "./models.js";
import {
  BaseSecretsProvider,
  type DeleteOptions,
  type GetOptions,
  type SecretMetadata,
  type SecretValue,
  type SetOptions,
  type SignalOptions,
} from "./secrets/index.js";

/** Options of {@link AwsSecretsManagerSecretsProvider} (`client.secrets(options)`). */
export interface AwsSecretsManagerSecretsOptions {
  /** Recovery window of `delete()` in days (default `config.recoveryWindowDays`, i.e. 30). */
  recoveryWindowDays?: number;
}

/** Batch error codes that mean "missing" for `getMany` (deleted counts as missing). */
const MISSING_BATCH_CODES: ReadonlySet<string> = new Set([
  "ResourceNotFoundException",
  "InvalidRequestException",
]);

function trimSlashes(path: string): string {
  return path.replace(/^\/+|\/+$/g, "");
}

/** `path/name` when a path is given, otherwise `name`. */
export function fullName(name: string, path: string | undefined): string {
  const p = path === undefined ? "" : trimSlashes(path);
  return p === "" ? name : `${p}/${name}`;
}

function signalOnly(options: SignalOptions): SignalOptions {
  return options.signal === undefined ? {} : { signal: options.signal };
}

function isMissing(err: unknown): boolean {
  return (
    isAwsSecretsManagerError(err, ErrorCode.NotFound) ||
    // InvalidRequestException: the secret is scheduled for deletion.
    (isAwsSecretsManagerError(err, ErrorCode.Conflict) &&
      err.message.includes("InvalidRequestException"))
  );
}

/** Converts a description into SPEC metadata. */
export function toMetadata(d: SecretDescription): SecretMetadata {
  const current = Object.entries(d.versionIdsToStages).find(([, stages]) =>
    stages.includes("AWSCURRENT"),
  )?.[0];
  const slash = d.name.lastIndexOf("/");
  const extra: Record<string, string> = { arn: d.arn, rotationEnabled: String(d.rotationEnabled) };
  if (d.description !== undefined) extra.description = d.description;
  if (d.kmsKeyId !== undefined) extra.kmsKeyId = d.kmsKeyId;
  if (d.nextRotationDate !== undefined) extra.nextRotationDate = d.nextRotationDate.toISOString();
  if (d.deletedDate !== undefined) extra.deletedDate = d.deletedDate.toISOString();
  if (d.primaryRegion !== undefined) extra.primaryRegion = d.primaryRegion;
  return {
    name: d.name,
    ...(slash > 0 ? { path: d.name.slice(0, slash) } : {}),
    ...(current === undefined ? {} : { version: current }),
    ...(d.createdDate === undefined ? {} : { createdAt: d.createdDate }),
    ...(d.lastChangedDate === undefined ? {} : { updatedAt: d.lastChangedDate }),
    tags: { ...d.tags },
    versions: Object.keys(d.versionIdsToStages).length,
    extra,
  };
}

/**
 * {@link SecretsProvider} over AWS Secrets Manager. Capabilities: `write`, `versions`, `delete`.
 *
 * - `get(name, {version})` reads `VersionId = version` (stage labels: use
 *   `client.getSecretValue`).
 * - `set` stores text as `SecretString` and other bytes as `SecretBinary`; it creates the secret
 *   when missing (with `description`/`tags`) and returns the new VersionId. `cas` is not
 *   supported (`ValidationError`).
 * - `delete` schedules deletion with the recovery window (default 30 days); `permanent: true`
 *   deletes immediately. A name scheduled for deletion cannot be written again until it is
 *   restored or purged (`ConflictError`).
 * - `list(prefix)` matches names by string prefix (recursive); `getAll(path)` returns the
 *   secrets directly under `path` (non-recursive).
 */
export class AwsSecretsManagerSecretsProvider extends BaseSecretsProvider {
  /** Capabilities declared to the conformance runner. */
  static readonly capabilities = ["write", "versions", "delete"] as const;

  readonly #client: AwsSecretsManagerClient;
  readonly #recoveryWindowDays: number;
  readonly #onClose: (() => void) | undefined;

  constructor(
    client: AwsSecretsManagerClient,
    options: AwsSecretsManagerSecretsOptions = {},
    onClose?: () => void,
  ) {
    super();
    this.#client = client;
    const days = options.recoveryWindowDays ?? client.config.recoveryWindowDays;
    if (!Number.isInteger(days) || days < 7 || days > 30) {
      throw new ValidationError("secrets: recoveryWindowDays must be an integer from 7 to 30");
    }
    this.#recoveryWindowDays = days;
    this.#onClose = onClose;
  }

  /** The client this provider uses. */
  get client(): AwsSecretsManagerClient {
    return this.#client;
  }

  protected async fetchSecret(name: string, options: GetOptions): Promise<SecretValue | null> {
    try {
      const out = await this.#client.getSecretValue(fullName(name, options.path), {
        ...signalOnly(options),
        ...(options.version === undefined ? {} : { versionId: options.version }),
      });
      return out.value;
    } catch (err) {
      if (isMissing(err)) return null;
      throw err;
    }
  }

  protected async listSecrets(
    prefixOrPath: string | undefined,
    options: SignalOptions,
  ): Promise<SecretMetadata[]> {
    const prefix = prefixOrPath ?? "";
    return (await this.#listDescriptions(prefix, options)).map(toMetadata);
  }

  async #listDescriptions(prefix: string, options: SignalOptions): Promise<SecretDescription[]> {
    const all = await this.#client
      .listSecrets({
        ...signalOnly(options),
        ...(prefix === "" ? {} : { filters: [{ key: "name", values: [prefix] }] }),
      })
      .toArray();
    // AWS's name filter also matches word prefixes inside names: re-filter by string prefix.
    return all.filter((d) => d.name.startsWith(prefix) && d.deletedDate === undefined);
  }

  /** Every secret directly under `path` (non-recursive), keyed by full name. */
  override async getAll(
    path?: string,
    options: SignalOptions = {},
  ): Promise<Map<string, SecretValue>> {
    throwIfAborted(options.signal, "secrets.getAll");
    const base = path === undefined ? "" : trimSlashes(path);
    const prefix = base === "" ? "" : `${base}/`;
    const names = (await this.#listDescriptions(prefix, options))
      .map((d) => d.name)
      .filter((n) => !n.slice(prefix.length).includes("/"))
      .sort();
    return this.getMany(names, options);
  }

  /**
   * Present secrets in request order (`BatchGetSecretValue` in chunks of 20; per-name reads when
   * a `version` is requested).
   */
  override async getMany(
    names: readonly string[],
    options: GetOptions = {},
  ): Promise<Map<string, SecretValue>> {
    if (options.version !== undefined) return super.getMany(names, options);
    throwIfAborted(options.signal, "secrets.getMany");
    const unique = [...new Set(names)];
    const byFull = new Map<string, string>();
    for (const n of unique) byFull.set(fullName(n, options.path), n);
    const found = new Map<string, SecretValue>();
    const ids = [...byFull.keys()];
    for (let i = 0; i < ids.length; i += BATCH_GET_MAX_IDS) {
      const chunk = ids.slice(i, i + BATCH_GET_MAX_IDS);
      const result = await this.#client.batchGetSecretValue(chunk, signalOnly(options));
      for (const e of result.errors) {
        if (e.errorCode !== undefined && MISSING_BATCH_CODES.has(e.errorCode)) continue;
        const code =
          (e.errorCode === undefined ? undefined : AWS_ERROR_CODES[e.errorCode]) ??
          ErrorCode.Unavailable;
        throw errorForCode(code, `secrets.getMany ${e.secretId ?? ""}: ${e.errorCode ?? "error"}`);
      }
      for (const v of result.secretValues) {
        const requested = byFull.get(v.name) ?? byFull.get(v.arn);
        if (requested !== undefined) found.set(requested, v.value);
      }
    }
    const ordered = new Map<string, SecretValue>();
    for (const n of unique) {
      const value = found.get(n);
      if (value !== undefined) ordered.set(n, value);
    }
    return ordered;
  }

  protected async putSecret(name: string, value: Uint8Array, options: SetOptions): Promise<string> {
    if (options.cas !== undefined) {
      throw new ValidationError(
        `secrets.set ${name}: AWS Secrets Manager has no compare-and-set (cas)`,
      );
    }
    const id = fullName(name, options.path);
    const encoded = encodeBytes(value);
    const input = "SecretString" in encoded ? encoded.SecretString : encoded.SecretBinary;
    const call = signalOnly(options);
    const putExisting = async (): Promise<string> => {
      const out = await this.#client.putSecretValue(id, input, call);
      if (options.tags !== undefined && Object.keys(options.tags).length > 0) {
        await this.#client.tagResource(id, options.tags, call);
      }
      if (options.description !== undefined) {
        await this.#client.updateSecret(id, { ...call, description: options.description });
      }
      return out.versionId;
    };
    try {
      return await putExisting();
    } catch (err) {
      if (!isAwsSecretsManagerError(err, ErrorCode.NotFound)) throw err;
    }
    try {
      const created = await this.#client.createSecret(id, input, {
        ...call,
        ...(options.description === undefined ? {} : { description: options.description }),
        ...(options.tags === undefined ? {} : { tags: options.tags }),
      });
      return created.versionId ?? "";
    } catch (err) {
      // Lost a create race: the secret exists now, write the value as a new version.
      if (
        isAwsSecretsManagerError(err, ErrorCode.Conflict) &&
        err.message.includes("ResourceExistsException")
      ) {
        return await putExisting();
      }
      throw err;
    }
  }

  protected async removeSecret(name: string, options: DeleteOptions): Promise<void> {
    if (options.versions !== undefined) {
      throw new ValidationError(
        `secrets.delete ${name}: AWS Secrets Manager cannot delete single versions; use updateSecretVersionStage`,
      );
    }
    const id = fullName(name, options.path);
    const call = signalOnly(options);
    // Required: a forced delete of a missing secret succeeds on AWS.
    const meta = await this.#describe(id, call);
    if (meta === null) throw new NotFoundError(`secrets.delete ${id}: not found`);
    await this.#client.deleteSecret(
      id,
      options.permanent === true
        ? { ...call, forceDeleteWithoutRecovery: true }
        : { ...call, recoveryWindowDays: this.#recoveryWindowDays },
    );
  }

  protected async fetchMetadata(name: string, options: GetOptions): Promise<SecretMetadata | null> {
    const d = await this.#describe(fullName(name, options.path), signalOnly(options));
    return d === null ? null : toMetadata(d);
  }

  /** DescribeSecret; `null` when missing or scheduled for deletion. */
  async #describe(id: string, options: SignalOptions): Promise<SecretDescription | null> {
    try {
      const d = await this.#client.describeSecret(id, options);
      return d.deletedDate === undefined ? d : null;
    } catch (err) {
      if (isMissing(err)) return null;
      throw err;
    }
  }

  /** Stops the watchers of this provider. Idempotent. */
  override async close(): Promise<void> {
    await super.close();
    this.#onClose?.();
  }
}
