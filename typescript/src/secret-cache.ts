// Service-owned: a version-stage aware secret cache with the semantics of the AWS caching
// clients (`aws-secretsmanager-caching-*`, DECISIONS.md #3): entries per (secretId, versionStage),
// default TTL 1 h and 1 024 entries; on expiry `DescribeSecret` checks whether the stage moved
// to another version and `GetSecretValue` runs only when it did.

import { ValidationError } from "./core/index.js";
import type { SecretCacheOptions } from "./secrets/index.js";
import { AWSCURRENT, type AwsSecretValue, type CallOptions } from "./models.js";

/** The AWS caching-client defaults: TTL 1 h, 1 024 entries. Also usable with `SecretCache`. */
export const AWS_SECRET_CACHE_DEFAULTS: Readonly<
  Required<Pick<SecretCacheOptions, "ttlMs" | "maxEntries">>
> = Object.freeze({ ttlMs: 3_600_000, maxEntries: 1024 });

/** The client operations the cache needs. */
export interface SecretCacheSource {
  getSecretValue(
    secretId: string,
    options?: CallOptions & { versionStage?: string },
  ): Promise<AwsSecretValue>;
  describeSecret(
    secretId: string,
    options?: CallOptions,
  ): Promise<{ versionIdsToStages: Record<string, string[]> }>;
}

/** Options of {@link AwsSecretCache}. */
export interface AwsSecretCacheOptions {
  /** Refresh interval in ms (default 3 600 000 = 1 h). */
  ttlMs?: number;
  /** LRU capacity (default 1 024). */
  maxEntries?: number;
  /** Default stage label (default `AWSCURRENT`). */
  versionStage?: string;
  /** Clock in ms (default `Date.now`). */
  clock?: () => number;
  /** Called when a refresh fails and the cached value is served instead. */
  onRefreshError?: (error: unknown) => void;
}

/** Options of the cache reads. */
export interface CacheGetOptions extends CallOptions {
  /** Stage label (default: the cache's `versionStage`). */
  versionStage?: string;
}

/** Counters reported by {@link AwsSecretCache.stats}. */
export interface AwsSecretCacheStats {
  hits: number;
  misses: number;
  /** Expired entries checked with `DescribeSecret`. */
  refreshes: number;
  /** Refreshes that fetched a new version. */
  versionChanges: number;
  evictions: number;
  size: number;
}

interface Entry {
  secretId: string;
  value: AwsSecretValue;
  checkedAt: number;
  failures: number;
}

/** Initial delay before retrying a failed refresh (doubles per failure, capped at the TTL). */
const REFRESH_RETRY_MS = 1_000;

/**
 * Version-stage aware cache in front of an {@link AwsSecretsManagerClient}
 * (`client.secretCache()`). Reads are coalesced per (secretId, stage). A refresh that fails
 * keeps serving the cached value and retries with exponential backoff (AWS caching-client
 * behaviour); a first read that fails throws.
 */
export class AwsSecretCache {
  /** The AWS caching-client defaults (TTL 1 h, 1 024 entries). */
  static awsDefaults(): { ttlMs: number; maxEntries: number } {
    return { ...AWS_SECRET_CACHE_DEFAULTS };
  }

  readonly #source: SecretCacheSource;
  readonly #ttl: number;
  readonly #max: number;
  readonly #stage: string;
  readonly #clock: () => number;
  readonly #onRefreshError: ((error: unknown) => void) | undefined;
  readonly #entries = new Map<string, Entry>();
  readonly #inflight = new Map<string, Promise<AwsSecretValue>>();
  #hits = 0;
  #misses = 0;
  #refreshes = 0;
  #versionChanges = 0;
  #evictions = 0;

  constructor(source: SecretCacheSource, options: AwsSecretCacheOptions = {}) {
    this.#source = source;
    this.#ttl = options.ttlMs ?? AWS_SECRET_CACHE_DEFAULTS.ttlMs;
    this.#max = options.maxEntries ?? AWS_SECRET_CACHE_DEFAULTS.maxEntries;
    this.#stage = options.versionStage ?? AWSCURRENT;
    this.#clock = options.clock ?? Date.now;
    this.#onRefreshError = options.onRefreshError;
    if (!(this.#ttl > 0)) throw new ValidationError("AwsSecretCache: ttlMs must be > 0");
    if (!Number.isInteger(this.#max) || this.#max < 1) {
      throw new ValidationError("AwsSecretCache: maxEntries must be >= 1");
    }
    if (this.#stage.trim() === "") {
      throw new ValidationError("AwsSecretCache: versionStage must not be empty");
    }
  }

  /** The cached value of `secretId` at the stage (default `AWSCURRENT`). */
  async getSecretValue(secretId: string, options: CacheGetOptions = {}): Promise<AwsSecretValue> {
    const stage = options.versionStage ?? this.#stage;
    const key = keyOf(secretId, stage);
    const entry = this.#entries.get(key);
    if (entry !== undefined) {
      this.#hits++;
      this.#entries.delete(key);
      this.#entries.set(key, entry);
      if (this.#clock() - entry.checkedAt < this.#nextCheckAfter(entry)) return entry.value;
      return this.#coalesce(key, () => this.#refresh(key, entry, stage, options));
    }
    this.#misses++;
    return this.#coalesce(key, async () => {
      const value = await this.#source.getSecretValue(secretId, withStage(options, stage));
      this.#store(key, { secretId, value, checkedAt: this.#clock(), failures: 0 });
      return value;
    });
  }

  /** The value as text (`SecretString`, or UTF-8 of the binary). */
  async getSecretString(secretId: string, options: CacheGetOptions = {}): Promise<string> {
    return (await this.getSecretValue(secretId, options)).value.reveal();
  }

  /** The value as bytes. */
  async getSecretBinary(secretId: string, options: CacheGetOptions = {}): Promise<Uint8Array> {
    return (await this.getSecretValue(secretId, options)).value.revealBytes();
  }

  /** Forces a refresh check now (and a fetch when the stage moved); returns the value. */
  async refreshNow(secretId: string, options: CacheGetOptions = {}): Promise<AwsSecretValue> {
    const stage = options.versionStage ?? this.#stage;
    const key = keyOf(secretId, stage);
    const entry = this.#entries.get(key);
    if (entry === undefined) return this.getSecretValue(secretId, options);
    entry.checkedAt = Number.NEGATIVE_INFINITY;
    entry.failures = 0;
    return this.getSecretValue(secretId, options);
  }

  /** Drops every cached stage of `secretId`. */
  invalidate(secretId: string): void {
    for (const [key, entry] of this.#entries) {
      if (entry.secretId === secretId) this.#entries.delete(key);
    }
  }

  /** Drops every entry. */
  clear(): void {
    this.#entries.clear();
  }

  /** Counters and current size. */
  stats(): AwsSecretCacheStats {
    return {
      hits: this.#hits,
      misses: this.#misses,
      refreshes: this.#refreshes,
      versionChanges: this.#versionChanges,
      evictions: this.#evictions,
      size: this.#entries.size,
    };
  }

  #nextCheckAfter(entry: Entry): number {
    if (entry.failures === 0) return this.#ttl;
    return Math.min(this.#ttl, REFRESH_RETRY_MS * 2 ** (entry.failures - 1));
  }

  async #refresh(
    key: string,
    entry: Entry,
    stage: string,
    options: CallOptions,
  ): Promise<AwsSecretValue> {
    this.#refreshes++;
    try {
      const described = await this.#source.describeSecret(entry.secretId, signalOnly(options));
      const current = Object.entries(described.versionIdsToStages).find(([, stages]) =>
        stages.includes(stage),
      )?.[0];
      let value = entry.value;
      if (current === undefined || current !== entry.value.versionId) {
        value = await this.#source.getSecretValue(entry.secretId, withStage(options, stage));
        this.#versionChanges++;
      }
      this.#store(key, { secretId: entry.secretId, value, checkedAt: this.#clock(), failures: 0 });
      return value;
    } catch (err) {
      entry.failures++;
      entry.checkedAt = this.#clock();
      try {
        this.#onRefreshError?.(err);
      } catch {
        // ignored
      }
      return entry.value;
    }
  }

  #coalesce(key: string, load: () => Promise<AwsSecretValue>): Promise<AwsSecretValue> {
    const pending = this.#inflight.get(key);
    if (pending !== undefined) return pending;
    const promise = load().finally(() => {
      this.#inflight.delete(key);
    });
    this.#inflight.set(key, promise);
    return promise;
  }

  #store(key: string, entry: Entry): void {
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    while (this.#entries.size > this.#max) {
      const oldest = this.#entries.keys().next().value as string;
      this.#entries.delete(oldest);
      this.#evictions++;
    }
  }
}

function keyOf(secretId: string, stage: string): string {
  return JSON.stringify([secretId, stage]);
}

function signalOnly(options: CallOptions): CallOptions {
  return options.signal === undefined ? {} : { signal: options.signal };
}

function withStage(options: CallOptions, stage: string): CallOptions & { versionStage: string } {
  return { ...signalOnly(options), versionStage: stage };
}
