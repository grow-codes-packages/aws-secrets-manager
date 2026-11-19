// Service-owned: generated once by sdk-kit, then maintained in this repository.

import type { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@smithy/types";
import {
  type CommonConfig,
  type CommonConfigOptions,
  type CommonVendorEnv,
  ConfigError,
  type EnvMap,
  EnvReader,
  type Hooks,
  type ClientLogger,
  REDACTED,
  type RetryPolicy,
  Secret,
  type TlsOptions,
  describeCommonConfig,
  mergeOptions,
  readCommonEnv,
  resolveCommonConfig,
  secretValues,
  validateCommonConfig,
} from "./core/index.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/** Default recovery window of `deleteSecret` / `SecretsProvider.delete` in days (AWS default). */
export const DEFAULT_RECOVERY_WINDOW_DAYS = 30;

/** Default STS role session name of the assume-role helper. */
export const DEFAULT_ROLE_SESSION_NAME = "grow-sdk";

/** Options accepted by {@link AwsSecretsManagerConfig} (all optional). */
export interface AwsSecretsManagerConfigOptions extends CommonConfigOptions {
  /**
   * Endpoint override (env `GROW_AWS_SECRETS_MANAGER_URL` > `AWS_ENDPOINT_URL_SECRETS_MANAGER` >
   * `AWS_ENDPOINT_URL`). Unset: the AWS SDK resolves `https://secretsmanager.<region>.amazonaws.com`.
   */
  url?: string;
  /** AWS region (env `GROW_AWS_SECRETS_MANAGER_REGION` > `AWS_REGION` > `AWS_DEFAULT_REGION`). */
  region?: string;
  /** Access key id (env `GROW_AWS_SECRETS_MANAGER_ACCESS_KEY_ID` > `AWS_ACCESS_KEY_ID`). */
  accessKeyId?: string;
  /** Secret access key (env `GROW_AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY` > `AWS_SECRET_ACCESS_KEY`). */
  secretAccessKey?: string | Secret;
  /** Session token (env `GROW_AWS_SECRETS_MANAGER_SESSION_TOKEN` > `AWS_SESSION_TOKEN`). */
  sessionToken?: string | Secret;
  /** Shared config/credentials profile (env `GROW_AWS_SECRETS_MANAGER_PROFILE` > `AWS_PROFILE`). */
  profile?: string;
  /** An AWS SDK credentials object or provider (instead of the key fields or the default chain). */
  credentials?: AwsCredentialIdentity | AwsCredentialIdentityProvider;
  /** Role to assume with STS on top of the base credentials (env `GROW_AWS_SECRETS_MANAGER_ROLE_ARN`). */
  roleArn?: string;
  /** STS session name (default `grow-sdk`, env `GROW_AWS_SECRETS_MANAGER_ROLE_SESSION_NAME`). */
  roleSessionName?: string;
  /** STS external id (env `GROW_AWS_SECRETS_MANAGER_EXTERNAL_ID`). */
  externalId?: string;
  /** Assumed-role session duration in ms (900 s – 43 200 s; default: the role's default). */
  roleDurationMs?: number;
  /** Recovery window of deletes in days, 7–30 (default 30, env `GROW_AWS_SECRETS_MANAGER_RECOVERY_WINDOW_DAYS`). */
  recoveryWindowDays?: number;
  /**
   * An existing AWS SDK `SecretsManagerClient` to use instead of building one. Mutually exclusive
   * with the credential, region and endpoint fields; `close()` never destroys it and the Grow
   * hooks, TLS, proxy and User-Agent settings do not apply to it.
   */
  sdkClient?: SecretsManagerClient;
}

/**
 * Vendor environment variables read after `GROW_AWS_SECRETS_MANAGER_*`, in order (standard AWS
 * variables). Unset credentials fall back to the AWS SDK default credential chain.
 */
export const VENDOR_ENV: CommonVendorEnv & {
  region: readonly string[];
  accessKeyId: readonly string[];
  secretAccessKey: readonly string[];
  sessionToken: readonly string[];
  profile: readonly string[];
} = {
  url: ["AWS_ENDPOINT_URL_SECRETS_MANAGER", "AWS_ENDPOINT_URL"],
  region: ["AWS_REGION", "AWS_DEFAULT_REGION"],
  accessKeyId: ["AWS_ACCESS_KEY_ID"],
  secretAccessKey: ["AWS_SECRET_ACCESS_KEY"],
  sessionToken: ["AWS_SESSION_TOKEN"],
  profile: ["AWS_PROFILE"],
};

/** Immutable configuration of {@link AwsSecretsManagerClient}. */
export class AwsSecretsManagerConfig implements CommonConfig {
  /** Prefix of every environment variable. */
  static readonly ENV_PREFIX = "GROW_AWS_SECRETS_MANAGER_";

  /**
   * Effective endpoint: {@link endpoint} when set, otherwise the public AWS endpoint of
   * {@link region} (`us-east-1` when the region is left to the SDK). Informational.
   */
  readonly url: string;
  /** Explicit endpoint override passed to the AWS SDK (`undefined` = SDK resolves it). */
  readonly endpoint?: string;
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly totalTimeoutMs: number;
  readonly retry: RetryPolicy;
  readonly tls: Readonly<TlsOptions>;
  readonly proxy?: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly userAgentSuffix?: string;
  readonly hooks?: Hooks;
  readonly logger?: ClientLogger;
  /** AWS region (`undefined` = SDK chain: env, shared config). */
  readonly region?: string;
  /** Access key id. */
  readonly accessKeyId?: string;
  /** Secret access key. */
  readonly secretAccessKey?: Secret;
  /** Session token. */
  readonly sessionToken?: Secret;
  /** Shared config profile. */
  readonly profile?: string;
  /** Explicit SDK credentials. */
  readonly credentials?: AwsCredentialIdentity | AwsCredentialIdentityProvider;
  /** Role assumed with STS. */
  readonly roleArn?: string;
  /** STS session name. */
  readonly roleSessionName: string;
  /** STS external id. */
  readonly externalId?: string;
  /** Assumed-role session duration in ms. */
  readonly roleDurationMs?: number;
  /** Recovery window of deletes in days. */
  readonly recoveryWindowDays: number;
  /** Caller-supplied AWS SDK client. */
  readonly sdkClient?: SecretsManagerClient;

  /** Applies defaults, validates (throws {@link ConfigError}) and freezes. */
  constructor(options: AwsSecretsManagerConfigOptions = {}) {
    const region = blankToUndefined(options.region);
    const fallbackUrl = `https://secretsmanager.${region ?? "us-east-1"}.amazonaws.com`;
    const endpointOption = blankToUndefined(options.url);
    const common = resolveCommonConfig(
      endpointOption === undefined ? { ...options, url: fallbackUrl } : options,
      fallbackUrl,
    );
    this.url = common.url;
    if (endpointOption !== undefined) this.endpoint = endpointOption;
    this.connectTimeoutMs = common.connectTimeoutMs;
    this.requestTimeoutMs = common.requestTimeoutMs;
    this.totalTimeoutMs = common.totalTimeoutMs;
    this.retry = common.retry;
    this.tls = common.tls;
    this.headers = common.headers;
    if (common.proxy !== undefined) this.proxy = common.proxy;
    if (common.userAgentSuffix !== undefined) this.userAgentSuffix = common.userAgentSuffix;
    if (common.hooks !== undefined) this.hooks = common.hooks;
    if (common.logger !== undefined) this.logger = common.logger;
    if (region !== undefined) this.region = region;
    const accessKeyId = blankToUndefined(options.accessKeyId);
    if (accessKeyId !== undefined) this.accessKeyId = accessKeyId;
    const secretAccessKey = Secret.from(options.secretAccessKey);
    if (secretAccessKey !== undefined) this.secretAccessKey = secretAccessKey;
    const sessionToken = Secret.from(options.sessionToken);
    if (sessionToken !== undefined) this.sessionToken = sessionToken;
    const profile = blankToUndefined(options.profile);
    if (profile !== undefined) this.profile = profile;
    if (options.credentials !== undefined) this.credentials = options.credentials;
    const roleArn = blankToUndefined(options.roleArn);
    if (roleArn !== undefined) this.roleArn = roleArn;
    this.roleSessionName = blankToUndefined(options.roleSessionName) ?? DEFAULT_ROLE_SESSION_NAME;
    const externalId = blankToUndefined(options.externalId);
    if (externalId !== undefined) this.externalId = externalId;
    if (options.roleDurationMs !== undefined) this.roleDurationMs = options.roleDurationMs;
    this.recoveryWindowDays = options.recoveryWindowDays ?? DEFAULT_RECOVERY_WINDOW_DAYS;
    if (options.sdkClient !== undefined) this.sdkClient = options.sdkClient;
    this.validate();
    Object.freeze(this);
  }

  /** Returns `options` when it already is a config, otherwise builds one. */
  static from(options: AwsSecretsManagerConfigOptions = {}): AwsSecretsManagerConfig {
    if (options instanceof AwsSecretsManagerConfig) return options;
    return new AwsSecretsManagerConfig(options);
  }

  /**
   * Builds a config from the environment. Precedence: explicit `overrides` >
   * `GROW_AWS_SECRETS_MANAGER_<NAME>` > standard AWS variables ({@link VENDOR_ENV}) > defaults.
   * Credentials left unset use the AWS SDK default chain.
   */
  static fromEnv(
    overrides: AwsSecretsManagerConfigOptions = {},
    env: EnvMap = process.env,
  ): AwsSecretsManagerConfig {
    const reader = new EnvReader(AwsSecretsManagerConfig.ENV_PREFIX, env);
    const fromEnv: AwsSecretsManagerConfigOptions = readCommonEnv(reader, VENDOR_ENV);
    const set = <K extends keyof AwsSecretsManagerConfigOptions>(
      key: K,
      value: AwsSecretsManagerConfigOptions[K] | undefined,
    ): void => {
      if (value !== undefined) fromEnv[key] = value;
    };
    set("region", reader.string("REGION", VENDOR_ENV.region));
    // Credentials from a single layer: a GROW_* key id never pairs with an AWS_* secret.
    const growKey = reader.string("ACCESS_KEY_ID");
    if (growKey !== undefined) {
      set("accessKeyId", growKey);
      set("secretAccessKey", reader.secret("SECRET_ACCESS_KEY"));
      set("sessionToken", reader.secret("SESSION_TOKEN"));
    } else {
      set("accessKeyId", firstEnv(env, VENDOR_ENV.accessKeyId));
      set("secretAccessKey", Secret.from(firstEnv(env, VENDOR_ENV.secretAccessKey)));
      set("sessionToken", Secret.from(firstEnv(env, VENDOR_ENV.sessionToken)));
    }
    set("profile", reader.string("PROFILE", VENDOR_ENV.profile));
    set("roleArn", reader.string("ROLE_ARN"));
    set("roleSessionName", reader.string("ROLE_SESSION_NAME"));
    set("externalId", reader.string("EXTERNAL_ID"));
    set("recoveryWindowDays", reader.int("RECOVERY_WINDOW_DAYS"));
    const merged = mergeOptions<AwsSecretsManagerConfigOptions>(fromEnv, overrides);
    if (overrides.sdkClient !== undefined || overrides.credentials !== undefined) {
      // An explicit client or credentials object replaces the credentials found in the environment.
      delete merged.accessKeyId;
      delete merged.secretAccessKey;
      delete merged.sessionToken;
      if (overrides.sdkClient !== undefined) {
        if (overrides.region === undefined) delete merged.region;
        if (overrides.url === undefined) delete merged.url;
        if (overrides.profile === undefined) delete merged.profile;
        if (overrides.roleArn === undefined) delete merged.roleArn;
      }
    }
    return new AwsSecretsManagerConfig(merged);
  }

  /** Throws {@link ConfigError} when a setting is invalid. */
  validate(): void {
    validateCommonConfig(this);
    const problems: string[] = [];
    if (this.endpoint !== undefined && !/^https?:\/\//i.test(this.endpoint)) {
      problems.push("url must be an http or https URL");
    }
    if (this.region !== undefined && !/^[a-z0-9-]+$/.test(this.region)) {
      problems.push("region must look like us-east-1");
    }
    if (this.accessKeyId !== undefined && this.secretAccessKey === undefined) {
      problems.push("accessKeyId requires secretAccessKey");
    }
    if (this.accessKeyId === undefined && this.secretAccessKey !== undefined) {
      problems.push("secretAccessKey requires accessKeyId");
    }
    if (this.sessionToken !== undefined && this.accessKeyId === undefined) {
      problems.push("sessionToken requires accessKeyId and secretAccessKey");
    }
    if (this.credentials !== undefined && this.accessKeyId !== undefined) {
      problems.push("credentials and accessKeyId/secretAccessKey are mutually exclusive");
    }
    if (this.sdkClient !== undefined) {
      const clash = (
        [
          ["accessKeyId", this.accessKeyId],
          ["credentials", this.credentials],
          ["profile", this.profile],
          ["roleArn", this.roleArn],
          ["region", this.region],
          ["url", this.endpoint],
        ] as const
      ).filter(([, v]) => v !== undefined);
      if (clash.length > 0) {
        problems.push(`sdkClient is mutually exclusive with ${clash.map(([k]) => k).join(", ")}`);
      }
    }
    if (this.roleArn !== undefined && !this.roleArn.startsWith("arn:")) {
      problems.push("roleArn must be an ARN");
    }
    if (
      this.roleDurationMs !== undefined &&
      !(this.roleDurationMs >= 900_000 && this.roleDurationMs <= 43_200_000)
    ) {
      problems.push("roleDurationMs must be between 900000 and 43200000");
    }
    if (
      !Number.isInteger(this.recoveryWindowDays) ||
      this.recoveryWindowDays < 7 ||
      this.recoveryWindowDays > 30
    ) {
      problems.push("recoveryWindowDays must be an integer from 7 to 30");
    }
    if (problems.length > 0) {
      throw new ConfigError(`invalid configuration: ${problems.join("; ")}`);
    }
  }

  /** Credential values to redact from error messages and logs. */
  knownSecrets(): string[] {
    return secretValues(this.secretAccessKey, this.sessionToken);
  }

  /** Debug form with every credential redacted. */
  toJSON(): Record<string, unknown> {
    const out: Record<string, unknown> = {
      ...describeCommonConfig(this),
      endpoint: this.endpoint ?? null,
      region: this.region ?? null,
      accessKeyId: this.accessKeyId ?? null,
      secretAccessKey: this.secretAccessKey === undefined ? null : REDACTED,
      sessionToken: this.sessionToken === undefined ? null : REDACTED,
      profile: this.profile ?? null,
      credentials: this.credentials === undefined ? null : REDACTED,
      roleArn: this.roleArn ?? null,
      roleSessionName: this.roleSessionName,
      externalId: this.externalId === undefined ? null : REDACTED,
      recoveryWindowDays: this.recoveryWindowDays,
      sdkClient: this.sdkClient === undefined ? null : "SecretsManagerClient",
    };
    if (this.roleDurationMs !== undefined) out.roleDurationMs = this.roleDurationMs;
    return out;
  }

  toString(): string {
    return `AwsSecretsManagerConfig(${JSON.stringify(this.toJSON())})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}

function firstEnv(env: EnvMap, names: readonly string[]): string | undefined {
  for (const name of names) {
    const value = env[name];
    if (value !== undefined && value !== "") return value;
  }
  return undefined;
}

function blankToUndefined(value: string | undefined): string | undefined {
  return value === undefined || value.trim() === "" ? undefined : value;
}
