import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { ListSecretsCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  API_VERSION,
  AwsSecretsManagerClient,
  AwsSecretsManagerConfig,
  AwsSecretsManagerError,
  ConfigError,
  DEFAULT_RECOVERY_WINDOW_DAYS,
  GROW_USER_AGENT,
  PACKAGE_KEY,
  REDACTED,
  RetryPolicy,
  SDK_VERSION,
  Secret,
  VENDOR_ENV,
  type ErrorInfo,
  type RequestInfo,
  type ResponseInfo,
} from "../src/index.js";
import { type MockServer, closedPort, startConnectProxy, startServer } from "./helpers/server.js";
import {
  type AwsMock,
  TEST_KEYS,
  awsError,
  clientFor,
  fixture,
  ok,
  operationOf,
  startAws,
} from "./support/aws.js";

const servers: { close(): Promise<void> }[] = [];
const clients: AwsSecretsManagerClient[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await Promise.all(servers.splice(0).map((s) => s.close()));
  vi.unstubAllEnvs();
});

async function aws(routes: Parameters<typeof startAws>[0]): Promise<AwsMock> {
  const m = await startAws(routes);
  servers.push(m);
  return m;
}

function track(c: AwsSecretsManagerClient): AwsSecretsManagerClient {
  clients.push(c);
  return c;
}

const P = AwsSecretsManagerConfig.ENV_PREFIX;

describe("AwsSecretsManagerConfig", () => {
  it("uses defaults and freezes", () => {
    const c = new AwsSecretsManagerConfig();
    expect(c.url).toBe("https://secretsmanager.us-east-1.amazonaws.com");
    expect(c.endpoint).toBeUndefined();
    expect(c.region).toBeUndefined();
    expect(c.requestTimeoutMs).toBe(30_000);
    expect(c.retry).toBeInstanceOf(RetryPolicy);
    expect(c.recoveryWindowDays).toBe(DEFAULT_RECOVERY_WINDOW_DAYS);
    expect(c.roleSessionName).toBe("grow-sdk");
    expect(Object.isFrozen(c)).toBe(true);
    expect(AwsSecretsManagerConfig.from(c)).toBe(c);
    expect(AwsSecretsManagerConfig.from().url).toBe(c.url);
    expect(P).toBe(`GROW_${PACKAGE_KEY.toUpperCase().replaceAll("-", "_")}_`);
    expect(new AwsSecretsManagerConfig({ region: "eu-west-1" }).url).toBe(
      "https://secretsmanager.eu-west-1.amazonaws.com",
    );
    expect(API_VERSION).toBe("2017-10-17");
  });

  it("keeps every optional setting", () => {
    const hooks = {};
    const logger = { debug() {}, info() {}, warn() {}, error() {} };
    const provider = () => Promise.resolve({ accessKeyId: "a", secretAccessKey: "b" });
    const c = new AwsSecretsManagerConfig({
      url: "http://moto:5000",
      region: "eu-central-1",
      proxy: "http://p:1",
      userAgentSuffix: "s",
      hooks,
      logger,
      credentials: provider,
      profile: "dev",
      roleArn: "arn:aws:iam::1:role/r",
      roleSessionName: "sess",
      externalId: "ext",
      roleDurationMs: 3_600_000,
      recoveryWindowDays: 7,
    });
    expect(c.endpoint).toBe("http://moto:5000");
    expect(c.url).toBe("http://moto:5000");
    expect(c.region).toBe("eu-central-1");
    expect(c.proxy).toBe("http://p:1");
    expect(c.userAgentSuffix).toBe("s");
    expect(c.hooks).toBe(hooks);
    expect(c.logger).toBe(logger);
    expect(c.credentials).toBe(provider);
    expect(c.profile).toBe("dev");
    expect(c.roleArn).toBe("arn:aws:iam::1:role/r");
    expect(c.roleSessionName).toBe("sess");
    expect(c.externalId).toBe("ext");
    expect(c.roleDurationMs).toBe(3_600_000);
    expect(c.recoveryWindowDays).toBe(7);
    expect(c.toJSON()).toMatchObject({ roleDurationMs: 3_600_000, credentials: REDACTED });
  });

  it("validate() raises ConfigError for every invalid setting", () => {
    const bad: ConstructorParameters<typeof AwsSecretsManagerConfig>[0][] = [
      { url: "ftp://x" },
      { region: "Not A Region" },
      { accessKeyId: "AKID" },
      { secretAccessKey: "s" },
      { sessionToken: "t", region: "us-east-1" },
      { credentials: { accessKeyId: "a", secretAccessKey: "b" }, ...TEST_KEYS },
      { sdkClient: new SecretsManagerClient({ region: "us-east-1" }), region: "us-east-1" },
      { roleArn: "role" },
      { roleDurationMs: 60_000 },
      { recoveryWindowDays: 3 },
      { recoveryWindowDays: 31 },
      { recoveryWindowDays: 7.5 },
    ];
    for (const options of bad) {
      expect(
        () => new AwsSecretsManagerConfig(options),
        JSON.stringify(Object.keys(options ?? {})),
      ).toThrow(ConfigError);
    }
    let err: unknown;
    try {
      new AwsSecretsManagerConfig({ accessKeyId: "AKID", sdkClient: new SecretsManagerClient({}) });
    } catch (e) {
      err = e;
    }
    expect((err as Error).message).toContain("sdkClient is mutually exclusive with accessKeyId");
    // blank strings count as unset
    const blank = new AwsSecretsManagerConfig({ url: " ", region: "", profile: " " });
    expect(blank.endpoint).toBeUndefined();
    expect(blank.region).toBeUndefined();
    expect(blank.profile).toBeUndefined();
  });

  it("core.redaction.config: toString/JSON/inspect hide credentials", () => {
    const c = new AwsSecretsManagerConfig({
      ...TEST_KEYS,
      sessionToken: new Secret("session-token-value"),
      externalId: "external-id-value",
      headers: { "x-api-key": "hdr-secret" },
    });
    for (const form of [String(c), JSON.stringify(c), inspect(c), String(c.secretAccessKey)]) {
      expect(form).not.toContain(TEST_KEYS.secretAccessKey);
      expect(form).not.toContain("session-token-value");
      expect(form).not.toContain("external-id-value");
      expect(form).not.toContain("hdr-secret");
    }
    expect(String(c)).toContain(REDACTED);
    expect(String(c)).toMatch(/^AwsSecretsManagerConfig\(/);
    expect(c.knownSecrets()).toEqual([TEST_KEYS.secretAccessKey, "session-token-value"]);
    const empty = new AwsSecretsManagerConfig().toJSON();
    expect(empty.secretAccessKey).toBeNull();
    expect(empty.sessionToken).toBeNull();
    expect(empty.externalId).toBeNull();
    expect(empty.sdkClient).toBeNull();
    expect(
      new AwsSecretsManagerConfig({ sdkClient: new SecretsManagerClient({}) }).toJSON().sdkClient,
    ).toBe("SecretsManagerClient");
  });

  it("core.config.env-precedence: explicit > GROW_* > AWS_* > default", () => {
    const env = {
      [`${P}URL`]: "http://grow:1",
      AWS_ENDPOINT_URL_SECRETS_MANAGER: "http://vendor:2",
      AWS_ENDPOINT_URL: "http://generic:3",
      [`${P}REGION`]: "eu-west-1",
      AWS_REGION: "us-west-2",
      AWS_DEFAULT_REGION: "us-west-1",
      AWS_ACCESS_KEY_ID: "AKIDVENDOR",
      AWS_SECRET_ACCESS_KEY: "vendor-secret-value",
      AWS_SESSION_TOKEN: "vendor-session",
      AWS_PROFILE: "vendor-profile",
      [`${P}REQUEST_TIMEOUT`]: "5s",
      [`${P}MAX_RETRIES`]: "7",
      [`${P}ROLE_ARN`]: "arn:aws:iam::1:role/r",
      [`${P}ROLE_SESSION_NAME`]: "s1",
      [`${P}EXTERNAL_ID`]: "e1",
      [`${P}RECOVERY_WINDOW_DAYS`]: "10",
    };
    const c = AwsSecretsManagerConfig.fromEnv({}, env);
    expect(c.endpoint).toBe("http://grow:1");
    expect(c.region).toBe("eu-west-1");
    expect(c.accessKeyId).toBe("AKIDVENDOR");
    expect(c.secretAccessKey?.reveal()).toBe("vendor-secret-value");
    expect(c.sessionToken?.reveal()).toBe("vendor-session");
    expect(c.profile).toBe("vendor-profile");
    expect(c.requestTimeoutMs).toBe(5000);
    expect(c.retry.maxRetries).toBe(7);
    expect(c.roleArn).toBe("arn:aws:iam::1:role/r");
    expect(c.roleSessionName).toBe("s1");
    expect(c.externalId).toBe("e1");
    expect(c.recoveryWindowDays).toBe(10);
    expect(c.connectTimeoutMs).toBe(10_000);

    const vendorOnly = AwsSecretsManagerConfig.fromEnv(
      {},
      {
        AWS_ENDPOINT_URL_SECRETS_MANAGER: "http://vendor:2",
        AWS_ENDPOINT_URL: "http://g:3",
        AWS_DEFAULT_REGION: "us-west-1",
      },
    );
    expect(vendorOnly.endpoint).toBe("http://vendor:2");
    expect(vendorOnly.region).toBe("us-west-1");
    expect(AwsSecretsManagerConfig.fromEnv({}, { AWS_ENDPOINT_URL: "http://g:3" }).endpoint).toBe(
      "http://g:3",
    );

    // GROW_* credentials win as a set: never mixed with AWS_* values
    const grow = AwsSecretsManagerConfig.fromEnv(
      {},
      {
        ...env,
        [`${P}ACCESS_KEY_ID`]: "AKIDGROW",
        [`${P}SECRET_ACCESS_KEY`]: "grow-secret-value",
        [`${P}PROFILE`]: "grow-profile",
      },
    );
    expect(grow.accessKeyId).toBe("AKIDGROW");
    expect(grow.secretAccessKey?.reveal()).toBe("grow-secret-value");
    expect(grow.sessionToken).toBeUndefined();
    expect(grow.profile).toBe("grow-profile");
    const growSession = AwsSecretsManagerConfig.fromEnv(
      {},
      {
        [`${P}ACCESS_KEY_ID`]: "AKIDGROW",
        [`${P}SECRET_ACCESS_KEY`]: "grow-secret-value",
        [`${P}SESSION_TOKEN`]: "grow-session",
      },
    );
    expect(growSession.sessionToken?.reveal()).toBe("grow-session");

    const explicit = AwsSecretsManagerConfig.fromEnv(
      { url: "http://explicit:3", region: "ap-south-1", retry: { initialBackoffMs: 1 } },
      env,
    );
    expect(explicit.endpoint).toBe("http://explicit:3");
    expect(explicit.region).toBe("ap-south-1");
    expect(explicit.retry.maxRetries).toBe(7);
    expect(explicit.retry.initialBackoffMs).toBe(1);

    const withCreds = AwsSecretsManagerConfig.fromEnv(
      { credentials: { accessKeyId: "x", secretAccessKey: "y" } },
      env,
    );
    expect(withCreds.accessKeyId).toBeUndefined();
    expect(withCreds.region).toBe("eu-west-1");
    const sdk = new SecretsManagerClient({});
    const withSdk = AwsSecretsManagerConfig.fromEnv({ sdkClient: sdk }, env);
    expect(withSdk.sdkClient).toBe(sdk);
    expect(withSdk.region).toBeUndefined();
    expect(withSdk.endpoint).toBeUndefined();

    expect(AwsSecretsManagerConfig.fromEnv({}, {}).endpoint).toBeUndefined();
    expect(AwsSecretsManagerConfig.fromEnv().url).toBeTypeOf("string");
    expect(VENDOR_ENV.url).toEqual(["AWS_ENDPOINT_URL_SECRETS_MANAGER", "AWS_ENDPOINT_URL"]);

    for (const [name, value] of [
      [`${P}TOTAL_TIMEOUT`, "forever-and-secret"],
      [`${P}RECOVERY_WINDOW_DAYS`, "thirty-secret"],
    ] as const) {
      let err: unknown;
      try {
        AwsSecretsManagerConfig.fromEnv({}, { [name]: value });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as Error).message).toContain(name);
      expect((err as Error).message).not.toContain(value);
    }
  });
});

describe("AwsSecretsManagerClient core", () => {
  it("health, ping and serverVersion", async () => {
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const client = track(clientFor(m));
    expect(await client.health()).toEqual({ healthy: true, status: "ok", details: {} });
    expect(await client.ping()).toBeGreaterThanOrEqual(0);
    await expect(client.serverVersion()).rejects.toMatchObject({ code: "UNSUPPORTED" });
    await expect(client.serverVersion({ signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    expect(client.sdk).toBeInstanceOf(SecretsManagerClient);
  });

  it("ping maps Moto's XML auth errors to AUTHENTICATION and PERMISSION_DENIED", async () => {
    const m = await aws({
      ListSecrets: [
        fixture("ping.auth-unknown-key"),
        fixture("ping.auth-bad-signature"),
        fixture("createSecret.access-denied"),
        awsError("UnrecognizedClientException", "bad key"),
        awsError("AccessDeniedException", "no"),
      ],
    });
    const client = track(clientFor(m));
    for (const code of [
      "AUTHENTICATION",
      "AUTHENTICATION",
      "PERMISSION_DENIED",
      "AUTHENTICATION",
      "PERMISSION_DENIED",
    ]) {
      const err = await client.ping().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AwsSecretsManagerError);
      expect((err as AwsSecretsManagerError).code).toBe(code);
      expect((err as Error).message).not.toContain(TEST_KEYS.secretAccessKey);
    }
  });

  it("health: auth failure is reachable, throttling is degraded, 5xx unhealthy, 4xx ok", async () => {
    const m = await aws({
      ListSecrets: [
        fixture("ping.auth-unknown-key"),
        awsError("ThrottlingException", "slow down"),
        awsError("InternalServiceError", "boom", 500),
        awsError("InvalidParameterException", "bad"),
      ],
    });
    const client = track(clientFor(m, { retry: { maxRetries: 3 } }));
    expect(await client.health()).toEqual({
      healthy: true,
      status: "ok",
      details: { auth: "failed", code: "AUTHENTICATION" },
    });
    expect(await client.health()).toEqual({
      healthy: true,
      status: "degraded",
      details: { code: "RATE_LIMITED" },
    });
    expect(await client.health()).toEqual({
      healthy: false,
      status: "unhealthy",
      details: { httpStatus: "500", error: "UNAVAILABLE" },
    });
    expect(await client.health()).toEqual({
      healthy: true,
      status: "ok",
      details: { httpStatus: "400", code: "VALIDATION" },
    });
    // health never retries
    expect(m.calls("ListSecrets")).toHaveLength(4);
  });

  it("core.health.unreachable: closed port -> healthy=false, status=unreachable", async () => {
    const port = await closedPort();
    const client = track(clientFor({ url: `http://127.0.0.1:${String(port)}` }));
    expect(await client.health()).toEqual({
      healthy: false,
      status: "unreachable",
      details: { error: "UNAVAILABLE" },
    });
    await expect(client.ping()).rejects.toMatchObject({ code: "UNAVAILABLE" });
  });

  it("health rethrows cancellation and closed-client errors", async () => {
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const client = clientFor(m);
    await expect(client.health({ signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    await client.close();
    await expect(client.health()).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("core.close.idempotent: close twice is safe", async () => {
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const client = clientFor(m);
    const provider = client.secrets();
    const handle = provider.watch("x", 60_000, () => undefined);
    await client.health();
    expect(client.closed).toBe(false);
    await client.close();
    await client.close();
    expect(client.closed).toBe(true);
    expect(handle.stopped).toBe(true);
    await expect(client.ping()).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("wraps a caller-supplied SDK client and never destroys it", async () => {
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const sdk = new SecretsManagerClient({
      region: "us-east-1",
      endpoint: m.url,
      credentials: TEST_KEYS,
    });
    const destroy = vi.spyOn(sdk, "destroy");
    const client = AwsSecretsManagerClient.withSdkClient(sdk, { retry: { maxRetries: 0 } });
    expect(client.sdk).toBe(sdk);
    expect(await client.health()).toMatchObject({ healthy: true });
    expect(await client.ping()).toBeGreaterThanOrEqual(0);
    await client.close();
    expect(destroy).not.toHaveBeenCalled();
    expect(await sdk.send(new ListSecretsCommand({}))).toBeDefined();
    sdk.destroy();
  });

  it("core.useragent and extra headers; SigV4 signs with the configured key", async () => {
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const client = track(
      clientFor(m, { userAgentSuffix: "my-app/1", headers: { "x-extra": "1" } }),
    );
    await client.ping();
    const req = m.calls("ListSecrets")[0]!;
    expect(GROW_USER_AGENT).toBe(`grow-codes-${PACKAGE_KEY}/${SDK_VERSION} (typescript)`);
    expect(String(req.headers["user-agent"])).toContain(`${GROW_USER_AGENT} my-app/1`);
    expect(req.headers["x-extra"]).toBe("1");
    expect(String(req.headers.authorization)).toContain(`Credential=${TEST_KEYS.accessKeyId}/`);
    expect(String(req.headers.authorization)).toContain("/us-east-1/secretsmanager/aws4_request");
  });

  it("core.hooks: redacted data per attempt, throwing hooks ignored", async () => {
    const requests: RequestInfo[] = [];
    const responses: ResponseInfo[] = [];
    const errors: ErrorInfo[] = [];
    const m = await aws({
      ListSecrets: [awsError("InternalServiceError", "x", 503), fixture("ping.ok")],
      DescribeSecret: fixture("describeSecret.not-found"),
    });
    const client = track(
      clientFor(m, {
        retry: { maxRetries: 2 },
        hooks: {
          onRequest: (i) => {
            requests.push(i);
            throw new Error("hook failure is ignored");
          },
          onResponse: (i) => responses.push(i),
          onError: (i) => errors.push(i),
        },
      }),
    );
    await client.ping();
    expect(requests.map((r) => r.attempt)).toEqual([1, 2]);
    expect(requests[0]?.method).toBe("POST");
    expect(requests[0]?.headers.authorization).toBe(REDACTED);
    expect(responses.map((r) => r.status)).toEqual([503, 200]);
    expect(responses[1]?.requestId).toBeTruthy();
    await expect(client.describeSecret("missing")).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({ willRetry: false, attempt: 1 });
    expect(JSON.stringify([requests, responses])).not.toContain(TEST_KEYS.secretAccessKey);
  });

  it("onError fires for network errors with willRetry", async () => {
    const errors: ErrorInfo[] = [];
    const port = await closedPort();
    const client = track(
      clientFor(
        { url: `http://127.0.0.1:${String(port)}` },
        { retry: { maxRetries: 1 }, hooks: { onError: (i) => errors.push(i) } },
      ),
    );
    await expect(client.ping()).rejects.toMatchObject({ code: "UNAVAILABLE" });
    expect(errors.map((e) => [e.attempt, e.willRetry])).toEqual([
      [1, true],
      [2, false],
    ]);
  });

  it("core.retry.503-backoff and core.retry.exhausted via the SDK standard retry mode", async () => {
    const m = await aws({
      ListSecrets: [
        awsError("ServiceUnavailable", "x", 503),
        awsError("ServiceUnavailable", "x", 503),
        fixture("ping.ok"),
      ],
      DescribeSecret: awsError("InternalServiceError", "x", 500),
    });
    const client = track(clientFor(m, { retry: { maxRetries: 2 } }));
    await client.ping();
    expect(m.calls("ListSecrets")).toHaveLength(3);
    const err = (await client
      .describeSecret("a")
      .catch((e: unknown) => e)) as AwsSecretsManagerError;
    expect(err.code).toBe("UNAVAILABLE");
    expect(err.retryable).toBe(true);
    expect(err.httpStatus).toBe(500);
    expect(m.calls("DescribeSecret")).toHaveLength(3);
  });

  it("throttling maps to RATE_LIMITED with Retry-After", async () => {
    const m = await aws({
      ListSecrets: {
        ...awsError("ThrottlingException", "Rate exceeded"),
        headers: { ...awsError("ThrottlingException").headers, "retry-after": "2" },
      },
    });
    const client = track(clientFor(m));
    const err = (await client.ping().catch((e: unknown) => e)) as AwsSecretsManagerError;
    expect(err.code).toBe("RATE_LIMITED");
    expect(err.retryable).toBe(true);
    expect(err.retryAfterMs).toBe(2000);
  });

  it("core.timeout.request and core.timeout.total", async () => {
    const slow = await startServer([{ ...ok({ SecretList: [] }), delayMs: 400 }]);
    servers.push(slow);
    const perAttempt = track(clientFor(slow, { requestTimeoutMs: 50 }));
    await expect(perAttempt.ping()).rejects.toMatchObject({ code: "TIMEOUT" });
    const total = track(clientFor(slow, { requestTimeoutMs: 5_000, totalTimeoutMs: 60 }));
    const err = (await total.ping().catch((e: unknown) => e)) as Error;
    expect(err).toMatchObject({ code: "TIMEOUT" });
    expect(err.message).toContain("total timeout");
  });

  it("core.cancel: before and during the request", async () => {
    const slow = await startServer([{ ...ok({ SecretList: [] }), delayMs: 300 }]);
    servers.push(slow);
    const client = track(clientFor(slow));
    await expect(client.ping({ signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    const controller = new AbortController();
    setTimeout(() => {
      controller.abort();
    }, 30);
    await expect(client.ping({ signal: controller.signal })).rejects.toMatchObject({
      code: "CANCELLED",
    });
  });

  it("uses the proxy setting", async () => {
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const proxy = await startConnectProxy();
    servers.push(proxy);
    const client = track(clientFor(m, { proxy: proxy.url }));
    await client.ping();
    expect(proxy.tunnels()).toBeGreaterThan(0);
  });

  it("credentials from an explicit provider and from a shared-config profile", async () => {
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const viaProvider = track(
      new AwsSecretsManagerClient({
        url: m.url,
        region: "us-east-1",
        credentials: () => Promise.resolve({ accessKeyId: "AKIDPROVIDER", secretAccessKey: "p" }),
      }),
    );
    await viaProvider.ping();
    expect(String(m.requests.at(-1)?.headers.authorization)).toContain("Credential=AKIDPROVIDER/");

    const dir = mkdtempSync(join(tmpdir(), "asm-profile-"));
    writeFileSync(
      join(dir, "credentials"),
      "[unit]\naws_access_key_id = AKIDPROFILE\naws_secret_access_key = profile-secret\n",
    );
    writeFileSync(join(dir, "config"), "[profile unit]\nregion = eu-west-3\n");
    vi.stubEnv("AWS_SHARED_CREDENTIALS_FILE", join(dir, "credentials"));
    vi.stubEnv("AWS_CONFIG_FILE", join(dir, "config"));
    const viaProfile = track(new AwsSecretsManagerClient({ url: m.url, profile: "unit" }));
    await viaProfile.ping();
    const auth = String(m.requests.at(-1)?.headers.authorization);
    expect(auth).toContain("Credential=AKIDPROFILE/");
    expect(auth).toContain("/eu-west-3/secretsmanager/");
  });

  it("assume-role helper: STS AssumeRole, then calls signed with the temporary key", async () => {
    const sts = await startServer((req) => {
      if (req.body.includes("Action=AssumeRole")) {
        expect(req.body).toContain("RoleSessionName=grow-sdk");
        expect(req.body).toContain("ExternalId=ext-1");
        expect(req.body).toContain("DurationSeconds=900");
        return {
          status: 200,
          headers: { "content-type": "text/xml" },
          body:
            '<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>' +
            "<Credentials><AccessKeyId>ASIATEMPORARY</AccessKeyId><SecretAccessKey>temp-secret</SecretAccessKey>" +
            "<SessionToken>temp-session</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>" +
            "<AssumedRoleUser><Arn>arn:aws:sts::1:assumed-role/r/grow-sdk</Arn><AssumedRoleId>AROA:grow-sdk</AssumedRoleId></AssumedRoleUser>" +
            "</AssumeRoleResult><ResponseMetadata><RequestId>r1</RequestId></ResponseMetadata></AssumeRoleResponse>",
        };
      }
      return { status: 400, body: "unexpected" };
    });
    servers.push(sts);
    vi.stubEnv("AWS_ENDPOINT_URL_STS", sts.url);
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const client = track(
      clientFor(m, {
        roleArn: "arn:aws:iam::123456789012:role/reader",
        externalId: "ext-1",
        roleDurationMs: 900_000,
      }),
    );
    await client.ping();
    expect(sts.requests).toHaveLength(1);
    expect(String(sts.requests[0]?.headers.authorization)).toContain(
      `Credential=${TEST_KEYS.accessKeyId}/`,
    );
    const req = m.calls("ListSecrets")[0]!;
    expect(String(req.headers.authorization)).toContain("Credential=ASIATEMPORARY/");
    expect(req.headers["x-amz-security-token"]).toBe("temp-session");
    expect(operationOf(req)).toBe("ListSecrets");
  });

  it("assume-role without base keys uses the default chain (fails clearly without credentials)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "asm-empty-"));
    vi.stubEnv("AWS_SHARED_CREDENTIALS_FILE", join(dir, "none"));
    vi.stubEnv("AWS_CONFIG_FILE", join(dir, "none"));
    vi.stubEnv("AWS_ACCESS_KEY_ID", "");
    vi.stubEnv("AWS_SECRET_ACCESS_KEY", "");
    vi.stubEnv("AWS_EC2_METADATA_DISABLED", "true");
    vi.stubEnv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "");
    vi.stubEnv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "");
    vi.stubEnv("AWS_WEB_IDENTITY_TOKEN_FILE", "");
    const m = await aws({ ListSecrets: fixture("ping.ok") });
    const client = track(
      new AwsSecretsManagerClient({
        url: m.url,
        region: "us-east-1",
        roleArn: "arn:aws:iam::1:role/r",
        retry: { maxRetries: 0 },
      }),
    );
    await expect(client.ping()).rejects.toMatchObject({ code: "AUTHENTICATION" });
    const noRole = track(
      new AwsSecretsManagerClient({ url: m.url, region: "us-east-1", retry: { maxRetries: 0 } }),
    );
    await expect(noRole.ping()).rejects.toMatchObject({ code: "AUTHENTICATION" });
  });

  it("a missing region raises ConfigError", async () => {
    const dir = mkdtempSync(join(tmpdir(), "asm-noregion-"));
    vi.stubEnv("AWS_CONFIG_FILE", join(dir, "none"));
    vi.stubEnv("AWS_REGION", undefined);
    vi.stubEnv("AWS_DEFAULT_REGION", undefined);
    const client = track(new AwsSecretsManagerClient({ ...TEST_KEYS }));
    await expect(client.ping()).rejects.toMatchObject({ code: "CONFIG" });
    vi.stubEnv("AWS_REGION", "");
    const blank = track(new AwsSecretsManagerClient({ ...TEST_KEYS }));
    await expect(blank.ping()).rejects.toMatchObject({ code: "CONFIG" });
  });

  it("fromEnv builds from the environment", async () => {
    const m: MockServer = await aws({ ListSecrets: fixture("ping.ok") });
    vi.stubEnv(`${P}URL`, m.url);
    vi.stubEnv(`${P}REGION`, "us-east-1");
    vi.stubEnv(`${P}ACCESS_KEY_ID`, TEST_KEYS.accessKeyId);
    vi.stubEnv(`${P}SECRET_ACCESS_KEY`, TEST_KEYS.secretAccessKey);
    const client = track(AwsSecretsManagerClient.fromEnv());
    expect(client.config.endpoint).toBe(m.url);
    expect(await client.ping()).toBeGreaterThanOrEqual(0);
  });
});
