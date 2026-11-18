// Unit-test support: a local HTTP server that answers AWS JSON 1.1 calls with the responses
// recorded from Moto 5.2.4 (test/fixtures, see API.md §6) or with hand-written AWS shapes.

import { readFileSync } from "node:fs";
import { AwsSecretsManagerClient, type AwsSecretsManagerConfigOptions } from "../../src/index.js";
import {
  type MockResponse,
  type MockServer,
  type RecordedRequest,
  startServer,
} from "../helpers/server.js";

interface FixtureFile {
  request: { body: Record<string, unknown> };
  response: { status: number; headers: Record<string, string>; body: unknown };
}

/** Loads `test/fixtures/<name>.json`. */
export function loadFixture(name: string): FixtureFile {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/${name}.json`, import.meta.url), "utf8"),
  ) as FixtureFile;
}

/** The recorded response of a fixture as a mock response. */
export function fixture(name: string): MockResponse {
  const { response } = loadFixture(name);
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(response.headers)) {
    if (k === "content-length" || k === "status") continue;
    headers[k] = v;
  }
  const body =
    response.body === null
      ? ""
      : typeof response.body === "string"
        ? response.body
        : JSON.stringify(response.body);
  return { status: response.status, headers, body };
}

/** An AWS-shaped JSON error (HTTP 400 unless given). */
export function awsError(type: string, message = "error", status = 400): MockResponse {
  return {
    status,
    headers: {
      "content-type": "application/x-amz-json-1.1",
      "x-amzn-requestid": "req-123",
      "x-amzn-errortype": type,
    },
    body: JSON.stringify({ __type: type, message }),
  };
}

/** A JSON 200 answer. */
export function ok(body: unknown = {}): MockResponse {
  return {
    status: 200,
    headers: { "content-type": "application/x-amz-json-1.1", "x-amzn-requestid": "req-ok" },
    body: JSON.stringify(body),
  };
}

/** The operation of a recorded request (`X-Amz-Target: secretsmanager.<Op>`). */
export function operationOf(req: RecordedRequest): string {
  const target = req.headers["x-amz-target"];
  return String(target ?? "").replace(/^secretsmanager\./, "");
}

/** The JSON body of a recorded request. */
export function bodyOf(req: RecordedRequest): Record<string, unknown> {
  return req.body === "" ? {} : (JSON.parse(req.body) as Record<string, unknown>);
}

type Route = MockResponse | MockResponse[] | ((req: RecordedRequest) => MockResponse);

/** A server routing by operation; a list answers in order (the last repeats). */
export interface AwsMock extends MockServer {
  /** Requests of one operation. */
  calls(operation: string): RecordedRequest[];
}

export async function startAws(routes: Record<string, Route>): Promise<AwsMock> {
  const counters = new Map<string, number>();
  const server = await startServer((req) => {
    const op = operationOf(req);
    const route = routes[op];
    if (route === undefined) return awsError("UnknownOperationException", `no route for ${op}`);
    if (typeof route === "function") return route(req);
    if (Array.isArray(route)) {
      const i = counters.get(op) ?? 0;
      counters.set(op, i + 1);
      return route[Math.min(i, route.length - 1)] ?? {};
    }
    return route;
  });
  return Object.assign(server, {
    calls: (operation: string) => server.requests.filter((r) => operationOf(r) === operation),
  });
}

/** Test credentials (fake). */
export const TEST_KEYS = {
  accessKeyId: "AKIDUNITTEST0000",
  secretAccessKey: "unit-test-secret-access-key-value",
};

/** A client against a mock server with fast retries. */
export function clientFor(
  server: { url: string },
  options: AwsSecretsManagerConfigOptions = {},
): AwsSecretsManagerClient {
  return new AwsSecretsManagerClient({
    url: server.url,
    region: "us-east-1",
    ...TEST_KEYS,
    retry: { maxRetries: 0 },
    ...options,
  });
}
