import { MockAgent } from "undici";
import { afterEach, describe, expect, it } from "vitest";
import { AwsSecretsManagerClient, AwsSecretsManagerConfig, GrowHttpHandler } from "../src/index.js";
import { startServer, type MockServer } from "./helpers/server.js";
import { TEST_KEYS, fixture } from "./support/aws.js";

const servers: MockServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

describe("GrowHttpHandler", () => {
  it("sends query strings, ports and binary bodies; exposes Smithy handler API", async () => {
    const s = await startServer([
      { status: 201, body: "ok", headers: { "x-amz-request-id": "r2" } },
    ]);
    servers.push(s);
    const ids: (string | undefined)[] = [];
    const handler = new GrowHttpHandler({
      config: new AwsSecretsManagerConfig({ hooks: { onResponse: (i) => ids.push(i.requestId) } }),
    });
    const { response } = await handler.handle({
      method: "put",
      protocol: "http:",
      hostname: "127.0.0.1",
      port: s.port,
      path: "x",
      query: { a: "1", b: ["2", "3"], c: null as unknown as string },
      headers: {},
      body: new Uint8Array([1, 2]),
    });
    expect(response.statusCode).toBe(201);
    expect(new TextDecoder().decode(response.body as Uint8Array)).toBe("ok");
    expect(s.requests[0]?.url).toBe("/x?a=1&b=2&b=3");
    expect(s.requests[0]?.method).toBe("PUT");
    expect(s.requests[0]?.headers["user-agent"]).toBe(handler.userAgent);
    expect(ids).toEqual(["r2"]);
    expect(handler.httpHandlerConfigs()).toEqual({});
    handler.updateHttpClientConfig();
    expect(handler.metadata.handlerProtocol).toBe("http/1.1");
    handler.destroy();
    handler.destroy();
  });

  it("an already-aborted signal fails with AbortError; a destroyed injected dispatcher is left open", async () => {
    const agent = new MockAgent();
    agent.disableNetConnect();
    const handler = new GrowHttpHandler({
      config: new AwsSecretsManagerConfig(),
      dispatcher: agent,
    });
    const err = await handler
      .handle(
        { method: "POST", protocol: "http:", hostname: "example.invalid", path: "/", headers: {} },
        { abortSignal: AbortSignal.abort() },
      )
      .catch((e: unknown) => e);
    expect((err as Error).name).toBe("AbortError");
    handler.destroy();
    await agent.close();
  });

  it("works with an injected undici MockAgent through the client", async () => {
    const agent = new MockAgent();
    agent.disableNetConnect();
    const f = fixture("ping.ok");
    agent
      .get("http://asm.test")
      .intercept({ path: "/", method: "POST" })
      .reply(f.status ?? 200, typeof f.body === "string" ? f.body : JSON.stringify(f.body), {
        headers: f.headers ?? {},
      });
    const client = new AwsSecretsManagerClient(
      { url: "http://asm.test", region: "us-east-1", ...TEST_KEYS, retry: { maxRetries: 0 } },
      { dispatcher: agent },
    );
    expect(await client.ping()).toBeGreaterThanOrEqual(0);
    await client.close();
    await agent.close();
  });
});
