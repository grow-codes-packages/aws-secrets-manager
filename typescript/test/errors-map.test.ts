import { describe, expect, it } from "vitest";
import {
  AWS_ERROR_CODES,
  AttemptTimeoutError,
  NotFoundError,
  errorCodeFromBody,
  mapAwsError,
} from "../src/index.js";
import { parseAttemptHeader } from "../src/http-handler.js";

function sdkError(
  name: string,
  status: number | undefined,
  extra: Record<string, unknown> = {},
): Error {
  const e = new Error(`${name} message`) as Error & Record<string, unknown>;
  e.name = name;
  if (status !== undefined) e.$metadata = { httpStatusCode: status, requestId: "rid" };
  Object.assign(e, extra);
  return e;
}

describe("mapAwsError (core.errors.mapping for AWS codes)", () => {
  it("maps every documented AWS code", () => {
    for (const [awsCode, code] of Object.entries(AWS_ERROR_CODES)) {
      const err = mapAwsError(sdkError(awsCode, 400, { $fault: "client" }), "op");
      expect(err.code, awsCode).toBe(code);
      expect(err.httpStatus).toBe(400);
      expect(err.requestId).toBe("rid");
      expect(err.message).toBe(`op: ${awsCode}: ${awsCode} message (HTTP 400)`);
    }
  });

  it("falls back to the HTTP status for unknown codes and unparsed bodies", () => {
    const cases: [number, string][] = [
      [400, "VALIDATION"],
      [401, "AUTHENTICATION"],
      [404, "NOT_FOUND"],
      [409, "CONFLICT"],
      [412, "CONFLICT"],
      [413, "VALIDATION"],
      [422, "VALIDATION"],
      [429, "RATE_LIMITED"],
      [500, "UNAVAILABLE"],
      [501, "UNSUPPORTED"],
      [502, "UNAVAILABLE"],
      [503, "UNAVAILABLE"],
      [504, "TIMEOUT"],
    ];
    for (const [status, code] of cases) {
      const err = mapAwsError(sdkError("SyntaxError", status), "op");
      expect(err.code, String(status)).toBe(code);
      expect(err.message).toMatch(new RegExp(`^op: .+ \\(HTTP ${String(status)}\\)$`));
    }
    expect(mapAwsError(sdkError("Weird", 400, { $fault: "client" }), "op").code).toBe("VALIDATION");
  });

  it("reads XML and JSON error codes from the raw body (Moto IAM errors)", () => {
    const xml = (code: string): Record<string, unknown> => ({
      $response: {
        statusCode: 403,
        body: new TextEncoder().encode(
          `<ErrorResponse><Error><Code>${code}</Code></Error></ErrorResponse>`,
        ),
      },
    });
    expect(mapAwsError(sdkError("SyntaxError", 403, xml("InvalidClientTokenId")), "op").code).toBe(
      "AUTHENTICATION",
    );
    expect(mapAwsError(sdkError("SyntaxError", 403, xml("AccessDenied")), "op").code).toBe(
      "PERMISSION_DENIED",
    );
    const heuristic = (body: string): string =>
      mapAwsError(sdkError("SyntaxError", 403, { $response: { body } }), "op").code;
    expect(heuristic("<Code>Odd</Code> The security token included is invalid")).toBe(
      "AUTHENTICATION",
    );
    expect(heuristic("<Code>Odd</Code> nope")).toBe("PERMISSION_DENIED");
    expect(heuristic("")).toBe("PERMISSION_DENIED");
    expect(
      errorCodeFromBody('{"__type":"com.amazonaws.secretsmanager#ResourceNotFoundException"}'),
    ).toBe("ResourceNotFoundException");
    expect(errorCodeFromBody('{"code":"ThrottlingException:extra"}')).toBe("ThrottlingException");
    expect(errorCodeFromBody('{"other":1}')).toBeUndefined();
    expect(errorCodeFromBody("not json")).toBeUndefined();
    expect(mapAwsError(sdkError("SyntaxError", 400, { $response: { body: 42 } }), "op").code).toBe(
      "VALIDATION",
    );
  });

  it("HTML 500 is UNSUPPORTED only for operations emulators lack", () => {
    const html = { $response: { body: "<!doctype html><html><title>500</title></html>" } };
    expect(mapAwsError(sdkError("SyntaxError", 500, html), "op").code).toBe("UNAVAILABLE");
    expect(
      mapAwsError(sdkError("SyntaxError", 500, html), "op", { unsupportedOnHtml500: true }).code,
    ).toBe("UNSUPPORTED");
  });

  it("rate limits carry Retry-After", () => {
    const err = mapAwsError(
      sdkError("ThrottlingException", 400, {
        $fault: "client",
        $response: { headers: { "retry-after": "3" } },
      }),
      "op",
    );
    expect(err.retryAfterMs).toBe(3000);
    expect(err.retryable).toBe(true);
  });

  it("errors without a response: abort, region, credentials, timeouts, network, unknown", () => {
    const abort = new Error("aborted");
    abort.name = "AbortError";
    expect(mapAwsError(abort, "op").code).toBe("CANCELLED");
    expect(mapAwsError(new Error("Region is missing"), "op").code).toBe("CONFIG");
    expect(mapAwsError(sdkError("CredentialsProviderError", undefined), "op").code).toBe(
      "AUTHENTICATION",
    );
    expect(mapAwsError(new AttemptTimeoutError(5), "op").code).toBe("TIMEOUT");
    const connectTimeout = new Error("x", { cause: { code: "UND_ERR_CONNECT_TIMEOUT" } });
    expect(mapAwsError(connectTimeout, "op").code).toBe("TIMEOUT");
    const refused = Object.assign(new Error("connect refused"), { code: "ECONNREFUSED" });
    const mapped = mapAwsError(refused, "op");
    expect(mapped.code).toBe("UNAVAILABLE");
    expect(mapped.message).toContain("ECONNREFUSED");
    expect(mapAwsError("a string", "op").code).toBe("UNAVAILABLE");
    expect(mapAwsError(null, "op").code).toBe("UNAVAILABLE");
    const already = new NotFoundError("x");
    expect(mapAwsError(already, "op")).toBe(already);
  });

  it("core.redaction.error-text: known secrets and secret-like pairs never reach the message", () => {
    const secret = "super-secret-value-123";
    const err = mapAwsError(
      sdkError("InvalidParameterException", 400, {
        $fault: "client",
        message: `bad   value ${secret} password=hunter22   ${"x".repeat(400)}`,
      }),
      "op",
      { knownSecrets: [secret] },
    );
    expect(err.message).not.toContain(secret);
    expect(err.message).not.toContain("hunter22");
    expect(err.message).not.toContain("  ");
    expect(err.message.length).toBeLessThan(400);
    expect(err.message).toContain("…");
  });

  it("parseAttemptHeader", () => {
    expect(parseAttemptHeader("attempt=2; max=4")).toEqual({ attempt: 2, max: 4 });
    expect(parseAttemptHeader(undefined)).toEqual({ attempt: 1, max: 1 });
  });
});
