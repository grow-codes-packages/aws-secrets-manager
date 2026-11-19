// Service-owned: maps AWS SDK errors to the SPEC §2.1 error classes by AWS error code
// (AWS JSON services answer 400 for throttling and access denied, so status mapping is wrong).

import {
  type AwsSecretsManagerError,
  ErrorCode,
  type KnownSecret,
  MAX_VENDOR_TEXT,
  codeForStatus,
  errorForCode,
  parseRetryAfter,
  reasonForCode,
  redactSecretsInText,
  redactText,
  isAwsSecretsManagerError,
} from "./core/index.js";

/** AWS error code → Grow {@link ErrorCode} (API.md §1.1). */
export const AWS_ERROR_CODES: Readonly<Record<string, ErrorCode>> = Object.freeze({
  ResourceNotFoundException: ErrorCode.NotFound,
  ResourceExistsException: ErrorCode.Conflict,
  PreconditionNotMetException: ErrorCode.Conflict,
  InvalidRequestException: ErrorCode.Conflict,
  InvalidParameterException: ErrorCode.Validation,
  InvalidParameterValue: ErrorCode.Validation,
  ValidationException: ErrorCode.Validation,
  InvalidNextTokenException: ErrorCode.Validation,
  MalformedPolicyDocumentException: ErrorCode.Validation,
  PublicPolicyException: ErrorCode.Validation,
  LimitExceededException: ErrorCode.Validation,
  EncryptionFailure: ErrorCode.Validation,
  DecryptionFailure: ErrorCode.Validation,
  SerializationException: ErrorCode.Validation,
  AccessDeniedException: ErrorCode.PermissionDenied,
  AccessDenied: ErrorCode.PermissionDenied,
  UnrecognizedClientException: ErrorCode.Authentication,
  InvalidClientTokenId: ErrorCode.Authentication,
  InvalidSignatureException: ErrorCode.Authentication,
  SignatureDoesNotMatch: ErrorCode.Authentication,
  IncompleteSignature: ErrorCode.Authentication,
  IncompleteSignatureException: ErrorCode.Authentication,
  MissingAuthenticationToken: ErrorCode.Authentication,
  MissingAuthenticationTokenException: ErrorCode.Authentication,
  ExpiredToken: ErrorCode.Authentication,
  ExpiredTokenException: ErrorCode.Authentication,
  InvalidAccessKeyId: ErrorCode.Authentication,
  CredentialsProviderError: ErrorCode.Authentication,
  ThrottlingException: ErrorCode.RateLimited,
  Throttling: ErrorCode.RateLimited,
  TooManyRequestsException: ErrorCode.RateLimited,
  RequestLimitExceeded: ErrorCode.RateLimited,
  InternalServiceError: ErrorCode.Unavailable,
  InternalServiceErrorException: ErrorCode.Unavailable,
  InternalFailure: ErrorCode.Unavailable,
  ServiceUnavailable: ErrorCode.Unavailable,
  ServiceUnavailableException: ErrorCode.Unavailable,
  RequestTimeout: ErrorCode.Timeout,
  RequestTimeoutException: ErrorCode.Timeout,
  TimeoutError: ErrorCode.Timeout,
});

/** Node/undici network error codes → {@link ErrorCode}. */
const NETWORK_TIMEOUT_CODES: ReadonlySet<string> = new Set([
  "ETIMEDOUT",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
]);

/** Options of {@link mapAwsError}. */
export interface MapErrorOptions {
  /** Credential values redacted from the message. */
  knownSecrets?: Iterable<KnownSecret>;
  /**
   * The operation is known to be missing from some emulators: a non-JSON HTTP 500 answer then
   * maps to `UNSUPPORTED` instead of `UNAVAILABLE` (Moto 5.2.4 `ValidateResourcePolicy`).
   */
  unsupportedOnHtml500?: boolean;
}

interface SdkErrorShape {
  name?: unknown;
  message?: unknown;
  code?: unknown;
  $fault?: unknown;
  $metadata?: { httpStatusCode?: number; requestId?: string };
  $response?: { statusCode?: number; headers?: Record<string, string>; body?: unknown };
}

function bodyText(body: unknown): string {
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  return "";
}

/** Extracts an error code from an XML (`<Code>`) or JSON (`__type`) error body. */
export function errorCodeFromBody(text: string): string | undefined {
  const xml = /<Code>\s*([^<\s]+)\s*<\/Code>/.exec(text)?.[1];
  if (xml !== undefined) return xml;
  try {
    const parsed = JSON.parse(text) as { __type?: unknown; code?: unknown };
    const raw = typeof parsed.__type === "string" ? parsed.__type : parsed.code;
    if (typeof raw === "string") return raw.split("#").pop()?.split(":")[0];
  } catch {
    // not JSON
  }
  return undefined;
}

function cleanVendorText(text: string, knownSecrets: Iterable<KnownSecret>): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  const redacted = redactSecretsInText(redactText(collapsed, knownSecrets));
  return redacted.length > MAX_VENDOR_TEXT ? `${redacted.slice(0, MAX_VENDOR_TEXT)}…` : redacted;
}

function nodeCode(err: unknown): string | undefined {
  let current: unknown = err;
  for (let depth = 0; depth < 5 && current !== undefined && current !== null; depth++) {
    const code = (current as { code?: unknown }).code;
    if (typeof code === "string") return code;
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

/**
 * Converts anything the AWS SDK throws into an SDK error (`AwsSecretsManagerError` subclass) with
 * the message `"<operation>: <AwsCode>: <redacted vendor text> (HTTP <status>)"`.
 */
export function mapAwsError(
  err: unknown,
  operation: string,
  options: MapErrorOptions = {},
): AwsSecretsManagerError {
  if (isAwsSecretsManagerError(err)) return err;
  const known = [...(options.knownSecrets ?? [])];
  const e = (typeof err === "object" && err !== null ? err : {}) as SdkErrorShape;
  const name = typeof e.name === "string" ? e.name : "";
  const message = typeof e.message === "string" ? e.message : String(err);
  const status = e.$metadata?.httpStatusCode ?? e.$response?.statusCode;
  const requestId = e.$metadata?.requestId;
  const details = {
    ...(status === undefined ? {} : { httpStatus: status }),
    ...(requestId === undefined ? {} : { requestId }),
    cause: err,
  };
  const suffix = status === undefined ? "" : ` (HTTP ${String(status)})`;

  if (name === "AbortError") {
    return errorForCode(ErrorCode.Cancelled, `${operation}: cancelled`, { cause: err });
  }
  if (/Region is missing|Region not accepted/i.test(message)) {
    return errorForCode(
      ErrorCode.Config,
      `${operation}: no AWS region configured (set region or AWS_REGION)`,
      { cause: err },
    );
  }

  if (status !== undefined) {
    const parsed = e.$fault !== undefined && name !== "" ? name : undefined;
    const raw = bodyText(e.$response?.body);
    const awsCode = parsed ?? errorCodeFromBody(raw);
    let code = awsCode === undefined ? undefined : AWS_ERROR_CODES[awsCode];
    if (code === undefined) {
      if (status === 403) {
        code = /InvalidClientTokenId|SignatureDoesNotMatch|security token/i.test(raw)
          ? ErrorCode.Authentication
          : ErrorCode.PermissionDenied;
      } else if (status === 500 && options.unsupportedOnHtml500 === true && /<html/i.test(raw)) {
        code = ErrorCode.Unsupported;
      } else {
        code = codeForStatus(status);
      }
    }
    const vendor = parsed !== undefined ? cleanVendorText(message, known) : "";
    const reason =
      awsCode === undefined
        ? reasonForCode(code)
        : vendor === ""
          ? awsCode
          : `${awsCode}: ${vendor}`;
    const retryAfterRaw = e.$response?.headers?.["retry-after"];
    const retryAfterMs =
      code === ErrorCode.RateLimited && retryAfterRaw !== undefined
        ? parseRetryAfter(retryAfterRaw)
        : undefined;
    return errorForCode(code, `${operation}: ${reason}${suffix}`, {
      ...details,
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    });
  }

  const mappedByName = AWS_ERROR_CODES[name];
  if (mappedByName !== undefined) {
    const text = cleanVendorText(message, known);
    return errorForCode(
      mappedByName,
      `${operation}: ${reasonForCode(mappedByName)}: ${text}`,
      details,
    );
  }
  const net = nodeCode(err);
  if (net !== undefined && NETWORK_TIMEOUT_CODES.has(net)) {
    return errorForCode(ErrorCode.Timeout, `${operation}: timed out (${net})`, details);
  }
  const text = cleanVendorText(message, known);
  return errorForCode(
    ErrorCode.Unavailable,
    `${operation}: service unavailable: ${net === undefined ? text : `${net}: ${text}`}`,
    details,
  );
}
