// Service-owned: the HTTP handler the AWS SDK client uses (SPEC §2.3 "Cloud SDK services").
//
// The AWS SDK signs, serialises, retries and parses; this handler only sends one attempt. It is
// built on undici with the dispatcher from the shared core (`createDispatcher`), so the Grow TLS
// (CA bundle, client certificate, insecureSkipVerify), proxy and connect-timeout settings apply
// to AWS calls exactly as they do to every other Grow client. It also adds the Grow User-Agent
// and extra headers (both unsigned, which SigV4 allows) and fires the SPEC §2.5 hooks.

import type { HttpHandlerOptions, HttpRequest, HttpResponse } from "@smithy/types";
import { type Dispatcher, fetch as undiciFetch } from "undici";
import {
  type ClientLogger,
  type CommonConfig,
  type Hooks,
  LANGUAGE,
  PACKAGE_KEY,
  SDK_VERSION,
  createDispatcher,
  redactHeaders,
  redactUrl,
  safeCall,
  safeLogger,
} from "./core/index.js";

/** Grow User-Agent product token: `grow-codes-aws-secrets-manager/<version> (typescript)`. */
export const GROW_USER_AGENT = `grow-codes-${PACKAGE_KEY}/${SDK_VERSION} (${LANGUAGE})`;

/** Options of {@link GrowHttpHandler}. */
export interface GrowHttpHandlerOptions {
  /** Resolved common configuration (timeouts, TLS, proxy, headers, hooks, logger). */
  config: CommonConfig;
  /** Test seam: replaces the dispatcher built from the TLS/proxy settings. */
  dispatcher?: Dispatcher;
}

/** Error raised when one attempt exceeds `requestTimeoutMs` (the SDK retries it). */
export class AttemptTimeoutError extends Error {
  /** Node-style code, recognised by the SDK retry strategy as a transient error. */
  readonly code = "ETIMEDOUT";
  constructor(ms: number) {
    super(`request timed out after ${ms} ms`);
    this.name = "TimeoutError";
  }
}

/** Parses `attempt=2; max=4` from the SDK's `amz-sdk-request` header. */
export function parseAttemptHeader(value: string | undefined): { attempt: number; max: number } {
  const attempt = /attempt=(\d+)/.exec(value ?? "")?.[1];
  const max = /max=(\d+)/.exec(value ?? "")?.[1];
  return {
    attempt: attempt === undefined ? 1 : Number(attempt),
    max: max === undefined ? 1 : Number(max),
  };
}

function buildUrl(request: HttpRequest): string {
  const port = request.port === undefined ? "" : `:${String(request.port)}`;
  const path = request.path.startsWith("/") ? request.path : `/${request.path}`;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(request.query ?? {})) {
    if (v === null) continue;
    for (const item of Array.isArray(v) ? v : [v]) params.append(k, item);
  }
  const qs = params.toString();
  return `${request.protocol}//${request.hostname}${port}${path}${qs === "" ? "" : `?${qs}`}`;
}

/**
 * One-attempt HTTP handler for the AWS SDK v3 client, on undici. Not used when the caller
 * passes its own SDK client (`sdkClient`).
 */
export class GrowHttpHandler {
  readonly #config: CommonConfig;
  readonly #hooks: Hooks;
  readonly #logger: ClientLogger;
  readonly #userAgent: string;
  #dispatcher: Dispatcher | undefined;
  readonly #ownsDispatcher: boolean;
  #destroyed = false;

  constructor(options: GrowHttpHandlerOptions) {
    this.#config = options.config;
    this.#hooks = options.config.hooks ?? {};
    this.#logger = safeLogger(options.config.logger);
    this.#dispatcher = options.dispatcher;
    this.#ownsDispatcher = options.dispatcher === undefined;
    const suffix = options.config.userAgentSuffix;
    this.#userAgent = GROW_USER_AGENT + (suffix !== undefined && suffix !== "" ? ` ${suffix}` : "");
  }

  /** The User-Agent token appended to the SDK's own User-Agent. */
  get userAgent(): string {
    return this.#userAgent;
  }

  /** Smithy handler metadata. */
  readonly metadata = { handlerProtocol: "http/1.1" };

  #getDispatcher(): Dispatcher {
    this.#dispatcher ??= createDispatcher(this.#config, this.#logger);
    return this.#dispatcher;
  }

  /** Sends one attempt. Called by the SDK (after signing) for every attempt. */
  async handle(
    request: HttpRequest,
    options: HttpHandlerOptions = {},
  ): Promise<{ response: HttpResponse }> {
    const url = buildUrl(request);
    const safeUrl = redactUrl(url);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(this.#config.headers)) headers[k.toLowerCase()] = v;
    for (const [k, v] of Object.entries(request.headers)) headers[k.toLowerCase()] = v;
    headers["user-agent"] =
      headers["user-agent"] === undefined
        ? this.#userAgent
        : `${headers["user-agent"]} ${this.#userAgent}`;
    const { attempt, max } = parseAttemptHeader(headers["amz-sdk-request"]);
    const method = request.method.toUpperCase();
    safeCall(this.#hooks.onRequest, {
      method,
      url: safeUrl,
      headers: redactHeaders(headers),
      attempt,
    });
    this.#logger.debug("aws-secrets-manager request", { method, url: safeUrl, attempt });

    const timeoutMs = options.requestTimeout ?? this.#config.requestTimeoutMs;
    const controller = new AbortController();
    const external = options.abortSignal as AbortSignal | undefined;
    const onAbort = (): void => {
      controller.abort(external?.reason);
    };
    if (external?.aborted === true) onAbort();
    else external?.addEventListener("abort", onAbort, { once: true });
    const state = { timedOut: false };
    const timer = setTimeout(() => {
      state.timedOut = true;
      controller.abort();
    }, timeoutMs);
    timer.unref();
    const start = performance.now();
    try {
      const res = await undiciFetch(url, {
        method,
        headers,
        ...(request.body === undefined || request.body === null
          ? {}
          : { body: request.body as string | Uint8Array }),
        signal: controller.signal,
        dispatcher: this.#getDispatcher(),
      });
      const body = new Uint8Array(await res.arrayBuffer());
      const responseHeaders: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });
      const requestId = responseHeaders["x-amzn-requestid"] ?? responseHeaders["x-amz-request-id"];
      safeCall(this.#hooks.onResponse, {
        method,
        url: safeUrl,
        status: res.status,
        durationMs: performance.now() - start,
        attempt,
        ...(requestId === undefined ? {} : { requestId }),
      });
      return {
        response: {
          statusCode: res.status,
          reason: res.statusText,
          headers: responseHeaders,
          body,
        },
      };
    } catch (err) {
      const error: Error =
        state.timedOut && external?.aborted !== true
          ? new AttemptTimeoutError(timeoutMs)
          : external?.aborted === true
            ? abortError()
            : toError(err);
      safeCall(this.#hooks.onError, {
        method,
        url: safeUrl,
        error,
        attempt,
        willRetry: external?.aborted !== true && attempt < max,
      });
      throw error;
    } finally {
      clearTimeout(timer);
      external?.removeEventListener("abort", onAbort);
    }
  }

  /** Smithy handler API (no runtime-updatable settings). */
  updateHttpClientConfig(): void {
    // settings come from the immutable Grow config
  }

  /** Smithy handler API. */
  httpHandlerConfigs(): Record<string, never> {
    return {};
  }

  /** Closes the dispatcher (only when this handler created it). Idempotent. */
  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    const dispatcher = this.#dispatcher;
    this.#dispatcher = undefined;
    if (dispatcher !== undefined && this.#ownsDispatcher) {
      dispatcher.close().catch(() => undefined);
    }
  }
}

function abortError(): Error {
  const err = new Error("Request aborted");
  err.name = "AbortError";
  return err;
}

function toError(err: unknown): Error {
  if (err instanceof Error) {
    // undici wraps socket errors: surface the Node code (ECONNREFUSED, …) for the SDK and mapping.
    const cause = err.cause as { code?: unknown; message?: unknown } | undefined;
    if (typeof cause?.code === "string") {
      const wrapped = new Error(typeof cause.message === "string" ? cause.message : err.message, {
        cause: err,
      }) as Error & { code: string };
      wrapped.code = cause.code;
      wrapped.name = cause.code;
      return wrapped;
    }
    return err;
  }
  return new Error(String(err));
}
