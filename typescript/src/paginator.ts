// Service-owned: auto-paginating async iterator for the AWS list operations.

/** Fetches one page: returns the items and the next token (`undefined` = last page). */
export type PageFetcher<T> = (
  nextToken: string | undefined,
) => Promise<{ items: T[]; nextToken: string | undefined }>;

/**
 * Lazily walks every page of an AWS list operation. Iterate with `for await`, or collect
 * everything with {@link toArray}. Each iteration starts again from the first page.
 */
export class Paginator<T> implements AsyncIterable<T> {
  readonly #fetch: PageFetcher<T>;

  constructor(fetch: PageFetcher<T>) {
    this.#fetch = fetch;
  }

  /** Yields one array per page. */
  async *pages(): AsyncGenerator<T[], void, undefined> {
    let token: string | undefined;
    const seen = new Set<string>();
    do {
      const page = await this.#fetch(token);
      yield page.items;
      token = page.nextToken;
      // Defensive: a service that repeats a token would loop forever.
      if (token !== undefined) {
        if (seen.has(token)) return;
        seen.add(token);
      }
    } while (token !== undefined);
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<T, void, undefined> {
    for await (const page of this.pages()) yield* page;
  }

  /** Collects every item of every page. */
  async toArray(): Promise<T[]> {
    const out: T[] = [];
    for await (const page of this.pages()) out.push(...page);
    return out;
  }
}
