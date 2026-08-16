import { describe, expect, expectTypeOf, it, vi } from "vitest";

import { createAPIClient } from "./client";
import type { ProductID } from "./client";
import type {
  Cursor,
  PageInfo,
  paths,
  ProductError,
} from "./generated";

function assertProductErrorIsReadonly(value: ProductError) {
  // @ts-expect-error -- generated state is immutable by contract.
  value.code = "changed";
}

describe("generated API client", () => {
  it("exposes the exact immutable root component types and no current operations", () => {
    const correlationID = "pid_12345678-1234-4123-8123-123456789abc" as ProductID;
    const cursor = "YQ" as Cursor;
    const error: ProductError = {
      code: "invalid_request",
      message: "Request rejected",
      correlation_id: correlationID,
      retryable: false,
    };
    const continuingPage: PageInfo = { next_cursor: cursor, has_more: true };
    const finalPage: PageInfo = { next_cursor: null, has_more: false };

    expect(error).toEqual({
      code: "invalid_request",
      message: "Request rejected",
      correlation_id: correlationID,
      retryable: false,
    });
    expect(continuingPage.has_more).toBe(true);
    expect(finalPage.has_more).toBe(false);
    expectTypeOf<paths>().toEqualTypeOf<Record<string, never>>();
    expectTypeOf(error.code).toEqualTypeOf<string>();

    expect(assertProductErrorIsReadonly).toBeTypeOf("function");
  });

  it("constructs the typed Fetch client without performing I/O", () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));
    const client = createAPIClient({
      baseUrl: "https://example.invalid",
      fetch,
    });

    expect(client).toBeDefined();
    expect(fetch).not.toHaveBeenCalled();
  });
});
