import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../apps/web/api/client";

describe("generated API client runtime boundary", () => {
  it("constructs without performing Fetch I/O or selecting a remote server", () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));

    const defaultClient = createAPIClient();

    const client = createAPIClient({
      baseUrl: "https://example.invalid",
      fetch,
    });

    expect(defaultClient).toBeDefined();
    expect(client).toBeDefined();
    expect(fetch).not.toHaveBeenCalled();
  });
});
