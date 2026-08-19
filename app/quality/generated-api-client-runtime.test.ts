import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../apps/web/api/client";

describe("generated API client runtime boundary", () => {
  it("constructs without Fetch I/O and rejects remote servers", () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));
    const client = createAPIClient({ fetch });

    expect(client).toBeDefined();
    expect(fetch).not.toHaveBeenCalled();
    expect(() => createAPIClient({ baseUrl: "https://example.invalid", fetch })).toThrow("Invalid API client configuration");
  });
});
