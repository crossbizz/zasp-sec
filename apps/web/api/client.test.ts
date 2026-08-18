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
  it("exposes the exact immutable root component and identity-path types", () => {
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
    expectTypeOf<keyof paths>().toEqualTypeOf<
      | "/api/v1/admin/api-tokens"
      | "/api/v1/admin/api-tokens/{id}"
      | "/api/v1/admin/group-mappings"
      | "/api/v1/admin/members"
      | "/api/v1/admin/roles"
      | "/api/v1/admin/scim-connections"
      | "/api/v1/admin/scim-connections/{id}"
      | "/api/v1/admin/sso-connections"
      | "/api/v1/admin/sso-connections/{id}"
      | "/api/v1/admin/sso-connections/{id}/test"
      | "/api/v1/agents"
      | "/api/v1/agents/{id}"
      | "/api/v1/agents/{id}/capabilities"
      | "/api/v1/agents/{id}/relationships"
      | "/api/v1/agents/{id}/sessions"
      | "/api/v1/assets/{id}"
      | "/api/v1/attack-paths"
      | "/api/v1/attack-paths/{id}"
      | "/api/v1/attack-paths/{id}/break-options"
      | "/api/v1/attack-lab/runs"
      | "/api/v1/attack-lab/runs/{id}"
      | "/api/v1/attack-lab/runs/{id}/cancel"
      | "/api/v1/attack-lab/runs/{id}/rerun"
      | "/api/v1/audit-events"
      | "/api/v1/audit-exports"
      | "/api/v1/audit-exports/{id}"
      | "/api/v1/compliance/controls"
      | "/api/v1/compliance/evidence"
      | "/api/v1/compliance/exports"
      | "/api/v1/compliance/exports/{id}"
      | "/api/v1/environments"
      | "/api/v1/environments/{id}"
      | "/api/v1/findings"
      | "/api/v1/findings/{id}"
      | "/api/v1/findings/{id}/accept-risk"
      | "/api/v1/findings/{id}/ticket"
      | "/api/v1/home/summary"
      | "/api/v1/integration-catalog"
      | "/api/v1/integrations"
      | "/api/v1/integrations/{id}"
      | "/api/v1/integrations/{id}/authorize"
      | "/api/v1/integrations/{id}/sync"
      | "/api/v1/integrations/{id}/syncs"
      | "/api/v1/integrations/{id}/syncs/{syncId}"
      | "/api/v1/identities"
      | "/api/v1/identities/{id}"
      | "/api/v1/me"
      | "/api/v1/organization"
      | "/api/v1/policies"
      | "/api/v1/policies/{id}"
      | "/api/v1/policies/{id}/decisions"
      | "/api/v1/policies/{id}/disable"
      | "/api/v1/policies/{id}/rollout"
      | "/api/v1/policies/{id}/simulate"
      | "/api/v1/sensors"
      | "/api/v1/sensors/{id}"
      | "/api/v1/sensors/{id}/coverage"
      | "/api/v1/sensors/{id}/rotate-token"
      | "/api/v1/runtimes"
      | "/api/v1/runtimes/{id}"
      | "/api/v1/search"
      | "/api/v1/sessions"
      | "/api/v1/sessions/{id}"
      | "/api/v1/sessions/{id}/events"
      | "/api/v1/settings/data-controls"
      | "/api/v1/test-runs"
      | "/api/v1/test-runs/{id}"
      | "/api/v1/test-runs/{id}/cancel"
      | "/api/v1/tests"
      | "/api/v1/tests/{id}"
      | "/api/v1/tests/{id}/runs"
      | "/api/v1/tools"
      | "/api/v1/tools/{id}"
      | "/api/v1/workspaces"
      | "/api/v1/workspaces/{id}"
    >();
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
