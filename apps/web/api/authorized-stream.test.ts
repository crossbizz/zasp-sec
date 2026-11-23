import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "./client";

const pid = (n: number) => "pid_10000000-0000-4000-8000-" + String(n).padStart(12, "0");
const scope = [pid(1), pid(2), pid(3)].join("/");
function fixture(payload: string, limit = 4096, mime = "text/event-stream") {
  let current = scope;
  const fetch = vi.fn(async (_request: Request) => new Response(payload, { headers: {
    "Content-Type": mime, "Cache-Control": "no-store", "x-vercel-ai-ui-message-stream": "v1",
  } }));
  const client = createAPIClient({ fetch, maximumResponseBytes: limit, getExpectedScope: () => current, getCSRFToken: () => "z".repeat(32) });
  const open = (approval: readonly ("inspect_session"|"external_inventory_status")[]=[]) => client.openAuthorizedEventStream(pid(4), pid(5), "Which attempts were prevented?", pid(6), undefined, approval);
  return { open, fetch, switchScope: () => { current = [pid(1),pid(2),pid(7)].join("/"); } };
}
describe("scoped analyst event stream", () => {
  it("sends only the question and request ID to its canonical same-origin endpoint", async () => {
    const f = fixture("data: [DONE]\n\n");
    expect(await (await f.open()).text()).toBe("data: [DONE]\n\n");
    const request = f.fetch.mock.calls[0][0];
    expect(request.headers.get("X-Zasp-Expected-Scope")).toBe(scope);
    expect(request.headers.get("X-CSRF-Token")).toBe("z".repeat(32));
    expect(request.headers.get("X-Correlation-ID")).toMatch(/^pid_/);
    expect(request.redirect).toBe("error");
    expect(new URL(request.url).origin).toBe(window.location.origin);
    expect(await request.json()).toEqual({message:"Which attempts were prevented?",request_id:pid(6)});
  });
  it("includes the single native read grant only on an approved question", async () => {
    const f=fixture("data: [DONE]\n\n");
    await (await f.open(["inspect_session"])).text();
    expect(await f.fetch.mock.calls[0][0].json()).toEqual({message:"Which attempts were prevented?",request_id:pid(6),approved_read_tools:["inspect_session"]});
    await (await f.open(["external_inventory_status"])).text();
    expect(await f.fetch.mock.calls[1][0].json()).toHaveProperty("approved_read_tools",["external_inventory_status"]);
    await (await f.open()).text();
    expect(await f.fetch.mock.calls[2][0].json()).not.toHaveProperty("approved_read_tools");
  });
  it("rejects a wrong media type, oversized body and a caller without scope", async () => {
    await expect(fixture("payload",4096,"text/html").open()).rejects.toThrow();
    await expect((await fixture("a".repeat(4097)).open()).text()).rejects.toThrow();
    const fetch = vi.fn();
    await expect(createAPIClient({fetch}).openAuthorizedEventStream(pid(4),pid(5),"question",pid(6))).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});
