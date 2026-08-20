import { describe, expect, it, vi } from "vitest";

import { loadAllCursorPages } from "./pagination";

describe("bounded cursor pagination", () => {
  it("preserves each page boundary and follows only the returned continuation", async () => {
    const read = vi.fn(async (cursor?: string) => cursor === undefined
      ? { items: ["a", "b"], page_info: { has_more: true as const, next_cursor: "cursor-1" } }
      : { items: ["c"], page_info: { has_more: false as const, next_cursor: null } });

    const result = await loadAllCursorPages(read, { maximumItems: 10, maximumPages: 3 });

    expect(read.mock.calls).toEqual([[undefined], ["cursor-1"]]);
    expect(result.items).toEqual(["a", "b", "c"]);
    expect(result.pages.map((page) => page.page_info)).toEqual([
      { has_more: true, next_cursor: "cursor-1" },
      { has_more: false, next_cursor: null },
    ]);
  });

  it("fails closed on repeated cursors and item/page caps", async () => {
    await expect(loadAllCursorPages(async () => ({ items: ["a"], page_info: { has_more: true, next_cursor: "repeat" } }), { maximumItems: 10, maximumPages: 3 })).rejects.toThrow("repeated cursor");
    await expect(loadAllCursorPages(async () => ({ items: ["a", "b"], page_info: { has_more: false, next_cursor: null } }), { maximumItems: 1, maximumPages: 3 })).rejects.toThrow("item cap");
    let cursor = 0;
    await expect(loadAllCursorPages(async () => ({ items: [String(cursor)], page_info: { has_more: true, next_cursor: `cursor-${cursor += 1}` } }), { maximumItems: 10, maximumPages: 2 })).rejects.toThrow("page cap");
  });

  it("propagates cancellation without issuing a later page", async () => {
    const reason = new DOMException("scope changed", "AbortError");
    const read = vi.fn(async () => { throw reason; });
    await expect(loadAllCursorPages(read, { maximumItems: 10_000, maximumPages: 100 })).rejects.toBe(reason);
    expect(read).toHaveBeenCalledTimes(1);
  });
});
