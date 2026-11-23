import { useEffect, type ReactNode } from "react";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../apps/web/api/client";
import type { SearchResult } from "../../apps/web/api/generated";
import { APIProvider, useAPI } from "../api/APIProvider";
import { activityLink } from "../domain/activity-links";
import { ProductionGlobalSearch } from "./ProductionGlobalSearch";

const id = (n: number) => `pid_0000000${n}-0000-4000-8000-00000000000${n}`;
const scope = { organizationID: id(1), workspaceID: id(2), environmentID: id(3) };
const row = (type: SearchResult["type"]) => ({ type, id: id(4), name: "Example result" });
const ok = (items: SearchResult[]) => ({ data: { items }, response: new Response() });
function QueryScope({ children }: { children: ReactNode }) {
  const { setQueryScope } = useAPI();
  useEffect(() => setQueryScope("search-test"), [setQueryScope]);
  return children;
}
function mount(get: ReturnType<typeof vi.fn>) {
  const navigate = vi.fn();
  render(<APIProvider><QueryScope><ProductionGlobalSearch client={{ GET: get } as unknown as APIClient} scope={scope} onNavigate={navigate} /><button>Outside search</button></QueryScope></APIProvider>);
  return { navigate, user: userEvent.setup(), input: screen.getByRole("searchbox") };
}

describe("Production global search", () => {
  it.each([
    ["agent", "/discovery/assets"], ["tool", "/inventory/tools"],
    ["identity", "/identities"], ["runtime", "/inventory/runtimes"], ["finding", "/violations"],
  ] as const)("opens the exact %s record", async (type, route) => {
    const { navigate, user, input } = mount(vi.fn().mockResolvedValue(ok([row(type)])));
    await user.type(input, "Example{enter}");
    await user.click(await screen.findByRole("button", { name: "Open Example result" }));
    expect(navigate).toHaveBeenCalledWith(type === "finding" ? activityLink({ kind: "finding", id: id(4) }, scope) : `${route}?inventory=${id(4)}`);
  });

  it("cancels superseded reads and dismisses pending or visible results", async () => {
    let finish!: (response: ReturnType<typeof ok>) => void;
    const get = vi.fn().mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })).mockResolvedValue(ok([row("tool")]));
    const { user, input } = mount(get);
    await user.type(input, "A{enter}");
    expect(get).not.toHaveBeenCalled();
    await user.type(input, "b{enter}");
    await user.type(input, "c");
    expect(get.mock.calls[0][1].signal.aborted).toBe(true);
    await act(async () => { finish(ok([row("agent")])); });
    expect(screen.queryByRole("button", { name: "Open Example result" })).toBeNull();
    await user.keyboard("{Enter}");
    const result = await screen.findByRole("button", { name: "Open Example result" });
    result.focus();
    await user.keyboard("{Escape}");
    expect(input).toHaveFocus();
    expect(input).toHaveValue("Abc");
    expect(result).not.toBeInTheDocument();
    await user.keyboard("{Enter}");
    await screen.findByRole("button", { name: "Open Example result" });
    await user.click(screen.getByRole("button", { name: "Outside search" }));
    expect(screen.queryByRole("button", { name: "Open Example result" })).toBeNull();
  });

  it("reads a generic asset from its own authorized detail endpoint", async () => {
    const get = vi.fn().mockResolvedValueOnce(ok([row("asset")])).mockRejectedValueOnce(new Error("Unavailable"));
    const { user, input, navigate } = mount(get);
    await user.type(input, "Example{enter}");
    await user.click(await screen.findByRole("button", { name: "Open Example result" }));
    expect(await screen.findByRole("dialog", { name: "Example result" })).toBeVisible();
    expect(await screen.findByRole("alert")).toHaveTextContent("Asset details could not be refreshed");
    expect(get).toHaveBeenLastCalledWith("/api/v1/assets/{id}", expect.objectContaining({ params: { path: { id: id(4) } } }));
    expect(navigate).not.toHaveBeenCalled();
  });
});
