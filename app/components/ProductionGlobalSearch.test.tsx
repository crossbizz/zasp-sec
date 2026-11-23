import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { createAPIClient } from "../../apps/web/api/client";
import { ProductionGlobalSearch } from "./ProductionGlobalSearch";

const entity = "pid_10000004-0000-4000-8000-000000000004";
const scope = { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" };
afterEach(() => document.querySelector("#product-search-results")?.remove());

it("opens the exact scoped search result and keeps unavailable destinations read-only", async () => {
  const resultsHost = document.body.appendChild(document.createElement("div")); resultsHost.id = "product-search-results";
  const onNavigate = vi.fn();
  const client = createAPIClient({ fetch: async () => new Response(JSON.stringify({ items: [
    { id: entity, name: "Invoice finding", type: "finding" }, { id: entity, name: "Invoice tool", type: "tool" },
  ] }), { headers: { "Content-Type": "application/json" } }) });
  render(<ProductionGlobalSearch client={client} scope={scope} resultsHost={resultsHost} routes={[{ path: "/violations" }]} onNavigate={onNavigate} />);
  await userEvent.type(screen.getByRole("searchbox"), "Invoice");
  await userEvent.click(screen.getByRole("button", { name: "Search" }));
  const link = await screen.findByRole("link", { name: "Open Invoice finding" });
  const href = `/violations?entity_id=${entity}&organization_id=${scope.organizationID}&workspace_id=${scope.workspaceID}&environment_id=${scope.environmentID}`;
  expect(link).toHaveAttribute("href", href);
  expect(resultsHost).toContainElement(link);
  expect(screen.getByText("Invoice tool")).toBeVisible();
  expect(screen.queryByRole("link", { name: "Open Invoice tool" })).toBeNull();
  await userEvent.click(link);
  expect(onNavigate).toHaveBeenCalledWith(href);
  expect(resultsHost).toBeEmptyDOMElement();
});
