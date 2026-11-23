import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { decodeDelegations } from "../../../apps/web/api/workload-delegations";
import { APIProvider } from "../../api/APIProvider";
import { WorkloadDelegations } from "./WorkloadDelegations";

const pid = (n: number) => "pid_11111111-1111-4111-8111-" + String(n).padStart(12, "0");
const [credential, parent, agent] = [1, 2, 3].map(pid);
const hop = { parent_agent_id: parent, child_agent_id: agent, depth: 1, max_depth: 2, expires_at: 1700000100,
  allowed_operations: ["draft_reply"], allowed_resources: ["inbox"] };
const receipt = { id: "1", parent_task_id: "reply-task", status: "verified", observed_at: "2023-11-14T22:14:00Z", grants: [hop] };
const page = { credential_id: credential, agent_id: agent, items: [receipt], truncated: false };

it("shows scoped signed evidence and distinguishes an unverified receipt", async () => {
  const get = vi.fn().mockResolvedValue({ response: new Response(), data: { ...page, items: [receipt,
    { ...receipt, id: "2", status: "delegation_unverified", grants: [] }] } });
  render(<APIProvider><WorkloadDelegations client={{GET: get} as unknown as APIClient} credential={credential} agent={agent} /></APIProvider>);
  expect(get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText("Task delegation receipts"));
  expect(await screen.findByText("draft_reply")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", {name:"Task owner"}));
  expect(screen.getByText(parent)).toBeInTheDocument();
  fireEvent.change(screen.getByRole("combobox", {name:"Receipt"}), {target:{value:"2"}});
  expect(screen.getByText("The workload presented no verifiable grant.")).toBeInTheDocument();
});

it("rejects another workload's page and an expanding or disconnected chain", () => {
  expect(() => decodeDelegations(page, credential, parent)).toThrow();
  for (const change of [{allowed_operations: ["send_reply"]}, {parent_agent_id: parent}, {expires_at: hop.expires_at + 120}]) {
    const next = {...hop, parent_agent_id: agent, child_agent_id: pid(4), depth: 2, ...change};
    expect(() => decodeDelegations({...page, agent_id: pid(4), items: [{...receipt, grants: [hop, next]}]}, credential, pid(4))).toThrow();
  }
});
