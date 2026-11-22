import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { APIProvider } from "../../api/APIProvider";
import { TicketVerification } from "./TicketVerification";

const id = "pid_71000001-0000-4000-8000-000000000001";
const receipt = { schema_version: 1, evidence_source: "operator_import", definition_version: 2, policy_revision: "ticket-rev-2", target_id: id, submitted_by: id, submitted_at: "2026-01-01T00:00:00Z", evidence_sha256: "a".repeat(64), result: { verification_mode:"side_effect_verified", run_id:id, verdict:"unexpected_effect", reason:"protected_write_recorded", protected_receipt_id:"ticket-42" } };
function show(status: number, data?: unknown, canWrite = true) {
  const get = vi.fn(async () => ({response:new Response(null,{status}),data}));
  const put = vi.fn(async () => ({response:new Response(null,{status:200}),data:receipt}));
  render(<APIProvider client={{GET:get,PUT:put} as unknown as APIClient}><TicketVerification runID={id} canWrite={canWrite} locked={false} /></APIProvider>);
  return {get,put};
}
describe("ticket proof run detail",()=>{
  it("reads immutable operator evidence explicitly and never offers to overwrite it", async()=>{
    const {get,put}=show(200,receipt); expect(get).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button",{name:"View ticket proof"}));
    expect(await screen.findByText("unexpected_effect")).toBeVisible();
    expect(screen.getByText("ticket-42")).toBeVisible();
    expect(screen.queryByText("Import ticket proof")).toBeNull();
    expect(put).not.toHaveBeenCalled();
  });
  it("provides read-only reviewers the missing evidence state",async()=>{
    show(404,undefined,false);await userEvent.click(screen.getByRole("button",{name:"View ticket proof"}));
    expect(await screen.findByText(/no imported ticket proof/)).toBeVisible();
    expect(screen.queryByLabelText("Adapter decisions")).toBeNull();
  });
  it("requires three independently captured exports before saving",async()=>{
    const {put}=show(404); const user=userEvent.setup(); await user.click(screen.getByRole("button",{name:"View ticket proof"}));
    const submit=await screen.findByRole("button",{name:"Import ticket proof"});expect(submit).toBeDisabled();
    for (const label of ["Pinned scenario","Adapter decisions","Independent recorder readback"]) await user.upload(screen.getByLabelText(label),new File(["{}"],"export.json",{type:"application/json"}));
    expect(submit).toBeEnabled();await user.click(submit);
    expect(await screen.findByText("unexpected_effect")).toBeVisible();
    expect(put).toHaveBeenCalledTimes(1);
  });
});
