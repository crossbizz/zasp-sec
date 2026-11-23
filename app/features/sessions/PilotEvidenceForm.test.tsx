import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { PilotEvidenceForm, pilotSelection } from "./PilotEvidenceForm";

const env="pid_30000000-0000-4000-8000-000000000001", device="pid_40000000-0000-4000-8000-000000000001";
const ref="a".repeat(64);
const client={GET:vi.fn(async()=>({data:{items:[],next_after_id:null,counts:{expected:0,enrolled:0,online:0,acknowledged:0}},response:new Response(null,{status:200})}))} as unknown as APIClient;
describe("managed pilot evidence selection",()=>{
  it("opens the CLI's exact device session without submitting until the browser user confirms",async()=>{
    window.history.replaceState({}, "", "/compliance/evidence#"+new URLSearchParams({pilot_environment:env,device_id:device,endpoint_session_ref:ref}));
    const create=vi.fn();
    render(<PilotEvidenceForm environmentID={env} client={client} fresh busy={false} create={create}/>);
    const submit=await screen.findByRole("button",{name:"Request retained pilot report"});
    expect(create).not.toHaveBeenCalled(); expect(screen.getByLabelText("Device ID")).toHaveValue(device);
    fireEvent.click(submit);
    expect(create).toHaveBeenCalledWith({device_id:device,endpoint_session_ref:ref});
  });
  it("rejects a different Environment before reading devices or offering a download",async()=>{
    window.history.replaceState({}, "", "/compliance/evidence#pilot_environment="+device+"&device_id="+device);
    const create=vi.fn();
    render(<PilotEvidenceForm environmentID={env} client={client} fresh busy={false} create={create}/>);
    await screen.findByRole("alert");
    expect(screen.queryByRole("button",{name:"Request retained pilot report"})).not.toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
  });
  it("requires closed selectors and fresh authentication",async()=>{
    window.history.replaceState({}, "", "/compliance/evidence");
    render(<PilotEvidenceForm environmentID={env} client={client} fresh={false} busy={false} create={vi.fn()}/>);
    fireEvent.click(screen.getByRole("button",{name:"Export managed pilot evidence"}));
    fireEvent.change(screen.getByLabelText("Cohort"),{target:{value:"pilot-a"}});
    expect(screen.getByRole("button",{name:"Request retained pilot report"})).toBeDisabled();
    expect(pilotSelection("cohort","/bad","","")).toBeUndefined();
    expect(pilotSelection("session","","",ref)).toBeUndefined();
  });
});
