import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { EndpointPolicyCohort } from "./EndpointPolicyCohort";

const id = "pid_00000000-0000-4000-8000-000000000001";
const scope = [id,id,id].join("/");
const cohort = "support-canary";
const planned = { id:"approved-tools",type:"mcp_tool_policy",match:"allowlist",values:["mcp__support__create_ticket"],allowed_destinations:["support.example.com"] };
const empty = { cohort,revision:0,mode:"monitor",failure_mode:"open",rules:[] };
function service(conflict = false, existing = false) {
  const calls: Array<Pick<Request, "method" | "url" | "headers" | "json">> = [];
  const client = createAPIClient({ getExpectedScope:()=>scope,getCSRFToken:()=>"c".repeat(32),fetch:async req => {
    calls.push(req.clone());
    const err = {code:"revision_conflict",message:"Conflict",retryable:false,correlation_id:id};
    const response = req.method==="GET" ? existing ? {...empty,revision:1,rules:[planned]} : empty : conflict ? err : {...empty,revision:1,rules:[planned]};
    return new Response(JSON.stringify(response),{status:req.method==="PUT"&&conflict?409:200,headers:{"Content-Type":"application/json"}});
  } });
  return { client,calls };
}
async function load() {
  await userEvent.type(screen.getByLabelText("Endpoint policy cohort"),cohort);
  await userEvent.click(screen.getByRole("button",{name:"Load template"}));
  return screen.findByRole("region",{name:"Cohort template rules"});
}

describe("managed cohort pre-tool policy",()=>{
  it("saves an exact, revision-bound MCP rule without issuing it to a device",async()=>{
    const { client,calls }=service();
    render(<EndpointPolicyCohort client={client} canManage fresh reauthenticate={vi.fn()}/>);
    expect(calls).toHaveLength(0);
    await load();
    const save=screen.getByRole("button",{name:"Save cohort template"});
    expect(save).toBeDisabled();
    await userEvent.click(screen.getByRole("button",{name:"Add rule"}));
    await userEvent.type(screen.getByLabelText("Rule ID"),planned.id);
    await userEvent.selectOptions(screen.getByLabelText("Match"),"allowlist");
    await userEvent.type(screen.getByLabelText("Tool names"),planned.values[0]);
    await userEvent.type(screen.getByLabelText("Allowed destinations (optional)"),planned.allowed_destinations[0]);
    await userEvent.click(save);
    expect(await screen.findByText("Saved template revision 1.")).toBeVisible();
    expect(calls.map(req=>req.method)).toEqual(["GET","PUT"]);
    expect(new URL(calls[1].url).pathname).toBe("/api/v1/device-cohorts/support-canary/pretool-policy");
    expect(calls[1].headers.get("X-Zasp-Expected-Scope")).toEqual(scope);
    expect(calls[1].headers.get("Idempotency-Key")).toBeTruthy();
    expect(await calls[1].json()).toEqual({expected_revision:0,mode:"monitor",failure_mode:"open",rules:[planned]});
  });

  it("keeps a stale revision or an expired session from replacing the cohort template",async()=>{
    const { client,calls }=service(true,true);
    const view=render(<EndpointPolicyCohort client={client} canManage fresh reauthenticate={vi.fn()}/>);
    await load();
    await userEvent.selectOptions(screen.getByLabelText("Policy mode"),"enforce");
    await userEvent.click(screen.getByRole("button",{name:"Save cohort template"}));
    expect(await screen.findByRole("alert")).toHaveTextContent("revision changed");
    expect(screen.getByRole("button",{name:"Save cohort template"})).toBeDisabled();
    view.rerender(<EndpointPolicyCohort key="restarted" client={client} canManage fresh={false} reauthenticate={vi.fn()}/>);
    await load();
    expect(screen.getByRole("button",{name:"Save cohort template"})).toBeDisabled();
    expect(calls.filter(req=>req.method==="PUT")).toHaveLength(1);
  });

  it("reveals a saved template to an authorized read-only reviewer without mutation controls",async()=>{
    const { client,calls }=service(false,true);
    render(<EndpointPolicyCohort client={client} canManage={false} fresh reauthenticate={vi.fn()}/>);
    const detail=await load();
    expect(within(detail).getByLabelText("Tool names")).toHaveValue(planned.values[0]);
    expect(within(detail).getByLabelText("Policy mode")).toBeDisabled();
    expect(screen.queryByRole("button",{name:"Save cohort template"})).toBeNull();
    expect(calls).toHaveLength(1);
  });
});
