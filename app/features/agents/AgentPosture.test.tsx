import {render,screen} from "@testing-library/react";
import {expect,it} from "vitest";
import {APIProvider} from "../../api/APIProvider";
import type {AgentPostureSummary} from "../../../apps/web/api/generated";
import {decodeAgentPosture} from "../../../apps/web/api/agent-posture";
import {AgentPosture} from "./AgentPosture";

const agent="pid_11111111-1111-4111-8111-111111111111";
const posture: AgentPostureSummary = {agent_id:agent,deployment_kind:"repo_code",deployment_evidence:"repository",discovery_evidence_id:null,purpose_revision:0,allowed_tool_ids:[],access_known:false,granted_categories:[],last_observed_at:null,observed_evidence_id:null};
it("distinguishes unlinked code, unapproved purpose and missing runtime evidence",async () => {
  render(<APIProvider><AgentPosture agent={agent} capabilities={[]} getPosture={async () => posture}/></APIProvider>);
  expect(await screen.findByText("Repository code · awaiting deployment evidence")).toBeVisible();
  expect(screen.getByText("Awaiting a purpose declaration")).toBeVisible();
  expect(screen.getByText("Inventory coverage unavailable")).toBeVisible();
  expect(screen.getByText("No runtime activity with confirmed attribution")).toBeVisible();
});
it("rejects deployment claims without matching evidence",() => {
  expect(() => decodeAgentPosture({...posture,deployment_kind:"deployed_agent"},agent)).toThrow();
  expect(() => decodeAgentPosture({...posture,deployment_kind:"deployed_agent",deployment_evidence:"runtime_receipt"},agent)).toThrow();
});
