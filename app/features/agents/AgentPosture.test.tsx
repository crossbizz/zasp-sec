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
it("displays only post-sync results cited to the current discovery",async () => {
  const evidence="pid_22222222-2222-4222-8222-222222222222";
  const review={purpose:"agent_discovery_verify",state:"reviewed",evidence_id:evidence,result:{kind:"simple_llm_app",evidence_refs:[evidence]}} as const;
  const raw={...posture,discovery_evidence_id:evidence,sync_reviews:[review]};
  const supported=decodeAgentPosture(raw,agent);
  render(<APIProvider><AgentPosture agent={agent} capabilities={[]} getPosture={async () => supported}/></APIProvider>);
  expect(await screen.findByText(/simple llm app/)).toBeVisible();
  expect(() => decodeAgentPosture({...raw,sync_reviews:[{...review,result:{kind:"simple_llm_app",evidence_refs:[agent]}}]},agent)).toThrow();
});
