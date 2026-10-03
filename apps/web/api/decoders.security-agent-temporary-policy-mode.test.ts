import { describe, expect, it } from "vitest";
import { decodeSecurityAgentRunDetail, decodeSecurityAgentDefinition, decodeSecurityAgentApproval } from "./decoders";

const id = "pid_78000005-0000-4000-8000-000000000005";
const device = "pid_78000009-0000-4000-8000-000000000009";
const unavailable = { state: "unavailable", source: "none" };

function detail(action: string, args: unknown = null) {
  const policy = action === "create_temporary_policy" || action === "isolate_session";
  return {
    run: { id, agent_id: device, state: "running", evidence_ids: [id], definition_version: 1, version: 1 },
    evidence_ids: [id], plan: { plan_hash: `sha256:${"a".repeat(64)}`, catalog_version: "security-agent-actions-v1", expires_at: "2026-09-16T12:00:00Z", steps: [{ id, index: 0, action, authorization: "allow", state: "authorized", version: 1 }] },
    authorization: "authorized", approvals: [], execution: [{ step_id: id, action, state: "authorized", version: 1 }], verification: "not_started",
    action_details: [{ step_id: id, action, arguments: args, result: null, ttl_seconds: policy && args !== null ? 120 : null, control_expires_at: null,
      rollback: { support: policy ? "automatic" : action === "update_finding_response" ? "manual" : "not_supported", state: policy ? "not_started" : "unavailable", verification: policy ? { state: "unavailable", source: "policy_targets" } : unavailable },
      verification: policy ? { state: "unavailable", source: "policy_targets" } : unavailable }],
  };
}


describe("typed temporary Monitor boundary", () => {
 it("keeps Monitor arguments and existing Block without coercion", () => {
  for (const mode of ["monitor","block"]) {
   const value=detail("create_temporary_policy",{target_id:id,mode,scope:id,ttl_seconds:120});
   expect(decodeSecurityAgentRunDetail(value)).toEqual(value);
  }
 });
 it("rejects present null/empty/unknown mode and permanent TTL",()=>{
  for (const mode of [null,"","allow",1]) expect(()=>decodeSecurityAgentRunDetail(detail("create_temporary_policy",{target_id:id,mode,scope:id,ttl_seconds:120}))).toThrow("schema mismatch");
  expect(()=>decodeSecurityAgentRunDetail(detail("create_temporary_policy",{target_id:id,mode:"monitor",scope:id,ttl_seconds:0}))).toThrow("schema mismatch");
 });
 const definition={id,name:"Temporary observation",trigger_kind:"finding",trigger_source:"credential",environment_ids:[id],autonomy:"supervised",max_steps:1,max_duration_seconds:900,temporary_policy_seconds:600,ai_token_budget:1000,concurrency_limit:1,allowed_actions:["create_temporary_policy"],verification_kind:"policy_state",definition_version:1,enabled:false};
 it("preserves persisted selection and absent-mode legacy bytes",()=>{
  expect(decodeSecurityAgentDefinition(definition)).toEqual(definition);
  for (const mode of ["monitor","block"]) expect(decodeSecurityAgentDefinition({...definition,temporary_policy_mode:mode})).toEqual({...definition,temporary_policy_mode:mode});
 });
 it("rejects Monitor outside its supervised one-action TTL scope",()=>{
  const monitor={...definition,temporary_policy_mode:"monitor"};
  for (const delta of [{autonomy:"autonomous"},{max_steps:2},{temporary_policy_seconds:0},{temporary_policy_seconds:3601},{verification_kind:"test_run"},{allowed_actions:["run_test"]}]) expect(()=>decodeSecurityAgentDefinition({...monitor,...delta})).toThrow("schema mismatch");
  for (const mode of [null,"","allow"]) expect(()=>decodeSecurityAgentDefinition({...definition,temporary_policy_mode:mode})).toThrow("schema mismatch");
 });
});

it("keeps a truthful Monitor operator approval without changing its approval floor",()=>{
 const approval={id,run_id:id,step_id:id,state:"pending",expires_at:"2026-10-04T12:00:00Z",version:1,expected_effect:"Apply temporary monitoring policy",reversible:true,ttl_seconds:120,evidence_summary:[id],approval_context:{agent_id:device,action:"create_temporary_policy",target_id:id,plan_hash:`sha256:${"a".repeat(64)}`,catalog_version:"security-agent-actions-v1",requester:{state:"withheld",id:null},reason:{code:"operator_approval_required",source:"persisted_step"},risk:{class:"containment",source:"action_catalog"},rationale:{state:"withheld",summary:""}}};
 expect(decodeSecurityAgentApproval(approval)).toEqual(approval);
 expect(()=>decodeSecurityAgentApproval({...approval,approval_context:{...approval.approval_context,risk:{class:"low",source:"action_catalog"}}})).toThrow("schema mismatch");
});
