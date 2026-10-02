import assert from "node:assert/strict";
import test from "node:test";
import { assertSecurityAgentSimulationProof, assertSecurityAgentSimulationDurability, validateSecurityAgentRunContextMode } from "./security-agent-simulation-browser-proof.mjs";

test("run-context browser acceptance requires explicit isolated simulation mode", () => {
  assert.equal(validateSecurityAgentRunContextMode({}), false);
  assert.equal(validateSecurityAgentRunContextMode({ ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION_ONLY: "true", ZASP_COMBINED_E2E_SECURITY_AGENT_RUN_CONTEXT: "true" }), true);
  for (const value of ["false", "", "1", "TRUE"]) assert.throws(() => validateSecurityAgentRunContextMode({ ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION_ONLY: "true", ZASP_COMBINED_E2E_SECURITY_AGENT_RUN_CONTEXT: value }));
  assert.throws(() => validateSecurityAgentRunContextMode({ ZASP_COMBINED_E2E_SECURITY_AGENT_RUN_CONTEXT: "true" }));
  assert.throws(() => validateSecurityAgentRunContextMode({ ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION_ONLY: "true", ZASP_COMBINED_E2E_SECURITY_AGENT_RUN_CONTEXT: "true", ZASP_COMBINED_E2E_AUDIT_BROWSE: "true" }));
});

const evidenceID = "pid_30000102-0000-4000-8000-000000000102";
const simulationPath = "/api/v1/security-agents/pid_78000001-0000-4000-8000-000000000001/simulate";
function proof() {
  const body = { matched_evidence_ids: [evidenceID], steps: [{ index: 0, action: "update_finding_response", authorization: "approval_required", approval_required: true }], summary: "Bounded plan", plan_hash: `sha256:${"a".repeat(64)}`, expires_at: "2026-09-15T20:00:00Z", side_effects: 0 };
  return { response: { status: 200, body }, displayed: { evidence: [evidenceID], steps: [{ action: "update_finding_response", authorization: "Authorization: approval_required", approval: "Approval required", order: 1 }], summary: "Bounded plan", metadata: `Plan ${body.plan_hash}, zero side effects, expires ${body.expires_at}`, notice: "Simulation only. This does not execute the proposed steps.", controls: 0 }, before: { steps: 0, approvals: 0, effects: 0 }, after: { steps: 0, approvals: 0, effects: 0 }, requests: [{ method: "POST", path: simulationPath }], simulationPath };
}

test("Security Agent simulation proof checks actual response projection and unchanged durable counts", () => {
  assert.doesNotThrow(() => assertSecurityAgentSimulationProof(proof()));
  for (const key of ["steps", "approvals", "effects"]) {
    const value = proof(); value.after[key] = 1;
    assert.throws(() => assertSecurityAgentSimulationProof(value), /durable/);
  }
});

test("Security Agent simulation proof fails closed on absent or invalid evidence", () => {
  for (const key of ["response", "displayed", "before", "after", "requests"]) {
    const value = proof(); delete value[key];
    assert.throws(() => assertSecurityAgentSimulationProof(value));
  }
  for (const change of [
    value => { value.response.status = 500; },
    value => { value.response.body.steps = []; },
    value => { value.response.body.matched_evidence_ids = []; },
    value => { value.after.effects = "0"; },
    value => { value.displayed.steps[0].authorization = "Authorization: allow"; },
    value => { value.displayed.steps[0].approval = "Approval not required"; },
    value => { value.displayed.evidence = []; },
    value => { value.displayed.controls = 1; },
    value => { value.requests = []; },
  ]) { const value = proof(); change(value); assert.throws(() => assertSecurityAgentSimulationProof(value)); }
});

test("Security Agent simulation proof rejects extra execution and approval mutations", () => {
  for (const path of [simulationPath.replace("/simulate", "/runs"), "/api/v1/security-agent-approvals/pid_78000002-0000-4000-8000-000000000002/decision", "/api/v1/findings/pid_30000102-0000-4000-8000-000000000102"]) {
    const value = proof(); value.requests.push({ method: "POST", path });
    assert.throws(() => assertSecurityAgentSimulationProof(value), /mutation/);
  }
});

test("Security Agent simulation proof checks every step's order and exact authorization", () => {
  const value = proof();
  value.response.body.steps.push({ index: 1, action: "isolate_session", authorization: "deny", approval_required: false }, { index: 2, action: "update_finding_response", authorization: "allow", approval_required: false });
  value.displayed.steps.push({ action: "isolate_session", authorization: "Authorization: deny", approval: "Approval not required", order: 2 }, { action: "update_finding_response", authorization: "Authorization: allow", approval: "Approval not required", order: 3 });
  assert.doesNotThrow(() => assertSecurityAgentSimulationProof(value));
  value.displayed.steps.reverse();
  assert.throws(() => assertSecurityAgentSimulationProof(value), /step/);
});

function durability() {
  const runID = "pid_78000003-0000-4000-8000-000000000003";
  const stepID = "pid_78000004-0000-4000-8000-000000000004";
  const empty = { count: 0, digest: "a".repeat(64) };
  const before = { raw_steps: [], execution_runs: empty, execution_steps: empty, approvals: empty, effects: empty, target: { count: 1, digest: "b".repeat(64) } };
  const after = { ...structuredClone(before), raw_steps: [{ run_id: runID, step_id: stepID, digest: "c".repeat(64) }] };
  const simulation = { run: { run_id: runID, definition_id: "pid_78000001-0000-4000-8000-000000000001", definition_version: 2, state: "simulated", attempt: 0, has_lease: false, completed: true }, steps: [{ run_id: runID, step_id: stepID, index: 0, action: "update_finding_response", authorization: "approval_required" }] };
  return { before, after, afterClaim: structuredClone(after), simulation, afterClaimSimulation: structuredClone(simulation), body: { ...proof().response.body, run_id: runID, definition_id: simulation.run.definition_id, definition_version: 2 }, claim: { principal: "zasp_e2e_security_agent_worker", ready: true, result: { items: [] } } };
}

test("Security Agent simulation durability permits only its exact persisted proposed steps", () => {
  assert.doesNotThrow(() => assertSecurityAgentSimulationDurability(durability()));
});

test("Security Agent simulation durability rejects unexplained growth and changed execution authority", () => {
  for (const change of [
    value => { value.after.raw_steps.push({ run_id: "foreign", step_id: "extra", digest: "c".repeat(64) }); },
    value => { value.simulation.steps[0].action = "isolate_session"; },
    value => { value.simulation.run.state = "queued"; },
    value => { value.simulation.run.attempt = 1; },
    value => { value.simulation.run.has_lease = true; },
    value => { value.simulation.run.completed = false; },
    value => { value.claim.result.items = [{ run_id: value.body.run_id }]; },
    value => { value.claim.ready = false; },
    value => { value.claim.principal = "zasp_e2e"; },
    value => { delete value.claim.result; },
    value => { value.afterClaimSimulation.run.attempt = 1; },
    ...["execution_runs", "execution_steps", "approvals", "effects", "target"].map(key => value => { value.after[key].digest = "d".repeat(64); }),
    ...["execution_runs", "execution_steps", "approvals", "effects"].map(key => value => { value.after[key].count = 1; }),
  ]) { const value = durability(); change(value); assert.throws(() => assertSecurityAgentSimulationDurability(value)); }
});

test("Security Agent simulation durability rejects replacement of an existing step at unchanged count", () => {
  const value = durability();
  const existing = { run_id: "pid_78000005-0000-4000-8000-000000000005", step_id: "pid_78000006-0000-4000-8000-000000000006", digest: "d".repeat(64) };
  value.before.raw_steps.push(existing);
  value.after.raw_steps.push({ ...existing, digest: "e".repeat(64) });
  value.afterClaim = structuredClone(value.after);
  assert.throws(() => assertSecurityAgentSimulationDurability(value), /existing step/);
});
