import assert from "node:assert/strict";

export function validateSecurityAgentRunContextMode(environment) {
  const key = "ZASP_COMBINED_E2E_SECURITY_AGENT_RUN_CONTEXT";
  if (!Object.hasOwn(environment, key)) return false;
  assert.equal(environment[key], "true", "run-context mode requires exact true or absent opt-in");
  assert.equal(validateSecurityAgentSimulationMode(environment), true, "run-context mode requires isolated simulation browser mode");
  return true;
}

export function validateSecurityAgentSimulationMode(environment) {
  const key = "ZASP_COMBINED_E2E_SECURITY_AGENT_SIMULATION_ONLY";
  if (!Object.hasOwn(environment, key)) return false;
  assert.equal(environment[key], "true", "Security Agent simulation mode requires exact true or absent opt-in");
  for (const suffix of ["AUDIT_BROWSE", "RUNTIME_PIPELINE_ONLY", "RUNTIME_SANDBOX_SEARCH", "RUNTIME_PRECISION", "RUNTIME_PRECISION_BROWSER", "RED_TEAM_RUNTIME"]) {
    assert.equal(Object.hasOwn(environment, `ZASP_COMBINED_E2E_${suffix}`), false, "Security Agent simulation mode cannot combine with other selected modes");
  }
  assert.equal(Object.hasOwn(environment, "ZASP_RECONCILIATION_API_LOAD_DIAGNOSTIC"), false, "Security Agent simulation mode cannot combine with load diagnostics");
  return true;
}

export function assertSecurityAgentSimulationProof({ response, displayed, before, after, requests, simulationPath }) {
  assert.equal(response?.status, 200, "actual successful simulation response required");
  const body = response.body;
  assert.ok(Array.isArray(body?.matched_evidence_ids) && body.matched_evidence_ids.length > 0, "actual matched evidence required");
  assert.ok(Array.isArray(body.steps) && body.steps.length > 0, "actual simulation steps required");
  assert.equal(body.side_effects, 0);
  assert.deepEqual(displayed?.evidence, body.matched_evidence_ids, "browser omitted or changed matched evidence");
  assert.deepEqual(displayed.steps, body.steps.map((step, index) => {
    assert.equal(step.index, index, "actual step order invalid");
    assert.ok(["allow", "deny", "approval_required"].includes(step.authorization), "actual authorization invalid");
    assert.equal(step.approval_required, step.authorization === "approval_required", "actual approval flag invalid");
    return { action: step.action, authorization: `Authorization: ${step.authorization}`, approval: step.approval_required ? "Approval required" : "Approval not required", order: index + 1 };
  }), "browser omitted or changed proposed steps");
  assert.equal(displayed.summary, body.summary, "simulation summary changed");
  assert.equal(displayed.metadata, `Plan ${body.plan_hash}, zero side effects, expires ${body.expires_at}`, "simulation metadata changed");
  assert.equal(displayed.notice, "Simulation only. This does not execute the proposed steps.");
  assert.equal(displayed.controls, 0, "simulation result contains an execution control");
  for (const counts of [before, after]) {
    assert.ok(counts && Object.keys(counts).sort().join(",") === "approvals,effects,steps", "durable count evidence missing");
    for (const value of Object.values(counts)) assert.ok(Number.isSafeInteger(value) && value >= 0, "durable count evidence invalid");
  }
  assert.deepEqual(after, before, "simulation changed durable execution/approval/effect counts");
  assert.match(simulationPath, /^\/api\/v1\/security-agents\/pid_[0-9a-f-]{36}\/simulate$/);
  assert.ok(Array.isArray(requests) && requests.length > 0, "simulation request trace missing");
  const mutations = requests.filter(request => !["GET", "HEAD", "OPTIONS"].includes(request.method));
  assert.equal(mutations.length, 1, "simulation emitted an unexpected mutation");
  assert.equal(mutations[0].method, "POST", "simulation mutation method changed");
  assert.equal(mutations[0].path, simulationPath, "simulation emitted an unexpected mutation path");
}

export function assertSecurityAgentSimulationDurability({ before, after, afterClaim, simulation, afterClaimSimulation, body, claim }) {
  for (const snapshot of [before, after, afterClaim]) {
    assert.ok(snapshot && Array.isArray(snapshot.raw_steps), "raw step evidence missing");
    for (const key of ["execution_runs", "execution_steps", "approvals", "effects", "target"]) {
      assert.ok(Number.isSafeInteger(snapshot[key]?.count) && snapshot[key].count >= 0, "durable count missing");
      assert.match(snapshot[key].digest, /^[0-9a-f]{64}$/, "durable digest missing");
    }
    const keys = snapshot.raw_steps.map(row => {
      assert.match(row.digest, /^[0-9a-f]{64}$/, "raw step digest missing");
      return `${row.run_id}/${row.step_id}`;
    });
    assert.equal(new Set(keys).size, keys.length, "duplicate raw step keys");
    assert.equal(snapshot.target.count, 1, "target finding evidence missing");
  }
  for (const key of ["execution_runs", "execution_steps", "approvals", "effects", "target"]) assert.deepEqual(after[key], before[key], `simulation changed ${key}`);
  assert.deepEqual(afterClaim, after, "worker claim changed durable state");
  assert.deepEqual(afterClaimSimulation, simulation, "worker claim changed simulation state");
  assert.deepEqual(simulation.run, { run_id: body.run_id, definition_id: body.definition_id, definition_version: body.definition_version, state: "simulated", attempt: 0, has_lease: false, completed: true }, "simulation has execution authority");
  const existing = new Set(before.raw_steps.map(row => `${row.run_id}/${row.step_id}`));
  assert.equal(before.raw_steps.some(row => row.run_id === body.run_id), false, "simulation run already existed");
  for (const row of before.raw_steps) assert.deepEqual(after.raw_steps.find(candidate => candidate.run_id === row.run_id && candidate.step_id === row.step_id), row, "existing step changed");
  const added = after.raw_steps.filter(row => !existing.has(`${row.run_id}/${row.step_id}`));
  assert.equal(after.raw_steps.length - before.raw_steps.length, body.steps.length, "unexplained raw step growth");
  assert.equal(added.length, body.steps.length, "unexplained new steps");
  assert.equal(simulation.steps.length, body.steps.length, "simulation steps missing");
  assert.deepEqual(simulation.steps.map(({ run_id, step_id, ...step }) => {
    assert.equal(run_id, body.run_id, "new step belongs to another run");
    assert.ok(added.some(row => row.run_id === run_id && row.step_id === step_id), "new step identity missing");
    return step;
  }), body.steps.map(({ index, action, authorization }) => ({ index, action, authorization })), "persisted proposed steps changed");
  assert.equal(new Set(simulation.steps.map(step => step.step_id)).size, body.steps.length, "duplicate proposed step identity");
  assert.equal(claim.principal, "zasp_e2e_security_agent_worker", "worker principal was bypassed");
  assert.equal(claim.ready, true, "registered worker principal not ready");
  assert.deepEqual(claim.result, { items: [] }, "worker claimed simulation or unexpected work");
}
