import type { SecurityAgentApproval, SecurityAgentCancellation, SecurityAgentManualRunInput, SecurityAgentOrderedStep, SecurityAgentRunDetail } from "./generated";
import { decodeSecurityAgentRun } from "./decoders";

const PRODUCT_ID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TERMINAL = ["contained", "remediated", "needs_human", "failed", "inconclusive", "cancelled"];
function fail(): never { throw new Error("schema mismatch"); }
function check(condition: unknown): asserts condition { if (!condition) fail(); }
function record(value: unknown, keys: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  check(value !== null && typeof value === "object" && !Array.isArray(value));
  const result = value as Record<string, unknown>;
  check(keys.every((key) => Object.hasOwn(result, key)) && Object.keys(result).every((key) => keys.includes(key) || optional.includes(key)));
  return result;
}
function list(value: unknown, max: number): unknown[] { check(Array.isArray(value) && value.length <= max); return value; }
function integer(value: unknown, min = 1, max = 1000000): void { check(Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max); }
function id(value: unknown): void { check(typeof value === "string" && PRODUCT_ID.test(value)); }
function digest(value: unknown): void { check(typeof value === "string" && DIGEST.test(value)); }
function oneOf(value: unknown, allowed: readonly string[]): void { check(typeof value === "string" && allowed.includes(value)); }
function same(value: unknown, expected: unknown): void { check(JSON.stringify(value) === JSON.stringify(expected)); }
function timestamp(value: unknown): string {
  check(typeof value === "string" && /^(?:[2-9][0-9]{3})-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/.test(value));
  const parsed = new Date(value);
  check(Number.isFinite(parsed.valueOf()) && parsed.toISOString().slice(0, 19) === value.slice(0, 19));
  return value.slice(0, 19) + "." + (value.split(".")[1]?.slice(0, -1) ?? "").padEnd(9, "0") + "Z";
}
function evidence(value: unknown, expected?: unknown): void {
  const values = list(value, 1); check(values.length === 1); id(values[0]);
  if (expected !== undefined) same(values, expected);
}
export function hasOrderedSecurityAgent(value: unknown): boolean {
  return value !== null && typeof value === "object" && Object.hasOwn(value, "ordered");
}

export function decodeSecurityAgentManualRunInput(value: unknown): SecurityAgentManualRunInput {
  check(value !== null && typeof value === "object");
  const ordered = Object.hasOwn(value, "trigger_version") || Object.hasOwn(value, "trigger_source");
  const v = record(value, ordered ? ["environment_id", "trigger_kind", "trigger_id", "trigger_version", "trigger_source"] : ["environment_id", "trigger_kind", "trigger_id"]);
  id(v.environment_id); id(v.trigger_id); oneOf(v.trigger_kind, ordered ? ["finding", "attack_path"] : ["finding", "attack_path", "session"]);
  if (ordered) {
    integer(v.trigger_version);
    check(typeof v.trigger_source === "string" && v.trigger_source.length > 0 && new TextEncoder().encode(v.trigger_source).length <= 128 && !/^\p{White_Space}|\p{White_Space}$/u.test(v.trigger_source) && [...v.trigger_source].every((char) => char.charCodeAt(0) >= 32 && (char.charCodeAt(0) < 127 || char.charCodeAt(0) > 159)));
  }
  return value as SecurityAgentManualRunInput;
}

export function decodeSecurityAgentCancellation(value: unknown): SecurityAgentCancellation {
  if (!hasOrderedSecurityAgent(value)) return decodeSecurityAgentRun(value);
  const v = record(value, ["id", "agent_id", "state", "evidence_ids", "definition_version", "version", "ordered"]);
  const { ordered, ...run } = v;
  decodeSecurityAgentRun(run); integer(v.definition_version); integer(v.version, 2); evidence(v.evidence_ids);
  const extension = record(ordered, ["cleanup_required"]);
  check(typeof extension.cleanup_required === "boolean");
  oneOf(v.state, ["cancelled", "needs_human"]);
  if (v.state === "needs_human") check(!extension.cleanup_required && (v.version as number) >= 3);
  if (v.state === "cancelled") check(v.version === 2 ? !extension.cleanup_required : (v.version as number) >= 4);
  return value as SecurityAgentCancellation;
}

// Existing legacy effects still use the unchanged legacy decoder outside
// ordered detail. This also validates the new standalone test approval effect.
export function decodeOrderedSecurityAgentApproval(value: unknown): SecurityAgentApproval {
  const v = record(value, ["id", "run_id", "step_id", "state", "expires_at", "version", "expected_effect", "reversible", "ttl_seconds", "evidence_summary"]);
  id(v.id); id(v.run_id); id(v.step_id); timestamp(v.expires_at); evidence(v.evidence_summary);
  oneOf(v.state, ["pending", "approved", "rejected", "expired"]);
  check(v.version === (v.state === "pending" ? 1 : 2));
  if (v.expected_effect === "Apply temporary containment policy") { check(v.reversible === true); integer(v.ttl_seconds, 60, 3600); }
  else check(v.expected_effect === "Run existing test" && v.reversible === false && v.ttl_seconds === 0);
  return value as SecurityAgentApproval;
}

function step(value: unknown, index: number, runVersion: number): SecurityAgentOrderedStep {
  const s = record(value, ["step_id", "index", "action", "state", "version", "dependency", "authorization", "approval", "receipt", "settlement", "cleanup"]);
  id(s.step_id); check(s.index === index && s.action === (index === 0 ? "create_temporary_policy" : "run_test") && s.authorization === "approval_required");
  integer(s.version, 1, runVersion); oneOf(s.state, ["blocked", "waiting_approval", "authorized", "executing", "verifying", "succeeded", "failed", "inconclusive", "cancelled"]);
  const d = record(s.dependency, ["predecessor_step_id", "required_receipt_kind", "satisfied", "blocked", "ready"]);
  for (const key of ["satisfied", "blocked", "ready"]) check(typeof d[key] === "boolean");
  const a = record(s.approval, ["state", "version", "approval_id"]);
  oneOf(a.state, ["absent", "pending", "approved", "rejected", "expired"]);
  if (a.state === "absent") check(index === 1 && ["blocked", "cancelled"].includes(s.state as string) && a.version === 0 && a.approval_id === null);
  else {
    id(a.approval_id); check(a.version === (a.state === "pending" ? 1 : 2) && (a.version as number) <= (s.version as number));
    check(s.state !== "blocked" && (s.state === "waiting_approval") === (a.state === "pending"));
    if (["authorized", "executing", "verifying", "succeeded"].includes(s.state as string)) check(a.state === "approved");
  }
  check((s.receipt !== null) === (s.state === "succeeded"));
  if (s.receipt !== null) {
    const r = record(s.receipt, ["kind", "version", "digest", "reference"]);
    check(r.kind === (index === 0 ? "temporary_policy_applied.v1" : "existing_test_settled.v1") && r.version === 1); digest(r.digest); id(r.reference);
  }
  if (index === 0) check(s.settlement === "not_applicable");
  else if (s.receipt === null) check(s.settlement === "pending");
  else oneOf(s.settlement, ["not_reproduced", "reproduced", "unknown"]);
  const c = record(s.cleanup, ["state", "version", "attempt", "partial", "cleaned"]);
  oneOf(c.state, ["not_applicable", "not_started", "pending", "leased", "retryable", "cleaned"]);
  integer(c.version, 0, 999999); integer(c.attempt, 0, 100); check(typeof c.partial === "boolean" && typeof c.cleaned === "boolean");
  return value as SecurityAgentOrderedStep;
}

function cleanup(s: SecurityAgentOrderedStep, applied: boolean, terminal: boolean, state: string): void {
  const c = s.cleanup;
  if (s.index === 1 || c.state === "not_started" || c.state === "pending") {
    check(c.state === (s.index === 1 ? "not_applicable" : applied ? "pending" : "not_started") && c.version === 0 && c.attempt === 0 && !c.partial && !c.cleaned);
    return;
  }
  check(["leased", "retryable", "cleaned"].includes(c.state) && terminal && c.version >= 1 && c.attempt >= 1 && c.cleaned === (c.state === "cleaned"));
  const conservative = state === "cancelled" || state === "needs_human";
  if (!applied) check(c.partial && conservative);
  if (c.partial || c.attempt > 1 || c.state === "retryable") check(conservative);
  if (c.state === "cleaned") check(state === "remediated" || conservative);
  check(c.version >= 2 * c.attempt - 1 + (c.state === "retryable" ? 1 : c.state === "cleaned" ? 2 : 0));
}

export function decodeOrderedSecurityAgentRunDetail(value: unknown): SecurityAgentRunDetail {
  const v = record(value, ["run", "evidence_ids", "plan", "authorization", "approvals", "execution", "verification", "ordered"]);
  record(v.run, ["id", "agent_id", "state", "evidence_ids", "definition_version", "version"]);
  const run = decodeSecurityAgentRun(v.run); integer(run.version); integer(run.definition_version); evidence(run.evidence_ids); evidence(v.evidence_ids, run.evidence_ids);
  const o = record(v.ordered, ["contract_version", "steps"]); check(o.contract_version === 62);
  const steps = list(o.steps, 2).map((s, index) => step(s, index, run.version));
  const approvals = list(v.approvals, 2); const execution = list(v.execution, 2);
  const terminal = TERMINAL.includes(run.state); const admitted = v.plan !== null;
  check(v.authorization === (admitted ? run.state === "cancelled" ? "cancelled" : "approval_required" : "not_planned"));
  check(v.verification === (terminal ? ["contained", "remediated"].includes(run.state) ? "verified" : run.state === "failed" ? "failed" : "inconclusive" : admitted ? "pending" : "not_started"));
  if (!admitted) {
    check(steps.length === 0 && approvals.length === 0 && execution.length === 0);
    oneOf(run.state, ["queued", "planning", "needs_human", "cancelled", "failed", "inconclusive"]);
    if (run.state === "queued") check(run.version === 1);
    if (run.state === "planning") check(run.version >= 2);
    return value as SecurityAgentRunDetail;
  }
  check(steps.length === 2 && run.version >= 3 && (terminal || ["waiting_approval", "running", "verifying"].includes(run.state)));
  check(steps[0].step_id !== steps[1].step_id);
  const p = record(v.plan, ["plan_hash", "catalog_version", "expires_at", "steps"]);
  digest(p.plan_hash); check(p.catalog_version === "security-agent-actions-v1"); const expiry = timestamp(p.expires_at);
  const planned = list(p.steps, 2); check(planned.length === 2 && execution.length === 2);
  const applied = steps[0].receipt !== null;
  const approvalIDs = new Set<string>(); const receiptIDs = new Set<string>(); let approvalIndex = 0;
  for (const s of steps) {
    const d = s.dependency;
    if (s.index === 0) check(d.predecessor_step_id === null && d.required_receipt_kind === null && d.satisfied && !d.blocked && s.state !== "blocked");
    else check(d.predecessor_step_id === steps[0].step_id && d.required_receipt_kind === "temporary_policy_applied.v1" && d.satisfied === applied && d.blocked === (s.state === "blocked") && (applied || ["blocked", "cancelled"].includes(s.state)));
    if (d.ready) check(!terminal && d.satisfied && !d.blocked && ["authorized", "waiting_approval"].includes(s.state));
    if (s.state === "waiting_approval") check(run.state === "waiting_approval");
    cleanup(s, applied, terminal, run.state);
    const state = s.state === "blocked" ? "queued" : s.state;
    const planStep = record(planned[s.index], ["id", "index", "action", "authorization", "state", "version"]);
    check(planStep.id === s.step_id && planStep.index === s.index && planStep.action === s.action && planStep.authorization === s.authorization && planStep.state === state && planStep.version === s.version);
    const x = record(execution[s.index], ["step_id", "action", "state", "version"], s.receipt ? ["result_digest"] : []);
    check(x.step_id === s.step_id && x.action === s.action && x.state === state && x.version === s.version);
    if (s.receipt) { check(x.result_digest === s.receipt.digest && !receiptIDs.has(s.receipt.reference)); receiptIDs.add(s.receipt.reference); }
    if (s.approval.approval_id !== null) {
      check(!approvalIDs.has(s.approval.approval_id)); approvalIDs.add(s.approval.approval_id);
      const a = decodeOrderedSecurityAgentApproval(approvals[approvalIndex++]);
      check(a.id === s.approval.approval_id && a.run_id === run.id && a.step_id === s.step_id && a.state === s.approval.state && a.version === s.approval.version && timestamp(a.expires_at) === expiry);
      check(a.expected_effect === (s.index === 0 ? "Apply temporary containment policy" : "Run existing test")); evidence(a.evidence_summary, run.evidence_ids);
    }
  }
  check(approvalIndex === approvals.length);
  if (run.state === "waiting_approval") check(steps.some((s) => s.state === "waiting_approval"));
  if (!terminal) check(steps[1].receipt === null);
  if (run.state === "contained" || run.state === "remediated") check(applied && steps[1].settlement === "not_reproduced");
  if (run.state === "contained") check(!steps[0].cleanup.cleaned);
  if (run.state === "remediated") check(steps[0].cleanup.cleaned && !steps[0].cleanup.partial);
  return value as SecurityAgentRunDetail;
}

// JSON.parse loses duplicate keys. Called while the transport still has the
// bounded original bytes; syntax has already been checked by JSON.parse.
export function validateOrderedSecurityAgentJSON(text: string): void {
  check(new TextEncoder().encode(text).length <= 16384);
  const tokens = text.match(/"(?:[^"\\]|\\.)*"|[{}[\]:,]|[^\s{}[\]:,]+/g) ?? [];
  let cursor = 0;
  const visit = (depth: number): void => {
    check(depth <= 12);
    const token = tokens[cursor++];
    if (token === "{") {
      const keys = new Set<string>();
      while (tokens[cursor] !== "}") {
        const key = JSON.parse(tokens[cursor++]) as string;
        check(!keys.has(key)); keys.add(key); check(tokens[cursor++] === ":"); visit(depth + 1);
        if (tokens[cursor] !== "}") check(tokens[cursor++] === ",");
      }
      cursor++;
    } else if (token === "[") {
      while (tokens[cursor] !== "]") { visit(depth + 1); if (tokens[cursor] !== "]") check(tokens[cursor++] === ","); }
      cursor++;
    }
  };
  visit(0); check(cursor === tokens.length);
}
