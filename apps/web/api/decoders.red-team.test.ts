import { describe, expect, it } from "vitest";

import { decodeAttackLabPreflight, decodeAttackLabRun, decodeAttackLabRunDetail, decodeAttackLabRunPage, decodeTestDefinition, decodeTestDefinitionPage, decodeTestRun, decodeTestRunDetail, decodeTestRunPage } from "./decoders";

const definitionID = "pid_91000001-0000-4000-8000-000000000001";
const targetID = "pid_91000002-0000-4000-8000-000000000002";
const runID = "pid_91000003-0000-4000-8000-000000000003";
const attackLabRunID = "pid_91000004-0000-4000-8000-000000000004";

const definition = {
  id: definitionID,
  version: 2,
  name: "Staging agent safety",
  target_id: targetID,
  target_kind: "agent_endpoint",
  categories: ["prompt_injection", "data_leakage"],
  safety: { environment: "staging", credential_class: "read_only", expected_side_effects: ["bounded evaluation"] },
  enabled: true,
  created_at: "2026-08-24T10:00:00Z",
  updated_at: "2026-08-24T10:01:00Z",
} as const;

const completeRun = {
  id: runID,
  version: 4,
  definition_id: definitionID,
  definition_version: 2,
  status: "complete",
  attempt: 1,
  cancel_requested: false,
  queued_at: "2026-08-24T10:02:00Z",
  started_at: "2026-08-24T10:02:01Z",
  completed_at: "2026-08-24T10:02:05Z",
  verdict: "fail",
  evidence_reference: "s3://zasp-evidence/organizations/o/workspaces/w/environments/e/artifacts/run",
} as const;

describe("red team API decoders", () => {
  it("accepts exact definitions and stable pages", () => {
    expect(decodeTestDefinition(definition).id).toBe(definitionID);
    expect(decodeTestDefinitionPage({ items: [definition], next_cursor: "Y3Vyc29yXzAx" }).items).toHaveLength(1);
  });

  it.each([
    { categories: ["prompt_injection", "prompt_injection"] },
    { safety: { ...definition.safety, environment: "production" } },
    { updated_at: "2026-08-24T09:59:59Z" },
    { extra: true },
  ])("rejects hostile definition shape %#", (change) => {
    expect(() => decodeTestDefinition({ ...definition, ...change })).toThrow("schema mismatch");
  });

  it("accepts coherent queued, retryable, complete, failed, and cancelled states", () => {
    expect(decodeTestRun({ id: runID, version: 1, definition_id: definitionID, definition_version: 2, status: "queued", attempt: 0, cancel_requested: false, queued_at: "2026-08-24T10:02:00Z" }).status).toBe("queued");
    expect(decodeTestRun({ id: runID, version: 3, definition_id: definitionID, definition_version: 2, status: "retryable", attempt: 1, cancel_requested: false, queued_at: "2026-08-24T10:02:00Z", started_at: "2026-08-24T10:02:01Z", error_code: "rate_limited" }).status).toBe("retryable");
    expect(decodeTestRun(completeRun).verdict).toBe("fail");
    expect(decodeTestRun({ id: runID, version: 8, definition_id: definitionID, definition_version: 2, status: "failed", attempt: 5, cancel_requested: false, queued_at: "2026-08-24T10:02:00Z", started_at: "2026-08-24T10:02:01Z", completed_at: "2026-08-24T10:05:00Z", error_code: "exhausted" }).status).toBe("failed");
    expect(decodeTestRun({ id: runID, version: 2, definition_id: definitionID, definition_version: 2, status: "cancelled", attempt: 0, cancel_requested: true, queued_at: "2026-08-24T10:02:00Z", completed_at: "2026-08-24T10:02:01Z", error_code: "cancelled" }).status).toBe("cancelled");
  });

  it.each([
    { ...completeRun, attempt: 0 },
    { ...completeRun, verdict: undefined },
    { ...completeRun, status: "queued" },
    { ...completeRun, completed_at: "2026-08-24T10:01:59Z" },
    { ...completeRun, error_code: "retryable" },
  ])("rejects impossible run state %#", (value) => {
    expect(() => decodeTestRun(value)).toThrow("schema mismatch");
  });

  it("binds the immutable attempt to the completed run", () => {
    const attempt = { attempt: 1, verdict: "fail", objective: "Evaluate curated categories: prompt_injection, data_leakage", behavior: "One unsafe behavior was observed.", evidence: ["prompt_injection: unsafe behavior observed", "data_leakage: protected"], evidence_reference: completeRun.evidence_reference, completed_at: completeRun.completed_at };
    expect(decodeTestRunDetail({ ...completeRun, attempts: [attempt] }).attempts[0]?.verdict).toBe("fail");
    expect(() => decodeTestRunDetail({ ...completeRun, attempts: [{ ...attempt, evidence_reference: "s3://foreign" }] })).toThrow("schema mismatch");
  });

  it("accepts descending run pages and rejects cursor/order drift", () => {
    const older = { ...completeRun, id: "pid_91000004-0000-4000-8000-000000000004", queued_at: "2026-08-24T09:00:00Z" };
    expect(decodeTestRunPage({ items: [completeRun, older], next_cursor: "Y3Vyc29yXzAy" }).items).toHaveLength(2);
    expect(() => decodeTestRunPage({ items: [older, completeRun] })).toThrow("schema mismatch");
  });

  it("accepts exact Attack Lab preflight, run, detail, and page authority", () => {
    const limits = { cpu: "500m", memory: "1Gi", ephemeral_storage: "2Gi", timeout_seconds: 300 } as const;
    const preflight = { source_run_id: runID, definition_id: definitionID, definition_version: 2, target_id: targetID, target_kind: "agent_endpoint", environment: "staging", credential_class: "read_only", destination: "adapter.customer.example", allowed_destinations: ["adapter.customer.example"], success_criterion: "Evaluate curated categories: prompt_injection", expected_side_effects: ["bounded evaluation"], decision_digest: "a".repeat(64), decision_expires_at: "2026-08-24T10:10:00Z", limits } as const;
    expect(decodeAttackLabPreflight(preflight).destination).toBe("adapter.customer.example");
    const complete = { id: attackLabRunID, version: 4, source_run_id: runID, definition_id: definitionID, definition_version: 2, target_id: targetID, target_kind: "agent_endpoint", environment: "staging", credential_class: "read_only", destination: "adapter.customer.example", status: "complete", attempt: 1, cancel_requested: false, cleanup_state: "complete", limits, queued_at: "2026-08-24T10:06:00Z", started_at: "2026-08-24T10:06:01Z", attempt_started_at: "2026-08-24T10:06:01Z", completed_at: "2026-08-24T10:06:05Z", verdict: "verified", evidence_reference: "s3://zasp-attack-lab-evidence/exact", evidence_version_id: "version-attack-lab-1", evidence_checksum: "c".repeat(64), evidence_size: 512 } as const;
    expect(decodeAttackLabRun(complete).verdict).toBe("verified");
    const attempt = { attempt: 1, evidence_state: "complete", verdict: "verified", criterion_observed: true, canary_touched: true, cleanup_completed: true, evidence: ["semantic:criterion observed", "gateway:allowed", "egress:destination exact", "kubernetes:job complete", "cloud:canary touched"], evidence_reference: complete.evidence_reference, evidence_version_id: complete.evidence_version_id, evidence_checksum: complete.evidence_checksum, evidence_size: complete.evidence_size, completed_at: complete.completed_at } as const;
    expect(decodeAttackLabRunDetail({ ...complete, attempts: [attempt] }).attempts[0]?.canary_touched).toBe(true);
    expect(decodeAttackLabRunPage({ items: [complete] }).items[0]?.id).toBe(attackLabRunID);
  });

  it.each([
    { allowed_destinations: ["foreign.example"] },
    { environment: "production" },
    { limits: { cpu: "1", memory: "1Gi", ephemeral_storage: "2Gi", timeout_seconds: 300 } },
    { expected_side_effects: [] },
    { expected_side_effects: ["duplicate", "duplicate"] },
    { decision_digest: "A".repeat(64) },
    { decision_expires_at: "2026-08-24T03:10:00-07:00" },
  ])("rejects hostile Attack Lab preflight %#", (change) => {
    const value = { source_run_id: runID, definition_id: definitionID, definition_version: 2, target_id: targetID, target_kind: "agent_endpoint", environment: "staging", credential_class: "read_only", destination: "adapter.customer.example", allowed_destinations: ["adapter.customer.example"], success_criterion: "Evaluate curated categories", expected_side_effects: ["bounded evaluation"], decision_digest: "a".repeat(64), decision_expires_at: "2026-08-24T10:10:00Z", limits: { cpu: "500m", memory: "1Gi", ephemeral_storage: "2Gi", timeout_seconds: 300 }, ...change };
    expect(() => decodeAttackLabPreflight(value)).toThrow("schema mismatch");
  });

  it("rejects incoherent Attack Lab run and attempt authority", () => {
    const value = { id: attackLabRunID, version: 4, source_run_id: runID, definition_id: definitionID, definition_version: 2, target_id: targetID, target_kind: "agent_endpoint", environment: "staging", credential_class: "read_only", destination: "adapter.customer.example", status: "complete", attempt: 1, cancel_requested: false, cleanup_state: "complete", limits: { cpu: "500m", memory: "1Gi", ephemeral_storage: "2Gi", timeout_seconds: 300 }, queued_at: "2026-08-24T10:06:00Z", started_at: "2026-08-24T10:06:01Z", attempt_started_at: "2026-08-24T10:06:01Z", completed_at: "2026-08-24T10:06:05Z", verdict: "verified", evidence_reference: "s3://zasp-attack-lab-evidence/exact", evidence_version_id: "version-attack-lab-1", evidence_checksum: "c".repeat(64), evidence_size: 512 };
    expect(() => decodeAttackLabRun({ ...value, attempt_started_at: undefined })).toThrow("schema mismatch");
    expect(() => decodeAttackLabRun({ ...value, cleanup_state: "pending" })).toThrow("schema mismatch");
    const attempt = { attempt: 1, evidence_state: "complete", verdict: "verified", criterion_observed: true, canary_touched: true, cleanup_completed: true, evidence: ["semantic:criterion observed", "gateway:allowed", "egress:destination exact", "kubernetes:job complete", "cloud:canary touched"], evidence_reference: "s3://foreign", evidence_version_id: value.evidence_version_id, evidence_checksum: value.evidence_checksum, evidence_size: value.evidence_size, completed_at: value.completed_at };
    expect(() => decodeAttackLabRunDetail({ ...value, attempts: [attempt] })).toThrow("schema mismatch");
    expect(() => decodeAttackLabRun({ ...value, evidence_version_id: undefined })).toThrow("schema mismatch");
    expect(() => decodeAttackLabRun({ ...value, evidence_checksum: "0".repeat(64) })).toThrow("schema mismatch");
  });
});
