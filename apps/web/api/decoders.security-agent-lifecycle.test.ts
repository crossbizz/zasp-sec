import { expect, it } from "vitest";
import { decodeSecurityAgentExecutionControls, decodeSecurityAgentExecutionControlResult } from "./decoders";

const keys = ["create_temporary_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "update_finding_response"];
const controls = (actions = keys) => ({ global: { target: "global", action_key: "*", enabled: false, version: 1 }, environment: { target: "environment", action_key: "*", enabled: false, version: 0 }, actions: actions.map(action_key => ({ target: "action", action_key, enabled: false, version: 0 })) });
it.each([keys, ["create_temporary_policy", "isolate_session", "revoke_integration_connection", "update_finding_response"], ["create_temporary_policy", "revoke_integration_connection", "update_finding_response"], ["create_temporary_policy", "update_finding_response"]].map(actions => ({ actions })))("reads exact supported control shape $actions", ({ actions }) => {
 const value = controls(actions); expect(decodeSecurityAgentExecutionControls(value)).toEqual(value);
});
it.each([keys.slice(0, 5), [...keys.slice(0, 4), "rerun_test", "update_finding_response"], [...keys].reverse(), [...keys, "unknown"]].map(actions => ({ actions })))("refuses incomplete/duplicate control shape $actions", ({ actions }) => {
 expect(() => decodeSecurityAgentExecutionControls(controls(actions))).toThrow();
});
it.each(["run_test", "rerun_test", "create_evidence_export"])("reads durable %s mutation", action_key => {
 const value = { target: "action", action_key, enabled: true, version: 1, audit_id: "pid_8ba00000-0000-4000-8000-000000000001", correlation_id: "pid_8ba00000-0000-4000-8000-000000000002", receipt_id: "pid_8ba00000-0000-4000-8000-000000000003", replayed: false };
 expect(decodeSecurityAgentExecutionControlResult(value)).toEqual(value);
});

it("reads only the exact sorted eight-key export control shape", () => {
 const exportKeys = ["create_evidence_export", "create_temporary_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "start_attack_lab", "update_finding_response"];
 expect(decodeSecurityAgentExecutionControls(controls(exportKeys))).toEqual(controls(exportKeys));
 for (const invalid of [exportKeys.slice(0, 7), [...exportKeys].reverse(), exportKeys.map(key => key === "start_attack_lab" ? "run_test" : key), [...exportKeys, "unknown"]]) expect(() => decodeSecurityAgentExecutionControls(controls(invalid))).toThrow();
});

it("refuses enabled export authority without a persisted control version", () => {
 const value = controls(["create_evidence_export", "create_temporary_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "start_attack_lab", "update_finding_response"]);
 value.actions[0].enabled = true;
 expect(() => decodeSecurityAgentExecutionControls(value)).toThrow();
 value.actions[0].version = 1;
 expect(decodeSecurityAgentExecutionControls(value)).toEqual(value);
});
