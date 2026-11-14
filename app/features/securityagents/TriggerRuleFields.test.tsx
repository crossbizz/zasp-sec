import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { TriggerRuleFields, triggerRuleDraft, triggerRuleSource, triggerRuleValue, validFindingRule } from "./TriggerRuleFields";

function Harness({ kind }: { kind: string }) {
  const [draft, setDraft] = useState(() => triggerRuleDraft("credential"));
  const source = triggerRuleSource(draft, kind, "credential");
  return <><TriggerRuleFields value={draft} kind={kind} disabled={false} onChange={setDraft} /><output aria-label="source">{source}</output><output aria-label="rules">{JSON.stringify(triggerRuleValue(draft, kind, source))}</output></>;
}

describe("trigger rules of a manual finding responder", () => {
  it("offers the finding rule and uses it as the trigger source", async () => {
    render(<Harness kind="finding" />);
    expect(screen.queryByLabelText("Finding rule")).not.toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Trigger mode"), "manual");
    const rule = screen.getByLabelText("Finding rule");
    expect(rule).toHaveValue("credential");
    await userEvent.clear(rule);
    expect(screen.getByLabelText("rules")).toHaveTextContent("null");
    await userEvent.type(rule, "ec2_instance_imdsv2_enabled");
    expect(screen.getByLabelText("source")).toHaveTextContent("ec2_instance_imdsv2_enabled");
    expect(screen.getByLabelText("rules")).toHaveTextContent('{"version":1,"mode":"manual"}');
  });

  it("keeps the template source for the existing template behavior and for other trigger kinds", async () => {
    const draft = { ...triggerRuleDraft("credential"), family: "ec2_instance_imdsv2_enabled" };
    expect(triggerRuleSource(draft, "finding", "credential")).toBe("credential");
    expect(triggerRuleSource({ ...draft, mode: "manual" }, "attack_path", "verified")).toBe("verified");
    expect(triggerRuleSource({ ...draft, mode: "manual" }, "runtime_decision", "block")).toBe("block");
    render(<Harness kind="attack_path" />);
    await userEvent.selectOptions(screen.getByLabelText("Trigger mode"), "manual");
    expect(screen.queryByLabelText("Finding rule")).not.toBeInTheDocument();
  });

  it("keeps the rule of a saved manual definition when it is edited", () => {
    const draft = triggerRuleDraft("iam_role_administratoraccess_policy", { version: 1, mode: "manual" });
    expect(draft.family).toBe("iam_role_administratoraccess_policy");
    expect(triggerRuleSource(draft, "finding", "iam_role_administratoraccess_policy")).toBe("iam_role_administratoraccess_policy");
  });

  it("refuses a rule the API would refuse", () => {
    expect(validFindingRule("iam_role_administratoraccess_policy")).toBe(true);
    for (const value of ["", " credential", "credential ", "a".repeat(65), "bad\u0007rule"]) {
      expect(validFindingRule(value)).toBe(false);
      expect(triggerRuleValue({ ...triggerRuleDraft("credential"), mode: "manual", family: value }, "finding", value)).toBeNull();
    }
  });
});

describe("trigger rules of an automatic responder", () => {
  function draftFor(kind: string, legacy: string, rules?: Parameters<typeof triggerRuleDraft>[1]) {
    void kind;
    return { ...triggerRuleDraft(legacy, rules), mode: "automatic" as const };
  }

  it("builds an automatic finding rule from the family and severity a person enters", async () => {
    render(<Harness kind="finding" />);
    await userEvent.selectOptions(screen.getByLabelText("Trigger mode"), "automatic");
    expect(screen.getByText(/Rules take effect after validation and activation/)).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("Finding family"));
    await userEvent.type(screen.getByLabelText("Finding family"), "credential_exposed");
    await userEvent.selectOptions(screen.getByLabelText("Minimum finding severity"), "high");
    await userEvent.clear(screen.getByLabelText("Trigger cooldown seconds"));
    await userEvent.type(screen.getByLabelText("Trigger cooldown seconds"), "120");
    expect(screen.getByLabelText("source")).toHaveTextContent("credential_exposed");
    expect(JSON.parse(screen.getByLabelText("rules").textContent ?? "")).toEqual({ version: 1, mode: "automatic", cooldown_seconds: 120, finding: { family: "credential_exposed", minimum_severity: "high" } });
    // Fields of other kinds are not offered.
    expect(screen.queryByLabelText("Path evidence state")).toBeNull();
    expect(screen.queryByLabelText("Runtime decision")).toBeNull();
  });

  it("builds an automatic attack path rule whose source is the evidence state", async () => {
    render(<Harness kind="attack_path" />);
    await userEvent.selectOptions(screen.getByLabelText("Trigger mode"), "automatic");
    await userEvent.selectOptions(screen.getByLabelText("Path evidence state"), "observed");
    expect(screen.getByLabelText("source")).toHaveTextContent("observed");
    expect(JSON.parse(screen.getByLabelText("rules").textContent ?? "")).toEqual({ version: 1, mode: "automatic", cooldown_seconds: 600, attack_path: { state: "observed" } });
    expect(screen.queryByLabelText("Finding family")).toBeNull();
  });

  it("builds an automatic runtime rule, with the risk only when one is chosen", async () => {
    render(<Harness kind="runtime_decision" />);
    await userEvent.selectOptions(screen.getByLabelText("Trigger mode"), "automatic");
    expect(JSON.parse(screen.getByLabelText("rules").textContent ?? "")).toEqual({ version: 1, mode: "automatic", cooldown_seconds: 600, runtime: { decision: "block", action: "http_request", count: 1, window_seconds: 300 } });
    await userEvent.selectOptions(screen.getByLabelText("Runtime decision"), "monitor");
    await userEvent.clear(screen.getByLabelText("Evaluated action"));
    await userEvent.type(screen.getByLabelText("Evaluated action"), "shell_exec");
    await userEvent.selectOptions(screen.getByLabelText("Policy risk"), "critical");
    await userEvent.clear(screen.getByLabelText("Distinct decision count"));
    await userEvent.type(screen.getByLabelText("Distinct decision count"), "5");
    await userEvent.clear(screen.getByLabelText("Decision window seconds"));
    await userEvent.type(screen.getByLabelText("Decision window seconds"), "60");
    // The runtime trigger keeps the template's source.
    expect(screen.getByLabelText("source")).toHaveTextContent("credential");
    expect(JSON.parse(screen.getByLabelText("rules").textContent ?? "")).toEqual({ version: 1, mode: "automatic", cooldown_seconds: 600, runtime: { decision: "monitor", action: "shell_exec", count: 5, window_seconds: 60, risk: "critical" } });
  });

  it("refuses automatic rules outside the API limits", () => {
    const finding = draftFor("finding", "credential");
    expect(triggerRuleValue({ ...finding, cooldown: "0" }, "finding", "credential")).toBeNull();
    expect(triggerRuleValue({ ...finding, cooldown: "86401" }, "finding", "credential")).toBeNull();
    expect(triggerRuleValue({ ...finding, cooldown: "1.5" }, "finding", "credential")).toBeNull();
    expect(triggerRuleValue({ ...finding, cooldown: "" }, "finding", "credential")).toBeNull();
    // The finding family must equal the trigger source.
    expect(triggerRuleValue(finding, "finding", "other_family")).toBeNull();
    expect(triggerRuleValue({ ...finding, family: " x" }, "finding", " x")).toBeNull();
    const runtime = draftFor("runtime_decision", "credential");
    expect(triggerRuleValue(runtime, "runtime_decision", "credential")).not.toBeNull();
    expect(triggerRuleValue({ ...runtime, count: "101" }, "runtime_decision", "credential")).toBeNull();
    expect(triggerRuleValue({ ...runtime, count: "0" }, "runtime_decision", "credential")).toBeNull();
    expect(triggerRuleValue({ ...runtime, window: "86401" }, "runtime_decision", "credential")).toBeNull();
    expect(triggerRuleValue({ ...runtime, action: "" }, "runtime_decision", "credential")).toBeNull();
    const path = draftFor("attack_path", "credential");
    expect(triggerRuleValue(path, "attack_path", "verified")).not.toBeNull();
    expect(triggerRuleValue(path, "attack_path", "observed")).toBeNull();
    // An unknown trigger kind has no automatic rule.
    expect(triggerRuleValue(finding, "schedule", "credential")).toBeNull();
  });

  it("keeps legacy definitions without rules and reads saved automatic rules back", () => {
    expect(triggerRuleValue(triggerRuleDraft("credential"), "finding", "credential")).toBeUndefined();
    expect(triggerRuleSource(triggerRuleDraft("credential"), "finding", "legacy_source")).toBe("legacy_source");
    const saved = triggerRuleDraft("ignored", { version: 1, mode: "automatic", cooldown_seconds: 30, runtime: { decision: "allow", action: "db_write", count: 3, window_seconds: 90, risk: "medium" } });
    expect(saved).toMatchObject({ mode: "automatic", decision: "allow", action: "db_write", count: "3", window: "90", risk: "medium", cooldown: "30" });
    const savedFinding = triggerRuleDraft("ignored", { version: 1, mode: "automatic", cooldown_seconds: 45, finding: { family: "secret_leak", minimum_severity: "critical" } });
    expect(savedFinding).toMatchObject({ family: "secret_leak", severity: "critical", cooldown: "45" });
    expect(triggerRuleDraft("ignored", { version: 1, mode: "automatic", cooldown_seconds: 45, attack_path: { state: "potential" } }).state).toBe("potential");
  });

  it("disables every field when the form is disabled", () => {
    render(<TriggerRuleFields value={{ ...triggerRuleDraft("credential"), mode: "automatic" }} kind="runtime_decision" disabled onChange={() => undefined} />);
    for (const label of ["Trigger mode", "Runtime decision", "Evaluated action", "Policy risk", "Distinct decision count", "Decision window seconds", "Trigger cooldown seconds"]) {
      expect(screen.getByLabelText(label)).toBeDisabled();
    }
  });
});
