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
