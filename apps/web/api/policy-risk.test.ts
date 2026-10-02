import { expect, it } from "vitest";
import { decodePolicy } from "./decoders";

const base = { id: "policy-risk", name: "Risk", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "invoke" }], action: "block", rollout: "draft", failure_mode: "closed" };
it.each(["low", "medium", "high", "critical"])("retains policy risk %s", risk => expect(decodePolicy({ ...base, risk })).toEqual({ ...base, risk }));
it("preserves unknown policy risk as omission", () => expect(decodePolicy(base)).toEqual(base));
it.each([null, "", "severe", 1])("rejects invalid policy risk %j", risk => expect(() => decodePolicy({ ...base, risk })).toThrow());
