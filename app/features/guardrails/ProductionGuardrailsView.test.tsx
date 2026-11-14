import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import { decodeGuardrailPolicy, GUARDRAIL_RULE_IDS, type GuardrailMode, type GuardrailPolicy } from "../../../apps/web/api/decoders";
import { APIProvider } from "../../api/APIProvider";
import { createGuardrailPolicyAPI, GuardrailPolicyConflict, type GuardrailPolicyAPI } from "./guardrail-policy-api";
import { ProductionGuardrailsView } from "./ProductionGuardrailsView";

const environmentID = "pid_10000003-0000-4000-8000-000000000003";

function policy(version: number, modes: Partial<Record<string, GuardrailMode>> = {}): GuardrailPolicy {
  return {
    environment_id: environmentID, version, updated_at: version === 0 ? null : "2026-11-14T10:00:00.000000Z",
    rules: GUARDRAIL_RULE_IDS.map((id) => {
      const injection = id.startsWith("injection."), defaultMode: GuardrailMode = injection ? "block" : "redact";
      return { id, category: injection ? "prompt_injection" as const : "sensitive_data" as const, description: `Matches ${id}`, mode: modes[id] ?? defaultMode, default_mode: defaultMode, redactable: !injection };
    }),
  };
}

function show(api: GuardrailPolicyAPI, canWrite = true, onNavigate?: (path: string) => void) {
  return render(<APIProvider client={{} as APIClient}><ProductionGuardrailsView canWrite={canWrite} api={api} origin="https://zasp.example" onNavigate={onNavigate} /></APIProvider>);
}

function response(status: number, body: unknown, headers: Record<string, string> = {}) {
  const result = new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
  return status < 400 ? { data: body, response: result } : { error: body, response: result };
}

describe("Guardrails page", () => {
  it("shows every rule with its mode and saves the whole policy against the loaded version", async () => {
    const user = userEvent.setup();
    const savePolicy = vi.fn(async (rules: Readonly<Record<string, GuardrailMode>>) => policy(1, rules));
    show({ getPolicy: async () => policy(0), savePolicy });
    const table = await screen.findByRole("table", { name: "Guardrail rules" });
    expect(within(table).getAllByRole("row")).toHaveLength(GUARDRAIL_RULE_IDS.length + 1);
    expect(screen.getByText("Defaults")).toBeInTheDocument();
    expect(screen.getByText(/No policy has been saved for this Environment/)).toBeInTheDocument();
    // A rule that cannot redact does not offer it; a redactable one does.
    const injection = screen.getByLabelText("Mode of injection.instruction_override");
    expect(within(injection).queryByRole("option", { name: /Redact/ })).not.toBeInTheDocument();
    expect(within(screen.getByLabelText("Mode of pii.email")).getByRole("option", { name: "Redact (default)" })).toBeInTheDocument();

    const save = screen.getByRole("button", { name: "Save policy" });
    expect(save).toBeDisabled();
    await user.selectOptions(injection, "monitor");
    await user.selectOptions(screen.getByLabelText("Mode of pii.email"), "block");
    expect(save).toBeEnabled();
    await user.click(save);
    await waitFor(() => expect(savePolicy).toHaveBeenCalledTimes(1));
    const [rules, version] = savePolicy.mock.calls[0] as unknown as [Record<string, GuardrailMode>, number];
    expect(version).toBe(0);
    // Every rule is sent: a rule that is not named would fall back to its default.
    expect(Object.keys(rules).sort()).toEqual([...GUARDRAIL_RULE_IDS].sort());
    expect(rules["injection.instruction_override"]).toBe("monitor");
    expect(rules["pii.email"]).toBe("block");
    expect(rules["pii.phone"]).toBe("redact");
    expect(await screen.findByRole("status")).toHaveTextContent("Guardrail policy saved as version 1.");
    expect(screen.getByText("Version 1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save policy" })).toBeDisabled();
  });

  it("shows the other person's policy and says nothing was saved when the version moved", async () => {
    const user = userEvent.setup();
    const getPolicy = vi.fn().mockResolvedValueOnce(policy(1)).mockResolvedValue(policy(2, { "pii.phone": "off" }));
    const savePolicy = vi.fn().mockRejectedValue(new GuardrailPolicyConflict());
    show({ getPolicy, savePolicy });
    await user.selectOptions(await screen.findByLabelText("Mode of injection.tool_call"), "off");
    await user.click(screen.getByRole("button", { name: "Save policy" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("changed by someone else");
    expect(screen.getByText("Version 2")).toBeInTheDocument();
    expect(screen.getByLabelText("Mode of pii.phone")).toHaveValue("off");
    // The draft was dropped with the stale version.
    expect(screen.getByLabelText("Mode of injection.tool_call")).toHaveValue("block");
    expect(screen.getByRole("button", { name: "Save policy" })).toBeDisabled();
  });

  it("is read-only without permission to manage workflows", async () => {
    show({ getPolicy: async () => policy(3), savePolicy: vi.fn() }, false);
    expect(await screen.findByLabelText("Mode of pii.credit_card")).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Save policy" })).not.toBeInTheDocument();
    expect(screen.getByText(/Changing it needs permission to manage workflows/)).toBeInTheDocument();
  });

  it("reports an unavailable policy and retries", async () => {
    const user = userEvent.setup();
    const getPolicy = vi.fn().mockRejectedValueOnce(new Error("offline")).mockResolvedValue(policy(0));
    show({ getPolicy, savePolicy: vi.fn() });
    expect(await screen.findByRole("alert")).toHaveTextContent("The guardrail policy is unavailable.");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("table", { name: "Guardrail rules" })).toBeInTheDocument();
  });

  it("shows how a gateway asks for a decision, with a token that can do nothing else", async () => {
    const user = userEvent.setup();
    const onNavigate = vi.fn();
    show({ getPolicy: async () => policy(0), savePolicy: vi.fn() }, true, onNavigate);
    const example = await screen.findByLabelText("Decision request example");
    expect(example).toHaveTextContent("POST https://zasp.example/api/v1/guardrails/decisions");
    expect(example).toHaveTextContent('Authorization: Bearer $ZASP_GUARDRAIL_TOKEN');
    expect(example).toHaveTextContent('"direction":"input"');
    expect(screen.getByText(/Guardrail decisions only/)).toBeInTheDocument();
    expect(screen.getByText(/it is not stored/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "API Access" }));
    expect(onNavigate).toHaveBeenCalledWith("/administration/api-access");
  });
});

describe("guardrail policy API", () => {
  it("reads the policy with its version and saves against it", async () => {
    const GET = vi.fn(async () => response(200, policy(0), { ETag: '"0"', "Cache-Control": "no-store" }));
    const PUT = vi.fn(async () => response(200, policy(1, { "pii.email": "off" }), { ETag: '"1"', "Cache-Control": "no-store" }));
    const api = createGuardrailPolicyAPI({ GET, PUT } as unknown as APIClient);
    await expect(api.getPolicy()).resolves.toEqual(policy(0));
    expect(GET).toHaveBeenCalledWith("/api/v1/guardrails/policy", expect.anything());
    await expect(api.savePolicy({ "pii.email": "off" }, 0)).resolves.toEqual(policy(1, { "pii.email": "off" }));
    const [path, options] = PUT.mock.calls[0] as unknown as [string, { params: { header: Record<string, string> }; body: unknown }];
    expect(path).toBe("/api/v1/guardrails/policy");
    expect(options.params.header["If-Match"]).toBe('"0"');
    expect(options.params.header["Idempotency-Key"].length).toBeGreaterThanOrEqual(16);
    expect(options.body).toEqual({ rules: { "pii.email": "off" } });
    // A policy without its version, a save that skipped a version, and a save
    // that did not take the mode that was sent are refused.
    GET.mockResolvedValueOnce(response(200, policy(0), { "Cache-Control": "no-store" }));
    await expect(api.getPolicy()).rejects.toThrow();
    PUT.mockResolvedValueOnce(response(200, policy(3, { "pii.email": "off" }), { ETag: '"3"', "Cache-Control": "no-store" }));
    await expect(api.savePolicy({ "pii.email": "off" }, 0)).rejects.toThrow();
    PUT.mockResolvedValueOnce(response(200, policy(1), { ETag: '"1"', "Cache-Control": "no-store" }));
    await expect(api.savePolicy({ "pii.email": "off" }, 0)).rejects.toThrow();
    PUT.mockResolvedValueOnce(response(409, { code: "conflict", message: "Conflict", retryable: false, correlation_id: "pid_90000001-0000-4000-8000-000000000001" }));
    await expect(api.savePolicy({ "pii.email": "off" }, 0)).rejects.toBeInstanceOf(GuardrailPolicyConflict);
  });

  it("decodes only a complete policy", () => {
    expect(() => decodeGuardrailPolicy(policy(0))).not.toThrow();
    expect(() => decodeGuardrailPolicy(policy(2, { "pii.us_ssn": "monitor" }))).not.toThrow();
    const broken: ((value: GuardrailPolicy) => unknown)[] = [
      (value) => ({ ...value, rules: value.rules.slice(1) }),
      (value) => ({ ...value, rules: [value.rules[0], ...value.rules.slice(0, -1)] }),
      (value) => ({ ...value, rules: value.rules.map((rule) => rule.id === "injection.role_switch" ? { ...rule, mode: "redact" } : rule) }),
      (value) => ({ ...value, rules: value.rules.map((rule) => rule.id === "pii.email" ? { ...rule, mode: "allow" } : rule) }),
      (value) => ({ ...value, rules: value.rules.map((rule) => rule.id === "pii.email" ? { ...rule, text: "alice@example.com" } : rule) }),
      (value) => ({ ...value, version: 0, updated_at: "2026-11-14T10:00:00.000000Z" }),
      (value) => ({ ...value, version: 1, updated_at: null }),
      (value) => ({ ...value, environment_id: "production" }),
    ];
    for (const change of broken) expect(() => decodeGuardrailPolicy(change(policy(1)))).toThrow();
  });
});
