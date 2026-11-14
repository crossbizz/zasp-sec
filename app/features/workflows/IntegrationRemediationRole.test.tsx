import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { APIProductError, type APIClient } from "../../../apps/web/api/client";
import { APIProvider } from "../../api/APIProvider";
import { createRemediationRoleAPI, IntegrationRemediationRole, RemediationRoleConflict, type RemediationRoleAPI } from "./IntegrationRemediationRole";

const integrationID = "pid_80000001-0000-4000-8000-000000000001";
const roleARN = "arn:aws:iam::123456789012:role/zasp-remediation";
const unset = { integration_id: integrationID, supported: true, configured: false, role_arn: null, version: 0, updated_at: null };
const configured = { integration_id: integrationID, supported: true, configured: true, role_arn: roleARN, version: 1, updated_at: "2026-11-14T10:00:00.000000Z" };

function show(api: RemediationRoleAPI, canWrite = true) {
  return render(<APIProvider client={{} as APIClient}><IntegrationRemediationRole integrationID={integrationID} canWrite={canWrite} api={api} /></APIProvider>);
}

function response(status: number, body: unknown, headers: Record<string, string> = {}) {
  const result = new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
  return status < 400 ? { data: body, response: result } : { error: body, response: result };
}

describe("remediation role of an AWS integration", () => {
  it("shows that no role is set, what the role must allow, and saves a role against the loaded version", async () => {
    const user = userEvent.setup();
    const setRole = vi.fn(async () => configured);
    show({ getRole: async () => unset, setRole });
    expect(await screen.findByText("No remediation role is set.")).toBeInTheDocument();
    const permissions = screen.getByRole("list", { name: "Remediation role permissions" });
    for (const action of ["bedrock:GetAgent", "bedrock:UpdateAgent", "bedrock:PrepareAgent", "iam:ListAttachedRolePolicies", "iam:DetachRolePolicy", "iam:GetPolicy", "iam:GetPolicyVersion"]) expect(permissions).toHaveTextContent(action);
    expect(screen.getByText(/never the role discovery reads with/)).toBeInTheDocument();

    const save = screen.getByRole("button", { name: "Save remediation role" });
    expect(save).toBeDisabled();
    await user.type(screen.getByLabelText("Remediation role ARN"), "zasp-remediation");
    expect(save).toBeDisabled();
    expect(screen.getByText(/Enter the ARN of an IAM role/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Remediation role ARN"));
    await user.type(screen.getByLabelText("Remediation role ARN"), `  ${roleARN} `);
    await user.click(save);
    await waitFor(() => expect(setRole).toHaveBeenCalledWith(integrationID, roleARN, 0));
    expect(await screen.findByText("Remediation role saved.")).toBeInTheDocument();
    expect(screen.getByText(roleARN)).toBeInTheDocument();
    // The saved role is the current one: there is nothing to save again.
    expect(screen.getByRole("button", { name: "Save remediation role" })).toBeDisabled();
  });

  it("removes the role with the empty value and the current version", async () => {
    const user = userEvent.setup();
    const setRole = vi.fn(async () => unset);
    show({ getRole: async () => configured, setRole });
    await user.click(await screen.findByRole("button", { name: "Remove remediation role" }));
    await waitFor(() => expect(setRole).toHaveBeenCalledWith(integrationID, "", 1));
    expect(await screen.findByText(/Remediations of this integration are refused until a role is set/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove remediation role" })).not.toBeInTheDocument();
  });

  it("reloads and says so when someone else changed the role, and explains a refused role", async () => {
    const user = userEvent.setup();
    const other = { ...configured, role_arn: "arn:aws:iam::123456789012:role/zasp-other", version: 2 };
    const getRole = vi.fn().mockResolvedValueOnce(configured).mockResolvedValue(other);
    const setRole = vi.fn().mockRejectedValueOnce(new RemediationRoleConflict()).mockRejectedValueOnce(new APIProductError(400, { code: "invalid_request", message: "Request rejected", retryable: false, correlation_id: "pid_90000001-0000-4000-8000-000000000001" }));
    show({ getRole, setRole });
    await user.click(await screen.findByRole("button", { name: "Remove remediation role" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("changed by someone else");
    expect(screen.getByText("arn:aws:iam::123456789012:role/zasp-other")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Remediation role ARN"));
    await user.type(screen.getByLabelText("Remediation role ARN"), "arn:aws:iam::210987654321:role/zasp-remediation");
    await user.click(screen.getByRole("button", { name: "Save remediation role" }));
    await waitFor(() => expect(setRole).toHaveBeenLastCalledWith(integrationID, "arn:aws:iam::210987654321:role/zasp-remediation", 2));
    expect(await screen.findByRole("alert")).toHaveTextContent("same AWS account");
  });

  it("is read-only without permission to manage workflows and quiet when the setting cannot be loaded", async () => {
    const view = show({ getRole: async () => configured, setRole: vi.fn() }, false);
    expect(await screen.findByText(roleARN)).toBeInTheDocument();
    expect(screen.queryByLabelText("Remediation role ARN")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save remediation role" })).not.toBeInTheDocument();
    view.unmount();
    show({ getRole: async () => { throw new Error("offline"); }, setRole: vi.fn() });
    expect(await screen.findByText(/The remediation role is unavailable/)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("reads and writes the role through the two operations with the version as If-Match", async () => {
    const GET = vi.fn(async () => response(200, unset, { ETag: '"0"' }));
    const PUT = vi.fn(async () => response(200, configured, { ETag: '"1"' }));
    const api = createRemediationRoleAPI({ GET, PUT } as unknown as APIClient);
    await expect(api.getRole(integrationID)).resolves.toEqual(unset);
    expect(GET).toHaveBeenCalledWith("/api/v1/integrations/{id}/remediation-role", expect.objectContaining({ params: { path: { id: integrationID } } }));
    await expect(api.setRole(integrationID, roleARN, 0)).resolves.toEqual(configured);
    const [path, options] = PUT.mock.calls[0] as unknown as [string, { params: { path: { id: string }; header: Record<string, string> }; body: unknown }];
    expect(path).toBe("/api/v1/integrations/{id}/remediation-role");
    expect(options.params.path).toEqual({ id: integrationID });
    expect(options.params.header["If-Match"]).toBe('"0"');
    expect(options.params.header["Idempotency-Key"].length).toBeGreaterThanOrEqual(16);
    expect(options.body).toEqual({ role_arn: roleARN });
    // An answer for another integration, without its version, or for another role is refused.
    GET.mockResolvedValueOnce(response(200, { ...unset, integration_id: "pid_80000009-0000-4000-8000-000000000009" }, { ETag: '"0"' }));
    await expect(api.getRole(integrationID)).rejects.toThrow();
    GET.mockResolvedValueOnce(response(200, unset));
    await expect(api.getRole(integrationID)).rejects.toThrow();
    PUT.mockResolvedValueOnce(response(200, { ...configured, role_arn: "arn:aws:iam::123456789012:role/zasp-other" }, { ETag: '"1"' }));
    await expect(api.setRole(integrationID, roleARN, 0)).rejects.toThrow();
    // A stale version is a conflict.
    PUT.mockResolvedValueOnce(response(409, { code: "conflict", message: "Conflict", retryable: false, correlation_id: "pid_90000001-0000-4000-8000-000000000001" }));
    await expect(api.setRole(integrationID, roleARN, 0)).rejects.toBeInstanceOf(RemediationRoleConflict);
  });
});
