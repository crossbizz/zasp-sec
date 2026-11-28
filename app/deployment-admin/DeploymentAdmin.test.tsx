import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DeploymentAdmin } from "./DeploymentAdmin";
import { dashboardLink } from "./operator-api";

const sessionRoute = "/api/v1/deployment-admin/session";
const settingsRoute = "/api/v1/deployment-admin/settings";
const session = { deployment_id: "production-us-west", csrf_token: "a".repeat(32), expires_at: "2099-01-01T00:00:00Z" };
const nango = { api_url: "https://nango.svc:8443", dashboard_url: "https://nango.svc:18443", login_hint: "platform-ops", credential_ref: "kubernetes://connectors/nango#dashboard" };
const opensearch = { api_url: "https://search.internal", dashboard_url: "", login_hint: "", credential_ref: "" };
const settings = { deployment_id: session.deployment_id, version: 2, nango, opensearch };
const json = (data: unknown, status = 200) => status === 204 ? new Response(null, { status }) : Response.json(data, { status });

type Fetcher = (path: string, init: RequestInit) => Response | Promise<Response>;
function mockOperatorAPI(handler: Fetcher) {
  const fetch = vi.fn((path: string, init: RequestInit) => {
    expect([sessionRoute, settingsRoute]).toContain(path);
    expect(init.credentials).toBe("same-origin"); expect(init.redirect).toBe("error"); expect(init.cache).toBe("no-store");
    return handler(path, init);
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("deployment administrator", () => {
  it("uses a separate operator login, edits versioned service pointers and signs out", async () => {
    let loggedIn = false;
    const edit = { ...nango, login_hint: "search-oncall" };
    const fetch = mockOperatorAPI((path, init) => {
      if (path === sessionRoute && init.method === "POST") {
        expect(JSON.parse(String(init.body))).toEqual({ password: "operator-demo-pass" });
        loggedIn = true; return json(session);
      }
      if (path === sessionRoute && init.method === "DELETE") {
        expect(new Headers(init.headers).get("X-CSRF-Token")).toBe(session.csrf_token);
        loggedIn = false; return json(null, 204);
      }
      if (path === sessionRoute) return json({}, 401);
      expect(loggedIn).toBe(true);
      if (init.method === "PUT") {
        expect(new Headers(init.headers).get("X-CSRF-Token")).toBe(session.csrf_token);
        expect(JSON.parse(String(init.body))).toEqual({ version: 2, nango: edit, opensearch });
        return json({ ...settings, nango: edit, version: 3 });
      }
      return json(settings);
    });
    render(<DeploymentAdmin />);
    const password = await screen.findByLabelText("Operator password");
    expect(screen.getByText(window.location.host)).toBeVisible();
    expect(password).toHaveAttribute("type", "password");
    expect(fetch).toHaveBeenCalledTimes(1);
    fireEvent.change(password, { target: { value: "operator-demo-pass" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    const panel = await screen.findByRole("region", { name: "Nango" });
    expect(screen.getByText(new RegExp(session.deployment_id))).toBeVisible();
    expect(within(panel).getByRole("link", { name: "Open Nango dashboard" })).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(screen.getByRole("region", { name: "OpenSearch" })).queryByRole("link")).toBeNull();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    fireEvent.change(within(panel).getByLabelText("Login account"), { target: { value: edit.login_hint } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Service access settings saved");
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByLabelText("Operator password");
    expect(screen.queryByRole("region", { name: "Nango" })).toBeNull();
    expect(screen.queryByDisplayValue(nango.credential_ref)).toBeNull();
  });

  it("clears rejected passwords and explains throttled operator sign-in", async () => {
    let attempts = 0;
    mockOperatorAPI((_path, init) => json({}, init.method === "POST" && ++attempts > 1 ? 429 : 401));
    render(<DeploymentAdmin />);
    const input = await screen.findByLabelText("Operator password");
    for (const explanation of ["Incorrect operator password.", "Too many attempts. Wait before trying again."]) {
      fireEvent.change(input, { target: { value: "invalid" } });
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
      await screen.findByText(explanation);
      expect(input).toHaveValue("");
    }
    expect(screen.queryByRole("region", { name: "OpenSearch" })).toBeNull();
  });

  it("reloads a disabled deployment and clears visible settings if authorization expires on save", async () => {
    let ready = false;
    mockOperatorAPI((path, init) => path === sessionRoute ? ready ? json(session) : json({}, 503) : init.method === "PUT" ? json({}, 401) : json(settings));
    render(<DeploymentAdmin />);
    expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
    expect(screen.queryByLabelText("Operator password")).toBeNull();
    ready = true;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    const panel = await screen.findByRole("region", { name: "OpenSearch" });
    fireEvent.change(within(panel).getByLabelText("Dashboard URL"), { target: { value: "https://dash.search.internal" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByLabelText("Operator password")).toBeVisible();
    expect(screen.queryByRole("link", { name: "Open Nango dashboard" })).toBeNull();
    expect(screen.getByRole("alert")).toHaveTextContent(/session changed or expired/);
  });

  it("keeps a pasted raw credential out of the settings request", async () => {
    const fetch = mockOperatorAPI(path => path === sessionRoute ? json(session) : json(settings));
    render(<DeploymentAdmin />);
    const nango = within(await screen.findByRole("region", { name: "Nango" }));
    fireEvent.change(nango.getByLabelText(/^Credential reference/), { target: { value: "pasted-value" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Enter a Kubernetes, Vault, or AWS Secrets Manager reference for Nango");
    expect(fetch.mock.calls.some(([, init]) => init.method === "PUT")).toBe(false);
  });

  it("retains a stale edit until the operator chooses to reload", async () => {
    let version = 2;
    mockOperatorAPI((path, init) => {
      if (path === sessionRoute) return json(session);
      if (init.method === "PUT") { version = 3; return json({}, 409); }
      return json({ ...settings, version, nango: { ...nango, login_hint: version === 2 ? "old-account" : "updated-account" } });
    });
    render(<DeploymentAdmin />);
    const account = within(await screen.findByRole("region", { name: "Nango" })).getByLabelText("Login account");
    fireEvent.change(account, { target: { value: "my-edit" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("another session");
    expect(account).toHaveValue("my-edit"); expect(account).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Reload saved settings" }));
    expect(await screen.findByDisplayValue("updated-account")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
  });

  it("rejects settings labeled for another deployment", async () => {
    mockOperatorAPI(path => path === sessionRoute ? json(session) : json({ ...settings, deployment_id: "another-stack" }));
    render(<DeploymentAdmin />);
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be loaded");
    expect(screen.queryByRole("region", { name: "Nango" })).toBeNull();
  });

  it("removes access records when the operator session reaches expiry", async () => {
    const until = Date.now() + 60_000;
    vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
    mockOperatorAPI(path => path === sessionRoute ? json({ ...session, expires_at: new Date(until).toISOString() }) : json(settings));
    await act(async () => { render(<DeploymentAdmin />); });
    expect(screen.getByDisplayValue(nango.credential_ref)).toBeVisible();
    await act(async () => { vi.advanceTimersByTime(60_001); });
    expect(screen.getByLabelText("Operator password")).toBeVisible();
    expect(screen.queryByDisplayValue(nango.credential_ref)).toBeNull();
  });
});

describe("operator dashboard links", () => {
  it.each(["javascript:alert(1)", "data:text/html,x", "//other.test", "http://public.example", "http://10.attacker.invalid", "https://alice:secret@dash.test", "https://dash.test/?token=private", "https://dash.test/#secret", "https://dash.test\\@other.test"])("rejects %s", input => {
    expect(dashboardLink(input)).toBeUndefined();
  });
  it("preserves an explicitly configured private dashboard address", () => {
    expect(dashboardLink("https://nango.nango.svc.cluster.local:18443/")).toBe("https://nango.nango.svc.cluster.local:18443/");
  });
});
