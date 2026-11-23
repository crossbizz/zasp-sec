import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { APIClient } from "../../../apps/web/api/client";
import { readCLIRequest } from "../../../apps/web/api/cli-consent";
import { CLIConsent } from "./page";

const env = "pid_10000000-0000-4000-8000-000000000001";
const id = "pid_20000000-0000-4000-8000-000000000001";
const POST = vi.hoisted(() => vi.fn());
const state = vi.hoisted(() => ({ fresh: true, permitted: true }));
vi.mock("../../api/APIProvider", () => ({ APIProvider: ({children}: {children: React.ReactNode}) => children,
  useAPI: () => ({ client: { POST } as unknown as APIClient }) }));
vi.mock("../../auth/SessionProvider", () => ({ SessionProvider: ({children}: {children: React.ReactNode}) => children,
  useSession: () => ({status:"authenticated", environmentID:env, workspaceID:id, organizationID:id,
    scopes:[], isFreshAuthenticated:state.fresh, hasCapability: (capability: string) => capability === "addon-scans.share" && state.permitted}) }));
function link() {
  return "#" + new URLSearchParams({request_id:id,environment_id:env,code_challenge:"X".repeat(43),
    request_proof: Math.floor(Date.now()/1000+300)+"."+"Y".repeat(43)}).toString();
}
beforeEach(() => {
  state.fresh=true; state.permitted=true; POST.mockReset();
  window.history.replaceState({}, "", "/cli/authorize"+link());
});
describe("CLI consent", () => {
  it("requires terminal code and explicit approval in a fresh matching session", async () => {
    POST.mockResolvedValue({data:{approved:true},response:new Response(null,{status:200})});
    render(<CLIConsent />);
    const button=await screen.findByRole("button",{name:"Approve CLI access"});
    expect(window.location.hash).toBe("");
    expect(button).toBeDisabled();
    expect(POST).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole("textbox"),{target:{value:"aabbccdd"}});
    expect(POST).not.toHaveBeenCalled();
    fireEvent.click(button);
    await screen.findByText("Approved. Return to your terminal to complete sign-in.");
    expect(POST).toHaveBeenCalledTimes(1);
    expect(POST).toHaveBeenCalledWith("/api/v1/cli/auth/approve", expect.objectContaining({
      headers:{"X-Zasp-Expected-Scope":[id,id,env].join("/")}, body:expect.objectContaining({environment_id:env,comparison_code:"aabbccdd"})}));
  });
  it("requires the selected Environment's existing token issuance capability", async () => {
    state.permitted=false; render(<CLIConsent />);
    await screen.findByText(/cannot approve CLI credentials/);
    expect(POST).not.toHaveBeenCalled();
  });
  it("preserves a pending consent while signing in in another tab", async () => {
    state.fresh=false; render(<CLIConsent />);
    const signin=await screen.findByRole("link",{name:"Sign in to Zasp"});
    expect(signin).toHaveAttribute("target","_blank");
    await waitFor(()=>expect(POST).not.toHaveBeenCalled());
  });
  it("rejects unsolicited code, duplicated fields and expired grants", () => {
    expect(readCLIRequest(link()+"&comparison_code=aabbccdd")).toBeUndefined();
    expect(readCLIRequest(link()+"&environment_id="+env)).toBeUndefined();
    expect(readCLIRequest(link(),Date.now()+700_000)).toBeUndefined();
  });
});
