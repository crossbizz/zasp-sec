import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScopeOnboardingView, type ScopeAdminAPI, type ScopeEnvironmentClass } from "./ScopeOnboardingView";

import type { SessionContextValue } from "../../auth/SessionProvider";
const sessionFixture=vi.hoisted(()=>({current:null as SessionContextValue|null}));
vi.mock("../../auth/SessionProvider",()=>({useOptionalSession:()=>sessionFixture.current}));
beforeEach(()=>{sessionFixture.current=null});
function classificationSession(enabled=true,fresh=true):SessionContextValue {
 const capabilities=enabled?["identity.scopes.manage","identity.environments.classify"]:["identity.scopes.manage"];
 return {status:"authenticated",principal:{id:"pid_principal_a",organization_id:"pid_organization_a",organization_reference:"org",member_reference:"member",role:"organization_admin",active:true},organizationID:"pid_organization_a",workspaceID:"pid_workspace_a",environmentID:"pid_environment_a",permissions:["view","manage_identity"],capabilities,scopes:[{organization_id:"pid_organization_a",workspace_id:"pid_workspace_a",environment_id:"pid_environment_a",label:"Active"}],freshAuthExpiresAt:"2099-01-01T00:00:00Z",isFreshAuthenticated:fresh,hasCapability:(capability)=>capabilities.includes(capability),reauthenticate:vi.fn(),signIn:vi.fn(),signOut:async()=>{},retry:async()=>{},switchScope:async()=>{},scopeSwitch:{status:"idle",retry:async()=>{}}};
}
function fixtureAPI(overrides: Partial<ScopeAdminAPI> = {}): ScopeAdminAPI {
  return {
    listWorkspaces: async () => [{ id: "pid_workspace_a", name: "Agent Security" }],
    createWorkspace: async (name) => ({ id: "pid_workspace_b", name, initialEnvironmentId: "pid_environment_b" }),
    updateWorkspace: async (id, name) => ({ id, name }),
    listEnvironments: async (workspaceId) => workspaceId === "pid_workspace_b" ? [{ id: "pid_environment_b", workspaceId, name: "Development" }] : [{ id: "pid_environment_a", workspaceId: "pid_workspace_a", name: "Production" }],
    createEnvironment: async (workspaceId, name) => ({ id: "pid_environment_b", workspaceId, name }),
    updateEnvironment: async (id, name) => ({ id, workspaceId: "pid_workspace_a", name }),
    ...overrides,
  };
}

describe("Workspace and Environment onboarding", () => {
  it("creates, updates, and selects only API-authorized scopes", async () => {
    const user = userEvent.setup();
    const onScopeChange = vi.fn();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    render(<ScopeOnboardingView api={fixtureAPI()} onScopeChange={onScopeChange} />);
    expect(await screen.findByRole("option", { name: "Agent Security" })).toBeInTheDocument();
    expect(screen.queryByText("Inaccessible workspace")).not.toBeInTheDocument();

    await user.type(screen.getByLabelText("New workspace name"), "Research");
    await user.click(screen.getByRole("button", { name: "Create workspace" }));
    expect(await screen.findByRole("option", { name: "Research" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Authorized workspace" })).toHaveValue("pid_workspace_b");
    await waitFor(() => expect(onScopeChange).toHaveBeenCalledWith({ workspaceId: "pid_workspace_b", environmentId: "pid_environment_b" }));

    await user.selectOptions(screen.getByLabelText("Authorized workspace"), "pid_workspace_a");
    await user.selectOptions(await screen.findByLabelText("Authorized environment"), "pid_environment_a");
    await waitFor(() => expect(onScopeChange).toHaveBeenCalledWith({ workspaceId: "pid_workspace_a", environmentId: "pid_environment_a" }));

    await user.clear(screen.getByLabelText("Environment display name"));
    await user.type(screen.getByLabelText("Environment display name"), "Primary production");
    await user.click(screen.getByRole("button", { name: "Update environment" }));
    expect(await screen.findByRole("option", { name: "Primary production" })).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Workspace display name"));
    await user.type(screen.getByLabelText("Workspace display name"), "Agent Platform");
    await user.click(screen.getByRole("button", { name: "Update workspace" }));
    expect(await screen.findByRole("option", { name: "Agent Platform" })).toBeInTheDocument();

    await user.type(screen.getByLabelText("New environment name"), "Staging");
    await user.click(screen.getByRole("button", { name: "Create environment" }));
    expect(await screen.findByRole("option", { name: "Staging" })).toBeInTheDocument();
    expect(setItem).not.toHaveBeenCalledWith("zasp-authorized-scope", expect.anything());
  });

  it("renders stable empty, validation, and provider error states", async () => {
    const user = userEvent.setup();
    render(<ScopeOnboardingView api={fixtureAPI({ listWorkspaces: async () => [] })} />);
    expect(await screen.findByText("No authorized workspaces")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create workspace" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter a workspace name");

    cleanup();
    render(<ScopeOnboardingView api={fixtureAPI({ listWorkspaces: async () => { throw new Error("database detail"); } })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Authorized scopes could not be loaded");
    expect(screen.queryByText("database detail")).not.toBeInTheDocument();
  });

  it("renders only the exact environments returned by the authorized scope boundary", async () => {
    const listEnvironments = vi.fn(async (workspaceId: string) => [
      { id: "pid_environment_a", workspaceId, name: "Production" },
      { id: "pid_environment_b", workspaceId, name: "Authorized development" },
    ]);
    render(<ScopeOnboardingView api={fixtureAPI({ listEnvironments })} />);
    expect(await screen.findByRole("option", { name: "Production" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Authorized development" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Unpermitted environment" })).not.toBeInTheDocument();
    expect(listEnvironments).toHaveBeenCalledWith("pid_workspace_a");
  });
});

describe("Environment classification through current discovered capability",()=>{
 it.each(["production","staging","development"] as const)("creates and updates %s independently of its display name",async(environmentClass)=>{
  const user=userEvent.setup();sessionFixture.current=classificationSession();
  const createEnvironment=vi.fn(async(workspaceId:string,name:string,requested?:ScopeEnvironmentClass)=>({id:"pid_environment_created",workspaceId,name,environmentClass:requested,version:37}));
  const updateEnvironment=vi.fn(async(id:string,name:string,_version?:number,requested?:ScopeEnvironmentClass)=>({id,workspaceId:"pid_workspace_a",name,environmentClass:requested,version:38}));
  const onScopeChange=vi.fn(async(scope:{workspaceId:string;environmentId:string})=>{if(sessionFixture.current?.status==="authenticated"){sessionFixture.current.workspaceID=scope.workspaceId;sessionFixture.current.environmentID=scope.environmentId}});
  render(<ScopeOnboardingView api={fixtureAPI({listEnvironments:async(workspaceId)=>[{id:"pid_environment_a",workspaceId,name:"Production",environmentClass:"development",version:12}],createEnvironment,updateEnvironment})} onScopeChange={onScopeChange}/>);
  expect(await screen.findByLabelText("Environment classification")).toHaveValue("development");
  await user.type(screen.getByLabelText("New environment name"),"Research boundary");
  await user.selectOptions(screen.getByLabelText("New environment classification"),environmentClass);
  await user.click(screen.getByRole("button",{name:"Create environment"}));
  await waitFor(()=>expect(createEnvironment).toHaveBeenCalledWith("pid_workspace_a","Research boundary",environmentClass));
  expect(await screen.findByLabelText("Environment classification")).toHaveValue(environmentClass);
  await user.clear(screen.getByLabelText("Environment display name"));await user.type(screen.getByLabelText("Environment display name"),"Still a neutral name");
  await user.selectOptions(screen.getByLabelText("Environment classification"),"test");
  await user.click(screen.getByRole("button",{name:"Update environment"}));
  await waitFor(()=>expect(updateEnvironment).toHaveBeenCalledWith("pid_environment_created","Still a neutral name",37,"test"));
  expect(await screen.findByLabelText("Environment classification")).toHaveValue("test");
  expect(await screen.findByRole("option",{name:"Still a neutral name"})).toBeInTheDocument();
 });
 it("omits class on the name-only compatibility path when current capability is absent",async()=>{
  const user=userEvent.setup();sessionFixture.current=classificationSession(false);
  const createEnvironment=vi.fn(async(workspaceId:string,name:string)=>({id:"pid_created",workspaceId,name,environmentClass:"development" as const,version:1}));
  render(<ScopeOnboardingView api={fixtureAPI({createEnvironment})} onScopeChange={vi.fn()}/>);
  await screen.findByRole("option",{name:"Agent Security"});expect(screen.queryByLabelText("New environment classification")).not.toBeInTheDocument();expect(screen.queryByLabelText("Environment classification")).not.toBeInTheDocument();
  await user.type(screen.getByLabelText("New environment name"),"Production");await user.click(screen.getByRole("button",{name:"Create environment"}));
  await waitFor(()=>expect(createEnvironment).toHaveBeenCalledWith("pid_workspace_a","Production"));
 });
 it("disables stale-auth class changes and does not infer or resend an uncertain update",async()=>{
  const user=userEvent.setup();sessionFixture.current=classificationSession(true,false);
  const updateEnvironment=vi.fn(async()=>{throw new Error("private database uncertainty")});
  const onScopeChange=vi.fn();const api=fixtureAPI({listEnvironments:async(workspaceId)=>[{id:"pid_environment_a",workspaceId,name:"Production",environmentClass:"development",version:8}],updateEnvironment});
  const {rerender}=render(<ScopeOnboardingView api={api} onScopeChange={onScopeChange}/>);
  expect(await screen.findByLabelText("Environment classification")).toBeDisabled();expect(screen.getByRole("button",{name:"Update environment"})).toBeDisabled();
  sessionFixture.current=classificationSession();rerender(<ScopeOnboardingView api={api} onScopeChange={onScopeChange}/>);
  await waitFor(()=>expect(screen.getByLabelText("Environment classification")).toBeEnabled());await user.selectOptions(screen.getByLabelText("Environment classification"),"production");await user.click(screen.getByRole("button",{name:"Update environment"}));
  expect(await screen.findByRole("alert")).toHaveTextContent("Scope action could not be completed");expect(updateEnvironment).toHaveBeenCalledTimes(1);expect(onScopeChange).not.toHaveBeenCalled();expect(screen.queryByText("Environment updated")).not.toBeInTheDocument();expect(screen.queryByText("private database uncertainty")).not.toBeInTheDocument();
 });
});
