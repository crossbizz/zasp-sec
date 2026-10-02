import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { ZaspProductionApp } from "./ZaspProductionApp";
import { APIProvider } from "../api/APIProvider";
import { SessionProvider, useSession } from "../auth/SessionProvider";

const org="pid_10000001-0000-4000-8000-000000000001", workspace="pid_10000002-0000-4000-8000-000000000002", environment="pid_10000003-0000-4000-8000-000000000003", principal="pid_10000004-0000-4000-8000-000000000004", second="pid_10000005-0000-4000-8000-000000000005";
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
const bootstrap=(capabilities:string[], active=environment)=>({principal:{id:principal,organization_id:org,organization_reference:"organization-postlogin",member_reference:"member-postlogin",role:"security_admin",active:true},organization_id:org,workspace_id:workspace,environment_id:active,permissions:[],capabilities,csrf_token:"c".repeat(32),fresh_auth_expires_at:new Date(Date.now()+240_000).toISOString(),correlation_id:principal});
const emptyPage=()=>json({items:[],page_info:{has_more:false,next_cursor:null}});
afterEach(()=>{vi.unstubAllGlobals();window.history.replaceState({},"","/");});

it.each([false,true])("keeps a permitted Security Agent visible with catalog authority %s",async(catalogAllowed)=>{
  window.history.replaceState({},"","/protect/security-agents");
  const catalogReads:string[]=[];
  const id="pid_40000001-0000-4000-8000-000000000001";
  const definition={id,name:"Resource-only response",trigger_kind:"finding",trigger_source:"credential",environment_ids:[environment],autonomy:"supervised",max_steps:10,max_duration_seconds:900,temporary_policy_seconds:3600,ai_token_budget:4000,concurrency_limit:2,allowed_actions:["update_finding_response"],verification_kind:"finding_state",definition_version:1,enabled:false};
  vi.stubGlobal("fetch",async(request:Request)=>{
    const path=new URL(request.url).pathname;
    if(path==="/api/v1/session/bootstrap")return json(bootstrap(["security-agents.read","security-agents.write",...(catalogAllowed?["security-agents.catalog.read"]:[])]));
    if(path==="/api/v1/workflow-mutation-receipts")return json({items:[]});
    if(path==="/api/v1/security-agents")return json({items:[definition],page_info:{has_more:false,next_cursor:null}});
    if(path===`/api/v1/security-agents/${id}`)return new Response(JSON.stringify(definition),{headers:{"Content-Type":"application/json","Cache-Control":"no-store",ETag:'"1"'}});
    if(path===`/api/v1/security-agents/${id}/activation`)return json({id,activation:"draft",enabled:false,version:1});
    if(path==="/api/v1/security-agent-runs"||path==="/api/v1/security-agent-approvals")return json({items:[]});
    if(path==="/api/v1/security-agent-templates"||path==="/api/v1/security-actions"){
      catalogReads.push(path);
      return catalogAllowed?json({items:[]}):json({code:"request_forbidden",message:"Environment catalog denied",correlation_id:principal,retryable:false},403);
    }
    throw Error(`Unexpected resource-only request ${path}`);
  });
  render(<ZaspProductionApp/>);
  const open=await screen.findByRole("button",{name:"Open Resource-only response"});
  if(catalogAllowed)expect(screen.getByRole("button",{name:"Create Security Agent"})).toBeVisible();
  else expect(screen.queryByRole("button",{name:"Create Security Agent"})).not.toBeInTheDocument();
  await userEvent.click(open);
  expect(await screen.findByLabelText("Definition name")).toHaveValue("Resource-only response");
  expect(screen.getByRole("button",{name:"Delete definition"})).toBeEnabled();
  if(catalogAllowed){expect(catalogReads.sort()).toEqual(["/api/v1/security-actions","/api/v1/security-agent-templates"].sort());}
  else{expect(catalogReads).toEqual([]);expect(screen.queryByRole("button",{name:"Create Security Agent"})).not.toBeInTheDocument();expect(screen.getAllByText(/Environment catalog access is unavailable/).length).toBeGreaterThan(0);expect(screen.queryByText("This server does not support the configured actions.")).not.toBeInTheDocument();}
});

it.each([false,true])("uses scoped execution-control capability, not organization identity authority (%s)",async(scoped)=>{
  window.history.replaceState({},"","/protect/security-agents");
  let controlReads=0;
  vi.stubGlobal("fetch",async(request:Request)=>{
    const path=new URL(request.url).pathname;
    if(path==="/api/v1/session/bootstrap")return json(bootstrap(["security-agents.read",scoped?"security-agents.controls.manage":"identity.manage"]));
    if(path==="/api/v1/workflow-mutation-receipts")return json({items:[]});
    if(path==="/api/v1/security-agent-execution-controls"){
      controlReads++;
      return new Response(JSON.stringify({global:{target:"global",action_key:"*",enabled:true,version:1},environment:{target:"environment",action_key:"*",enabled:true,version:1},actions:["create_evidence_export","create_temporary_policy","isolate_session","rerun_test","revoke_integration_connection","run_test","start_attack_lab","update_finding_response"].map(action_key=>({target:"action",action_key,enabled:true,version:1}))}),{headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
    }
    if(path==="/api/v1/security-agents")return emptyPage();
    if(path.startsWith("/api/v1/security-agent")||path==="/api/v1/security-actions")return json({items:[]});
    throw Error(`Unexpected controls request ${path}`);
  });
  render(<ZaspProductionApp/>);
  await screen.findByRole("heading",{name:"Security agents"});
  if(scoped)expect(await screen.findByText("Execution controls")).toBeVisible();
  else await waitFor(()=>expect(screen.queryByText("Loading Security Agents…")).not.toBeInTheDocument());
  expect(controlReads).toBe(scoped?1:0);
  if(!scoped)expect(screen.queryByText("Execution controls")).not.toBeInTheDocument();
});

function PolicyRefreshConsumer(){const session=useSession();return <><span>{session.status === "error" ? session.authorizationStatus : session.status}</span>{session.hasCapability("findings.read")&&<span>Current findings access</span>}<button onClick={()=>void session.retry()}>Refresh policy</button></>;}
it("withdraws earlier capabilities on pending rebootstrap and recovers with current denial",async()=>{
  let phase=0;
  vi.stubGlobal("fetch",async(request:Request)=>{
    expect(new URL(request.url).pathname).toBe("/api/v1/session/bootstrap");
    if(phase===1)return json({code:"authorization_pending",message:"Projection pending",correlation_id:principal,retryable:true},409);
    return json(bootstrap(phase===0?["findings.read"]:[]));
  });
  render(<APIProvider><SessionProvider><PolicyRefreshConsumer/></SessionProvider></APIProvider>);
  expect(await screen.findByText("Current findings access")).toBeVisible();
  phase=1;await userEvent.click(screen.getByRole("button",{name:"Refresh policy"}));
  expect(await screen.findByText("pending")).toBeVisible();expect(screen.queryByText("Current findings access")).not.toBeInTheDocument();
  phase=2;await userEvent.click(screen.getByRole("button",{name:"Refresh policy"}));
  expect(await screen.findByText("authenticated")).toBeVisible();expect(screen.queryByText("Current findings access")).not.toBeInTheDocument();
});

it("shows pending and outage without authenticated capabilities, then switches an empty-policy scope",async()=>{
  let phase=0,switched=false;
  vi.stubGlobal("fetch",async(request:Request)=>{
    const path=new URL(request.url).pathname;
    if(path==="/api/v1/session/bootstrap"){
      if(phase<2)return json({code:phase===0?"authorization_pending":"authorization_unavailable",message:"Authorization unavailable",correlation_id:principal,retryable:true},phase===0?409:503);
      return json(bootstrap(switched?["scope.switch","findings.read"]:["scope.switch"],switched?second:environment));
    }
    if(path==="/api/v1/session/scopes")return json({items:[{organization_id:org,workspace_id:workspace,environment_id:environment,label:"Original"},{organization_id:org,workspace_id:workspace,environment_id:second,label:"Second"}]});
    if(path==="/api/v1/session/scope"){expect(request.method).toBe("PUT");expect(request.headers.get("X-CSRF-Token")).toBe("c".repeat(32));expect(await request.json()).toEqual({workspace_id:workspace,environment_id:second});switched=true;return new Response(null,{status:204});}
    if(path==="/api/v1/workflow-mutation-receipts")return json({items:[]});
    if(path==="/api/v1/findings")return emptyPage();
    throw Error(`Unexpected post-login request ${path}`);
  });
  render(<ZaspProductionApp/>);
  expect(await screen.findByRole("heading",{name:"Authorization pending"})).toBeVisible();
  expect(screen.queryByRole("navigation",{name:"Main navigation"})).not.toBeInTheDocument();
  phase=1;await userEvent.click(screen.getByRole("button",{name:"Retry"}));
  expect(await screen.findByRole("heading",{name:"Session unavailable"})).toBeVisible();
  phase=2;await userEvent.click(screen.getByRole("button",{name:"Retry"}));
  expect(await screen.findByRole("heading",{name:"No product capabilities"})).toBeVisible();
  await userEvent.selectOptions(screen.getByRole("combobox",{name:"Authorized scope"}),`${workspace}/${second}`);
  expect(await screen.findByRole("link",{name:"Findings"})).toBeVisible();
  expect(screen.queryByRole("link",{name:"Agents"})).not.toBeInTheDocument();
  expect(screen.getByRole("combobox",{name:"Authorized scope"})).toHaveValue(`${workspace}/${second}`);
});

it.each([[true,false],[false,true],[true,true]] as const)("loads only authorized identity subviews (organization %s, environment %s)",async(organizationAllowed,environmentAllowed)=>{
  window.history.replaceState({},"","/administration/identity-access");
  const forbidden:string[]=[];
  vi.stubGlobal("fetch",async(request:Request)=>{
    const path=new URL(request.url).pathname;
    if(path==="/api/v1/session/bootstrap")return json(bootstrap([...(organizationAllowed?["identity.manage"]:[]),...(environmentAllowed?["identity.groups.manage","identity.scopes.manage"]:[])]));
    if(path==="/api/v1/workflow-mutation-receipts")return json({items:[]});
    const orgOnly=["/api/v1/admin/members","/api/v1/admin/roles","/api/v1/admin/sso-connections","/api/v1/admin/scim-connections"].includes(path);
    const envOnly=["/api/v1/admin/group-mappings","/api/v1/organization","/api/v1/workspaces","/api/v1/environments"].includes(path);
    if(orgOnly&&!organizationAllowed||envOnly&&!environmentAllowed){forbidden.push(path);return json({code:"request_forbidden",message:"Request forbidden",correlation_id:principal,retryable:false},403);}
    if(path==="/api/v1/admin/roles")return json({items:[{role:"security_admin",permissions:["manage_identity"]}],page_info:{has_more:false,next_cursor:null}});
    if(path==="/api/v1/organization")return json({id:org,name:"Post-login",domain:"post-login.invalid",version:1});
    if(orgOnly||envOnly)return emptyPage();
    throw Error(`Unexpected identity request ${path}`);
  });
  render(<ZaspProductionApp/>);
  expect(await screen.findByRole("heading",{name:environmentAllowed?"Group mappings":"Members"})).toBeVisible();
  await waitFor(()=>expect(screen.queryByText("Loading identity and access…")).not.toBeInTheDocument());
  expect(screen.queryByRole("heading",{name:"Members"})!==null).toBe(organizationAllowed);
  expect(screen.queryByRole("heading",{name:"Group mappings"})!==null).toBe(environmentAllowed);
  if(environmentAllowed){expect(within(screen.getByRole("combobox",{name:"Mapped role"})).getByRole("option",{name:"read only viewer"})).toBeVisible();expect(await screen.findByRole("button",{name:"Create workspace"})).toBeVisible();}
  expect(screen.queryByText("Identity data could not be loaded")).not.toBeInTheDocument();
  expect(forbidden).toEqual([]);
});
