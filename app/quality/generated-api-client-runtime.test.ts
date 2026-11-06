import { describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../apps/web/api/client";

describe("generated API client runtime boundary", () => {
  it("constructs without Fetch I/O and rejects remote servers", () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));
    const client = createAPIClient({ fetch });

    expect(client).toBeDefined();
    expect(fetch).not.toHaveBeenCalled();
    expect(() => createAPIClient({ baseUrl: "https://example.invalid", fetch })).toThrow("Invalid API client configuration");
  });
});

import { createScopeAdminAPI } from "../features/identity/ScopeOnboardingView";

it("carries optional Environment class through generated mutations and retains authoritative response class/version",async()=>{
 const id=(n:number)=>`pid_${n.toString(16).padStart(8,"0")}-0000-4000-8000-000000000001`;
 const requests:{method:string;body:Record<string,unknown>;headers:Headers}[]=[];
 const fetch=vi.fn(async(request:Request)=>{
  const body=await request.json() as Record<string,unknown>;requests.push({method:request.method,body,headers:request.headers});
  // Deliberately return a class independent of request/name; success follows
  // server authority, never an optimistic local selected value.
  const response={id:id(4),organization_id:id(1),workspace_id:id(2),name:"Server display name",environment_class:"test",version:37};
  return new Response(JSON.stringify(response),{status:request.method==="POST"?201:200,headers:{"Content-Type":"application/json","X-Correlation-ID":id(5),ETag:'"37"'}});
 });
 const client=createAPIClient({fetch,getCSRFToken:()=>"c".repeat(48),getExpectedScope:()=>`${id(1)}/${id(2)}/${id(3)}`,generateCorrelationID:()=>id(5)});
 const api=createScopeAdminAPI(client);
 for(const environmentClass of ["production","staging","development","test"] as const){
  const created=await api.createEnvironment(id(2),"Neutral name",environmentClass);
  expect(requests.at(-1)?.body).toEqual({workspace_id:id(2),name:"Neutral name",environment_class:environmentClass});
  expect(created).toMatchObject({environmentClass:"test",version:37,name:"Server display name"});
  const updated=await api.updateEnvironment(id(4),"Production",37,environmentClass);
  expect(requests.at(-1)?.body).toEqual({name:"Production",environment_class:environmentClass});
  expect(requests.at(-1)?.headers.get("If-Match")).toBe('"37"');expect(requests.at(-1)?.headers.get("X-CSRF-Token")).toBe("c".repeat(48));expect(requests.at(-1)?.headers.get("X-Zasp-Expected-Scope")).toBe(`${id(1)}/${id(2)}/${id(3)}`);
  expect(updated).toMatchObject({environmentClass:"test",version:37});
 }
 await api.createEnvironment(id(2),"Production");expect(requests.at(-1)?.body).toEqual({workspace_id:id(2),name:"Production"});
 await api.updateEnvironment(id(4),"Development",37);expect(requests.at(-1)?.body).toEqual({name:"Development"});
 expect(fetch).toHaveBeenCalledTimes(10);
});
