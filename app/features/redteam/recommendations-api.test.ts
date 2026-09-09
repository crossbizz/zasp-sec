import { describe, expect, it } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { createProductionRedTeamAPI } from "./api";

const id="pid_92600001-0000-4000-8000-000000000001", evidence="pid_92600002-0000-4000-8000-000000000002", other="pid_92600003-0000-4000-8000-000000000003";
const scope=`${id}/${evidence}/${other}`;
const observed=new Date(Date.now()-60_000).toISOString(),fresh=new Date(Date.now()+3_600_000).toISOString();
const summary={id,name:"Agent",kind:"agent",owner:"",team:"",tags:[],evidence_id:evidence,confidence_basis_points:9500,first_seen:observed,last_seen:observed,observed_at:observed,fresh_until:fresh,freshness_state:"fresh",version:1};
const detail={summary,sources:[{integration_id:other,provider:"kubernetes",source:"kubernetes",source_identifier:`sha256:${"a".repeat(64)}`,snapshot_id:other,generation:1,evidence_id:evidence,confidence_basis_points:9500,observed_at:observed,fresh_until:fresh,projection_version:1,winning:true}],evidence:[{id:evidence,checksum:`sha256:${"b".repeat(64)}`,media_type:"application/json",schema_version:"raw_v1",parser_version:"parser_v1",tool_version:"tool_v1",collected_at:observed,size_bytes:128}]};
const edge={agent_id:id,target_id:other,target_kind:"resource",category:"data_read",outcome:"read",state:"reachable",reachable:true,evidence_ids:[evidence]};
function fixture(options:{foreign?:boolean;wrongTarget?:boolean;stale?:boolean;unavailable?:boolean;tool?:boolean}={}) {
  const requests:Request[]=[];
  const client=createAPIClient({getExpectedScope:()=>`${other}/${id}/${evidence}`,fetch:async request=>{
    requests.push(request.clone() as Request);
    const capabilities=new URL(request.url).pathname.endsWith("/capabilities");
    const body=capabilities?{items:[{...edge,agent_id:options.foreign?other:id}],page_info:{has_more:false,next_cursor:null}}:{...detail,summary:{...summary,id:options.wrongTarget?other:id,kind:options.tool?"tool":"agent",freshness_state:options.stale?"stale":"fresh"}};
    return new Response(JSON.stringify(options.unavailable?{code:"provider_unavailable",message:"unavailable",retryable:true,correlation_id:other}:body),{status:options.unavailable?503:200,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
  }});
  return {api:createProductionRedTeamAPI(client,scope),requests};
}
describe("production recommendation authority",()=>{
  it("derives data reach from actual scoped inventory and capability API reads",async()=>{
    const f=fixture();const result=await f.api.getTargetRecommendations(id,"agent");
    expect(result.items.map(item=>item.category)).toEqual(["data_leakage"]);expect(result.freshUntil).toBe(fresh);expect(result.targetID).toBe(id);
    expect(f.requests.map(request=>new URL(request.url).pathname)).toEqual([`/api/v1/agents/${id}`,`/api/v1/agents/${id}/capabilities`]);
    expect(f.requests.every(request=>request.headers.get("X-Zasp-Expected-Scope")===scope)).toBe(true);
  });
  for(const options of [{foreign:true},{wrongTarget:true},{stale:true},{unavailable:true}])it(`fails closed for ${Object.keys(options)[0]}`,async()=>{
    await expect(fixture(options).api.getTargetRecommendations(id,"agent")).rejects.toThrow();
  });
  it("uses tool detail without sending a tool ID to an agent operation",async()=>{
    const f=fixture({tool:true});expect((await f.api.getTargetRecommendations(id,"tool")).items[0].category).toBe("tool_abuse");
    expect(f.requests.map(request=>new URL(request.url).pathname)).toEqual([`/api/v1/tools/${id}`]);
  });
});
