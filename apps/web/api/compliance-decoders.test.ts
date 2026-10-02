import { describe, expect, it } from "vitest";
import { decodeComplianceControlPage, decodeComplianceEvidencePage, decodeSessionPage } from "./administration-decoders";
import { createSessionsComplianceAPI } from "../../../app/features/sessions/SessionsComplianceView";
import { decodeComplianceEvidenceDetail, decodeComplianceExport, decodeComplianceDownloadGrant } from "./compliance-decoders";
import { createAPIClient, requireAPIData } from "./client";
const scope={organization_id:"pid_10000001-0000-4000-8000-000000000001",workspace_id:"pid_10000002-0000-4000-8000-000000000002",environment_id:"pid_10000003-0000-4000-8000-000000000003"};
const record={id:"policy-001",asset_id:"policy-001",source:"policy",at:"2026-01-02T00:00:00.000000Z",target:{source_kind:"policy",source_id:"policy-001",source_version:7},metadata:{verification:"definition_only"}};
const detail={...scope,record,freshness:"stale"};
describe("compliance current contracts",()=>{
 it("paginates maximum policy IDs without widening unrelated cursors",async()=>{
  const id="policy-"+"a".repeat(121);
  const cursor=btoa(JSON.stringify({...scope,operation:"listEvidence",framework:"soc2_security",control_id:"",source_kind:"policy",source_id:id}).replaceAll(",",", ").replaceAll(":",": ")).replaceAll("=","").replaceAll("+","-").replaceAll("/","_");
  expect(cursor.length).toBeGreaterThan(512);
  const longRecord={...record,id,asset_id:id,target:{...record.target,source_id:id}};
  const item={control:{id:"soc2_security-policies",framework:"soc2_security",name:"Policy definitions",evidence_ids:[id],fresh_until:"2026-01-03T00:00:00Z"},freshness:"stale",evidence:[longRecord]};
  const first={items:[item],page_info:{has_more:true,next_cursor:cursor}};
  expect(decodeComplianceEvidencePage(first).items[0].evidence[0].id).toBe(id);
  expect(()=>decodeSessionPage({items:[],page_info:first.page_info})).toThrow();
  expect(()=>decodeComplianceEvidencePage({...first,page_info:{has_more:true,next_cursor:"a".repeat(5463)}})).toThrow();
  const client=createAPIClient({fetch:async request=>{
   const url=new URL(request.url);
   const next=url.searchParams.get("cursor");
   if(url.searchParams.get("framework")==="hipaa")return new Response(JSON.stringify({items:[],page_info:{has_more:false,next_cursor:null}}),{headers:{"Content-Type":"application/json"}});
   if(next)expect(next).toBe(cursor);
   return new Response(JSON.stringify(next?{items:[],page_info:{has_more:false,next_cursor:null}}:first),{headers:{"Content-Type":"application/json"}});
  }});
  expect((await createSessionsComplianceAPI(client).listEvidence(undefined,"current"))[0].evidence[0].target?.source_id).toBe(id);
 });
 it("validates authoritative freshness when present on direct live controls",()=>{
  const control={id:"soc2_security-policies",framework:"soc2_security",name:"Policy definitions",evidence_ids:[],fresh_until:"1970-01-01T00:00:00Z",freshness:"missing"};
  const page=(item:unknown)=>({items:[item],page_info:{has_more:false,next_cursor:null}});
  expect(decodeComplianceControlPage(page(control)).items[0]).toMatchObject({freshness:"missing"});
  for(const freshness of [undefined,"unknown",null]) expect(()=>decodeComplianceControlPage(page({...control,freshness}))).toThrow();
 });
 it("decodes the disabled-service legacy response without inventing freshness",async()=>{
  const legacy={id:"legacy-control",framework:"SOC 2",name:"Legacy seed",evidence_ids:[],fresh_until:"2020-01-02T00:00:00Z"};
  const client=createAPIClient({fetch:async()=>new Response(JSON.stringify({items:[legacy],page_info:{has_more:false,next_cursor:null}}),{headers:{"Content-Type":"application/json"}})});
  const result=await client.GET("/api/v1/compliance/controls");
  expect(requireAPIData(result,decodeComplianceControlPage).items[0]).toEqual(legacy);
  expect(requireAPIData(result,decodeComplianceControlPage).items[0]).not.toHaveProperty("freshness");
 });
 it("accepts typed policy sources, preserving old page records",()=>{
  expect(decodeComplianceEvidenceDetail(detail,scope).record.target?.source_version).toBe(7);
  const item={control:{id:"soc2_security-policies",framework:"soc2_security",name:"Policy definitions",evidence_ids:["policy-001"],fresh_until:"2026-01-03T00:00:00Z",freshness:"stale"},freshness:"stale",evidence:[record]};
  expect(decodeComplianceEvidencePage({items:[item],page_info:{has_more:false,next_cursor:null}}).items[0].evidence[0].target?.source_id).toBe("policy-001");
 });
 it("accepts retained PostgreSQL offset timestamps only on untargeted legacy records",()=>{
  const legacy={control:{id:"access-control",name:"Logical access controls",framework:"SOC 2",fresh_until:"2026-09-20T00:00:00+00:00",evidence_ids:["evidence-membership"]},evidence:[{at:"2026-09-19T00:00:00+00:00",id:"evidence-membership",source:"product-membership",asset_id:"asset-member"}],freshness:"fresh"};
  const page={items:[legacy],page_info:{has_more:false,next_cursor:null}};
  expect(decodeComplianceEvidencePage(page).items[0].evidence[0].at).toBe("2026-09-19T00:00:00+00:00");
  for(const at of ["2026-09-18T17:00:00-07:00","2026-09-19T05:30:00+05:30"])expect(decodeComplianceEvidencePage({...page,items:[{...legacy,evidence:[{...legacy.evidence[0],at}]}]}).items[0].evidence[0].at).toBe(at);
  for(const at of ["2026-02-31T00:00:00+00:00","2026-09-19T00:00:00+24:00","2026-09-19T00:00:00+05:60","2026-09-19T00:00:00"] )expect(()=>decodeComplianceEvidencePage({...page,items:[{...legacy,evidence:[{...legacy.evidence[0],at}]}]})).toThrow();
  expect(()=>decodeComplianceEvidenceDetail({...detail,record:{...record,at:"2026-01-02T00:00:00+00:00"}},scope)).toThrow();
  expect(()=>decodeComplianceEvidencePage({...page,items:[{...legacy,evidence:[{...record,at:"2026-01-02T00:00:00+00:00"}]}]})).toThrow();
 });
 it("rejects scope changes, untyped detail and source metadata outside its allowlist",()=>{
  for(const value of [{...detail,environment_id:scope.workspace_id},{...detail,record:{...record,target:undefined}},{...detail,record:{...record,metadata:{verification:"definition_only",prompt:"private"}}},{...detail,record:{...record,target:{...record.target,source_kind:"unknown"}}},{...detail,record:{...record,target:{...record.target,source_id:"policy-other"}}}]) expect(()=>decodeComplianceEvidenceDetail(value,scope)).toThrow();
 });
 it("bounds public jobs and body-only download grants",()=>{
  const job={id:scope.organization_id,status:"pending",formats:["json","csv","human"],created_at:"2026-09-18T00:00:00Z",expires_at:"2026-09-19T00:00:00Z",failure_code:null,mapping_revision:"product-evidence-v1"};
  expect(decodeComplianceExport(job).status).toBe("pending");
  for(const value of [{...job,reference:"s3://private"},{...job,id:"export-caller"},{...job,status:"uploading"},{...job,expires_at:job.created_at},{...job,created_at:"2026-09-18T00:00:00+00:00"}])expect(()=>decodeComplianceExport(value)).toThrow();
  const grant={token:"a".repeat(64),format:"human",expires_at:job.expires_at};expect(decodeComplianceDownloadGrant(grant).format).toBe("human");
  for(const value of [{...grant,format:"readable"},{...grant,url:"https://private"},{...grant,token:"short"},{...grant,expires_at:"2026-09-19T00:00:00+00:00"}])expect(()=>decodeComplianceDownloadGrant(value)).toThrow();
 });
 it("rejects calendar overflow instead of normalizing source timestamps",()=>{
  expect(()=>decodeComplianceEvidenceDetail({...detail,record:{...record,at:"2026-02-31T00:00:00Z"}},scope)).toThrow();
 });
});
