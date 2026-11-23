import {APITransportError,requireAPIData,type APIClient} from "./client";
import type {InventoryReviewReceipt} from "./generated";
const routes = {
 agent_discovery_verify:"/api/v1/agents/{id}/discovery/verify",
 agent_purpose_draft:"/api/v1/agents/{id}/purpose/draft",
 addon_semantic_audit:"/api/v1/addon-versions/{id}/deep-scan",
} as const;
export type ReviewPurpose=keyof typeof routes;
const list=(v:unknown,max:number) => Array.isArray(v) && v.length<=max && v.every(item=>typeof item==="string" && item.length<=128);
const score=(v:unknown) => typeof v==="number" && Number.isFinite(v) && v>=0 && v<=1;

export function decodeInventoryReview(raw:unknown,id:string,p:ReviewPurpose): InventoryReviewReceipt {
 const fail=():never=>{throw new APITransportError("invalid_response","Invalid evidence review receipt");};
 if (!raw || typeof raw !=="object") return fail();
 const r=raw as Record<string,unknown>;
 if(r.target_id!==id || r.purpose!==p || typeof r.coverage_degraded!=="boolean") return fail();
 if(r.coverage_degraded){if(r.result!==null)return fail();return r as InventoryReviewReceipt;}
 if(!r.result || typeof r.result!=="object") return fail();
 const v=r.result as Record<string,unknown>;
 if(p==="agent_discovery_verify" && (!list(v.evidence_refs,32) || !["autonomous_agent","simple_llm_app","mcp_server","skill_addon","not_an_agent_fp"].includes(String(v.kind))))return fail();
 if(p==="agent_purpose_draft" && (!list(v.allowed_tool_ids,64) || !list(v.iam_mismatches,32)))return fail();
 if(p==="addon_semantic_audit" && (!list(v.citations,32)||!list(v.tags,16)||!score(v.threat_score)||!score(v.risk_score)))return fail();
 return r as InventoryReviewReceipt;
}

export const reviewAPI=(client:APIClient)=>async(id:string,p:ReviewPurpose,key:string,signal?:AbortSignal) =>
 requireAPIData(await client.POST(routes[p],{params:{path:{id},header:{"Idempotency-Key":key,"X-CSRF-Token":""}},body:{},signal}),raw=>decodeInventoryReview(raw,id,p));
