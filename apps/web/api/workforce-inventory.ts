import {APITransportError,requireAPIData,type APIClient} from "./client";
import type {WorkforceInventoryPage} from "./generated";

const cursorPattern=/^pid_[0-9a-f-]{36}\.(built_in|studio)$/;
const validList=(v:unknown)=>Array.isArray(v)&&v.every(value=>typeof value==="string");
export function decodeWorkforcePage(raw:unknown,after=""):WorkforceInventoryPage{
 const invalid=():never=>{throw new APITransportError("invalid_response","Invalid workforce inventory");};
 if(!raw||typeof raw!=="object")return invalid();
 const p=raw as Record<string,unknown>;
 if(!Array.isArray(p.items)||p.items.length>25)return invalid();
 let prior=after;
 for(const row of p.items){
  if(!row || typeof row!=="object" || typeof row.id!=="string" || !["built_in","studio"].includes(row.source) || !cursorPattern.test(row.id+"."+row.source) || row.id+"."+row.source<=prior ||
   !Number.isSafeInteger(row.revision)||row.revision<1||typeof row.name!=="string" || typeof row.mission!=="string" || typeof row.trigger!=="string" || !validList(row.actions)||!validList(row.read_tools) ||
   !Number.isSafeInteger(row.trigger_receipts)||row.trigger_receipts<0 || typeof row.updated_at!=="string" || !Number.isFinite(Date.parse(row.updated_at)))return invalid();
  prior=row.id+"."+row.source;
 }
 if(p.next_cursor!==null && (!p.items.length || p.next_cursor!==prior))return invalid();
 return p as WorkforceInventoryPage;
}
export const workforceAPI=(client:APIClient)=>async(cursor:string|undefined,signal?:AbortSignal)=>
 requireAPIData(await client.GET("/api/v1/agents/workforce",{params:{query:{limit:25,cursor}},signal}),raw=>decodeWorkforcePage(raw,cursor));
