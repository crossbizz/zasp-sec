import { describe, expect, it } from "vitest";
import { decodeInventoryPage } from "./decoders";
const summary = { id:"pid_10000001-0000-4000-8000-000000000001",name:"Agent",kind:"agent",owner:"",team:"platform",tags:[],evidence_id:"pid_20000001-0000-4000-8000-000000000001",confidence_basis_points:9500,first_seen:"2026-08-19T00:00:00Z",last_seen:"2026-08-19T01:00:00Z",observed_at:"2026-08-19T01:00:00Z",fresh_until:"2026-08-19T01:15:00Z",freshness_state:"fresh",version:1 };
const decode = (owner:string) => decodeInventoryPage({items:[{...summary,owner}],page_info:{next_cursor:null,has_more:false}}).items[0].owner;
describe("persisted Agent owner label domain",()=>{
 it("retains exact whitespace and128 Unicode scalars independent of UTF16 units",()=>{for(const owner of ["","   "," Security ","😀".repeat(128),"é".repeat(128)]) expect(decode(owner)).toBe(owner);});
 it("rejects excess scalars, controls and unpaired surrogates",()=>{for(const owner of ["😀".repeat(129),"a\u0000b","a\u007fb","\ud800","\udfff"]) expect(()=>decode(owner)).toThrow();});
 it("does not relax other summary field bounds",()=>{expect(()=>decodeInventoryPage({items:[{...summary,team:"😀".repeat(128)}],page_info:{next_cursor:null,has_more:false}})).toThrow();});
});
