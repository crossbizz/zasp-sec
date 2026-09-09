import { describe, expect, it } from "vitest";
import type { Capability, InventorySummary } from "../../../apps/web/api/generated";
import { recommendRedTeamPacks } from "./recommendations";

const target: InventorySummary = {id:"pid_92500001-0000-4000-8000-000000000001",name:"discovered-agent",kind:"agent",owner:"",team:"",tags:[],evidence_id:"pid_92500002-0000-4000-8000-000000000002",confidence_basis_points:9500,first_seen:"2026-09-09T00:00:00Z",last_seen:"2026-09-09T00:00:00Z",observed_at:"2026-09-09T00:00:00Z",fresh_until:"2026-09-09T02:00:00Z",freshness_state:"fresh",version:1};
const now = Date.parse("2026-09-09T01:00:00Z");
const edge: Capability = {agent_id:target.id,target_id:"pid_92500003-0000-4000-8000-000000000003",target_kind:"tool",category:"action_execute",outcome:"execute",state:"reachable",reachable:true,evidence_ids:[target.evidence_id]};

describe("evidence-derived Red Team recommendations",()=>{
  it("recommends only relevant tool and data boundaries with evidence and explanations",()=>{
    const values=recommendRedTeamPacks(target,[edge,{...edge,target_kind:"resource",category:"data_read",outcome:"read"}],now);
    expect(values.map(value=>value.category)).toEqual(["tool_abuse","data_leakage","excessive_agency"]);
    for(const value of values){expect(value.explanation.length).toBeGreaterThan(15);expect(value.evidenceIDs).toEqual([target.evidence_id]);}
    expect(values.find(value=>value.category==="data_leakage")!.explanation).not.toMatch(/sensitive/i);
  });
  it("does not infer capabilities from names, tags, or missing edges",()=>{
    expect(recommendRedTeamPacks({...target,name:"Sensitive tool reader",tags:["admin","untrusted"]},[],now)).toEqual([]);
  });
  it("excludes blocked and unreachable boundaries",()=>{
    expect(recommendRedTeamPacks(target,[{...edge,state:"blocked"},{...edge,reachable:false}],now)).toEqual([]);
  });
  it("rejects another agent or missing evidence instead of producing misleading recommendations",()=>{
    expect(()=>recommendRedTeamPacks(target,[{...edge,agent_id:edge.target_id}],now)).toThrow();
    expect(()=>recommendRedTeamPacks(target,[{...edge,evidence_ids:[]}],now)).toThrow();
  });
  it("rejects stale inventory regardless of a stale cached freshness label",()=>{
    expect(()=>recommendRedTeamPacks(target,[edge],Date.parse(target.fresh_until))).toThrow();
    expect(()=>recommendRedTeamPacks({...target,freshness_state:"stale"},[edge],now)).toThrow();
  });
  it("deduplicates and orders recommendations independently of capability row order",()=>{
    const identity={...edge,target_kind:"identity" as const,category:"identity_assume" as const,outcome:"assume" as const};
    expect(recommendRedTeamPacks(target,[identity,edge,edge],now)).toEqual(recommendRedTeamPacks(target,[edge,identity],now));
  });
  it("recommends a directly discovered tool boundary without inventing agent capabilities",()=>{
    expect(recommendRedTeamPacks({...target,kind:"tool"},[],now)).toEqual([{category:"tool_abuse",explanation:"This freshly discovered tool is a direct tool-security test target.",evidenceIDs:[target.evidence_id]}]);
    expect(()=>recommendRedTeamPacks({...target,kind:"tool"},[edge],now)).toThrow();
  });
});
