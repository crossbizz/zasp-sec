import type { Capability, InventorySummary, TestDefinitionInput } from "../../../apps/web/api/generated";

export type RedTeamPackRecommendation = Readonly<{category:TestDefinitionInput["categories"][number];explanation:string;evidenceIDs:readonly string[]}>;
const rules = [
  {category:"tool_abuse",explanation:"Reachable tool invocation is supported by discovered capability evidence.",matches:(edge:Capability)=>edge.target_kind==="tool" && edge.category==="action_execute" && edge.outcome==="execute"},
  {category:"data_leakage",explanation:"Discovered read access reaches data; test that boundary. Data classification is not inferred.",matches:(edge:Capability)=>edge.category==="data_read" && edge.outcome==="read"},
  {category:"authorization_bypass",explanation:"Discovered identity or administrative authority warrants authorization-boundary testing.",matches:(edge:Capability)=>edge.category==="identity_assume" && edge.outcome==="assume" || edge.category==="administration" && edge.outcome==="administer"},
  {category:"excessive_agency",explanation:"Discovered write or execution authority warrants bounded side-effect testing.",matches:(edge:Capability)=>edge.category==="data_write" && edge.outcome==="write" || edge.category==="action_execute" && edge.outcome==="execute"},
] as const;

// Names and tags are not capability authority. A missing recommendation does
// not assert safety; operators can still select an explicit curated category.
export function recommendRedTeamPacks(target:InventorySummary,capabilities:readonly Capability[],now:number):readonly RedTeamPackRecommendation[] {
  if (!Number.isFinite(now) || !["agent","tool"].includes(target.kind) || target.freshness_state!=="fresh" || !(Date.parse(target.observed_at)<=now && Date.parse(target.fresh_until)>now) || capabilities.length>10_000) throw new Error("Fresh target authority is unavailable");
  if (capabilities.some(edge=>edge.agent_id!==target.id || edge.evidence_ids.length===0) || target.kind==="tool" && capabilities.length>0) throw new Error("Capability evidence does not match the target");
  if(target.kind==="tool") return [{category:"tool_abuse",explanation:"This freshly discovered tool is a direct tool-security test target.",evidenceIDs:[target.evidence_id]}];
  const reachable=capabilities.filter(edge=>edge.reachable && edge.state!=="blocked");
  return rules.flatMap(rule=>{
    const matching=reachable.filter(rule.matches);
    if(matching.length===0)return [];
    return [{category:rule.category,explanation:rule.explanation,evidenceIDs:[...new Set(matching.flatMap(edge=>edge.evidence_ids))].sort()}];
  });
}
