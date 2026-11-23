export const redTeamPath = "/red-team/results";
export type RedTeamStatusReference = Readonly<{kind:"created"|"updated"|"submitted"|"cancellation"; id:string; version:number; scope:string}>;
const pid=/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const scopeNames=["principal_id","organization_id","workspace_id","environment_id"] as const;
export function redTeamStatusLink(ref:RedTeamStatusReference) {
  const ids=ref.scope.split("/");
  if (!["created","updated","submitted","cancellation"].includes(ref.kind) || !pid.test(ref.id) ||
    ids.length!==4 || !ids.every(id=>pid.test(id)) || !Number.isSafeInteger(ref.version) || ref.version<0 || ref.version>999999 ||
    ((ref.kind==="created" || ref.kind==="submitted") !== (ref.version===0))) throw Error("Invalid record reference");
  const q=new URLSearchParams({record_status:ref.kind,record_id:ref.id,from_version:String(ref.version)});
  scopeNames.forEach((name,i)=>q.set(name,ids[i]));
  return redTeamPath+"?"+q;
}
export function parseRedTeamStatusLink(location:string,scope:string) {
  if (!location.startsWith(redTeamPath+"?record_status=")) return {state:"none" as const};
  const q=new URLSearchParams(location.slice(redTeamPath.length+1));
  const ref={kind:q.get("record_status"),id:q.get("record_id")??"",version:Number(q.get("from_version")),scope:scopeNames.map(name=>q.get(name)??"").join("/")} as RedTeamStatusReference;
  try{if(redTeamStatusLink(ref)!==location)return {state:"invalid" as const};}catch{return {state:"invalid" as const};}
  if(ref.scope!==scope)return {state:"scope_mismatch" as const};
  return {state:"selected" as const,ref};
}
