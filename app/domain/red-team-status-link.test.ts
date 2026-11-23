import {expect,it} from "vitest";
import {parseActivityLink} from "./activity-links";
import {parseRedTeamStatusLink,redTeamStatusLink,type RedTeamStatusReference} from "./red-team-status-link";
const id=(n:number)=>"pid_90000000-0000-4000-8000-"+String(n).padStart(12,"0");
const scope=[id(1),id(2),id(3),id(4)].join("/");
const ref:RedTeamStatusReference={kind:"updated",id:id(5),scope,version:2};
it("accepts only the canonical record and matching authenticated principal",()=>{
 const link=redTeamStatusLink(ref);
 expect(parseRedTeamStatusLink(link,scope)).toEqual({state:"selected",ref});
 expect(parseRedTeamStatusLink(link,scope.replace(id(1),id(6))).state).toBe("scope_mismatch");
 expect(parseActivityLink(link,{principalID:id(6),organizationID:id(2),workspaceID:id(3),environmentID:id(4)}).state).toBe("scope_mismatch");
 for(const query of [link+"&target="+id(6),link+"&record_id="+id(6),link.replace("from_version=2","from_version=0"),link.replace("record_status=updated","record_status=create")]){
  expect(parseRedTeamStatusLink(query,scope).state).toBe("invalid");
 }
});
