import { randomUUID } from "node:crypto";
import path from "node:path";

export const RED_TEAM_RUNTIME_IMAGE="ghcr.io/promptfoo/promptfoo:0.121.19@sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96";
const ownerPattern=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const runPattern=/^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function bridge(value, database=false) {
  const url=new URL(value);
  if(url.hostname!=="127.0.0.1" || !url.port || url.password || url.hash || (database ? url.protocol!=="postgres:" || url.username!=="zasp_e2e" || url.pathname!=="/postgres" || url.search!=="?sslmode=disable" : url.protocol!=="http:" || url.username || url.pathname!=="/" || url.search))throw new Error("local runtime authority rejected");
  url.hostname="host.docker.internal";return url.toString();
}
export function buildRedTeamRuntimeArguments({owner,binary,runner,dsn,awsEndpoint,runID}) {
  if(!ownerPattern.test(owner) || !runPattern.test(runID) || [binary,runner].some(value=>typeof value!=="string" || !path.isAbsolute(value) || /[,\r\n\0]/.test(value)))throw new Error("runtime proof identity rejected");
  return ["create","--name",`zasp-red-team-runtime-${owner}`,"--label","zasp.proof=red-team-runtime","--label",`zasp.owner=${owner}`,"--user","1000:1000","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","128","--memory","2g","--cpus","2","--tmpfs","/tmp:rw,nosuid,nodev,size=512m,mode=1777","--tmpfs","/var/run/secrets/zasp-red-team:rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=1000,gid=1000","--add-host","host.docker.internal:host-gateway","--add-host","agentsec-red-team-adapter.zasp.svc.cluster.local:127.0.0.1","--mount",`type=bind,src=${binary},dst=/proof/red-team-worker.test,readonly`,"--mount",`type=bind,src=${runner},dst=/app/redteam-runner.mjs,readonly`,"--env","ZASP_RED_TEAM_RUNTIME_PROOF=true","--env",`ZASP_RED_TEAM_RUNTIME_DSN=${bridge(dsn,true)}`,"--env",`ZASP_RED_TEAM_RUNTIME_AWS=${bridge(awsEndpoint)}`,"--env",`ZASP_RED_TEAM_RUNTIME_RUN_ID=${runID}`,"--entrypoint","/proof/red-team-worker.test",RED_TEAM_RUNTIME_IMAGE,"-test.run","^(TestProductionCombinedE2ERedTeamRuntime|TestProductionRedTeamCommandCancellationStopsDescendant|TestProductionRedTeamCommandCompletionAndCancellationRace)$","-test.v","-test.timeout","240s"];
}
export function createRedTeamRuntimeProof(command,{owner=randomUUID()}={}) {
  if(typeof command!=="function" || !ownerPattern.test(owner))throw new Error("runtime proof owner rejected");
  let closed=false,started=false,creating,containerID,closing;
  const name=`zasp-red-team-runtime-${owner}`;
  return {
    async prepare(){
      if(closed || started)throw new Error("runtime preparation rejected");
      await command("docker",["pull",RED_TEAM_RUNTIME_IMAGE],{timeout:120_000});
      const result=await command("docker",["image","inspect","--format","{{.Architecture}}",RED_TEAM_RUNTIME_IMAGE],{timeout:10_000});
      const architecture=result.stdout.trim();
      if(closed || !["amd64","arm64"].includes(architecture))throw new Error("runtime image architecture rejected");
      return architecture;
    },
    async run(config){
      if(closed || started)throw new Error("runtime execution rejected");
      const args=buildRedTeamRuntimeArguments({...config,owner});started=true;
      creating=command("docker",args,{timeout:10_000,reject:false});
      const result=await creating;
      if(result.status!==0 || !/^[a-f0-9]{64}$/.test(result.stdout.trim()))throw new Error("runtime container creation failed");
      containerID=result.stdout.trim();if(closed)throw new Error("runtime proof interrupted");
      return command("docker",["start","--attach",containerID],{timeout:250_000});
    },
    close(){
      if(closing)return closing;closed=true;
      closing=(async()=>{
        if(!started)return;
        await creating?.catch(()=>undefined);
        const result=await command("docker",["inspect",containerID??name],{timeout:3_000,reject:false});
        if(result.status!==0){if(/No such (object|container)/i.test(result.stderr??result.stdout))return;throw new Error("runtime cleanup inspection failed");}
        const records=JSON.parse(result.stdout),record=records[0];
        if(records.length!==1 || !/^[a-f0-9]{64}$/.test(record?.Id??"") || containerID && record.Id!==containerID || record.Name!==`/${name}` || record.Config?.Labels?.["zasp.proof"]!=="red-team-runtime" || record.Config?.Labels?.["zasp.owner"]!==owner)throw new Error("runtime cleanup ownership rejected");
        const removed=await command("docker",["rm","--force",record.Id],{timeout:3_000,reject:false});if(removed.status!==0)throw new Error("runtime cleanup failed");
      })();return closing;
    },
  };
}
