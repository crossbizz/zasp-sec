import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { buildRedTeamRuntimeArguments, createRedTeamRuntimeProof } from "./red-team-runtime-proof.mjs";

const config={owner:"12345678-1234-4234-8234-123456789abc",binary:"/tmp/proof/worker.test",runner:"/workspace/workers/redteam-node/runner.mjs",dsn:"postgres://zasp_e2e@127.0.0.1:15432/postgres?sslmode=disable",awsEndpoint:"http://127.0.0.1:14566",runID:"pid_92700001-0000-4000-8000-000000000001"};
test("Linux supervisor never signals after wait ownership is lost", async()=>{
  const source=await readFile(new URL("../services/platform/agentsec-worker/red_team_command_linux.go",import.meta.url),"utf8");
  const lost=source.split("if observed != nil {")[1]?.split("return errRuntimeUnavailable")[0];
  assert.ok(lost);
  assert.doesNotMatch(lost,/\.Kill\(|unix\.Kill\(|\.Signal\(/);
  assert.match(lost,/go func\(\)/);
});
test("composed runtime keeps the exact pinned image and production paths",()=>{
  const args=buildRedTeamRuntimeArguments(config);
  assert.equal(args[args.indexOf("--user")+1],"1000:1000");
  for(const value of ["--read-only","--cap-drop","ALL","--pids-limit","128","--memory","2g","--cpus","2","--entrypoint","/proof/red-team-worker.test","agentsec-red-team-adapter.zasp.svc.cluster.local:127.0.0.1","ZASP_RED_TEAM_RUNTIME_PROOF=true"])assert.ok(args.includes(value),value);
  assert.ok(args.some(value=>value.includes("@sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96")));
  assert.ok(args.some(value=>value.includes("dst=/app/redteam-runner.mjs,readonly")));
  assert.ok(args.includes("/var/run/secrets/zasp-red-team:rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=1000,gid=1000"));
  assert.ok(args.includes("ZASP_RED_TEAM_RUNTIME_DSN=postgres://zasp_e2e@host.docker.internal:15432/postgres?sslmode=disable"));
  assert.ok(!args.includes("--privileged"));assert.ok(!args.includes("--publish"));
});
test("runtime bridge rejects nonlocal data authority and malformed ownership",()=>{
  for(const changed of [{dsn:config.dsn.replace("127.0.0.1","database.customer.example")},{dsn:config.dsn.replace("zasp_e2e@","zasp_e2e:secret@")},{awsEndpoint:"https://aws.customer.example"},{owner:"foreign"},{binary:"/tmp/proof,readonly=false"},{runID:"bad"}])assert.throws(()=>buildRedTeamRuntimeArguments({...config,...changed}));
});
test("cleanup verifies exact labels before removing only its owned container",async()=>{
  const calls=[];const id="a".repeat(64);
  const command=async(_exe,args)=>{calls.push(args);if(args[0]==="create")return {status:0,stdout:id};if(args[0]==="inspect")return {status:0,stdout:JSON.stringify([{Id:id,Name:`/zasp-red-team-runtime-${config.owner}`,Config:{Labels:{"zasp.proof":"red-team-runtime","zasp.owner":config.owner}}}])};return {status:0,stdout:"PASS"};};
  const proof=createRedTeamRuntimeProof(command,{owner:config.owner});await proof.run(config);await proof.close();await proof.close();
  assert.deepEqual(calls.filter(args=>args[0]==="rm"),[["rm","--force",id]]);
});
test("cleanup refuses a container whose ownership changed",async()=>{
  const calls=[];const command=async(_exe,args)=>{calls.push(args);if(args[0]==="create")return {status:0,stdout:"a".repeat(64)};if(args[0]==="inspect")return {status:0,stdout:JSON.stringify([{Id:"a".repeat(64),Name:"/foreign",Config:{Labels:{}}}])};return {status:0,stdout:"PASS"};};
  const proof=createRedTeamRuntimeProof(command,{owner:config.owner});await proof.run(config);await assert.rejects(()=>proof.close(),/ownership/);assert.ok(!calls.some(args=>args[0]==="rm"));
});
test("an interrupted uncertain create is awaited and cleaned by its exact owner",async()=>{
  const calls=[];let resolveCreate;
  const id="b".repeat(64);
  const command=async(_exe,args)=>{
    calls.push(args);
    if(args[0]==="create")return new Promise(resolve=>{resolveCreate=resolve;});
    if(args[0]==="inspect")return {status:0,stdout:JSON.stringify([{Id:id,Name:`/zasp-red-team-runtime-${config.owner}`,Config:{Labels:{"zasp.proof":"red-team-runtime","zasp.owner":config.owner}}}])};
    return {status:0,stdout:""};
  };
  const proof=createRedTeamRuntimeProof(command,{owner:config.owner});
  const running=assert.rejects(proof.run(config),/creation failed/);
  const closing=proof.close();await Promise.resolve();
  assert.ok(!calls.some(args=>args[0]==="inspect"));
  resolveCreate({status:1,stdout:"",stderr:"response lost"});
  await running;await closing;
  assert.deepEqual(calls.filter(args=>args[0]==="rm"),[["rm","--force",id]]);
  assert.ok(!calls.some(args=>args[0]==="start"));
  await assert.rejects(proof.run(config),/execution rejected/);
});
test("successful creation completing after close never starts the container",async()=>{
  let resolveCreate;const calls=[];const id="c".repeat(64);
  const command=async(_exe,args)=>{calls.push(args);if(args[0]==="create")return new Promise(resolve=>{resolveCreate=resolve;});if(args[0]==="inspect")return {status:0,stdout:JSON.stringify([{Id:id,Name:`/zasp-red-team-runtime-${config.owner}`,Config:{Labels:{"zasp.proof":"red-team-runtime","zasp.owner":config.owner}}}])};return {status:0,stdout:""};};
  const proof=createRedTeamRuntimeProof(command,{owner:config.owner});
  const running=assert.rejects(proof.run(config),/interrupted/);const closing=proof.close();
  resolveCreate({status:0,stdout:id});await running;await closing;
  assert.ok(!calls.some(args=>args[0]==="start"));assert.deepEqual(calls.filter(args=>args[0]==="rm"),[["rm","--force",id]]);
});
test("cleanup rejects inspection outage but accepts confirmed owned absence",async()=>{
  for(const [stderr,allowed]of [["daemon unavailable",false],["No such object",true],["error: no such object",true]]){
    const calls=[];const proof=createRedTeamRuntimeProof(async(_exe,args)=>{calls.push(args);return args[0]==="create"?{status:1,stdout:""}:{status:1,stdout:"",stderr};},{owner:config.owner});
    await assert.rejects(proof.run(config),/creation failed/);
    if(allowed)await proof.close();else await assert.rejects(proof.close(),/inspection failed/);
    assert.ok(!calls.some(args=>args[0]==="rm"));
  }
});
