// Owned local acceptance operator. No registry pull or product credentials.
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm, mkdir, chmod, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
const evidence=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(evidence,"../../../..");
const temporary=await mkdtemp("/private/tmp/zasp-public-restart-");
const containerName=path.basename(temporary).toLowerCase();
let activeChild;
let interrupted=false;
const runtimeEvidence=path.join(evidence,"runtime");
await mkdir(runtimeEvidence,{recursive:true});await chmod(runtimeEvidence,0o777);
const image="postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba";
const commands=[];
async function files(directory) {
  const result=[];
  for(const entry of await readdir(path.join(root,directory),{withFileTypes:true})) {
    const name=path.join(directory,entry.name);
    if(entry.isDirectory()) result.push(...await files(name));
    else if(entry.isFile()) result.push(name);
  }
  return result.sort();
}
const source=await files("services/platform");
const hashes={};
for(const name of source) hashes[name]=createHash("sha256").update(await readFile(path.join(root,name))).digest("hex");
async function run(command,args,env={},timeout=960000) {
  if(interrupted) throw new Error("operator interrupted");
  commands.push({command,args,env});
  const child=spawn(command,args,{cwd:path.join(root,"services/platform"),env:{...process.env,...env},stdio:["ignore","pipe","pipe"]});
  activeChild=child;
  let escalation;
  const deadline=setTimeout(()=>{child.kill("SIGTERM");escalation=setTimeout(()=>child.kill("SIGKILL"),3000)},timeout);
  let stdout="",stderr="";
  child.stdout.on("data",b=>{stdout+=b;process.stdout.write(b)});
  child.stderr.on("data",b=>{stderr+=b;process.stderr.write(b)});
  const result=await new Promise((resolve,reject)=>{child.once("error",reject);child.once("close",(status,signal)=>resolve({status,signal,stdout,stderr}))});
  clearTimeout(deadline);clearTimeout(escalation);activeChild=undefined;
  return result;
}
for(const signal of ["SIGINT","SIGTERM"]) process.on(signal,()=>{interrupted=true;activeChild?.kill("SIGTERM")});
try {
  for(const [pkg,name] of [["apiserver","api.test"],["agentsec-worker","worker.test"]]) {
    const result=await run("/opt/homebrew/bin/go",["test","-c","-o",path.join(temporary,name),"./"+pkg],{GOTOOLCHAIN:"local",GOPROXY:"off",GOSUMDB:"off",GOOS:"linux",GOARCH:"arm64",CGO_ENABLED:"0"});
    if(result.status!==0) throw new Error("offline compile failed");
    hashes[name]=createHash("sha256").update(await readFile(path.join(temporary,name))).digest("hex");
  }
  const result=await run("docker",["run","--name",containerName,"--rm","--pull=never","--network","none","--read-only","--user","postgres","--cpus","2","--memory","2g","--pids-limit","512","--tmpfs","/tmp:rw,exec,size=1400m","--tmpfs","/var/run/postgresql:rw","--mount",`type=bind,src=${temporary}/api.test,dst=/export.test,readonly`,"--mount",`type=bind,src=${temporary}/worker.test,dst=/compliance-worker.test,readonly`,"--mount",`type=bind,src=${root},dst=/workspace,readonly`,"--mount",`type=bind,src=${runtimeEvidence},dst=/evidence`,"--env","ZASP_PUBLIC_EXPORT_EVIDENCE=/evidence","--workdir","/workspace/services/platform/apiserver","--entrypoint","/export.test",image,"-test.run",process.env.ZASP_RESTART_SELECTOR??"^TestSecurityAgentExportPublicRestartPostgres$","-test.v","-test.timeout","900s"]);
  const stamp=new Date().toISOString().replaceAll(":","-");
  await writeFile(path.join(evidence,`run-${stamp}.log`),result.stdout+result.stderr);
  await writeFile(path.join(evidence,`run-${stamp}.json`),JSON.stringify({commands,hashes,status:result.status,signal:result.signal},null,2));
  await writeFile(path.join(evidence,"run-log.txt"),result.stdout+result.stderr);
  await writeFile(path.join(evidence,"run-metadata.json"),JSON.stringify({commands,hashes,status:result.status,signal:result.signal},null,2));
  process.exitCode=result.status??1;
} finally {
  // Exact per-run name, never a shared container or a broad process match.
  const cleanup=spawn("docker",["rm","--force",containerName],{stdio:["ignore","pipe","pipe"]});
  let stdout="",stderr="";
  cleanup.stdout.on("data",b=>stdout+=b);cleanup.stderr.on("data",b=>stderr+=b);
  const deadline=setTimeout(()=>cleanup.kill("SIGKILL"),10000);
  const result=await new Promise(resolve=>{cleanup.once("error",error=>resolve({error:String(error)}));cleanup.once("close",status=>resolve({status,stdout,stderr}))});
  clearTimeout(deadline);
  await writeFile(path.join(evidence,"operator-cleanup.json"),JSON.stringify({containerName,result,temporaryRemoved:true},null,2));
  await rm(temporary,{recursive:true,force:true});
}
