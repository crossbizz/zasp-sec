import {spawn} from "node:child_process";
import {mkdtemp,readFile,writeFile,rm,mkdir,chmod,readdir} from "node:fs/promises";
import {createHash} from "node:crypto";
import path from "node:path";
import {fileURLToPath} from "node:url";
const evidence=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(evidence,"../../../..");
const temporary=await mkdtemp("/private/tmp/zasp-cleanup-process-");
const container=path.basename(temporary).toLowerCase();
const stamp=new Date().toISOString().replaceAll(":","-");
const runtime=path.join(evidence,stamp);await mkdir(runtime);await chmod(runtime,0o777);
const commands=[],hashes={};
async function files(dir){const out=[];for(const e of await readdir(path.join(root,dir),{withFileTypes:true})){const n=path.join(dir,e.name);if(e.isDirectory())out.push(...await files(n));else if(e.isFile())out.push(n)}return out.sort()}
for(const name of await files("services/platform"))hashes[name]=createHash("sha256").update(await readFile(path.join(root,name))).digest("hex");
let active,interrupted=false;
for(const signal of ["SIGINT","SIGTERM"])process.on(signal,()=>{interrupted=true;active?.kill("SIGTERM")});
async function run(command,args,env={}){
 if(interrupted)throw new Error("operator interrupted");commands.push({command,args,env});
 const child=spawn(command,args,{cwd:path.join(root,"services/platform"),env:{...process.env,...env},stdio:["ignore","pipe","pipe"]});active=child;
 let output="",force;const timer=setTimeout(()=>{child.kill("SIGTERM");force=setTimeout(()=>child.kill("SIGKILL"),3000)},960000);
 child.stdout.on("data",b=>{output+=b;process.stdout.write(b)});child.stderr.on("data",b=>{output+=b;process.stderr.write(b)});
 const status=await new Promise((resolve,reject)=>{child.once("error",reject);child.once("close",resolve)});clearTimeout(timer);clearTimeout(force);active=undefined;return {status,output};
}
try{
 for(const [pkg,name]of[["apiserver","api.test"],["agentsec-worker","worker.test"]]){const r=await run("/opt/homebrew/bin/go",["test","-c","-o",path.join(temporary,name),"./"+pkg],{GOTOOLCHAIN:"local",GOPROXY:"off",GOSUMDB:"off",GOOS:"linux",GOARCH:"arm64",CGO_ENABLED:"0"});if(r.status!==0)throw new Error(r.output);hashes[name]=createHash("sha256").update(await readFile(path.join(temporary,name))).digest("hex")}
 const result=await run("docker",["run","--name",container,"--rm","--pull=never","--network","none","--read-only","--user","postgres","--cpus","2","--memory","2g","--pids-limit","512","--tmpfs","/tmp:rw,exec,size=1400m","--tmpfs","/var/run/postgresql:rw","--mount",`type=bind,src=${temporary}/api.test,dst=/export.test,readonly`,"--mount",`type=bind,src=${temporary}/worker.test,dst=/compliance-worker.test,readonly`,"--mount",`type=bind,src=${root},dst=/workspace,readonly`,"--mount",`type=bind,src=${runtime},dst=/evidence`,"--env","ZASP_PUBLIC_EXPORT_EVIDENCE=/evidence","--workdir","/workspace/services/platform/apiserver","--entrypoint","/export.test","postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba","-test.run",process.env.ZASP_CLEANUP_SELECTOR??"^TestSecurityAgentExportCleanupProcessPostgres$","-test.v","-test.timeout=900s"]);
 await writeFile(path.join(runtime,"run.log"),result.output);await writeFile(path.join(runtime,"run.json"),JSON.stringify({commands,hashes,status:result.status},null,2));process.exitCode=result.status??1;
}finally{
 const child=spawn("docker",["rm","--force",container],{stdio:["ignore","pipe","pipe"]});let output="";child.stdout.on("data",b=>output+=b);child.stderr.on("data",b=>output+=b);const timer=setTimeout(()=>child.kill("SIGKILL"),10000);const status=await new Promise(resolve=>{child.once("error",e=>resolve(String(e)));child.once("close",resolve)});clearTimeout(timer);
 await rm(temporary,{recursive:true,force:true});await writeFile(path.join(runtime,"cleanup.json"),JSON.stringify({container,status,output,temporaryRemoved:true},null,2));console.log("Retained evidence: "+runtime);
}
