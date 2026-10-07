import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, mkdtemp, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { apiEnvironment } from "./api-start.mjs";
const keys = ["PROJECT_ID", "SECRET", "PUBLIC_TOKEN"];
const fixture = () => Object.fromEntries(keys.map((key, i) => [`STYTCH_${key}`, `sample-${i}`]));

test("standard credentials reach exactly three consumed aliases without mutating parent", () => {
  const parent = { ...fixture(), DATABASE_URL: "not-a-dsn", GITHUB_TOKEN: "other" };
  const before = { ...parent }; const mapped = apiEnvironment(parent);
  for (const key of keys) assert.equal(mapped[`ZASP_STYTCH_${key}`], parent[`STYTCH_${key}`]);
  assert.deepEqual(parent, before); assert.equal(mapped.GOTOOLCHAIN, "local");
  for (const key of ["ZASP_POSTGRES_DSN", "ZASP_SECURITY_AGENT_POSTGRES_DSN", "ZASP_STYTCH_WEBHOOK_SECRET", "ZASP_STYTCH_ORGANIZATION_ID", "ZASP_PUBLIC_ORIGIN", "ZASP_STYTCH_BASE_URL", "ZASP_STYTCH_AUTHORIZE_URL"]) assert.equal(Object.hasOwn(mapped,key),false);
});
test("prefixed and identical paired values preserve exact bytes; missing pairs stay missing", () => {
  assert.deepEqual(apiEnvironment({}), { GOTOOLCHAIN: "local" });
  for (const key of keys) {
    const name=`ZASP_STYTCH_${key}`; assert.equal(apiEnvironment({[name]:" sample "})[name]," sample ");
    assert.equal(apiEnvironment({[name]:"same",[`STYTCH_${key}`]:"same"})[name],"same");
  }
});
test("conflicts and invalid provided values refuse before launch without disclosing values", () => {
  for (const key of keys) {
    const name=`ZASP_STYTCH_${key}`, standard=`STYTCH_${key}`;
    for (const values of [{[name]:"one",[standard]:"two"},{[name]:"",[standard]:"two"},{[name]:"one",[standard]:""},{[name]:" "},{[standard]:null},{[name]:undefined}]) {
      assert.throws(()=>apiEnvironment(values),error=>error.message==="API credential mapping refused");
    }
  }
});
async function instrument(body) {
  const directory=await mkdtemp(path.join(os.tmpdir(),"api-launch-test-"));
  let source=await readFile(new URL("./api-start.mjs",import.meta.url),"utf8");
  source=source.replace('import { spawnOwnedCommand } from "./owned-command.mjs";', 'const spawnOwnedCommand = globalThis.__apiTestSpawn;');
  await writeFile(path.join(directory,"api-start.mjs"),source);
  try { return await body(directory); } finally { delete globalThis.__apiTestSpawn; await rm(directory,{recursive:true,force:true}); }
}
test("actual launcher consumes mapped environment with fixed command and forced local toolchain", async()=>instrument(async directory=>{
  let observed, stops=0;
  globalThis.__apiTestSpawn=(...args)=>{observed=args;return{completed:Promise.resolve({status:9,signal:null}),stop:async()=>{stops++;}};};
  const {runAPI}=await import(path.join(directory,"api-start.mjs"));
  const result=await runAPI({...fixture(),GOTOOLCHAIN:"auto"},new EventEmitter());
  assert.equal(result.status,9);assert.equal(stops,1);
  assert.equal(observed[0],"go");assert.deepEqual(observed[1],["run","-mod=readonly","./agentsec-api"]);
  assert.equal(observed[2].cwd,path.join(directory,"..","services","platform"));
  assert.equal(observed[2].env.GOTOOLCHAIN,"local");assert.equal(observed[2].env.ZASP_STYTCH_SECRET,"sample-1");
  assert.equal(observed[2].maxOutputBytes,262144);
}));
test("owned signal stops and joins the command, removes handlers, and preserves signal", async()=>instrument(async directory=>{
  let finish, stops=0;const signals=new EventEmitter();
  globalThis.__apiTestSpawn=()=>({completed:new Promise(resolve=>{finish=resolve;}),stop:async()=>{stops++;finish({status:null,signal:"SIGTERM"});}});
  const {runAPI}=await import(path.join(directory,"api-start.mjs"));
  const running=runAPI(fixture(),signals);assert.equal(signals.listenerCount("SIGTERM"),1);signals.emit("SIGTERM");
  const result=await running;assert.equal(result.signal,"SIGTERM");assert.ok(stops>=1);
  for(const name of ["SIGINT","SIGTERM","SIGHUP"])assert.equal(signals.listenerCount(name),0);
}));
async function entry(source, args=[]) {
  return instrument(async directory=>{
    const candidate=await readFile(path.join(directory,"api-start.mjs"),"utf8");
    await writeFile(path.join(directory,"api-start.mjs"),source+'\n'+candidate);
    const child=spawn(process.execPath,[path.join(directory,"api-start.mjs"),...args],{env:{PATH:process.env.PATH},stdio:["ignore","pipe","pipe"]});
    let stdout="",stderr="";child.stdout.on("data",b=>stdout+=b);child.stderr.on("data",b=>stderr+=b);
    const timer=setTimeout(()=>child.kill("SIGKILL"),3000);
    try {return await new Promise((resolve,reject)=>{child.on("error",reject);child.on("close",(status,signal)=>resolve({status,signal,stdout,stderr}));});}finally{clearTimeout(timer);}
  });
}
test("actual entrypoint refuses caller arguments before spawn and propagates nonzero status",async()=>{
  const code='globalThis.__apiTestSpawn=()=>({completed:Promise.resolve({status:17,signal:null}),stop:async()=>{}});';
  assert.deepEqual(await entry(code),{status:17,signal:null,stdout:"",stderr:""});
  assert.deepEqual(await entry('globalThis.__apiTestSpawn=()=>{throw Error("sample-private");};',["--url=sample-private"]),{status:1,signal:null,stdout:"",stderr:"API launch refused\n"});
});
test("actual entrypoint preserves child signal and sanitizes spawn errors",async()=>{
  const signaled=await entry('globalThis.__apiTestSpawn=()=>({completed:Promise.resolve({status:null,signal:"SIGTERM"}),stop:async()=>{}});');
  assert.equal(signaled.signal,"SIGTERM");assert.equal(signaled.stdout,"");assert.equal(signaled.stderr,"");
  const failed=await entry('globalThis.__apiTestSpawn=()=>{throw Error("sample-private");};');
  assert.deepEqual(failed,{status:1,signal:null,stdout:"",stderr:"API launch refused\n"});
});

test("conflicting credentials never spawn; absent unrelated configuration stays absent at launch",async()=>instrument(async directory=>{
  let calls=0, observed;
  globalThis.__apiTestSpawn=(_command,_args,options)=>{calls++;observed=options.env;return{completed:Promise.resolve({status:1,signal:null}),stop:async()=>{}};};
  const {runAPI}=await import(path.join(directory,"api-start.mjs"));
  await assert.rejects(runAPI({STYTCH_SECRET:"one",ZASP_STYTCH_SECRET:"two"},new EventEmitter()),error=>error.message==="API credential mapping refused");
  assert.equal(calls,0);
  await runAPI(fixture(),new EventEmitter());assert.equal(calls,1);
  for(const name of ["ZASP_STYTCH_WEBHOOK_SECRET","ZASP_STYTCH_ORGANIZATION_ID","ZASP_PUBLIC_ORIGIN","ZASP_POSTGRES_DSN","ZASP_SECURITY_AGENT_POSTGRES_DSN"])assert.equal(Object.hasOwn(observed,name),false);
}));
test("published npm command connects to this launcher without changing web start",async()=>{
  const pkg=JSON.parse(await readFile(new URL("../package.json",import.meta.url),"utf8"));
  assert.equal(pkg.scripts["api:start"],"node scripts/api-start.mjs");
  assert.equal(pkg.scripts.start,"WRANGLER_LOG_PATH=.wrangler/wrangler.log vinext start");
});

test("configuration check uses fixed Go flag and the same credential and ownership boundary", async()=>instrument(async directory=>{
  let observed, stops=0;const signals=new EventEmitter();
  globalThis.__apiTestSpawn=(...args)=>{observed=args;return{completed:Promise.resolve({status:0,signal:null}),stop:async()=>{stops++;}};};
  const {runAPIConfigurationCheck}=await import(path.join(directory,"api-start.mjs"));
  assert.deepEqual(await runAPIConfigurationCheck({...fixture(),GOTOOLCHAIN:"auto"},signals),{status:0,signal:null});
  assert.equal(observed[0],"go");
  assert.deepEqual(observed[1],["run","-mod=readonly","./agentsec-api","--check-config"]);
  assert.equal(observed[2].env.GOTOOLCHAIN,"local");
  assert.equal(observed[2].env.ZASP_STYTCH_SECRET,"sample-1");
  assert.equal(observed[2].maxOutputBytes,262144);assert.equal(stops,1);
  for(const name of ["SIGINT","SIGTERM","SIGHUP"])assert.equal(signals.listenerCount(name),0);
  let calls=0;globalThis.__apiTestSpawn=()=>{calls++;throw Error("private");};
  await assert.rejects(runAPIConfigurationCheck({STYTCH_SECRET:"one",ZASP_STYTCH_SECRET:"two"},signals),/API credential mapping refused/);
  assert.equal(calls,0);
}));

test("configuration entrypoint refuses arguments and never echoes captured child output",async()=>instrument(async directory=>{
 const candidate=await readFile(new URL('./api-check-config.mjs',import.meta.url),'utf8');
 await writeFile(path.join(directory,'api-check-config.mjs'),candidate);
 const original=await readFile(path.join(directory,'api-start.mjs'),'utf8');
 await writeFile(path.join(directory,'api-start.mjs'),'globalThis.__apiTestSpawn=()=>({completed:Promise.resolve({status:0,signal:null,stdout:"private-child-output",stderr:"private-child-error"}),stop:async()=>{}});\n'+original);
 async function run(args){
  const child=spawn(process.execPath,[path.join(directory,'api-check-config.mjs'),...args],{env:{PATH:process.env.PATH},stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';child.stdout.on('data',v=>stdout+=v);child.stderr.on('data',v=>stderr+=v);
  const timer=setTimeout(()=>child.kill('SIGKILL'),3000);
  try{return await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',(status,signal)=>resolve({status,signal,stdout,stderr}));});}finally{clearTimeout(timer);}
 }
 assert.deepEqual(await run([]),{status:0,signal:null,stdout:'API configuration syntax accepted; runtime access and production readiness are unverified.\n',stderr:''});
 assert.deepEqual(await run(['private-argument']),{status:1,signal:null,stdout:'',stderr:'API configuration check refused\n'});
}));
