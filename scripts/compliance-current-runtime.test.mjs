import {installOwnedCurrent80,closedOwnedAmbientEnvironment} from "./owned-current80-composition.mjs";
import {complianceRuntimeBindings} from "./compliance-runtime-prerequisites.mjs";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { prepareComplianceCurrentRuntime } from "./compliance-current-runtime.mjs";
const environment = () => ({ ZASP_RUNTIME_SERVICES_ENABLED:"true", ZASP_RUNTIME_SERVICES_TIMEOUT:"5s",
 ZASP_TEMPORAL_ADDRESS:"127.0.0.1:17233", ZASP_TEMPORAL_NAMESPACE:"owned-test", ZASP_TEMPORAL_TASK_QUEUE:"owned-main", ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE:"owned-discovery",
 ZASP_OPENFGA_URL:"http://127.0.0.1:18088", ZASP_OPENFGA_STORE_ID:"01ARZ3NDEKTSV4RRFFQ69G5FAV", ZASP_OPENFGA_MODEL_ID:"01ARZ3NDEKTSV4RRFFQ69G5FAW", ZASP_OPENFGA_TOKEN_FILE:"/tmp/owned-fixture-token" });
const signingKey="controlled-test-signing-key-32bytes";
// Controlled command effects verify the actual orchestration source prefix.
// No migration SQL, service, model or API readiness is exercised by this fixture.
export function cases(sourceURL) {
 test("actual owned compliance startup preserves release56 controls and installs and verifies the current baseline before API construction", async()=>{
  const text=fs.readFileSync(sourceURL,"utf8");
  const start=text.indexOf("async function exerciseComplianceBrowser(configuration) {");
  const end=text.indexOf('  const storage=await mkdtemp("/tmp/zasp-compliance-browser-");',start);
  const prepareStart=text.indexOf("async function prepareOwnedCurrentComplianceRuntime(");
  assert.ok(prepareStart>=0&&start>prepareStart&&end>start);
  let seeded=false, historicalHTTP=false, currentSeeded=false, profile=false, verifier=false;
  const calls=[], env={...environment(),ZASP_ENVIRONMENT:"test"};
  const organization="pid_10000001-0000-4000-8000-000000000001";
  const revision={organization_id:organization,desired:1,applied:1,generation:1,store_id:env.ZASP_OPENFGA_STORE_ID,model_id:env.ZASP_OPENFGA_MODEL_ID};
  const command=async(executable,args,options)=>{
   if(executable==="/owned/migrate") {
    calls.push(args[0]);assert.ok(seeded&&historicalHTTP,"the historical fixture and HTTP checks must finish before the current install");
    assert.equal(options.timeout,300000);
    if(args[0]==="install-baseline"){assert.equal(currentSeeded,false);assert.match(options.env.ZASP_POSTGRES_DSN,/zasp_operator@/);profile=true;}
    else if(args[0]==="approval-maintenance-checksum"){assert.ok(profile);return {status:0,signal:null,stdout:"a".repeat(64)+"\n"};}
    else if(args[0]==="register-authorization-verifier"){assert.ok(profile);assert.equal(options.env.ZASP_WORKFLOW_SIGNING_KEY,signingKey);verifier=true;}
    else if(args[0].startsWith("register-identity-")||args[0]==="verify-baseline")assert.ok(currentSeeded);
    else assert.ok(["register-worker-authorization-verifier","register-compensation-authorization-verifier","register-approval-maintenance-verifier"].includes(args[0]),"unexpected migration command");
    return {status:0,signal:null,stdout:""};
   }
   if(executable==="go"&&args[0]==="test"){
    assert.ok(seeded);assert.equal(profile,false);assert.equal(options.env.ZASP_LEGACY_COMPLIANCE_PG_PORT,"15500");
    assert.deepEqual(Array.from(args),["test","-json","-count=1","-timeout=90s","-run","^TestHistoricalRelease56ComplianceHTTP$","./apiserver"]);
    historicalHTTP=true;return {status:0,signal:null,stdout:JSON.stringify({Action:"pass",Test:"TestHistoricalRelease56ComplianceHTTP",Package:"github.com/zasp-ai/zasp-sec/services/platform/apiserver"})};
   }
   if(executable==="go") { assert.deepEqual(Array.from(args),["build","-o","/owned/tmp/zasp-authorization-reconcile","./cmd/zasp-authorization-reconcile"]);return {status:0,signal:null,stdout:""}; }
   if(executable==="/owned/tmp/zasp-authorization-reconcile") {
    assert.ok(currentSeeded&&profile);
    const target=args[3];
    return {status:0,signal:null,stdout:args[1]==="reconcile"?JSON.stringify({organization_id:target,status:"applied",receipt:{Applied:true,TupleCount:0,Revision:{...revision,organization_id:target}}}):""};
   }
   assert.equal(executable,"/owned/psql");const statement=args.at(-1);
   if(statement.includes("zasp_authorization79.revision")){
    const target=statement.match(/zasp_authorization79\.revision\('([^']+)'\)/)[1];
    return {status:0,signal:null,stdout:JSON.stringify({...revision,organization_id:target})};
   }
   if(statement==="SELECT max(version) FROM zasp_schema_versions"){assert.equal(args[0],"controlled-owner-dsn");return {status:0,signal:null,stdout:"56"};}
   if(statement.includes("activate_projection"))return {status:0,signal:null,stdout:"t\n"};
   if(statement.startsWith("CREATE ROLE zasp_operator")){assert.match(args[0],/zasp_e2e@/);assert.ok(statement.includes("NOSUPERUSER"));return {status:0,signal:null,stdout:""};}
   if(args[0].includes("zasp_operator@")){assert.ok(profile);return {status:0,signal:null,stdout:""};}
   if(statement.startsWith("CREATE ROLE") && !statement.includes("zasp_compliance_register_workers")) { assert.ok(statement.includes("NOBYPASSRLS"));return {status:0,signal:null,stdout:""}; }
   assert.ok(statement.includes("zasp_compliance_register_workers('compliance_executor','compliance_cleanup'"));
   assert.ok(statement.includes("version=56"));assert.ok(statement.includes("view_compliance"));
   seeded=true;return {status:0,signal:null,stdout:""};
  };
  const pending=new Promise(()=>{});
  const context=vm.createContext({assert,path,Buffer,AbortController,command,postgresBin:"/owned",installOwnedCurrent80,complianceRuntimeBindings,closedOwnedAmbientEnvironment,
    complianceBrowserMode:true,compliancePhase:"services",ownedResourceCleanupStarted:false,currentComplianceClosing:false,currentComplianceFailure:undefined,currentCompliancePreparation:undefined,currentComplianceRuntimeStartup:undefined,
    currentComplianceStateRoot:undefined,currentComplianceServices:undefined,currentCompliancePostgres:undefined,currentComplianceProjectionController:undefined,currentComplianceProjectionLoop:undefined,
    process:{env:{ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT:"/owned/archives",ZASP_BROWSER_RUNTIME_RAW_ROOT:"/owned/raw"}},
    temporaryRoot:"/owned/tmp",platform:"/owned/platform",productHostname:"owned-browser.test",withOwnedRuntimeStartupDiagnostics:async action=>action(),
    mkdtemp:async()=>"/owned/state",randomBytes:size=>Buffer.alloc(size),writeFile:async()=>{},
    startRetainedOwnedRuntimeLifetime:async()=>({environment:env,completed:pending}),reservePort:async()=>15432,createOwnedBrowserPostgres:()=>({start:async()=>{}}),
    seedCurrentComplianceIdentity:async dsn=>{assert.ok(profile);assert.match(dsn,/zasp_operator@/);currentSeeded=true;},runOwnedProjectionLoop:()=>pending,cleanupController:{run:async()=>{}},
    combinedAPIEnvironment:()=>({ZASP_PUBLIC_ORIGIN:"https://owned-browser.test",ZASP_STYTCH_BASE_URL:"http://127.0.0.1:18082",ZASP_STYTCH_PROJECT_ID:"fixture",ZASP_STYTCH_ORGANIZATION_ID:"fixture",ZASP_DEPLOYMENT_MODE:"saas",ZASP_ORGANIZATION_ID:"",ZASP_WORKFLOW_SIGNING_KEY:signingKey})});
  const actual=vm.runInContext(text.slice(prepareStart,start)+text.slice(start,end)+"\n};exerciseComplianceBrowser",context);
  await actual({dsn:"controlled-owner-dsn",migrate:"/owned/migrate",migrationEnvironment:{ZASP_MIGRATION_DB_PRINCIPAL:"owned_migration"},proxyPort:18089,postgresPort:15500});
  assert.ok(seeded&&currentSeeded);assert.ok(profile&&verifier,"actual owned source reaches current profile and verifier before API construction");
  assert.equal(calls.filter(action=>action==="install-baseline").length,1);assert.equal(calls.filter(action=>action==="verify-baseline").length,1);
 });
 test("missing runtime bindings refuse before migration; no environment-only fallback",async()=>{
  let called=false;
  await assert.rejects(prepareComplianceCurrentRuntime({command:async()=>{called=true},migrate:"migrate",migrationEnvironment:{},sql:async()=>"61",environment:{},signingKey}),error=>error.code==="ZASP_COMPLIANCE_RUNTIME_PREREQUISITE_REFUSED");
  assert.equal(called,false);
 });
 test("rejected current installer or canonical mismatch cannot register usable startup",async()=>{
  const calls=[];
  await assert.rejects(prepareComplianceCurrentRuntime({command:async(_p,args)=>{calls.push(args[0]);if(args[0]==="up-authorization-runtime-profile")throw new Error("controlled installer rejection")},migrate:"migrate",migrationEnvironment:{},sql:async()=>"61",environment:environment(),signingKey}),/controlled installer rejection/);
  assert.equal(calls.includes("register-authorization-verifier"),false);
  await assert.rejects(prepareComplianceCurrentRuntime({command:async()=>{},migrate:"migrate",migrationEnvironment:{},sql:async()=>"56",environment:environment(),signingKey}),/current canonical authorization runtime profile/);
 });
}

cases(new URL("./production-combined-e2e.mjs", import.meta.url));
