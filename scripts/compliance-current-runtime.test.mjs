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
// Maintenance helper injection checks wiring; its real protocol has its own suite.
export function cases(sourceURL) {
 test("owned compliance wiring retains release56 controls and passes complete maintenance ownership through the real current installer", async()=>{
  const text=fs.readFileSync(sourceURL,"utf8");
  const start=text.indexOf("async function exerciseComplianceBrowser(configuration) {");
  const end=text.indexOf('  const storage=await mkdtemp("/tmp/zasp-compliance-browser-");',start);
  const prepareStart=text.indexOf("async function prepareOwnedCurrentComplianceRuntime(");
  assert.ok(prepareStart>=0&&start>prepareStart&&end>start);
  let version="56", seeded=false, currentSeeded=false, profile=false, verifier=false, activated=false, projectionPasses=0;
  const order=[];let helperCalls=0;
  const calls=[], env={...environment(),ZASP_ENVIRONMENT:"test",ZASP_OPENFGA_TOKEN_FILE:"/owned/state/fga-new.token"};
  let observedProjection;
  const organization="pid_10000001-0000-4000-8000-000000000001";
  const revision={organization_id:organization,desired:1,applied:1,generation:1,store_id:env.ZASP_OPENFGA_STORE_ID,model_id:env.ZASP_OPENFGA_MODEL_ID};
  const command=async(executable,args,options)=>{
   assert.equal(JSON.stringify(args).includes("controlled-private-storage-dsn"),false,"storage credentials stay outside command arguments");
   if(executable==="/owned/migrate") {
    calls.push(args[0]);assert.ok(seeded,"current profile must follow original compliance fixture");
    if(args[0]==="up-to-56") { version="56";assert.equal(options.timeout,300000); }
    else if(args[0]==="up-to-60") { assert.ok(currentSeeded);version="60"; }
    else if(args[0]==="up-authorization-runtime-profile"){assert.equal(version,"60");version="61";profile=true;}
    else if(args[0]==="register-authorization-verifier"){assert.ok(profile);assert.equal(options.env.ZASP_WORKFLOW_SIGNING_KEY,signingKey);verifier=true;}
    else assert.ok(["register-temporal-executor-principals","register-identity-session-verifier","register-identity-webhook-verifier","register-worker-authorization-verifier","register-compensation-authorization-verifier"].includes(args[0]),"unexpected migration command");
    return {status:0,signal:null,stdout:""};
   }
   if(executable==="go") {
    const name=path.basename(args[2]);
    assert.ok(["zasp-authorization-reconcile","zasp-controlled-maintenance-cutover","zasp-maintenance-register"].includes(name));
    assert.deepEqual(Array.from(args),["build","-o",`/owned/tmp/${name}`,`./cmd/${name}`]);
    assert.equal(options.cwd,"/owned/platform");assert.equal(options.timeout,120000);
    order.push(`build:${name}`);return {status:0,signal:null,stdout:""};
   }
   if(executable==="/owned/tmp/zasp-authorization-reconcile") {
    assert.equal(version,"61");
    if(args[1]==="reconcile") {
     projectionPasses++;
     if(activated) {
      assert.equal(options.env.ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM,"c".repeat(64));
      assert.equal(options.env.ZASP_OPENFGA_TOKEN_FILE,"/owned/state/fga-new.token");
     } else {assert.equal(options.env.ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM,undefined);assert.equal(options.env.ZASP_OPENFGA_TOKEN_FILE,"/owned/state/fga-new.token");}
    }
    return {status:0,signal:null,stdout:args[1]==="reconcile"?JSON.stringify({organization_id:organization,status:"applied",receipt:{Applied:true,TupleCount:0,Revision:revision}}):""};
   }
   assert.equal(executable,"/owned/psql");const statement=args.at(-1);
   if(statement.includes("zasp_authorization79.revision"))return {status:0,signal:null,stdout:JSON.stringify(revision)};
   if(statement==="SELECT max(version) FROM zasp_schema_versions")return {status:0,signal:null,stdout:version};
   if(statement.startsWith("CREATE ROLE") && !statement.includes("zasp_compliance_register_workers")) { assert.ok(statement.includes("NOBYPASSRLS"));return {status:0,signal:null,stdout:""}; }
   assert.ok(statement.includes("zasp_compliance_register_workers('compliance_executor','compliance_cleanup'"));
   assert.ok(statement.includes("version=56"));assert.ok(statement.includes("view_compliance"));
   seeded=true;return {status:0,signal:null,stdout:""};
  };
  const pending=new Promise(()=>{});
  const withdrawOldCredential=async()=>{throw Error("wiring fixture cannot withdraw credentials");};
  const services={environment:env,completed:pending,oldTokenFile:"/owned/state/fga-old.token",newTokenFile:"/owned/state/fga-new.token",withdrawOldCredential};
  const activationBoundary=async input=>{
   assert.ok(profile&&verifier);assert.equal(projectionPasses,1);
   assert.equal(input.cutover,"/owned/tmp/zasp-controlled-maintenance-cutover");
   assert.equal(input.register,"/owned/tmp/zasp-maintenance-register");
   assert.equal(input.keyRoot,"/owned/state");assert.equal(input.cwd,"/owned/root");
   assert.equal(input.oldTokenFile,services.oldTokenFile);assert.equal(input.newTokenFile,services.newTokenFile);
   assert.equal(input.withdrawOldCredential,withdrawOldCredential);
   assert.equal(input.runtimeEnvironment,env);assert.equal(input.runtimeEnvironment.ZASP_OPENFGA_TOKEN_FILE,input.newTokenFile);assert.equal(input.port,15432);
   assert.equal(input.migrationEnvironment.ZASP_WORKFLOW_SIGNING_KEY,signingKey);
   assert.equal(input.migrationEnvironment.ZASP_UNRELATED_SECRET,undefined);
   assert.deepEqual(order.slice(-3),["build:zasp-authorization-reconcile","build:zasp-controlled-maintenance-cutover","build:zasp-maintenance-register"]);
   helperCalls++;activated=true;revision.desired=2;revision.applied=2;
   return {environment:{...env,ZASP_OPENFGA_TOKEN_FILE:services.newTokenFile,
    ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM:"a".repeat(64),ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM:"b".repeat(64),ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM:"c".repeat(64),
    ZASP_CONNECTOR_MAINTENANCE_POSTGRES_DSN:"postgres://connector@127.0.0.1:15432/postgres?sslmode=disable",ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN:"postgres://approval@127.0.0.1:15432/postgres?sslmode=disable",
    ZASP_CONNECTOR_MAINTENANCE_KEY_FILE:"/owned/state/connector.seed",ZASP_APPROVAL_MAINTENANCE_KEY_FILE:"/owned/state/approval.seed"}};
  };
  const context=vm.createContext({assert,path,Buffer,AbortController,command,postgresBin:"/owned",installOwnedCurrent80:input=>installOwnedCurrent80(input,activationBoundary),complianceRuntimeBindings,closedOwnedAmbientEnvironment,
    complianceBrowserMode:true,compliancePhase:"services",ownedResourceCleanupStarted:false,currentComplianceClosing:false,currentComplianceFailure:undefined,currentCompliancePreparation:undefined,currentComplianceRuntimeStartup:undefined,
    currentComplianceStateRoot:undefined,currentComplianceServices:undefined,currentCompliancePostgres:undefined,currentComplianceProjectionController:undefined,currentComplianceProjectionLoop:undefined,
    process:{env:{ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT:"/owned/archives",ZASP_BROWSER_RUNTIME_RAW_ROOT:"/owned/raw",ZASP_UNRELATED_SECRET:"must-not-propagate"}},
    temporaryRoot:"/owned/tmp",platform:"/owned/platform",root:"/owned/root",productHostname:"owned-browser.test",withOwnedRuntimeStartupDiagnostics:async action=>action(),
    mkdtemp:async()=>"/owned/state",randomBytes:size=>Buffer.alloc(size),writeFile:async()=>{},
    startRetainedOwnedRuntimeLifetime:async input=>{assert.deepEqual(order,["postgres-start","fga-storage"]);assert.equal(input.openfgaPostgresDSN,"controlled-private-storage-dsn");order.push("services-start");return services;},
    provisionOwnedFGAStorage:async input=>{assert.deepEqual(order,["postgres-start"]);assert.equal(input.port,15432);assert.equal(input.psql,"/owned/psql");assert.equal(input.environment.ZASP_UNRELATED_SECRET,undefined);order.push("fga-storage");return {dsn:"controlled-private-storage-dsn"};},
    reservePort:async()=>15432,createOwnedBrowserPostgres:()=>({start:async()=>{order.push("postgres-start");}}),
    provisionPostgresPrincipals:async()=>{},seedPostgres:async()=>{currentSeeded=true;},runOwnedProjectionLoop:(projector,signal)=>{observedProjection=projector;assert.equal(signal.aborted,false);return pending;},cleanupController:{run:async()=>{}},
    combinedAPIEnvironment:()=>({ZASP_PUBLIC_ORIGIN:"https://owned-browser.test",ZASP_STYTCH_BASE_URL:"http://127.0.0.1:18082",ZASP_STYTCH_PROJECT_ID:"fixture",ZASP_STYTCH_ORGANIZATION_ID:"fixture",ZASP_DEPLOYMENT_MODE:"saas",ZASP_ORGANIZATION_ID:"",ZASP_WORKFLOW_SIGNING_KEY:signingKey})});
  const actual=vm.runInContext(text.slice(prepareStart,start)+text.slice(start,end)+"\n};exerciseComplianceBrowser",context);
  await actual({dsn:"controlled-owner-dsn",migrate:"/owned/migrate",migrationEnvironment:{ZASP_MIGRATION_DB_PRINCIPAL:"owned_migration",ZASP_UNRELATED_SECRET:"must-not-propagate"},proxyPort:18089});
  assert.ok(seeded&&currentSeeded);assert.ok(profile&&verifier,"actual owned source reaches current profile and verifier before API construction");
  assert.equal(version,"61");assert.equal(calls.filter(action=>action==="up-authorization-runtime-profile").length,1);
  assert.equal(helperCalls,1);assert.equal(projectionPasses,2);
  assert.equal(observedProjection.environment.ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM,"c".repeat(64));
  assert.equal(observedProjection.environment.ZASP_OPENFGA_TOKEN_FILE,services.newTokenFile);
  assert.equal(observedProjection.applied.desired,2);
  assert.equal(observedProjection.applied.applied,2);
  assert.equal(Object.hasOwn(observedProjection.environment,"ZASP_POSTGRES_DSN"),false);
  assert.equal(observedProjection.native,false);assert.equal(observedProjection.acceptance,false);assert.equal(observedProjection.production,false);assert.equal(observedProjection.deployed,false);
  await context.currentCompliancePreparation;
  assert.equal(context.currentComplianceServices,services);
  assert.equal(context.currentComplianceProjectionController.signal.aborted,false);
 });
 test("cleanup during PostgreSQL startup retains ownership and prevents storage or service allocation",async()=>{
  const text=fs.readFileSync(sourceURL,"utf8");
  const start=text.indexOf("async function prepareOwnedCurrentComplianceRuntime(");
  const end=text.indexOf("async function exerciseComplianceBrowser(configuration) {",start);
  assert.ok(start>=0&&end>start);
  let storageCalls=0,serviceCalls=0,context;
  const postgres={start:async()=>{context.ownedResourceCleanupStarted=true;}};
  context=vm.createContext({assert,path,Buffer,
   ownedResourceCleanupStarted:false,currentComplianceClosing:false,currentCompliancePreparation:undefined,
   currentComplianceStateRoot:undefined,currentCompliancePostgres:undefined,
   currentComplianceServices:undefined,currentComplianceProjectionLoop:undefined,
   complianceBrowserMode:true,compliancePhase:"services",postgresBin:"/owned",
   process:{env:{ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT:"/owned/archive",ZASP_BROWSER_RUNTIME_RAW_ROOT:"/owned/raw"}},
   withOwnedRuntimeStartupDiagnostics:async action=>action(),mkdtemp:async()=>"/owned/state",reservePort:async()=>15432,
   createOwnedBrowserPostgres:()=>postgres,
   provisionOwnedFGAStorage:async()=>{storageCalls++;throw Error("unexpected storage allocation");},
   startRetainedOwnedRuntimeLifetime:async()=>{serviceCalls++;throw Error("unexpected service allocation");},
  });
  const prepare=vm.runInContext(text.slice(start,end)+"\nprepareOwnedCurrentComplianceRuntime",context);
  await assert.rejects(prepare({migrate:"/owned/migrate",migrationEnvironment:{},proxyPort:18089},"controlled fixture"),/startup after cleanup refused/);
  await context.currentCompliancePreparation;
  assert.equal(context.currentCompliancePostgres,postgres,"cleanup retains the already allocated PostgreSQL owner");
  assert.equal(context.currentComplianceStateRoot,"/owned/state");
  assert.equal(storageCalls,0);assert.equal(serviceCalls,0);
  assert.equal(context.currentComplianceServices,undefined);assert.equal(context.currentComplianceProjectionLoop,undefined);
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
