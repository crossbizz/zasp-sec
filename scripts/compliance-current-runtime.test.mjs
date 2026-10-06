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
 test("actual compliance startup selects current profile after preserving release56 fixture", async()=>{
  const text=fs.readFileSync(sourceURL,"utf8");
  const start=text.indexOf("async function exerciseComplianceBrowser(configuration) {");
  const end=text.indexOf('  const storage=await mkdtemp("/tmp/zasp-compliance-browser-");',start);
  assert.ok(start>=0&&end>start);
  let version="56", seeded=false, profile=false, verifier=false;
  const calls=[];
  const command=async(executable,args,options)=>{
   if(executable==="migrate") {
    calls.push(args[0]);assert.ok(seeded,"current profile must follow original compliance fixture");
    if(args[0]==="up-to-60")version="60";
    else if(args[0]==="up-authorization-runtime-profile"){assert.equal(version,"60");version="61";profile=true;}
    else if(args[0]==="register-authorization-verifier"){assert.ok(profile);assert.equal(options.env.ZASP_WORKFLOW_SIGNING_KEY,signingKey);verifier=true;}
    else assert.fail("unexpected migration command");
    return {stdout:""};
   }
   assert.equal(executable,"/owned/psql");
   const statement=args.at(-1);
   if(statement==="SELECT max(version) FROM zasp_schema_versions")return {stdout:version};
   assert.ok(statement.includes("zasp_compliance_register_workers('compliance_executor','compliance_cleanup'"));
   assert.ok(statement.includes("version=56"));assert.ok(statement.includes("view_compliance"));
   seeded=true;return {stdout:""};
  };
  const context=vm.createContext({assert,path,command,postgresBin:"/owned",prepareComplianceCurrentRuntime,
    process:{env:environment()},productHostname:"owned-browser.test",combinedAPIEnvironment:()=>({ZASP_WORKFLOW_SIGNING_KEY:signingKey})});
  const actual=vm.runInContext(text.slice(start,end)+"\n};exerciseComplianceBrowser",context);
  await actual({dsn:"controlled-owner-dsn",migrate:"migrate",migrationEnvironment:{ZASP_MIGRATION_DB_PRINCIPAL:"owned_migration"},proxyPort:18089});
  assert.ok(seeded);assert.ok(profile&&verifier,"actual compliance source reaches current profile and verifier before API construction");
  assert.equal(version,"61");
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
