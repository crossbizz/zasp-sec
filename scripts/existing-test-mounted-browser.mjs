import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

const org="pid_10000001-0000-4000-8000-000000000001",ws="pid_10000022-0000-4000-8000-000000000022",env="pid_10000023-0000-4000-8000-000000000023",actor="pid_10000004-0000-4000-8000-000000000004";
const scope=`${org}/${ws}/${env}`,target="pid_7f300003-0000-4000-8000-000000000003",finding="pid_7f550001-0000-4000-8000-000000000001";
const owned=`organization_id='${org}' AND workspace_id='${ws}' AND environment_id='${env}'`;
const productID=/^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function assertMountedEvidenceText(text,state,outcome,reason) {
  assert.ok(text.includes(`Test verification ${state}.`));
  if(state==="pending")assert.doesNotMatch(text,/Test outcome:|Reason:|Proof digest:|Recorded check comparison/);
  else {assert.ok(text.includes(`Test outcome: ${outcome}`));assert.ok(text.includes(`Reason: ${reason}`));}
}
export function assertMountedHistorySelection(value,id,expectedScope) {
  const url=new URL(value.url),[organization_id,workspace_id,environment_id]=expectedScope.split("/");
  assert.equal(url.pathname,"/red-team/results");
  assert.deepEqual(Object.fromEntries(url.searchParams),{entity_id:id,organization_id,workspace_id,environment_id});
  assert.equal([...url.searchParams].length,4);assert.equal(value.title,"Red team run");assert.equal(value.id,id);
}
export function assertMountedCancellationControl(before,foreign,missing,after,owner) {
  assert.equal(before.state,"queued");assert.ok(Number.isSafeInteger(before.version));
  // Released cancellation deliberately conflates missing scope/version/state.
  // A foreign ID must be indistinguishable from a nonexistent valid ID.
  assert.equal(foreign.status,409);assert.equal(missing.status,409);
  assert.deepEqual(after,before);assert.equal(owner.status,200);assert.equal(owner.body.state,"cancelled");assert.equal(owner.body.version,before.version+1);
}

export async function seedPrerequisites(sql) {
  // Identity, discovered target/provenance, credential binding and risk only.
  // Agent definitions, controls, plans, runs, links and proofs are never seeded.
  await sql(`UPDATE zasp_authorized_scopes SET permissions=permissions||'["run_tests"]'::jsonb WHERE principal_id='${actor}' AND ${owned};
INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES('pid_7f550002-0000-4000-8000-000000000002','${org}','organization-test-local','member-mounted-approver','security_admin');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES('pid_7f550002-0000-4000-8000-000000000002','${org}','${ws}','${env}','Mounted approval scope','["view","manage_workflows","run_tests"]',true);
INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
VALUES('${org}','${ws}','${env}','${target}','agent_endpoint','Mounted owned target','active',clock_timestamp(),clock_timestamp(),'agent',clock_timestamp(),clock_timestamp()+interval '1 hour','{"red_team":{"enabled":true,"endpoint":"https://adapter.customer.example/v1/evaluate","credential_reference":"ref:red-team/target_e2e_0001","target_kinds":["agent_endpoint"]}}');
INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state)
VALUES('${org}','${ws}','${env}','pid_7f300010-0000-4000-8000-000000000010','kubernetes','1.0.0','Mounted prerequisite','{}','active');
INSERT INTO zasp_discovery_syncs(organization_id,workspace_id,environment_id,id,integration_id,idempotency_key,request_digest,trigger_kind,principal_id,parser_version,tool_version)
VALUES('${org}','${ws}','${env}','pid_7f300011-0000-4000-8000-000000000011','pid_7f300010-0000-4000-8000-000000000010','mounted-prerequisite',decode(repeat('ab',32),'hex'),'manual','${actor}','parser_v1','tool_v1');
INSERT INTO zasp_discovery_snapshots(organization_id,workspace_id,environment_id,id,integration_id,sync_id,generation,source,manifest_reference,manifest_checksum,state,candidate_digest,apply_result,complete,is_last_good,collected_at,committed_at)
VALUES('${org}','${ws}','${env}','pid_7f300012-0000-4000-8000-000000000012','pid_7f300010-0000-4000-8000-000000000010','pid_7f300011-0000-4000-8000-000000000011',1,'kubernetes','s3://zasp-production-e2e-evidence/red-team/manifest.json',decode(repeat('ab',32),'hex'),'complete',decode(repeat('ab',32),'hex'),'{}',true,true,clock_timestamp(),clock_timestamp());
UPDATE zasp_inventory_entities SET confidence_basis_points=9500,winning_evidence_id='pid_7f300013-0000-4000-8000-000000000013',winning_snapshot_id='pid_7f300012-0000-4000-8000-000000000012',winning_generation=1,projection_version=1,winning_integration_id='pid_7f300010-0000-4000-8000-000000000010',winning_provider='kubernetes',winning_source='kubernetes',winning_source_native_id='mounted-owned-target',winning_identity_rule=1,winning_source_projection=1 WHERE ${owned} AND id='${target}';
INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,entity_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,source,generation,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
VALUES('${org}','${ws}','${env}','pid_7f300013-0000-4000-8000-000000000013','pid_7f300010-0000-4000-8000-000000000010','pid_7f300012-0000-4000-8000-000000000012','${target}','s3://zasp-production-e2e-evidence/red-team/page.json',decode(repeat('ab',32),'hex'),'application/json','raw_v1','parser_v1',clock_timestamp(),'kubernetes',1,'pid_7f300014-0000-4000-8000-000000000014','red-team/page.json','version-1',128,'tool_v1');
INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
VALUES('${org}','${ws}','${env}','pid_7f300010-0000-4000-8000-000000000010','kubernetes','${target}','mounted-owned-target','pid_7f300012-0000-4000-8000-000000000012','present','{}',clock_timestamp(),clock_timestamp(),'kubernetes','kubernetes_agent','Mounted owned target','{}','kubernetes_agent','agent',1,decode(repeat('ab',32),'hex'),'pid_7f300013-0000-4000-8000-000000000013',9500,clock_timestamp(),clock_timestamp()+interval '1 hour',1,80,1);
SELECT zasp_attack_lab_register_credential_binding('${org}','${ws}','${env}','pid_7f300004-0000-4000-8000-000000000004','${target}','ref:red-team/target_e2e_0001','read_only',1,digest(convert_to('owned-mounted-credential','UTF8'),'sha256'),clock_timestamp()+interval '1 hour');
INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,agent_id)
VALUES('${org}','${ws}','${env}','${finding}','posture','credential','Mounted credential risk','high','open','${target}');`);
  assert.equal(await sql(`SELECT count(*) FROM zasp_security_agent_definitions WHERE ${owned}`),"0");
  assert.equal(await sql(`SELECT count(*) FROM zasp_security_agent_test_links WHERE ${owned}`),"0");
}

export async function runExistingTestMountedBrowser({sql,cdp,publicOrigin,chromePort,ui,plan,execute,record}) {
  await seedPrerequisites(sql);
  const {navigateBrowser,waitForBrowserText,waitForBrowserScope,selectBrowserOption,clickBrowserText,clickBrowserAria,fillBrowserLabel,reloadBrowser,browserFetchJSON,browserBodyText,waitForBrowserAction,startBrowserTab}=ui;
  const route=async(path)=>{await navigateBrowser(cdp,publicOrigin+path);};
  const read=async(path)=>{const response=await browserFetchJSON(cdp,path,{"X-Zasp-Expected-Scope":scope,"X-Zasp-Action-Details":"v1","X-Zasp-Run-Context":"v1"});assert.equal(response.status,200,JSON.stringify(response));return response.body;};
  const evidenceText=async()=>{const value=await cdp.send("Runtime.evaluate",{expression:`document.querySelector('section[aria-label="Recorded test evidence"]')?.innerText ?? ''`,returnByValue:true});return value.result.value;};
  const assertHistory=async id=>{await waitForBrowserAction(cdp,`document.querySelector('[role="dialog"][aria-label="Red team run"] .drawer__body > p > code')?.textContent === ${JSON.stringify(id)}`);const value=await cdp.send("Runtime.evaluate",{expression:`(()=>{const drawer=document.querySelector('[role="dialog"][aria-label="Red team run"]');return {url:location.href,title:drawer?.getAttribute('aria-label'),id:drawer?.querySelector('.drawer__body > p > code')?.textContent};})()`,returnByValue:true});assertMountedHistorySelection(value.result.value,id,scope);};
  await route("/api/v1/session/start?return_to=%2Fred-team%2Fresults");
  await waitForBrowserText(cdp,/No Red Team tests in this scope/);
  await selectBrowserOption(cdp,"Authorized scope","Staging");await waitForBrowserScope(cdp,scope);
  for(const name of ["Mounted comparable test","Mounted no baseline test"]) {
    await route("/red-team/results");await waitForBrowserText(cdp,/Red Team/);
    await clickBrowserText(cdp,"Create test");await fillBrowserLabel(cdp,"Test name",name);
    await selectBrowserOption(cdp,"Fresh discovered target","Mounted owned target");
    await clickBrowserText(cdp,"Save test");
    await waitForBrowserAction(cdp,`document.querySelector('[aria-label="Run ${name}"]')?.disabled === false`);
  }
  await route("/protect/security-agents");await waitForBrowserText(cdp,/Tenant-scoped response definitions/);
  await clickBrowserText(cdp,"Enable environment automation");await waitForBrowserText(cdp,/Environment automation enabled/);
  for(const action of ["run_test","rerun_test"]) { await clickBrowserText(cdp,`Enable ${action}`);await waitForBrowserText(cdp,new RegExp(`${action} enabled`)); }
  const cases=[
    {name:"Mounted supervised run",action:"run_test",autonomy:"supervised",test:"Mounted comparable test",response:"fail",outcome:"needs_human",reason:"test_condition_persists"},
    {name:"Mounted autonomous rerun",action:"rerun_test",autonomy:"autonomous",test:"Mounted comparable test",response:"pass",outcome:"remediated",reason:"test_condition_changed"},
    {name:"Mounted autonomous run",action:"run_test",autonomy:"autonomous",test:"Mounted no baseline test",response:"pass",outcome:"needs_human",reason:"test_baseline_unavailable"},
    {name:"Mounted supervised rerun",action:"rerun_test",autonomy:"supervised",test:"Mounted comparable test",response:"engine_error",outcome:"inconclusive",reason:"test_outcome_unknown"},
  ];
  const completed=[];
  for(const item of cases) {
    await route("/protect/security-agents");await waitForBrowserText(cdp,/Tenant-scoped response definitions/);
    await clickBrowserText(cdp,"Create Security Agent");
    await selectBrowserOption(cdp,"Definition template",item.action==="run_test"?"Run Existing Test":"Rerun Existing Test");
    await waitForBrowserText(cdp,new RegExp(item.test));
    await selectBrowserOption(cdp,"Existing test definition",`${item.test} · version 1`);
    await fillBrowserLabel(cdp,"Definition name",item.name);await fillBrowserLabel(cdp,"AI cost budget (nano OpenRouter credits)","10000");
    await fillBrowserLabel(cdp,"Step limit","1");
    await clickBrowserText(cdp,"Save Security Agent definition");await waitForBrowserText(cdp,new RegExp(item.name));
    await clickBrowserAria(cdp,`Open ${item.name}`);await clickBrowserText(cdp,"Validate definition");await waitForBrowserText(cdp,/Resource version 2/);
    await fillBrowserLabel(cdp,"Evidence ID",finding);
    const beforeSimulation=await sql(`SELECT count(*) FROM zasp_red_team_runs WHERE ${owned}`);
    await clickBrowserText(cdp,"Simulate plan");await waitForBrowserText(cdp,/Simulation only\. This does not execute the proposed steps\./);
    assert.equal(await sql(`SELECT count(*) FROM zasp_red_team_runs WHERE ${owned}`),beforeSimulation,"simulation enqueued work");
    await clickBrowserText(cdp,"Enable supervised execution");await waitForBrowserText(cdp,/Resource version 3/);
    if(item.autonomy==="autonomous") { await clickBrowserText(cdp,"Enable autonomous execution");await waitForBrowserText(cdp,/Resource version 4/); }
    const definitionID=await sql(`SELECT definition_id FROM zasp_security_agent_definitions WHERE ${owned} AND body->>'name'='${item.name}'`);assert.match(definitionID,productID);
    await clickBrowserText(cdp,`Start ${item.autonomy} run`);
    await waitForBrowserAction(cdp,`[...document.querySelectorAll('button')].some(button => button.getAttribute('aria-label')?.startsWith('Open run ')) && document.querySelector('[aria-label="Close"]')?.disabled === false`);
    await clickBrowserAria(cdp,"Close");
    await plan();
    const runID=await sql(`SELECT run_id FROM zasp_security_agent_runs WHERE ${owned} AND definition_id='${definitionID}' AND state<>'simulated' ORDER BY created_at DESC LIMIT 1`);assert.match(runID,productID);
    if(item.autonomy==="supervised") {
      assert.equal(await sql(`SELECT state FROM zasp_security_agent_runs WHERE ${owned} AND run_id='${runID}'`),"waiting_approval");
      const approval=await sql(`SELECT approval_id FROM zasp_security_agent_approvals WHERE ${owned} AND run_id='${runID}' AND state='pending'`);assert.match(approval,productID);
      const approvalToken=randomBytes(32).toString("hex"),approvalDigest=createHash("sha256").update(approvalToken).digest("hex"),approvalCSRF=randomBytes(32).toString("hex");
      await sql(`INSERT INTO zasp_product_sessions(token_digest,csrf_token,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at,authenticated_at) VALUES(decode('${approvalDigest}','hex'),'${approvalCSRF}','session-mounted-approval-${runID.slice(4)}','pid_7f550002-0000-4000-8000-000000000002','${org}','${ws}','${env}','["view","manage_workflows","run_tests"]',clock_timestamp()+interval '1 hour',clock_timestamp())`);
      const approver=await startBrowserTab(chromePort,publicOrigin+"/protect/approvals",{name:"__Host-zasp_session",value:approvalToken,sameSite:"Lax"});
      try { await waitForBrowserScope(approver,scope);await clickBrowserAria(approver,`Open approval ${approval}`);await clickBrowserText(approver,"Approve");await waitForBrowserText(approver,/approved\s+Version 2/); }
      finally { await approver.dispose(); }
    }
    await plan();
    const linkedID=await sql(`SELECT test_run_id FROM zasp_security_agent_test_links WHERE ${owned} AND run_id='${runID}' AND reconcile_state='pending'`);assert.match(linkedID,productID);
    await route("/protect/security-agents");await waitForBrowserText(cdp,new RegExp(runID));await clickBrowserAria(cdp,`Open run ${runID}`);
    const pending=await read(`/api/v1/security-agent-runs/${runID}`);
    assert.equal(pending.action_details[0].existing_test.state,"pending");assert.equal(pending.action_details[0].existing_test.verification,null);
    assertMountedEvidenceText(await evidenceText(),"pending");
    assert.match(await browserBodyText(cdp),new RegExp(linkedID));
    await execute(linkedID,item.response);
    const result=await read(`/api/v1/security-agent-runs/${runID}`),proof=result.action_details[0].existing_test.verification;
    assert.equal(proof.outcome,item.outcome);assert.equal(proof.reason,item.reason);
    if(item.response==="engine_error") {assert.equal(proof.after,null);assert.equal(proof.before,null);}
    else assert.equal(proof.after?.run_id,linkedID);
    if(item.outcome==="remediated") { assert.equal(proof.before.run_id,completed[0].linkedID);assert.ok(proof.checks.some(check=>!check.before_protected&&check.after_protected)); }
    else assert.deepEqual(proof.checks,[]);
    await reloadBrowser(cdp);await waitForBrowserText(cdp,new RegExp(runID));await clickBrowserAria(cdp,`Open run ${runID}`);
    await waitForBrowserText(cdp,/Test verification settled\./);
    assertMountedEvidenceText(await evidenceText(),"settled",{needs_human:"Needs human review",remediated:"Remediated",inconclusive:"Inconclusive"}[item.outcome],{test_condition_persists:"Test condition persists.",test_condition_changed:"Test condition changed.",test_baseline_unavailable:"Test baseline unavailable.",test_outcome_unknown:"Test outcome unknown."}[item.reason]);
    const rendered=await browserBodyText(cdp);
    assert.match(rendered,new RegExp(linkedID));assert.ok(rendered.includes(proof.proof_digest));
    for(const attempt of [proof.before,proof.after].filter(Boolean)) {
      assert.ok(rendered.includes(attempt.run_id));assert.ok(rendered.includes(attempt.input_digest));
      for(const artifact of [attempt.input_artifact,attempt.output_artifact])for(const value of [artifact.reference_digest,artifact.version_id,artifact.sha256,String(artifact.size_bytes)])assert.ok(rendered.includes(value),`stored artifact identity missing: ${value}`);
    }
    if(item.outcome==="remediated") {
      const rows=await cdp.send("Runtime.evaluate",{expression:`[...document.querySelectorAll('section[aria-label="Recorded test evidence"] tbody tr')].map(row=>[...row.cells].map(cell=>cell.textContent))`,returnByValue:true});
      assert.deepEqual(rows.result.value,proof.checks.map(check=>["Prompt injection",check.check_id,check.before_protected?"Yes":"No",check.after_protected?"Yes":"No",String(check.before_http_status),String(check.after_http_status),check.prompt_digest,check.assertion_digest]));
    }
    assert.doesNotMatch(rendered,/ref:red-team|s3:\/\/|lease_token|sk-or-v1/);
    assert.deepEqual((await read(`/api/v1/security-agent-runs/${runID}`)).action_details,result.action_details,"reload changed stored proof");
    await record(runID,cdp,{...item,runID,linkedID,proof});
    if(proof.before) {await clickBrowserText(cdp,"Open before test run");await assertHistory(proof.before.run_id);await reloadBrowser(cdp);await assertHistory(proof.before.run_id);await route("/protect/security-agents");await waitForBrowserText(cdp,new RegExp(runID));await clickBrowserAria(cdp,`Open run ${runID}`);}
    await clickBrowserText(cdp,"Open linked test run");await assertHistory(linkedID);
    await reloadBrowser(cdp);await assertHistory(linkedID);
    assert.equal((await read(`/api/v1/test-runs/${linkedID}`)).id,linkedID);
    completed.push({runID,linkedID,proof});console.log(`mounted existing-test case passed: ${JSON.stringify({...item,runID,linkedID,proof})}`);
  }
  const history=await read("/api/v1/security-agent-runs?limit=100");
  for(const item of completed)assert.ok(history.items.some(run=>run.id===item.runID));
  const cancelFinding="pid_7f550003-0000-4000-8000-000000000003";
  await sql(`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,agent_id) VALUES('${org}','${ws}','${env}','${cancelFinding}','posture','credential','Mounted cancellation prerequisite','high','open','${target}')`);
  await route("/protect/security-agents");await waitForBrowserText(cdp,/Tenant-scoped response definitions/);await clickBrowserAria(cdp,`Open ${cases[0].name}`);await fillBrowserLabel(cdp,"Evidence ID",cancelFinding);await clickBrowserText(cdp,"Start supervised run");
  await waitForBrowserAction(cdp,`document.querySelector('[aria-label="Close"]')?.disabled === false`);await clickBrowserAria(cdp,"Close");
  const cancelID=await sql(`SELECT run_id FROM zasp_security_agent_runs WHERE ${owned} AND trigger_id='${cancelFinding}' AND state='queued'`);assert.match(cancelID,productID);
  const cancellationSnapshot=async()=>JSON.parse(await sql(`SELECT row_to_json(r) FROM zasp_security_agent_runs r WHERE ${owned} AND run_id='${cancelID}'`));
  const cancelBefore=await cancellationSnapshot();assert.equal(cancelBefore.state,"queued");
  const foreignScope="pid_90000001-0000-4000-8000-000000000001/pid_90000002-0000-4000-8000-000000000002/pid_90000003-0000-4000-8000-000000000003";
  const token=randomBytes(32).toString("hex"),csrf=randomBytes(32).toString("hex"),digest=createHash("sha256").update(token).digest("hex");
  await sql(`UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","run_tests"]' WHERE principal_id='pid_90000004-0000-4000-8000-000000000004';
INSERT INTO zasp_product_sessions(token_digest,csrf_token,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(decode('${digest}','hex'),'${csrf}','session-mounted-foreign','pid_90000004-0000-4000-8000-000000000004','pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','["view","manage_workflows","run_tests"]',clock_timestamp()+interval '1 hour')`);
  const foreign=await startBrowserTab(chromePort,publicOrigin+"/protect/security-agents",{name:"__Host-zasp_session",value:token,sameSite:"Lax"});
  try {
    await waitForBrowserScope(foreign,foreignScope);
    const headers={"X-Zasp-Expected-Scope":foreignScope,"X-Zasp-Action-Details":"v1"};
    const own=await browserFetchJSON(foreign,"/api/v1/security-agent-runs?limit=100",headers);assert.equal(own.status,200);assert.deepEqual(own.body.items,[]);
    for(const item of completed) {
      for(const path of [`/api/v1/security-agent-runs/${item.runID}`,`/api/v1/test-runs/${item.linkedID}`]) { const denied=await browserFetchJSON(foreign,path,headers);assert.equal(denied.status,404);assert.equal(JSON.stringify(denied.body).includes(item.linkedID),false); }
      assert.equal((await browserBodyText(foreign)).includes(item.runID),false);
    }
    const denyCancel=async id=>(await foreign.send("Runtime.evaluate",{expression:`(async()=>{const r=await fetch('/api/v1/security-agent-runs/${id}/cancel',{method:'POST',headers:{'X-Zasp-Expected-Scope':${JSON.stringify(foreignScope)},'X-CSRF-Token':${JSON.stringify(csrf)},'Idempotency-Key':'mounted-foreign-${id}','If-Match':${JSON.stringify(`"${cancelBefore.version}"`)}}});return {status:r.status,body:await r.json()};})()`,awaitPromise:true,returnByValue:true})).result.value;
    const mutation=await denyCancel(cancelID),missingID="pid_7f55ffff-0000-4000-8000-000000000001";
    assert.equal(await sql(`SELECT count(*) FROM zasp_security_agent_runs WHERE run_id='${missingID}'`),"0");
    const missing=await denyCancel(missingID);
    for(const denied of [mutation,missing]) {assert.equal(JSON.stringify(denied.body).includes(cancelID),false);assert.equal(JSON.stringify(denied.body).includes(missingID),false);}
    const cancelAfter=await cancellationSnapshot();
    await route("/protect/security-agents");await waitForBrowserText(cdp,new RegExp(cancelID));await clickBrowserAria(cdp,`Open run ${cancelID}`);await clickBrowserText(cdp,"Cancel run");await waitForBrowserText(cdp,/cancelled/);
    const owner=await read(`/api/v1/security-agent-runs/${cancelID}`);
    assertMountedCancellationControl(cancelBefore,mutation,missing,cancelAfter,{status:200,body:owner.run});
    await record(cancelID,cdp,{kind:"foreign-cancellation-control",runID:cancelID,foreignStatus:mutation.status,missingStatus:missing.status,beforeState:cancelBefore.state,beforeVersion:cancelBefore.version,unchangedSnapshotSHA256:createHash("sha256").update(JSON.stringify(cancelBefore)).digest("hex"),ownerState:owner.run.state,ownerVersion:owner.run.version,completedRuns:completed.map(item=>({runID:item.runID,linkedID:item.linkedID,proofDigest:item.proof.proof_digest}))});
  } finally { await foreign.dispose(); }
  for(const item of completed)assert.deepEqual((await read(`/api/v1/security-agent-runs/${item.runID}`)).action_details[0].existing_test.verification,item.proof);
  console.log("mounted existing-test browser passed: both actions/autonomies, fail-to-pass, no-baseline, fail, engine-error, reload/history, foreign read/control refusal and positive controls; local composition only");
}
