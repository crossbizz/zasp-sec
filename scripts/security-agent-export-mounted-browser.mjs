import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

export const exportBrowserRelease = Object.freeze({ version: 58, checksum: "5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985", fingerprint: "8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f" });

export function assertExportBrowserDownload({ saved, envelope, format, exportID, packageSHA256, packageSize, filename, events }) {
  assert.ok(Buffer.isBuffer(saved) && saved.length > 0, "native browser file missing");
  assert.ok(saved.length <= 4 * 1024 * 1024, "saved format exceeds product bound");
  assert.equal(envelope.length, packageSize, "package size differs from SQL");
  assert.equal(createHash("sha256").update(envelope).digest("hex"), packageSHA256.replace(/^sha256:/, ""), "package digest differs from SQL");
  const value = JSON.parse(envelope.toString("utf8"));
  assert.equal(value.version, 1); assert.equal(value.id, exportID);
  assert.ok(["json", "csv", "human"].includes(format));
  const expectedName = `agent-export-${exportID}.${format === "human" ? "txt" : format}`;
  assert.equal(filename, expectedName, "wrong native filename");
  const begin = events.find(event => event.suggestedFilename === expectedName);
  assert.ok(begin?.guid, "browser download start missing");
  assert.ok(events.some(event => event.guid === begin.guid && event.state === "completed" && event.receivedBytes === saved.length), "browser download not completed");
  let expected;
  if (format === "json") {
    // The package uses raw JSON, preserve those bytes instead of serializing it.
    const text = envelope.toString("utf8"), key = '"json":';
    const start = text.indexOf(key);
    assert.ok(start >= 0 && text.indexOf(key, start + key.length) === -1, "ambiguous JSON member");
    let cursor = start + key.length;
    while (/\s/.test(text[cursor] ?? "")) cursor++;
    assert.equal(text[cursor], "{", "agent export JSON is not a manifest");
    const beginJSON = cursor;
    let depth = 0, quoted = false, escaped = false;
    for (; cursor < text.length; cursor++) {
      const character = text[cursor];
      if (quoted) { if (escaped) escaped = false; else if (character === "\\") escaped = true; else if (character === '"') quoted = false; continue; }
      if (character === '"') quoted = true;
      else if (character === "{" || character === "[") depth++;
      else if (character === "}" || character === "]") depth--;
      if (!quoted && depth === 0) { expected = Buffer.from(text.slice(beginJSON, cursor + 1)); break; }
    }
    assert.ok(expected, "incomplete stored manifest");
  } else {
    assert.equal(typeof value[format], "string");
    expected = Buffer.from(value[format]);
  }
  assert.deepEqual(saved, expected, "native saved bytes differ from persisted format");
  return { filename, bytes: saved.length, sha256: createHash("sha256").update(saved).digest("hex"), downloadGUID: begin.guid };
}

export async function prepareExportBrowserRelease({ migrate, migrationEnvironment, command, sql }) {
  await command(migrate, ["up-to-58"], { env: migrationEnvironment });
  assert.equal(await sql("SELECT max(version) FROM zasp_schema_versions"), "58", "export browser requires registered58");
  assert.equal(await sql("SELECT v.checksum||'|'||m.value FROM zasp_schema_versions v,zasp_schema_metadata m WHERE v.version=58 AND m.key='production_security_agent_exports_fingerprint'"), `${exportBrowserRelease.checksum}|${exportBrowserRelease.fingerprint}`, "export browser release58 pin drift");
  await sql("CREATE ROLE compliance_executor LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE compliance_cleanup LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS");
  await command(migrate, ["register-compliance-workers"], { env: { ...migrationEnvironment, ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL: "compliance_executor", ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL: "compliance_cleanup" } });
}

export const exportBrowserScope = "pid_10000001-0000-4000-8000-000000000001/pid_10000022-0000-4000-8000-000000000022/pid_10000023-0000-4000-8000-000000000023";
export const exportBrowserForeignScope = "pid_90000001-0000-4000-8000-000000000001/pid_90000002-0000-4000-8000-000000000002/pid_90000003-0000-4000-8000-000000000003";
const productID = /^pid_[0-9a-f-]{36}$/;

export function exportBrowserIdentity(name) {
  assert.ok(["author","approver","foreign"].includes(name),"unknown export browser identity");
  return {name,token:`export-${name}-oauth-token`,jwt:`export.${name}.fixture`,organization:name==="foreign"?"organization-export-foreign":"organization-test-local",member:name==="author"?"member-test-local":`member-export-${name}`,principal:name==="author"?"pid_10000004-0000-4000-8000-000000000004":name==="approver"?"pid_7f550002-0000-4000-8000-000000000002":"pid_90000004-0000-4000-8000-000000000004"};
}

export async function seedExportBrowserIdentity(sql) {
  const [o,w,e] = exportBrowserScope.split("/"), [fo,fw,fe] = exportBrowserForeignScope.split("/");
  await sql(`INSERT INTO zasp_organizations(id,name,domain) VALUES('${o}','Export browser organization','export.example.test'),('${fo}','Foreign export organization','foreign.example.test');
INSERT INTO zasp_workspaces(id,organization_id,name) VALUES('${w}','${o}','Staging Workspace'),('${fw}','${fo}','Foreign Workspace');
INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES('${e}','${o}','${w}','Staging','staging'),('${fe}','${fo}','${fw}','Foreign','test');
INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES
('pid_10000004-0000-4000-8000-000000000004','${o}','organization-test-local','member-test-local','security_admin'),
('pid_7f550002-0000-4000-8000-000000000002','${o}','organization-test-local','member-export-approver','security_admin'),
('pid_90000004-0000-4000-8000-000000000004','${fo}','organization-export-foreign','member-export-foreign','security_admin');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES
('pid_10000004-0000-4000-8000-000000000004','${o}','${w}','${e}','Staging','["view","manage_workflows","manage_identity"]',true),
('pid_7f550002-0000-4000-8000-000000000002','${o}','${w}','${e}','Staging','["view","manage_workflows"]',true),
('pid_90000004-0000-4000-8000-000000000004','${fo}','${fw}','${fe}','Foreign','["view","manage_workflows"]',true);
SELECT zasp_inventory_backfill_scope('${o}','${w}','${e}'); SELECT zasp_inventory_cutover_scope('${o}','${w}','${e}');
SELECT zasp_inventory_backfill_scope('${fo}','${fw}','${fe}'); SELECT zasp_inventory_cutover_scope('${fo}','${fw}','${fe}');`);
  for (const table of ["zasp_security_agent_definitions", "zasp_security_agent_definition_versions", "zasp_security_agent_runs", "zasp_security_agent_plans", "zasp_security_agent_approvals", "zasp_sa_export_links", "zasp_compliance_export_jobs", "zasp_product_sessions"]) assert.equal(await sql(`SELECT count(*) FROM ${table}`), "0", `unexpected seeded ${table}`);
  assert.equal(await sql("SELECT count(*) FROM zasp_security_agent_kill_switches WHERE action_key='create_evidence_export'"), "0");
}

export async function runSecurityAgentExportMountedBrowser({ sql, author, login, publicOrigin, ui, step, restart, storeDirectory, downloads, record }) {
  const {navigateBrowser,waitForBrowserText,waitForBrowserScope,selectBrowserOption,clickBrowserText,clickBrowserAria,fillBrowserLabel,browserFetchJSON,waitForBrowserAction} = ui;
  const cdp = author.cdp, scope = exportBrowserScope;
  const route = async pathname => { await navigateBrowser(cdp,publicOrigin+pathname); };
  const read = async pathname => { const response = await browserFetchJSON(cdp,pathname,{"X-Zasp-Expected-Scope":scope,"X-Zasp-Action-Details":"v1","X-Zasp-Run-Context":"v1"}); assert.equal(response.status,200,JSON.stringify(response)); return response.body; };
  await login("author", author, "/protect/security-agents"); await waitForBrowserScope(cdp,scope);
  await waitForBrowserText(cdp,/Tenant-scoped response definitions/);
  const controls = await read("/api/v1/security-agent-execution-controls");
  assert.deepEqual(controls.actions.map(value=>value.action_key),["create_evidence_export","create_temporary_policy","isolate_session","rerun_test","revoke_integration_connection","run_test","start_attack_lab","update_finding_response"]);
  assert.equal(controls.actions[0].enabled,false); assert.equal(controls.actions[0].version,0);
  await clickBrowserText(cdp,"Create Security Agent");
  await selectBrowserOption(cdp,"Definition template","Run-scoped evidence export");
  await fillBrowserLabel(cdp,"Definition name","Browser run-scoped export");
  await fillBrowserLabel(cdp,"AI cost budget (nano OpenRouter credits)","1000000");
  await clickBrowserText(cdp,"Save Security Agent definition");
  await waitForBrowserText(cdp,/Browser run-scoped export/);
  const definitions = await read("/api/v1/security-agents?limit=10"); assert.equal(definitions.items.length,1);
  const definition = definitions.items[0]; assert.deepEqual(definition.allowed_actions,["create_evidence_export"]);assert.equal(definition.verification_kind,"export");assert.equal(definition.max_steps,1);assert.equal(definition.max_ai_cost_nano_credits,1000000);assert.equal(definition.enabled,false);assert.equal(Object.hasOwn(definition,"existing_test"),false);
  await clickBrowserAria(cdp,"Open Browser run-scoped export");
  await waitForBrowserText(cdp,/Resource version 1/);
  await record("draft",cdp,{controls});
  await fillBrowserLabel(cdp,"Definition name","Browser run-scoped export updated"); await clickBrowserText(cdp,"Save definition");
  await waitForBrowserText(cdp,/Resource version 2/); await clickBrowserAria(cdp,"Close");
  await clickBrowserText(cdp,"Enable environment automation"); await waitForBrowserText(cdp,/Environment automation enabled/);
  await clickBrowserText(cdp,"Enable create_evidence_export"); await waitForBrowserText(cdp,/create_evidence_export enabled/);
  await clickBrowserAria(cdp,"Open Browser run-scoped export updated");
  await clickBrowserText(cdp,"Validate definition"); await waitForBrowserText(cdp,/Resource version 3/);
  await clickBrowserText(cdp,"Enable supervised execution"); await waitForBrowserText(cdp,/Resource version 4/);
  await record("activated",cdp,await read("/api/v1/security-agent-execution-controls"));
  await clickBrowserText(cdp,"Start supervised run");
  await waitForBrowserAction(cdp,`[...document.querySelectorAll('button')].some(button=>button.getAttribute('aria-label')?.startsWith('Open run ')) && document.querySelector('[aria-label="Close"]')?.disabled === false`);
  await clickBrowserAria(cdp,"Close");
  const page = await read("/api/v1/security-agent-runs?limit=10");
  assert.equal(page.items.length,1); const run = page.items[0]; assert.match(run.id,productID); assert.deepEqual(run.evidence_ids,[]); assert.equal(run.manual_trigger?.version,1);
  await step("plan"); await route("/protect/security-agents"); await clickBrowserAria(cdp,`Open run ${run.id}`); await waitForBrowserText(cdp,/waiting_approval/);
  await record("waiting-approval",cdp,await read(`/api/v1/security-agent-runs/${run.id}`));
  const approvalID = await sql(`SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id='${run.id}' AND state='pending'`); assert.match(approvalID,productID);
  const approver = await login("approver", null, "/protect/approvals");
  await waitForBrowserScope(approver.cdp,scope); await clickBrowserAria(approver.cdp,`Open approval ${approvalID}`); await clickBrowserText(approver.cdp,"Approve"); await waitForBrowserText(approver.cdp,/approved\s+Version 2/);
  await record("approved",approver.cdp,{approvalID,approver:"pid_7f550002-0000-4000-8000-000000000002"});
  await step("dispatch");
  const stepID = await sql(`SELECT step_id FROM zasp_sa_export_links WHERE run_id='${run.id}'`); assert.match(stepID,productID);
  const exportPath = `/api/v1/security-agent-runs/${run.id}/steps/${stepID}/export`;
  const pending = await read(exportPath); assert.equal(pending.state,"pending");
  await route("/protect/security-agents"); await clickBrowserAria(cdp,`Open run ${run.id}`); await waitForBrowserText(cdp,/Evidence export/); await record("pending-export",cdp,pending);
  await step("capture"); await step("settle");
  const job = await read(exportPath); assert.equal(job.state,"completed"); assert.equal(job.cleanup_state,"retained");
  const state = JSON.parse(await readFile(path.join(storeDirectory,"state.json"),"utf8")); assert.equal(state.version,1);
  const objects = state.objects.filter(o => !o.deleted && JSON.parse(Buffer.from(o.body,"base64").toString()).id === job.export_id); assert.equal(objects.length,1);
  const envelope = Buffer.from(objects[0].body,"base64"), manifest = JSON.parse(envelope).json;
  assert.equal(manifest.run_id,run.id); assert.equal(manifest.step_id,stepID);
  assert.equal([manifest.organization_id,manifest.workspace_id,manifest.environment_id].join("/"),scope);
  assert.deepEqual(manifest.records.map(({source_kind,source_id,source_version,association_digest}) => ({source_kind,source_id,source_version,association_digest})),job.selection);
  assert.deepEqual(job.selection.map(value=>value.source_kind),["manual","run_audit"],"public manual run selection changed");
  const [manual,audit]=job.selection, [organization,workspace,environment]=scope.split("/");
  // API and stored fixture values cross into owner SQL here; equality between
  // them is not validation. Refuse noncanonical literals before either query.
  assert.equal(scope.split("/").length,3);
  for(const value of [organization,workspace,environment,run.id,stepID,definition.id,audit.source_id]){
    assert.match(value,/^pid_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    assert.equal(value.length,40);
  }
  assert.match(manual.source_id,/^[0-9a-f]{64}$/);assert.equal(manual.source_id.length,64);
  for(const value of [run.manual_trigger.intent_digest,manual.association_digest,audit.association_digest]){
    assert.match(value,/^sha256:[0-9a-f]{64}$/);assert.equal(value.length,71);
  }
  assert.ok(Number.isSafeInteger(manual.source_version)&&manual.source_version>0);
  assert.deepEqual(manual,{source_kind:"manual",source_id:run.manual_trigger.intent_digest.replace(/^sha256:/,""),source_version:run.manual_trigger.version,association_digest:run.manual_trigger.intent_digest});
  assert.match(audit.source_id,productID);assert.equal(audit.source_version,1);assert.equal(audit.association_digest,run.manual_trigger.intent_digest);
  const originals=[
    JSON.parse(await sql(`SELECT jsonb_build_object('run_id',run_id,'definition_id',definition_id,'trigger_id',trigger_id,'trigger_kind',trigger_kind,'trigger_version',trigger_version,'trigger_digest','sha256:'||encode(trigger_digest,'hex'),'received_at',received_at) FROM zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,trigger_kind,trigger_id,trigger_version)=('${organization}','${workspace}','${environment}','${run.id}','${definition.id}','manual','${manual.source_id}',${manual.source_version}) AND 'sha256:'||encode(trigger_digest,'hex')='${manual.association_digest}'`)),
    JSON.parse(await sql(`SELECT jsonb_build_object('id',audit_id,'run_id',run_id,'organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'actor_reference',actor_id,'event_kind',event_kind,'correlation_id',correlation_id,'occurred_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,audit_id,event_kind)=('${organization}','${workspace}','${environment}','${run.id}','${audit.source_id}','run_queued') AND 'sha256:'||encode(event_digest,'hex')='${audit.association_digest}'`)),
  ];
  for(const [index,original] of manifest.records.entries()){
    assert.equal(createHash("sha256").update(original.content_json).digest("hex"),original.content_sha256,"persisted record digest differs from content");
    assert.deepEqual(JSON.parse(original.content_json),originals[index],"persisted record differs from original scoped source");
  }
  await clickBrowserText(cdp,"Refresh export status"); await waitForBrowserText(cdp,/Export completed/); await record("completed-export",cdp,job);
  const events = [], files = [];
  cdp.on("Browser.downloadWillBegin", event => events.push({guid:event.guid,suggestedFilename:event.suggestedFilename}));
  cdp.on("Browser.downloadProgress", event => events.push({guid:event.guid,state:event.state,receivedBytes:event.receivedBytes}));
  await cdp.send("Browser.setDownloadBehavior",{behavior:"allow",downloadPath:downloads,eventsEnabled:true});
  const saveFormat=async(format,label,directory=downloads)=>{
    const eventStart=events.length;
    await clickBrowserText(cdp,label); await waitForBrowserText(cdp,/Download handed to your browser/);
    const filename = `agent-export-${job.export_id}.${format === "human" ? "txt" : format}`;
    let saved;
    for (let n=0;n<100;n++) { try { const bytes=await readFile(path.join(directory,filename)),fresh=events.slice(eventStart); if(fresh.some(e=>e.state==="completed"&&fresh.some(b=>b.guid===e.guid&&b.suggestedFilename===filename))) {saved=bytes;break;} } catch { /* Wait for the owned final file. */ } await delay(100); }
    return assertExportBrowserDownload({saved,envelope,format,exportID:job.export_id,packageSHA256:job.artifact.sha256,packageSize:job.artifact.size,filename,events:events.slice(eventStart)});
  };
  for (const [format,label] of [["json","Download JSON"],["csv","Download CSV"],["human","Download readable"]]) files.push(await saveFormat(format,label));
  assert.equal((await readdir(downloads)).some(name=>name.endsWith(".crdownload")),false);
  await record("downloads",cdp,{files,package:job.artifact,objectVersion:objects[0].version_id});
  await restart();
  await route("/protect/security-agents"); await clickBrowserAria(cdp,`Open run ${run.id}`); await waitForBrowserText(cdp,/Export completed/);
  assert.deepEqual(await read(exportPath),job,"API/worker restart changed export status");
  const restartedDownloads=path.join(downloads,"restart");await mkdir(restartedDownloads,{mode:0o700});
  await cdp.send("Browser.setDownloadBehavior",{behavior:"allow",downloadPath:restartedDownloads,eventsEnabled:true});
  const restartFile=await saveFormat("json","Download JSON",restartedDownloads);assert.equal(restartFile.sha256,files[0].sha256);
  assert.deepEqual(JSON.parse(await readFile(path.join(storeDirectory,"state.json"),"utf8")),state,"restart/download altered provider object identity");
  assert.equal(await sql("SELECT count(*) FROM zasp_sa_export_links"),"1");assert.equal(await sql("SELECT count(*) FROM zasp_compliance_export_jobs"),"1");
  await record("restart-download",cdp,{restartFile});
  const foreign = await login("foreign",null,"/protect/security-agents"); await waitForBrowserScope(foreign.cdp,exportBrowserForeignScope);
  const denied = await browserFetchJSON(foreign.cdp,exportPath,{"X-Zasp-Expected-Scope":exportBrowserForeignScope}); assert.ok([403,404].includes(denied.status),JSON.stringify(denied));
  await record("foreign-denied",foreign.cdp,{status:denied.status});
  assert.equal(await sql(`SELECT state FROM zasp_security_agent_runs WHERE run_id='${run.id}'`),"needs_human");
  return {runID:run.id,stepID,exportID:job.export_id,manualTrigger:run.manual_trigger,selection:job.selection,files,restartFile,package:job.artifact,identity:"controlled OAuth callback, not live Stytch",provider:"controlled model and SDK store, not live providers"};
}
