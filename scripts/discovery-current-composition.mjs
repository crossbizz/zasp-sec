import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import { createInterface } from "node:readline/promises";
import path from "node:path";
import { spawnOwnedCommand } from "./owned-command.mjs";
import { installBoundedSignalCleanup } from "./bounded-signal-cleanup.mjs";
import { reloadBrowserPage } from "./browser-e2e-helpers.mjs";

const profile = "canonical61-temporal78-authorization79-80-worker-v1";
const roles = Object.freeze(["observer", "api", "discovery", "scheduler", "projector", "compensation"]);
const identifier = /^[a-z][a-z0-9_]{0,62}$/;
const productID = /^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const kubernetesReference = /^ref:kubernetes\/connection\/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/;
const digest = /^[a-f0-9]{64}$/;
const codes = new Set(["mode-invalid", "config-invalid", "config-unavailable", "observation-invalid", "database-unavailable", "profile-mismatch", "principal-unavailable", "evidence-unavailable", "internal-refusal", "browser-unavailable", "public-refusal", "external-checkpoint", "observer-unavailable", "journey-deadline", "evidence-mismatch", "cleanup-incomplete"]);
class PreflightError extends Error {
  constructor(code) { super(`current discovery: ${code}`); this.code = code; }
}
function requireValue(value, code = "config-invalid") { if (!value) throw new PreflightError(code); }
function exact(value, keys, code = "config-invalid") {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype, code);
  requireValue(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), code);
}
function absolute(value) { return typeof value === "string" && value.length <= 1024 && !/[\x00-\x1f'\\]/.test(value) && path.isAbsolute(value) && path.normalize(value) === value && value !== "/"; }
function sha(value) { return createHash("sha256").update(value).digest("hex"); }

export function currentDiscoveryFailureCode(error) {
  return error instanceof PreflightError && codes.has(error.code) ? error.code : "internal-refusal";
}

export function currentDiscoveryExitCode(result) {
  return result?.journey==="passed"&&result.phase==="complete"&&result.code==="journey-complete" ? 0 : 1;
}

export async function readCurrentAgentIDs(get) {
  const ids=[],cursors=new Set();let cursor;
  for(let page=0;page<100;page++){
    const value=await get(`/api/v1/agents?limit=100${cursor?`&cursor=${encodeURIComponent(cursor)}`:""}`);
    exact(value,["items","page_info"],"observation-invalid");
    exact(value.page_info,["has_more","next_cursor"],"observation-invalid");
    requireValue(Array.isArray(value.items)&&value.items.length<=100,"observation-invalid");
    for(const item of value.items){requireValue(productID.test(item?.id)&&(!ids.length||item.id>ids.at(-1)),"evidence-mismatch");ids.push(item.id);}
    if(value.page_info.has_more===false){requireValue(value.page_info.next_cursor===null,"observation-invalid");return ids;}
    cursor=value.page_info.next_cursor;
    requireValue(value.page_info.has_more===true&&value.items.length>0&&typeof cursor==="string"&&cursor.length>0&&cursor.length<=4096&&!/[\x00-\x20]/.test(cursor)&&!cursors.has(cursor),"observation-invalid");cursors.add(cursor);
  }
  throw new PreflightError("observation-invalid");
}

export function validateCurrentDiscoveryMode(env) {
  if (!Object.hasOwn(env, "ZASP_COMBINED_E2E_CURRENT_DISCOVERY")) return false;
  requireValue(env.ZASP_COMBINED_E2E_CURRENT_DISCOVERY === "true", "mode-invalid");
  for (const key of Object.keys(env)) {
    requireValue(!key.startsWith("ZASP_COMBINED_E2E_") || ["ZASP_COMBINED_E2E_CURRENT_DISCOVERY", "ZASP_COMBINED_E2E_CHROME"].includes(key), "mode-invalid");
  }
  requireValue(!Object.hasOwn(env, "ZASP_RECONCILIATION_API_LOAD_DIAGNOSTIC"), "mode-invalid");
  return true;
}

export function validateCurrentDiscoveryConfig(value) {
  const connected = value?.format === "zasp-current-discovery-journey-v1";
  exact(value, ["format", "publicOrigin", "scope", "profile", "canonical61Checksum", "workerChecksum", "provider", "database", "evidenceDirectory", ...(connected ? ["journey"] : [])]);
  requireValue((connected || value.format === "zasp-current-discovery-preflight-v1") && value.profile === profile);
  let origin;
  try { origin = new URL(value.publicOrigin); } catch { throw new PreflightError("config-invalid"); }
  requireValue(origin.protocol === "https:" && origin.origin === value.publicOrigin && !origin.username && !origin.password);
  exact(value.scope, ["organizationID", "workspaceID", "environmentID"]);
  requireValue(Object.values(value.scope).every(id => typeof id === "string" && productID.test(id)));
  requireValue(digest.test(value.canonical61Checksum) && digest.test(value.workerChecksum));
  exact(value.provider, ["kind", "protectedReference"]);
  requireValue(["aws", "kubernetes", "github", "okta"].includes(value.provider.kind));
  requireValue(typeof value.provider.protectedReference === "string" && (connected?kubernetesReference:/^[a-z][a-z0-9_-]{0,127}$/).test(value.provider.protectedReference));
  exact(value.database, ["psql", "serviceFile", "passwordFile", "connections"]);
  requireValue([value.database.psql, value.database.serviceFile, value.database.passwordFile, value.evidenceDirectory].every(absolute));
  requireValue(path.basename(value.database.psql) === "psql");
  exact(value.database.connections, roles);
  for (const role of roles) {
    const connection = value.database.connections[role];
    exact(connection, ["service", "login"]);
    requireValue(identifier.test(connection.service) && identifier.test(connection.login));
  }
  for (const field of ["service", "login"]) requireValue(new Set(roles.map(role => value.database.connections[role][field])).size === roles.length);
  if (connected) validateJourneyConfig(value);
  // Copy only after full closed-shape validation; the caller cannot mutate a
  // queued probe's authority configuration via its original object.
  return JSON.parse(JSON.stringify(value));
}

function validateJourneyConfig(c) {
  const j = c.journey;
  exact(j, ["chrome", "integrationName", "configuration", "source", "foreignScope", "temporal"]);
  requireValue(absolute(j.chrome) && /^[A-Za-z0-9][A-Za-z0-9 _-]{0,95}$/.test(j.integrationName));
  requireValue(j.configuration && Object.getPrototypeOf(j.configuration) === Object.prototype && Object.keys(j.configuration).length > 0 && Object.keys(j.configuration).length <= 16);
  for (const [key,value] of Object.entries(j.configuration)) requireValue(/^[a-z][a-z0-9_]{0,63}$/.test(key) && !/(password|token|secret|credential)(?!_reference$)/.test(key) && typeof value === "string" && value.length > 0 && value.length <= 1024 && !/[\x00-\x1f]/.test(value));
  exact(j.configuration,["connection_reference"]);
  requireValue(j.configuration.connection_reference===c.provider.protectedReference&&kubernetesReference.test(j.configuration.connection_reference));
  exact(j.source, ["nativeID", "metadataKey", "before", "after"]);
  // The initial connected provider contract uses an actual Kubernetes Agent
  // posture field, not an invented image/label field absent from collection.
  requireValue(c.provider.kind === "kubernetes" && /^kubernetes:deployment:[A-Za-z0-9_-]{1,128}$/.test(j.source.nativeID));
  requireValue(["posture.runtime_policy_supported", "posture.production_agent"].includes(j.source.metadataKey) && typeof j.source.before === "boolean" && typeof j.source.after === "boolean" && j.source.before !== j.source.after);
  exact(j.foreignScope, ["organizationID", "workspaceID", "environmentID"]);
  requireValue(Object.values(j.foreignScope).every(id => typeof id === "string" && productID.test(id)) && JSON.stringify(j.foreignScope) !== JSON.stringify(c.scope));
  exact(j.temporal, ["executable", "sha256", "config"]);
  requireValue(absolute(j.temporal.executable) && digest.test(j.temporal.sha256));
  const t = j.temporal.config;
  exact(t,["Enabled","Environment","TemporalAddress","Namespace","TaskQueue","DiscoveryTaskQueue","TemporalCAFile","TemporalCertFile","TemporalKeyFile","FGAURL","StoreID","ModelID","FGATokenFile","FGACAFile","Timeout"]);
  requireValue(t.Enabled === true && t.Environment === "production" && t.Timeout === 10_000_000_000);
  requireValue([t.Namespace,t.TaskQueue,t.DiscoveryTaskQueue].every(v => typeof v === "string" && /^[a-z][a-z0-9._-]{1,127}$/.test(v)) && t.TaskQueue !== t.DiscoveryTaskQueue);
  requireValue([t.TemporalCAFile,t.TemporalCertFile,t.TemporalKeyFile,t.FGATokenFile,t.FGACAFile].every(absolute));
  requireValue(typeof t.TemporalAddress === "string" && t.TemporalAddress.length < 256 && !/[\x00-\x20/@]/.test(t.TemporalAddress));
  let fga; try { fga = new URL(t.FGAURL); } catch { throw new PreflightError("config-invalid"); }
  requireValue(fga.protocol === "https:" && !fga.username && !fga.password && fga.origin === t.FGAURL);
  requireValue([t.StoreID,t.ModelID].every(v => typeof v === "string" && /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(v)));
  // Go's existing runtime config validates private endpoints/TLS before RPC.
}

export function currentDiscoveryAuthorityProbe(config) {
  const c = validateCurrentDiscoveryConfig(config);
  requireValue(c.journey);
  const t = c.journey.temporal.config;
  const probe = currentDiscoveryProbe(c, "observer");
  probe.args[probe.args.length - 1] = `BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SELECT jsonb_build_object('model_bound',o.store_id='${t.StoreID}' AND o.model_id='${t.ModelID}' AND o.blocked_reason='', 'verifiers_bound',(SELECT count(*)=2 AND bool_and(purpose IN('worker-forward','captured-compensation') AND version~'^[a-f0-9]{64}$') FROM zasp_authorization80_worker.verifiers),'desired',o.desired,'applied',o.applied,'generation',o.generation) FROM zasp_authorization79.organizations o WHERE o.organization_id='${c.scope.organizationID}'; ROLLBACK;`;
  return probe;
}

export function currentDiscoveryStateProbe(config, kind, ids) {
  const c = validateCurrentDiscoveryConfig(config);
  requireValue(c.journey && ["receipt", "state", "inventory"].includes(kind));
  exact(ids, ["integrationID", "syncID", "receiptID", "auditID"]);
  requireValue(Object.values(ids).every(v => typeof v === "string" && productID.test(v)));
  const scope = alias => `${alias}.organization_id='${c.scope.organizationID}' AND ${alias}.workspace_id='${c.scope.workspaceID}' AND ${alias}.environment_id='${c.scope.environmentID}'`;
  const integration = alias => `${scope(alias)} AND ${alias}.integration_id='${ids.integrationID}'`;
  const literal = value => `convert_from(decode('${Buffer.from(value).toString("hex")}','hex'),'UTF8')`;
  let body;
  if (kind === "receipt") body = `SELECT jsonb_build_object('bound',EXISTS(SELECT 1 FROM public.zasp_workflow_receipts r JOIN public.zasp_workflow_audit a ON (a.organization_id,a.workspace_id,a.environment_id,a.audit_id,a.principal_id,a.operation,a.resource_kind,a.resource_id,a.resource_version)=(r.organization_id,r.workspace_id,r.environment_id,r.audit_id,r.principal_id,r.operation,r.resource_kind,r.resource_id,r.resource_version) WHERE ${scope("r")} AND r.receipt_id='${ids.receiptID}' AND r.audit_id='${ids.auditID}' AND ((r.resource_kind='integration_sync' AND r.resource_id='${ids.syncID}') OR (r.resource_kind IN('integration','integration_schedule') AND r.resource_id='${ids.integrationID}'))));`;
  if (kind === "state") body = `SELECT jsonb_build_object('database_now',clock_timestamp(),
 'schedules',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',s.id,'state',s.state,'version',s.version,'next_run_at',s.next_run_at,'anchor',s.anchor,'acknowledged_revision',s.acknowledged_revision,'delivered_revision',s.delivered_revision,'cadence_seconds',s.cadence_seconds)),'[]') FROM zasp_temporal72.schedules s WHERE ${integration("s")}),
 'runs',(SELECT COALESCE(jsonb_agg(jsonb_build_object('job_id',r.job_id,'sync_id',r.sync_id,'schedule_id',r.schedule_id,'scheduled_for',r.scheduled_for,'state',r.state,'admitted_at',r.admitted_at,'outbox_published',EXISTS(SELECT 1 FROM public.zasp_discovery_outbox o WHERE ${scope("o")} AND o.id=r.outbox_id AND o.state='published'),'page_effects',(SELECT count(*) FROM zasp_temporal72.page_effects p WHERE ${scope("p")} AND p.job_id=r.job_id AND p.recorded_at IS NOT NULL),'apply_commits',(SELECT count(*) FROM zasp_temporal72.apply_effects a WHERE ${scope("a")} AND a.job_id=r.job_id AND a.committed_at IS NOT NULL)) ORDER BY r.admitted_at),'[]') FROM zasp_temporal72.runs r WHERE ${integration("r")}),
 'snapshots',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',s.id,'sync_id',s.sync_id,'complete',s.complete,'state',s.state,'is_last_good',s.is_last_good,'committed_at',s.committed_at,'manifest_version',(SELECT i.manifest_version_id FROM public.zasp_discovery_snapshot_inputs i WHERE ${integration("i")} AND i.snapshot_id=s.id),'manifest_sha256',encode(s.manifest_checksum,'hex'))),'[]') FROM public.zasp_discovery_snapshots s WHERE ${integration("s")}));`;
  if (kind === "inventory") body = `SELECT jsonb_build_object('target',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',e.id,'display_name',e.display_name,'last_seen_at',o.last_seen_at,'snapshot_id',o.snapshot_id,'source_state',o.source_state,'metadata',o.attributes #> '{${c.journey.source.metadataKey.split(".").join(",")}}')),'[]') FROM public.zasp_inventory_source_observations o JOIN public.zasp_inventory_entities e ON(e.organization_id,e.workspace_id,e.environment_id,e.id)=(o.organization_id,o.workspace_id,o.environment_id,o.entity_id) WHERE ${integration("o")} AND o.source_native_id=${literal(c.journey.source.nativeID)} AND e.kind='agent' AND o.source_kind='kubernetes_agent'),
 'unrelated_digest',(SELECT md5(COALESCE(jsonb_agg(jsonb_build_array(e.id,e.kind,e.display_name,e.stable_fields,e.state,o.integration_id,o.source,o.source_native_id,o.attributes,o.source_state) ORDER BY e.id,o.integration_id,o.source)::text,'[]')) FROM public.zasp_inventory_entities e LEFT JOIN public.zasp_inventory_source_observations o ON(e.organization_id,e.workspace_id,e.environment_id,e.id)=(o.organization_id,o.workspace_id,o.environment_id,o.entity_id) WHERE ${scope("e")} AND NOT EXISTS(SELECT 1 FROM public.zasp_inventory_source_observations t WHERE ${integration("t")} AND t.entity_id=e.id AND t.source_native_id=${literal(c.journey.source.nativeID)})));`;
  const probe = currentDiscoveryProbe(c, "observer");
  probe.args[probe.args.length - 1] = `BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; ${body} ROLLBACK;`;
  return probe;
}

// These are existing native read-only entry points, not owner membership
// substitutes. Each expression runs through a separately configured LOGIN.
const principalQueries = Object.freeze({
  api: "zasp_temporal72.principal_ready('zasp_discovery_api')",
  discovery: "zasp_temporal72.principal_ready('zasp_discovery_worker')",
  scheduler: "zasp_temporal72.principal_ready('zasp_discovery_scheduler')",
  projector: "public.zasp_discovery_principal_ready('zasp_outbox_worker')",
  compensation: "zasp_temporal68.principal_ready('zasp_temporal_compensation')",
});

export function currentDiscoveryProbe(config, role) {
  const c = validateCurrentDiscoveryConfig(config);
  requireValue(roles.includes(role));
  const identity = "'session_user',session_user,'current_user',current_user,'read_only',current_setting('transaction_read_only')='on'";
  const body = role === "observer" ? `SELECT jsonb_build_object(${identity},
 'scope_exists',EXISTS(SELECT 1 FROM public.zasp_environments WHERE organization_id='${c.scope.organizationID}' AND workspace_id='${c.scope.workspaceID}' AND id='${c.scope.environmentID}'),
 'canonical_count',(SELECT count(*) FROM public.zasp_schema_versions),
 'canonical_checksum',(SELECT checksum FROM public.zasp_schema_versions WHERE version=61),
 'worker_checksum',(SELECT checksum FROM zasp_authorization80_worker.registration),
 'catalog_ready',zasp_authorization80_worker.catalog_ready(),
 'runtime_ready',zasp_authorization80_worker.runtime_ready());` : `SELECT jsonb_build_object(${identity},
 'registered',${principalQueries[role]},
 'login_role',(SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=session_user),
 'superuser',(SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=session_user));`;
  return {
    executable: c.database.psql,
    args: ["-X", "-w", "-qAt", "-v", "ON_ERROR_STOP=1", "--dbname", `service=${c.database.connections[role].service} sslmode=verify-full connect_timeout=2 options='-c default_transaction_read_only=on'`, "-c", `BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; ${body} ROLLBACK;`],
    // No process.env, HOME, PGPASSWORD, PGOPTIONS, startup SQL, or inherited DSN.
    // libpq alone reads the explicitly approved protected files. A missing
    // service cannot fall back to the system service directory or .pgpass.
    env: { LANG: "C", LC_ALL: "C", PGSERVICEFILE: c.database.serviceFile, PGSYSCONFDIR: "/dev/null", PGPASSFILE: c.database.passwordFile },
  };
}

async function queryDatabase(config, role) {
  return executeProbe(currentDiscoveryProbe(config, role));
}

async function executeProbe(probe, own) {
  const owned = spawnOwnedCommand(probe.executable, probe.args, { env: probe.env, maxOutputBytes: 16_384 });
  const release = own?.(owned.stop);
  let interrupted = false, timer, fail;
  const rejected = new Promise((_, reject) => { fail = reject; });
  const refuse = () => {
    if (interrupted) return;
    interrupted = true;
    void owned.stop().then(() => fail(new PreflightError("database-unavailable")), () => fail(new PreflightError("database-unavailable")));
  };
  const cleanup = own ? { dispose() {} } : installBoundedSignalCleanup(async () => { interrupted = true; await owned.stop(); }, { timeout: 8000 });
  timer = setTimeout(refuse, 10_000);
  try {
    const result = await Promise.race([owned.completed, rejected]);
    requireValue(!interrupted && !result.outputLimitExceeded && result.status === 0 && result.signal === null, "database-unavailable");
    try { return JSON.parse(result.stdout); } catch { throw new PreflightError("observation-invalid"); }
  } catch { throw new PreflightError("database-unavailable"); }
  finally {
    clearTimeout(timer);
    try { await owned.stop(); } finally { release?.(); cleanup.dispose(); }
  }
}

// This function is serialized into the owned browser. It observes only the
// configured product origin, never Stytch/provider bodies. Retained request
// headers stay in its closure for the single schedule replay, not Node/logs.
export function installDiscoveryBrowserBoundary(origin, configuredScope, ownedIntegrationID = null, cleanupOnly = false) {
  if (location.origin !== origin || (!cleanupOnly && window.__zaspCurrentDiscovery)) return;
  // Cleanup is returned only into a CDP-owned isolated world. The page receives
  // neither an ownership setter nor a cleanup method.
  const boundScope=Object.freeze({...configuredScope});
  const original = window.fetch.bind(window), mutations = [], retained = new Map();
  let failed = false;
  const allowed = /^\/api\/v1\/integrations(?:\/pid_[a-f0-9-]+(?:\/(?:sync|schedule|reference-authorization))?)?$/;
  const read = async response => {
    if (Number(response.headers.get("content-length")) > 1048576) throw Error("bounded response");
    if (!response.body) return null;
    const reader = response.body.getReader(), chunks = []; let n = 0;
    try {
      for (;;) { const r = await reader.read(); if (r.done) break; n += r.value.byteLength; if (n > 1048576) throw Error("bounded response"); chunks.push(r.value); }
      const data = new Uint8Array(n); let at = 0; for (const c of chunks) { data.set(c, at); at += c.length; }
      return n ? JSON.parse(new TextDecoder().decode(data)) : null;
    } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  };
  const clean = value => {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) { for (const item of value) clean(item); return; }
    for (const [key,item] of Object.entries(value)) {
      if (/^(?:access_token|refresh_token|provider_token|password|client_secret|code_verifier)$/i.test(key)) throw Error("secret response");
      clean(item);
    }
  };
  const result = async response => {
    const value = await read(response); clean(value);
    return { status: response.status, value, version: response.headers.get("etag"), auditID: response.headers.get("x-audit-id"), receiptID: response.headers.get("x-mutation-receipt-id"), noStore: response.headers.get("cache-control") === "no-store" };
  };
  if (!cleanupOnly) window.fetch = async (input, init) => {
    const request = new Request(input, init), url = new URL(request.url);
    const observe = url.origin === origin && allowed.test(url.pathname) && ["POST","PUT","DELETE"].includes(request.method);
    const copy = observe ? request.clone() : null;
    const response = await original(request);
    if (observe) {
      try {
        const record = { path: url.pathname, method: request.method, ...await result(response.clone()) };
        if (mutations.length >= 32) throw Error("bounded observations");
        mutations.push(record);
        if (request.method === "PUT" && url.pathname.endsWith("/schedule") && response.ok && !retained.has(url.pathname)) retained.set(url.pathname, copy);
      } catch { failed = true; }
    }
    return response;
  };
  const id=/^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
  const validateCleanup=q=>{
    if(!cleanupOnly||!id.test(ownedIntegrationID)||!q||q.integrationID!==ownedIntegrationID||!q.scope||Object.keys(q.scope).sort().join(",")!=="environmentID,organizationID,workspaceID"||Object.keys(boundScope).sort().join(",")!=="environmentID,organizationID,workspaceID"||!Object.keys(boundScope).every(k=>id.test(boundScope[k])&&q.scope[k]===boundScope[k]))throw Error("cleanup refused");
  };
  const expectedScope=[boundScope.organizationID,boundScope.workspaceID,boundScope.environmentID].join("/");
  const cleanupSession=async signal=>{
    const session=await result(await original("/api/v1/session/bootstrap",{credentials:"same-origin",cache:"no-store",redirect:"error",headers:{"X-Zasp-Expected-Scope":expectedScope},signal}));
    const s=session.value;
    if(session.status!==200||!session.noStore||!s||s.organization_id!==boundScope.organizationID||s.workspace_id!==boundScope.workspaceID||s.environment_id!==boundScope.environmentID||!(Date.parse(s.fresh_auth_expires_at)>Date.now())||typeof s.csrf_token!=="string"||s.csrf_token.length<16||s.csrf_token.length>4096||/[\x00-\x20]/.test(s.csrf_token))throw Error("cleanup session refused");
    return s;
  };
  const boundary={
    mutation(method,path) { if (failed) throw Error("observation refused"); const at = mutations.findIndex(v => v.method === method && v.path === path); return at < 0 ? null : mutations.splice(at,1)[0]; },
    async cleanupMutation(q,timeout=10000) {
      validateCleanup(q);
      if(!Number.isInteger(timeout)||timeout<1||timeout>10000)throw Error("cleanup refused");
      if(Object.keys(q).sort().join(",")!=="action,integrationID,scope,version"||!["disable-schedule","delete-schedule","delete-integration"].includes(q.action)||!/^"[1-9][0-9]{0,5}"$/.test(q.version))throw Error("cleanup refused");
      const signal=AbortSignal.timeout(timeout);
      const s=await cleanupSession(signal);
      const schedule=q.action!=="delete-integration",method=q.action==="disable-schedule"?"PUT":"DELETE";
      return result(await original(`/api/v1/integrations/${ownedIntegrationID}${schedule?"/schedule":""}`,{method,credentials:"same-origin",cache:"no-store",redirect:"error",headers:{"X-CSRF-Token":s.csrf_token,"X-Zasp-Expected-Scope":expectedScope,"If-Match":q.version,"Idempotency-Key":crypto.randomUUID(),...(method==="PUT"?{"Content-Type":"application/json"}:{})},...(method==="PUT"?{body:JSON.stringify({cadence_seconds:300,state:"disabled"})}:{}),signal}));
    },
    async cleanupRead(q,timeout=10000) {
      validateCleanup(q);
      if(!Number.isInteger(timeout)||timeout<1||timeout>10000)throw Error("cleanup refused");
      if(Object.keys(q).sort().join(",")!=="integrationID,resource,scope"||!["integration","schedule"].includes(q.resource))throw Error("cleanup refused");
      const signal=AbortSignal.timeout(timeout);
      await cleanupSession(signal);
      return result(await original(`/api/v1/integrations/${ownedIntegrationID}${q.resource==="schedule"?"/schedule":""}`,{method:"GET",credentials:"same-origin",cache:"no-store",redirect:"error",headers:{"X-Zasp-Expected-Scope":expectedScope},signal}));
    },
    async get(path,foreignScope) {
      if (!/^\/api\/v1\/(?:session\/bootstrap|integration-catalog|integrations(?:\/|\?|$)|agents(?:\/|\?|$))/.test(path) || path.startsWith("//") || path.includes("#")) throw Error("read refused");
      const headers = foreignScope ? { "X-Zasp-Expected-Scope": foreignScope } : {};
      const response = await original(path,{credentials:"same-origin",cache:"no-store",redirect:"error",headers,signal:AbortSignal.timeout(10000)});
      const out = await result(response);
      if (path === "/api/v1/session/bootstrap" && out.value) delete out.value.csrf_token;
      return out;
    },
    async replay(path) {
      const r = retained.get(path); if (!r) throw Error("replay refused"); retained.delete(path);
      return result(await original(r));
    },
    leakFree() {
      if (failed || /[?&](?:token|code|state|access_token)=/i.test(location.href)) return false;
      for (const s of [localStorage,sessionStorage]) for (let i=0;i<s.length;i++) if (/(?:bearer\s|access_token|refresh_token|provider_token|client_secret|code_verifier)/i.test(s.key(i)+s.getItem(s.key(i)))) return false;
      return !/(?:access_token|refresh_token|provider_token|client_secret|code_verifier)/i.test(document.body.innerText);
    },
  };
  if(cleanupOnly)return Object.freeze({cleanupRead:boundary.cleanupRead,cleanupMutation:boundary.cleanupMutation});
  delete boundary.cleanupRead;delete boundary.cleanupMutation;
  Object.defineProperty(window, "__zaspCurrentDiscovery", { value: Object.freeze(boundary) });
}

// This object remains in Node. Only the receipt-verified create response can
// bind it, once; no page-visible setter or arbitrary cleanup object ID exists.
export function createDiscoveryCleanupChannel(send,c) {
  const scope=Object.freeze({...c.scope}),origin=c.publicOrigin;
  let ownedID,objectID;
  const call=async(method,q)=>{
    requireValue(ownedID&&q?.integrationID===ownedID&&q.scope&&Object.keys(q.scope).length===3&&Object.keys(scope).every(k=>q.scope[k]===scope[k]),"cleanup-incomplete");
    const deadline=Date.now()+10000;
    const remaining=()=>{const ms=deadline-Date.now();requireValue(ms>0,"cleanup-incomplete");return ms;};
    const rpc=(method,params)=>send(method,params,remaining());
    if(!objectID){
      const tree=await rpc("Page.getFrameTree",{});
      requireValue(new URL(tree.frameTree.frame.url).origin===origin,"cleanup-incomplete");
      const world=await rpc("Page.createIsolatedWorld",{frameId:tree.frameTree.frame.id,worldName:"zasp-owned-discovery-cleanup",grantUniveralAccess:false});
      const result=await rpc("Runtime.evaluate",{contextId:world.executionContextId,expression:`(${installDiscoveryBrowserBoundary.toString()})(${JSON.stringify(origin)},${JSON.stringify(scope)},${JSON.stringify(ownedID)},true)`,returnByValue:false});
      requireValue(!result.exceptionDetails&&typeof result.result?.objectId==="string","cleanup-incomplete");
      objectID=result.result.objectId;
    }
    const result=await rpc("Runtime.callFunctionOn",{objectId:objectID,functionDeclaration:method==="cleanupRead"?"function(q,ms){return this.cleanupRead(q,ms);}":"function(q,ms){return this.cleanupMutation(q,ms);}",arguments:[{value:q},{value:remaining()}],awaitPromise:true,returnByValue:true});
    remaining();requireValue(!result.exceptionDetails,"cleanup-incomplete");return result.result?.value;
  };
  return Object.freeze({
    bindOwnedIntegration(id){requireValue(!ownedID&&productID.test(id),"cleanup-incomplete");ownedID=id;},
    cleanupRead:q=>call("cleanupRead",q),cleanupMutation:q=>call("cleanupMutation",q),
  });
}

async function connectCurrentCDP(url, onEvent) {
  const target = new URL(url);
  requireValue(target.protocol === "ws:" && target.hostname === "127.0.0.1" && /^\/devtools\/browser\/[a-f0-9-]+$/.test(target.pathname),"browser-unavailable");
  const socket = new WebSocket(url), pending = new Map(); let serial = 0;
  const ready = new Promise((resolve,reject) => { const timer=setTimeout(()=>reject(new PreflightError("browser-unavailable")),5000); socket.addEventListener("open",()=>{clearTimeout(timer);resolve();},{once:true});socket.addEventListener("error",()=>{clearTimeout(timer);reject(new PreflightError("browser-unavailable"));},{once:true}); });
  const refuse = () => { for (const p of pending.values()) { clearTimeout(p.timer);p.reject(new PreflightError("browser-unavailable")); } pending.clear(); };
  socket.addEventListener("close",refuse);
  socket.addEventListener("message",event=>{
    if (typeof event.data!=="string" || event.data.length>1048576) {refuse();socket.close();return;}
    let value;try{value=JSON.parse(event.data);}catch{refuse();socket.close();return;}
    if(value.method){try{onEvent?.(value);}catch{refuse();socket.close();}return;}
    const p=pending.get(value.id);if(!p)return;pending.delete(value.id);clearTimeout(p.timer);if(value.error)p.reject(new PreflightError("browser-unavailable"));else p.resolve(value.result);
  });
  try{await ready;}catch(e){socket.close();throw e;}
  return {send(method,params={},sessionId,timeout=10000){requireValue(Number.isInteger(timeout)&&timeout>0&&timeout<=10000,"browser-unavailable");return new Promise((resolve,reject)=>{const id=++serial,timer=setTimeout(()=>{pending.delete(id);reject(new PreflightError("browser-unavailable"));},timeout);pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});},close(){refuse();socket.close();}};
}

async function createCurrentBrowser(c, own) {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(),"zasp-current-discovery-")));
  const owned = spawnOwnedCommand(c.journey.chrome,["--remote-debugging-address=127.0.0.1","--remote-debugging-port=0",`--user-data-dir=${dir}`,"--no-first-run","--no-default-browser-check","about:blank"],{env:{PATH:"/usr/bin:/bin",LANG:"en_US.UTF-8"},maxOutputBytes:16384});
  let connection;
  let closing; const close = ()=>closing??=(async()=>{connection?.close();await owned.stop();await rm(dir,{recursive:true,force:true});})();
  own?.(close);
  try {
    const until=Date.now()+10000;let lines;
    while(Date.now()<until){try{const data=await readFile(path.join(dir,"DevToolsActivePort"),"utf8");if(data.length<256){lines=data.trim().split("\n");break;}}catch{/* Browser port file may not exist until startup completes. */} await delay(100);}
    requireValue(lines?.length===2 && /^[0-9]{1,5}$/.test(lines[0]),"browser-unavailable");
    const reads=new Map(),session={start:false,callback:false,bootstrap:false};
    connection=await connectCurrentCDP(`ws://127.0.0.1:${lines[0]}${lines[1]}`,event=>{
      const response=event.method==="Network.responseReceived"?event.params?.response:event.method==="Network.requestWillBeSent"?event.params?.redirectResponse:null;
      if(!response)return;let url;try{url=new URL(response.url);}catch{return;}if(url.origin!==c.publicOrigin)return;
      if(url.pathname==="/api/v1/session/start"&&[302,303,307].includes(response.status))session.start=true;
      if(url.pathname==="/api/v1/session/callback"&&response.status===200)session.callback=true;
      if(url.pathname==="/api/v1/session/bootstrap"&&response.status===200)session.bootstrap=true;
      if(response.status===200&&/^\/api\/v1\/integrations\/pid_[a-f0-9-]+\/syncs\/pid_[a-f0-9-]+$/.test(url.pathname)){requireValue(reads.size<64||reads.has(url.pathname),"browser-unavailable");reads.set(url.pathname,(reads.get(url.pathname)??0)+1);}
    });
    const {targetId}=await connection.send("Target.createTarget",{url:"about:blank"});
    const {sessionId}=await connection.send("Target.attachToTarget",{targetId,flatten:true});
    const send=(method,params,timeout)=>connection.send(method,params,sessionId,timeout);
    const evaluate=async expression=>{const result=await send("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true});requireValue(!result.exceptionDetails,"browser-unavailable");return result.result?.value;};
    await send("Page.enable",{});
    await send("Network.enable",{maxPostDataSize:1,maxTotalBufferSize:1048576,maxResourceBufferSize:1048576});
    await send("Page.addScriptToEvaluateOnNewDocument",{source:`(${installDiscoveryBrowserBoundary.toString()})(${JSON.stringify(c.publicOrigin)},${JSON.stringify(c.scope)})`});
    const cleanupChannel=createDiscoveryCleanupChannel(send,c);
    const ui=async(action,label,value)=>evaluate(`(()=>{const action=${JSON.stringify(action)},label=${JSON.stringify(label)},value=${JSON.stringify(value)};if(action==='text')return document.body.innerText.includes(label);if(action==='fill'){const l=[...document.querySelectorAll('label')].filter(x=>x.textContent.trim()===label);if(l.length!==1)return false;const i=l[0].control||l[0].querySelector('input');if(!i||i.disabled)return false;Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(i,value);i.dispatchEvent(new Event('input',{bubbles:true}));i.dispatchEvent(new Event('change',{bubbles:true}));return true;}const b=[...document.querySelectorAll('button,a')].filter(x=>(x.getAttribute('aria-label')===label||x.textContent.trim()===label)&&!x.disabled&&x.getClientRects().length);if(b.length!==1)return false;b[0].click();return true;})()`);
    return {close,sessionWitness:async()=>({...session}),navigate:async route=>{requireValue(/^\/(?:sign-in|connectors|discovery\/assets)(?:\?.*)?$/.test(route));await send("Page.navigate",{url:c.publicOrigin+route});},reload:()=>reloadBrowserPage({send}),
      click:label=>ui("click",label),fill:(label,value)=>ui("fill",label,value),text:label=>ui("text",label),
      get:(route,scope)=>evaluate(`window.__zaspCurrentDiscovery?.get(${JSON.stringify(route)},${JSON.stringify(scope)})`),
      mutation:(method,route)=>evaluate(`window.__zaspCurrentDiscovery?.mutation(${JSON.stringify(method)},${JSON.stringify(route)})`),
      replay:route=>evaluate(`window.__zaspCurrentDiscovery.replay(${JSON.stringify(route)})`),
      ...cleanupChannel,
      openSync:async(integration,sync)=>{
        requireValue(productID.test(integration)&&productID.test(sync));
        const route=`/api/v1/integrations/${integration}/syncs/${sync}`,before=reads.get(route)??0;
        const clicked=await evaluate(`(async()=>{const p=await window.__zaspCurrentDiscovery.get(${JSON.stringify(`/api/v1/integrations/${integration}/syncs?limit=100`)});if(p.status!==200||p.value.page_info.has_more)return false;const i=p.value.items.findIndex(v=>v.id===${JSON.stringify(sync)});const buttons=[...document.querySelectorAll('section[aria-label="Automatic discovery"] button[aria-label]')];if(i<0||buttons.length!==p.value.items.length||buttons[i].disabled)return false;buttons[i].click();return true;})()`);
        if(!clicked)return false;const end=Date.now()+10000;while(Date.now()<end){if((reads.get(route)??0)>before)return true;await delay(100);}return false;
      },
      leakFree:async()=>{if(!await evaluate("window.__zaspCurrentDiscovery?.leakFree()"))return false;const h=await send("Page.getNavigationHistory",{});return h.entries.every(e=>{try{const u=new URL(e.url);return ![...u.searchParams.keys()].some(k=>/^(access_token|refresh_token|provider_token|code_verifier)$/.test(k));}catch{return false;}});},
    };
  } catch(error){await close();throw error;}
}

async function providerCheckpoint(phase) {
  requireValue(["change","failure","restore"].includes(phase) && process.stdin.isTTY && process.stderr.isTTY,"external-checkpoint");
  const reader=createInterface({input:process.stdin,output:process.stderr});
  try {
    const answer=await reader.question(`Authorized provider ${phase} checkpoint. Complete ONLY the configured change for the fixed native identity, then type ${phase}; anything else stops: `,{signal:AbortSignal.timeout(15*60_000)});
    requireValue(answer===phase,"external-checkpoint");
  } catch {throw new PreflightError("external-checkpoint");} finally {reader.close();}
}

async function runCurrentObserver(c,mode,input,own) {
  const t=c.journey.temporal, handle=await open(t.executable,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try {const stat=await handle.stat();requireValue(stat.isFile()&&stat.size>0&&stat.size<=128*1024*1024&&(stat.mode&0o022)===0,"observer-unavailable");requireValue(sha(await handle.readFile())===t.sha256,"observer-unavailable");}finally{await handle.close();}
  const child=spawnOwnedCommand(t.executable,[mode],{env:{LANG:"C",LC_ALL:"C"},input:JSON.stringify(input),maxOutputBytes:16384});
  const release=own?.(child.stop),signals=own?{dispose(){}}:installBoundedSignalCleanup(child.stop,{timeout:8000});let timer;
  try {
    const result=await Promise.race([child.completed,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new PreflightError("observer-unavailable")),10000);})]);
    requireValue(result.status===0&&result.signal===null&&!result.outputLimitExceeded&&!result.stderr,"observer-unavailable");
    return JSON.parse(result.stdout);
  } catch {throw new PreflightError("observer-unavailable");}finally{clearTimeout(timer);try{await child.stop();}finally{release?.();signals.dispose();}}
}

async function validateCurrentRuntime(c) {
  const result=await runCurrentObserver(c,"--validate-config",{format:"zasp-discovery-config-validation-v1",config:c.journey.temporal.config});
  exact(result,["format","valid"],"observation-invalid");requireValue(result.format==="zasp-discovery-config-validation-v1"&&result.valid===true,"config-invalid");return true;
}

async function observeCurrentTemporal(c,q,own) {
  const result=await runCurrentObserver(c,"--observe",{format:"zasp-discovery-observation-request-v1",config:c.journey.temporal.config,...q},own);
  exact(result,["format","kind","schedule_id","revision","task_queue","paused","executions","status"],"observation-invalid");
  requireValue(result.format==="zasp-discovery-observation-v1"&&result.kind===q.kind&&result.revision===q.revision&&result.task_queue===c.journey.temporal.config.DiscoveryTaskQueue,"evidence-mismatch");return result;
}

function checkedMutation(r,statuses) {
  requireValue(r&&statuses.includes(r.status)&&r.noStore===true&&productID.test(r.auditID)&&productID.test(r.receiptID)&&/^"[1-9][0-9]*"$/.test(r.version),"public-refusal");return r;
}
function successfulSync(r,integrationID) {
  requireValue(r?.status===200&&r.noStore===true&&r.value?.integration_id===integrationID,"public-refusal");
  return r.value;
}
function targetInventory(v,metadata) {
  requireValue(Array.isArray(v?.target)&&v.target.length===1&&productID.test(v.target[0].id)&&v.target[0].source_state==="present"&&v.target[0].metadata===metadata&&typeof v.unrelated_digest==="string","evidence-mismatch");return v.target[0];
}

// Called only after the new integration's scoped creation receipt is proven.
// Each mutation uses the current public ETag and a fresh scoped session. Never
// restore a provider, write owner SQL, retry conflicts or delete an unknown ID.
async function cleanupCurrentResources(c,browser,integrationID,restoreRequired,receipt) {
  const outcome={scheduleDeleted:false,integrationDeleted:false,integrationRetained:true,providerRestoreRequired:restoreRequired,complete:false,recovery:"retry-owned-resource-cleanup"};
  const end=Date.now()+90_000;
  const step=async fn=>{requireValue(Date.now()+20_000<=end,"cleanup-incomplete");return fn();};
  const read=route=>step(()=>browser.cleanupRead({scope:c.scope,integrationID,resource:route.endsWith("/schedule")?"schedule":"integration"}));
  const mutate=async(action,version,statuses)=>{
    const r=checkedMutation(await step(()=>browser.cleanupMutation({action,scope:c.scope,integrationID,version})),statuses);
    requireValue(Number(r.version.slice(1,-1))===Number(version.slice(1,-1))+1,"cleanup-incomplete");
    await step(()=>receipt(r));return r;
  };
  const route=`/api/v1/integrations/${integrationID}`;
  try {
    const integration=await read(route);
    if(integration.status===404&&integration.noStore){outcome.integrationDeleted=true;outcome.integrationRetained=false;outcome.scheduleDeleted=true;outcome.complete=!restoreRequired;outcome.recovery=restoreRequired?"restore-provider":"none";return outcome;}
    requireValue(integration.status===200&&integration.noStore&&integration.value?.id===integrationID&&integration.value.name===c.journey.integrationName&&integration.value.connector_key===c.provider.kind,"cleanup-incomplete");
    let schedule=await read(`${route}/schedule`);
    if(schedule.status===404&&schedule.noStore)outcome.scheduleDeleted=true;
    else {
      requireValue(schedule.status===200&&schedule.noStore&&schedule.value?.integration_id===integrationID&&schedule.value.cadence_seconds===300&&schedule.version===`"${schedule.value.version}"`&&["enabled","disabled"].includes(schedule.value.state),"cleanup-incomplete");
      if(schedule.value.state==="enabled"){
        const disabled=await mutate("disable-schedule",schedule.version,[200]);
        requireValue(disabled.value?.integration_id===integrationID&&disabled.value.state==="disabled"&&disabled.value.cadence_seconds===300,"cleanup-incomplete");
        schedule=await read(`${route}/schedule`);requireValue(schedule.status===200&&schedule.noStore&&schedule.value?.state==="disabled"&&schedule.value.integration_id===integrationID&&schedule.version===disabled.version,"cleanup-incomplete");
      }
      await mutate("delete-schedule",schedule.version,[204]);
      const absent=await read(`${route}/schedule`);requireValue(absent.status===404&&absent.noStore,"cleanup-incomplete");outcome.scheduleDeleted=true;
    }
    // Preserve the authorized connector needed for a real restoration sync.
    if(restoreRequired){outcome.recovery="restore-provider-confirm-sync-then-delete-owned-integration";return outcome;}
    const current=await read(route);requireValue(current.status===200&&current.noStore&&current.value?.id===integrationID&&current.value.name===c.journey.integrationName&&current.value.connector_key===c.provider.kind,"cleanup-incomplete");
    const deleted=await mutate("delete-integration",current.version,[202,204]);
    if(deleted.status!==204)return outcome;
    const absent=await read(route);requireValue(absent.status===404&&absent.noStore,"cleanup-incomplete");
    outcome.integrationDeleted=true;outcome.integrationRetained=false;outcome.complete=true;outcome.recovery="none";
  }catch{outcome.refused=true;}
  return outcome;
}

// All adapters below are actual product/browser/read-only observer paths in the
// command entry. The narrow dependency seam permits cheap refusal/order tests;
// it is never populated from environment, config or a success fixture file.
export async function runCurrentDiscoveryJourney(config, dependencies={}) {
  const c=validateCurrentDiscoveryConfig(config);
  const preflight=await runCurrentDiscoveryPreflight(c,{query:dependencies.query??queryDatabase});
  if(preflight.code==="runtime-closed"||!c.journey)return preflight;
  try{requireValue(await (dependencies.validateRuntime??validateCurrentRuntime)(c)===true,"config-invalid");}catch{return {phase:"runtime-config",code:"config-invalid",journey:"not-run",observedLogins:6};}
  try {
    const authority=await (dependencies.readAuthority??(()=>executeProbe(currentDiscoveryAuthorityProbe(c))))();
    exact(authority,["model_bound","verifiers_bound","desired","applied","generation"],"observation-invalid");
    requireValue(authority.model_bound===true&&authority.verifiers_bound===true&&[authority.desired,authority.applied,authority.generation].every(v=>Number.isSafeInteger(v)&&v>0)&&authority.desired===authority.applied,"profile-mismatch");
  } catch(error) {return {phase:"authority-preflight",code:currentDiscoveryFailureCode(error),journey:"not-run",observedLogins:6};}
  let phase="browser",browser,integrationID,ids,integrationOwned=false,providerChanged=false,providerRestored=false,scheduleDeleted=false,result;
  const facts={receipts:[],snapshots:[],logicalProviderPages:0,artifactCommits:0};
  const started=Date.now(),deadline=started+90*60_000,resources=new Set();
  const own=close=>{resources.add(close);return()=>resources.delete(close);};
  const cleanup=async()=>{const done=await Promise.allSettled([...resources].map(close=>close()));requireValue(done.every(v=>v.status==="fulfilled"),"cleanup-incomplete");};
  const signals=installBoundedSignalCleanup(cleanup,{timeout:20000});
  const progress=setInterval(()=>console.error(`current discovery: phase=${phase} elapsed_seconds=${Math.floor((Date.now()-started)/1000)}`),30000);
  const wait=async(action,budget=10_000)=>{const end=Math.min(deadline,Date.now()+budget);while(Date.now()<end){const value=await action();if(value)return value;await delay(500);}throw new PreflightError("journey-deadline");};
  const db=async kind=>{const value=await (dependencies.readState??((kind,ids)=>executeProbe(currentDiscoveryStateProbe(c,kind,ids),own)))(kind,ids);requireValue(value&&typeof value==="object","observation-invalid");return value;};
  const temporal=q=>(dependencies.observeTemporal??((q)=>observeCurrentTemporal(c,q,own)))(q);
  const checkpoint=dependencies.checkpoint??providerCheckpoint;
  const get=async route=>{const r=await browser.get(route);requireValue(r?.status===200&&r.noStore===true,"public-refusal");return r.value;};
  const click=label=>wait(()=>browser.click(label));
  const mutation=(method,route,statuses)=>wait(async()=>{const r=await browser.mutation(method,route);return r?checkedMutation(r,statuses):null;});
  const receipt=async r=>{ids={...ids,receiptID:r.receiptID,auditID:r.auditID};requireValue((await db("receipt")).bound===true,"evidence-mismatch");requireValue(facts.receipts.length<16,"observation-invalid");facts.receipts.push({phase,receiptID:r.receiptID,auditID:r.auditID});};
  const openIntegration=async()=>{await browser.navigate("/connectors");await click(`Open ${c.journey.integrationName}`);};
  const terminalSync=syncID=>wait(async()=>{const v=successfulSync(await browser.get(`/api/v1/integrations/${integrationID}/syncs/${syncID}`),integrationID);requireValue(v.id===syncID,"evidence-mismatch");return ["succeeded","failed","partial","cancelled"].includes(v.status)?v:null;},30*60_000);
  const committed=async sync=>{
    requireValue(sync.status==="succeeded"&&productID.test(sync.snapshot_id),"evidence-mismatch");
    const s=await db("state"),runs=s.runs.filter(r=>r.sync_id===sync.id),snapshots=s.snapshots.filter(v=>v.id===sync.snapshot_id&&v.sync_id===sync.id);
    requireValue(runs.length===1&&runs[0].state==="succeeded"&&runs[0].outbox_published===true&&runs[0].page_effects>0&&runs[0].apply_commits===1&&snapshots.length===1&&snapshots[0].complete===true&&snapshots[0].state==="complete"&&snapshots[0].is_last_good===true&&snapshots[0].committed_at&&typeof snapshots[0].manifest_version==="string"&&snapshots[0].manifest_version.length>0&&digest.test(snapshots[0].manifest_sha256),"evidence-mismatch");
    facts.snapshots.push({syncID:sync.id,snapshotID:sync.snapshot_id,manifestSHA256:snapshots[0].manifest_sha256});facts.logicalProviderPages+=runs[0].page_effects;facts.artifactCommits++;
    return {state:s,run:runs[0],snapshot:snapshots[0]};
  };
  try {
    browser=await (dependencies.createBrowser??createCurrentBrowser)(c,own);own(browser.close);
    phase="sign-in";await browser.navigate("/sign-in?return_to=%2Fconnectors");await click("Continue to sign in");
    const session=await wait(async()=>{const r=await browser.get("/api/v1/session/bootstrap");if(!r||r.status===401)return null;requireValue(r.status===200&&r.noStore===true,"public-refusal");return r.value;},15*60_000);
    requireValue(session.organization_id===c.scope.organizationID&&session.workspace_id===c.scope.workspaceID&&session.environment_id===c.scope.environmentID&&Date.parse(session.fresh_auth_expires_at)>Date.now(),"principal-unavailable");
    const witness=await browser.sessionWitness();requireValue(witness.start===true&&witness.callback===true&&witness.bootstrap===true,"evidence-mismatch");
    phase="integration-create";await browser.navigate("/connectors");
    const catalog=await wait(async()=>{const r=await browser.get("/api/v1/integration-catalog");return r?.status===200?r.value:null;});
    const entries=catalog.items.filter(v=>v.key===c.provider.kind);requireValue(entries.length===1&&Array.isArray(entries[0].setup_schema),"evidence-mismatch");
    const manifest=entries[0];requireValue(Object.keys(c.journey.configuration).every(k=>manifest.setup_schema.some(f=>f.key===k)),"config-invalid");
    await click(`Configure ${manifest.provider}`);requireValue(await browser.fill("Integration name",c.journey.integrationName),"browser-unavailable");
    for(const field of manifest.setup_schema){const value=c.journey.configuration[field.key];if(field.required)requireValue(value,"config-invalid");if(value!==undefined){if(field.type==="secret_reference")requireValue(value===c.provider.protectedReference,"config-invalid");requireValue(await browser.fill(field.label,value),"browser-unavailable");}}
    await click("Save integration");const created=await mutation("POST","/api/v1/integrations",[200,201]);integrationID=created.value?.id;requireValue(productID.test(integrationID)&&created.value.connector_key===c.provider.kind,"evidence-mismatch");
    ids={integrationID,syncID:integrationID,receiptID:created.receiptID,auditID:created.auditID};await receipt(created);integrationOwned=true;
    browser.bindOwnedIntegration(integrationID);
    phase="integration-authorize";await openIntegration();await click("Authorize Kubernetes reference");await receipt(await mutation("POST",`/api/v1/integrations/${integrationID}/reference-authorization`,[200]));
    const setup=await get(`/api/v1/integrations/${integrationID}/setup-status`);requireValue(setup.integration_id===integrationID&&setup.connector_key===c.provider.kind&&setup.authorization?.state==="verified","evidence-mismatch");
    phase="manual-sync";await click("Sync inventory now");const queued=await mutation("POST",`/api/v1/integrations/${integrationID}/sync`,[202]);ids.syncID=queued.value?.id;requireValue(productID.test(ids.syncID)&&queued.value.trigger_kind==="manual","evidence-mismatch");await receipt(queued);
    const baselineSync=await terminalSync(ids.syncID),baseline=await committed(baselineSync),before=await db("inventory"),first=targetInventory(before,c.journey.source.before);
    requireValue(baseline.run.schedule_id===null&&first.snapshot_id===baselineSync.snapshot_id,"evidence-mismatch");
    const baselineAgents=await readCurrentAgentIDs(get);requireValue(baselineAgents.includes(first.id),"evidence-mismatch");
    phase="schedule-create";requireValue(await browser.fill("Automatic sync cadence seconds","300"),"browser-unavailable");await click("Save automatic sync");const saved=await mutation("PUT",`/api/v1/integrations/${integrationID}/schedule`,[200]);await receipt(saved);
    const desired=await db("state");requireValue(desired.schedules.length===1,"evidence-mismatch");const schedule=desired.schedules[0],due=Date.parse(schedule.next_run_at);
    requireValue(schedule.state==="enabled"&&schedule.cadence_seconds===300&&due>Date.parse(desired.database_now)&&Date.parse(saved.value.next_run_at)===due,"evidence-mismatch");
    const replay=checkedMutation(await browser.replay(`/api/v1/integrations/${integrationID}/schedule`),[200]);requireValue(replay.receiptID===saved.receiptID&&replay.auditID===saved.auditID&&replay.version===saved.version&&replay.value.next_run_at===saved.value.next_run_at&&(await db("state")).schedules[0].next_run_at===schedule.next_run_at,"evidence-mismatch");
    const ref={organization_id:c.scope.organizationID,workspace_id:c.scope.workspaceID,environment_id:c.scope.environmentID,schedule_id:schedule.id,integration_id:integrationID};
    phase="schedule-projection";await wait(async()=>{const s=(await db("state")).schedules[0];if(s.delivered_revision!==schedule.version)return false;const t=await temporal({kind:"schedule",ref,revision:schedule.version,workflow_id:"",run_id:""});return !t.paused;},5*60_000);
    phase="provider-change";providerChanged=true;await checkpoint("change");
    phase="scheduled-sync";const scheduled=await wait(async()=>{const s=await db("state"),runs=s.runs.filter(v=>v.schedule_id===schedule.id&&Date.parse(v.scheduled_for)===due);requireValue(runs.length<=1,"evidence-mismatch");return runs.length===1&&runs[0].state==="succeeded"?runs[0]:null;},30*60_000);
    requireValue(Date.parse(scheduled.admitted_at)>=due,"evidence-mismatch");ids.syncID=scheduled.sync_id;
    const updatedSync=await terminalSync(scheduled.sync_id);requireValue(updatedSync.trigger_kind==="schedule","evidence-mismatch");await committed(updatedSync);const after=await db("inventory"),second=targetInventory(after,c.journey.source.after);
    requireValue(second.id===first.id&&second.snapshot_id===updatedSync.snapshot_id&&second.snapshot_id!==first.snapshot_id&&Date.parse(second.last_seen_at)>Date.parse(first.last_seen_at)&&after.unrelated_digest===before.unrelated_digest,"evidence-mismatch");
    const projected=await temporal({kind:"schedule",ref,revision:schedule.version,workflow_id:"",run_id:""});
    const executions=projected.executions.filter(v=>Date.parse(v.scheduled_at)>=due&&Date.parse(v.scheduled_at)<due+300000);requireValue(executions.length===1,"evidence-mismatch");
    const occurrence=await temporal({kind:"occurrence",ref,revision:schedule.version,workflow_id:executions[0].workflow_id,run_id:executions[0].run_id});requireValue(occurrence.status===2&&occurrence.executions.length===1&&occurrence.executions[0].scheduled_at===executions[0].scheduled_at,"evidence-mismatch");
    phase="mounted-refresh";await browser.navigate("/discovery/assets");await browser.reload();await click(`Open ${second.display_name}`);requireValue(await browser.text(second.id),"evidence-mismatch");
    requireValue(JSON.stringify(await readCurrentAgentIDs(get))===JSON.stringify(baselineAgents),"evidence-mismatch");
    const agent=await get(`/api/v1/agents/${second.id}`);requireValue(agent.summary?.id===second.id&&Array.isArray(agent.sources)&&Array.isArray(agent.evidence),"evidence-mismatch");
    const boundSources=agent.sources.filter(s=>s.integration_id===integrationID&&s.provider===c.provider.kind&&s.snapshot_id===updatedSync.snapshot_id);
    requireValue(boundSources.length===1&&productID.test(boundSources[0].evidence_id)&&agent.evidence.some(e=>e.id===boundSources[0].evidence_id),"evidence-mismatch");
    const foreign=await browser.get(`/api/v1/agents/${second.id}`,Object.values(c.journey.foreignScope).join("/"));requireValue([403,404,409].includes(foreign.status),"evidence-mismatch");
    await openIntegration();await wait(async()=>{const f=await get(`/api/v1/integrations/${integrationID}/freshness`);requireValue(f.last_good?.snapshot_id===updatedSync.snapshot_id,"evidence-mismatch");return ["risk","graph","search"].every(k=>f.projections?.[k]?.state==="current"&&f.projections[k].snapshot_id===updatedSync.snapshot_id);},10*60_000);
    await openIntegration();await wait(async()=>await browser.text("Risk projection: current")&&await browser.text("Graph projection: current")&&await browser.text("Search projection: current"));
    requireValue(await browser.openSync(integrationID,updatedSync.id)&&await browser.text("Sync detail: succeeded"),"evidence-mismatch");
    phase="provider-failure";await checkpoint("failure");await click("Sync inventory now");const failedQueued=await mutation("POST",`/api/v1/integrations/${integrationID}/sync`,[202]);ids.syncID=failedQueued.value.id;await receipt(failedQueued);const failed=await terminalSync(ids.syncID);requireValue(["failed","partial"].includes(failed.status),"evidence-mismatch");
    const retained=targetInventory(await db("inventory"),c.journey.source.after),freshness=await get(`/api/v1/integrations/${integrationID}/freshness`);requireValue(retained.id===second.id&&retained.snapshot_id===second.snapshot_id&&freshness.last_good?.snapshot_id===updatedSync.snapshot_id&&freshness.latest_sync?.id===failed.id&&freshness.latest_sync.status===failed.status,"evidence-mismatch");
    await openIntegration();requireValue(await browser.openSync(integrationID,failed.id)&&await browser.text(`Sync detail: ${failed.status}`)&&await browser.text("Last good inventory:"),"evidence-mismatch");
    phase="schedule-withdrawal";const priorWithdrawal=await db("state"),withdrawDue=Date.parse(priorWithdrawal.schedules[0].next_run_at),occurrences=priorWithdrawal.runs.filter(v=>v.schedule_id===schedule.id).length;
    await click("Disable automatic sync");await receipt(await mutation("PUT",`/api/v1/integrations/${integrationID}/schedule`,[200]));await click("Delete automatic sync");await receipt(await mutation("DELETE",`/api/v1/integrations/${integrationID}/schedule`,[204]));scheduleDeleted=true;
    await wait(async()=>{const s=await db("state");requireValue(s.runs.filter(v=>v.schedule_id===schedule.id).length===occurrences&&s.schedules[0].state==="deleted","evidence-mismatch");return Date.parse(s.database_now)>withdrawDue+1000;},6*60_000);
    phase="provider-restore";await checkpoint("restore");
    // Restoration acknowledgment is not independently observed restoration.
    // One actual public manual sync must re-produce the configured baseline.
    await click("Sync inventory now");const restoredQueued=await mutation("POST",`/api/v1/integrations/${integrationID}/sync`,[202]);ids.syncID=restoredQueued.value.id;await receipt(restoredQueued);const restoredSync=await terminalSync(ids.syncID);await committed(restoredSync);requireValue(targetInventory(await db("inventory"),c.journey.source.before).id===first.id,"evidence-mismatch");providerRestored=true;
    phase="owned-integration-cleanup";await click("Delete integration");const deletion=await mutation("DELETE",`/api/v1/integrations/${integrationID}`,[204]);await receipt(deletion);requireValue((await browser.get(`/api/v1/integrations/${integrationID}`)).status===404,"evidence-mismatch");
    phase="evidence";requireValue(await browser.leakFree(),"evidence-mismatch");
    result={phase:"complete",code:"journey-complete",journey:"passed",observedLogins:6,manualBaseline:true,scheduledOccurrence:true,stableAgent:true,lastGoodRetained:true,scheduleWithdrawn:true,providerRestored:true};
  }catch(error){
    result={phase,code:currentDiscoveryFailureCode(error),journey:"failed",observedLogins:6,ownedIntegrationCreated:integrationOwned,scheduleDeleted,providerRestoreRequired:providerChanged&&!providerRestored,...(integrationID?{ownedIntegrationID:integrationID}:{})};
    if(integrationOwned&&browser){const ownedCleanup=await cleanupCurrentResources(c,browser,integrationID,result.providerRestoreRequired,receipt);result={...result,ownedCleanup,scheduleDeleted:ownedCleanup.scheduleDeleted};}
  }
  finally{clearInterval(progress);try{await cleanup();}catch{result={...result,journey:"failed",code:"cleanup-incomplete"};}signals.dispose();}
  return {...result,elapsedSeconds:Math.floor((Date.now()-started)/1000),facts};
}

function assertIdentity(observation, expected) {
  requireValue(observation.session_user === expected && observation.current_user === expected && observation.read_only === true, "principal-unavailable");
}

export async function runCurrentDiscoveryPreflight(config, { query = queryDatabase } = {}) {
  const c = validateCurrentDiscoveryConfig(config);
  const first = await query(c, "observer");
  exact(first, ["session_user", "current_user", "read_only", "scope_exists", "canonical_count", "canonical_checksum", "worker_checksum", "catalog_ready", "runtime_ready"], "observation-invalid");
  assertIdentity(first, c.database.connections.observer.login);
  requireValue(first.scope_exists === true && first.canonical_count === 61 && first.canonical_checksum === c.canonical61Checksum && first.worker_checksum === c.workerChecksum && first.catalog_ready === true, "profile-mismatch");
  requireValue(typeof first.runtime_ready === "boolean", "observation-invalid");
  if (!first.runtime_ready) return { phase: "runtime-gate", code: "runtime-closed", journey: "not-run", observedLogins: 1 };
  for (const role of roles.slice(1)) {
    const observation = await query(c, role);
    exact(observation, ["session_user", "current_user", "read_only", "registered", "login_role", "superuser"], "observation-invalid");
    assertIdentity(observation, c.database.connections[role].login);
    requireValue(observation.registered === true && observation.login_role === true && observation.superuser === false, "principal-unavailable");
  }
  // This is an explicit partial Batch2 boundary, not a placeholder success.
  // Live FGA/verifier/schedule evidence and the public/browser producer must
  // be connected and reviewed before this branch may launch the journey.
  return { phase: "preflight", code: "journey-not-implemented", journey: "not-run", observedLogins: 6 };
}

async function readConfig(file) {
  requireValue(absolute(file));
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    requireValue(stat.isFile() && stat.size > 0 && stat.size <= 16_384 && (stat.mode & 0o022) === 0);
    const buffer = Buffer.alloc(16_385);
    let length = 0;
    while (length < buffer.length) {
      const read = await handle.read(buffer, length, buffer.length - length, null);
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
    }
    requireValue(length > 0 && length <= 16_384);
    const bytes = buffer.subarray(0, length);
    return { config: validateCurrentDiscoveryConfig(JSON.parse(bytes)), hash: sha(bytes) };
  } catch { throw new PreflightError("config-unavailable"); }
  finally { await handle?.close(); }
}

export async function runCurrentDiscoveryMode(env) {
  requireValue(validateCurrentDiscoveryMode(env), "mode-invalid");
  requireValue(process.version === "v22.23.1", "config-invalid");
  const { config, hash } = await readConfig(env.ZASP_CURRENT_DISCOVERY_CONFIG);
  const sourcePaths=["discovery-current-composition.mjs","production-combined-e2e.mjs","owned-command.mjs","bounded-signal-cleanup.mjs","browser-e2e-helpers.mjs"];
  const sourceDigests=async()=>Object.fromEntries(await Promise.all(sourcePaths.map(async name=>[name,sha(await readFile(new URL(name,import.meta.url)))])));
  const sourcesBefore=await sourceDigests();
  let evidence;
  try {
    requireValue(await realpath(config.evidenceDirectory) === config.evidenceDirectory, "evidence-unavailable");
    evidence = await open(path.join(config.evidenceDirectory, config.journey?"current-discovery-journey.json":"current-discovery-preflight.json"), "wx", 0o600);
  } catch { throw new PreflightError("evidence-unavailable"); }
  try {
    let result;
    try { result = config.journey?await runCurrentDiscoveryJourney(config):await runCurrentDiscoveryPreflight(config); }
    catch (error) { result = { phase: "preflight", code: currentDiscoveryFailureCode(error), journey: "not-run" }; }
    let stable=false;
    try {stable=(await readConfig(env.ZASP_CURRENT_DISCOVERY_CONFIG)).hash===hash&&JSON.stringify(await sourceDigests())===JSON.stringify(sourcesBefore);}catch{/* Failed reads retain false: never certify unstable evidence. */}
    if(!stable)result={...result,code:"evidence-mismatch",journey:"failed",phase:"source-integrity"};
    // Receipt/snapshot IDs are private run evidence, not credential material.
    // No origin, service names/paths, provider references, raw SQL, raw errors,
    // session payloads or provider bodies are persisted.
    const integrity=config.journey?{sourcesSHA256:sourcesBefore,sourceStable:stable,observerSHA256:config.journey.temporal.sha256}:{};
    await evidence.writeFile(`${JSON.stringify({ format: config.journey?"zasp-current-discovery-journey-evidence-v1":"zasp-current-discovery-preflight-evidence-v1", configSHA256: hash, sourceSHA256: sourcesBefore["discovery-current-composition.mjs"],...integrity, ...result })}\n`);
    await evidence.sync();
    return result;
  } finally { await evidence.close(); }
}
