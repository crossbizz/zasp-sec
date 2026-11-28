import {setTimeout as delay}from 'node:timers/promises';
export class OwnedProjectionCleanupIncomplete extends Error {constructor(){super('owned projection cleanup incomplete');}}
const refusal=()=>{throw Error('owned current authorization fixture unavailable');};
const fields=['organization_id','desired','applied','generation','store_id','model_id'];
const canonicalID=value=>typeof value==='string'&&/^pid_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const absolute=value=>typeof value==='string'&&/^\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/.test(value)&&!value.split('/').includes('..');
const closed=value=>Object.fromEntries(Object.entries(value).filter(([key])=>!key.startsWith('ZASP_')));
export const closedOwnedAmbientEnvironment=closed;
function revision(value,organization,environment, requireApplied = true){if(!value||Object.keys(value).length!==fields.length||!fields.every(key=>Object.hasOwn(value,key))||value.organization_id!==organization||value.store_id!==environment.ZASP_OPENFGA_STORE_ID||value.model_id!==environment.ZASP_OPENFGA_MODEL_ID||![value.desired,value.applied,value.generation].every(Number.isSafeInteger)||value.desired<1||value.generation<1||value.applied<0||value.applied>value.desired||requireApplied&&value.desired!==value.applied)refusal();return value;}

// Existing commands remain the only installer, verifier and projection writers.
// Call this after the independently retained legacy56 controls, before either
// current API lifetime. No registration or acknowledgement SQL is manufactured.
export async function installOwnedCurrent80({command,migrate,reconcile,psql,port,organization,foreignOrganization,identityEnvironment,runtimeEnvironment,keyFiles,seedCurrent}){
 if(typeof command!=='function'||typeof seedCurrent!=='function'||![migrate,reconcile,psql].every(absolute)||!Number.isSafeInteger(port)||port<1024||port>65535||!canonicalID(organization)||!identityEnvironment||!runtimeEnvironment||runtimeEnvironment.ZASP_RUNTIME_SERVICES_ENABLED!=='true'||runtimeEnvironment.ZASP_ENVIRONMENT!=='test'||!keyFiles||![keyFiles.forward,keyFiles.compensation,keyFiles.approval].every(absolute)||new Set([keyFiles.forward,keyFiles.compensation,keyFiles.approval]).size!==3)refusal();
  const runtimeKeys=['ZASP_RUNTIME_SERVICES_ENABLED','ZASP_ENVIRONMENT','ZASP_RUNTIME_SERVICES_TIMEOUT','ZASP_TEMPORAL_ADDRESS','ZASP_TEMPORAL_NAMESPACE','ZASP_TEMPORAL_TASK_QUEUE','ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE','ZASP_OPENFGA_URL','ZASP_OPENFGA_STORE_ID','ZASP_OPENFGA_MODEL_ID','ZASP_OPENFGA_TOKEN_FILE'];
 if(Object.keys(runtimeEnvironment).length!==runtimeKeys.length||runtimeKeys.some(key=>typeof runtimeEnvironment[key]!=='string')||!/^127\.0\.0\.1:[0-9]{4,5}$/.test(runtimeEnvironment.ZASP_TEMPORAL_ADDRESS)||!/^http:\/\/127\.0\.0\.1:[0-9]{4,5}$/.test(runtimeEnvironment.ZASP_OPENFGA_URL)||![runtimeEnvironment.ZASP_OPENFGA_STORE_ID,runtimeEnvironment.ZASP_OPENFGA_MODEL_ID].every(value=>/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(value))||!absolute(runtimeEnvironment.ZASP_OPENFGA_TOKEN_FILE))refusal();
const required=['ZASP_PUBLIC_ORIGIN','ZASP_STYTCH_BASE_URL','ZASP_STYTCH_PROJECT_ID','ZASP_STYTCH_ORGANIZATION_ID','ZASP_DEPLOYMENT_MODE','ZASP_ORGANIZATION_ID','ZASP_WORKFLOW_SIGNING_KEY'];
 if(required.some(key=>typeof identityEnvironment[key]!=='string')||identityEnvironment.ZASP_DEPLOYMENT_MODE!=='saas'||identityEnvironment.ZASP_ORGANIZATION_ID!==''||!identityEnvironment.ZASP_PUBLIC_ORIGIN||!identityEnvironment.ZASP_STYTCH_BASE_URL||!identityEnvironment.ZASP_WORKFLOW_SIGNING_KEY)refusal();
 const organizations = foreignOrganization === undefined ? [organization] : [organization, foreignOrganization];
 if (!organizations.every(canonicalID) || new Set(organizations).size !== organizations.length) refusal();
 const dsn = user => `postgres://${user}@127.0.0.1:${port}/postgres?sslmode=disable`;
 const ambient = closed(identityEnvironment);
 const operatorDSN = dsn('zasp_operator');
 const apiDSN = dsn('zasp_svc_api');
 const runSQL = async (connection, statement) => {
  const result = await command(psql, [connection, '-X', '-v', 'ON_ERROR_STOP=1', '-qAt', '-c', statement], {env: ambient, timeout: 30000});
  if (result.status !== 0 || result.signal) refusal();
  return result.stdout;
 };
 const migrateOnce = async (action, environment) => {
  const result = await command(migrate, [action], {env: environment, timeout: 300000});
  if (result.status !== 0 || result.signal) refusal();
  return result.stdout;
 };
 // The disposable cluster starts with zasp_e2e as its bootstrap superuser.
 // The published installer runs as its own restricted database owner.
 await runSQL(dsn('zasp_e2e'), 'CREATE ROLE zasp_operator LOGIN CREATEROLE BYPASSRLS NOSUPERUSER NOCREATEDB NOREPLICATION; ALTER DATABASE postgres OWNER TO zasp_operator');
 const migration = {...ambient, ZASP_POSTGRES_DSN: operatorDSN, ZASP_MIGRATION_DB_PRINCIPAL: 'zasp_operator',
  ZASP_DISCOVERY_API_DB_PRINCIPAL: 'zasp_svc_api', ZASP_MIGRATION_TIMEOUT: '5m'};
 await migrateOnce('install-baseline', migration);
 const pinOutput = await migrateOnce('approval-maintenance-checksum', ambient);
 if (typeof pinOutput !== 'string' || pinOutput.length !== 65 || !/^[0-9a-f]{64}\n$/.test(pinOutput)) refusal();
 const checksum = pinOutput.trimEnd();
 const environment = {...runtimeEnvironment, ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM: checksum};
 await migrateOnce('register-authorization-verifier', {...migration, ZASP_WORKFLOW_SIGNING_KEY: identityEnvironment.ZASP_WORKFLOW_SIGNING_KEY});
 await migrateOnce('register-worker-authorization-verifier', {...migration, ZASP_AUTHORIZATION_WORKER_KEY_FILE: keyFiles.forward});
 await migrateOnce('register-compensation-authorization-verifier', {...migration, ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE: keyFiles.compensation});
 await migrateOnce('register-approval-maintenance-verifier', {...migration, ZASP_APPROVAL_MAINTENANCE_KEY_FILE: keyFiles.approval});
 await seedCurrent(operatorDSN);
 const identity = {...migration, ...Object.fromEntries(required.map(key => [key, identityEnvironment[key]]))};
 await migrateOnce('register-identity-session-verifier', identity);
 await migrateOnce('register-identity-webhook-verifier', identity);
 await migrateOnce('verify-baseline', migration);
 const projector = {...ambient, ...environment};
 for (const id of organizations) {
  const configure = await command(reconcile, ['-mode', 'configure', '-organization', id, '-timeout', '2m'],
   {env: {...projector, ZASP_POSTGRES_DSN: operatorDSN}, timeout: 125000});
  if (configure.status !== 0 || configure.signal) refusal();
  const active = await runSQL(operatorDSN, `SELECT zasp_approval_maintenance.activate_projection('${id}')`);
  if (active !== 't\n') refusal();
 }
 const delivery = {...projector, ZASP_POSTGRES_DSN: dsn('zasp_svc_outbox')};
 const readRevisions = async (ids, signal) => {
  // The list contains only the strict canonical fixture IDs checked above.
  const rows = ids.map(id => "('" + id + "')").join(",");
  const sql = `WITH state AS MATERIALIZED (SELECT id,zasp_authorization79.revision(id) r FROM (VALUES ${rows}) AS owned(id)) SELECT jsonb_build_object('organization_id',r->'organization_id','desired',r->'desired','applied',r->'applied','generation',r->'generation','store_id',r->'store_id','model_id',r->'model_id') FROM state ORDER BY id`;
  const result = await command(psql,[apiDSN,'-X','-v','ON_ERROR_STOP=1','-At','-c',sql],{env:ambient,timeout:5000,signal});
  const observed = new Map();
  for (const value of outputRecords(result)) {
   const id = value?.organization_id;
   if (!ids.includes(id) || observed.has(id)) refusal();
   observed.set(id,revision(value,id,runtimeEnvironment,false));
  }
  if (observed.size !== ids.length) refusal();
  return observed;
 };
 const reconcilePass = async (target, signal) => {
  const selection = target ? ['-organization',target,'-limit','1'] : ['-limit','20'];
  const args = ['-mode','reconcile',...selection,'-timeout','2m'];
  const deadline = performance.now() + 125000;
  const receipts = new Map();
  const outstanding = new Set();
  // A single native pass can apply one organization while another changes
  // during delivery. Retry only named contention outcomes within one budget.
  for (let attempt = 0; attempt < 4; attempt++) {
   const timeout = Math.ceil(deadline - performance.now());
   if (timeout <= 0) refusal();
   signal?.throwIfAborted();
   const result = await command(reconcile,args,{env:delivery,timeout,signal,reject:Boolean(target)});
   const retryExit = !target && result.status === 1;
   const seen = new Set();
   let contended = false;
   for (const row of outputRecords(result, retryExit)) {
    const id = row?.organization_id;
    if (!organizations.includes(id) || target && id !== target || seen.has(id)) refusal();
    seen.add(id);
    if (retryExit && ['busy','retry_from_current_state'].includes(row.status) && row.receipt?.Applied === false) {
     receipts.delete(id);
     outstanding.add(id);
     contended = true;
     continue;
    }
    if (row.status !== 'applied' || row.receipt?.Applied !== true ||
        !Number.isSafeInteger(row.receipt.TupleCount) || row.receipt.TupleCount < 0) refusal();
    receipts.set(id,revision(row.receipt.Revision,id,runtimeEnvironment));
    outstanding.delete(id);
   }
   if (retryExit !== contended) refusal();
   if (!contended) {
    if (outstanding.size) refusal();
    return receipts;
   }
   if (attempt < 3) await delay(100 * 2 ** attempt,undefined,{signal});
  }
  refusal();
 };
 function outputRecords(result, retryExit=false) {
  if ((!retryExit && result.status!==0) || result.signal || typeof result.stdout!=='string' || result.stdout.length>65536) refusal();
  const data = result.stdout.trimEnd();
  if (!data) return [];
  try { return data.split(/\r?\n/).map(line=>JSON.parse(line)); } catch { refusal(); }
 }
 const pass = async (signal, target) => {
  if (signal?.aborted) throw Error('owned projection canceled');
  const receipts = await reconcilePass(target,signal);
  const observed = (await readRevisions([target],signal)).get(target);
  const applied = receipts.get(target);
  if (!applied || fields.some(key=>observed[key]!==applied[key])) refusal();
  return Object.freeze(observed);
 };
 const pending = async signal => {
  if (signal?.aborted) throw Error('owned projection canceled');
  const before = await readRevisions(organizations,signal);
  const dirty = [...before.values()].filter(row=>row.desired!==row.applied);
  if (!dirty.length) return;
  const receipts = await reconcilePass(undefined,signal);
  if (dirty.some(row=>!receipts.has(row.organization_id))) refusal();
  const after = await readRevisions([...receipts.keys()],signal);
  for (const [id,receipt] of receipts) {
   const current = after.get(id);
   // A later user mutation can already be pending. It is consumed by the next
   // iteration. The revisions actually acknowledged must always be observable.
   const previous = before.get(id);
   if (receipt.generation !== previous.generation || receipt.applied < previous.desired ||
       current.generation !== receipt.generation || current.applied !== receipt.applied) refusal();
  }
 };
 let sequence = Promise.resolve();
 const serialize = action => {
  const next = sequence.then(action);
  sequence = next.catch(()=>{});
  return next;
 };
 const refresh = (signal,target=organization) => {
  if (!organizations.includes(target)) refusal();
  return serialize(()=>pass(signal,target));
 };
 const poll = signal => serialize(()=>pending(signal));
 const applied = await refresh();
 if (foreignOrganization !== undefined) await refresh(undefined, foreignOrganization);
 const apiEnvironment = Object.freeze({
  ...environment,
  ZASP_POSTGRES_DSN: apiDSN,
  ZASP_SECURITY_AGENT_POSTGRES_DSN: dsn('zasp_svc_security_agent_api'),
  ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN: dsn('zasp_svc_approval_maintenance'),
  ZASP_APPROVAL_MAINTENANCE_KEY_FILE: keyFiles.approval,
  ZASP_AUTHORIZATION_WORKER_KEY_FILE: keyFiles.forward,
  ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE: keyFiles.compensation,
 });
 return Object.freeze({refresh,poll,applied,apiDSN,environment:apiEnvironment,acceptance:false,native:false,production:false,deployed:false,upgradeInstalled:false,ledger:false});
}

export async function runOwnedProjectionLoop(projector,signal,onFailure,wait=delay){
 if(!projector||typeof projector.poll!=='function'||!(signal instanceof AbortSignal)||typeof onFailure!=='function')refusal();
 try{while(!signal.aborted){await projector.poll(signal);if(signal.aborted)break;await wait(100,undefined,{signal});}}
 catch(error){if(signal.aborted&&!(error instanceof OwnedProjectionCleanupIncomplete))return;onFailure();throw error instanceof OwnedProjectionCleanupIncomplete?error:Error('owned authorization projection unavailable');}
}
