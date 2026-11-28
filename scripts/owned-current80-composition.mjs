import {setTimeout as delay}from 'node:timers/promises';
export class OwnedProjectionCleanupIncomplete extends Error {constructor(){super('owned projection cleanup incomplete');}}
const refusal=()=>{throw Error('owned current authorization fixture unavailable');};
const fields=['organization_id','desired','applied','generation','store_id','model_id'];
const canonicalID=value=>typeof value==='string'&&/^pid_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const absolute=value=>typeof value==='string'&&/^\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/.test(value)&&!value.split('/').includes('..');
const closed=value=>Object.fromEntries(Object.entries(value).filter(([key])=>!key.startsWith('ZASP_')));
export const closedOwnedAmbientEnvironment=closed;
function revision(value,organization,environment){if(!value||Object.keys(value).length!==fields.length||!fields.every(key=>Object.hasOwn(value,key))||value.organization_id!==organization||value.store_id!==environment.ZASP_OPENFGA_STORE_ID||value.model_id!==environment.ZASP_OPENFGA_MODEL_ID||![value.desired,value.applied,value.generation].every(Number.isSafeInteger)||value.desired<1||value.generation<1||value.desired!==value.applied)refusal();return value;}

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
 const pass=async(signal, targetOrganization)=>{if(signal?.aborted)throw Error('owned projection canceled');
  const result=await command(reconcile,['-mode','reconcile','-organization',targetOrganization,'-limit','1','-timeout','2m'],{env:delivery,timeout:125000,signal});if(result.status!==0||result.signal||typeof result.stdout!=='string'||result.stdout.length>65536)refusal();
  let receipt;try{receipt=JSON.parse(result.stdout);}catch{refusal();}
  if(receipt.organization_id!==targetOrganization||receipt.status!=='applied'||receipt.receipt?.Applied!==true||!Number.isSafeInteger(receipt.receipt.TupleCount)||receipt.receipt.TupleCount<0)refusal();
  const applied=revision(receipt.receipt.Revision,targetOrganization,runtimeEnvironment);
  const sql=`SELECT jsonb_build_object('organization_id',r->'organization_id','desired',r->'desired','applied',r->'applied','generation',r->'generation','store_id',r->'store_id','model_id',r->'model_id') FROM (SELECT zasp_authorization79.revision('${targetOrganization}') r) observed`;
  const observation=await command(psql,[apiDSN,'-X','-v','ON_ERROR_STOP=1','-At','-c',sql],{env:closed(identityEnvironment),timeout:5000,signal});if(observation.status!==0||observation.signal||typeof observation.stdout!=='string'||observation.stdout.length>65536)refusal();
  let data;try{data=JSON.parse(observation.stdout);}catch{refusal();}const observed=revision(data,targetOrganization,runtimeEnvironment);if(fields.some(key=>observed[key]!==applied[key]))refusal();return Object.freeze(observed);
 };
 let sequence = Promise.resolve();
 const refresh = (signal, targetOrganization = organization) => {
  if (!organizations.includes(targetOrganization)) refusal();
  const pending = sequence.then(() => pass(signal, targetOrganization));
  sequence = pending.catch(() => {});
  return pending;
 };
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
 return Object.freeze({refresh,applied,apiDSN,environment:apiEnvironment,acceptance:false,native:false,production:false,deployed:false,upgradeInstalled:false,ledger:false});
}

export async function runOwnedProjectionLoop(projector,signal,onFailure,wait=delay){
 if(!projector||typeof projector.refresh!=='function'||!(signal instanceof AbortSignal)||typeof onFailure!=='function')refusal();
 try{while(!signal.aborted){await projector.refresh(signal);if(signal.aborted)break;await wait(100,undefined,{signal});}}
 catch(error){if(signal.aborted&&!(error instanceof OwnedProjectionCleanupIncomplete))return;onFailure();throw error instanceof OwnedProjectionCleanupIncomplete?error:Error('owned authorization projection unavailable');}
}
