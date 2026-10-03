import {setTimeout as delay}from 'node:timers/promises';
import { readFile } from 'node:fs/promises';
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
export async function installOwnedCurrent80({command,migrate,reconcile,psql,port,organization,identityEnvironment,runtimeEnvironment,keyFiles}){
 if(typeof command!=='function'||![migrate,reconcile,psql].every(absolute)||!Number.isSafeInteger(port)||port<1024||port>65535||!canonicalID(organization)||!identityEnvironment||!runtimeEnvironment||runtimeEnvironment.ZASP_RUNTIME_SERVICES_ENABLED!=='true'||runtimeEnvironment.ZASP_ENVIRONMENT!=='test'||!keyFiles||!absolute(keyFiles.forward)||!absolute(keyFiles.compensation)||keyFiles.forward===keyFiles.compensation)refusal();
  const runtimeKeys=['ZASP_RUNTIME_SERVICES_ENABLED','ZASP_ENVIRONMENT','ZASP_RUNTIME_SERVICES_TIMEOUT','ZASP_TEMPORAL_ADDRESS','ZASP_TEMPORAL_NAMESPACE','ZASP_TEMPORAL_TASK_QUEUE','ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE','ZASP_OPENFGA_URL','ZASP_OPENFGA_STORE_ID','ZASP_OPENFGA_MODEL_ID','ZASP_OPENFGA_TOKEN_FILE'];
 if(Object.keys(runtimeEnvironment).length!==runtimeKeys.length||runtimeKeys.some(key=>typeof runtimeEnvironment[key]!=='string')||!/^127\.0\.0\.1:[0-9]{4,5}$/.test(runtimeEnvironment.ZASP_TEMPORAL_ADDRESS)||!/^http:\/\/127\.0\.0\.1:[0-9]{4,5}$/.test(runtimeEnvironment.ZASP_OPENFGA_URL)||![runtimeEnvironment.ZASP_OPENFGA_STORE_ID,runtimeEnvironment.ZASP_OPENFGA_MODEL_ID].every(value=>/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(value))||!absolute(runtimeEnvironment.ZASP_OPENFGA_TOKEN_FILE))refusal();
const required=['ZASP_PUBLIC_ORIGIN','ZASP_STYTCH_BASE_URL','ZASP_STYTCH_PROJECT_ID','ZASP_STYTCH_ORGANIZATION_ID','ZASP_DEPLOYMENT_MODE','ZASP_ORGANIZATION_ID','ZASP_WORKFLOW_SIGNING_KEY'];
 if(required.some(key=>typeof identityEnvironment[key]!=='string')||identityEnvironment.ZASP_DEPLOYMENT_MODE!=='saas'||identityEnvironment.ZASP_ORGANIZATION_ID!==''||!identityEnvironment.ZASP_PUBLIC_ORIGIN||!identityEnvironment.ZASP_STYTCH_BASE_URL||!identityEnvironment.ZASP_WORKFLOW_SIGNING_KEY)refusal();
 const roles=JSON.parse(await readFile(new URL('./fixed-fixture-role-map.json',import.meta.url)));
 const dsn=user=>`postgres://${user}@127.0.0.1:${port}/postgres?sslmode=disable`;
 const migration={...closed(identityEnvironment),...roles,...Object.fromEntries(required.map(key=>[key,identityEnvironment[key]])),...runtimeEnvironment,ZASP_POSTGRES_DSN:dsn(roles.ZASP_MIGRATION_DB_PRINCIPAL),ZASP_MIGRATION_TIMEOUT:'5m',ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL:'zasp_e2e_temporal_executor',ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL:'zasp_e2e_temporal_compensation',ZASP_AUTHORIZATION_WORKER_KEY_FILE:keyFiles.forward,ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE:keyFiles.compensation};
 for(const action of ['up-to-60','up-authorization-runtime-profile','register-temporal-executor-principals','register-authorization-verifier','register-identity-session-verifier','register-identity-webhook-verifier','register-worker-authorization-verifier','register-compensation-authorization-verifier']){const result=await command(migrate,[action],{env:migration,timeout:300000});if(result.status!==0||result.signal)refusal();}
 const configure=await command(reconcile,['-mode','configure','-organization',organization,'-timeout','2m'],{env:migration,timeout:125000});if(configure.status!==0||configure.signal)refusal();
 const delivery={...migration,ZASP_POSTGRES_DSN:dsn(roles.ZASP_OUTBOX_WORKER_DB_PRINCIPAL)};
 const reader={...migration,ZASP_POSTGRES_DSN:dsn(roles.ZASP_DISCOVERY_API_DB_PRINCIPAL)};
 const pass=async(signal)=>{if(signal?.aborted)throw Error('owned projection canceled');
  const result=await command(reconcile,['-mode','reconcile','-organization',organization,'-limit','1','-timeout','2m'],{env:delivery,timeout:125000,signal});if(result.status!==0||result.signal||typeof result.stdout!=='string'||result.stdout.length>65536)refusal();
  let receipt;try{receipt=JSON.parse(result.stdout);}catch{refusal();}
  if(receipt.organization_id!==organization||receipt.status!=='applied'||receipt.receipt?.Applied!==true||!Number.isSafeInteger(receipt.receipt.TupleCount)||receipt.receipt.TupleCount<0)refusal();
  const applied=revision(receipt.receipt.Revision,organization,runtimeEnvironment);
  const sql=`SELECT jsonb_build_object('organization_id',r->'organization_id','desired',r->'desired','applied',r->'applied','generation',r->'generation','store_id',r->'store_id','model_id',r->'model_id') FROM (SELECT zasp_authorization79.revision('${organization}') r) observed`;
  const observation=await command(psql,[reader.ZASP_POSTGRES_DSN,'-X','-v','ON_ERROR_STOP=1','-At','-c',sql],{env:closed(identityEnvironment),timeout:5000,signal});if(observation.status!==0||observation.signal||typeof observation.stdout!=='string'||observation.stdout.length>65536)refusal();
  let data;try{data=JSON.parse(observation.stdout);}catch{refusal();}const observed=revision(data,organization,runtimeEnvironment);if(fields.some(key=>observed[key]!==applied[key]))refusal();return Object.freeze(observed);
 };
 let sequence=Promise.resolve();const refresh=signal=>{const pending=sequence.then(()=>pass(signal));sequence=pending.catch(()=>{});return pending;};
 const applied=await refresh();
 return Object.freeze({refresh,applied,apiDSN:reader.ZASP_POSTGRES_DSN,environment:Object.freeze({...runtimeEnvironment,ZASP_AUTHORIZATION_WORKER_KEY_FILE:keyFiles.forward,ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE:keyFiles.compensation}),acceptance:false,native:false,production:false,deployed:false,upgradeInstalled:false,ledger:false});
}

export async function runOwnedProjectionLoop(projector,signal,onFailure,wait=delay){
 if(!projector||typeof projector.refresh!=='function'||!(signal instanceof AbortSignal)||typeof onFailure!=='function')refusal();
 try{while(!signal.aborted){await projector.refresh(signal);if(signal.aborted)break;await wait(100,undefined,{signal});}}
 catch(error){if(signal.aborted&&!(error instanceof OwnedProjectionCleanupIncomplete))return;onFailure();throw error instanceof OwnedProjectionCleanupIncomplete?error:Error('owned authorization projection unavailable');}
}
