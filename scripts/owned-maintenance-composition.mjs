import {randomBytes} from 'node:crypto';
import {lstat,open} from 'node:fs/promises';
import {join} from 'node:path';
import {runOwnedMaintenanceCutover} from './owned-maintenance-cutover.mjs';

const refuse=()=>{throw Error('owned maintenance composition refused');};
const absolute=value=>typeof value==='string'&&/^\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/.test(value)&&!value.split('/').includes('..');
const pinNames=['ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM','ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM','ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM'];
const pinFields=['connector_profile_checksum','approval_profile_checksum','activation_profile_checksum'];
const connectorPrincipal='zasp_e2e_outbox',approvalPrincipal='zasp_e2e_approval_maintenance';

// The connector retains the original canonical outbox binding. Registering a
// second login for that authority would violate the original UNIQUE binding.
const roleSQL=`BEGIN;
DO $owned_maintenance_roles$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles r JOIN pg_roles a ON a.rolname='zasp_outbox_worker'
  WHERE r.rolname='zasp_e2e_outbox' AND r.rolcanlogin AND r.rolinherit
  AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
  AND pg_has_role(r.oid,a.oid,'MEMBER')
  AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND(m.roleid<>a.oid OR m.admin_option))
  AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b WHERE b.principal_name=r.rolname AND b.authority_role=a.rolname))
 THEN RAISE EXCEPTION 'owned connector principal refused'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='zasp_e2e_approval_maintenance') THEN
  CREATE ROLE zasp_e2e_approval_maintenance LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  GRANT zasp_approval_maintenance_worker TO zasp_e2e_approval_maintenance;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles r JOIN pg_roles a ON a.rolname='zasp_approval_maintenance_worker'
  WHERE r.rolname='zasp_e2e_approval_maintenance' AND r.rolcanlogin AND NOT r.rolinherit
  AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
  AND NOT(a.rolcanlogin OR a.rolinherit OR a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolreplication OR a.rolbypassrls)
  AND pg_has_role(r.oid,a.oid,'MEMBER')
  AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=a.oid OR(m.member=r.oid AND(m.roleid<>a.oid OR m.admin_option))))
 THEN RAISE EXCEPTION 'owned approval principal refused'; END IF;
END $owned_maintenance_roles$;
COMMIT;`;

function succeeded(result){if(!result||result.status!==0||result.signal!=null||result.stderr||result.outputLimitExceeded)refuse();return result;}
function objectOutput(result,fields){const raw=succeeded(result).stdout;if(typeof raw!=='string'||raw.length>4096)refuse();let value;try{value=JSON.parse(raw);}catch{refuse();}if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==fields.length||fields.some(field=>!Object.hasOwn(value,field)))refuse();for(const field of fields){if([...raw.matchAll(new RegExp('"'+field+'"\\s*:','g'))].length!==1)refuse();}return value;}
async function seedFile(root,name){
 const path=join(root,name),key=randomBytes(32);let file;
 try{file=await open(path,'wx',0o400);await file.writeFile(key);await file.sync();const stat=await file.stat();if(!stat.isFile()||(stat.mode&0o7777)!==0o400||stat.size!==32||stat.nlink!==1||stat.uid!==process.geteuid())refuse();return path;}
 finally{key.fill(0);await file?.close();}
}

// Component composition only: the installed commands and measured coordinator
// remain responsible for catalog, operator, process and credential authority.
export async function activateOwnedMaintenance(config,runCutover=runOwnedMaintenanceCutover){
 try{
  const {command,migrate,reconcile,cutover,register,psql,port,organization,migrationEnvironment,runtimeEnvironment,keyRoot,oldTokenFile,newTokenFile,withdrawOldCredential,cwd}=config??{};
  const env=value=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.entries(value).every(([k,v])=>/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)&&typeof v==='string');
  if(typeof command!=='function'||typeof runCutover!=='function'||typeof withdrawOldCredential!=='function'||![migrate,reconcile,cutover,register,psql,keyRoot,oldTokenFile,newTokenFile,cwd].every(absolute)||!Number.isSafeInteger(port)||port<1024||port>65535||!/^pid_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(organization??'')||!env(migrationEnvironment)||!env(runtimeEnvironment)||pinNames.some(name=>Object.hasOwn(runtimeEnvironment,name))||oldTokenFile===newTokenFile||runtimeEnvironment.ZASP_OPENFGA_TOKEN_FILE!==newTokenFile||runtimeEnvironment.ZASP_RUNTIME_SERVICES_ENABLED!=='true'||runtimeEnvironment.ZASP_ENVIRONMENT!=='test'||migrationEnvironment.ZASP_OUTBOX_WORKER_DB_PRINCIPAL!==connectorPrincipal)refuse();
  const dsn=user=>`postgres://${user}@127.0.0.1:${port}/postgres?sslmode=disable`;
  if(migrationEnvironment.ZASP_POSTGRES_DSN!==dsn('zasp_e2e'))refuse();
  const root=await lstat(keyRoot);if(!root.isDirectory()||(root.mode&0o7777)!==0o700||root.uid!==process.geteuid())refuse();
  const cleanEnvironment={...migrationEnvironment};for(const name of pinNames)delete cleanEnvironment[name];
  for(const action of ['up-approval-maintenance-profile','up-connector-maintenance-profile','up-approval-activation-profile','up-approval-settlement-audit-profile'])succeeded(await command(migrate,[action],{env:cleanEnvironment,cwd,timeout:300000}));
  succeeded(await command(psql,[migrationEnvironment.ZASP_POSTGRES_DSN,'-X','-v','ON_ERROR_STOP=1','-c',roleSQL],{env:cleanEnvironment,cwd,timeout:10000}));
  const pins=objectOutput(await command(cutover,['-mode','pins'],{env:cleanEnvironment,cwd,timeout:10000}),pinFields);
  if(pinFields.some(field=>typeof pins[field]!=='string'||!/^[a-f0-9]{64}$/.test(pins[field])))refuse();
  const profiles=Object.fromEntries(pinNames.map((name,i)=>[name,pins[pinFields[i]]]));
  const connectorKey=await seedFile(keyRoot,'connector-maintenance-forward.seed');
  const approvalKey=await seedFile(keyRoot,'approval-maintenance-forward.seed');
  const environment={...runtimeEnvironment,...profiles,ZASP_OPENFGA_TOKEN_FILE:newTokenFile,ZASP_CONNECTOR_MAINTENANCE_POSTGRES_DSN:dsn(connectorPrincipal),ZASP_APPROVAL_MAINTENANCE_POSTGRES_DSN:dsn(approvalPrincipal),ZASP_CONNECTOR_MAINTENANCE_KEY_FILE:connectorKey,ZASP_APPROVAL_MAINTENANCE_KEY_FILE:approvalKey};
  const operatorEnvironment={...migrationEnvironment,...environment,ZASP_POSTGRES_DSN:migrationEnvironment.ZASP_POSTGRES_DSN,ZASP_CONNECTOR_MAINTENANCE_DB_PRINCIPAL:connectorPrincipal,ZASP_APPROVAL_MAINTENANCE_DB_PRINCIPAL:approvalPrincipal};
  const registered=objectOutput(await command(register,[],{env:operatorEnvironment,cwd,timeout:65000}),['status']);if(registered.status!=='registered')refuse();
  const oldEnvironment={...cleanEnvironment,...runtimeEnvironment,ZASP_POSTGRES_DSN:dsn(connectorPrincipal),ZASP_OPENFGA_TOKEN_FILE:oldTokenFile};for(const name of pinNames)delete oldEnvironment[name];
  const activated=await runCutover({reconcile,cutover,organization,oldEnvironment,newEnvironment:{...operatorEnvironment,ZASP_POSTGRES_DSN:dsn(connectorPrincipal)},operatorEnvironment,withdrawOldCredential,cwd});
  if(!activated||Object.keys(activated).length!==1||activated.activated!==true)refuse();
  return Object.freeze({environment:Object.freeze(environment)});
 }catch{refuse();}
}
