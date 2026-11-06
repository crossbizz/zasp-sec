import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,lstat,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {activateOwnedMaintenance} from './owned-maintenance-composition.mjs';

const organization='pid_78219401-0000-4000-8000-000000000001';
const pins={connector_profile_checksum:'a'.repeat(64),approval_profile_checksum:'b'.repeat(64),activation_profile_checksum:'c'.repeat(64)};
async function fixture(t,failure){
 const keyRoot=await mkdtemp(join(tmpdir(),'maintenance-composition-'));t.after(()=>rm(keyRoot,{recursive:true,force:true}));
 const calls=[];
 const runtimeEnvironment={ZASP_RUNTIME_SERVICES_ENABLED:'true',ZASP_ENVIRONMENT:'test',ZASP_OPENFGA_URL:'http://127.0.0.1:32101',ZASP_OPENFGA_STORE_ID:'01K00000000000000000000001',ZASP_OPENFGA_MODEL_ID:'01K00000000000000000000002',ZASP_OPENFGA_TOKEN_FILE:'/owned/new-token'};
 const config={migrate:'/tools/migrate',reconcile:'/tools/reconcile',cutover:'/tools/cutover',register:'/tools/register',psql:'/tools/psql',port:32100,organization,migrationEnvironment:{PATH:'/tools',ZASP_POSTGRES_DSN:'postgres://zasp_e2e@127.0.0.1:32100/postgres?sslmode=disable',ZASP_OUTBOX_WORKER_DB_PRINCIPAL:'zasp_e2e_outbox'},runtimeEnvironment,keyRoot,oldTokenFile:'/owned/old-token',newTokenFile:'/owned/new-token',withdrawOldCredential:async()=>calls.push('withdraw'),cwd:'/workspace'};
 config.command=async(file,args,options)=>{calls.push({file,args,options});if(failure!==undefined&&(failure===file||failure===args[0]))return {status:1,signal:null,stdout:'private-error',stderr:'private-error'};if(file===config.cutover)return {status:0,signal:null,stdout:JSON.stringify(failure==='bad-pins'?{...pins,extra:'untrusted'}:pins),stderr:''};if(file===config.register)return {status:0,signal:null,stdout:JSON.stringify(failure==='bad-register'?{status:'registered',extra:true}:{status:'registered'}),stderr:''};return {status:0,signal:null,stdout:'',stderr:''};};
 const runCutover=async(value)=>{calls.push({cutover:value});if(failure==='cutover')throw Error('private process details');return {activated:true};};
 return {config,calls,runCutover,keyRoot};
}

test('composes original installers, restricted logins, bound registration and measured cutover in order',async t=>{
 const f=await fixture(t);const result=await activateOwnedMaintenance(f.config,f.runCutover);
 assert.deepEqual(f.calls.slice(0,4).map(c=>c.args[0]),['up-approval-maintenance-profile','up-connector-maintenance-profile','up-approval-activation-profile','up-approval-settlement-audit-profile']);
 const ddl=f.calls.find(c=>c.file===f.config.psql);assert.match(ddl.args.at(-1),/LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);assert.match(ddl.args.at(-1),/zasp_e2e_outbox/);assert.match(ddl.args.at(-1),/admin_option/);assert.doesNotMatch(ddl.args.at(-1),/UPDATE|ALTER ROLE|activate_controlled|origins|delegation|register_verifier/i);
 const registered=f.calls.find(c=>c.file===f.config.register);assert.deepEqual(registered.args,[]);assert.equal(registered.options.env.ZASP_CONNECTOR_MAINTENANCE_DB_PRINCIPAL,'zasp_e2e_outbox');assert.equal(registered.options.env.ZASP_APPROVAL_MAINTENANCE_DB_PRINCIPAL,'zasp_e2e_approval_maintenance');
 assert.equal(f.config.runtimeEnvironment.ZASP_OPENFGA_TOKEN_FILE,'/owned/new-token');const cutover=f.calls.at(-1).cutover;assert.equal(cutover.oldEnvironment.ZASP_OPENFGA_TOKEN_FILE,'/owned/old-token');assert.equal(cutover.newEnvironment.ZASP_OPENFGA_TOKEN_FILE,'/owned/new-token');assert.match(cutover.newEnvironment.ZASP_POSTGRES_DSN,/zasp_e2e_outbox@/);assert.match(cutover.operatorEnvironment.ZASP_POSTGRES_DSN,/zasp_e2e@/);for(const field of ['ZASP_OPENFGA_URL','ZASP_OPENFGA_STORE_ID','ZASP_OPENFGA_MODEL_ID']){assert.equal(cutover.oldEnvironment[field],cutover.newEnvironment[field]);assert.equal(cutover.newEnvironment[field],f.config.runtimeEnvironment[field]);}
 for(const name of ['ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM','ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM','ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM']){assert.ok(!Object.hasOwn(cutover.oldEnvironment,name));assert.match(cutover.newEnvironment[name],/^[a-f0-9]{64}$/);}
 assert.ok(!Object.hasOwn(result.environment,'ZASP_POSTGRES_DSN'));assert.equal(result.environment.ZASP_OPENFGA_TOKEN_FILE,'/owned/new-token');
 const keys=[];for(const name of ['ZASP_CONNECTOR_MAINTENANCE_KEY_FILE','ZASP_APPROVAL_MAINTENANCE_KEY_FILE']){const path=result.environment[name],stat=await lstat(path);assert.equal(stat.mode&0o777,0o400);assert.equal(stat.nlink,1);assert.equal(stat.size,32);keys.push(await readFile(path));assert.ok(!JSON.stringify(f.calls).includes(keys.at(-1).toString('hex')));}
 assert.notDeepEqual(keys[0],keys[1]);
});
test('any prerequisite failure stops before activation and hides command details',async t=>{
 for(const failure of ['up-approval-maintenance-profile','up-connector-maintenance-profile','up-approval-activation-profile','up-approval-settlement-audit-profile','/tools/psql','bad-pins','/tools/register','bad-register','cutover']){await t.test(failure,async t=>{const f=await fixture(t,failure);await assert.rejects(activateOwnedMaintenance(f.config,f.runCutover),/^Error: owned maintenance composition refused$/);if(failure!=='cutover')assert.ok(!f.calls.some(c=>c.cutover));});}
});
test('invalid scope or credential custody refuses before command execution',async t=>{
 for(const change of [c=>c.organization='other',c=>c.oldTokenFile=c.newTokenFile,c=>c.port=80,c=>c.runtimeEnvironment.ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM='a'.repeat(64),c=>c.migrationEnvironment.ZASP_OUTBOX_WORKER_DB_PRINCIPAL='unsafe',c=>c.runtimeEnvironment.ZASP_OPENFGA_TOKEN_FILE='/unowned/token',c=>c.runtimeEnvironment.ZASP_OPENFGA_TOKEN_FILE=c.oldTokenFile]){const f=await fixture(t);change(f.config);await assert.rejects(activateOwnedMaintenance(f.config,f.runCutover));assert.equal(f.calls.length,0);}
});
