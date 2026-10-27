import test from 'node:test';
import assert from 'node:assert/strict';
import {provisionOwnedFGAStorage} from './owned-fga-storage.mjs';

test('owned FGA storage creates a separate restricted identity and verifies actual catalog privileges',async()=>{
 const calls=[];
 const value=await provisionOwnedFGAStorage({psql:'/owned/psql',port:32100,environment:{PATH:'/bin',PGOPTIONS:'untrusted',ZASP_POSTGRES_DSN:'untrusted'},command:async(...args)=>{calls.push(args);return {status:0,signal:null,stdout:calls.length===1?'':'t\n',stderr:''};}});
 assert.equal(calls.length,2);const url=new URL(value.dsn);
 assert.equal(url.username,'zasp_e2e_fga');assert.equal(url.pathname,'/zasp_e2e_fga');assert.match(url.password,/^[a-f0-9]{64}$/);
 assert.ok(calls.every(([_exe,args,options])=>!JSON.stringify(args).includes(url.password)&&!options.env.PGOPTIONS&&!options.env.ZASP_POSTGRES_DSN));
 assert.match(calls[0][2].input,/NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
 assert.ok(calls[1][2].input.includes('pg_auth_members'));assert.equal(value.production,false);
});

test('storage failures and unexpected privilege observations remain generic and deny startup',async()=>{
 for(const outcome of ['failure','wrong-role','extra-output','stderr','throw']) {
  let calls=0;
  await assert.rejects(provisionOwnedFGAStorage({psql:'/owned/psql',port:32100,environment:{},command:async()=>{calls++;if(outcome==='throw')throw Error('PRIVATE_RAW_FAILURE');return {status:outcome==='failure'?1:0,signal:null,stdout:calls===1?'':outcome==='wrong-role'?'f':outcome==='extra-output'?'t\nPRIVATE_RAW_FAILURE':'t',stderr:outcome==='stderr'?'PRIVATE_RAW_FAILURE':''};}}),/^Error: owned OpenFGA storage unavailable$/);
 }
});

test('invalid owned storage configuration refuses before command execution',async()=>{
 for(const port of [0,1023,65536,3.5])await assert.rejects(provisionOwnedFGAStorage({psql:'/owned/psql',port,environment:{},command:async()=>assert.fail('invalid configuration reached PostgreSQL')}));
});
