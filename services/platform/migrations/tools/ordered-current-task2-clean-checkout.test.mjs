import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';

const repo=new URL('../../../../',import.meta.url);
const tools=new URL('./',import.meta.url);
const artifactRoot=new URL('./ordered-current-worker-source-closure-v1-artifacts/',import.meta.url);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const inventory=Object.freeze({
 'effective-contract3.json':'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6',
 'effective-catalog1.json':'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077',
 'inventory-compiled.json':'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425',
 'supplementary-query-contract2.json':'6b8fc25c4d5d0a379735d686fe1d6cde8245663a47d346dbf8cf1c11dd33418f',
 'supplementary-reference1.json':'484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b',
 'private-reference-alias1.json':'15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607',
 'private-reference-alias-contract.json':'59b78441d81c02cedb4e3106c8d573dcf1907c8548bd0e961e0fed464b29ee63',
 'remaining-reference1.json':'cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797',
 'supplementary-query-contract3.json':'2334ebbbad1382db7eafa47f81eec5b59f7721aaafa34b6b0d51311d959538ce',
 'remaining-reference-packet-manifest.json':'338026bf79be5535bf0f57206b679e5846526da676fee6b0adac75186083d7ea',
 'complete-capture-wire-contract.md':'563fe703c7dbd43edc4b87595d168e4aaaf1a13cf096779c448e0795c38509d0',
 'complete-capture-wire-vectors.json':'438c2f9e563ce01d0052c4e8556d1dea93185d9494d2c46f4d25b1616f059a96',
});

test('Task2 builders use one complete nonignored exact authority inventory',()=>{
 for(const [name,digest]of Object.entries(inventory))assert.equal(sha(fs.readFileSync(new URL(name,artifactRoot))),digest,name);
 const ignored=spawnSync('git',['check-ignore',...Object.keys(inventory).map(name=>new URL(name,artifactRoot).pathname)],{cwd:new URL('.',repo),encoding:'utf8'});
 assert.equal(ignored.status,1,ignored.stdout||ignored.stderr);
 for(const name of ['build-ordered-current-development.mjs','build-ordered-current-consolidated-reference.mjs','ordered-current-capture-closure.mjs','ordered-current-capture-closure.test.mjs','ordered-current-consolidation-needs.mjs','ordered-current-worker-source-closure-v1.mjs'])assert.doesNotMatch(fs.readFileSync(new URL(name,tools),'utf8'),/\.superpowers|\/private\/tmp/,name);
});

test('Task2 development and consolidation checks pass in an isolated tree with no ignored evidence directory',()=>{
 const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-task2-clean-'));
 try{
  const migrations=path.join(temporary,'services/platform/migrations');
  fs.mkdirSync(path.dirname(migrations),{recursive:true});
  fs.cpSync(new URL('../',import.meta.url),migrations,{recursive:true});
  const appserver=path.join(temporary,'services/platform/apiserver');fs.mkdirSync(appserver,{recursive:true});
  for(const name of ['authorization_worker_consolidated_reference_boundary_test.go','authorization_worker_consolidated_reference_controls_test.go','authorization_worker_consolidated_reference_postgres_test.go'])fs.copyFileSync(new URL(`../../apiserver/${name}`,import.meta.url),path.join(appserver,name));
  assert.equal(fs.existsSync(path.join(temporary,'.superpowers')),false);
  for(const builder of ['build-ordered-current-development.mjs','build-ordered-current-consolidated-reference.mjs']){
   const result=spawnSync(process.execPath,[path.join(migrations,'tools',builder),'--check'],{cwd:temporary,encoding:'utf8',maxBuffer:32*1024*1024});
   assert.equal(result.status,0,result.stderr||result.stdout);
  }
  const closure=spawnSync(process.execPath,['--test',path.join(migrations,'tools','ordered-current-capture-closure.test.mjs')],{cwd:temporary,encoding:'utf8',maxBuffer:32*1024*1024});
  assert.equal(closure.status,0,closure.stderr||closure.stdout);
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
});
