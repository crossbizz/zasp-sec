import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {buildOrderedConsolidatedReference} from './build-ordered-current-consolidated-reference.mjs';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const packetPrefix='services/platform/migrations/ordered_current/';
const packetNames=['consolidated-capture-coverage.json','consolidated-capture-contract.json','consolidated-capture-demand.sql','consolidated-capture-keys.sql','consolidated-capture-original.sql','consolidated-capture-resolution.sql','consolidated-capture-witness.sql'];
const phases=['demand','keys','original','resolution','witness'];
const emitterPath='services/platform/migrations/tools/build-ordered-current-consolidated-reference.mjs';
const pinsPath='services/platform/apiserver/authorization_worker_consolidated_reference_pins_test.go';
const producerPaths=[
 'services/platform/apiserver/authorization_worker_consolidated_reference_boundary_test.go',
 'services/platform/apiserver/authorization_worker_consolidated_reference_controls_test.go',
 'services/platform/apiserver/authorization_worker_consolidated_reference_postgres_test.go'
];
const supportPins={
 'services/platform/migrations/sql/0079_production_authorization_projection.up.sql':'8b358e304b2eedaed7a4148f317f6d21d9c624ccc39105ca6199265ae661a987',
 'services/platform/migrations/sql/0080_authorization_hierarchy_create.sql':'97482f048fb4ee282bd4f8506f618b83b1252d5afce267ad3b36edcc8a33d46e',
 'services/platform/migrations/sql/0014_typed_inventory_cutover.up.sql':'06ed7d1310bee92bfd80c92698b91c18e3932a573793dcb32344a3fea56831b8',
 'services/platform/migrations/sql/0027_production_recovery.up.sql':'0e4dcbaf987cc3b5f69cf4d415a028d643c2f95bf5160e827e1607e3f60dbc14'
};

test('emitted source maxima survive raw, demand and roster construction',()=>{
 const {contract}=buildOrderedConsolidatedReference();
 for(const [id,maximum]of [['worker:projected_domain:table',23],['worker-edge:gateway_projected27:8',1],['worker-edge:gateway_projected27:10',2],['worker-edge:runtime_projected50_binding:7',2]]){
  for(const suffix of ['',':demand',':keys']){
   assert.equal(contract.rules[id+suffix].sourceMaxRows,maximum,id+suffix);
   assert.equal(contract.rules[id+suffix].refusalMaxRows,10000);
  }
 }
});

test('fixed complete closure emits one deterministic seven-member variant A packet',()=>{
 const first=buildOrderedConsolidatedReference(),second=buildOrderedConsolidatedReference();
 assert.deepEqual(Object.keys(first.files),packetNames.map(name=>packetPrefix+name));
 assert.deepEqual(Object.keys(second.files),Object.keys(first.files));
 for(const path of Object.keys(first.files)){
  assert.ok(Buffer.isBuffer(first.files[path]),path);
  assert.equal(first.files[path].at(-1),10,path);
  assert.deepEqual(second.files[path],first.files[path],path);
 }

 const contract=JSON.parse(first.files[packetPrefix+'consolidated-capture-contract.json']);
 assert.deepEqual(Object.keys(contract),['format','status','installable','captureReady','sourceFrameVersion','compilerArtifactSHA256','compilerChecksum','compiledSourceSHA256','sourceContractSHA256','closureSHA256','catalog1FileSHA256','requiredPostgres','requiredServerVersionNum','pgcrypto','variant','sessionUser','requiredRole','requiredTimeZone','maxRows','maxBytes','phases','rules','reusedEvidence','sourcePins']);
 assert.equal(contract.format,'ordered-current-complete-capture-contract-v1');
 assert.equal(contract.status,'REFERENCE-CAPTURE-ONLY');
 assert.equal(contract.installable,false);
 assert.equal(contract.captureReady,true);
 assert.equal(contract.variant,'A');
 assert.equal(contract.sessionUser,'zasp_test');
 assert.equal(contract.requiredRole,'zasp_discovery_authority');
 assert.equal(contract.requiredTimeZone,'UTC');
 assert.equal(contract.maxRows,10000);
 assert.equal(contract.maxBytes,16777216);
 assert.deepEqual(contract.phases.map(phase=>phase.id),phases);
 assert.deepEqual(contract.phases.map(phase=>phase.searchPath),['pg_catalog, public','pg_catalog','pg_catalog, public','pg_catalog, public','pg_catalog, public']);
 assert.ok(Object.keys(contract.rules).length>500);
 const declared=new Set;
 for(const phase of contract.phases){
  const sql=first.files[packetPrefix+`consolidated-capture-${phase.id}.sql`];
  assert.equal(sha(sql),phase.sqlSHA256);
  assert.ok(phase.ruleIds.length>0,phase.id);
  for(const id of phase.ruleIds){assert.equal(declared.has(id),false,id);declared.add(id);assert.equal(contract.rules[id].phase,phase.id);}
  assert.match(sql.toString(),/^SELECT \* FROM \([\s\S]+\) AS capture_[a-z]+_0001/);
  assert.doesNotMatch(sql.toString(),/\bLIMIT\b/i);
 }
 assert.equal(declared.size,Object.keys(contract.rules).length);
 assert.equal(first.files[packetPrefix+'consolidated-capture-coverage.json'].length>0,true);
 assert.equal(sha(first.files[packetPrefix+'consolidated-capture-coverage.json']),contract.closureSHA256);

 const keys=first.files[packetPrefix+'consolidated-capture-keys.sql'].toString();
 assert.match(keys,/\$1::jsonb/);
 assert.match(keys,/JOIN pg_type c ON c\.oid=split_part\(d\.handle,':',2\)::oid/);
 assert.match(keys,/split_part\(d\.handle,':',1\)='pg_type'/);
 assert.doesNotMatch(keys,/\$(?:[2-9]|[1-9][0-9]+)/);
 for(const phase of ['demand','original','resolution','witness'])assert.doesNotMatch(first.files[packetPrefix+`consolidated-capture-${phase}.sql`].toString(),/\$[0-9]+/);
});

test('owned snapshot binds exact source graph, fixed inputs, producer bytes and packet members without a hash cycle',()=>{
 const built=buildOrderedConsolidatedReference();
 const manifest=JSON.parse(built.manifestRaw);
 assert.deepEqual(Object.keys(manifest),['format','source','files']);
 assert.equal(manifest.format,1);
 assert.equal(manifest.source,'ordered-current-task2-tracked-authority');
 assert.equal(Object.hasOwn(manifest.files,'snapshot-manifest.json'),false);
 assert.equal(Object.hasOwn(manifest.files,pinsPath),false);
 for(const path of [...packetNames.map(name=>packetPrefix+name),emitterPath,...producerPaths])assert.match(manifest.files[path],/^[0-9a-f]{64}$/,path);
 assert.deepEqual(Object.keys(built.snapshotFiles),Object.keys(manifest.files));
 for(const [path,digest] of Object.entries(manifest.files)){
  assert.ok(Buffer.isBuffer(built.snapshotFiles[path]),path);
  assert.equal(sha(built.snapshotFiles[path]),digest,path);
 }

 const contract=JSON.parse(built.files[packetPrefix+'consolidated-capture-contract.json']);
 assert.equal(Object.hasOwn(contract.sourcePins,pinsPath),false);
 assert.equal(Object.hasOwn(contract.sourcePins,packetPrefix+'consolidated-capture-contract.json'),false);
 assert.equal(Object.hasOwn(contract.sourcePins,'snapshot-manifest.json'),false);
 assert.deepEqual(contract.sourcePins,Object.fromEntries(Object.entries(manifest.files).filter(([path])=>!path.startsWith(packetPrefix+'consolidated-capture-'))));
 for(const [path,digest] of Object.entries(supportPins)){
  assert.equal(contract.sourcePins[path],digest,path);
  assert.equal(manifest.files[path],digest,path);
  assert.deepEqual(built.snapshotFiles[path],fs.readFileSync(new URL('../../../../'+path,import.meta.url)),path);
 }
 for(const path of Object.keys(contract.sourcePins))assert.deepEqual(built.snapshotFiles[path],fs.readFileSync(new URL('../../../../'+path,import.meta.url)),path);
});

test('tracked authority replaces ignored predecessor snapshots with exact fixed inputs',()=>{
 const built=buildOrderedConsolidatedReference(),prefix='services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/';
 const expected={'effective-contract3.json':'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6','effective-catalog1.json':'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077','inventory-compiled.json':'4ad7d7218fff014766d92d8af7522ed5bb382b95e5fa1e12d9be70a407543425','supplementary-reference1.json':'484a5c749d6750e0af783147f0d12efed6c9e4ebce1daf5bd5eec4eda643d23b','remaining-reference1.json':'cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797','private-reference-alias1.json':'15ae007312b14b8503aadcd852db33be9dd1932d1b499614d9dced3c801f4607','complete-capture-wire-contract.md':'563fe703c7dbd43edc4b87595d168e4aaaf1a13cf096779c448e0795c38509d0','complete-capture-wire-vectors.json':'438c2f9e563ce01d0052c4e8556d1dea93185d9494d2c46f4d25b1616f059a96'};
 for(const [name,digest]of Object.entries(expected)){const relative=prefix+name;assert.equal(sha(fs.readFileSync(new URL('../../../../'+relative,import.meta.url))),digest,name);assert.equal(JSON.parse(built.manifestRaw).files[relative],digest,name);}
 for(const file of ['build-ordered-current-consolidated-reference.mjs','build-ordered-current-development.mjs','ordered-current-capture-closure.mjs'])assert.doesNotMatch(fs.readFileSync(new URL(file,import.meta.url),'utf8'),/\.superpowers|\/private\/tmp/,file);
});

test('checked-in packet and immutable snapshot match the closed deterministic build',()=>{
 const node='/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node';
 const result=spawnSync(node,[new URL('./build-ordered-current-consolidated-reference.mjs',import.meta.url).pathname,'--check'],{encoding:'utf8'});
 assert.equal(result.status,0,result.stderr||result.stdout);
 const summary=JSON.parse(result.stdout);
 assert.equal(summary.variant,'A');
 assert.equal(summary.files,7);
 assert.ok(summary.rules>500);
 assert.match(summary.manifestSHA256,/^[0-9a-f]{64}$/);
 assert.match(summary.contractSHA256,/^[0-9a-f]{64}$/);
});
