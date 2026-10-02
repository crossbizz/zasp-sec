import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../../../../',import.meta.url));
const tools='services/platform/migrations/tools/';
const historical=tools+'ordered-current-private-historical-v1/';
const reader=tools+'ordered-current-build-source-inventory-v1.mjs';
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const manifestRaw=fs.readFileSync(path.join(root,historical+'manifest.json'));
assert.equal(sha(manifestRaw),'8d4fee2253344603a4878751f70f96bcf7d4b4884a5cab2b6ee1016db9d40732');
const historicalPaths=[historical+'manifest.json',...Object.keys(JSON.parse(manifestRaw).files).map(name=>historical+name)];
const currentPaths=[
 'ordered-current-private-historical-v1.mjs','ordered-current-private-historical-v1.test.mjs',
 'ordered-current-private-successor-reference.mjs','ordered-current-private-successor-reference.test.mjs',
 'ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',
 'ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',
 'ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json',
 'build-worker-readiness-graph.mjs','worker-readiness-regions.mjs',
 'ordered-current-worker-higher-source-replay-v1.mjs','ordered-current-worker-higher-source-replay-v1.test.mjs',
 'ordered-current-worker-higher-integration-v1.mjs','build-ordered-current-development-higher.test.mjs',
 'ordered-current-remaining-projection-witness-v1.mjs','ordered-current-remaining-projection-witness-v1.test.mjs',
 'ordered-current-remaining-projection-witness-v1-artifacts/reference.json','ordered-current-development-remaining.test.mjs',
 'ordered-current-precision-resolver-frame-v1.mjs','ordered-current-precision-resolver-frame-v1.test.mjs',
 'build-ordered-current-development-private.test.mjs',
 'ordered-current-build-source-inventory-v1.mjs','ordered-current-build-source-inventory-v1.test.mjs',
].map(name=>tools+name);
const externalPaths=[
 'services/platform/migrations/sql/0080_authorization_worker_readiness_graph.sql',
 'services/platform/apiserver/authorization_worker_ordered_readiness_capture_test.go',
 'services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go',
];
export const expectedCurrentBuildSourcePaths=[...historicalPaths,...currentPaths,...externalPaths].sort();
let api={};
try{api=await import('./ordered-current-build-source-inventory-v1.mjs');}
catch(error){if(error.code!=='ERR_MODULE_NOT_FOUND')throw error;}
function read(){
 assert.equal(typeof api.readOrderedCurrentBuildSourceInventoryV1,'function','fixed source inventory reader is required');
 return api.readOrderedCurrentBuildSourceInventoryV1();
}

// Break caught: omitted raw data/test/Go/historical input cannot appear as a
// successful closed source inventory. Expectations are an independent roster.
test('fixed inventory binds the complete 53-file current package without promoting execution',()=>{
 const inventory=read();
 assert.deepEqual(Object.keys(inventory),['format','status','installable','native','executable','inputs']);
 assert.equal(inventory.format,'ordered-current-build-source-inventory-v1');
 assert.equal(inventory.status,'SOURCE-PROVENANCE-ONLY');
 for(const flag of ['installable','native','executable'])assert.equal(inventory[flag],false);
 assert.equal(expectedCurrentBuildSourcePaths.length,53);
 assert.deepEqual(Object.keys(inventory.inputs),expectedCurrentBuildSourcePaths);
 for(const relative of expectedCurrentBuildSourcePaths)assert.equal(inventory.inputs[relative],sha(fs.readFileSync(path.join(root,relative))),relative);
 assert.equal(inventory.inputs[externalPaths[2]],'78427e95a296b9b636154a9d7d81e022772fe43b2503fc972c0f34e1e20488b6');
 assert.equal(inventory.inputs[historical+'tools/ordered-current-private-successor-reference.mjs'],'454f8e426f10462d414501fb2ff9204122d744e501261f4ac59039b2f8d99306');
 assert.equal(inventory.inputs[tools+'ordered-current-private-successor-reference.mjs'],'6f81cabbd3672c70190f43f9b70918ade8ef97a392e3a491922bdd874e066450');
});

test('fixed inventory refuses caller-selected paths, hashes and roots',()=>{
 read();
 for(const override of [undefined,{},root,{inputs:{}},{native:true}])assert.throws(()=>api.readOrderedCurrentBuildSourceInventoryV1(override),/caller|fixed/);
});

test('development build record includes every current source input under its actual path',t=>{
 const directory=isolated(t);
 const result=spawnSync(process.execPath,['./'+tools+'build-ordered-current-development.mjs','--write'],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_OPTIONS:''}});
 assert.equal(result.status,0,result.stderr);
 const manifest=JSON.parse(fs.readFileSync(path.join(directory,'services/platform/migrations/ordered_current/development-manifest.json')));
 const rows=manifest.facts.filter(row=>row.kind==='build'&&row.identity==='provenance');
 assert.equal(rows.length,1);
 const pins=Object.fromEntries(rows[0].fact.module_sha256.map(entry=>entry.split('=')));
 for(const relative of expectedCurrentBuildSourcePaths)assert.equal(pins[relative],sha(fs.readFileSync(path.join(directory,relative))),relative);
 assert.equal(manifest.installable,false);
 const checkpoint=JSON.parse(fs.readFileSync(path.join(directory,'services/platform/migrations/ordered_current/development-checkpoint.json')));
 assert.equal(checkpoint.facts,10052);
 assert.equal(checkpoint.nativeVerified,false);
 for(const flag of ['installable','nativeVerified','executableReplacementVerified'])assert.equal(checkpoint.dormantEvaluator[flag],false);
});

function isolated(t){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-source-inventory-test-'));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 for(const relative of ['services/platform/migrations/tools','services/platform/migrations/sql'])fs.cpSync(path.join(root,relative),path.join(directory,relative),{recursive:true,filter:filename=>!path.basename(filename).startsWith('.env')});
 for(const relative of externalPaths.slice(1)){
  fs.mkdirSync(path.dirname(path.join(directory,relative)),{recursive:true});
  fs.copyFileSync(path.join(root,relative),path.join(directory,relative));
 }
 return directory;
}
function probe(directory){
 const result=spawnSync(process.execPath,['--input-type=module','-e',`import {readOrderedCurrentBuildSourceInventoryV1 as read} from ${JSON.stringify('./'+reader)}; console.log(JSON.stringify(read()));`],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_OPTIONS:''}});
 return result;
}

// Break caught: disk substitutions must not be hidden by accepted manifest
// metadata or a cached reader. Each mutation is confined to a disposable tree.
test('inventory refuses missing, extra, changed and substituted admitted source inputs',t=>{
 read();
 const directory=isolated(t);
 const positive=probe(directory);
 assert.equal(positive.status,0,positive.stderr);
 assert.equal(Object.keys(JSON.parse(positive.stdout).inputs).length,53);
 const mutations=[
  ['missing historical',historical+'tools/ordered-current-private.mjs','missing'],
  ['changed historical',historical+'sql/0080_authorization_worker_ordered_current_integrity.sql','changed'],
  ['altered manifest',historical+'manifest.json','changed'],
  ['missing Go',externalPaths[1],'missing'],
  ['changed Go',externalPaths[2],'changed'],
  ['missing raw data',tools+'ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json','missing'],
  ['missing test',tools+'ordered-current-precision-resolver-frame-v1.test.mjs','missing'],
  ['symlink file',historical+'tools/ordered-current-private.mjs','symlink'],
  ['symlink Go',externalPaths[1],'symlink'],
 ];
 for(const [label,relative,kind]of mutations){
  const filename=path.join(directory,relative),raw=fs.readFileSync(filename);
  fs.unlinkSync(filename);
  if(kind==='changed')fs.writeFileSync(filename,Buffer.concat([raw,Buffer.from('\n')]));
  if(kind==='symlink')fs.symlinkSync(path.join(root,relative),filename);
  const result=probe(directory);
  assert.notEqual(result.status,0,label);
  assert.match(result.stderr,/source inventory|higher successor/,label);
  if(fs.existsSync(filename)||kind==='symlink')fs.unlinkSync(filename);
  fs.writeFileSync(filename,raw);
 }
 const extra=path.join(directory,historical+'extra.mjs');
 fs.writeFileSync(extra,'export const unlisted=true;');
 const unlisted=probe(directory);
 assert.notEqual(unlisted.status,0);
 assert.match(unlisted.stderr,/source inventory/);
 fs.unlinkSync(extra);
 const bundle=path.join(directory,historical.slice(0,-1)),moved=bundle+'-substituted';
 fs.renameSync(bundle,moved);fs.symlinkSync(moved,bundle,'dir');
 const substituted=probe(directory);
 assert.notEqual(substituted.status,0);
 assert.match(substituted.stderr,/source inventory/);
});

test('cached inventory rechecks source bytes after a successful read',t=>{
 read();
 const directory=isolated(t);
 const relative=externalPaths[2];
 const result=spawnSync(process.execPath,['--input-type=module','-e',`import fs from 'node:fs'; import assert from 'node:assert/strict'; import {readOrderedCurrentBuildSourceInventoryV1 as read} from ${JSON.stringify('./'+reader)}; read(); fs.appendFileSync(${JSON.stringify(relative)},'\\n'); assert.throws(()=>read(),/source inventory/);`],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_OPTIONS:''}});
 assert.equal(result.status,0,result.stderr);
});

test('A and development consumers refuse a conflicting duplicate or promoted inventory flag',t=>{
 read();
 const directory=isolated(t);
 for(const name of [
  'authorization_worker_consolidated_reference_boundary_test.go',
  'authorization_worker_consolidated_reference_controls_test.go',
  'authorization_worker_consolidated_reference_postgres_test.go',
 ])fs.copyFileSync(path.join(root,'services/platform/apiserver',name),path.join(directory,'services/platform/apiserver',name));
 const aPath=path.join(directory,tools+'build-ordered-current-consolidated-reference.mjs');
 const aRaw=fs.readFileSync(aPath,'utf8');
 const buildA=()=>spawnSync(process.execPath,['--input-type=module','-e',`import {buildOrderedConsolidatedReference as build} from './${tools}build-ordered-current-consolidated-reference.mjs'; build();`],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_OPTIONS:''}});
 // Poison an already populated exact path before the real inventory merge.
 fs.writeFileSync(aPath,aRaw.replace('addClosureSourcePins(sourceFiles,currentInventory.inputs);',`sourceFiles[${JSON.stringify(externalPaths[2])}]=Buffer.from('conflict'); addClosureSourcePins(sourceFiles,currentInventory.inputs);`));
 const conflict=buildA();
 assert.notEqual(conflict.status,0);
 assert.match(conflict.stderr,/closure source conflict/);
 fs.writeFileSync(aPath,aRaw);
 const devPath=path.join(directory,tools+'build-ordered-current-development.mjs');
 const devRaw=fs.readFileSync(devPath,'utf8');
 fs.writeFileSync(devPath,devRaw.replace('...workerHigherSuccessor.currentSuccessor.sourceInventory,',`...workerHigherSuccessor.currentSuccessor.sourceInventory,${JSON.stringify(externalPaths[2])}:'${'0'.repeat(64)}',`));
 const devConflict=spawnSync(process.execPath,['--input-type=module','-e',`await import('./${tools}build-ordered-current-development.mjs');`],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_OPTIONS:''}});
 assert.notEqual(devConflict.status,0);
 assert.match(devConflict.stderr,/conflicting duplicate/);
 fs.writeFileSync(devPath,devRaw);
 const readerPath=path.join(directory,reader),readerRaw=fs.readFileSync(readerPath,'utf8');
 fs.writeFileSync(readerPath,readerRaw.replace("status:'SOURCE-PROVENANCE-ONLY',installable:false,native:false,executable:false","status:'SOURCE-PROVENANCE-ONLY',installable:false,native:true,executable:false"));
 const promoted=buildA();
 assert.notEqual(promoted.status,0);
 assert.match(promoted.stderr,/source inventory.*(?:shape|status|flags)/);
 const devPromoted=spawnSync(process.execPath,['--input-type=module','-e',`await import('./${tools}build-ordered-current-development.mjs');`],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_OPTIONS:''}});
 assert.notEqual(devPromoted.status,0);
 assert.match(devPromoted.stderr,/source inventory.*(?:shape|status|flags)/);
});

test('A source graph refuses producer, imported-file and ancestor-directory symlinks',t=>{
 read();
 const directory=isolated(t);
 for(const name of ['authorization_worker_consolidated_reference_boundary_test.go','authorization_worker_consolidated_reference_controls_test.go','authorization_worker_consolidated_reference_postgres_test.go'])fs.copyFileSync(path.join(root,'services/platform/apiserver',name),path.join(directory,'services/platform/apiserver',name));
 const buildA=()=>spawnSync(process.execPath,['--input-type=module','-e',`import {buildOrderedConsolidatedReference as build} from './${tools}build-ordered-current-consolidated-reference.mjs'; build();`],{cwd:directory,encoding:'utf8',env:{...process.env,NODE_OPTIONS:''}});
 const baseline=buildA();assert.equal(baseline.status,0,baseline.stderr);
 for(const name of ['build-ordered-current-development.mjs','ordered-current-private.mjs']){
  const relative=tools+name,filename=path.join(directory,relative),raw=fs.readFileSync(filename);
  fs.unlinkSync(filename);fs.symlinkSync(path.join(root,relative),filename);
  const linked=buildA();
  assert.notEqual(linked.status,0,name);
  assert.match(linked.stderr,/source.*(?:symlink|nonregular|topology)/,name);
  fs.unlinkSync(filename);fs.writeFileSync(filename,raw);
 }
 const emitter=path.join(directory,tools+'build-ordered-current-consolidated-reference.mjs'),source=fs.readFileSync(emitter,'utf8');
 const target=path.join(directory,'linked-source-target');
 fs.mkdirSync(target);fs.writeFileSync(path.join(target,'entry.mjs'),'export const sourceOnly=true;\n');
 fs.symlinkSync(target,path.join(directory,tools+'linked-source'),'dir');
 fs.writeFileSync(emitter,source+"\nimport './linked-source/entry.mjs';\n");
 const linkedDirectory=buildA();
 assert.notEqual(linkedDirectory.status,0);
 assert.match(linkedDirectory.stderr,/source.*(?:symlink|nonregular|topology)/);
});
