import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import test from 'node:test';
import {native19WorkerSourceReplay} from './ordered-current-worker-source-replay-v1.mjs';

// Each failure below names a source-authority or replay break. Whole-file
// mutations deliberately test admission, not the semantic gate behind it.
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const artifact = new URL('./ordered-current-worker-source-closure-v1-artifacts/', import.meta.url);
const inputs = {
  optIn:true,
  contractRaw:fs.readFileSync(new URL('effective-contract3.json', artifact)),
  catalogRaw:fs.readFileSync(new URL('effective-catalog1.json', artifact)),
  releaseRaw:fs.readFileSync(new URL('native19-worker-release.json', artifact)),
  graphRaw:fs.readFileSync(new URL('../sql/0080_authorization_worker_readiness_graph.sql', import.meta.url)),
  compilerRaw:fs.readFileSync(new URL('./build-worker-readiness-graph.mjs', import.meta.url)),
  regionsRaw:fs.readFileSync(new URL('./worker-readiness-regions.mjs', import.meta.url)),
  captureSourceRaw:fs.readFileSync(new URL('../../apiserver/authorization_worker_ordered_readiness_capture_test.go', import.meta.url)),
};
const contract=JSON.parse(inputs.contractRaw),catalog=JSON.parse(inputs.catalogRaw),release=JSON.parse(inputs.releaseRaw);
let implementation={};
try { implementation=await import('./ordered-current-worker-higher-source-replay-v1.mjs'); }
catch(error) { if(error.code!=='ERR_MODULE_NOT_FOUND')throw error; }
const api=name=>{assert.equal(typeof implementation[name],'function',`missing source successor ${name}`);return implementation[name];};
const graph=JSON.parse(inputs.graphRaw.toString().split('$higher_records$')[1]);
const base=JSON.parse(inputs.graphRaw.toString().split('$readiness_records$')[1]);
let prepared,compiled,closed;
const prepare=()=>prepared??=api('prepareWorkerHigherUniverse')({contract,catalog,release,graph});
const compile=()=>compiled??=api('compileWorkerHigherGraph')({...prepare(),workerChecksum:release.checksum});
const positive=()=>closed??=api('workerHigherSourceReplay')(inputs);
const targets=[
 ['zasp_temporal68.predecessor_ready(text,text)',119914,'c6eed3d3fd1aad9eb53690e2a1e364dc576e1910224af2fec91813189c944bb6'],
 ['zasp_temporal68.ready(text,text)',7871,'f9557bcb94debad45801d1715181e4592c47be92fa79005b3c811b6281757f83'],
 ['zasp_temporal77.base67_fingerprint()',117393,'ae6456305a2ffc9aa054dd32e085fd7595859714c1cdf56946c8d837c082e907'],
 ['zasp_temporal78.ready(text,text)',25122,'a6a988fd4b42b6c63dc66b34a2de51476a0bfe9452ef4536b061206d120999ac'],
];

test('successor is opt-in and refuses before reading missing inputs',()=>{
 assert.deepEqual(api('workerHigherSourceReplay')(),{version:'worker-higher-source-replay-v1',status:'refused',reason:'explicit source-only opt-in required',sourceClosed:false,native:false,installable:false,executable:false});
});
for(const field of ['contractRaw','catalogRaw','releaseRaw','graphRaw','compilerRaw','regionsRaw','captureSourceRaw'])test(`rejects changed admitted ${field} byte before replay`,()=>{
 const changed=Buffer.from(inputs[field]);changed[changed.length-1]^=1;
 assert.throws(()=>api('workerHigherSourceReplay')({...inputs,[field]:changed}),/input authority/);
});
test('reconstructs 82 complete original records in source order and complete typed frames',()=>{
 const value=prepare();assert.equal(value.originals.length,82);assert.equal(new Set(value.originals.map(x=>x.signature)).size,82);
 // Original capture predicate: all zasp_ schema callables plus public.zasp_.
 // This includes 2,282 names/signatures, not just the 82 selected originals.
 assert.equal(value.functions.length,2282);
 assert.ok(value.functions.some(x=>x.identity==='zasp_temporal75."references"(text,integer)'));
 assert.ok(!value.functions.some(x=>x.identity==='public.digest(bytea,text)'));
 assert.deepEqual(value.originals.map(x=>x.signature),graph.records.map(x=>x.signature));
 assert.deepEqual(value.frameCounts,{sqlInvoker:58,sqlDefiner:13,plpgsqlDefiner:11});
 assert.equal(value.base67.definitionSHA256,'1c00ffffdf90307f3b99bc9eae0645df72442cebc58f34df6a873536cf1a6e92');
 assert.equal(value.base67.sourceSHA256,'604cb02288a00024e6816728fdf954988a2224cd1a7e31fc601294fb2503acd8');
 assert.deepEqual(value.base67.anchorCounts,[2,1]);
});
test('missing and duplicate source identities cannot be guessed or silently overwritten',()=>{
 const missing=structuredClone(contract);missing.nodes=missing.nodes.filter(x=>x.identity!=='zasp_authorization80_worker.catalog_ready()');
 assert.throws(()=>api('prepareWorkerHigherUniverse')({contract:missing,catalog,release,graph}),/unique contract/);
 const duplicate=structuredClone(catalog);duplicate.functions.push(duplicate.functions[0]);
 assert.throws(()=>api('prepareWorkerHigherUniverse')({contract,catalog:duplicate,release,graph}),/duplicate callable/);
 const saved=structuredClone(catalog);saved.saved_functions.push(saved.saved_functions.find(x=>x.schema==='zasp_authorization80_worker'&&x.signature===targets[0][0]));
 assert.throws(()=>api('prepareWorkerHigherUniverse')({contract,catalog:saved,release,graph}),/unique saved/);
});
test('87 checked saved dependency origins keep 82 precedence and five explicit exclusions',()=>{
 const value=prepare();assert.equal(value.dependencyProvenance?.records.length,87);
 assert.deepEqual(value.dependencyProvenance.excluded.map(x=>x.signature).sort(),[
  'zasp_temporal68.progress(jsonb)','zasp_temporal69.inspect(jsonb)','zasp_temporal69.inspect_message(jsonb)','zasp_temporal69.stop(jsonb)',
  'zasp_temporal74.activate(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)',
 ].sort());
 for(const record of value.dependencyProvenance.records){const fn=value.functions.find(x=>x.signature===record.signature);assert.equal(fn.originalAdmitted,false);assert.equal(sha(fn.definition),record.savedDefinitionSHA256);assert.equal(sha(fn.source),record.savedSourceSHA256);}
 const mutated=structuredClone(catalog),saved=mutated.saved_functions.find(x=>x.schema==='zasp_authorization80_worker'&&x.signature==='zasp_temporal69.ready(text,text)');
 assert.ok(saved);saved.definition+=' attempted body override';
 const changed=api('prepareWorkerHigherUniverse')({contract,catalog:mutated,release,graph});
 assert.equal(changed.originals.find(x=>x.signature==='zasp_temporal69.ready(text,text)').definition,value.originals.find(x=>x.signature==='zasp_temporal69.ready(text,text)').definition);
});
test('dependency-only saved body header owner ACL and duplicate provenance drift refuses',()=>{
 for(const mutate of [s=>s.definition+=' ',s=>s.definition=s.definition.replace('RETURNS text','RETURNS boolean'),s=>s.owner='bad_owner',s=>s.acl=null]){
  const changed=structuredClone(catalog),saved=changed.saved_functions.find(x=>x.schema==='zasp_authorization80_worker'&&x.signature==='zasp_temporal69.fingerprint()');mutate(saved);
  assert.throws(()=>api('prepareWorkerHigherUniverse')({contract,catalog:changed,release,graph}),/dependency provenance/);
 }
 const changed=structuredClone(catalog);changed.saved_functions.push(changed.saved_functions.find(x=>x.schema==='zasp_authorization80_worker'&&x.signature==='zasp_temporal69.fingerprint()'));
 assert.throws(()=>api('prepareWorkerHigherUniverse')({contract,catalog:changed,release,graph}),/dependency provenance unique/);
 const changedRelease={...release,source:release.source.replace('DO $ordered69_retirement$','DO $changed$')};
 assert.throws(()=>api('prepareWorkerHigherUniverse')({contract,catalog,release:changedRelease,graph}),/dependency provenance recipe/);
});
test('newly selected provenance-only original cannot supply an expanded expression',()=>{
 const value=prepare(),functions=structuredClone(value.functions),fn=functions.find(x=>x.signature==='zasp_temporal69.fingerprint()');
 assert.equal(fn.originalAdmitted,false);fn.source='SELECT zasp_authorization80_worker.catalog_ready()';
 assert.throws(()=>api('compileWorkerHigherGraph')({...value,functions,workerChecksum:release.checksum}),/unadmitted higher original/);
});
test('public mapping must agree with the qualified identity and full definition header',()=>{
 const mutated=structuredClone(catalog),row=mutated.functions.find(x=>x.identity==='public.zasp_production_runtime_sessions_live_fingerprint()');
 row.identity=row.identity.replace('public.','zasp_false.');
 assert.throws(()=>api('prepareWorkerHigherUniverse')({contract,catalog:mutated,release,graph}),/identity header|unique catalog/);
});
test('every owner ACL and typed frame disagreement rejects before source closure',()=>{
 for(const [field,value] of [['owner','bad_owner'],['acl',null],['language','plpgsql'],['volatility','v'],['strict',true],['parallel','s'],['security_definer',false],['config',[]],['arguments','c oid, f text'],['result','text'],['cost',101],['rows',1],['leakproof',true]]){
  const mutated=structuredClone(contract);mutated.nodes.find(x=>x.identity===targets[1][0])[field]=value;
  assert.throws(()=>api('prepareWorkerHigherUniverse')({contract:mutated,catalog,release,graph}),/typed frame|definition header/,field);
 }
});
test('changed original body full definition or named-normalization pin rejects',()=>{
 for(const field of ['definition','source']){
  const mutated=structuredClone(contract);mutated.nodes.find(x=>x.identity==='zasp_authorization80_worker.catalog_ready()')[field]+=' ';
  assert.throws(()=>api('prepareWorkerHigherUniverse')({contract:mutated,catalog,release,graph}),/source authority|body|definition/,field);
 }
 const mutated=structuredClone(graph);mutated.records[0].sourceHash='a'.repeat(64);
 assert.throws(()=>api('prepareWorkerHigherUniverse')({contract,catalog,release,graph:mutated}),/source authority/);
});
test('base67 recipe is source-span bound and rejects either 2+1 anchor count change',()=>{
 const original=catalog.saved_functions.find(x=>x.schema==='zasp_authorization80_worker'&&x.signature===targets[2][0]).definition;
 for(const needle of ['pg_get_functiondef(p.oid)','ELSE public.zasp_sa_multistep_function_identity(p.oid) END']){
  assert.throws(()=>api('deriveWorkerBase67Original')(original.replace(needle,'changed'),release.source),/anchor|saved original/);
 }
 const spanAnchor="signature='zasp_temporal77.base67_fingerprint()';\n needle:='pg_get_functiondef(p.oid)';";
 assert.equal(release.source.split(spanAnchor).length,2);
 assert.throws(()=>api('deriveWorkerBase67Original')(original,release.source.replace(spanAnchor,()=>spanAnchor.replace('pg_get_functiondef(p.oid)','changed'))),/recipe span/);
});
test('whole callable universe exposes overload ambiguity outside the 82-node roster',()=>{
 const value=prepare(),functions=structuredClone(value.functions),leaf=functions.find(x=>x.signature==='zasp_authorization80_worker.catalog_ready()');
 functions.push({...leaf,signature:'zasp_authorization80_worker.catalog_ready(text)',arguments:'v text'});
 assert.throws(()=>api('compileWorkerHigherGraph')({...value,functions,workerChecksum:release.checksum}),/ambiguous/);
});
test('complete higher and base replay records queries edits ordering and joined SQL match admitted graph',()=>{
 const value=compile();assert.deepEqual(value.higher.records,graph.records);assert.deepEqual(value.higher.regions,graph.regions);assert.deepEqual(value.records,base);
 assert.deepEqual(value.higher.regions.map(x=>x.signature),[targets[0][0],targets[1][0],targets[3][0]]);
 assert.deepEqual(value.higher.regions.map(x=>x.expanded.length),[67,7,30]);assert.deepEqual(value.higher.regions.map(x=>x.materialized.length),[47,4,16]);
 assert.equal(value.records.length,52);assert.equal(value.records.filter(x=>x.cte!==null).length,48);assert.equal(value.records.reduce((n,x)=>n+x.edits.length,0),61);
 assert.equal(value.sql,inputs.graphRaw.toString());assert.equal(sha(value.sql),'530acbf49171985068c55928cb4f0a89b1c383ab223effd533af9450375b5ef6');
});
test('edit span text order root order and lazy fallback mutations fail the complete graph proof',()=>{
 const value=compile();
 for(const mutate of [x=>x.records.at(-1).edits[0].start++,x=>x.records.at(-1).edits[0].text+=' ',x=>x.records.find(r=>r.edits.length>1).edits.reverse(),x=>x.higher.regions.reverse(),x=>x.higher.regions[0].expanded.pop(),x=>x.higher.regions[0].materialized.pop(),x=>x.higher.regions[0].expanded.find(r=>r.copyEdits.length).copyEdits[0].to+=' ',x=>x.higher.regions[0].query=x.higher.regions[0].query.replace('ELSE NULL','ELSE false'),x=>x.higher.regions[2].prefix='',x=>x.sql+=' ']){
  const changed=structuredClone(value);mutate(changed);assert.throws(()=>api('proveWorkerHigherGraph')(changed,inputs.graphRaw),/graph equivalence/);
 }
});
test('an unknown explicit application call in an original refuses instead of vanishing',()=>{
 const value=prepare(),functions=structuredClone(value.functions);
 functions.find(x=>x.signature===targets[2][0]).source+=' + zasp_unadmitted.missing_original()';
 assert.throws(()=>api('compileWorkerHigherGraph')({...value,functions,workerChecksum:release.checksum}),/missing admitted application callable/);
});
test('inserted source call and lost selected node cannot disappear in a narrowed graph',()=>{
 const value=prepare();
 for(const [mutate,pattern] of [[f=>f.splice(f.findIndex(x=>x.signature==='zasp_authorization80_worker.projected79()'),1),/missing admitted application callable/],[f=>{f.find(x=>x.signature===targets[2][0]).source+=' + zasp_temporal68.ready(c,f)';},/readiness cycle/]]){
  const functions=structuredClone(value.functions);mutate(functions);
  assert.throws(()=>{const result=api('compileWorkerHigherGraph')({...value,functions,workerChecksum:release.checksum});api('proveWorkerHigherGraph')(result,inputs.graphRaw);},pattern);
 }
});
test('scalar shadow procedural wrapper and original NULL guards cannot be weakened',()=>{
 const value=prepare();
 for(const [signature,change] of [
  ['zasp_authorization79.ready(text)',s=>s.replace('SELECT ','SELECT c AS c, ')],
  ['zasp_temporal69.ready(text,text)',s=>s.replace('BEGIN','BEGIN PERFORM 1;')],
  [targets[0][0],s=>s.replace('IF c IS DISTINCT FROM','IF c =')],
  [targets[3][0],s=>s.replace('SELECT c=','SELECT COALESCE(c=')],
 ]){
  const functions=structuredClone(value.functions);functions.find(x=>x.signature===signature).source=change(functions.find(x=>x.signature===signature).source);
  assert.throws(()=>api('compileWorkerHigherGraph')({...value,functions,workerChecksum:release.checksum}),/parameter shadow|non-scalar wrapper|static IF anchor|nullable root guards/);
 }
});
test('literal-safe one-body replacement preserves all four predecessor dollar pairs',()=>{
 const value=prepare(),region=compile().higher.regions[0],original=value.originals.find(x=>x.signature===targets[0][0]);
 const replacement=region.prefix+'('+region.query+')'+region.suffix;
 assert.equal((region.query.match(/\$\$/g)??[]).length,4);
 const literal=api('replaceWorkerBodyLiteral')(original.definition,original.source,replacement);
 const broken=original.definition.replace(original.source,'\n'+replacement+'\n');
 assert.equal(literal.length-broken.length,4);assert.equal((literal.match(/\$\$/g)??[]).length,4);assert.equal((broken.match(/\$\$/g)??[]).length,0);
 const bind=s=>s.replaceAll('-- worker catalog body digest','28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016').replaceAll('-- worker profile checksum',release.checksum);
 assert.equal(Buffer.byteLength(bind(literal)),119914);assert.equal(sha(bind(literal)),targets[0][2]);
 assert.equal(Buffer.byteLength(bind(broken)),119910);assert.equal(sha(bind(broken)),'874c6293c924ba3b9a15d2bfe787cecbe3ce7d573100031e23914cbca0396043');
 assert.throws(()=>api('replaceWorkerBodyLiteral')(original.definition+original.source,original.source,replacement),/one occurrence/);
 assert.throws(()=>api('replaceWorkerBodyLiteral')(original.definition,'absent',replacement),/one occurrence/);
});
test('all four complete source-built definitions and frames source-close only after every gate',()=>{
 const value=positive();assert.equal(value.sourceClosed,true);assert.equal(value.native,false);assert.equal(value.installable,false);assert.equal(value.executable,false);
 assert.equal(value.accepted.length,4);assert.equal(value.registration.status,'refused');assert.equal(value.registration.ruleId,'worker-line-2');
 for(const [identity,bytes,digest] of targets){
  const fact=value.accepted.find(x=>x.identity===identity),row=catalog.functions.find(x=>x.identity===identity);
  assert.equal(fact.status,'sourceClosed');assert.equal(Buffer.byteLength(fact.replacementDefinition),bytes);assert.equal(sha(fact.replacementDefinition),digest);assert.equal(fact.replacementDefinition,row.definition);
  assert.equal(fact.replacementFactSHA256,sha(JSON.stringify({acl:row.acl,definition:row.definition,owner:row.owner})));
  assert.equal(fact.body,row.definition.split('$function$')[1]);
  for(const key of ['owner','acl','language','volatility','strict','parallel','security_definer','config','arguments','result','cost','rows','leakproof'])assert.deepEqual(fact.frame[key],row[key]);
 }
 assert.equal(value.inputLedger.graphSHA256,'530acbf49171985068c55928cb4f0a89b1c383ab223effd533af9450375b5ef6');
 assert.equal(value.inputLedger.dependencyProvenance?.records.length,87);
 assert.equal(value.inputLedger.dependencyProvenance.excluded.length,5);
 assert.equal(value.inputLedger.callableUniverse.applicationFunctions,2282);
 assert.equal(value.baseReplay.query,value.accepted.find(x=>x.identity===targets[2][0]).body.trim());
});
test('historical default remains 13 accepted four higher refused and registration refused',()=>{
 const old=native19WorkerSourceReplay();assert.equal(old.accepted.length,13);assert.equal(old.refused.length,4);assert.deepEqual(old.refused.map(x=>x.identity).sort(),targets.map(x=>x[0]).sort());assert.equal(old.registration.status,'refused');
});
