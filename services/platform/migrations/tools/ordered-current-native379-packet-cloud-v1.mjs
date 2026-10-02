// Fixed cloud source successor only; no PostgreSQL, publication or native admission.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const fail=message=>{throw Error('ordered-current native379 cloud '+message);};
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const canonical=value=>JSON.stringify(value,(_,v)=>{
 if(['undefined','function','symbol','bigint'].includes(typeof v)||(typeof v==='number'&&!Number.isFinite(v)))fail('non-JSON authority value');
 return v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v;
});
const same=(a,b)=>canonical(a)===canonical(b);
const literal=value=>"'"+value.replaceAll("'","''")+"'";
const packetModulePins={"ordered-current-cloud-source-copy-v1.mjs":"b27db0c0c4ee8eae75488371fb003f77f865977ddf88db23191e83cecce1d2d4","ordered-current-native379-semantics-v1.mjs":"66778c48aa109b4dc8dcdcf0b45548584ba8c079107122784faa4ee319d471c9","ordered-current-native379-coverage-v1.mjs":"1e1ca6a042bc1b2ae3d2d3991340101bc5145ddb43e8b55f5f15f6f31433eea5","ordered-current-native379-entry-frame-cloud-v1.mjs":"0fba6954f79ab8af7592fc2a414134b6d820dc40f36433757ce65f3baa9af99a"};
const outputPins={"effective-contract4.json":"06210a2df2f96445b2e864812c83672a46a747c57ffc5b8c4ba380c23e1ab7b0","development-manifest.json":"4820af14e63ea69b9285e5c69463436fe4ce01ef3a39111b7cbefc8adc2897f9","development-module.sql":"4add5c6dff44aa768bd524c357bc0310ee69c5833a6f9821df84d2b1376e2c74","development-checkpoint.json":"905664791351c9714bfa4769ab94a6c11c6f1744c11ff56c165536fc71d13705","development-collector.sql":"97f6547ee1a61a8af8c82dbf3bdba38a35b0df3eb60cd69c0ba3743d7bf6446f","development-admission.sql":"999db012258f1cd04880c8fd5451bd41d4317556bb00c9dec15d493b257ba3ef","consolidated-reference-contract.json":"d7e2149d8be0d1e04bd1f18e571bf55ffe4458cbe380bc1f406d3ef49aae02ff","consolidated-reference-select.sql":"23f8a023d001acbf0c257c653335603864eead2b9f963ebdbafc03e266577b57"};
function compilerAuthority(){
 for(const [name,pin]of Object.entries(packetModulePins)){
  const file=fileURLToPath(new URL(name,import.meta.url));
  for(let current=file;;current=path.dirname(current)){
   const stat=fs.lstatSync(current);if(stat.isSymbolicLink()||(current===file?!stat.isFile():!stat.isDirectory()))fail('compiler topology');
   if(path.dirname(current)===current)break;
  }
  if(sha(fs.readFileSync(file))!==pin)fail('compiler source bytes');
 }
}
const generatorNames=['ordered-current-native379-packet-cloud-v1.mjs','ordered-current-native379-packet-cloud-v1.test.mjs','ordered-current-native379-entry-frame-cloud-v1.mjs','ordered-current-native379-entry-frame-cloud-v1.test.mjs'];
function generatorSources(){
 const pins={};
 for(const name of generatorNames){
  const file=fileURLToPath(new URL(name,import.meta.url));
  for(let current=file;;current=path.dirname(current)){
   const stat=fs.lstatSync(current);if(stat.isSymbolicLink()||(current===file?!stat.isFile():!stat.isDirectory()))fail('generator topology');
   if(path.dirname(current)===current)break;
  }
  if(fs.lstatSync(file).size>33554432)fail('generator byte cap');
  const raw=fs.readFileSync(file);if(raw.length>33554432)fail('generator consumed byte cap');pins[name]=sha(raw);
 }
 return pins;
}
// These are current source metadata, not self-referential expected output
// truth. Independent review freezes their bytes; every cached use rechecks it.
const generatorSourcePins=generatorSources();
function verifyGeneratorSources(){if(!same(generatorSources(),generatorSourcePins))fail('generator source drift');}
compilerAuthority();
const {buildOrderedCurrentCloudSourceCopyV1,assertOrderedCurrentCloudSourceCopyV1}=await import('./ordered-current-cloud-source-copy-v1.mjs');
const {buildNative379SemanticControls,native379SQLProgram}=await import('./ordered-current-native379-semantics-v1.mjs');
const {buildNative379CatalogCoverage}=await import('./ordered-current-native379-coverage-v1.mjs');
const {buildOrderedCurrentNative379EntryFrameCloudV1,assertOrderedCurrentNative379EntryFrameCloudV1}=await import('./ordered-current-native379-entry-frame-cloud-v1.mjs');
compilerAuthority();
const taskPins={task1:'08bb1eb3dc0c0bf98f3ac8d3dc643ca675e0c7d5c81e27cd2f087685cbbd4ed8',task2:'7027b418bd3141c21acc575deb037e3c26d43713ea2c3e90884caf05f666cd29',task3:'1dea4521a26a1760742a9526ed5d41687d479f4f7b08dd40592b612d8de5af96',task4:'c53be34495eb18c6194a7f877fd4bd4434c087c9a9c5e80b8ec1e8b48a30d773'};
const phaseSpecs=[['preflight',1024,1048576,60000],['pristine-truth',12000,33554432,180000],['drift',16000,33554432,240000],['forged-entry',2048,4194304,60000],['null-error-lazy-demand',4096,8388608,120000],['frame-restoration',2048,4194304,60000],['cleanup-result',1024,1048576,30000]];
const limits={maxRows:38240,maxBytes:85983232,maxMilliseconds:750000,maxPacketBytes:33554432,sqlMilliseconds:10000,lockMilliseconds:3000,cleanupMilliseconds:3000,overflow:'abort-and-publish-nothing'};
const dimensions=['role','search_path','timezone','read_only','transaction','advisory_locks','schema_locks','catalog'];
const buildRuntime={version:'v22.23.1',platform:'linux',arch:'x64',executableSHA256:'93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068',executablePolicy:'resolved-process-executable-regular-file-exact-sha256'};
function wholeSource(contract,identity){
 const node=contract.nodes.find(n=>n.identity===identity);if(!node)fail('source identity '+identity);
 if(sha(node.source)!==node.sourceSHA256)fail('source body authority');
 return {sourceIdentity:identity,sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,start:0,end:Buffer.byteLength(node.source),siteSHA256:node.sourceSHA256,scope:'whole-original-source-boundary',frame:{owner:node.owner,acl:node.acl,config:node.config,securityDefiner:node.security_definer,language:node.language}};
}
function sourceForRule(rule,contract,module){
 const [prefix,family]=rule.id.split(':');
 if(rule.id.startsWith('private-')){
  const marker='CREATE FUNCTION zasp_authorization80_ordered_current.catalog(expected_manifest text)',start=module.indexOf(marker),end=module.indexOf('$catalog$;',start)+10;
  if(start<0||end<=start)fail('source-built catalog declaration');
  return {sourceIdentity:'zasp_authorization80_ordered_current.catalog(text)',sourceSHA256:sha(module),definitionSHA256:sha(module.slice(start,end)),start,end,siteSHA256:sha(module.slice(start,end)),scope:'source-built-module-declaration',frame:{owner:'zasp_discovery_authority',searchPath:'pg_catalog'}};
 }
 let identity;
 if(prefix==='worker'||prefix==='worker-edge')identity=`zasp_authorization80_worker.${family}()`;
 else if(prefix==='runtime')identity=`public.zasp_production_runtime_${family}_live_fingerprint()`;
 else if(prefix==='product')identity=`public.zasp_production_${family}_live_fingerprint()`;
 else if(prefix==='temporal')identity=`zasp_temporal${family}()`;
 else if(prefix==='public')identity=`public.zasp_${family}_live_fingerprint()`;
 else if(prefix==='temporal72')identity=family==='precision-function'?'zasp_temporal72.retained_precision_fingerprint()':'zasp_temporal72.retained_execution_fingerprint()';
 else if(prefix==='inventory-fields')identity='public.zasp_inventory_live_fingerprint()';
 else if(prefix==='role-profile')identity='zasp_temporal68.ready(text,text)';
 else if(rule.id==='native-memberships')identity='zasp_authorization80_worker.catalog_ready()';
 else if(rule.id.startsWith('worker-line-'))identity='zasp_authorization80_worker.catalog_ready()';
 else fail('unmapped rule family '+rule.id);
 return wholeSource(contract,identity);
}
function build(outputs,sourceResult){
 const entryFrameInput={contractRaw:outputs['effective-contract4.json'],moduleRaw:outputs['development-module.sql'],manifestRaw:outputs['development-manifest.json'],admissionRaw:outputs['development-admission.sql']};
 const entryFrame=buildOrderedCurrentNative379EntryFrameCloudV1(entryFrameInput);assertOrderedCurrentNative379EntryFrameCloudV1(entryFrame,entryFrameInput);
 const checkpoint=JSON.parse(outputs['development-checkpoint.json']),manifest=JSON.parse(outputs['development-manifest.json']);
 const evaluator=checkpoint.dormantEvaluator,contract=JSON.parse(outputs['effective-contract4.json']),module=outputs['development-module.sql'].toString();
 if(sha(canonical(evaluator))!==taskPins.task4||evaluator.sourceContracts.precision.packetSHA256!==taskPins.task1||evaluator.sourceContracts.worker.packetSHA256!==taskPins.task2||evaluator.sourceContracts.current.packetSHA256!==taskPins.task3)fail('Task1-4 authority');
 if(evaluator.installable!==false||evaluator.nativeVerified!==false||manifest.installable!==false||manifest.facts.length!==10052||evaluator.rules.length!==379||new Set(evaluator.rules.map(r=>r.id)).size!==379||evaluator.sourceInventory.sites.length!==565||evaluator.sourceInventory.unclassified!==0)fail('dormant inventory');
 const controls=[],facts=manifest.facts,byRule=new Map(evaluator.rules.map(r=>[r.id,facts.filter(f=>f.kind!=='build'&&JSON.parse(f.identity)[0]===r.id)]));
 const restoration={operation:'rollback-and-compare-exact-pre-state',dimensions,beforeNextProbe:true,timeoutIsDenial:false};
 function add(id,phase,category,rule,mutation,expected,sourceSite=sourceForRule(rule,contract,module)){
  const rows=byRule.get(rule.id),fact=mutation.identity?rows.find(row=>row.identity===mutation.identity):rows[0];
  controls.push({id,phase,category,ruleIds:[rule.id],facts:fact?[{kind:fact.kind,identity:fact.identity,factSHA256:sha(canonical(fact.fact))}]:[],sourceSite,mutation,mutationSHA256:sha(canonical(mutation)),expected:{...expected,firstError:expected.firstError??null},restoration:structuredClone(restoration)});
 }
 // Every descriptor gets an exact-key comparator challenge. These are expected
 // storage tampering controls, not claims of catalog mutation/native parity.
	 for(const rule of evaluator.rules){
  const selected=byRule.get(rule.id);if(selected.length!==rule.expectedFacts)fail('rule fact cardinality '+rule.id);
  const mutation=selected.length?{operation:'delete-expected-row',kind:selected[0].kind,identity:selected[0].identity,sql:`DELETE FROM zasp_authorization80_ordered_current.expected WHERE kind=${literal(selected[0].kind)} AND identity=${literal(selected[0].identity)}`}:{operation:'insert-extra-expected-row',kind:rule.kind,identity:canonical([rule.id,'native379-extra']),fact:{},sql:`INSERT INTO zasp_authorization80_ordered_current.expected(kind,identity,fact) VALUES(${literal(rule.kind)},${literal(canonical([rule.id,'native379-extra']))},'{}'::jsonb)`};
  mutation.sqlSHA256=sha(mutation.sql);
	  add('rule:'+rule.id,'forged-entry','expected-key-set',rule,mutation,{outcome:'refuse',boundary:'complete-key-set-equality',sqlState:null});
	 }
	 // The per-rule key-set challenges use an exact one-key snapshot instead of
	 // repeatedly hashing the full expected table. Each challenge is
	 // still one owned rollback transaction and must prove that its selected key
	 // is byte-for-byte restored before the next control starts.
	 for(const c of controls.filter(c=>c.category==='expected-key-set')){
	  const kind=literal(c.mutation.kind),identity=literal(c.mutation.identity);
	  const snapshot=`SELECT encode(sha256(convert_to(COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.kind COLLATE "C",r.identity COLLATE "C") FROM zasp_authorization80_ordered_current.expected r WHERE r.kind=${kind} AND r.identity=${identity}),'[]'::jsonb)::text,'UTF8')),'hex') AS snapshot`;
	  const probe=`SELECT zasp_authorization80_ordered_current.catalog(${entryFrame.entry.manifestLiteral}) AS value`;
	  const step=(id,role,sql,expected)=>({id,role,sql,sqlSHA256:sha(sql),expected});
	  c.mutation.operands={kind:c.mutation.kind,identity:c.mutation.identity,operation:c.mutation.operation};
	  c.program={format:'native379-sql-program-v1',transaction:'owned-read-write-rollback',connection:'same-owned-session',steps:[
	   step('setup-session','zasp_test',"RESET ROLE; SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE; SET SESSION search_path TO pg_catalog,public; SET SESSION TimeZone TO 'UTC'",{outcome:'command-success'}),
	   step('snapshot-before','zasp_test',snapshot,{outcome:'capture',key:'before'}),step('begin','zasp_test','BEGIN',{outcome:'command-success'}),
	   step('mutate','zasp_test',c.mutation.sql,{outcome:'command-success'}),step('source-frame','zasp_test',"SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=pg_catalog; SET LOCAL TimeZone='UTC'",{outcome:'command-success'}),
	   step('probe-savepoint','zasp_discovery_authority','SAVEPOINT native379_probe',{outcome:'command-success'}),step('admit-before-selector','zasp_discovery_authority',entryFrame.entry.independentAdmission.sql,{outcome:'rows',rows:[{admitted:true}],sqlState:null}),step('probe','zasp_discovery_authority',probe,{outcome:'rows',rows:[{value:false}],sqlState:null}),
	   step('recover-probe','zasp_discovery_authority','ROLLBACK TO SAVEPOINT native379_probe',{outcome:'command-success'}),step('restore','zasp_discovery_authority','ROLLBACK',{outcome:'command-success'}),
	   step('snapshot-after','zasp_test',snapshot,{outcome:'equal-captured',key:'before'}),
	  ]};
	  c.restoration={operation:'rollback-and-compare-exact-pre-state',dimensions,beforeNextProbe:true,timeoutIsDenial:false,snapshotSQL:snapshot,restoreSQL:'ROLLBACK',assertionSQL:snapshot,assertion:'exact-json-row-equality-to-snapshot-before',protocolTransactionStatusAfter:'I'};
	  c.mutationSHA256=sha(canonical(c.mutation));
	 }
 const get=id=>{const rule=evaluator.rules.find(r=>r.id===id);if(!rule)fail('control rule '+id);return rule;};
 // Fixed catalog DDL/DML. The fixture executes each SQL string in a separate
 // owned rollback transaction and checks restoration before continuing.
 const fieldCases=[
  ['body','worker-line-5','definition'],['owner','worker-line-5','owner'],['acl','worker-line-5','acl'],
  ['default-acl','worker-line-6','acl'],['config','runtime:acceptance:function','config_text_or_empty'],
  ['rls','worker-line-6','row_security'],['constraint','worker-line-8','definition'],['index','worker-line-20','definition'],
  ['trigger','worker-line-10','enabled'],['saved-definition','worker-line-11','definition'],['registration','worker-line-2','fingerprint'],
 ];
 for(const [category,id,field]of fieldCases){
  const rule=get(id),fact=category==='rls'||category==='default-acl'?byRule.get(id).find(f=>f.fact.kind==='r'):byRule.get(id)[0];if(!fact||!Object.hasOwn(fact.fact,field))fail('field mutation '+id+':'+field);
  const target=JSON.parse(fact.identity)[1],before=fact.fact[field];
  const ddl={
   body:()=>fact.fact.definition.replace('AS $function$\n','AS $function$\n-- native379-body-drift\n'),
   owner:()=>`ALTER FUNCTION ${target} OWNER TO zasp_security_agent_worker`,
   acl:()=>`GRANT EXECUTE ON FUNCTION ${target} TO PUBLIC`,
   'default-acl':()=>`GRANT ALL ON TABLE ${target} TO zasp_discovery_authority`,
   config:()=>`ALTER FUNCTION ${target} SET search_path TO pg_catalog`,
   rls:()=>`ALTER TABLE ${target} ${before?'DISABLE':'ENABLE'} ROW LEVEL SECURITY`,
   constraint:()=>{const [relation,name]=JSON.parse(target);return `ALTER TABLE ${relation} DROP CONSTRAINT ${name}`;},
   index:()=>`ALTER INDEX ${target} RENAME TO native379_index_drift`,
   trigger:()=>{const [relation,name]=JSON.parse(target);return `ALTER TABLE ${relation} DISABLE TRIGGER ${name}`;},
   'saved-definition':()=>`ALTER TABLE zasp_authorization80_worker.predecessor_functions DISABLE TRIGGER USER; UPDATE zasp_authorization80_worker.predecessor_functions SET definition=definition||E'\\n-- native379-saved-drift' WHERE signature='zasp_attack_lab_execution_live_fingerprint()'`,
   registration:()=>`ALTER TABLE zasp_authorization80_worker.registration DISABLE TRIGGER USER; UPDATE zasp_authorization80_worker.registration SET fingerprint=repeat('0',64) WHERE singleton`,
  };
  const sql=ddl[category]();
  add('catalog:'+category,'drift',category,rule,{operation:'execute-fixed-catalog-sql',kind:fact.kind,identity:fact.identity,field,before,sql,sqlSHA256:sha(sql)},{outcome:'refuse',boundary:'fact-value-or-key-set-equality',sqlState:null});
 }
 for(const [category,operation]of [['addition','add-selected-catalog-object'],['missing-dependency','remove-selected-dependency']]){
  const rule=get('worker-line-5'),fact=byRule.get(rule.id)[0],target=JSON.parse(fact.identity)[1];
  const sql=category==='addition'?"CREATE FUNCTION zasp_authorization80_worker.native379_probe() RETURNS text LANGUAGE sql AS 'SELECT NULL::text'":`ALTER FUNCTION ${target} RENAME TO native379_missing_dependency`;
  add('catalog:'+category,'drift',category,rule,{operation,kind:fact.kind,identity:fact.identity,sql,sqlSHA256:sha(sql),probeSQL:category==='missing-dependency'?`SELECT ${literal(target)}::regprocedure`:null},{outcome:category==='missing-dependency'?'error':'refuse',boundary:category==='missing-dependency'?'selected-regprocedure-binding':'complete-key-set-equality',sqlState:category==='missing-dependency'?'42883':null,firstError:category==='missing-dependency'?{sourceIdentity:target,stage:'selected-regprocedure-binding',sqlState:'42883'}:null});
 }
 for(const c of controls.filter(c=>c.phase==='drift')){
  c.mutation.operands={ruleIds:c.ruleIds,facts:c.facts,field:c.mutation.field??null,before:c.mutation.before??null};
  const probe=c.mutation.probeSQL??`SELECT CASE WHEN (${entryFrame.entry.independentAdmission.sql}) THEN zasp_authorization80_ordered_current.catalog(${entryFrame.entry.manifestLiteral}) ELSE false END AS value`;
  native379SQLProgram(c,{setup:c.mutation.sql,probe,expected:c.expected.outcome==='error'?{outcome:'error',sqlState:c.expected.sqlState}:{outcome:'rows',rows:[{value:false}],sqlState:null},objects:{schemas:['public','zasp_authorization80_worker','zasp_authorization80_runtime']},searchPath:'pg_catalog'});
  c.mutationSHA256=sha(canonical(c.mutation));
 }
 const catalogCoverage=buildNative379CatalogCoverage({rules:evaluator.rules,byRule,sourceForRule:rule=>sourceForRule(rule,contract,module),entry:entryFrame.entry});
 controls.push(...catalogCoverage.controls,...entryFrame.controls);
 controls.push(...buildNative379SemanticControls({contract,checkpoint}));
 if(new Set(controls.map(c=>c.id)).size!==controls.length)fail('duplicate control');
 const provenance=facts.find(f=>f.kind==='build').fact;
 return {format:'ordered-current-native379-packet-cloud-v1',status:'NATIVE-PARITY-PENDING',installable:false,nativeVerified:false,captureAuthority:false,
  authority:{...taskPins,sourceReceipt:structuredClone(sourceResult.receipt),packetModules:packetModulePins,generatorSources:{...generatorSourcePins},generatorSourceStatus:'SOURCE-PROVENANCE-ONLY',generated:outputPins,source:'fixed-cloud-v1-171-input-regeneration-only'},
  identity:{serverVersionNum:180003,postgres:provenance.postgres,pgcrypto:'1.4'},buildRuntime,rules:evaluator.rules,expectedFacts:facts,sourceInventory:evaluator.sourceInventory,
  phases:phaseSpecs.map(([id,maxRows,maxBytes,maxMilliseconds])=>({id,limits:{maxRows,maxBytes,maxMilliseconds},controlIds:controls.filter(c=>c.phase===id).map(c=>c.id)})),controls,limits,coverage:catalogCoverage.coverage,entry:entryFrame.entry,
  nextGates:evaluator.nextGates,resultAuthority:'none; packet and bounds validation do not accept native results'};
}
let admitted,admittedText,sourceResult;
function verifiedOutputs(result){
 compilerAuthority();verifyGeneratorSources();assertOrderedCurrentCloudSourceCopyV1(result);
 if(result.receipt.inputs.length!==171||result.receipt.outputs.length!==8)fail('source receipt cardinality');
 const outputs={};
 for(const [name,pin]of Object.entries(outputPins)){
  const raw=result.outputs['services/platform/migrations/ordered_current/'+name];
  if(!Buffer.isBuffer(raw)||sha(raw)!==pin)fail('consumed output bytes');
  outputs[name]=Buffer.from(raw);if(sha(outputs[name])!==pin)fail('copied output bytes');
 }
 return outputs;
}
function regenerate(){
 const result=buildOrderedCurrentCloudSourceCopyV1(),outputs=verifiedOutputs(result);
 const candidate=build(outputs,result),text=canonical(candidate);
 if(Buffer.byteLength(text)+1>limits.maxPacketBytes)fail('packet byte cap');
 verifiedOutputs(result);compilerAuthority();
 if(admittedText!==undefined&&text!==admittedText)fail('source regeneration drift');
 sourceResult=result;admitted=candidate;admittedText=text;return admitted;
}
function fixed(){if(!admitted)regenerate();else verifiedOutputs(sourceResult);return admitted;}
export function admitOrderedCurrentNative379PacketCloudV1(){if(arguments.length!==0)fail('caller-selected authority');return structuredClone(regenerate());}
export function assertOrderedCurrentNative379PacketCloudV1(packet){
 if(arguments.length!==1)fail('caller-selected authority');fixed();
 try{if(canonical(packet)!==admittedText)fail('packet source/rule/fact/control/cap mismatch');}catch(error){fail(error.message);}
}
export function serializeOrderedCurrentNative379PacketCloudV1(packet){
 if(arguments.length!==1)fail('serializer caller authority');assertOrderedCurrentNative379PacketCloudV1(packet);
 const raw=Buffer.from(admittedText+'\n');return {raw,bytes:raw.length,sha256:sha(raw)};
}
export function parseOrderedCurrentNative379PacketCloudV1(raw){
 if(arguments.length!==1||!Buffer.isBuffer(raw)||raw.length>limits.maxPacketBytes)fail('wire byte cap or caller authority');
 let value;try{value=JSON.parse(raw.toString('utf8'));}catch{fail('truncated or malformed wire');}
 // Byte equality rejects duplicate keys, trailing bytes and alternate encodings.
 assertOrderedCurrentNative379PacketCloudV1(value);if(!raw.equals(Buffer.from(admittedText+'\n')))fail('noncanonical or duplicate wire');return value;
}
export function assertOrderedCurrentNative379ObservationBoundsCloudV1(observation,packet){
 if(arguments.length!==2)fail('observation caller authority');assertOrderedCurrentNative379PacketCloudV1(packet);
 const closed=(v,keys)=>v&&same(Object.keys(v).sort(),keys.sort());
 if(!closed(observation,['truncated','phases','totalRows','totalBytes','totalMilliseconds'])||observation.truncated!==false||!Array.isArray(observation.phases)||observation.phases.length!==packet.phases.length)fail('observation envelope/truncation');
 const total={rows:0,bytes:0,milliseconds:0};
 for(let i=0;i<packet.phases.length;i++){
  const got=observation.phases[i],want=packet.phases[i];
  if(!closed(got,['id','rows','bytes','milliseconds','rules','controls'])||got.id!==want.id||!same(got.controls,want.controlIds))fail('phase/control ordering');
  const rules=want.id==='pristine-truth'?packet.rules.map(r=>({id:r.id,rows:r.expectedFacts})):[];
  if(!same(got.rules,rules))fail('missing/extra/duplicate rule accounting');
  if(want.id==='pristine-truth'&&got.rows!==10052)fail('pristine rule/build row accounting');
  for(const [key,cap]of [['rows','maxRows'],['bytes','maxBytes'],['milliseconds','maxMilliseconds']]){
   if(!Number.isSafeInteger(got[key])||got[key]<0||got[key]>want.limits[cap])fail('phase '+key+' overflow');total[key]+=got[key];
  }
 }
 for(const [key,field,cap]of [['rows','totalRows','maxRows'],['bytes','totalBytes','maxBytes'],['milliseconds','totalMilliseconds','maxMilliseconds']])if(!Number.isSafeInteger(observation[field])||observation[field]!==total[key]||total[key]>packet.limits[cap])fail('total '+key+' overflow/accounting');
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
 if(process.argv.length!==3||!['--check','--json'].includes(process.argv[2]))fail('use --check or --json; caller authority refused');
 const packet=admitOrderedCurrentNative379PacketCloudV1(),wire=serializeOrderedCurrentNative379PacketCloudV1(packet);
 process.stdout.write(process.argv[2]==='--json'?wire.raw:JSON.stringify({status:packet.status,rules:packet.rules.length,facts:packet.expectedFacts.length,controls:packet.controls.length,bytes:wire.bytes,sha256:wire.sha256})+'\n');
}
