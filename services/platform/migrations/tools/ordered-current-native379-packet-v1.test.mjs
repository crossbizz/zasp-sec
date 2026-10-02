import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const url=new URL('./ordered-current-native379-packet-v1.mjs',import.meta.url);
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
let api, packet;
async function load(){
 assert.ok(fs.existsSync(url),'fixed native379 packet implementation is required');
 api??=await import(url);packet??=api.admitOrderedCurrentNative379PacketV1();return structuredClone(packet);
}
const phases=['preflight','pristine-truth','drift','forged-entry','null-error-lazy-demand','frame-restoration','cleanup-result'];

test('fixed admission preserves all approved contracts, complete truth and pending status',async()=>{
 const p=await load();
 assert.equal(p.status,'NATIVE-PARITY-PENDING');assert.equal(p.installable,false);assert.equal(p.captureAuthority,false);assert.equal(p.nativeVerified,false);
 assert.equal(p.authority.task1,'08bb1eb3dc0c0bf98f3ac8d3dc643ca675e0c7d5c81e27cd2f087685cbbd4ed8');
 assert.equal(p.authority.task2,'7027b418bd3141c21acc575deb037e3c26d43713ea2c3e90884caf05f666cd29');
 assert.equal(p.authority.task3,'ddbb22335e34dbbe660ce7546982eb44395a821dc9ec5b4ae8489d67db9bf747');
 assert.equal(p.authority.task4,'c2fdeb51382e9b1da8254c98071bcefb29cba671311fb2ddae13d0d3c6c0e508');
 assert.equal(p.identity.serverVersionNum,180003);assert.equal(p.identity.pgcrypto,'1.4');assert.match(p.identity.postgres,/^PostgreSQL 18\.3 \(Homebrew\)/);
 assert.equal(p.rules.length,379);assert.equal(new Set(p.rules.map(r=>r.id)).size,379);assert.equal(p.expectedFacts.length,10053);
 assert.equal(p.sourceInventory.sites.length,565);assert.equal(p.sourceInventory.unclassified,0);assert.deepEqual(p.phases.map(x=>x.id),phases);
 assert.equal(p.expectedFacts.find(f=>f.kind==='build').fact.generator_sha256,'4e05d0e7e66621baf269749665e7a53b881c64c758ff51453a5478c2f5828b3a');
 assert.equal(api.assertOrderedCurrentNative379PacketV1(p),undefined);
});

test('rule/fact/source identities and finite caps are bound before any target observation',async()=>{
 const p=await load();
 for(const limits of [p.limits,...p.phases.map(x=>x.limits)])for(const key of ['maxRows','maxBytes','maxMilliseconds'])assert.ok(Number.isSafeInteger(limits[key])&&limits[key]>0,key);
 const coverage=new Set(p.controls.flatMap(c=>c.ruleIds));assert.deepEqual(coverage,new Set(p.rules.map(r=>r.id)));
 for(const c of p.controls){
  assert.ok(phases.includes(c.phase));assert.ok(c.sourceSite.sourceIdentity);assert.match(c.sourceSite.siteSHA256,/^[a-f0-9]{64}$/);
  assert.match(c.mutationSHA256,/^[a-f0-9]{64}$/);assert.ok(c.mutation.operation);assert.ok(c.expected.outcome);assert.ok('firstError' in c.expected);
  assert.ok(c.restoration.dimensions.includes('catalog'));assert.equal(c.restoration.beforeNextProbe,true);
  for(const f of c.facts)assert.ok(p.expectedFacts.some(row=>row.kind===f.kind&&row.identity===f.identity));
 }
 const categories=new Set(p.controls.map(c=>c.category));
 for(const kind of ['body','owner','acl','default-acl','config','rls','constraint','index','trigger','saved-definition','registration','addition','missing-dependency','explicit-null','empty','duplicate-bag','scalar-zero','scalar-many','invalid-cast','reg-object','lazy-unselected','lazy-selected','aggregate-order','first-error','forged-evaluator','forged-entry','wrong-manifest','wrong-caller','post-admission-drift','frame'])assert.ok(categories.has(kind),kind);
});

test('closed packet rejects missing extra duplicate descriptors, facts, controls and role sites',async()=>{
 const p=await load();
 for(const collection of ['rules','expectedFacts','controls'])for(const mutate of [a=>a.pop(),a=>a.push(structuredClone(a[0])),a=>a.push({id:'unknown'})]){
  const q=structuredClone(p);mutate(q[collection]);assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);
 }
 for(const mutate of [q=>q.sourceInventory.sites.pop(),q=>q.sourceInventory.sites.push(q.sourceInventory.sites[0]),q=>q.sourceInventory.unclassified=1,q=>q.rules[0].expectedFacts++,q=>q.expectedFacts[0].fact=null,q=>q.controls[0].sourceSite.siteSHA256='0'.repeat(64),q=>q.controls[0].expected.outcome='accept',q=>q.controls[0].restoration.beforeNextProbe=false,q=>q.controls[0].mutation.operation='unknown']){
  const q=structuredClone(p);mutate(q);assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);
 }
});

test('stale Task1-4 identities, caller authority, status promotion and reordered phases refuse',async()=>{
 const p=await load();
 for(const key of ['task1','task2','task3','task4']){const q=structuredClone(p);q.authority[key]='0'.repeat(64);assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);}
 for(const mutate of [q=>q.identity.serverVersionNum=180004,q=>q.identity.pgcrypto='1.3',q=>q.identity.postgres='PostgreSQL 18.3',q=>q.installable=true,q=>q.captureAuthority=true,q=>q.nativeVerified=true,q=>q.phases.reverse(),q=>q.path='/tmp/authority',q=>q.authority.hash='caller']){
  const q=structuredClone(p);mutate(q);assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);
 }
 for(const options of [{path:'/tmp/authority'},{hash:'0'.repeat(64)},{generatedManifest:p},undefined])assert.throws(()=>api.admitOrderedCurrentNative379PacketV1(options),/native379/);
 assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(p,{authority:p}),/native379/);
 p.rules.length=0;assert.equal(api.admitOrderedCurrentNative379PacketV1().rules.length,379);
});

test('fixed caps cannot be removed relaxed or supplied by callers',async()=>{
 const p=await load();
 for(const v of [0,-1,Infinity,NaN,1.5,Number.MAX_SAFE_INTEGER])for(const key of ['maxRows','maxBytes','maxMilliseconds']){
  const q=structuredClone(p);q.limits[key]=v;assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);
 }
 const q=structuredClone(p);q.phases[1].limits.maxRows++;assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);
});

test('non-JSON caller values cannot impersonate null or absent fields',async()=>{
 const p=await load();
 for(const mutate of [q=>q.controls[0].expected.sqlState=NaN,q=>q.controls[0].expected.sqlState=Infinity,q=>q.extra=undefined]){const q=structuredClone(p);mutate(q);assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);}
});

test('wire admission rejects truncation duplicate keys trailing data and over-cap bytes',async()=>{
 const p=await load(),wire=api.serializeOrderedCurrentNative379PacketV1(p);
 assert.equal(sha(wire.raw),wire.sha256);assert.deepEqual(api.parseOrderedCurrentNative379PacketV1(wire.raw),p);
 for(const raw of [wire.raw.subarray(0,wire.raw.length-3),Buffer.concat([wire.raw,Buffer.from('{}')]),Buffer.from(wire.raw.toString().replace('{','{"status":"forged",')),Buffer.alloc(p.limits.maxPacketBytes+1)])assert.throws(()=>api.parseOrderedCurrentNative379PacketV1(raw),/native379/);
 assert.throws(()=>api.parseOrderedCurrentNative379PacketV1(wire.raw,{maxBytes:Infinity}),/native379/);
});

test('retirement controls preserve non-STRICT selection and fixed source-first error ordering',async()=>{
 const p=await load(),controls=p.controls.filter(c=>c.id.startsWith('retirement:'));
 assert.equal(controls.length,20);
 for(const c of controls){assert.equal(c.sourceSite.sourceIdentity,'zasp_temporal68.predecessor_ready(text,text)');assert.equal(c.sourceSite.start,118841);assert.equal(c.sourceSite.end,119679);assert.equal(c.sourceSite.siteSHA256,'5b50a6159ba6a8afb26d656ca91273a2c838558d06a14b6d59d0e3230eeb736a');}
 for(const c of controls.filter(c=>c.mutation.operation==='duplicate-select-into-not-scalar-error')){assert.equal(c.expected.outcome,'rows');assert.deepEqual(c.expected.rows,[{value:true}]);assert.equal(c.expected.sqlState,null);assert.equal(c.mutation.operands.duplicateRows,'identical-values');}
 for(const c of controls.filter(c=>c.mutation.operation==='native-first-error'))assert.equal(c.expected.firstError.stage,'fixed-original-fingerprint');
});

test('catalog drift binds executable fixed mutations and never enables RLS on a view',async()=>{
 const p=await load();
 for(const c of p.controls.filter(c=>c.id.startsWith('catalog:'))){assert.ok(c.mutation.sql?.length,c.id);assert.equal(c.mutation.sqlSHA256,sha(c.mutation.sql));}
 const rls=p.controls.find(c=>c.id==='catalog:rls');assert.equal(rls.mutation.identity,'["worker-line-6","zasp_authorization80_worker.associations"]');assert.equal(rls.mutation.before,true);assert.match(rls.mutation.sql,/DISABLE ROW LEVEL SECURITY/);
 const entry=p.controls.find(c=>c.id==='entry:forged-entry');assert.equal(entry.mutation.target,'zasp_authorization80_ordered_current.require(text)');
});

test('every semantic entry and frame case has an executable typed program and exact restoration SQL',async()=>{
 const p=await load();
 for(const c of p.controls.filter(c=>['null-error-lazy-demand','frame-restoration'].includes(c.phase)||c.id.startsWith('entry:'))){
  assert.equal(c.program?.format,'native379-sql-program-v1',c.id);
  assert.ok(c.program.steps.length>=3,c.id);
  for(const s of c.program.steps){assert.ok(s.id&&s.role&&s.sql&&s.expected,c.id);assert.equal(sha(s.sql),s.sqlSHA256,c.id);}
  assert.ok(c.restoration.snapshotSQL&&c.restoration.restoreSQL&&c.restoration.assertionSQL,c.id);
  assert.ok(c.mutation.operands&&Object.keys(c.mutation.operands).length,c.id);
  if(c.expected.firstError){assert.ok(Number.isSafeInteger(c.expected.firstError.start),c.id);assert.ok(c.expected.firstError.end>c.expected.firstError.start,c.id);assert.match(c.expected.firstError.siteSHA256,/^[a-f0-9]{64}$/);}
  for(const mutate of [x=>delete x.program.steps[0].sql,x=>delete x.mutation.operands,x=>delete x.restoration.assertionSQL]){const q=structuredClone(p),i=q.controls.findIndex(x=>x.id===c.id);mutate(q.controls[i]);assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);}
 }
});

test('retirement controls bind source obligations without invented evaluator rule or fact authority',async()=>{
 const p=await load();
 for(const c of p.controls.filter(c=>c.id.startsWith('retirement:'))){
  assert.equal(c.controlClass,'source-obligation');assert.equal(c.sourceRuleId,'temporal:68.predecessor_ready:retired63-64');assert.deepEqual(c.ruleIds,[]);assert.deepEqual(c.facts,[]);
  assert.equal(c.mutation.operands.relation,'zasp_temporal66.retired_authorities');assert.ok(c.mutation.operands.schema.startsWith('zasp_ordered_'));assert.equal(c.mutation.operands.workerRole,'zasp_security_agent_worker');
  assert.equal(c.sourceSteps.length,6);for(const s of c.sourceSteps){assert.ok(s.start>=118841&&s.end<=119679);assert.equal(sha(s.source),s.siteSHA256);}
 }
});

test('every approved temporal77 schedule export and representative wrapper native case is lowered',async()=>{
 const p=await load(),cases=p.controls.flatMap(c=>(c.sourceCaseIds??[]).map(s=>({...s,control:c})));
 const expected={temporal77:['like-underscore','membership-null','membership-duplicates','membership-cast-error','saved-zero-null','saved-multiple-error','helper-unselected-no-demand','helper-selected-binding-error','put-source-before-helper','native-first-error','original-frame-deparse','aggregate-null-bag'],schedule:['outer-cast-error','unselected-helper-binding','selected-helper-binding','guard-false-null','guard-null-null','saved-zero-null','saved-multiple-error','native-first-error','original-frame-deparse','aggregate-null-bag'],export:['owner-not-registered','member-false','member-null','duplicate-bindings-exists','acl-ordinality','acl-tags-cannot-collide','acl-remove-grantee-only','acl-empty-null','acl-scalar-error','raw-else-text','native-first-error','aggregate-null-bag'],wrapper:['condition-false-fallback','condition-null-fallback','selected-call-error','unselected-call-no-demand','registration-cardinality','owner-acl-frame-drift','native-first-error']};
 for(const [family,names]of Object.entries(expected)){const found=cases.filter(c=>c.family===family);assert.deepEqual(found.map(c=>c.id).sort(),names.sort());for(const c of found){assert.ok(c.control.program.steps.find(s=>s.id==='probe').sql);assert.ok(c.control.sourceSite.start>=0);}}
 const q=structuredClone(p),c=q.controls.find(c=>c.sourceCaseIds?.length);c.sourceCaseIds.pop();assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);
});

test('canonical mutation hashes independently bind every control including all 68 source semantics',async()=>{
 const p=await load();assert.equal(p.controls.length,589);
 // Independent recursive canonical serializer, not the production replacer.
 const encode=x=>Array.isArray(x)?'['+x.map(encode).join(',')+']':x!==null&&typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+encode(x[k])).join(',')+'}':JSON.stringify(x);
 const semantic=p.controls.filter(c=>c.phase==='null-error-lazy-demand');assert.equal(semantic.length,68);
 const bad=p.controls.filter(c=>c.mutationSHA256!==sha(encode(c.mutation))).map(c=>c.id);
 assert.deepEqual(bad,[],'all mutation pins must hash canonical JSON, including semantic/retirement objects');
 for(const c of semantic)assert.equal(c.mutationSHA256,sha(encode(c.mutation)),c.id);
});

test('every declared native control is executable and rollback-restored before the next control',async()=>{
 const p=await load();assert.equal(p.controls.length,589);
 for(const phase of p.phases){
  assert.deepEqual(phase.controlIds,p.controls.filter(c=>c.phase===phase.id).map(c=>c.id),phase.id);
 }
 for(const c of p.controls){
  assert.equal(c.program?.format,'native379-sql-program-v1',c.id);
  assert.ok(c.program.steps.length>=3,c.id);
  assert.equal(c.restoration.beforeNextProbe,true,c.id);
  assert.equal(c.restoration.timeoutIsDenial,false,c.id);
  assert.equal(c.restoration.protocolTransactionStatusAfter??c.restoration.expectedTransactionStatus,'I',c.id);
  assert.ok(c.program.steps.some(s=>s.id==='probe'),c.id);
  assert.ok(c.program.steps.some(s=>s.id==='restore'),c.id);
  assert.equal(c.program.steps.at(-1).id.startsWith('snapshot-after')||c.program.steps.at(-1).id==='assert-restored',true,c.id);
  for(const s of c.program.steps){assert.equal(s.sqlSHA256,sha(s.sql),`${c.id}:${s.id}`);}
 }
 const exact=p.controls.filter(c=>c.category==='expected-key-set');assert.equal(exact.length,379);
 for(const c of exact){
  assert.deepEqual(c.program.steps.map(s=>s.id),['setup-session','snapshot-before','begin','mutate','source-frame','probe-savepoint','admit-before-selector','probe','recover-probe','restore','snapshot-after'],c.id);
  const admission=c.program.steps.find(s=>s.id==='admit-before-selector');assert.equal(admission.sql,p.entry.independentAdmission.sql,c.id);assert.deepEqual(admission.expected,{outcome:'rows',rows:[{admitted:true}],sqlState:null},c.id);
  assert.deepEqual(c.program.steps.find(s=>s.id==='probe').expected,{outcome:'rows',rows:[{value:false}],sqlState:null},c.id);
  assert.equal(c.program.steps.find(s=>s.id==='mutate').sql,c.mutation.sql,c.id);
 }
});

test('distinct controls never reuse an identical full SQL program without source-proven equivalence',async()=>{
 const p=await load(),encode=x=>JSON.stringify(x,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v),groups=new Map();
 for(const c of p.controls){const digest=sha(encode(c.program));if(!groups.has(digest))groups.set(digest,[]);groups.get(digest).push(c.id);}
 const duplicate=[...groups.entries()].filter(([,ids])=>ids.length>1).map(([digest,ids])=>({digest,ids}));
 assert.deepEqual(duplicate,[]);
 for(const pair of [['semantics:temporal77:invalid-cast','semantics:temporal77:reg-object'],['coverage:worker-line-23','coverage:worker-line-32'],['coverage:private-view','coverage:private-rewrite'],['retirement:zasp_ordered_worker63:schema-absent-row-absent-continue','retirement:zasp_ordered_scheduler64:schema-absent-row-absent-continue']]){
  const [a,b]=pair.map(id=>p.controls.find(c=>c.id===id));assert.ok(a&&b,pair.join(','));assert.notEqual(sha(encode(a.program)),sha(encode(b.program)),pair.join(','));assert.notDeepEqual(a.mutation.operands,b.mutation.operands,pair.join(','));
 }
});

test('export ACL tag collision and grantee-only removal use distinct adversarial source operands',async t=>{
 const p=await load(),get=name=>p.controls.find(c=>c.id==='semantics:export:'+name),collision=get('acl-tags-cannot-collide'),removal=get('acl-remove-grantee-only'),baseline=get('duplicate-bindings-exists');
 const role='zasp_native379_export_owner';
 const collisionInput=[
  {grantee:role,grantor:'native379-grantor',privilege:'EXECUTE',grantable:false},
  {grantee:'registered-migration-principal',grantor:'native379-grantor',privilege:'EXECUTE',grantable:false},
  {grantee:'<registered-migration-principal>',grantor:'native379-grantor',privilege:'EXECUTE',grantable:false},
 ];
 const removalInput=[
  {grantee:role,grantor:role,privilege:'EXECUTE',grantable:true,note:role,metadata:{grantee:role,grantor:role,tag:'registered-migration-principal'}},
  {grantee:'native379-literal',grantor:role,privilege:'EXECUTE',grantable:false,metadata:{grantee:role}},
 ];
 const wants=[
  [collision,collisionInput,[['registered-migration-principal',{grantor:'native379-grantor',privilege:'EXECUTE',grantable:false}],['literal',{grantee:'registered-migration-principal',grantor:'native379-grantor',privilege:'EXECUTE',grantable:false}],['literal',{grantee:'<registered-migration-principal>',grantor:'native379-grantor',privilege:'EXECUTE',grantable:false}]]],
  [removal,removalInput,[['registered-migration-principal',{grantor:role,privilege:'EXECUTE',grantable:true,note:role,metadata:{grantee:role,grantor:role,tag:'registered-migration-principal'}}],['literal',{grantee:'native379-literal',grantor:role,privilege:'EXECUTE',grantable:false,metadata:{grantee:role}}]]],
 ];
 for(const [c,input,output]of wants)await t.test(c.id,()=>{
  assert.deepEqual(c.mutation.operands.row.acl,input,c.id);assert.notDeepEqual(input,baseline.mutation.operands.row.acl);
  assert.notEqual(c.mutation.sql,baseline.mutation.sql);assert.notDeepEqual(c.expected.rows,baseline.expected.rows);
  const mutate=c.program.steps.find(s=>s.id==='mutate'),probe=c.program.steps.find(s=>s.id==='probe');assert.equal(mutate.sql,c.mutation.sql);assert.ok(mutate.sql.includes("'"+JSON.stringify(input)+"'::jsonb"));
  assert.deepEqual(c.expected.rows,[{value:['<registered-migration-principal>',output]}]);assert.deepEqual(probe.expected.rows,c.expected.rows);
  assert.equal(c.sourceSite.sourceIdentity,'public.zasp_sa_export_live_fingerprint()');assert.equal(sha(c.sourceSite.source),c.sourceSite.siteSHA256);assert.ok(probe.sql.includes(c.sourceSite.source));
 });
 assert.notEqual(collision.mutation.sql,removal.mutation.sql);assert.notDeepEqual(collision.expected.rows,removal.expected.rows);
});

test('catalog coverage accounts for every descriptor family and kind without storage-tamper substitution',async()=>{
 const p=await load();assert.ok(p.coverage?.families&&p.coverage?.kinds);
 const expectedKinds=['worker_registration','namespace','routine','relation','column','constraint','policy','trigger','saved_function','saved_view','index','runtime_registration','view','rewrite','type','membership','column_name','policy_view','information_column','global_constraint','index_view','fixed_runtime_profile','role','saved_constraint','foreign_key_trigger','class_index','column_all'];
 assert.deepEqual(new Set(p.coverage.kinds.map(r=>r.id)),new Set(expectedKinds));
 assert.deepEqual(new Set(p.coverage.families.flatMap(r=>r.ruleIds)),new Set(p.rules.map(r=>r.id)));
 for(const row of [...p.coverage.families,...p.coverage.kinds]){
  assert.ok(row.ruleIds.length&&row.controlIds.length,row.id);
  for(const id of row.controlIds){const c=p.controls.find(c=>c.id===id);assert.equal(c?.phase,'drift',id);assert.notEqual(c.category,'expected-key-set');assert.ok(c.program?.steps.some(s=>s.id==='mutate'&&s.sql),id);}
 }
 const profile=p.controls.find(c=>c.id==='coverage:role-profile:current-profile');assert.ok(['canonical61-temporal78-authorization79-80-v1','canonical61-authorization79-80-v1'].includes(profile.mutation.operands.after));assert.notEqual(profile.mutation.operands.after,profile.mutation.operands.before);
 for(const change of [q=>q.coverage.families.pop(),q=>q.coverage.kinds.push(q.coverage.kinds[0]),q=>q.coverage.kinds[0].controlIds=[p.controls[0].id],q=>q.coverage.families[0].id='unknown']){const q=structuredClone(p);change(q);assert.throws(()=>api.assertOrderedCurrentNative379PacketV1(q),/native379/);}
});

test('authoritative regeneration is pinned to Node22.23.1 darwin arm64 executable bytes',async()=>{
 const p=await load();assert.deepEqual(p.buildRuntime,{version:'v22.23.1',platform:'darwin',arch:'arm64',executableSHA256:'2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d',executablePolicy:'resolved-process-executable-regular-file-exact-sha256'});
 const other=spawnSync('node',[fileURLToPath(url),'--check'],{encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
 if(spawnSync('node',['--version'],{encoding:'utf8'}).stdout.trim()!=='v22.23.1'){assert.notEqual(other.status,0);assert.match(other.stderr,/native379.*Node runtime/);}
});

function bounded(p){return {truncated:false,phases:p.phases.map(phase=>({id:phase.id,rows:phase.id==='pristine-truth'?10053:0,bytes:0,milliseconds:0,rules:phase.id==='pristine-truth'?p.rules.map(r=>({id:r.id,rows:r.expectedFacts})):[],controls:p.controls.filter(c=>c.phase===phase.id).map(c=>c.id)})),totalRows:10053,totalBytes:0,totalMilliseconds:0};}
test('observation accounting refuses overflow truncation missing extra duplicate or reordered controls',async()=>{
 const p=await load(),b=bounded(p);assert.equal(api.assertOrderedCurrentNative379ObservationBoundsV1(b,p),undefined);
 for(const mutate of [x=>x.truncated=true,x=>x.phases.pop(),x=>x.phases.reverse(),x=>x.phases[1].rules.pop(),x=>x.phases[1].rules.push(x.phases[1].rules[0]),x=>x.phases[1].rules[0].id='extra',x=>x.phases[2].controls.pop(),x=>x.phases[2].controls.push('extra'),x=>x.phases[2].controls.reverse(),x=>x.totalRows++,x=>x.totalBytes++,x=>x.totalMilliseconds++,x=>x.phases[0].rows=-1,x=>x.phases[0].bytes=NaN,x=>x.phases[0].milliseconds=Infinity,x=>x.phases[0].rows=p.phases[0].limits.maxRows+1,x=>x.phases[0].bytes=p.phases[0].limits.maxBytes+1,x=>x.phases[0].milliseconds=p.phases[0].limits.maxMilliseconds+1]){
  const q=structuredClone(b);mutate(q);assert.throws(()=>api.assertOrderedCurrentNative379ObservationBoundsV1(q,p),/native379/);
 }
 assert.throws(()=>api.assertOrderedCurrentNative379ObservationBoundsV1(b,p,{limits:{}}),/native379/);
});

test('packet rebuild ignores mutable generated files and requires fixed generator authority in a clean source tree',async()=>{
 await load();const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-native379-test-'));
 try{
  const migrations=path.join(temporary,'services/platform/migrations');fs.mkdirSync(path.dirname(migrations),{recursive:true});
  fs.cpSync(new URL('../',import.meta.url),migrations,{recursive:true});
  const generated=path.join(migrations,'ordered_current/development-manifest.json');fs.writeFileSync(generated,'FORGED GENERATED OUTPUT\n');
  const module=path.join(migrations,'tools/ordered-current-native379-packet-v1.mjs');
  const run=()=>spawnSync(process.execPath,[module,'--check'],{cwd:temporary,encoding:'utf8',timeout:90000,maxBuffer:1024*1024});
  let result=run();assert.equal(result.status,0,result.stderr);assert.equal(fs.readFileSync(generated,'utf8'),'FORGED GENERATED OUTPUT\n');assert.equal(fs.existsSync(path.join(temporary,'.superpowers')),false);
  for(const name of Object.keys(packet.authority.packetModules)){
   const helper=path.join(migrations,'tools',name),before=fs.readFileSync(helper);assert.equal(sha(before),packet.authority.packetModules[name]);fs.appendFileSync(helper,'\n// stale packet helper\n');
   result=run();assert.notEqual(result.status,0);assert.match(result.stderr,/native379.*source hash authority/);fs.writeFileSync(helper,before);
  }
  fs.appendFileSync(path.join(migrations,'tools/build-ordered-current-development.mjs'),'\n// stale authority\n');
  result=run();assert.notEqual(result.status,0);assert.match(result.stderr,/native379.*authority/);
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
});
