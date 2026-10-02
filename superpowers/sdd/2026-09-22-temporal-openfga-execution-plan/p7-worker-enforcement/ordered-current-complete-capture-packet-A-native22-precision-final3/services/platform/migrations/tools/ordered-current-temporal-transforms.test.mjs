import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedTemporalCatalog} from './ordered-current-temporal-selectors.mjs';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const bytes=fs.readFileSync(new URL('../../../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-contract3.json',import.meta.url));
assert.equal(sha(bytes),'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
const contract=JSON.parse(bytes),lower=()=>lowerOrderedTemporalTransforms(contract);
const id=(family,branch='function')=>`temporal:${family}:${branch}`;
const recipe=(o,f,b)=>o.recipes.find(r=>r.ruleId===id(f,b));
// Test-only consumer of the agreed closed AST. Expectations below are literal,
// independently specified source results, not produced by this interpreter.
function run(ast,row,saved=[]) {
  switch(ast.op){
    case 'field':assert.ok(Object.hasOwn(row,ast.field));return row[ast.field];
    case 'literal':return ast.value;
    case 'replace':{const v=run(ast.input,row,saved);return v===null?null:v.split(ast.from).join(ast.to);}
    case 'coalesce':for(const arg of ast.args){const v=run(arg,row,saved);if(v!==null)return v;}return null;
    case 'identity-case':return run(ast.cases.find(c=>c.identity===row.identity)?.then??ast.else,row,saved);
    case 'saved-scalar':{const rows=saved.filter(s=>s.schema===ast.schema&&s.signature===ast.signature);if(rows.length>1)throw Error('scalar multiple rows');return rows.length===0?null:rows[0][ast.field];}
    default:throw Error('closed AST unknown operator');
  }
}
test('nine complete recipes and two explicit unresolved sites cover exactly eleven original transformations',()=>{
  const o=lower();assert.equal(o.recipes.length,9);assert.equal(o.sites.length,11);assert.equal(o.unsupported.length,2);
  const original=lowerOrderedTemporalCatalog(contract);
  for(const s of o.sites){const old=original.sites.find(x=>x.sha256===s.sha256);assert.deepEqual(s,old);const n=contract.nodes.find(n=>n.identity===s.identity);assert.equal(Buffer.from(n.source).subarray(s.start,s.end).toString(),s.text);}
  for(const r of o.recipes){const old=original.obligations.find(x=>x.siteSHA256===r.siteSHA256&&x.type==='original-transformation');assert.deepEqual(r.selector,old.selector);assert.equal(r.sourceIdentity,`zasp_temporal${old.family}()`);assert.ok(o.obligations.some(x=>x.ruleId===r.ruleId&&x.type==='frame-resolution-and-aggregation'));}
  assert.deepEqual(o.unsupported.map(x=>x.ruleId),[id('78.predecessor77_fingerprint'),id('78.predecessor77_fingerprint','effective-policy-boundary')]);
});
test('literal checksum replacements produce all original tags, preserve raw owner/ACL, and propagate NULL',()=>{
  const r=recipe(lower(),'70.fingerprint');assert.ok(r,'complete70 recipe');
  const row={name:'f',identity_arguments:'text',owner:'actual_owner',acl:null,definition:'64e6bae3878ee548084f91f5ef2a6cf866105d2973594d8fe7d0a45cff032988/d15a4b32b9b528fc3913db76097f18d93c74461b31758a19c87142b972f03c99/c7f814af4248cf3f7901d51b116c1ff7bb5374739473b65134072766db7c174a/499b011078b1a124e95e44454ae1bcbe1e5eda8dbb99d59d156dfd1bd19c0dbf'};
  assert.equal(run(r.fields.definition,row),'<checksum>/<fingerprint>/<base-fingerprint>/<domain-fingerprint>');assert.equal(run(r.fields.owner,row),'actual_owner');assert.equal(run(r.fields.acl,row),'');assert.equal(run(r.fields.definition,{...row,definition:null}),null);
  assert.equal(run(r.fields.acl,{...row,acl:'{b=X/live_owner,a=X/live_owner}'}),'{b=X/live_owner,a=X/live_owner}');
  assert.deepEqual(Object.keys(r.fields),['name','identity_arguments','owner','acl','definition']);
  const tags=[];let x=r.fields.definition;while(x.op==='replace'){tags.unshift(x.to);x=x.input;}assert.deepEqual(tags,['<checksum>','<fingerprint>','<base-fingerprint>','<domain-fingerprint>']);assert.deepEqual(x,{op:'field',field:'definition'});
});
test('other literal families use their own pins, not another family or target-derived expected body',()=>{
  const o=lower();for(const [family,body,want] of [
    ['71.fingerprint','4ab3a167a76f1296c385b36330f83180fe2eedb7233f49377073248bac3f1ec8 1bfbd14f6f2a23fd3dd2be171473f646cc3c5b0b4b0b36de4dd2f12cec5f07b3','<checksum> <fingerprint>'],
    ['75.fingerprint','27c65026b98f6c7d68620eea2d174db0eebf68cea40c49094350878e185b5371 507b909dd0a59c2ffe8c664d8e70c40d120f63ad215a96fc002141c22687b873','<checksum> <fingerprint>'],
    ['77.domain67_fingerprint','b0ce6cf26b4b5f7e909f2e8e8ba5fdc987318efb21878c503117b4583b1544a8 b8b6e336ec72fa1b056c5e8a2f65cdd8275e9bbaee498ef1064d5f90133cf191','<checksum> <base-fingerprint>'],
    ['78.predecessor73_fingerprint','d2b10f7a97ee8cbc23ccacce852845ce20625851a93428013b0c83f799838556 09895c8411beabd971e2425c3382a1152df3d224334ded17433fa80ae243b115','<checksum> <fingerprint>']
  ]){const r=recipe(o,family);assert.ok(r);assert.equal(run(r.fields.definition,{identity:'unselected()',definition:body}),want);}
});
test('outbox and domain saved substitutions select exact signatures with zero/null/multiple-row semantics',()=>{
  const o=lower();for(const [family,schema,signature] of [['74.outbox65_fingerprint','zasp_temporal74','zasp_temporal65.capture()'],['77.domain67_fingerprint','zasp_temporal77','zasp_temporal67.fingerprint()'],['78.predecessor73_fingerprint','zasp_temporal78','zasp_temporal73.unresolved(text,text,text,text)']]){
    const r=recipe(o,family);assert.ok(r);const row={identity:signature,definition:'live wrong'},saved={schema,signature,definition:'saved exact'};
    assert.equal(run(r.fields.definition,row,[saved]),'saved exact');assert.equal(run(r.fields.definition,row),null);assert.equal(run(r.fields.definition,row,[{...saved,definition:null}]),null);assert.throws(()=>run(r.fields.definition,row,[saved,saved]),/multiple/);assert.equal(run(r.fields.definition,{identity:'other()',definition:'live exact'},[saved,saved]),'live exact');
  }
});
test('owner66 saved ACL is not coalesced, and ACL/definition identity cases remain independent',()=>{
  const r=recipe(lower(),'74.owner66_fingerprint');assert.ok(r);const signature='zasp_temporal66.legacy_visible(text,text,text,text)',row={identity:signature,acl:'live acl',definition:'live body'};
  assert.equal(run(r.fields.acl,row),null);assert.equal(run(r.fields.acl,row,[{schema:'zasp_temporal74',signature,acl:null}]),null);assert.equal(run(r.fields.acl,row,[{schema:'zasp_temporal74',signature,acl:'{b=X/z,a=X/z}'}]),'{b=X/z,a=X/z}');assert.equal(run(r.fields.definition,row),'live body');
  assert.equal(run(r.fields.acl,{identity:'zasp_temporal66.fingerprint()',acl:null}),'');assert.equal(run(r.fields.definition,{identity:'zasp_temporal66.fingerprint()',definition:'live'}),null);
});
test('executor branch keeps full original fixed universe and nested worker saved cases without replacement',()=>{
  const o=lower(),r=recipe(o,'78.predecessor76_fingerprint','executor-function');assert.ok(r);
  assert.deepEqual(r.selector,{any:['zasp_temporal74.takeover(text,text,text,text)','zasp_temporal74.context(text,text,text,text)','zasp_temporal74.context_parent(text,text,text,text,jsonb)','zasp_temporal74.fingerprint()'].map(identity=>({field:'identity',equals:identity}))});
  assert.deepEqual(Object.keys(r.fields),['identity','owner','acl','definition']);
  const signature='zasp_temporal74.context(text,text,text,text)',saved={schema:'zasp_authorization80_worker',signature,definition:'57cc7f96f487b7f172502c7dea30eccd0244ad14437a747c32a6d05ecdb3b107'};
  assert.equal(run(r.fields.definition,{identity:signature,definition:'live'},[saved]),saved.definition);assert.equal(run(r.fields.definition,{identity:signature,definition:'live'}),null);
  const fn=recipe(o,'78.predecessor76_fingerprint');assert.equal(run(fn.fields.definition,{identity:signature,definition:'live'},[saved]),'<checksum>');
  assert.equal(run(r.fields.definition,{identity:'zasp_temporal74.fingerprint()',definition:'live'}),'live');
});
test('dynamic saved regprocedure membership and ordered writer helper stay unsupported, never raw equality',()=>{
  const o=lower();assert.equal(o.unsupported.length,2);for(const x of o.unsupported){assert.equal(x.type,'original-transformation');assert.ok(x.required.includes('regprocedure'));assert.ok(x.required.includes('ordered_writer_definition'));assert.ok(!o.recipes.some(r=>r.ruleId===x.ruleId));assert.ok(x.source.includes("signature LIKE 'zasp_temporal77.%'"));}
});
test('full source/frame pins refuse rehashed edits and missing/duplicate nodes; output deterministic and input immutable',()=>{
  const o=lower(),before=JSON.stringify(contract);assert.equal(JSON.stringify(lower()),JSON.stringify(o));assert.equal(JSON.stringify(contract),before);
  const identity='zasp_temporal74.owner66_fingerprint()';for(const change of [n=>{n.source+=' ';n.sourceSHA256=sha(n.source);},n=>{n.definition+=' ';n.definitionSHA256=sha(n.definition);},n=>{n.owner='fixture_alias';},n=>{n.config=['search_path=public'];},n=>{n.strict=true;}]){const c=structuredClone(contract);change(c.nodes.find(n=>n.identity===identity));assert.throws(()=>lowerOrderedTemporalTransforms(c));}
  for(const mode of ['missing','duplicate']){const c=structuredClone(contract),n=c.nodes.find(n=>n.identity===identity);if(mode==='missing')c.nodes=c.nodes.filter(n=>n!==c.nodes.find(x=>x.identity===identity));else c.nodes.push(n);assert.throws(()=>lowerOrderedTemporalTransforms(c));}
});
