import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {native19WorkerSourceReplay,parseDeclarations} from './ordered-current-worker-source-replay-v1.mjs';

const artifactPath=new URL('./ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json',import.meta.url);
const catalogPath=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',import.meta.url);

test('native20 lifecycle source mutation is refused by immutable release identity',()=>{
 const release=JSON.parse(fs.readFileSync(artifactPath));
 release.source=release.source.replace('test74_lifecycle_source(phase text,q jsonb)','test74_lifecycle_source(phase text,q text)');
 assert.throws(()=>native19WorkerSourceReplay({releaseRaw:Buffer.from(JSON.stringify(release))}),/release identity/);
});

test('native20 persisted current spans and mapped body hashes are exact',()=>{
 const result=native19WorkerSourceReplay();
 const effect=result.accepted.find(row=>row.identity==='zasp_authorization80_worker.test74_effect_source(text,jsonb)');
 const lifecycle=result.accepted.find(row=>row.identity==='zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)');
 assert.deepEqual(effect.sourceSpan,[88133,92611]);
 assert.deepEqual(lifecycle.sourceSpan,[161122,167771]);
 assert.equal(effect.sourceRawSHA256,'5b7e9da001e1dc37f075cd5b5de8d14366a4ebe266bd2c00760a6252f22d185b');
 assert.equal(lifecycle.sourceRawSHA256,'1b35fa9580ad123d705e7a819c2f331dcd818ee43fd44fbdd9a06fd67063c0e8');
 assert.equal(effect.sourceMappedBodySHA256,'deb2d1559a49f064d32cb4a15140d44278d8055e684bc4fcdb5a433e771985f0');
 assert.equal(lifecycle.sourceMappedBodySHA256,'cdafb1ba4e542132ab39a69b218251b198bbbc535d5e23d6d5914367c0c11429');
});

test('native20 duplicate source candidate and duplicate identity are refused',()=>{
 const declaration='CREATE FUNCTION zasp_authorization80_worker.test74_lifecycle_source(phase text,q jsonb) RETURNS jsonb AS $function$SELECT q$function$;\n';
 assert.throws(()=>parseDeclarations(declaration+declaration,new Set(['zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)'])),/duplicate source span/);
 const catalog=JSON.parse(fs.readFileSync(catalogPath));
 const identity='zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)';
 const candidates=catalog.functions.filter(row=>row.identity===identity);
 assert.equal(candidates.length,1);
 catalog.functions.push({...candidates[0]});
 assert.equal(catalog.functions.filter(row=>row.identity===identity).length,2);
 assert.throws(()=>native19WorkerSourceReplay({catalog}),/native20 catalog candidate .*duplicate/);
});

test('native20 material frame mutations remain refused for both tails',()=>{
 const cases=[
  ['owner',()=>'wrong_owner'],['acl',()=>'{wrong_acl}'],['language',()=>'sql'],
  ['volatility',()=>'i'],['security_definer',row=>!row.security_definer],
  ['config',()=>['search_path=public']],['arguments',()=>'wrong text'],['result',()=>'text'],
 ];
 for(const identity of ['zasp_authorization80_worker.test74_effect_source(text,jsonb)','zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)']){
  for(const [field,mutate] of cases){
   const catalog=JSON.parse(fs.readFileSync(catalogPath));
   const row=catalog.functions.find(value=>value.identity===identity);
   row[field]=mutate(row);
   assert.throws(()=>native19WorkerSourceReplay({catalog}),field==='owner'||field==='acl'?/catalog frame/:/exact frame authority/);
  }
 }
});
