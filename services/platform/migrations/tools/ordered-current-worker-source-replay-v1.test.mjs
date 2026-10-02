import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {native19WorkerSourceReplay,native19WorkerDefinitionRows,native19WorkerSourceReplayManifest} from './ordered-current-worker-source-replay-v1.mjs';
import {regenerateCurrentWorkerCatalog} from './ordered-current-worker-source-descriptor-v1.mjs';

const artifactPath=new URL('./ordered-current-worker-source-closure-v1-artifacts/native19-worker-release.json',import.meta.url);
const catalogPath=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-catalog1.json',import.meta.url);

test('native19 source replay retains all worker definitions and registration as explicit refusals',()=>{
 const result=native19WorkerSourceReplay();
 assert.equal(result.accepted.length,13);
 assert.equal(result.refused.length,4);
 assert.equal(new Set([...result.accepted,...result.refused].map(row=>row.identity)).size,17);
 assert.equal(result.registration.status,'refused');
 assert.equal(result.accepted.filter(row=>row.transform==='pg_get_functiondef-v1-wrapper-v1').length,2);
 assert.equal(result.refused.filter(row=>row.reason.includes('higher-region')).length,4);
 assert.equal(result.builder.sourceSHA256,native19WorkerSourceReplayManifest.sourceSHA256);
 assert.deepEqual(result.refused.map(row=>row.identity),native19WorkerDefinitionRows.filter(row=>row.category==='higher').map(row=>row.identity));
});

test('native19 rejects release mutation and stale profile selection',()=>{
 const raw=fs.readFileSync(artifactPath),mutated=Buffer.from(raw);
 mutated[mutated.length-2]^=1;
 assert.throws(()=>native19WorkerSourceReplay({releaseRaw:mutated}),/release (JSON|identity)/);
 assert.throws(()=>native19WorkerSourceReplay({expectedChecksum:'e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960'}),/stale profile checksum/);
});

test('native19 rejects owner or ACL drift in pinned catalog frames',()=>{
 const catalog=JSON.parse(fs.readFileSync(catalogPath));
 catalog.functions.find(row=>row.identity===native19WorkerDefinitionRows[0].identity).owner='wrong_owner';
 assert.throws(()=>native19WorkerSourceReplay({catalog}),/catalog frame/);
 const second=JSON.parse(fs.readFileSync(catalogPath));
 second.functions.find(row=>row.identity==='zasp_temporal68.ready(text,text)').acl='{wrong_acl}';
 assert.throws(()=>native19WorkerSourceReplay({catalog:second}),/catalog frame/);
});

test('native19 rejects every accepted definition and frame authority mutation',()=>{
 const fields=['definition','language','volatility','security_definer','config','arguments','result'];
 for(const field of fields){
  const catalog=JSON.parse(fs.readFileSync(catalogPath));
  const row=catalog.functions.find(value=>value.identity==='zasp_authorization79.fingerprint()');
  row[field]=field==='definition'?row.definition.replace('RETURNS text','RETURNS boolean'):field==='config'?['search_path=public']:field==='security_definer'?!row[field]:field==='volatility'?'v':field==='language'?'plpgsql':field==='arguments'?'bad text':'boolean';
  assert.throws(()=>native19WorkerSourceReplay({catalog}),/exact (definition|frame) authority|catalog frame/);
 }
 const raw=fs.readFileSync(artifactPath),release=JSON.parse(raw);
 release.source=release.source.replace('CREATE FUNCTION zasp_authorization79.fingerprint()','CREATE OR REPLACE FUNCTION zasp_authorization79.fingerprint()');
 assert.throws(()=>native19WorkerSourceReplay({releaseRaw:Buffer.from(JSON.stringify(release))}),/release identity/);
});

test('native19 refuses registration before complete source closure',()=>{
 const result=native19WorkerSourceReplay();
 assert.equal(result.registration.identity,'["worker-line-2","[\\"zasp_authorization80_worker.registration\\",true]"]');
 assert.equal(result.registration.profileChecksum,native19WorkerSourceReplayManifest.catalogChecksum);
 assert.match(result.registration.reason,/complete 34-branch worker fact set/);
});

test('native19 descriptor regeneration is current-state idempotent and rejects wrong intermediates',()=>{
 const current=fs.readFileSync(catalogPath),same=regenerateCurrentWorkerCatalog(current);
 assert.equal(same.sha256,'b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077');
 assert.equal(same.changedRows.length,0);
 const wrong=Buffer.from(current.toString().replace('"compiled_checksum":"5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9"','"compiled_checksum":"wrong"'));
 assert.throws(()=>regenerateCurrentWorkerCatalog(wrong),/input pin|current checksum/);
});

test('native20 source replay closes the two test74 worker-line-5 tails without admitting registration',()=>{
 const result=native19WorkerSourceReplay();
 const byIdentity=new Map(result.accepted.map(row=>[row.identity,row]));
 const effect=byIdentity.get('zasp_authorization80_worker.test74_effect_source(text,jsonb)');
 const lifecycle=byIdentity.get('zasp_authorization80_worker.test74_lifecycle_source(text,jsonb)');
 assert.ok(effect,'native20 effect source must be accepted from pinned source');
 assert.ok(lifecycle,'native20 lifecycle source must be accepted from pinned source');
 assert.equal(effect.factSHA256,'60ce2dba06789d8904001e31870b0a02ddad9262dc252d60271c21a190bd4271');
 assert.equal(lifecycle.factSHA256,'661743088f23cff353385c8d425bbcf88005ee3cb1c1b798b9de1b48a180e70c');
 assert.equal(effect.sourceSpan[0],88133); assert.equal(effect.sourceSpan[1],92611);
 assert.equal(lifecycle.sourceSpan[0],161122); assert.equal(lifecycle.sourceSpan[1],167771);
 assert.equal(effect.sourceBodySHA256,'7f2d70d3fa899610cd4f3abe064821fe7ebe524ce2325ba4a3d26fa4bc9f6e82');
 assert.equal(effect.sourceMappedBodySHA256,'deb2d1559a49f064d32cb4a15140d44278d8055e684bc4fcdb5a433e771985f0');
 assert.equal(lifecycle.sourceBodySHA256,'4f85e19801e8a27a33da2892c937aa2550e0852603aab8ca4c8595f897d5ec1f');
 assert.equal(lifecycle.sourceMappedBodySHA256,'cdafb1ba4e542132ab39a69b218251b198bbbc535d5e23d6d5914367c0c11429');
 assert.equal(result.registration.status,'refused');
});

test('native20 refuses tail source, definition, frame, and profile-hash mutations',()=>{
 const effectIdentity='zasp_authorization80_worker.test74_effect_source(text,jsonb)';
 const catalog=JSON.parse(fs.readFileSync(catalogPath));
 const definitionRow=catalog.functions.find(row=>row.identity===effectIdentity);
 definitionRow.definition=definitionRow.definition.replace('RETURNS jsonb','RETURNS text');
 assert.throws(()=>native19WorkerSourceReplay({catalog}),/exact definition authority/);
 const aclCatalog=JSON.parse(fs.readFileSync(catalogPath));
 aclCatalog.functions.find(row=>row.identity===effectIdentity).acl='{wrong_acl}';
 assert.throws(()=>native19WorkerSourceReplay({catalog:aclCatalog}),/catalog frame/);
 const source=JSON.parse(fs.readFileSync(artifactPath));
 source.source=source.source.replace('test74_effect_source(phase text,q jsonb)','test74_effect_source(phase text,q text)');
 assert.throws(()=>native19WorkerSourceReplay({releaseRaw:Buffer.from(JSON.stringify(source))}),/release identity/);
 assert.throws(()=>native19WorkerSourceReplay({expectedChecksum:'e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960'}),/stale profile checksum/);
});
