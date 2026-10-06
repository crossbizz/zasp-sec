import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import * as api from './ordered-current-native379-source-schema-v2.mjs';

test('fixed v2 source schema includes actual migration importers and both apiserver authorities',()=>{
 const source=api.admitOrderedCurrentNative379SourceV2();
 assert.equal(source.format,'ordered-current-native379-source-inputs-v2');
 assert.equal(source.status,'SOURCE-PROVENANCE-ONLY');
 assert.equal(source.installable,false);assert.equal(source.nativeVerified,false);
 for(const fixture of ['authorization_worker_precision_resolver_postgres_test.go','authorization_worker_ordered_readiness_capture_test.go'])assert.ok(source.files['services/platform/apiserver/'+fixture]);
 const implementation='services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go';
 const companion='services/platform/apiserver/authorization_worker_ordered_current_native379_v2_pins_test.go';
 assert.ok(source.files[implementation]);assert.ok(!Object.hasOwn(source.files,companion));
 assert.deepEqual(source.goPacketAnchorPolicy.excludedSourcePaths,[companion]);
 assert.equal(source.goPacketAnchorPolicy.implementation,implementation);
 assert.equal(source.goPacketAnchorPolicy.companionBinding,'independently-reviewed-full-consumed-Go-source-module-test-binary-envelope');
 for(const importer of ['ordered-current-worker-source-replay-v1.test.mjs','ordered-current-worker-source-descriptor-v1.mjs','build-ordered-current-development.mjs'])assert.ok(source.files['services/platform/migrations/tools/'+importer]);
 assert.ok(source.pendingGates.includes('independently-reviewed-Go-source-module-test-binary-envelope'));
 assert.throws(()=>api.admitOrderedCurrentNative379SourceV2({}),/caller/);
 for(const change of [s=>delete s.files['services/platform/apiserver/authorization_worker_precision_resolver_postgres_test.go'],s=>s.files['services/platform/apiserver/extra.go']='0'.repeat(64),s=>s.files['services/platform/migrations/tools/ordered-current-worker-source-descriptor-v1.mjs']='0'.repeat(64),s=>s.nativeVerified=true,s=>s.extra=undefined,s=>s.importEdges['services/platform/migrations/tools/ordered-current-worker-source-replay-v1.test.mjs']=[],s=>s.pendingGates=[]]){
  const bad=structuredClone(source);change(bad);assert.throws(()=>api.assertOrderedCurrentNative379SourceV2(bad),/source/);
 }
});

test('repo-relative source reader refuses unsafe paths and symlink ancestors or files',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-native379-v2-topology-'));
 try{
  fs.mkdirSync(path.join(root,'safe'));fs.writeFileSync(path.join(root,'safe','input.mjs'),'source');
  const digest=crypto.createHash('sha256').update('source').digest('hex');
  assert.equal(api.readNative379RegularSourceV2(root,'safe/input.mjs',digest).toString(),'source');
  for(const relative of ['../outside','/safe/input.mjs','safe/../safe/input.mjs','safe//input.mjs','safe\\input.mjs'])assert.throws(()=>api.readNative379RegularSourceV2(root,relative,digest),/source/);
  assert.throws(()=>api.readNative379RegularSourceV2(root,'safe/input.mjs','0'.repeat(64)),/hash/);
  fs.symlinkSync('input.mjs',path.join(root,'safe','link.mjs'));fs.symlinkSync('safe',path.join(root,'alias'));
  for(const relative of ['safe/link.mjs','alias/input.mjs'])assert.throws(()=>api.readNative379RegularSourceV2(root,relative,digest),/symlink/);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});

test('fixed authority refuses a same-byte manifest or artifact ancestor reached through a symlink',async()=>{
 for(const ancestor of [false,true]){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'zasp-native379-v2-manifest-topology-'));
  try{
   const tools=path.join(root,'services/platform/migrations/tools');fs.mkdirSync(tools,{recursive:true});
   const schema=path.join(tools,'ordered-current-native379-source-schema-v2.mjs');fs.copyFileSync(new URL('./ordered-current-native379-source-schema-v2.mjs',import.meta.url),schema);
   const target=path.join(root,'same-byte-authority');fs.mkdirSync(target);
   const name='source-inputs.json';fs.copyFileSync(new URL('./ordered-current-native379-packet-v2-artifacts/source-inputs.json',import.meta.url),path.join(target,name));
   const artifacts=path.join(tools,'ordered-current-native379-packet-v2-artifacts');
   if(ancestor)fs.symlinkSync(target,artifacts);else{fs.mkdirSync(artifacts);fs.symlinkSync(path.join(target,name),path.join(artifacts,name));}
   const isolated=await import(pathToFileURL(schema).href);assert.throws(()=>isolated.admitOrderedCurrentNative379SourceV2(),/symlink/);
  }finally{fs.rmSync(root,{recursive:true,force:true});}
 }
});
