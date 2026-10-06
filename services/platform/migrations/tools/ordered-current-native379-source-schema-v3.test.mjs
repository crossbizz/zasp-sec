import test from 'node:test';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import {readOrderedCurrentNative379LinuxReferenceV3,assertOrderedCurrentNative379LinuxReferenceV3,admitOrderedCurrentNative379SourceV3,native379V3Canonical} from './ordered-current-native379-source-schema-v3.mjs';
import {readOrderedCurrentLinuxProvenanceV1} from './ordered-current-linux-provenance-v1.mjs';
let reference;
const load=()=>structuredClone(reference??=readOrderedCurrentNative379LinuxReferenceV3());
test('v3 reference binds exact reviewed Linux capture while final source admission remains closed',()=>{
 const r=load(),identity=readOrderedCurrentLinuxProvenanceV1();
 assert.equal(r.identity.postgres,identity.identity.version);assert.equal(r.referenceProvenance.postgres,r.identity.postgres);
 assert.equal(r.identity.serverVersionNum,180003);assert.equal(r.identity.pgcrypto,'1.4');assert.equal(Object.keys(r.source5Pins).length,5);assert.equal(Object.keys(r.outputs).length,8);
 assert.equal(r.installable,false);assert.equal(r.nativeVerified,false);assert.equal(r.captureAuthority,false);
 assert.throws(()=>admitOrderedCurrentNative379SourceV3(),/frozen Go v3/);
 assert.throws(()=>readOrderedCurrentNative379LinuxReferenceV3({}),/caller-selected/);
});
test('v3 reference refuses historical reference, omitted source/output and status promotion',()=>{
 const r=load();
 for(const mutate of [q=>q.referenceProvenance.postgres='PostgreSQL 18.3 (Homebrew)',q=>q.identity.postgres+=' borrowed',q=>delete q.source5Pins['ordered-current-linux-provenance-v1.json'],q=>delete q.outputs['development-module.sql'],q=>q.outputPins['development-module.sql']='0'.repeat(64),q=>q.outputs['development-module.sql']+='\n',q=>q.manifestPayloadSHA256='0'.repeat(64),q=>q.nativeVerified=true,q=>q.pending=[]]){const q=structuredClone(r);mutate(q);assert.throws(()=>assertOrderedCurrentNative379LinuxReferenceV3(q),/closed Linux/);}
});
test('v3 closure comparison refuses accessors, symbols and ambiguous array authority',()=>{
 const r=load();const q=structuredClone(r);Object.defineProperty(q,'installable',{get(){throw Error('getter invoked');}});assert.throws(()=>assertOrderedCurrentNative379LinuxReferenceV3(q),/accessor/);
 assert.throws(()=>native379V3Canonical([,1]),/(sparse|array authority)/);assert.throws(()=>native379V3Canonical({value:NaN}),/noninteger/);assert.throws(()=>native379V3Canonical({[Symbol('authority')]:true}),/symbol/);
});

test('wrong Node runtime refuses before any reviewed source assembly read',()=>{
 const url=new URL('./ordered-current-native379-source-schema-v3.mjs',import.meta.url).href;
 const code=`import fs from 'node:fs'; Object.defineProperty(process,'version',{value:'v22.23.0'}); fs.readFileSync=()=>{throw Error('reviewed input read before runtime refusal');}; try{await import(${JSON.stringify(url)});process.exitCode=2;}catch(e){if(!/approved executable SHA256/.test(e.message)){process.stderr.write(e.message);process.exitCode=3;}}`;
 const r=spawnSync(process.execPath,['--input-type=module','-e',code],{encoding:'utf8',timeout:10000,maxBuffer:1048576,env:{PATH:process.env.PATH,TMPDIR:process.env.TMPDIR,TZ:'UTC',LANG:'C'}});
 assert.equal(r.error,undefined);assert.equal(r.signal,null);assert.equal(r.status,0,r.stderr);
});

test('fixed execution closure refuses changed generator and transitive code before benign execution',()=>{
 for(const variant of ['generator-bytes','transitive-bytes','generator-symlink','ancestor-symlink']){
  const temporary=fs.mkdtempSync(path.join(process.env.TMPDIR,'native379-v3-preimport-'+variant+'-'));
  try{
   const originalRoot=fileURLToPath(new URL('../../../../',import.meta.url));
   const tools='services/platform/migrations/tools/';
   const manifest=JSON.parse(fs.readFileSync(path.join(originalRoot,tools,'ordered-current-native379-packet-v2-artifacts/source-inputs.json')));
   const extras=['ordered-current-native379-packet-v2.mjs','ordered-current-native379-source-schema-v2.mjs','ordered-current-native379-packet-v2-artifacts/source-inputs.json','ordered-current-native379-packet-v2-artifacts/generated-identities.json','ordered-current-native379-packet-v2-artifacts/source-fact-delta.json','build-ordered-current-linux-successor-v1.mjs','build-ordered-current-linux-successor-v1.test.mjs','ordered-current-linux-provenance-v1.mjs','ordered-current-linux-provenance-v1.test.mjs','ordered-current-linux-provenance-v1.json','ordered-current-native379-source-schema-v3.mjs'];
   // Read-only links avoid duplicating source artifacts. A mutated test member
   // is unlinked before writing, so no original inode can change.
   for(const relative of new Set([...Object.keys(manifest.files),...extras.map(n=>tools+n)])){
    const destination=path.join(temporary,relative);fs.mkdirSync(path.dirname(destination),{recursive:true});fs.linkSync(path.join(originalRoot,relative),destination);
   }
   const generator=path.join(temporary,tools,'build-ordered-current-linux-successor-v1.mjs');
   if(variant==='generator-bytes'||variant==='transitive-bytes'){
    const modified=variant==='generator-bytes'?generator:path.join(temporary,tools,'ordered-current-native379-semantics-v1.mjs');
    const raw=fs.readFileSync(modified);fs.unlinkSync(modified);fs.writeFileSync(modified,"process.stdout.write('BENIGN_UNVERIFIED_CODE_EXECUTED\\n');\n"+raw);
   }else if(variant==='generator-symlink'){
    fs.unlinkSync(generator);fs.symlinkSync(path.join(originalRoot,tools,'build-ordered-current-linux-successor-v1.mjs'),generator);
   }else{
    const directory=path.resolve(temporary,tools);const target=path.join(temporary,'regular-tools');fs.renameSync(directory,target);fs.symlinkSync(target,directory);
   }
   const url=pathToFileURL(path.join(temporary,tools,'ordered-current-native379-source-schema-v3.mjs')).href;
   const script=`import fs from 'node:fs';const original=fs.readFileSync;fs.readFileSync=function(...args){if(new Error().stack.includes('build-ordered-current-linux-successor-v1.mjs'))process.stdout.write('BENIGN_GENERATOR_ASSEMBLY_EXECUTED\\n');return original.apply(this,args);};try{await import(${JSON.stringify(url)});process.stdout.write('UNEXPECTED_ACCEPTANCE\\n');process.exitCode=2;}catch(e){if(!/ordered-current native379 v3 source (hash|nonregular or symlink)/.test(e.message)){process.stderr.write(e.message);process.exitCode=3;}else process.stdout.write('SOURCE_REFUSED_BEFORE_IMPORT\\n');}`;
   const r=spawnSync(process.execPath,['--preserve-symlinks','--input-type=module','-e',script],{encoding:'utf8',timeout:10000,maxBuffer:1048576,env:{PATH:process.env.PATH,TMPDIR:process.env.TMPDIR,TZ:'UTC',LANG:'C'}});
   assert.equal(r.error,undefined,variant);assert.equal(r.signal,null,variant);assert.equal(r.status,0,variant+':'+r.stderr);assert.equal(r.stdout,'SOURCE_REFUSED_BEFORE_IMPORT\n',variant);
  }finally{fs.rmSync(temporary,{recursive:true,force:true});}
 }
});
