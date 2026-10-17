import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {createMatcher,consumeFrames,frame} from './streaming_producer.mjs';
const lock=Buffer.from(JSON.stringify({lockfileVersion:3,packages:{'':{},'node_modules/example':{version:'1.2.0',integrity:'sha512-YQ==',resolved:'https://registry.npmjs.org/example/-/example-1.2.0.tgz'}}}));
const record=(name='example')=>({id:'GHSA-2345-6789-cfgh',published:'2020-01-01T00:00:00Z',modified:'2020-01-01T00:00:00Z',affected:[{package:{ecosystem:'npm',name},ranges:[{type:'SEMVER',events:[{introduced:'1.0.0'},{fixed:'2.0.0'}]}]}],database_specific:{severity:'HIGH'}});
const commit='a'.repeat(40),root='b'.repeat(40),sha='c'.repeat(64);
function messages(r=record()){return [{type:'start',profile:'official-github-complete-source-stream-v2',commit,root,lockSHA256:sha},{type:'npm',path:'advisories/unreviewed/GHSA-2345-6789-cfgh.json',blobOID:'d'.repeat(40),sha256:'e'.repeat(64),record:r},{type:'final',commit,root,lockSHA256:sha,selectedFiles:2,selectedBytes:200,npmRecords:1,npmBytes:100,allArchiveMembers:7,fullSelectedRosterSHA256:'f'.repeat(64),expandedArchiveBytes:10240,compressedBytes:500,compressedSHA256:'0'.repeat(64),releaseAccepted:false}];}
test('whole framed source to matcher retains HIGH and rejects omitted final or extra bytes',async()=>{
 const output=await consumeFrames(Readable.from(messages().map(frame)),createMatcher(lock),{commit,lockSHA256:sha});
 assert.equal(output.findings.length,1);assert.equal(output.findings[0].severity,'HIGH');assert.equal(output.releaseAccepted,false);
 for(const bytes of [Buffer.concat(messages().slice(0,2).map(frame)),Buffer.concat([...messages().map(frame),Buffer.from([0])]),Buffer.from([0,0,0,0]),Buffer.from([0,16,0,1])])await assert.rejects(consumeFrames(Readable.from([bytes]),createMatcher(lock),{commit,lockSHA256:sha}));
 const full=Buffer.concat(messages().map(frame));const chunks=Array.from(full,byte=>Buffer.from([byte]));assert.equal((await consumeFrames(Readable.from(chunks),createMatcher(lock),{commit,lockSHA256:sha})).findings.length,1);
});
test('unsupported npm semantics on unrelated names cannot hide behind lock filter',()=>{
 const matcher=createMatcher(lock);const r=record('unrelated');r.affected[0].ranges[0].database_specific={last_known_affected_version_range:'<99'};assert.throws(()=>matcher.accept({...messages()[1],record:r}));
 for(const edit of [r=>r.affected[0].ecosystem_specific={last_known_affected_version_range:'<99'},r=>r.affected[0].ranges[0].new_range_semantics='unhandled',r=>r.affected[0].database_specific={nested:{last_known_affected_version_range:'<99'}}]){const r=record('unrelated');edit(r);assert.throws(()=>createMatcher(lock).accept({...messages()[1],record:r}));}
 const wrong=record('unrelated');wrong.affected[0].ranges[0].events=[{introduced:'bad-version'}];assert.throws(()=>matcher.accept({...messages()[1],record:wrong}));
 const mixed=record();mixed.affected.push({package:{ecosystem:'PyPI',name:'other'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'different syntax'}]}]});const m=createMatcher(lock);m.accept({...messages()[1],record:mixed});assert.equal(m.result().findings.length,1);
 const withdrawn=record();withdrawn.withdrawn='2021-01-01T00:00:00Z';const w=createMatcher(lock);w.accept({...messages()[1],record:withdrawn});assert.equal(w.result().findings[0].withdrawn,withdrawn.withdrawn);
});
test('stream identity, counters and duplicate source records are closed',async()=>{
 for(const mutate of [m=>m[0].commit='1'.repeat(40),m=>m[2].npmRecords=2,m=>m.push(m[2]),m=>m[0].verified=true]){const m=structuredClone(messages());mutate(m);await assert.rejects(consumeFrames(Readable.from(m.map(frame)),createMatcher(lock),{commit,lockSHA256:sha}));}
 const m=createMatcher(lock);m.accept(messages()[1]);assert.throws(()=>m.accept(messages()[1]));
});

test('actual verifier frames feed actual matcher through a bounded Python fixture child',async()=>{
 const {spawnSync}=await import('node:child_process');const {fileURLToPath}=await import('node:url');
 const source=fileURLToPath(new URL('./',import.meta.url));
 const script=`import sys,io,hashlib\nsys.dont_write_bytecode=True\nsys.path.insert(0,sys.argv[1])\nimport streaming_intake as s\nfrom streaming_intake_test import fixture\nroot,trees,archive=fixture()\ncommit='a'*40\nlock='c'*64\ns.emit_frame({'type':'start','profile':'official-github-complete-source-stream-v2','commit':commit,'root':root,'lockSHA256':lock},sys.stdout.buffer)\nr=s.verify_archive(io.BytesIO(archive),root,lambda oid:trees[oid],commit,lambda msg:s.emit_frame(msg,sys.stdout.buffer),lambda:None)\nr.update(type='final',commit=commit,root=root,lockSHA256=lock,compressedBytes=len(archive),compressedSHA256=hashlib.sha256(archive).hexdigest())\ns.emit_frame(r,sys.stdout.buffer)\n`;
 const child=spawnSync('python3',['-B','-c',script,source],{timeout:10000,maxBuffer:4*2**20});assert.equal(child.status,0);assert.equal(child.signal,null);assert.equal(child.stderr.length,0);
 const result=await consumeFrames(Readable.from([child.stdout]),createMatcher(lock),{commit,lockSHA256:sha});assert.equal(result.source.selectedFiles,2);assert.equal(result.npmRecords,1);assert.equal(result.findings[0].severity,'HIGH');assert.equal(result.releaseAccepted,false);
});
