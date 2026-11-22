import test from 'node:test';
import assert from 'node:assert/strict';
import {observePublicSources,checkRefresh,refreshEndpoints} from './refresh.mjs';
import {sha256} from './trust.mjs';

const observedAt='2026-11-22T12:00:00.000Z', file='vulnerability-db_v6.1.2_2026-11-22T00:00:00Z_10.tar.zst';
const refs={
 npm:{ref:'refs/heads/main',object:{type:'commit',sha:'f'.repeat(40)}},
 go:{modified:'2026-11-20T10:00:00.000Z'},
 grype:{schemaVersion:'v6.1.2',checksum:'sha256:'+sha256('db'),built:observedAt,path:file,status:'active'}
};
test('fresh source records bind every revision, approved time, and publisher archive checksum',async()=>{
 const called=[];
 const refresh=await observePublicSources({clock:()=>new Date(observedAt),fetchPublic:async(url,opts)=>{
   const id=Object.keys(refreshEndpoints).find(id=>refreshEndpoints[id]===url);
   called.push(id);assert.equal(opts.credentials,'omit');assert.equal(opts.redirect,'error');assert.equal(Object.hasOwn(opts.headers,'authorization'),false);
   return Response.json(refs[id]);
 }});
 assert.deepEqual(called.sort(),['go','grype','npm']);
 const bytes=Buffer.from(JSON.stringify(refresh));
 const intake={refreshSha256:sha256(bytes),sources:[
   {id:'npm',version:refs.npm.object.sha},{id:'go',version:refs.go.modified},
   {id:'grype',version:file.slice(0,-8),transfer:{url:'https://grype.anchore.io/databases/v6/'+file,sha256:sha256('db')}}
 ].map(s=>({...s,refreshedAt:observedAt}))};
 checkRefresh(bytes,intake);
 assert.throws(()=>checkRefresh(Buffer.concat([bytes,Buffer.from('\n')]),intake),/digest differs/);
 intake.sources[2].transfer.sha256=sha256('other archive');assert.throws(()=>checkRefresh(bytes,intake),/checksum/);
 intake.sources[0].version='a'.repeat(40);assert.throws(()=>checkRefresh(bytes,intake),/revision/);
});
test('a missed provider refresh produces no observation receipt',async()=>{
 await assert.rejects(observePublicSources({fetchPublic:async url=>url===refreshEndpoints.go?new Response(null,{status:503}):Response.json(refs[url===refreshEndpoints.npm?'npm':'grype'])}),/unavailable/);
});
