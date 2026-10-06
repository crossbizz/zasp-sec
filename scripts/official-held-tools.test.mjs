import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const observed=JSON.parse(readFileSync(new URL('./observed-canonical-archive-members.json',import.meta.url)));
import { parseTar } from './official-held-tools.mjs';
function archive(entries){const chunks=[];for(const {name,body=Buffer.from('ELF-fixture'),type='0'}of entries){const h=Buffer.alloc(512);h.write(name);h.write('0000500\0',100);h.write('0000000\0',108);h.write('0000000\0',116);h.write(body.length.toString(8).padStart(11,'0')+'\0',124);h.write('00000000000\0',136);h.fill(32,148,156);h.write(type,156);h.write('ustar\0',257);h.write('00',263);let sum=0;for(const v of h)sum+=v;h.write(sum.toString(8).padStart(6,'0')+'\0 ',148);chunks.push(h,body,Buffer.alloc((512-body.length%512)%512));}chunks.push(Buffer.alloc(1024));return Buffer.concat(chunks);}
test('consumes exact regular executable member and closed auxiliary inventory',()=>{const tar=archive([{name:'LICENSE',body:Buffer.from('license')},{name:'temporal'}]);const result=parseTar('temporal',tar);assert.equal(result.member,'temporal');assert.equal(result.bytes.toString(),'ELF-fixture');assert.deepEqual(result.inventory,['LICENSE','temporal']);});
for(const [name,entries]of [
 ['duplicate executable',[{name:'temporal'},{name:'temporal'}]],
 ['traversal',[{name:'../temporal'}]],
 ['absolute',[{name:'/temporal'}]],
 ['symlink',[{name:'temporal',type:'2'}]],
 ['hardlink',[{name:'temporal',type:'1'}]],
 ['pax extension',[{name:'temporal',type:'x'}]],
 ['unknown member',[{name:'temporal'},{name:'unexpected'}]],
 ['missing executable',[{name:'LICENSE'}]],
])test('refuses '+name,()=>assert.throws(()=>parseTar('temporal',archive(entries))));
test('refuses header checksum corruption',()=>{const value=archive([{name:'temporal'}]);value[1]^=1;assert.throws(()=>parseTar('temporal',value));});
test('refuses truncated member data',()=>{const value=archive([{name:'temporal'}]);assert.throws(()=>parseTar('temporal',value.subarray(0,515)));});
test('refuses trailing nonzero payload',()=>{const value=archive([{name:'temporal'}]);value[value.length-1]=1;assert.throws(()=>parseTar('temporal',value));});

for(const profile of observed){
 test('accepts only complete observed '+profile.tool+' regular-name roster',()=>{const entries=profile.members.map(member=>({name:member.name,body:Buffer.from('x')}));const value=parseTar(profile.tool,archive(entries));assert.deepEqual(value.inventory,profile.members.map(member=>member.name).sort());assert.throws(()=>parseTar(profile.tool,archive(entries.slice(1))));assert.throws(()=>parseTar(profile.tool,archive([...entries,{name:'assets/unreviewed'}])));assert.throws(()=>parseTar(profile.tool,archive(entries.toReversed())));});
 test('refuses observed '+profile.tool+' member ceiling overflow before body consumption',()=>{const entries=profile.members.map(member=>({name:member.name,body:Buffer.from('x')}));const tar=archive(entries),member=profile.members[0];tar.fill(0,124,136);tar.write((member.bytes+1).toString(8).padStart(11,'0')+'\0',124);tar.fill(32,148,156);let sum=0;for(const byte of tar.subarray(0,512))sum+=byte;tar.write(sum.toString(8).padStart(6,'0')+'\0 ',148);assert.throws(()=>parseTar(profile.tool,tar));});
}
