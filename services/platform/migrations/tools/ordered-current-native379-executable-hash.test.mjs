import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
const approved = '93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068';
const source = fs.readFileSync(process.env.NATIVE379_HASH_SCHEMA || new URL('./ordered-current-native379-source-schema-v3.mjs',import.meta.url),'utf8');
function checker(filesystem=fs) {
 const context = vm.createContext({fs:filesystem,crypto,Buffer,fail(message){throw Error(message);}});
 if (source.includes('function native379V3ApprovedExecutable(')) {
  const start=source.indexOf('function native379V3ApprovedExecutable(');
  const end=source.indexOf('// Wrong runtime must fail before evaluating',start);
  assert.ok(end>start);
  return vm.runInContext(source.slice(start,end)+'\nnative379V3ApprovedExecutable',context);
 }
 // The genuine predecessor runtime guard, with only its fixed SHA literal
 // parameterized for owned tiny-file identity challenges. No generator is run.
 const literal="if(!fs.lstatSync(executable).isFile()||sha(fs.readFileSync(executable))!=="+JSON.stringify(approved).replaceAll('"',"'")+")fail('Node runtime requires approved executable SHA256');";
 assert.equal(source.split(literal).length,2,'exact original executable guard');
 return vm.runInContext("const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');(executable,expected)=>{"+literal.replace("'"+approved+"'",'expected')+'}',context);
}
function fixture(run) {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'native379-hash-fixture-'));
 try {const file=path.join(dir,'executable');fs.writeFileSync(file,'owned executable fixture\n');run(file,crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'));}
 finally {fs.rmSync(dir,{recursive:true,force:true});}
}
test('executable bootstrap preserves exact SHA with bounded reads and refuses identity/short-read faults',()=>{
 let largest=0,reads=0;
 const bounded={...fs,readFileSync(){throw Error('eager executable read refused by allocation oracle');},readSync(fd,buffer,offset,length,position){largest=Math.max(largest,length);reads++;return fs.readSync(fd,buffer,offset,length,position);}};
 checker(bounded)(fs.realpathSync(process.execPath),approved);
 assert.ok(reads>1);assert.ok(largest<=65536);
 fixture((file,expected)=>{
  assert.throws(()=>checker()(file,'0'.repeat(64)),/approved executable/);
  let opened=0,closed=0;
  const short={...fs,openSync(...args){opened++;return fs.openSync(...args);},closeSync(fd){closed++;return fs.closeSync(fd);},readSync(){return 0;},readFileSync(){return Buffer.alloc(0);}};
  assert.throws(()=>checker(short)(file,expected),/short read|approved executable/);assert.equal(closed,opened);
  let replaced=false;
  const replace=()=>{if(!replaced){replaced=true;const bytes=fs.readFileSync(file);fs.unlinkSync(file);fs.writeFileSync(file,bytes);}};
  const replacement={...fs,readFileSync(p,...args){const bytes=fs.readFileSync(p,...args);replace();return bytes;},readSync(fd,buffer,...args){const n=fs.readSync(fd,buffer,...args);replace();return n;}};
  assert.throws(()=>checker(replacement)(file,expected),/changed|approved executable/);assert.equal(replaced,true);
 });
});
