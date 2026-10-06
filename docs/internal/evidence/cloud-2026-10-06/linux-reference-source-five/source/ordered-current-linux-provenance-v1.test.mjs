import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {admitOrderedCurrentLinuxProvenanceV1,readOrderedCurrentLinuxProvenanceV1} from './ordered-current-linux-provenance-v1.mjs';
const load=()=>structuredClone(readOrderedCurrentLinuxProvenanceV1());
test('actual Linux witness admission retains observed build identity and pending flags',()=>{
 const p=load();assert.equal(p.expectedFromTarget,false);assert.equal(p.installable,false);assert.equal(p.nativeVerified,false);assert.equal(p.identity.server_version_num,'180003');assert.equal(p.identity.pgcrypto,'1.4');assert.match(p.identity.version,/^PostgreSQL 18\.3 \(Debian /);assert.equal(p.evidence.identitySHA256,'f0a0c2453f34ca87c7f3b38a58462cc6476eef44f0d0d0c6c504bae8dbd794ac');
 assert.equal(p.scope,'observed-build-provenance-only; no RR/frame/catalog/control/native acceptance');
});
test('forged version/build/cleanup/source authority is refused even with recomputed inner digest',()=>{
 for(const mutate of [p=>p.identity.version+=' forged',p=>p.identity.server_version_num='180004',p=>p.identity.pgcrypto='1.3',p=>p.evidence.identitySHA256='0'.repeat(64),p=>p.evidence.independentReviewSHA256='0'.repeat(64),p=>p.evidence.runtimeBindingSHA256='0'.repeat(64),p=>p.evidence.rootExecutionReceiptSHA256='0'.repeat(64),p=>p.installable=true,p=>p.nativeVerified=true,p=>p.expectedFromTarget=true,p=>p.sourceCommit='0'.repeat(40),p=>p.identity.backend_pid=1,p=>p.identity.tcp_port=5432,p=>p.identity.current_user='borrowed']){
  const p=load();mutate(p);assert.throws(()=>admitOrderedCurrentLinuxProvenanceV1(p));
 }
 const p=load();p.identity.version=p.identity.version.replace('gcc','GCC');p.evidence.identitySHA256='a'.repeat(64);assert.throws(()=>admitOrderedCurrentLinuxProvenanceV1(p));
});
test('unknown/duplicate/trailing/noncanonical/invalid UTF8 caller bytes never become capture authority',()=>{
 const p=load();for(const value of [undefined,null,[],{...p,extra:true},JSON.stringify(p)+' {}',Buffer.from([0xff]),'{"format":"a","format":"b"}'])assert.throws(()=>admitOrderedCurrentLinuxProvenanceV1(value));
 const copy=load();copy.identity.extra='secret-canary-not-public';assert.throws(()=>admitOrderedCurrentLinuxProvenanceV1(copy),e=>!e.message.includes('secret-canary-not-public'));
});
test('returned capture descriptor is detached; caller/env cannot select version',()=>{
 const a=load();a.identity.version='mutated';assert.notEqual(load().identity.version,'mutated');assert.throws(()=>readOrderedCurrentLinuxProvenanceV1('/tmp/borrowed.json'));
 const original=process.env.POSTGRES_VERSION;process.env.POSTGRES_VERSION='caller-selected';try{assert.notEqual(load().identity.version,'caller-selected');}finally{if(original===undefined)delete process.env.POSTGRES_VERSION;else process.env.POSTGRES_VERSION=original;}
});
test('borrowed array properties, holes and accessors cannot bypass closed admission',()=>{
 const p=load();p.pending.extra='borrowed';assert.throws(()=>admitOrderedCurrentLinuxProvenanceV1(p));
 const s=load();s.pending[Symbol('borrowed')]=true;assert.throws(()=>admitOrderedCurrentLinuxProvenanceV1(s));
 const h=load();delete h.pending[0];assert.throws(()=>admitOrderedCurrentLinuxProvenanceV1(h));
 const g=load();let invoked=false;Object.defineProperty(g.pending,'0',{get(){invoked=true;return 'source-successor-independent-review';},enumerable:true});assert.throws(()=>admitOrderedCurrentLinuxProvenanceV1(g));assert.equal(invoked,false);
});
