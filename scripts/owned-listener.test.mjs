import test from 'node:test';import assert from 'node:assert/strict';
import {captureStart,observeOwnedListener}from './owned-listener.mjs';
const pid=12345,start='998877',port=32102,inode='54321';
const stat=(p=pid,s=start,state='S')=>`${p} (owned tool) ${state} ${Array(18).fill('0').join(' ')} ${s}`;
const tcp=(address='0100007F',n=port,id=inode)=>`header\n 0: ${address}:${n.toString(16).toUpperCase()} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 ${id} 1`;
function readers(change){return {read:async p=>p.endsWith('/stat')?stat(change?.pid,change?.start,change?.state):tcp(change?.address,change?.port,change?.inode),fds:async()=>['0','1','2','3','4'],link:async()=>`socket:[${change?.fdInode??inode}]`};}
test('matches actual PID lifetime and exact loopback listener socket inode',async()=>{const r=readers();assert.equal(await captureStart(pid,r),start);const value=await observeOwnedListener({pid,start,port},r);assert.deepEqual(value,{pid,start,port,inode});});
for(const [name,change]of [['different PID',{pid:pid+1}],['reused PID',{start:'111'}],['zombie',{state:'Z'}],['nonloopback',{address:'00000000'}],['different port',{port:port+1}],['foreign socket inode',{fdInode:'111'}]])test('refuses '+name,async()=>assert.rejects(observeOwnedListener({pid,start,port},readers(change))));
