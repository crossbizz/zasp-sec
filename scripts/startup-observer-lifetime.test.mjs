import test from 'node:test';
import assert from 'node:assert/strict';
import {startOwnedRuntimeLifetime,startRetainedOwnedRuntimeLifetime} from './owned-runtime-lifetime.mjs';
import {recordOwnedRuntimeStartupFailure,describeOwnedRuntimeStartupFailure} from './owned-runtime-startup-diagnostics.mjs';

for(const retained of [false,true])test(`${retained?'retained':'new'} runtime stops and joins the active sampler before failed-start cleanup`,async()=>{
 let sample,release,entered,removed=false,observations=0,toolsClosed=0;
 const active=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{entered=resolve;});
 const original=recordOwnedRuntimeStartupFailure(Error('private startup failure'),'service-openfga-store');
 const adapters={
  observe:async()=>{if(++observations>1)await active;return {free:4_000_000_000n,allocated:1n};},
  load:async()=>({}),reopen:async()=>({}),closeTool:async()=>{toolsClosed++;},
  setTimer:fn=>{sample=fn;return 1;},clearTimer:()=>{},
  start:async(_config,_adapters,_signal,beforeStartupCleanup)=>{
   sample();
   const stopped=beforeStartupCleanup?.();entered();await stopped;
   removed=true;throw original;
  },
 };
 const config=retained?{stateRoot:'/state',archiveRoot:'/archive',rawRoot:'/raw',run:'0123456789abcdef'}:{root:'/owned',run:'0123456789abcdef'};
 const running=(retained?startRetainedOwnedRuntimeLifetime:startOwnedRuntimeLifetime)(config,adapters);
 void running.catch(()=>{});
 try {
  await started;await new Promise(resolve=>setImmediate(resolve));
  assert.equal(removed,false,'state removal must wait for the active sample');
  const before=observations;sample();assert.equal(observations,before,'a stopped sampler cannot start another observation');
  release();let failure;try{await running;}catch(error){failure=error;}
  assert.equal(failure,original);assert.deepEqual(describeOwnedRuntimeStartupFailure(failure),{phase:'service-openfga-store',kind:'refused'});
  assert.equal(removed,true);assert.equal(toolsClosed,2);
 } finally {release();await running.catch(()=>{});}
});
