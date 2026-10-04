import test from 'node:test';
import assert from 'node:assert/strict';
import {browserCommandFailureAnnotation}from './browser-command-failure.mjs';
const steps=["up-to-60", "up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response", "up-authorization-temporal-identity-profile", "up-authorization-worker-profile"];
const executable='/fixture/agentsec-migrate';
const args=['up-authorization-runtime-profile'];
const base='::error title=Compliance browser command failed::Observed command class: current-profile-up-authorization-runtime-profile; failure: nonzero-exit.';
const marker=(step,stage)=>`ZASP_AUTHORIZATION_RUNTIME_PROFILE_FAILED_STEP=${step};STAGE=${stage}\n`;
const detail=(step,stage)=>`${base} Observed inner step: ${step}; stage: ${stage}.`;

test('one exact complete known composite marker identifies every fixed inner step and stage',()=>{
 for(const step of steps)for(const stage of ['install','forward-readiness']){
  const got=browserCommandFailureAnnotation(executable,args,'nonzero-exit',marker(step,stage));
  assert.equal(got,detail(step,stage),'closed inner step/stage annotation absent');
 }
});
test('duplicates and mixed arbitrary stderr never become an inner witness',()=>{
 const known=marker(steps[1],'install');
 for(const output of [known+known,known+marker(steps[2],'forward-readiness'),'fixture-private-cause\n'+known,known+'fixture-private-cause\n',known+'\n','\n'+known]){
  const got=browserCommandFailureAnnotation(executable,args,'nonzero-exit',output);
  assert.equal(got,base);assert.doesNotMatch(got,/fixture-private-cause/);
 }
});
test('unknown malformed partial and nonstring witnesses are refused without coercion',()=>{
 const known=marker(steps[1],'install');
 for(const output of [marker('fixture-private-cause','install'),marker(steps[1],'fixture-private-cause'),known.trimEnd(),known.replace('\n','\r\n'),known.replace(';STAGE=',';STAGE= '),known.replace('FAILED_STEP=','FAILED_STEP ='),known.toLowerCase(),' '+known,known+'fixture-private-cause',null,undefined,{}, {toString(){throw Error('fixture-private-cause');}}]){
  assert.equal(browserCommandFailureAnnotation(executable,args,'nonzero-exit',output),base);
 }
});
test('oversized stderr and marker at a shifted boundary cannot be reflected or accepted',()=>{
 const known=marker(steps[1],'install');
 for(const output of ['x'.repeat(513),known+'x'.repeat(513),'x'.repeat(513)+known,'fixture-private-cause'+known]){
  const got=browserCommandFailureAnnotation(executable,args,'nonzero-exit',output);assert.equal(got,base);assert.doesNotMatch(got,/fixture-private-cause/);
 }
});
test('inner witness cannot change original action kind or executable classifications',()=>{
 const known=marker(steps[1],'install');
 for(const [exe,command,kind]of [[executable,args,'deadline'],[executable,['up-to-60'],'nonzero-exit'],['go',['build','-o','/fixture/out','./agentsec-migrate'],'nonzero-exit'],['agentsec-migrate',args,'nonzero-exit'],[executable,[...args,'fixture-private-cause'],'nonzero-exit'],[executable,args,'fixture-private-cause']]){
  assert.equal(browserCommandFailureAnnotation(exe,command,kind,known),browserCommandFailureAnnotation(exe,command,kind));
 }
});
test('absence preserves every existing current profile action annotation',()=>{
 for(const action of ['up-to-60','up-authorization-runtime-profile','register-temporal-executor-principals','register-authorization-verifier','register-identity-session-verifier','register-identity-webhook-verifier','register-worker-authorization-verifier','register-compensation-authorization-verifier'])for(const kind of ['deadline','nonzero-exit']){
  assert.equal(browserCommandFailureAnnotation(executable,[action],kind,''),browserCommandFailureAnnotation(executable,[action],kind));
 }
});
