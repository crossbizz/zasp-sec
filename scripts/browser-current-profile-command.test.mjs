import test from 'node:test';
import assert from 'node:assert/strict';
import {browserCommandFailureAnnotation} from './browser-command-failure.mjs';
const actions=['up-to-60','up-authorization-runtime-profile','register-temporal-executor-principals','register-authorization-verifier','register-identity-session-verifier','register-identity-webhook-verifier','register-worker-authorization-verifier','register-compensation-authorization-verifier'];
const annotation=(label,kind='nonzero-exit')=>`::error title=Compliance browser command failed::Observed command class: ${label}; failure: ${kind}.`;
test('closed current profile migration actions identify a failing command without raw paths or arguments',()=>{
 for(const action of actions)for(const kind of ['nonzero-exit','deadline']){
  const got=browserCommandFailureAnnotation('/CANARY_PRIVATE_PATH/agentsec-migrate',[action],kind);
  assert.equal(got,annotation(`current-profile-${action}`,kind));assert.doesNotMatch(got,/CANARY/);
 }
});
test('current profile classification refuses unknown executables and argument shapes',()=>{
 for(const [executable,args]of [
  ['/CANARY_PRIVATE_PATH/other',['up-to-60']],['agentsec-migrate',['up-to-60']],
  ['/owned/agentsec-migrate',['CANARY_RAW_ACTION']],['/owned/agentsec-migrate',['up-to-60','CANARY_EXTRA']],
  ['/owned/agentsec-migrate',null],['/owned/agentsec-migrate',[]],['/owned/agentsec-migrate',[{toString(){throw Error('CANARY');}}]],
 ])assert.equal(browserCommandFailureAnnotation(executable,args,'nonzero-exit'),annotation('other-command'));
 assert.equal(browserCommandFailureAnnotation('/owned/agentsec-migrate',['up-to-60'],'CANARY_FAILURE'),null);
});
