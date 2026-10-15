import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as traceDiagnostics from './connector-acceptance-groups.mjs';
import { CONNECTOR_ACCEPTANCE_GROUPS as groups, selectConnectorAcceptanceGroup as select, validateConnectorAcceptanceTrace as validate, parseConnectorNativeObservation as observation, describeConnectorAcceptanceTraceFailure as describeTraceFailure } from './connector-acceptance-groups.mjs';
const pkg = 'github.com/zasp-ai/zasp-sec/services/platform/apiserver';
const trace = selected => [...selected.names.flatMap(Test => [{Package: pkg, Test, Action: 'run'}, {Package: pkg, Test, Action: 'pass'}]), {Package: pkg, Action: 'pass'}];
test('required application groups retain every flow and owned database', () => {
  assert.deepEqual(Object.keys(groups), ['approval-test74', 'approval-ordered-planning', 'approval-ordered-progress', 'approval-flow', 'approval', 'oauth', 'lifecycle', 'pkce', 'callback', 'approval-overflow', 'approval-future-test74', 'approval-future-progress']);
  assert.deepEqual(Object.values(groups).map(g => [g.names.length, g.postgresJoins]), [[1, 2], [1, 2], [1, 2], [6, 2], [6, 1], [3, 1], [6, 2], [4, 2], [4, 2], [1, 2], [1, 2], [1, 2]]);
  const names = Object.values(groups).flatMap(g => g.names);
  assert.equal(names.length, 35); assert.equal(new Set(names).size, 35);
  assert.equal(Object.values(groups).reduce((n, g) => n + g.postgresJoins, 0), 22);
  for (const key of Object.keys(groups)) { assert.equal(select([key]), groups[key]); validate(trace(groups[key]), groups[key]); }
});
test('missing, arbitrary, inherited, or multiple selectors cannot silently run a subset', () => {
  for (const args of [[], [''], ['all'], ['oauth|callback'], ['oauth', 'pkce'], ['constructor'], ['__proto__'], null, 'oauth']) assert.throws(() => select(args));
});
test('partial, duplicated, skipped, failed, foreign, or cross-group traces refuse with issued closed stages', () => {
  const selected = groups.callback, good = trace(selected);
  const cases = [
    [good.slice(1), selected, 'run-roster'],
    [[...good, good[0]], selected, 'run-roster'],
    [[...good, {Package: pkg, Action: 'skip'}], selected, 'event-action'],
    [[...good, {Package: pkg, Action: 'fail'}], selected, 'event-action'],
    [[...good, {Package: pkg, Action: 'unknown'}], selected, 'event-action'],
    [[...good, {Package: pkg, Test: groups.pkce.top, Action: 'run'}], selected, 'event-case'],
    [good.map(row => ({...row, Package: 'other/package'})), selected, 'event-package'],
    [good.filter(row => row.Test !== undefined), selected, 'package-pass'],
    [good, {...selected}, 'selection'],
    [[], selected, 'empty'],
    [[null], selected, 'event-shape'],
    [good.filter(row => !(row.Action === 'pass' && row.Test === selected.top)), selected, 'pass-roster'],
  ];
  for (const [rows, group, stage] of cases) assert.throws(() => validate(rows, group), error => {
    assert.equal(describeTraceFailure(error), stage); return true;
  });
  for (const value of [new Error('PRIVATE_CANARY'), {stage:'event-package'}, {message:'event-case'}, null, 'event-action']) assert.equal(describeTraceFailure(value), 'unknown');
});

test('rejected extra event cases expose only issued fixed descriptors and never change acceptance',()=>{
  const selected=groups.approval,good=trace(selected);
  validate([...good,{Package:pkg,Action:'output',Output:'PRIVATE_PACKAGE_CANARY'}],selected);
  const cases=[
    [groups.pkce.top,'nonempty-string','other-fixed-group'],
    ['TestApprovalActivationOldWriterProcess','nonempty-string','source-known-owned-helper'],
    ['PRIVATE_TEST_CANARY','nonempty-string','unrecognized'],
    ['','empty-string','unrecognized'],[null,'null','non-string'],[[],'non-string','non-string'],
  ];
  for(const [Test,testShape,caseClass]of cases)for(const action of ['start','run','output','pass']){
    const rows=[...good,{Package:pkg,Test,Action:action,Output:'PRIVATE_OUTPUT_CANARY'}];let issued;
    assert.throws(()=>validate(rows,selected),error=>{issued=error;assert.equal(describeTraceFailure(error),'event-case');return true;});
    assert.equal(typeof traceDiagnostics.describeConnectorAcceptanceTraceEvent,'function');
    const descriptor=traceDiagnostics.describeConnectorAcceptanceTraceEvent(issued);
    assert.deepEqual(descriptor,{action,testShape,caseClass});assert.equal(Object.isFrozen(descriptor),true);
    assert.equal(traceDiagnostics.describeConnectorAcceptanceTraceEvent(issued),descriptor);
    assert.doesNotMatch(JSON.stringify(descriptor),/PRIVATE|CANARY|TestApproval|TestConnector|stack|hash/i);
    assert.throws(()=>validate(rows,selected));
  }
  let actionReads=0,changedActionError;
  const changing={Package:pkg,Test:'PRIVATE_TEST_CANARY',get Action(){return ++actionReads<=3?'output':'PRIVATE_ACTION_CANARY';}};
  assert.throws(()=>validate([...good,changing],selected),error=>{changedActionError=error;assert.equal(describeTraceFailure(error),'event-case');return true;});
  assert.equal(traceDiagnostics.describeConnectorAcceptanceTraceEvent(changedActionError),null);
  for(const error of [null,{},Error('PRIVATE_ERROR_CANARY'),{action:'output',testShape:'nonempty-string',caseClass:'unrecognized'}])assert.equal(traceDiagnostics.describeConnectorAcceptanceTraceEvent(error),null);
});

test('closed event observation preserves the exact original assertion error and existing stage API',()=>{
  const original=Error('PRIVATE_ASSERTION_CANARY'),stages=new WeakMap(),events=new WeakMap();
  const guarded={...assert,ok(value,...args){if(!value)throw original;return assert.ok(value,...args);}};
  // Execute the actual unchanged assertion function with a controlled issued
  // error. This verifies catch/observation never replaces that original object.
  const actual=new Function('assert','CONNECTOR_ACCEPTANCE_GROUPS','applicationPackage','traceFailureStages','traceFailureEvents',`return (${validate.toString()});`)(guarded,groups,pkg,stages,events);
  assert.throws(()=>actual([...trace(groups.approval),{Package:pkg,Test:'PRIVATE_EXTRA_CANARY',Action:'output'}],groups.approval),error=>error===original);
  assert.equal(stages.get(original),'event-case');
  assert.deepEqual(events.get(original),{action:'output',testShape:'nonempty-string',caseClass:'unrecognized'});
  assert.doesNotMatch(JSON.stringify(events.get(original)),/PRIVATE|CANARY/);
});

test('actual hosted refusal notice emits fixed fields without reflecting rejected test or output',()=>{
  const source=fs.readFileSync(new URL('./hosted-connected-connector-acceptance.mjs',import.meta.url),'utf8');
  const begin=source.indexOf("}catch(error){if(phase==='exact-test-roster')"),end=source.indexOf("\nfinally{phase='owned-service-cleanup';",begin);
  assert.ok(begin>0&&end>begin);
  const messages=[],receipt={};let issued;
  assert.throws(()=>validate([...trace(groups.approval),{Package:pkg,Test:'PRIVATE_TEST_CANARY',Action:'output',Output:'PRIVATE_OUTPUT_CANARY'}],groups.approval),error=>{issued=error;return true;});
  const run=new Function('describeConnectorAcceptanceTraceFailure','describeConnectorAcceptanceTraceEvent','receipt','console','failureClass','issued',`let phase='exact-test-roster',refused=false;try{throw issued;}${source.slice(begin+1,end)};return refused;`);
  assert.equal(run(describeTraceFailure,traceDiagnostics.describeConnectorAcceptanceTraceEvent,receipt,{log:value=>messages.push(value)},()=> 'ERR_ASSERTION',issued),true);
  assert.deepEqual(messages,['::notice title=Connector acceptance trace refusal::stage=event-case; eventAction=output; eventTestShape=nonempty-string; eventCaseClass=unrecognized. Closed diagnostic only; acceptance remains refused.']);
  assert.equal(receipt.traceFailureStage,'event-case');assert.equal(receipt.failedPhase,'exact-test-roster');assert.doesNotMatch(messages.join(''),/PRIVATE|CANARY|Output:/);
});

test('native observations expose only bounded closed catalog and cutover fields', () => {
  const payload='approval payload observation stage=payload-load outcome=denied parent_live=true lease_live=true provider_live=true';
  assert.deepEqual(observation(payload), {kind:'approval-payload',value:{stage:'payload-load',outcome:'denied',parentLive:true,leaseLive:true,providerLive:true}});
  for(const outcome of ['context-deadline','context-canceled','lease-margin','denied','unavailable','other-error','run-mismatch']) assert.equal(observation(payload.replace('outcome=denied','outcome='+outcome)).value.outcome,outcome);
  for(const input of [payload+' PRIVATE_CANARY',payload+'\nPRIVATE_CANARY',payload.replace('payload-load','PRIVATE_CANARY'),payload.replace('outcome=denied','outcome=PRIVATE_CANARY'),payload.replace('lease_live=true','lease_live=false')])assert.equal(observation(input),null);
  const lease='connector lease observation stage=preparation-finish outcome=denied parent_live=true lease_live=false provider_bound=true provider_live=false';
  assert.deepEqual(observation(lease), {kind:'lease',value:{stage:'preparation-finish',outcome:'denied',parentLive:true,leaseLive:false,providerBound:true,providerLive:false}});
  for(const stage of ['preparation-finish','preparation-forward','captured-compensation','revocation-pending','revocation-applied','recovery-forward','unknown']) {
    for(const outcome of ['denied','unavailable','operation','other']) assert.equal(observation(lease.replace('preparation-finish',stage).replace('outcome=denied','outcome='+outcome)).value.outcome,outcome);
  }
  for(const input of [lease+' PRIVATE_CANARY',lease+'\nPRIVATE_CANARY',lease.replace('preparation-finish','PRIVATE_CANARY'),lease.replace('outcome=denied','outcome=PRIVATE_CANARY'),lease.replace('parent_live=true','parent_live=PRIVATE_CANARY'),lease.replace('provider_bound=true provider_live=false','provider_bound=false provider_live=true')]) assert.equal(observation(input),null);
  assert.deepEqual(observation('connector preparation stage=begin'), {kind:'preparation',stage:'begin'});
  assert.equal(observation('connector preparation stage=SECRET_PAYLOAD'), null);
  const value = observation('    connector_maintenance_catalog_diagnostic_test.go:12: connector catalog kind=function before=4 after=4 added=0 removed=0 changed=1\n');
  assert.deepEqual(value, {kind: 'catalog-object', value: {kind: 'function', before:4, after:4, added:0, removed:0, changed:1}});
  assert.deepEqual(observation('connector cutover prepare stage=model-read\n'), {kind:'cutover',stage:'model-read'});
  for(const stage of ['invalid','permit','deadline','old-credential','writer-absence','new-model','sql-begin','sql-role','sql-lock','sql-baseline','sql-activation','sql-result','sql-commit','unknown'])assert.deepEqual(observation('connector cutover activation stage='+stage+'\n'),{kind:'activation',stage});
  for(const input of ['connector cutover activation stage=PRIVATE_CANARY','connector cutover activation stage=sql-role PRIVATE_CANARY','connector cutover activation stage=sql-role\nPRIVATE_CANARY'])assert.equal(observation(input),null);
  assert.deepEqual(observation('connector catalog diagnostic=unavailable\n'), {kind:'catalog-summary',value:{observed:false}});
  const summary='connector catalog diagnostic=observed before_rows=20 after_rows=20 before_duplicates=0 after_duplicates=0 before_registered=true after_registered=false before_guc_equal=true after_guc_equal=false owner_guc_stable=true api_guc_stable=true';
  assert.equal(observation(summary).value.afterRegistered,false);
  for (const input of [summary+' PRIVATE_CANARY',summary+'\nPRIVATE_CANARY',summary.replace('20','4097'),'connector catalog kind=PRIVATE_CANARY before=1 after=1 added=0 removed=0 changed=0','connector cutover prepare stage=PRIVATE_CANARY','PRIVATE_CANARY'+summary,'x'.repeat(16385),null]) assert.equal(observation(input),null);
});
