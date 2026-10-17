import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import * as traceDiagnostics from './connector-acceptance-groups.mjs';
import { CONNECTOR_ACCEPTANCE_GROUPS as groups, selectConnectorAcceptanceGroup as select, validateConnectorAcceptanceTrace as validate, parseConnectorNativeObservation as observation, describeConnectorAcceptanceTraceFailure as describeTraceFailure } from './connector-acceptance-groups.mjs';
const pkg = 'github.com/zasp-ai/zasp-sec/services/platform/apiserver';
const trace = selected => [...selected.names.flatMap(Test => [{Package: pkg, Test, Action: 'run'}, {Package: pkg, Test, Action: 'pass'}]), {Package: pkg, Action: 'pass'}];
test('required application groups retain every flow and owned database', () => {
  assert.deepEqual(Object.keys(groups), ['approval-test74', 'approval-ordered-planning', 'approval-ordered-progress', 'approval-flow', 'approval', 'oauth', 'lifecycle', 'pkce', 'callback', 'approval-overflow', 'approval-future-test74', 'approval-future-progress', 'optional-egress-audit', 'retention-audit']);
  assert.deepEqual(Object.values(groups).map(g => [g.names.length, g.postgresJoins]), [[1, 2], [1, 2], [5, 2], [6, 2], [22, 1], [3, 1], [6, 2], [4, 2], [4, 2], [1, 2], [1, 2], [5, 2], [9, 1], [11, 1]]);
  const names = Object.values(groups).flatMap(g => g.names);
  assert.equal(names.length, 79); assert.equal(new Set(names).size, 79);
  assert.equal(Object.values(groups).reduce((n, g) => n + g.postgresJoins, 0), 24);
  for (const key of Object.keys(groups)) { assert.equal(select([key]), groups[key]); validate(trace(groups[key]), groups[key]); }
});
test('environment classification adds fixed normal Audit and catalog groups without changing original acceptance', () => {
  const added = traceDiagnostics.ENVIRONMENT_CLASS_ACCEPTANCE_GROUPS;
  assert.ok(added, 'fixed supplementary environment classification acceptance groups are missing');
  assert.deepEqual(Object.keys(added), ['environment-class', 'environment-class-audit', 'environment-class-catalog']);
  assert.deepEqual(Object.values(added).map(g => [g.names.length, g.postgresJoins]), [[9, 1], [9, 1], [19, 2]]);
  const names = Object.values(added).flatMap(g => g.names);
  assert.equal(names.length, 37); assert.equal(new Set(names).size, 37);
  assert.equal(Object.values(added).reduce((n, g) => n + g.postgresJoins, 0), 4);
  assert.ok(names.every(name => !Object.values(groups).some(g => g.names.includes(name))));
  for (const [key, selected] of Object.entries(added)) {
    assert.equal(select([key]), selected);
    validate(trace(selected), selected);
    for (const name of selected.names) {
      assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
      assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
      for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
    }
  }
});
test('maintenance operators add exact restricted owner acceptance without replacing prior groups', () => {
  const added = traceDiagnostics.MAINTENANCE_OPERATOR_ACCEPTANCE_GROUPS;
  assert.ok(added, 'fixed supplementary maintenance operator groups are missing');
  assert.deepEqual(Object.keys(added), ['maintenance-operator', 'maintenance-operator-audit']);
  assert.deepEqual(Object.values(added).map(g => [g.names.length, g.postgresJoins]), [[9, 1], [9, 1]]);
  const source = fs.readFileSync(new URL('../services/platform/apiserver/maintenance_operator_noinherit_postgres_test.go', import.meta.url), 'utf8');
  for (const [key, selected] of Object.entries(added)) {
    assert.equal(select([key]), selected); validate(trace(selected), selected);
    assert.ok(source.includes(`func ${selected.top}(t *testing.T)`));
    for (const name of selected.names.slice(1)) assert.ok(source.includes(`t.Run("${name.slice(selected.top.length + 1)}"`));
    for (const name of selected.names) {
      assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
      assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
      for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
    }
  }
  const previous = {...groups, ...traceDiagnostics.ENVIRONMENT_CLASS_ACCEPTANCE_GROUPS};
  assert.ok(Object.values(added).flatMap(g => g.names).every(name => !Object.values(previous).some(g => g.names.includes(name))));
  const workflow = fs.readFileSync(new URL('../.github/workflows/connector-connected-lifecycle.yml', import.meta.url), 'utf8');
  for (const key of Object.keys(added)) assert.ok(workflow.includes(key));
});
test('optional egress operators require both fixed restricted owner groups and all cases', () => {
  const added = traceDiagnostics.OPTIONAL_EGRESS_OPERATOR_ACCEPTANCE_GROUPS;
  assert.ok(added, 'fixed supplementary optional egress operator groups are missing');
  assert.deepEqual(Object.keys(added), ['optional-egress-operator', 'optional-egress-operator-audit']);
  assert.deepEqual(Object.values(added).map(g => [g.names.length, g.postgresJoins]), [[6, 1], [6, 1]]);
  const source = fs.readFileSync(new URL('../services/platform/apiserver/optional_egress_operator_noinherit_postgres_test.go', import.meta.url), 'utf8');
  for (const [key, selected] of Object.entries(added)) {
    assert.equal(select([key]), selected); validate(trace(selected), selected);
    assert.ok(source.includes(`func ${selected.top}(t *testing.T)`));
    for (const name of selected.names.slice(1)) assert.ok(source.includes(`t.Run("${name.slice(selected.top.length + 1)}"`));
    for (const name of selected.names) {
      assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
      assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
      for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
    }
  }
  const previous = {...groups, ...traceDiagnostics.ENVIRONMENT_CLASS_ACCEPTANCE_GROUPS, ...traceDiagnostics.MAINTENANCE_OPERATOR_ACCEPTANCE_GROUPS};
  assert.ok(Object.values(added).flatMap(g => g.names).every(name => !Object.values(previous).some(g => g.names.includes(name))));
  const workflow = fs.readFileSync(new URL('../.github/workflows/connector-connected-lifecycle.yml', import.meta.url), 'utf8');
  for (const key of Object.keys(added)) assert.ok(workflow.includes(key));
});
test('both ordered progress flows require every original provider evidence control', () => {
  const cases = ['provider-evidence-unchanged', 'provider-evidence-ordinary-field', 'provider-evidence-timestamp-instant', 'provider-canonical-row-leaf'];
  const helper = fs.readFileSync(new URL('../services/platform/apiserver/authorization_worker_ordered_provider_evidence_test.go', import.meta.url), 'utf8');
  assert.match(helper, /\[\]string\{"unchanged", "ordinary-field", "timestamp-instant"\}/);
  assert.match(helper, /t\.Run\("provider-evidence-"\+control/);
  assert.match(helper, /t\.Run\("provider-canonical-row-leaf"/);
  for (const key of ['approval-ordered-progress', 'approval-future-progress']) {
    const selected = groups[key];
    assert.deepEqual(selected.names, [selected.top, ...cases.map(name => `${selected.top}/${name}`)]);
    validate(trace(selected), selected);
    for (const name of selected.names.slice(1)) {
      assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
      assert.throws(() => validate(trace(selected).map(row => row.Test === name ? {...row, Test: `${name}-unknown`} : row), selected));
      assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
      assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: 'skip'} : row), selected));
    }
  }
});
test('approval requires all original native signed planning proof controls', () => {
  const selected = groups.approval;
  const helper = fs.readFileSync(new URL('../services/platform/apiserver/authorization_worker_planning_proof_postgres_test.go', import.meta.url), 'utf8');
  const origin = fs.readFileSync(new URL('../services/platform/apiserver/approval_maintenance_genuine_enqueue_postgres_test.go', import.meta.url), 'utf8');
  const parent = fs.readFileSync(new URL('../services/platform/apiserver/approval_activation_postgres_test.go', import.meta.url), 'utf8');
  assert.match(parent, /assertApprovalOriginFindingPlanning\(t, ctx, f, run, other, otherRef, complete, completeRef, false\)/);
  assert.match(origin, /if !cleanupOnly \{\s*assertWorkerPlanningProofBindings\(/);
  assert.match(helper, /t\.Run\("planning proof "\+test\.name/);
  const cases = ['wrong purpose', 'wrong phase', 'wrong principal', 'expired', 'non-null request', 'wrong canonical digest', 'wrong job digest', 'other task', 'changed target', 'changed revision', 'repeatable read', 'serializable', 'state repeatable read', 'recovery serializable', 'compensation forward call', 'canonical formatting'];
  const names = cases.map(name => `${selected.top}/planning_proof_${name.replaceAll(' ', '_')}`);
  assert.equal(selected.names.length, 22);
  assert.deepEqual(selected.names.filter(name => name.includes('/planning_proof_')), names);
  for (let i = 0; i < cases.length; i++) {
    assert.ok(helper.includes(`{"${cases[i]}",`), cases[i]);
    const name = names[i];
    assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
    assert.throws(() => validate(trace(selected).map(row => row.Test === name ? {...row, Test: `${name}-unknown`} : row), selected));
    assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
    for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
  }
});
test('optional egress audit requires every exact native permission and settlement case', () => {
  const selected = groups['optional-egress-audit'];
  const source = fs.readFileSync(new URL('../services/platform/apiserver/optional_egress_native_postgres_test.go', import.meta.url), 'utf8');
  assert.equal(selected.top, 'TestOptionalEgressCurrentAuditNativePostgres');
  assert.equal(selected.postgresJoins, 1);
  assert.equal(selected.names.length, 9);
  for (const name of selected.names.slice(1)) {
    const child = name.slice(selected.top.length + 1);
    assert.ok(source.includes(`t.Run("${child}"`), child);
    assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
    assert.throws(() => validate(trace(selected).map(row => row.Test === name ? {...row, Test: `${name}-unknown`} : row), selected));
    assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
    for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
  }
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
  // Execute the actual acceptance assertion function with a controlled issued
  // error. This verifies catch/observation never replaces that original object.
  const actual=new Function('assert','acceptanceGroups','applicationPackage','traceFailureStages','traceFailureEvents',`return (${validate.toString()});`)(guarded,Object.freeze({...groups,...traceDiagnostics.ENVIRONMENT_CLASS_ACCEPTANCE_GROUPS,...traceDiagnostics.MAINTENANCE_OPERATOR_ACCEPTANCE_GROUPS,...traceDiagnostics.OPTIONAL_EGRESS_OPERATOR_ACCEPTANCE_GROUPS,...traceDiagnostics.AGENT_CURRENT_READ_ACCEPTANCE_GROUPS}),pkg,stages,events);
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
  const budget = 'connector pkce budget initial_lease_ms=9000 initial_provider_ms=6900 lease_live=true provider_live=true';
  assert.deepEqual(observation(budget), {kind: 'pkce-budget', value: {initialLeaseMS: 9000, initialProviderMS: 6900, leaseLive: true, providerLive: true}});
  const phase = 'connector pkce phase=begin-attempt count=2 elapsed_ms=500 max_ms=400 failed=true context_done=true deadline=true canceled=false SQLSTATE=57014 capped=false';
  assert.deepEqual(observation(phase), {kind: 'pkce-phase', value: {phase: 'begin-attempt', count: 2, elapsedMS: 500, maxMS: 400, failed: true, contextDone: true, deadline: true, canceled: false, sqlState: '57014', capped: false}});
  assert.equal(observation(phase.replace('context_done=true', 'context_done=false')).value.deadline, true);
  assert.equal(observation(phase.replace('canceled=false', 'canceled=true')).value.canceled, true);
  for (const name of ['pool-acquire', 'tx-begin', 'set-role', 'source', 'revision', 'begin-attempt', 'commit', 'rollback']) assert.equal(observation(phase.replace('phase=begin-attempt', 'phase='+name)).value.phase, name);
  for (const input of [budget+' PRIVATE_CANARY', budget+'\nPRIVATE_CANARY', budget.replace('9000', '120001'), budget.replace('lease_live=true', 'lease_live=false'), phase+' PRIVATE_CANARY', phase+'\nPRIVATE_CANARY', phase.replace('begin-attempt', 'PRIVATE_CANARY'), phase.replace('count=2', 'count=0'), phase.replace('count=2', 'count=17'), phase.replace('500', '120001'), phase.replace('max_ms=400', 'max_ms=501'), phase.replace('57014', 'private_payload')]) assert.equal(observation(input), null);
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

test('optional egress hosted sources bind the complete connected application closure', () => {
  const root = new URL('../', import.meta.url);
  const relative = name => fs.readFileSync(new URL(name, root));
  const sha = bytes => createHash('sha256').update(bytes).digest('hex');
  const files = [
    ...['agentsec-api', 'agentsec-migrate', 'agentsec-worker', 'apiserver', 'authorization', 'migrations'].flatMap(directory =>
      fs.readdirSync(new URL(`services/platform/${directory}/`, root)).filter(name => name.includes('optional_egress') && name.endsWith('.go')).map(name => `services/platform/${directory}/${name}`)),
    ...fs.readdirSync(new URL('services/platform/optionalegress/', root)).filter(name => name.endsWith('.go')).map(name => `services/platform/optionalegress/${name}`),
    'services/platform/migrations/sql/optional_egress_profile.sql',
    'services/platform/authorization/worker.go',
    'services/platform/authorization/operations.json',
    'services/platform/agentsec-worker/authorization_worker_planning.go',
    'services/platform/agentsec-worker/authorization_worker_runtime.go',
    'services/platform/agentsec-worker/runtime_config.go',
    'services/platform/agentsec-worker/production_runtime.go',
    'services/platform/agentsec-worker/security_agent_planner.go',
    'services/platform/agentsec-worker/security_agent_multistep_planning.go',
    'services/platform/agentsec-worker/security_agent_temporal_planning.go',
    'services/platform/agentsec-worker/security_agent_temporal_product.go',
    'services/platform/agentsec-worker/security_agent_temporal_runtime.go',
    'services/platform/agentsec-api/runtime.go',
    'services/platform/agentsec-api/production_runtime.go',
    'services/platform/agentsec-api/runtime_dependency_diagnostic.go',
    'services/platform/apiserver/composition.go',
    'services/platform/apiserver/authorization_targets.go',
  ];
  const compiled = JSON.parse(relative('.github/connector-native-compile-source-pins.json'));
  const compilePins = new Map(compiled.sources.map(item => [item.path, item]));
  assert.equal(compilePins.size, compiled.sources.length);
  for (const runner of ['scripts/hosted-connected-connector-acceptance.mjs', 'scripts/hosted-connector-authenticated-enqueue.mjs']) {
    const source = relative(runner).toString('utf8');
    const pins = JSON.parse(/const pins = (\{.*?\n\});/s.exec(source)[1]);
    for (const file of files) {
      const bytes = relative(file), digest = sha(bytes), compiledPin = compilePins.get(file);
      assert.equal(pins[file], digest, `${runner}: ${file}`);
      assert.equal(compiledPin?.sha256, digest, `compile: ${file}`);
      assert.equal(compiledPin?.bytes, bytes.length, `compile bytes: ${file}`);
    }
  }
});

// Proposed supplement: original groups/cases are retained above. This guards
// actual application test events and source custody, not service internals.
test('retention audit requires every original native permission and expiry case', () => {
  const selected = groups['retention-audit'];
  const source = fs.readFileSync(new URL('../services/platform/apiserver/retention_native_postgres_test.go', import.meta.url), 'utf8');
  assert.equal(selected.top, 'TestRetentionAuditProfileNativePostgres');
  assert.equal(selected.postgresJoins, 1);
  assert.equal(selected.names.length, 11);
  assert.match(source, /func TestRetentionAuditProfileNativePostgres\(t \*testing\.T\)/);
  assert.match(source, /newAuthorizationProjectionFGA\(t\)/);
  assert.match(source, /startDisposablePostgresAs\(t, "zasp_test"\)/);
  for (const name of selected.names.slice(1)) {
    const child = name.slice(selected.top.length + 1);
    assert.ok(source.includes(`t.Run("${child}"`), child);
    assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
    assert.throws(() => validate(trace(selected).map(row => row.Test === name ? {...row, Test: `${name}-unknown`} : row), selected));
    assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
    for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
  }
});
test('retention connected sources retain the complete declared application closure', () => {
  const root = new URL('../', import.meta.url);
  const relative = name => fs.readFileSync(new URL(name, root));
  const sha = bytes => createHash('sha256').update(bytes).digest('hex');
  const required = [
  "deploy/production/authorization-temporal-resources.mjs",
  "deploy/production/release-contract.mjs",
  "deploy/production/release-contract.test.mjs",
  "deploy/production/session-search-rollout.mjs",
  "deploy/staging/main.tf",
  "deploy/staging/product/templates/runtime.yaml",
  "deploy/staging/product/templates/workloads.yaml",
  "deploy/staging/product/values.yaml",
  "services/platform/agentsec-api/policy_production.go",
  "services/platform/agentsec-api/production_runtime.go",
  "services/platform/agentsec-api/runtime.go",
  "services/platform/agentsec-migrate/main.go",
  "services/platform/agentsec-worker/production_runtime.go",
  "services/platform/agentsec-worker/runtime_archive_production.go",
  "services/platform/agentsec-worker/runtime_config.go",
  "services/platform/agentsec-worker/runtime_index.go",
  "services/platform/agentsec-worker/runtime_index_production.go",
  "services/platform/agentsec-worker/runtime_session_search_current.go",
  "services/platform/agentsec-worker/runtime_session_search_processor.go",
  "services/platform/apiserver/administration_repository.go",
  "services/platform/apiserver/authorization_statement.go",
  "services/platform/apiserver/repository.go",
  "services/platform/policy/opensearchhistory/driver.go",
  "services/platform/runtimeindex/opensearchdriver/session_index.go",
  "services/platform/runtimeindex/opensearchdriver/session_selection.go",
  "services/platform/runtimeindex/opensearchdriver/session_visibility.go",
  "services/platform/runtimeindex/opensearchdriver/session_write.go",
  "services/platform/runtimeindex/opensearchdriver/session_write_test.go",
  "services/platform/runtimeindex/store.go",
  "deploy/production/retention-profile.mjs",
  "deploy/production/retention-profile.test.mjs",
  "deploy/staging/product/templates/_retention.tpl",
  "deploy/staging/product/templates/retention.yaml",
  "services/platform/agentsec-migrate/retention_profile.go",
  "services/platform/agentsec-migrate/retention_profile_test.go",
  "services/platform/agentsec-worker/retention_cleanup.go",
  "services/platform/agentsec-worker/retention_cleanup_test.go",
  "services/platform/agentsec-worker/retention_runtime.go",
  "services/platform/agentsec-worker/retention_runtime_index.go",
  "services/platform/agentsec-worker/retention_runtime_index_test.go",
  "services/platform/agentsec-worker/retention_runtime_pipeline.go",
  "services/platform/agentsec-worker/retention_runtime_pipeline_test.go",
  "services/platform/agentsec-worker/retention_runtime_test.go",
  "services/platform/apiserver/retention_native_postgres_test.go",
  "services/platform/apiserver/retention_visibility_repository.go",
  "services/platform/apiserver/retention_visibility_repository_test.go",
  "services/platform/apiserver/runtime_session_retention_search.go",
  "services/platform/apiserver/runtime_session_retention_search_test.go",
  "services/platform/migrations/production_retention_profile.go",
  "services/platform/migrations/production_retention_profile_test.go",
  "services/platform/migrations/sql/retention_cleanup.sql",
  "services/platform/migrations/sql/retention_index.sql",
  "services/platform/migrations/sql/retention_partition.sql",
  "services/platform/migrations/sql/retention_profile.sql",
  "services/platform/migrations/sql/retention_successor.sql",
  "services/platform/orchestration/retention_activities.go",
  "services/platform/orchestration/retention_schedule.go",
  "services/platform/orchestration/retention_schedule_test.go",
  "services/platform/orchestration/retention_workflow.go",
  "services/platform/orchestration/retention_workflow_test.go",
  "services/platform/policy/opensearchhistory/retention.go",
  "services/platform/policy/opensearchhistory/retention_test.go",
  "services/platform/runtimeevent/production_retention_profile.go",
  "services/platform/runtimeevent/production_retention_profile_test.go",
  "services/platform/runtimeindex/opensearchdriver/retention_purge.go",
  "services/platform/runtimeindex/opensearchdriver/retention_purge_test.go",
  "services/platform/runtimeindex/opensearchdriver/session_retention_test.go",
  "services/platform/runtimeindex/retained_write.go",
  "services/platform/runtimeindex/retained_write_test.go",
  "services/platform/runtimeindex/retention_visibility.go",
  "services/platform/runtimeindex/retention_visibility_test.go",
  "services/platform/runtimeevent/production_pipeline_repository.go",
  "services/platform/runtimeevent/production_current_profile.go",
  "services/platform/runtimeevent/production_ingest.go",
  "services/platform/runtimeevent/production_session_routing.go",
  "services/platform/runtimeevent/production_precise_ingest_repository.go",
  "services/platform/runtimeevent/production_precise_completion.go",
  "services/platform/runtimeevent/stage_receipt.go",
  "services/platform/runtimeevent/runtimeevent.go",
  "services/platform/runtimeprojection/projector.go",
  "services/platform/runtimeprojection/receipt.go",
  "services/platform/runtimeprojection/precise.go",
  "services/platform/runtimeprojection/precise_receipt.go",
  "services/platform/runtimecorrelation/correlator.go",
  "services/platform/runtimecorrelation/frozen_correlator.go",
  "services/platform/runtimecorrelation/sandbox_correlator.go",
  "services/platform/runtimecorrelation/precise_correlator.go",
  "services/platform/runtimecorrelation/receipt.go",
  "services/platform/runtimecorrelation/precise_receipt.go",
  "services/platform/runtimeindex/precise.go",
  "services/platform/runtimeindex/opensearchdriver/driver.go",
  "services/platform/runtimeindex/opensearchdriver/schema.go",
  "services/platform/runtimeindex/opensearchdriver/session_precise.go",
  "services/platform/sessionsearch/query.go",
  "services/platform/sessionsearch/document.go",
  "services/platform/sessionsearch/precise.go",
  "services/platform/orchestration/schedules.go",
  "services/platform/orchestration/contracts.go",
  "services/platform/orchestration/temporal_client.go",
  "services/platform/runtimepostgres/config.go",
  "services/platform/runtimeservices/config.go",
  "services/platform/runtimeservices/clients.go",
  "services/platform/sensoradapter/adapter.go",
  "services/platform/sensoradapter/envelope.go",
  "services/platform/sensoradapter/precise_envelope.go",
  "services/platform/sensoradapter/precise_record.go",
  "services/platform/apiserver/postgres_integration_test.go",
  "services/platform/apiserver/authorization_projection_fga_test.go",
  "services/platform/migrations/production_authorization_worker_profile.go",
  "services/platform/migrations/production_authorization_worker_runtime.go",
  "services/platform/migrations/production_authorization_runtime_profile.go",
  "services/platform/apiserver/approval_maintenance_owned_fga_test.go",
  "services/platform/apiserver/audit_export_http_size_lifetime_test.go",
  "services/platform/apiserver/authorization_attestation_test.go",
  "services/platform/apiserver/authorization_enforcement_postgres_test.go",
  "services/platform/apiserver/authorization_integration_mutations_postgres_test.go",
  "services/platform/apiserver/connector_authorization_postgres_test.go",
  "services/platform/apiserver/discovery_execution_postgres_test.go",
  "services/platform/apiserver/discovery_postgres_test.go",
  "services/platform/apiserver/inventory_cutover_postgres_test.go",
  "services/platform/apiserver/middleware_test.go",
  "services/platform/apiserver/reference_authorization_postgres_test.go",
  "services/platform/apiserver/runtime_data_plane_postgres_test.go",
  "services/platform/apiserver/runtime_sandbox_candidate_postgres_test.go",
  "services/platform/apiserver/runtime_sessions_postgres_test.go",
  "services/platform/apiserver/security_agent_temporal_automatic_sources_postgres_test.go",
  "services/platform/apiserver/retention_index_native_acceptance_test.go",
  "services/platform/runtimeindex/opensearchdriver/retained_terminal_flow_test.go",
  "services/platform/apiserver/connector_maintenance_pkce_observation_test.go",
  "deploy/staging/iam-policy-union-v1.mjs",
  "deploy/staging/iam-policy-union-v1.test.mjs",
  "deploy/staging/tests/session_search_iam.tftest.hcl",
  ".github/workflows/retention-iam-acceptance.yml",
  "services/platform/migrations/production_retention_ddl.go",
  "services/platform/migrations/production_retention_ddl_test.go",
  "services/platform/agentsec-migrate/retention_ddl_test.go",
  "services/platform/connectormaintenance/atomic_observation_test.go",
  "services/platform/migrations/sql/retention_journal.sql",
  "services/platform/migrations/production_retention_journal.go",
  "services/platform/migrations/production_retention_journal_test.go",
  "services/platform/agentsec-migrate/retention_journal.go",
  "services/platform/agentsec-migrate/retention_journal_test.go",
  "services/platform/apiserver/retention_journal_native_acceptance_test.go",
  "services/platform/runtimeindex/retained_journal.go",
  "services/platform/runtimeindex/retained_journal_test.go",
  "services/platform/runtimeindex/opensearchdriver/retained_journal_flow_test.go",
  "services/platform/agentsec-worker/retention_writer_journal.go",
  "services/platform/agentsec-worker/retention_writer_journal_test.go",
  "services/platform/agentsec-worker/retention_writer_journal_recovery.go",
  "services/platform/agentsec-worker/retention_writer_journal_recovery_test.go",
  "cmd/agentsecctl/go.mod",
  "cmd/agentsecctl/go.sum",
  "cmd/agentsecctl/preflight_live.go",
  "cmd/agentsecctl/preflight_live_contract_test.go",
  "cmd/agentsecctl/release.go",
  "services/platform/agentsec-worker/discovery_dependencies.go",
  "services/platform/cloudreadiness/aws.go",
  "services/platform/preflight/aws_contract_test.go",
  "services/platform/preflight/config.go",
  "services/platform/preflight/config_contract_test.go",
  "services/platform/preflight/contract.go",
  "services/platform/preflight/credentials.go",
  "services/platform/preflight/failures.go",
  "services/platform/preflight/report.go",
  "services/platform/preflight/runner.go",
  "services/platform/preflight/transport.go",
  "services/platform/preflight/dependency_config.go",
  "services/platform/preflight/dependency_runner.go",
  "services/platform/preflight/stytch.go",
  "services/platform/preflight/stytch_test.go",
  "services/platform/preflight/postgres.go",
  "services/platform/preflight/postgres_test.go",
  "services/platform/preflight/postgres_flow_test.go",
  "services/platform/migrations/preflight_observation.go",
  "services/platform/migrations/preflight_observation_test.go",
  "services/platform/preflight/connected_core_test.go",
  "services/platform/sensoradapter/node_coverage.go",
  "services/platform/sensoradapter/node_coverage_client.go",
  "services/platform/sensoradapter/node_coverage_test.go",
  "services/platform/preflight/sensor.go",
  "services/platform/preflight/sensor_test.go",
  "services/sensor-agent/node_coverage_identity.go",
  "services/sensor-agent/node_coverage_runtime.go",
  "services/sensor-agent/node_coverage_contract_test.go",
  "services/sensor-agent/cluster.go",
  "services/sensor-agent/runtime_config.go",
  "services/sensor-agent/production.go",
  "services/sensor-agent/lineage_generation.go",
  "services/sensor-agent/lineage_pump.go",
  "services/sensor-agent/lineage_daemon.go",
  "services/sensor-agent/lineage_layout.go",
  "services/sensor-agent/lineage_layout_test.go",
  "deploy/staging/product/templates/edge.yaml",
  "deploy/staging/product/values-customer-edge.yaml",
  "deploy/staging/tetragon/values.yaml",
  "deploy/staging/tetragon/templates/sensor-coverage-reader.yaml",
  "deploy/production/release-fixture.mjs",
  "services/sensor-agent/node_coverage_flow_test.go",
  "services/sensor-agent/lineage_consumer_daemon.go",
  "services/platform/preflight/aws_authority.go",
  "services/platform/preflight/aws_authority_catalog.go",
  "services/platform/preflight/aws_authority_config.go",
  "services/platform/preflight/aws_authority_policy.go",
  "services/platform/preflight/aws_authority_test.go",
  "services/platform/preflight/aws_webidentity.go",
  "services/platform/preflight/aws_webidentity_test.go",
  "services/platform/preflight/aws_kubernetes.go",
  "services/platform/preflight/aws_kubernetes_test.go",
  "services/platform/preflight/aws_integration.go",
  "services/platform/preflight/aws_integration_test.go",
  "services/platform/go.mod",
  "services/platform/go.sum",
  "services/platform/runtimeindex/opensearchdriver/schema_observer.go",
  "services/platform/runtimeindex/opensearchdriver/schema_observer_test.go",
  "services/platform/inventorysearch/opensearchdriver/schema_observer.go",
  "services/platform/inventorysearch/opensearchdriver/schema_observer_test.go",
  "services/platform/preflight/opensearch_config.go",
  "services/platform/preflight/opensearch_test.go",
  "services/platform/preflight/opensearch.go",
  "services/platform/preflight/opensearch_flow_test.go",
  "services/platform/preflight/opensearch_kubernetes.go",
  "services/platform/preflight/opensearch_kubernetes_test.go",
  "services/platform/preflight/opensearch_data_flow_test.go",
  "services/platform/inventorysearch/opensearchdriver/driver.go",
  "services/platform/inventorysearch/opensearchdriver/schema.go",
  "services/platform/preflight/attack_lab.go",
  "services/platform/preflight/attack_lab_config.go",
  "services/platform/preflight/attack_lab_identity.go",
  "services/platform/preflight/attack_lab_identity_test.go",
  "services/platform/preflight/attack_lab_integration.go",
  "services/platform/preflight/attack_lab_integration_test.go",
  "services/platform/preflight/attack_lab_kubernetes.go",
  "services/platform/preflight/attack_lab_kubernetes_test.go",
  "services/platform/preflight/attack_lab_network.go",
  "services/platform/preflight/attack_lab_network_test.go",
  "services/platform/preflight/attack_lab_test.go",
  "services/platform/preflight/attack_lab_topology.go",
  "services/platform/preflight/attack_lab_topology_predicates.go",
  "services/platform/preflight/attack_lab_topology_test.go",
  "services/platform/preflight/attack_lab_validation.go",
  "services/platform/preflight/aws_inspection_capture.go",
  "services/platform/cloudreadiness/attack_lab.go",
  "services/platform/cloudreadiness/attack_lab_test.go",
  "services/platform/agentsec-worker/attack_lab_kubernetes_api.go",
  "services/platform/preflight/attack_lab_failures.go",
  "services/platform/preflight/attack_lab_mounted_recipe_test.go",
  "services/platform/preflight/sqs_permissions.go",
  "services/platform/preflight/sqs_permissions_flow_test.go",
  "services/platform/preflight/sqs_permissions_kubernetes.go",
  "services/platform/preflight/sqs_permissions_kubernetes_test.go",
  "services/platform/preflight/sqs_permissions_mounted_test.go",
  "services/platform/preflight/sqs_permissions_integration.go",
  "services/platform/apiserver/authorization_post_login_resolver.go",
  "services/platform/apiserver/authorization_post_login_callback_resolver_test.go",
  "services/platform/apiserver/environment_class.go",
  "services/platform/apiserver/environment_class_statement.go",
  "services/platform/apiserver/authorization_openfga.go",
  "services/platform/apiserver/authorization_post_login.go",
  "services/platform/apiserver/environment_class_http_test.go",
  "services/platform/apiserver/environment_class_statement_test.go",
  "services/platform/apiserver/environment_class_postgres_test.go",
  "services/platform/agentsec-api/environment_class_runtime.go",
  "services/platform/agentsec-api/environment_class_runtime_test.go",
  "deploy/production/environment-class-profile.mjs",
  "deploy/production/environment-class-profile.test.mjs",
  "deploy/staging/product/templates/_environment-class.tpl",
  "services/platform/apiserver/environment_class_attack_lab_postgres_test.go",
  "services/platform/apiserver/environment_class_repository_test.go",
  "services/platform/migrations/sql/environment_class_profile.sql",
  "services/platform/migrations/production_environment_class_profile.go",
  "services/platform/migrations/production_environment_class_profile_test.go",
  "services/platform/agentsec-migrate/environment_class_profile.go",
  "services/platform/agentsec-migrate/environment_class_profile_test.go",
  "services/platform/apiserver/environment_class_profile_catalog_postgres_test.go",
  ".github/workflows/connector-connected-lifecycle.yml",
  "services/platform/migrations/maintenance_operator_role.go",
  "services/platform/migrations/maintenance_operator_role_test.go",
  "services/platform/agentsec-migrate/forward_release_confirmation.go",
  "services/platform/agentsec-migrate/maintenance_confirmation_role_test.go",
  "services/platform/apiserver/maintenance_operator_noinherit_postgres_test.go",
  "services/platform/migrations/optional_egress_operator_role_test.go",
  "services/platform/agentsec-migrate/optional_egress_confirmation_role_test.go",
  "services/platform/apiserver/optional_egress_operator_noinherit_postgres_test.go",
  "services/platform/migrations/installer_binding_authority_test.go",
  "services/platform/agentsec-migrate/principal_authority_transaction.go",
  "services/platform/agentsec-migrate/authorization_audit_profile.go",
  "services/platform/agentsec-migrate/principal_preflight_authority_test.go",
  "services/platform/agentsec-migrate/principal_preflight_recorders_test.go",
  "services/platform/agentsec-migrate/authorization_audit_profile_test.go",
  "services/platform/agentsec-migrate/authorization_runtime_profile_inner_diagnostic_test.go",
  "services/platform/agentsec-migrate/authorization_runtime_worker_profile_test.go",
  "services/platform/agentsec-migrate/authorization_temporal_profile_test.go",
  "services/platform/agentsec-migrate/authorization_worker_profile_test.go",
  "services/platform/agentsec-migrate/identity_profile_test.go",
  "services/platform/agentsec-migrate/authorization_runtime_profile.go",
  "services/platform/agentsec-migrate/authorization_confirmation_role_test.go",
  "services/platform/agentsec-migrate/authorization_confirmation_inner_loop_test.go",
  "services/platform/agentsec-migrate/authorization_runtime_worker_profile.go",
  "services/platform/agentsec-migrate/temporal_confirmation_role_test.go",
  "services/platform/agentsec-migrate/temporal_forward_readiness_cost_test.go",
  "services/platform/migrations/temporal_source_checksums.go",
  "services/platform/featureflags/featureflags.go",
  "services/platform/featureflags/server_cache_test.go",
  "services/platform/featureflags/server_cache_clock_test.go",
  "services/platform/featureflags/featureflags_test.go",
  "services/platform/migrations/production_agent_owner_filter_profile.go",
  "services/platform/migrations/sql/agent_owner_filter_profile.sql",
  "services/platform/migrations/production_agent_owner_filter_profile_test.go",
  "services/platform/apiserver/agent_owner_filter.go",
  "services/platform/apiserver/agent_owner_filter_test.go",
  "services/platform/apiserver/agent_owner_filter_authorization_test.go",
  "services/platform/apiserver/agent_owner_filter_repository_test.go",
  "services/platform/apiserver/inventory_handler.go",
  "services/platform/apiserver/inventory_repository.go",
  "services/platform/agentsec-api/agent_owner_filter_runtime.go",
  "services/platform/agentsec-api/agent_owner_filter_runtime_test.go",
  "services/platform/agentsec-migrate/agent_owner_filter_profile.go",
  "services/platform/apiserver/inventory_handler_test.go",
  "services/platform/apiserver/inventory_repository_test.go",
  "services/platform/apiserver/authorization_transaction_test.go",
  "services/platform/migrations/migrations_test.go",
  "services/platform/apiserver/authorization_statement_test.go",
  "services/platform/apiserver/authorization_openfga_test.go",
  "openapi/agents-owner-filter.test.mjs",
  "openapi/openapi.yaml",
  "deploy/production/agent-owner-filter-profile.test.mjs",
  "deploy/production/agent-owner-filter-profile.mjs",
  "deploy/staging/product/templates/_agent-owner-filter.tpl",
  "cmd/agentsecctl/api_load.go",
  "cmd/agentsecctl/api_load_runner.go",
  "cmd/agentsecctl/api_load_test.go",
  "cmd/agentsecctl/diagnostics_sensitive_keys_test.go",
  "cmd/agentsecctl/main.go",
  "cmd/agentsecctl/main_test.go",
  "cmd/agentsecctl/preflight_report_test.go",
  "cmd/agentsecctl/profiles.go",
  "cmd/agentsecctl/profiles_test.go",
  "cmd/agentsecctl/recovery_client.go",
  "cmd/agentsecctl/recovery_client_test.go",
  "cmd/agentsecctl/release_test.go",
  "cmd/agentsecctl/resilience.go",
  "cmd/agentsecctl/resilience_test.go",
  "cmd/agentsecctl/security_release.go",
  "cmd/agentsecctl/security_release_test.go",
  "cmd/agentsecctl/vulnerability_exception_test.go",
  "services/platform/apiserver/system_health_probe_integration_test.go",
  "services/platform/apiserver/administration_fix_round1_test.go",
  "services/platform/apiserver/middleware.go",
  "services/platform/admincontrol/admincontrol.go",
  "services/platform/admincontrol/http.go",
  "services/platform/admincontrol/admincontrol_test.go",
  "services/platform/domain/ids.go",
  "services/platform/domain/scope.go",
  ".github/workflows/agents-current-read-components.yml",
  "deploy/production/agent-read-profile.mjs",
  "deploy/production/agent-read-profile.test.mjs",
  "deploy/staging/product/templates/_agent-read.tpl",
  "scripts/implementation-status-check.mjs",
  "scripts/implementation-status-check.test.mjs",
  "scripts/validate_agent_read_components.py",
  "scripts/validate_agent_read_components_test.py",
  "services/platform/agentsec-api/agent_read_runtime.go",
  "services/platform/agentsec-api/agent_read_runtime_test.go",
  "services/platform/agentsec-api/runtime_test.go",
  "services/platform/agentsec-migrate/AGENT_READ.md",
  "services/platform/agentsec-migrate/agent_read_profile.go",
  "services/platform/agentsec-migrate/agent_read_profile_test.go",
  "services/platform/agentsec-migrate/main_test.go",
  "services/platform/agentsec-migrate/release_readiness_test.go",
  "services/platform/apiserver/agent_current_read.go",
  "services/platform/apiserver/agent_current_read_handler_test.go",
  "services/platform/apiserver/agent_current_read_postgres_test.go",
  "services/platform/apiserver/agent_current_read_test.go",
  "services/platform/apiserver/authorization_projection_postgres_test.go",
  "services/platform/apiserver/authorization_transaction.go",
  "services/platform/apiserver/authorization_worker_runtime_postgres_test.go",
  "services/platform/apiserver/discovery_fix_round1_postgres_test.go",
  "services/platform/apiserver/postgres_database.go",
  "services/platform/apiserver/security_agent_multistep_admission_repository_postgres_test.go",
  "services/platform/migrations/production_agent_read_compiler_test.go",
  "services/platform/migrations/production_agent_read_profile.go",
  "services/platform/migrations/production_agent_read_profile_test.go",
  "services/platform/migrations/sql/0041_production_runtime_session_reads.up.sql",
  "services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql",
  "services/platform/migrations/sql/0067_production_temporal_domain.base.sql",
  "services/platform/migrations/sql/0067_production_temporal_domain.up.sql",
  "services/platform/migrations/sql/0068_production_temporal_executor.up.sql",
  "services/platform/migrations/sql/0080_authorization_temporal_profile.sql",
  "services/platform/migrations/sql/0080_production_authorization_enforcement.up.sql",
  "services/platform/migrations/sql/agent_read_profile.sql",
  ".github/agent-exposure-component-roster.json",
  ".github/workflows/agents-exposure-filter-components.yml",
  "deploy/production/agent-exposure-filter-profile.mjs",
  "deploy/production/agent-exposure-filter-profile.test.mjs",
  "deploy/staging/product/templates/_agent-exposure-filter.tpl",
  "scripts/validate_agent_exposure_components.py",
  "scripts/validate_agent_exposure_components_test.py",
  "services/platform/agentsec-api/agent_exposure_filter_runtime.go",
  "services/platform/agentsec-api/agent_exposure_filter_runtime_test.go",
  "services/platform/agentsec-migrate/agent_exposure_filter_profile.go",
  "services/platform/agentsec-migrate/agent_exposure_filter_profile_test.go",
  "services/platform/apiserver/agent_exposure_filter.go",
  "services/platform/apiserver/agent_exposure_filter_authorization_test.go",
  "services/platform/apiserver/agent_exposure_filter_bootstrap_test.go",
  "services/platform/apiserver/agent_exposure_filter_postgres_test.go",
  "services/platform/apiserver/agent_exposure_filter_resolver.go",
  "services/platform/apiserver/agent_exposure_filter_resolver_test.go",
  "services/platform/apiserver/agent_exposure_filter_test.go",
  "services/platform/apiserver/authorization_targets_postgres.go",
  "services/platform/apiserver/authorization_targets_routing_test.go",
  "services/platform/apiserver/identity_post_login_test.go",
  "services/platform/apiserver/workflow_handler.go",
  "services/platform/migrations/production_agent_exposure_filter_compiler_test.go",
  "services/platform/migrations/production_agent_exposure_filter_profile.go",
  "services/platform/migrations/production_agent_exposure_filter_profile_test.go",
  "services/platform/migrations/production_authorization_enforcement.go",
  "services/platform/migrations/production_authorization_temporal_profile.go",
  "services/platform/migrations/sql/0014_typed_inventory_cutover.up.sql",
  "services/platform/migrations/sql/agent_exposure_filter_profile.sql",
  ".github/agent-ownership-write-component-roster.json",
  ".github/workflows/agents-ownership-write-components.yml",
  "deploy/production/agent-ownership-write-profile.mjs",
  "deploy/production/agent-ownership-write-profile.test.mjs",
  "deploy/staging/product/templates/_agent-ownership-write.tpl",
  "scripts/validate_agent_ownership_write_components.py",
  "scripts/validate_agent_ownership_write_components_test.py",
  "services/platform/agentsec-api/agent_ownership_write_runtime.go",
  "services/platform/agentsec-api/agent_ownership_write_runtime_test.go",
  "services/platform/agentsec-migrate/agent_ownership_write_profile.go",
  "services/platform/agentsec-migrate/agent_ownership_write_profile_test.go",
  "services/platform/apiserver/agent_current_ownership_write.go",
  "services/platform/apiserver/agent_current_ownership_write_postgres_test.go",
  "services/platform/apiserver/agent_current_ownership_write_test.go",
  "services/platform/migrations/migrations.go",
  "services/platform/migrations/production_agent_ownership_write_compiler_test.go",
  "services/platform/migrations/production_agent_ownership_write_profile.go",
  "services/platform/migrations/production_agent_ownership_write_profile_test.go",
  "services/platform/migrations/production_temporal_domain.go",
  "services/platform/migrations/sql/0010_production_discovery.up.sql",
  "services/platform/migrations/sql/0079_production_authorization_projection.up.sql",
  "services/platform/migrations/sql/agent_ownership_write_profile.sql",
  "cmd/agentsecctl/upgrade_preflight.go",
  "cmd/agentsecctl/upgrade_preflight_test.go",
  ".github/sensor-node-coverage-component-roster.json",
  ".github/workflows/sensor-node-coverage-components.yml",
  "app/features/sensors/ProductionSensorView.test.tsx",
  "app/features/sensors/ProductionSensorView.tsx",
  "app/features/sensors/api.test.ts",
  "app/features/sensors/api.ts",
  "apps/web/api/client.ts",
  "apps/web/api/decoders.ts",
  "apps/web/api/generated.ts",
  "apps/web/api/sensor-node-coverage.test.ts",
  "apps/web/api/sensor-node-coverage.ts",
  "deploy/production/sensor-node-coverage-profile.mjs",
  "deploy/production/sensor-node-coverage-profile.test.mjs",
  "deploy/staging/product/templates/_sensor-node-coverage.tpl",
  "openapi/generated-client.test.mjs",
  "openapi/openapi.test.mjs",
  "scripts/validate_sensor_node_coverage_components.py",
  "scripts/validate_sensor_node_coverage_components_test.py",
  "services/event-ingest/go.mod",
  "services/event-ingest/go.sum",
  "services/event-ingest/production.go",
  "services/event-ingest/production_composition.go",
  "services/event-ingest/production_composition_test.go",
  "services/event-ingest/production_node_coverage.go",
  "services/event-ingest/production_node_coverage_config_test.go",
  "services/event-ingest/production_node_coverage_test.go",
  "services/event-ingest/production_node_coverage_transaction_test.go",
  "services/event-ingest/production_precision.go",
  "services/event-ingest/production_runtime.go",
  "services/event-ingest/production_runtime_test.go",
  "services/event-ingest/production_test.go",
  "services/health/go.mod",
  "services/platform/agentsec-api/sensor_node_coverage_runtime.go",
  "services/platform/agentsec-api/sensor_node_coverage_runtime_test.go",
  "services/platform/agentsec-migrate/sensor_node_coverage_profile.go",
  "services/platform/agentsec-migrate/sensor_node_coverage_profile_test.go",
  "services/platform/apiserver/discovery_repository_test.go",
  "services/platform/apiserver/sensor_node_coverage.go",
  "services/platform/apiserver/sensor_node_coverage_postgres_test.go",
  "services/platform/apiserver/sensor_node_coverage_test.go",
  "services/platform/apiserver/sensor_public_handler.go",
  "services/platform/apiserver/sensor_public_handler_test.go",
  "services/platform/apiserver/sensor_public_repository.go",
  "services/platform/migrations/production_authorization_audit_profile.go",
  "services/platform/migrations/production_authorization_identity_profile.go",
  "services/platform/migrations/production_authorization_projection.go",
  "services/platform/migrations/production_sensor_node_coverage_compiler_test.go",
  "services/platform/migrations/production_sensor_node_coverage_profile.go",
  "services/platform/migrations/production_sensor_node_coverage_profile_test.go",
  "services/platform/migrations/sql/sensor_node_coverage_profile.sql",
  "services/platform/nodecoveragewire/envelope.go",
  "services/platform/nodecoveragewire/receipt.go",
  "services/platform/nodecoveragewire/report.go",
  "services/platform/nodecoveragewire/strict.go",
  "services/platform/nodecoveragewire/wire.go",
  "services/platform/nodecoveragewire/wire_test.go",
  "services/platform/runtimeevent/production_acceptance_test.go",
  "services/platform/runtimeevent/production_current_profile_test.go",
  "services/platform/runtimeevent/production_ingest_test.go",
  "services/platform/runtimeevent/production_node_coverage.go",
  "services/platform/runtimeevent/production_node_coverage_transaction.go",
  "services/platform/runtimeevent/production_repository.go",
  "services/platform/runtimeevent/production_repository_test.go",
  "services/platform/sensor/enrollment_binding.go",
  "services/platform/sensor/private_heartbeat.go",
  "services/platform/sensor/private_node_coverage_heartbeat.go",
  "services/platform/sensor/private_node_coverage_heartbeat_test.go",
  "services/platform/sensor/token.go",
  "services/platform/sensoradapter/retained_heartbeat_client.go",
  "services/platform/sensoradapter/retained_heartbeat_client_test.go",
  "services/sensor-agent/cluster_test.go",
  "services/sensor-agent/go.mod",
  "services/sensor-agent/go.sum",
  "services/sensor-agent/main.go",
  "services/sensor-agent/node_coverage_retention_coordinator.go",
  "services/sensor-agent/node_coverage_retention_coordinator_test.go",
  "services/sensor-agent/node_coverage_retention_state.go",
  "services/sensor-agent/node_coverage_retention_storage_test.go",
  "services/sensor-agent/production_test.go",
  "services/sensor-agent/runtime_config_test.go",
  "services/platform/connectors/kubernetesdiscovery/collection_api.go",
  "services/platform/connectors/kubernetesdiscovery/pinned_collection_api.go",
  "services/platform/connectors/kubernetesdiscovery/collection.go",
  "services/platform/connectors/kubernetesdiscovery/node_placement.go",
  "services/platform/connectors/kubernetesdiscovery/node_placement_test.go",
  "services/platform/connectors/internal/providercollection/client.go",
  "services/platform/connectors/internal/providercollection/node_placement.go",
  "services/platform/connectors/internal/providercollection/node_placement_schema_test.go",
  "services/platform/agentsec-worker/discovery_clients.go",
  "services/platform/agentsec-worker/discovery_composition.go",
  "services/platform/agentsec-worker/discovery_node_placement_test.go",
  ".github/workflows/connector-native-draft-compile.yml",
  "deploy/production/gateway-installation-profile.mjs",
  "deploy/production/gateway-installation-profile.test.mjs",
  "deploy/staging/product/templates/_gateway-installation.tpl",
  "services/gateway-control/go.mod",
  "services/gateway-control/go.sum",
  "services/gateway-control/installation_test.go",
  "services/gateway-control/main.go",
  "services/gateway-control/production.go",
  "services/gateway-control/production_runtime.go",
  "services/gateway-control/production_server.go",
  "services/gateway-control/production_server_test.go",
  "services/gateway-control/production_test.go",
  "services/platform/agentsec-migrate/gateway_installation_profile.go",
  "services/platform/agentsec-migrate/gateway_installation_profile_test.go",
  "services/platform/gatewaycontrol/automatic_readiness_test.go",
  "services/platform/gatewaycontrol/client.go",
  "services/platform/gatewaycontrol/contract.go",
  "services/platform/gatewaycontrol/evaluation.go",
  "services/platform/gatewaycontrol/evaluation_http_test.go",
  "services/platform/gatewaycontrol/evaluation_risk_test.go",
  "services/platform/gatewaycontrol/http.go",
  "services/platform/gatewaycontrol/http_test.go",
  "services/platform/gatewaycontrol/installation.go",
  "services/platform/gatewaycontrol/installation_test.go",
  "services/platform/gatewaycontrol/postgres.go",
  "services/platform/gatewaycontrol/postgres_test.go",
  "services/platform/gatewayinstallationwire/wire.go",
  "services/platform/gatewayinstallationwire/wire_test.go",
  "services/platform/internal/cacheownership/ownership.go",
  "services/platform/internal/cacheownership/ownership_linux.go",
  "services/platform/internal/cacheownership/ownership_other.go",
  "services/platform/internal/cacheownership/ownership_test.go",
  "services/platform/migrations/production_gateway_installation_compiler_test.go",
  "services/platform/migrations/production_gateway_installation_profile.go",
  "services/platform/migrations/production_gateway_installation_profile_test.go",
  "services/platform/migrations/sql/gateway_installation_profile.sql",
  "services/platform/policy/gateway_cache.go",
  "services/platform/policy/gateway_cache_test.go",
  "services/platform/policy/gateway_installation.go",
  "services/platform/policy/gateway_installation_test.go",
  "services/runtime-gateway/evaluation_risk.go",
  "services/runtime-gateway/evaluation_risk_test.go",
  "services/runtime-gateway/evidence_codec.go",
  "services/runtime-gateway/evidence_directory.go",
  "services/runtime-gateway/evidence_store.go",
  "services/runtime-gateway/evidence_store_test.go",
  "services/runtime-gateway/go.mod",
  "services/runtime-gateway/go.sum",
  "services/runtime-gateway/handler.go",
  "services/runtime-gateway/handler_test.go",
  "services/runtime-gateway/healthserver.go",
  "services/runtime-gateway/healthserver_test.go",
  "services/runtime-gateway/installation_ack.go",
  "services/runtime-gateway/installation_ack_test.go",
  "services/runtime-gateway/main.go",
  "services/runtime-gateway/main_test.go",
  "services/runtime-gateway/production.go",
  "services/runtime-gateway/production_combined_e2e_test.go",
  "services/runtime-gateway/production_proxy.go",
  "services/runtime-gateway/production_runtime.go",
  "services/runtime-gateway/production_runtime_test.go",
  "services/runtime-gateway/production_server.go",
  "services/runtime-gateway/production_server_test.go",
  "services/runtime-gateway/production_test.go",
  "services/runtime-gateway/proxy.go",
  "services/runtime-gateway/proxy_test.go",
  "services/runtime-gateway/runtime.go",
  "services/runtime-gateway/runtime_test.go",
  "services/platform/policy/policy.go"
];
  const compiled = JSON.parse(relative('.github/connector-native-compile-source-pins.json'));
  const compilePins = new Map(compiled.sources.map(item => [item.path, item]));
  assert.equal(compilePins.size, compiled.sources.length);
  for (const runner of ['scripts/hosted-connected-connector-acceptance.mjs', 'scripts/hosted-connector-authenticated-enqueue.mjs']) {
    const source = relative(runner).toString('utf8');
    const pins = JSON.parse(/const pins = (\{.*?\n\});/s.exec(source)[1]);
    for (const file of required) {
      const bytes = relative(file), digest = sha(bytes), compiledPin = compilePins.get(file);
      const helperPins = JSON.parse(/const helperPins\s*=\s*(\{.*?\n\});/s.exec(source)[1]);
      assert.equal(pins[file] ?? helperPins[file], digest, `${runner}: ${file}`);
      if (file in helperPins) assert.equal(helperPins[file], digest, `helper custody: ${file}`);
      assert.equal(compiledPin?.sha256, digest, `compile: ${file}`);
      assert.equal(compiledPin?.bytes, bytes.length, `compile bytes: ${file}`);
    }
  }
});

test('native retention installer diagnostics retain only bounded declared stages', () => {
  const expected = ["retention-lock", "retention-role", "retention-parent", "retention-namespace", "retention-bridges", "retention-definitions", "retention-registration", "retention-ready", "retention-commit", "retention-parent-binding", "retention-parent-membership", "retention-parent-canonical", "retention-parent-source-owners", "retention-parent-worker-catalog", "retention-parent-worker-pin", "retention-parent-runtime-catalog", "retention-parent-runtime-pin", "retention-parent-authorization", "retention-refusal-source-anchor", "retention-refusal-preimage-closure", "retention-refusal-constraint-family", "retention-refusal-original-source-owner", "retention-refusal-activation-rejected", "retention-refusal-activation-cutover", "retention-refusal-activation-source-owner", "retention-refusal-other", "retention-ddl-public-create-granted", "retention-ddl-public-create-refused", "retention-ddl-runtime-trigger-granted", "retention-ddl-runtime-trigger-refused", "retention-ddl-inventory-trigger-granted", "retention-ddl-inventory-trigger-refused"];
  for (const name of ['hosted-connected-connector-acceptance.mjs', 'hosted-connector-authenticated-enqueue.mjs']) {
    const source = fs.readFileSync(new URL(name, import.meta.url), 'utf8');
    const stages = JSON.parse(source.match(/const fixedStages=(\[[^\n]*?\]);const locations/)[1]);
    assert.equal(new Set(stages).size, stages.length);
    for (const label of expected) assert.ok(stages.includes(label), label);
    assert.ok(!stages.includes('retention-PRIVATE_CANARY'));
    assert.ok(source.includes('fixedStages.includes(match[1])&&diagnostic.fixtureStages.length<32'));
    assert.ok(source.includes("observed?.kind==='pkce-budget'&&diagnostic.pkceBudget===null"));
    assert.ok(source.includes("observed?.kind==='pkce-phase'&&diagnostic.pkcePhases.length<8"));
    assert.ok(source.includes('!diagnostic.pkcePhases.some(value=>value.phase===observed.value.phase)'));
    assert.ok(source.includes("'; pkceBudget='+JSON.stringify(diagnostic.pkceBudget)+'; pkcePhases='+JSON.stringify(diagnostic.pkcePhases)"));
  }
});


test('current Agent reads require both exact native profiles and every refusal case', () => {
  const added = traceDiagnostics.AGENT_CURRENT_READ_ACCEPTANCE_GROUPS;
  assert.deepEqual(Object.keys(added), ['agent-current-read', 'agent-current-read-audit']);
  const previous = {...groups, ...traceDiagnostics.ENVIRONMENT_CLASS_ACCEPTANCE_GROUPS,
    ...traceDiagnostics.MAINTENANCE_OPERATOR_ACCEPTANCE_GROUPS, ...traceDiagnostics.OPTIONAL_EGRESS_OPERATOR_ACCEPTANCE_GROUPS};
  const all = {...previous, ...added};
  assert.equal(Object.keys(previous).length, 21);
  assert.equal(Object.values(previous).flatMap(g => g.names).length, 146);
  assert.equal(Object.keys(all).length, 23);
  assert.equal(Object.values(all).flatMap(g => g.names).length, 162);
  assert.equal(Object.values(all).reduce((n,g) => n + g.postgresJoins, 0), 34);
  const source = fs.readFileSync(new URL('../services/platform/apiserver/agent_current_read_postgres_test.go', import.meta.url), 'utf8');
  const workflow = fs.readFileSync(new URL('../.github/workflows/connector-connected-lifecycle.yml', import.meta.url), 'utf8');
  for (const [key, selected] of Object.entries(added)) {
    assert.equal(select([key]), selected);
    assert.equal(selected.names.length, 8); assert.equal(selected.postgresJoins, 1);
    assert.ok(source.includes(`func ${selected.top}(t *testing.T)`));
    assert.ok(workflow.includes(key));
    validate(trace(selected), selected);
    for (const name of selected.names) {
      if (name !== selected.top) assert.ok(source.includes(`t.Run("${name.slice(selected.top.length + 1)}"`));
      assert.ok(!Object.values(previous).some(g => g.names.includes(name)));
      assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
      assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
      for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
    }
  }
});


test('combined Agent filters retain every earlier native group and require both exact profiles', () => {
  const added = traceDiagnostics.AGENT_EXPOSURE_FILTER_ACCEPTANCE_GROUPS;
  const previous = {...groups, ...traceDiagnostics.ENVIRONMENT_CLASS_ACCEPTANCE_GROUPS,
    ...traceDiagnostics.MAINTENANCE_OPERATOR_ACCEPTANCE_GROUPS, ...traceDiagnostics.OPTIONAL_EGRESS_OPERATOR_ACCEPTANCE_GROUPS,
    ...traceDiagnostics.AGENT_CURRENT_READ_ACCEPTANCE_GROUPS};
  assert.deepEqual(Object.keys(added), ['agent-exposure-filter', 'agent-exposure-filter-audit']);
  const all = {...previous, ...added};
  assert.equal(Object.keys(previous).length, 23);
  assert.equal(Object.values(previous).flatMap(g => g.names).length, 162);
  assert.equal(Object.values(previous).reduce((n,g) => n + g.postgresJoins, 0), 34);
  assert.equal(Object.keys(all).length, 25);
  assert.equal(Object.values(all).flatMap(g => g.names).length, 180);
  assert.equal(Object.values(all).reduce((n,g) => n + g.postgresJoins, 0), 36);
  const source = fs.readFileSync(new URL('../services/platform/apiserver/agent_exposure_filter_postgres_test.go', import.meta.url), 'utf8');
  const workflow = fs.readFileSync(new URL('../.github/workflows/connector-connected-lifecycle.yml', import.meta.url), 'utf8');
  for (const [key, selected] of Object.entries(added)) {
    assert.equal(select([key]), selected);
    assert.equal(selected.names.length, 9); assert.equal(selected.postgresJoins, 1);
    assert.ok(source.includes(`func ${selected.top}(t *testing.T)`));
    assert.ok(workflow.includes(key));
    validate(trace(selected), selected);
    for (const name of selected.names) {
      if (name !== selected.top) assert.ok(source.includes(`t.Run("${name.slice(selected.top.length + 1)}"`));
      assert.ok(!Object.values(previous).some(g => g.names.includes(name)));
      assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
      assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
      for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
    }
  }
});

test('current Agent ownership writes retain every native group and require both exact profiles', () => {
  const added = traceDiagnostics.AGENT_OWNERSHIP_WRITE_ACCEPTANCE_GROUPS;
  const previous = {...groups, ...traceDiagnostics.ENVIRONMENT_CLASS_ACCEPTANCE_GROUPS,
    ...traceDiagnostics.MAINTENANCE_OPERATOR_ACCEPTANCE_GROUPS, ...traceDiagnostics.OPTIONAL_EGRESS_OPERATOR_ACCEPTANCE_GROUPS,
    ...traceDiagnostics.AGENT_CURRENT_READ_ACCEPTANCE_GROUPS, ...traceDiagnostics.AGENT_EXPOSURE_FILTER_ACCEPTANCE_GROUPS};
  assert.deepEqual(Object.keys(added), ['agent-ownership-write', 'agent-ownership-write-audit']);
  const all = {...previous, ...added};
  assert.equal(Object.keys(previous).length, 25);
  assert.equal(Object.values(previous).flatMap(g => g.names).length, 180);
  assert.equal(Object.values(previous).reduce((n,g) => n + g.postgresJoins, 0), 36);
  assert.equal(Object.keys(all).length, 27);
  assert.equal(Object.values(all).flatMap(g => g.names).length, 198);
  assert.equal(Object.values(all).reduce((n,g) => n + g.postgresJoins, 0), 38);
  const source = fs.readFileSync(new URL('../services/platform/apiserver/agent_current_ownership_write_postgres_test.go', import.meta.url), 'utf8');
  const workflow = fs.readFileSync(new URL('../.github/workflows/connector-connected-lifecycle.yml', import.meta.url), 'utf8');
  for (const [key, selected] of Object.entries(added)) {
    assert.equal(select([key]), selected);
    assert.equal(selected.names.length, 9); assert.equal(selected.postgresJoins, 1);
    assert.ok(source.includes(`func ${selected.top}(t *testing.T)`));
    assert.ok(workflow.includes(key));
    validate(trace(selected), selected);
    for (const name of selected.names) {
      if (name !== selected.top) assert.ok(source.includes(`t.Run("${name.slice(selected.top.length + 1)}"`));
      assert.ok(!Object.values(previous).some(g => g.names.includes(name)));
      assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
      assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
      for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
    }
  }
});


test('retained node observations add both exact profiles while preserving every native group', () => {
  const added = traceDiagnostics.SENSOR_NODE_COVERAGE_ACCEPTANCE_GROUPS;
  const previous = {...groups, ...traceDiagnostics.ENVIRONMENT_CLASS_ACCEPTANCE_GROUPS,
    ...traceDiagnostics.MAINTENANCE_OPERATOR_ACCEPTANCE_GROUPS, ...traceDiagnostics.OPTIONAL_EGRESS_OPERATOR_ACCEPTANCE_GROUPS,
    ...traceDiagnostics.AGENT_CURRENT_READ_ACCEPTANCE_GROUPS, ...traceDiagnostics.AGENT_EXPOSURE_FILTER_ACCEPTANCE_GROUPS,
    ...traceDiagnostics.AGENT_OWNERSHIP_WRITE_ACCEPTANCE_GROUPS};
  const all = {...previous, ...added};
  assert.equal(Object.keys(previous).length, 27);
  assert.equal(Object.values(previous).flatMap(g => g.names).length, 198);
  assert.equal(Object.values(previous).reduce((n,g) => n + g.postgresJoins, 0), 38);
  assert.equal(Object.keys(all).length, 29);
  assert.equal(Object.values(all).flatMap(g => g.names).length, 206);
  assert.equal(Object.values(all).reduce((n,g) => n + g.postgresJoins, 0), 40);
  const source = fs.readFileSync(new URL('../services/platform/apiserver/sensor_node_coverage_postgres_test.go', import.meta.url), 'utf8');
  const workflow = fs.readFileSync(new URL('../.github/workflows/connector-connected-lifecycle.yml', import.meta.url), 'utf8');
  for (const [key, selected] of Object.entries(added)) {
    assert.equal(select([key]), selected);
    assert.equal(selected.names.length, 4); assert.equal(selected.postgresJoins, 1);
    assert.ok(source.includes(`func ${selected.top}(t *testing.T)`));
    assert.ok(workflow.includes(key));
    validate(trace(selected), selected);
    for (const name of selected.names) {
      if (name !== selected.top) assert.ok(source.includes(`t.Run("${name.slice(selected.top.length + 1)}"`));
      assert.ok(!Object.values(previous).some(g => g.names.includes(name)));
      assert.throws(() => validate(trace(selected).filter(row => row.Test !== name), selected));
      assert.throws(() => validate([...trace(selected), {Package: pkg, Test: name, Action: 'pass'}], selected));
      for (const action of ['skip', 'fail']) assert.throws(() => validate(trace(selected).map(row => row.Test === name && row.Action === 'pass' ? {...row, Action: action} : row), selected));
    }
  }
});
