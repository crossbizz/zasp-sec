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
  assert.deepEqual(Object.values(groups).map(g => [g.names.length, g.postgresJoins]), [[1, 2], [1, 2], [5, 2], [6, 2], [22, 1], [3, 1], [6, 2], [4, 2], [4, 2], [1, 2], [1, 2], [5, 2], [9, 1], [10, 1]]);
  const names = Object.values(groups).flatMap(g => g.names);
  assert.equal(names.length, 78); assert.equal(new Set(names).size, 78);
  assert.equal(Object.values(groups).reduce((n, g) => n + g.postgresJoins, 0), 24);
  for (const key of Object.keys(groups)) { assert.equal(select([key]), groups[key]); validate(trace(groups[key]), groups[key]); }
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
  assert.equal(selected.names.length, 10);
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
  "deploy/staging/iam-policy-union-v1.mjs",
  "deploy/staging/iam-policy-union-v1.test.mjs",
  "deploy/staging/tests/session_search_iam.tftest.hcl",
  ".github/workflows/retention-iam-acceptance.yml"
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
  const expected = ["retention-lock", "retention-role", "retention-parent", "retention-namespace", "retention-bridges", "retention-definitions", "retention-registration", "retention-ready", "retention-commit", "retention-parent-binding", "retention-parent-membership", "retention-parent-canonical", "retention-parent-source-owners", "retention-parent-worker-catalog", "retention-parent-worker-pin", "retention-parent-runtime-catalog", "retention-parent-runtime-pin", "retention-parent-authorization"];
  for (const name of ['hosted-connected-connector-acceptance.mjs', 'hosted-connector-authenticated-enqueue.mjs']) {
    const source = fs.readFileSync(new URL(name, import.meta.url), 'utf8');
    const stages = JSON.parse(source.match(/const fixedStages=(\[[^\n]*?\]);const locations/)[1]);
    assert.equal(new Set(stages).size, stages.length);
    for (const label of expected) assert.ok(stages.includes(label), label);
    assert.ok(!stages.includes('retention-PRIVATE_CANARY'));
    assert.ok(source.includes('fixedStages.includes(match[1])&&diagnostic.fixtureStages.length<32'));
  }
});
