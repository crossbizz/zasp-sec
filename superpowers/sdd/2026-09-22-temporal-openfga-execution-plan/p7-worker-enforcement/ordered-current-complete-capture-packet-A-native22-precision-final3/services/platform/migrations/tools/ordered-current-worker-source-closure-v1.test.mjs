import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const subject=await import('./ordered-current-worker-source-closure-v1.mjs').catch(()=>({}));
const authorityURL=new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url);
const contract=JSON.parse(fs.readFileSync(authorityURL));

const build=()=>{
  assert.equal(typeof subject.buildOrderedWorkerSourceClosureV1,'function');
  return subject.buildOrderedWorkerSourceClosureV1(contract);
};

test('worker closure classifies every pinned worker source site without supplying expected truth',()=>{
  const packet=build();
  assert.deepEqual(subject.admitOrderedWorkerSourceClosureV1(),packet);
  assert.equal(packet.format,'ordered-current-worker-source-closure-v1');
  assert.equal(packet.status,'SOURCE-CLOSED-NATIVE-VALUES-PENDING');
  assert.equal(packet.installable,false);
  assert.equal(packet.captureReady,false);
  assert.equal(packet.sourceSites.length,172);
  assert.equal(packet.sourceSites.filter(row=>row.disposition==='unclassified').length,0);
  assert.equal(new Set(packet.sourceSites.map(row=>`${row.sourceIdentity}:${row.start}:${row.end}`)).size,172);
  assert.equal(packet.unavailableUniverses.length,2);
  assert.deepEqual(packet.unavailableUniverses.map(row=>row.ruleId),[
    'worker:projected72:domain-catalog',
    'worker:projected72:inventory-catalog',
  ]);
  assert.equal(packet.workerRecipes.length,28);
  assert.equal(packet.edgeConditionals.length,7);
  assert.equal(packet.membershipBags.length,2);
  assert.equal(packet.delegates.length,6);
  assert.deepEqual(packet.retainedOpaque.map(row=>row.ruleId),[
    'worker:projected74:schema',
    'worker:projected74:column',
    'worker:projected74:index',
    'worker:projected74:policy',
    'worker:projected74:trigger',
    'worker:projected74:owner-policy',
    'worker:projected74:mutation-trigger',
    'worker:projected74:saved',
  ]);
  assert.equal(packet.retainedOpaque.every(row=>row.disposition==='retain-original-framed-opaque'),true);
  assert.equal(packet.nativeObservation.required,true);
  assert.equal(packet.nativeObservation.expectedFacts,undefined);
  assert.equal(packet.nativeObservation.installable,false);
  assert.equal(packet.runtimeObligations.every(row=>row.expectedFacts===undefined),true);
  assert.equal(subject.assertOrderedWorkerSourceClosureV1(packet,contract),undefined);
});

test('tracked authority and finite refusal caps make the packet clean-checkout reviewable but not capture ready',()=>{
  const packet=build(),source=fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1.mjs',import.meta.url),'utf8');
  assert.equal(subject.workerSourceClosureAuthorityV1.url.href,authorityURL.href);
  assert.equal(subject.workerSourceClosureAuthorityV1.fileSHA256,'be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6');
  assert.doesNotMatch(source,/\.superpowers|private\/tmp/);
  assert.equal(packet.nativeObservation.limits.maxRows,35843);
  assert.equal(packet.nativeObservation.limits.maxBytes,67108864);
  assert.equal(packet.nativeObservation.captureReady,false);
  for(const rule of packet.nativeObservation.rules){
    assert.ok(Number.isSafeInteger(rule.maxRows)&&rule.maxRows>0,rule.ruleId);
    assert.ok(Number.isSafeInteger(rule.maxBytes)&&rule.maxBytes>0,rule.ruleId);
    assert.match(rule.capBasis,/fixed source|membership source/);
  }
  const observation={rules:packet.nativeObservation.rules.map(rule=>({ruleId:rule.ruleId,rows:0,bytes:0})),totalRows:0,totalBytes:0,truncated:false};
  assert.equal(subject.assertOrderedWorkerNativeObservationBoundsV1(observation,packet),undefined);
  for(const mutate of [
    value=>value.rules.pop(),
    value=>value.rules.push({...value.rules[0]}),
    value=>value.rules[0].rows=packet.nativeObservation.rules[0].maxRows+1,
    value=>value.rules[0].bytes=packet.nativeObservation.rules[0].maxBytes+1,
    value=>value.totalRows=packet.nativeObservation.limits.maxRows+1,
    value=>value.totalBytes=packet.nativeObservation.limits.maxBytes+1,
    value=>value.truncated=true,
  ]){const changed=structuredClone(observation);mutate(changed);assert.throws(()=>subject.assertOrderedWorkerNativeObservationBoundsV1(changed,packet),/worker native observation/);}
});

test('conditional, membership and delegate contracts preserve exact branch, frame, bag, NULL and error semantics',()=>{
  const packet=build();
  for(const row of packet.edgeConditionals){
    assert.equal(row.branch,'function');
    assert.equal(row.projections.length,7);
    assert.ok(row.caseExpressions.length>0);
    assert.equal(row.semantic.branch,'ordered CASE; only the selected value arm is evaluated');
    assert.equal(row.semantic.scalar,'zero rows => NULL; more than one row => SQLSTATE 21000');
    assert.equal(row.semantic.errors,'retain original reg-object resolution and selected helper errors');
    assert.deepEqual(row.frame.config,['search_path=pg_catalog, public']);
  }
  for(const row of packet.membershipBags){
    assert.deepEqual(row.fields,['granted_role','member_role','admin_option']);
    assert.equal(row.bag,true);
    assert.equal(row.semantic.multiplicity,'UNION ALL bag; preserve duplicate membership rows');
    assert.equal(row.semantic.nulls,'concat_ws skips NULL fields without replacing them');
  }
  assert.deepEqual(packet.delegates.map(row=>row.target),[
    'public.zasp_security_agent_connector_revocation_live_fingerprint()',
    'public.zasp_attack_lab_execution_live_fingerprint()',
    'public.zasp_recovery_execution_live_fingerprint()',
    'public.zasp_production_red_team_artifacts_live_fingerprint()',
    'public.zasp_production_runtime_correlation_routing_live_fingerprint()',
    'zasp_authorization80_worker.runtime_projected50_search()',
  ]);
  for(const row of [...packet.unavailableUniverses,...packet.delegates]){
    assert.equal(row.semantic.execution,'live invocation at the original source demand point');
    assert.equal(row.semantic.nulls,'preserve concatenation NULL behavior; no empty-result substitution');
    assert.equal(row.semantic.errors,'propagate original invocation and resolution errors');
    assert.equal(row.semantic.aggregate,'retain source UNION ALL multiplicity and outer ordered digest');
  }
});

test('all 28 worker recipes retain exact source identity, branch, frame, aggregate and native-value obligations',()=>{
  const packet=build();
  for(const row of packet.workerRecipes){
    assert.match(row.ruleId,/^worker:/);
    assert.match(row.sourceIdentity,/^zasp_authorization80_worker\./);
    assert.equal(row.sourceIdentity.endsWith('()'),true);
    assert.match(row.siteSHA256,/^[a-f0-9]{64}$/);
    assert.match(row.sourceSHA256,/^[a-f0-9]{64}$/);
    assert.deepEqual(row.frame.config,['search_path=pg_catalog, public']);
    assert.equal(row.semantic.aggregate,'UNION ALL bag, bytewise value ordering, newline string_agg, UTF8 SHA256');
    assert.equal(row.semantic.nulls,'concat_ws skips NULL fields; empty aggregate remains NULL');
    assert.equal(row.semantic.multiplicity,'preserve every source row and duplicate; never DISTINCT');
    assert.equal(row.semantic.errors,'retain original cast, relation, column and scalar-subquery errors');
    assert.equal(row.expectedFacts,undefined);
  }
  assert.equal(packet.nativeObservation.rules.length,37);
  assert.equal(packet.runtimeObligations.length,43);
});

test('closed assertion refuses missing, extra, duplicate, unknown-call, frame and target-derived authority',()=>{
  const mutations=[
    packet=>packet.workerRecipes.pop(),
    packet=>packet.workerRecipes.push(structuredClone(packet.workerRecipes[0])),
    packet=>packet.workerRecipes.push({...structuredClone(packet.workerRecipes[0]),ruleId:'worker:unknown:recipe'}),
    packet=>packet.workerRecipes[0].calls.push({name:'public.target_derived_expected_truth',identity:'public.target_derived_expected_truth()'}),
    packet=>packet.edgeConditionals[0].frame.config=['search_path=public'],
    packet=>packet.membershipBags[0].fields.reverse(),
    packet=>packet.delegates[0].target='public.target_selected()',
    packet=>packet.workerRecipes[0].expectedFacts=[],
    packet=>packet.sourceSites.pop(),
    packet=>packet.nativeObservation.rules[0].maxRows=null,
    packet=>delete packet.nativeObservation.rules[0].maxRows,
    packet=>packet.nativeObservation.rules[0].maxRows=0,
    packet=>packet.nativeObservation.rules[0].maxRows++,
    packet=>delete packet.nativeObservation.rules[0].maxBytes,
    packet=>packet.nativeObservation.rules[0].maxBytes=null,
    packet=>packet.nativeObservation.rules[0].maxBytes=0,
    packet=>packet.nativeObservation.rules[0].maxBytes++,
    packet=>delete packet.nativeObservation.limits.maxRows,
    packet=>packet.nativeObservation.limits.maxRows=null,
    packet=>packet.nativeObservation.limits.maxRows=0,
    packet=>packet.nativeObservation.limits.maxRows++,
    packet=>packet.nativeObservation.limits.maxBytes=null,
    packet=>delete packet.nativeObservation.limits.maxBytes,
    packet=>packet.nativeObservation.limits.maxBytes++,
  ];
  for(const mutate of mutations){
    const packet=build();mutate(packet);
    assert.throws(()=>subject.assertOrderedWorkerSourceClosureV1(packet,contract),/worker source closure/);
  }
  assert.throws(()=>subject.buildOrderedWorkerSourceClosureV1(contract,{path:'/tmp/caller.json'}),/caller-selected/);
  assert.throws(()=>subject.buildOrderedWorkerSourceClosureV1(contract,'0'.repeat(64)),/caller-selected/);
});

test('source mutation, overload substitution and target-derived contract input fail before packet construction',()=>{
  const frame=structuredClone(contract),node=frame.nodes.find(row=>row.identity==='zasp_authorization80_worker.projected72()');node.config=['search_path=public'];
  assert.throws(()=>subject.buildOrderedWorkerSourceClosureV1(frame),/source|frame/);
  const overload=structuredClone(contract),base=overload.nodes.find(row=>row.identity==='zasp_authorization80_worker.gateway_projected27()');overload.nodes.push({...base,identity:'zasp_authorization80_worker.gateway_projected27(text)'});
  assert.throws(()=>subject.buildOrderedWorkerSourceClosureV1(overload),/source contract pin|identity|coverage/);
  const extra=structuredClone(contract);extra.callerSelectedExpectedTruth={path:'/tmp/target.json',sha256:'0'.repeat(64)};
  assert.throws(()=>subject.buildOrderedWorkerSourceClosureV1(extra),/source contract pin/);
});
