import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {buildOrderedCurrentLinuxSuccessorV1,analyzeOrderedCurrentLinuxSuccessorV1,assertOrderedCurrentLinuxSuccessorDeltaV1} from './build-ordered-current-linux-successor-v1.mjs';
const hash=v=>crypto.createHash('sha256').update(v).digest('hex');
test('separate Linux source assembly retains all eight outputs and source-derived facts',()=>{
 const b=buildOrderedCurrentLinuxSuccessorV1();assert.equal(b.format,'ordered-current-linux-successor-v1');assert.equal(b.installable,false);assert.equal(b.nativeVerified,false);assert.equal(b.expectedFromTarget,false);assert.equal(Object.keys(b.outputs).length,8);assert.equal(b.facts.length,10052);
 const provenance=b.facts.filter(x=>x.kind==='build');assert.equal(provenance.length,1);assert.match(provenance[0].fact.postgres,/Debian 18\.3-1/);assert.equal(b.manifest.entries.length,0);
 assert.match(b.outputs['development-module.sql'],/IF provenance->>'postgres' IS DISTINCT FROM pg_catalog.version\(\) THEN RETURN false; END IF;/);
 assert.throws(()=>buildOrderedCurrentLinuxSuccessorV1({postgres:'caller'}));
});
test('source fact/SQL delta explains only reserved build mutation and unchanged private routine bodies',()=>{
 const d=analyzeOrderedCurrentLinuxSuccessorV1();assert.equal(d.baselineFacts,10052);assert.equal(d.successorFacts,10052);assert.equal(d.added.length,0);assert.equal(d.removed.length,0);assert.equal(d.changed.length,1);assert.equal(d.changed[0].kind,'build');assert.equal(d.changed[0].identity,'provenance');assert.equal(d.functionalFactsEqual,true);assert.equal(d.privateRoutineDefinitions.length,8);assert.equal(d.privateRoutineDefinitions.every(x=>x.sameBytes),true);assert.equal(d.guardSameBytes,true);
 assert.equal(d.observations,'source-derived-delta-only; no SQL execution or runtime packet admission');
});
test('outputs and facts are detached and deterministic; malformed caller baselines cannot assert delta',()=>{
 const a=buildOrderedCurrentLinuxSuccessorV1(),b=buildOrderedCurrentLinuxSuccessorV1();for(const k of Object.keys(a.outputs))assert.equal(hash(a.outputs[k]),hash(b.outputs[k]));a.facts[0].fact={forged:true};a.outputs['development-module.sql']='forged';assert.notEqual(buildOrderedCurrentLinuxSuccessorV1().outputs['development-module.sql'],'forged');assert.throws(()=>analyzeOrderedCurrentLinuxSuccessorV1({baseline:'borrowed'}));
});

test('complete589/6348 source impact accounts every role/expectation/placement and preserves limits',()=>{
 const d=analyzeOrderedCurrentLinuxSuccessorV1();assert.equal(d.rules,379);assert.equal(d.sites,565);assert.equal(d.controlCount,589);assert.equal(d.stepCount,6348);assert.equal(d.programs.length,589);assert.equal(d.programs.reduce((n,c)=>n+c.steps.length,0),6348);assert.equal(new Set(d.programs.map(c=>c.id)).size,589);assert.equal(d.limits.maxRows,38240);assert.equal(d.phases.find(p=>p.id==='forged-entry').limits.maxRows,2048);assert.equal(d.phases.find(p=>p.id==='forged-entry').limits.maxBytes,4194304);assert.equal(d.outputs.length,8);assert.deepEqual(d.outputs.filter(x=>x.changed).map(x=>x.name).sort(),['development-checkpoint.json','development-manifest.json','development-module.sql']);assert.equal(assertOrderedCurrentLinuxSuccessorDeltaV1(d),true);
 for(const mutate of [x=>x.programs.pop(),x=>x.programs[0].steps[0].role='PUBLIC',x=>x.programs[0].steps[0].expectedSHA256='0'.repeat(64),x=>x.programs[0].steps[0].beforeSQLSHA256='0'.repeat(64),x=>x.limits.maxRows++,x=>x.phases[3].limits.maxBytes++,x=>x.changed[0].after.postgres='borrowed',x=>x.privateRoutineDefinitions[0].sameBytes=false]){const x=structuredClone(d);mutate(x);assert.throws(()=>assertOrderedCurrentLinuxSuccessorDeltaV1(x));}
});
