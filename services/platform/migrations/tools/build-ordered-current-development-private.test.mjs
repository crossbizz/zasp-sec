import test from 'node:test';
import assert from 'node:assert/strict';

// Break caught: a late evaluator validation selecting legacy private7 after
// attaching the precision-resolver private8 prevents the real builder loading.
// This exercises source assembly only; no output refresh or native acceptance.
test('combined dormant builder validates its precision private8 witness without promoting execution', async()=>{
 let api;
 await assert.doesNotReject(async()=>{
  api=await import('./build-ordered-current-development.mjs');
 }, 'all consumers must validate the same precision private8 assembly witness');
 const evaluator=api.admitOrderedCurrentDormantEvaluatorV1();
 assert.equal(evaluator.sourceContracts.private.compilerDerivedRoutines,8);
 assert.equal(evaluator.sourceContracts.private.importedRoutineObservations,0);
 assert.equal(evaluator.rules.length,379);
 assert.equal(evaluator.facts,10052); // 10051 source facts and one build record.
 assert.equal(evaluator.sourceContracts.worker.legacyReplay.accepted,13);
 assert.equal(evaluator.sourceContracts.worker.legacyReplay.refused,4);
 assert.equal(evaluator.sourceContracts.worker.higherSuccessor.accepted.length,4);
 assert.equal(evaluator.sourceContracts.worker.higherSuccessor.registration.status,'refused');
 assert.equal(evaluator.installable,false);
 assert.equal(evaluator.nativeVerified,false);
 assert.equal(evaluator.executableReplacementVerified,false);
 assert.equal(evaluator.ledgerStatus,'component-only');
});
