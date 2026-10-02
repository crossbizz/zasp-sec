import test from "node:test";
import assert from "node:assert/strict";
import {assertMountedEvidenceText,assertMountedHistorySelection,assertMountedCancellationControl} from "./existing-test-mounted-browser.mjs";

test("pending evidence cannot render a verdict and settled evidence must show its safe outcome/reason",()=>{
  assert.throws(()=>assertMountedEvidenceText("Test verification pending. Test outcome: Remediated","pending"));
  assert.throws(()=>assertMountedEvidenceText("Test verification settled. Test outcome: Remediated","settled","Needs human review","Test baseline unavailable."));
  assert.doesNotThrow(()=>assertMountedEvidenceText("Test verification pending.","pending"));
  assert.doesNotThrow(()=>assertMountedEvidenceText("Test verification settled. Test outcome: Inconclusive Reason: Test evaluation inconclusive.","settled","Inconclusive","Test evaluation inconclusive."));
});
test("history selection requires exact entity/scope URL and actual selected drawer",()=>{
  const expected="o/w/e",url="https://owned.example/red-team/results?entity_id=run&organization_id=o&workspace_id=w&environment_id=e";
  assert.throws(()=>assertMountedHistorySelection({url:"https://owned.example/red-team/results",title:"Red team run",id:"run"},"run",expected));
  assert.throws(()=>assertMountedHistorySelection({url,title:"Red Team",id:"run"},"run",expected));
  assert.doesNotThrow(()=>assertMountedHistorySelection({url,title:"Red team run",id:"run"},"run",expected));
});
test("foreign mutation denial needs unchanged cancellable authority and successful owner control",()=>{
  const before={state:"queued",version:3},foreign={status:409},missing={status:409},owner={status:200,body:{state:"cancelled",version:4}};
  assert.throws(()=>assertMountedCancellationControl({state:"remediated",version:3},foreign,missing,{state:"remediated",version:3},owner));
  assert.throws(()=>assertMountedCancellationControl(before,foreign,missing,before,{status:409}));
  assert.throws(()=>assertMountedCancellationControl(before,foreign,missing,{state:"queued",version:4},owner));
  assert.throws(()=>assertMountedCancellationControl(before,foreign,{status:404},before,owner));
  assert.doesNotThrow(()=>assertMountedCancellationControl(before,foreign,missing,before,owner));
});
