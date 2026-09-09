import assert from "node:assert/strict";
import test from "node:test";
import * as runner from "./runner.mjs";

const input={schema_version:"red-team-runner-input-v1",organization_id:"pid_99300001-0000-4000-8000-000000000001",workspace_id:"pid_99300002-0000-4000-8000-000000000002",environment_id:"pid_99300003-0000-4000-8000-000000000003",run_id:"pid_99300004-0000-4000-8000-000000000004",definition_id:"pid_99300005-0000-4000-8000-000000000005",definition_version:1,target_id:"pid_99300006-0000-4000-8000-000000000006",target_kind:"agent_endpoint",categories:["prompt_injection"],input_digest:"a".repeat(64)};
const prompt=runner.buildPromptfooConfiguration(input,"https://agentsec-red-team-adapter.zasp.svc.cluster.local/v1/evaluate").tests[0].vars.prompt;
function nativeResult(){return {metadata:{promptfooVersion:"0.121.19",secret:"native-private-fixture"},results:{version:3,results:[{success:false,provider:{label:"zasp-red-team-adapter",config:{token:"native-private-fixture"}},vars:{category:"prompt_injection",prompt,private:"native-private-fixture"},testCase:{metadata:{category:"prompt_injection"}},response:{metadata:{http:{status:200,headers:{authorization:"native-private-fixture"}}},output:"native-private-fixture ZASP_RED_TEAM_PROMPT_INJECTION"},gradingResult:{pass:false,reason:"native-private-fixture"},"native-private-fixture":"untrusted key"}]}};}

test("native artifact retains engine structure under an explicit deny-by-default redaction policy",()=>{
  assert.equal(typeof runner.buildRedTeamNativeArtifact,"function");
  const native=nativeResult();
  const original=JSON.stringify(native);
  const artifact=runner.buildRedTeamNativeArtifact(input,native);
  assert.equal(artifact.schema_version,"red-team-native-artifact-v1");
  assert.equal(artifact.redaction_policy,"red-team-artifact-redaction-v1");
  assert.equal(artifact.run_id,input.run_id);
  assert.equal(artifact.input_digest,input.input_digest);
  assert.equal(artifact.native_output.metadata.promptfooVersion,"0.121.19");
  assert.equal(artifact.native_output.results.version,3);
  const record=artifact.native_output.results.results[0];
  assert.equal(record.success,false);
  assert.equal(record.response.metadata.http.status,200);
  assert.equal(record.vars.prompt,prompt);
  assert.equal(record.response.output,"[REDACTED]");
  assert.equal(record.gradingResult.reason,"[REDACTED]");
  assert.doesNotMatch(JSON.stringify(artifact),/native-private-fixture|authorization|"token"|"headers"/);
  assert.equal(JSON.stringify(native),original,"redaction must not mutate native engine evidence");
  assert.equal(runner.normalizePromptfooResult(input,artifact.native_output).verdict,"fail");
});

test("native artifact rejects invalid engine identity and unknown input authority",()=>{
  assert.equal(typeof runner.buildRedTeamNativeArtifact,"function");
  const native=nativeResult();native.metadata.promptfooVersion="unreviewed";
  assert.throws(()=>runner.buildRedTeamNativeArtifact(input,native));
  assert.throws(()=>runner.buildRedTeamNativeArtifact({...input,categories:["custom"]},nativeResult()));
  assert.throws(()=>runner.buildRedTeamNativeArtifact(input,null));
});
