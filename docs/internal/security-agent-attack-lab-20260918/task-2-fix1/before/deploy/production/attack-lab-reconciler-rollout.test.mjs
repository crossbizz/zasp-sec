import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import { attackLabReconcilerReleaseFixture } from "./attack-lab-reconciler-release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";
import { testReconcilerReleaseFixture } from "./test-reconciler-release-fixture.mjs";
import { complianceExportReleaseFixture } from "./compliance-export-release-fixture.mjs";

test("57 mounts dedicated settlement authority and rejects additive credentials/network/RBAC", async () => {
  const attack = attackLabReconcilerReleaseFixture();
  const rows = await renderRelease(productionReleaseFixture, { schemaVersion: 57, sessionSearchPhase: "precision-intake", attackLabReconciler: attack });
  const name = "security-agent-attack-lab-reconciler";
  const deployment = rs => rs.find(r => r.kind === "Deployment" && r.metadata.name === name);
  const pod = rs => deployment(rs).spec.template.spec;
  const check = rs => validateRenderedRelease(rs,"123456789012",57,"precision-intake",undefined,undefined,undefined,attack);
  assert.doesNotThrow(() => check(rows));
  assert.equal(pod(rows).serviceAccountName,name);
  assert.equal(pod(rows).containers[0].env.find(e=>e.name==="ZASP_DATABASE_AUTHORITY").value,"zasp_security_agent_attack_lab_reconciler");
  const job=rows.find(r=>r.kind==="Job"&&r.metadata.name==="agentsec-schema-v57");
  assert.match(job.spec.template.spec.containers[0].args[0],/up-to-57.*register-security-agent-attack-lab-reconciler/);
  for(const mutate of [rs=>pod(rs).containers[0].env.push({name:"ZASP_ATTACK_LAB_ROLE_ARN",value:attack.roleArn}),rs=>pod(rs).containers[0].args=["exec /app/other"],rs=>pod(rs).volumes[1].projected.sources[0].serviceAccountToken.audience="other",rs=>rs.push({kind:"NetworkPolicy",metadata:{name:"wide"},spec:{podSelector:{},policyTypes:["Egress"],egress:[{}]}}),rs=>rs.push({kind:"ClusterRoleBinding",metadata:{name:"wide"},subjects:[{kind:"Group",name:"system:authenticated"}],roleRef:{kind:"ClusterRole",name:"admin"}})]){
    const changed=structuredClone(rows);mutate(changed);assert.throws(()=>check(changed),/release rejected/);
  }
  for(const schemaVersion of [49,56,58]) await assert.rejects(renderRelease(productionReleaseFixture,{schemaVersion,sessionSearchPhase:"precision-intake",attackLabReconciler:attack}),/release rejected/);
});

test("57 keeps audit, existing-test and compliance registration commands in both phases",async()=>{
  for(const phase of ["precision-consumers","precision-intake"]){
    const audit=auditExportReleaseFixture(),existing=testReconcilerReleaseFixture(),compliance=complianceExportReleaseFixture(),attack=attackLabReconcilerReleaseFixture();
    const rows=await renderRelease(productionReleaseFixture,{schemaVersion:57,sessionSearchPhase:phase,auditExports:audit,testReconciler:existing,complianceExports:compliance,attackLabReconciler:attack});
    assert.doesNotThrow(()=>validateRenderedRelease(rows,"123456789012",57,phase,audit,existing,compliance,attack));
    const command=rows.find(r=>r.kind==="Job"&&r.metadata.name==="agentsec-schema-v57").spec.template.spec.containers[0].args[0];
    for(const part of ["up-to-57","register-audit-export-api","register-audit-export-workers","configure-audit-exports","register-compliance-workers","register-security-agent-attack-lab-reconciler"]) assert.ok(command.includes(part),part);
  }
});
