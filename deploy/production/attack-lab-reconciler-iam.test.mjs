import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("settlement IAM source declares only exact version reads, bound decrypt and its own DSN",async()=>{
 const source=await readFile(new URL("../staging/attack_lab_reconciler.tf",import.meta.url),"utf8");
 assert.match(source,/system:serviceaccount:agentsec:security-agent-attack-lab-reconciler/);
 assert.match(source,/s3:GetObjectVersion/);
 assert.match(source,/aws_secretsmanager_secret.attack_lab_reconciler_dsn\[0\].arn/);
 assert.match(source,/kms:EncryptionContext:SecretARN/);
 assert.match(source,/kms:EncryptionContext:aws:s3:arn/);
 assert.match(source,/aws_s3_bucket.attack_lab_evidence.arn/);
 assert.match(source,/aws_kms_key.attack_lab.arn/);
 assert.doesNotMatch(source,/sqs:|eks:|s3:(?:GetObject"|Put|Delete|List|GetBucket)|kms:(?:Encrypt"|GenerateDataKey|DescribeKey)|postgres-security-agent-worker-dsn/);
 const runtime=await readFile(new URL("../../services/platform/agentsec-worker/security_agent_attack_lab_runtime.go",import.meta.url),"utf8");
 assert.doesNotMatch(runtime,/readyProductionDiscoveryArtifactAuthority/);
 assert.match(runtime,/readyProductionDiscoveryRole/);
});
