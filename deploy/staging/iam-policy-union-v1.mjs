import fs from 'node:fs';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';

const fail = (message) => { throw new Error(`IAM union refusal: ${message}`); };
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const strings = (v) => {
 const result = typeof v === 'string' ? [v] : v;
 if (!Array.isArray(result) || !result.length || result.some(x => typeof x !== 'string' || !x.length || x.length > 2048)) fail('policy string/list');
 return result;
};
const contextKeys = new Set(['kms:ViaService', 'kms:EncryptionContext:SecretARN', 'kms:EncryptionContext:aws:s3:arn', 'kms:EncryptionContext:aws:sqs:arn', 's3:x-amz-server-side-encryption', 's3:x-amz-server-side-encryption-aws-kms-key-id']);
const glob = (pattern, value, fold = false) => new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, fold ? 'i' : '').test(value);

// JSON duplicate members are ambiguous source evidence, including escaped equivalent keys.
function strictJSON(text) {
 let i = 0;
 const whitespace = () => { while (/\s/.test(text[i] ?? '') && i < text.length) i++; };
 const stringToken = () => {
  const start = i++;
  while (i < text.length) {
   if (text[i] === '\\') { i += 2; continue; }
   if (text[i++] === '"') return JSON.parse(text.slice(start, i));
  }
  fail('mock JSON string');
 };
 const value = (depth = 0) => {
  if (depth > 128) fail('JSON depth');
  whitespace();
  if (text[i] === '{') {
   i++; whitespace(); const keys = new Set();
   if (text[i] === '}') { i++; return; }
   for (;;) {
    whitespace(); if (text[i] !== '"') fail('mock JSON object');
    const key = stringToken(); if (keys.has(key)) fail('duplicate JSON key'); keys.add(key);
    whitespace(); if (text[i++] !== ':') fail('mock JSON colon');
    value(depth + 1); whitespace();
    const token = text[i++]; if (token === '}') return; if (token !== ',') fail('mock JSON object delimiter');
   }
  }
  if (text[i] === '[') {
   i++; whitespace(); if (text[i] === ']') { i++; return; }
   for (;;) { value(depth + 1); whitespace(); const token = text[i++]; if (token === ']') return; if (token !== ',') fail('mock JSON array delimiter'); }
  }
  if (text[i] === '"') { stringToken(); return; }
  const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));
  if (!match) fail('mock JSON value'); i += match[0].length;
 };
 value(); whitespace(); if (i !== text.length) fail('mock JSON trailing bytes');
 return JSON.parse(text);
}

export function validatePolicy(policy) {
 if (!object(policy) || policy.Version !== '2012-10-17' || Object.keys(policy).some(k => !['Version', 'Statement', 'Id'].includes(k))) fail('policy version/keys');
 const rows = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
 if (!rows.length || rows.length > 256) fail('policy statements');
 for (const row of rows) {
  if (!object(row) || Object.keys(row).some(k => !['Sid', 'Effect', 'Action', 'Resource', 'Condition'].includes(k))) fail('unsupported policy construct');
  if (!['Allow', 'Deny'].includes(row.Effect)) fail('policy effect');
  for (const action of strings(row.Action)) if (action !== '*' && !/^[a-z0-9-]+:[a-z0-9*?]+$/i.test(action)) fail('policy unsupported action');
  for (const resource of strings(row.Resource)) if (resource !== '*' && (!resource.startsWith('arn:aws:') || resource.includes('${'))) fail('policy unsupported resource');
  if (policy.Id !== undefined && typeof policy.Id !== 'string') fail('policy Id');
  if (row.Sid !== undefined && typeof row.Sid !== 'string') fail('policy Sid');
  if (row.Condition !== undefined) {
   if (!object(row.Condition) || !Object.keys(row.Condition).length) fail('policy condition');
   for (const [operator, values] of Object.entries(row.Condition)) {
    if (!['StringEquals', 'StringLike', 'ArnLike'].includes(operator) || !object(values) || !Object.keys(values).length) fail('unsupported condition operator');
    for (const [key, value] of Object.entries(values)) {
     if (!contextKeys.has(key)) fail('unsupported context key');
     for (const v of strings(value)) if (v.includes('${') || operator === 'ArnLike' && !v.startsWith('arn:aws:')) fail('unsupported ArnLike value');
    }
   }
  }
 }
 return rows;
}
export function evaluateUnion(policies, request) {
 if (!Array.isArray(policies) || !policies.length || !object(request) || typeof request.action !== 'string' || typeof request.resource !== 'string' || !object(request.context) || Object.entries(request.context).some(([k, v]) => !contextKeys.has(k) || typeof v !== 'string')) fail('request context/policies');
 // Validate the entire union before evaluating any request. An unknown nonmatching row cannot silently become a denial.
 const rows = policies.flatMap(validatePolicy);
 let allowed = false;
 for (const row of rows) {
  if (!strings(row.Action).some(a => glob(a, request.action, true)) || !strings(row.Resource).some(r => glob(r, request.resource))) continue;
  const matches = Object.entries(row.Condition ?? {}).every(([operator, values]) => Object.entries(values).every(([key, expected]) => {
   const actual = request.context[key];
   return typeof actual === 'string' && strings(expected).some(value => operator === 'StringEquals' ? value === actual : glob(value, actual));
  }));
  if (!matches) continue;
  if (row.Effect === 'Deny') return 'denied';
  allowed = true;
 }
 return allowed ? 'allowed' : 'denied';
}

export function parseMockPlan(input) {
 if (typeof input !== 'string' || !input.length || Buffer.byteLength(input) > 64 * 1024 * 1024) fail('mock buffer');
 let events;
 try { events = input.trimEnd().split('\n').map(line => strictJSON(line)); } catch (error) { if (error.message.includes('duplicate JSON key')) throw error; fail('mock JSON incomplete'); }
 if (events.some(e => !object(e) || e.type === 'diagnostic' && e.diagnostic?.severity === 'error')) fail('mock diagnostic');
 const allowedEvents = new Set(['version', 'test_abstract', 'test_file', 'test_run', 'test_plan', 'test_summary']);
 if (events.some(e => !allowedEvents.has(e.type))) fail('mock unsupported event');
 if (!same(events.map(e => e.type), ['version', 'test_abstract', 'test_file', 'test_run', 'test_run', 'test_plan', 'test_file', 'test_file', 'test_summary'])) fail('mock completion lifecycle event order');
 const abstract = events.filter(e => e.type === 'test_abstract');
 const files = events.filter(e => e.type === 'test_file');
 const runs = events.filter(e => e.type === 'test_run');
 if (!same(runs.map(e => e.test_run?.progress), ['starting', 'complete'])) fail('mock lifecycle run progress/order');
 if (events.length !== 9 || abstract.length !== 1 || !same(abstract[0].test_abstract, { 'tests/iam_policy_union.tftest.hcl': ['closed_default_workload_policy_union'] }) || files.length !== 3 || !same(files.map(e => e.test_file?.progress), ['starting', 'teardown', 'complete']) || files.some(e => e.test_file?.path !== 'tests/iam_policy_union.tftest.hcl') || files[2].test_file.status !== 'pass' || runs.length !== 2 || runs.some(e => e.test_run?.path !== 'tests/iam_policy_union.tftest.hcl' || e.test_run?.run !== 'closed_default_workload_policy_union')) fail('mock completion/event roster');
 const versions = events.filter(e => e.type === 'version');
 if (versions.length !== 1 || versions[0].terraform !== '1.15.8' || versions[0].ui !== '1.3') fail('mock Terraform version');
 const plans = events.filter(e => e.type === 'test_plan');
 const summaries = events.filter(e => e.type === 'test_summary');
 const complete = events.filter(e => e.type === 'test_run' && e.test_run?.progress === 'complete');
 if (plans.length !== 1 || plans[0]['@testfile'] !== 'tests/iam_policy_union.tftest.hcl' || plans[0]['@testrun'] !== 'closed_default_workload_policy_union' || summaries.length !== 1 || summaries[0].test_summary?.status !== 'pass' || summaries[0].test_summary?.passed !== 1 || summaries[0].test_summary?.failed !== 0 || summaries[0].test_summary?.errored !== 0 || summaries[0].test_summary?.skipped !== 0 || complete.length !== 1 || complete[0].test_run?.status !== 'pass') fail('mock completion/profile');
 return plans[0].test_plan;
}

// Closed source-profile addresses and distinct fixture identities; not an Allow-derived decision oracle.
const resourceRoster = [
 "aws_eks_addon.vpc_cni",
 "aws_eks_cluster.staging",
 "aws_eks_fargate_profile.attack_lab",
 "aws_eks_node_group.staging",
 "aws_iam_openid_connect_provider.eks",
 "aws_iam_policy.attack_lab_runner_test_boundary",
 "aws_iam_role.api",
 "aws_iam_role.api_connectors",
 "aws_iam_role.attack_lab[\"controller\"]",
 "aws_iam_role.attack_lab[\"outbox\"]",
 "aws_iam_role.attack_lab[\"proxy\"]",
 "aws_iam_role.attack_lab_pod",
 "aws_iam_role.attack_lab_runner_test",
 "aws_iam_role.audit_exports[\"publisher\"]",
 "aws_iam_role.audit_exports[\"reader\"]",
 "aws_iam_role.audit_exports[\"writer\"]",
 "aws_iam_role.canary_secret_sync",
 "aws_iam_role.eks_cluster",
 "aws_iam_role.eks_nodes",
 "aws_iam_role.migration",
 "aws_iam_role.outbox",
 "aws_iam_role.policy_deployment_worker",
 "aws_iam_role.projection_graph",
 "aws_iam_role.projection_graph_init",
 "aws_iam_role.projection_risk",
 "aws_iam_role.projection_search",
 "aws_iam_role.projection_search_init",
 "aws_iam_role.recovery[\"recovery_backup\"]",
 "aws_iam_role.recovery[\"recovery_backup_outbox\"]",
 "aws_iam_role.recovery[\"recovery_restore\"]",
 "aws_iam_role.recovery[\"recovery_restore_outbox\"]",
 "aws_iam_role.red_team[\"adapter\"]",
 "aws_iam_role.red_team[\"outbox\"]",
 "aws_iam_role.red_team[\"worker\"]",
 "aws_iam_role.runtime[\"archive\"]",
 "aws_iam_role.runtime[\"complete\"]",
 "aws_iam_role.runtime[\"coordinator\"]",
 "aws_iam_role.runtime[\"correlation\"]",
 "aws_iam_role.runtime[\"gateway_control\"]",
 "aws_iam_role.runtime[\"index\"]",
 "aws_iam_role.runtime[\"ingest\"]",
 "aws_iam_role.runtime[\"outbox\"]",
 "aws_iam_role.runtime[\"projection\"]",
 "aws_iam_role.scheduler",
 "aws_iam_role.security_agent_action_worker",
 "aws_iam_role.security_agent_worker",
 "aws_iam_role.worker",
 "aws_iam_role_policy.api",
 "aws_iam_role_policy.api_connectors",
 "aws_iam_role_policy.attack_lab[\"controller\"]",
 "aws_iam_role_policy.attack_lab[\"outbox\"]",
 "aws_iam_role_policy.attack_lab[\"proxy\"]",
 "aws_iam_role_policy.attack_lab_runner_test",
 "aws_iam_role_policy.audit_export_secrets[\"audit-export-cursor-signing-key\"]",
 "aws_iam_role_policy.audit_export_secrets[\"postgres-audit-export-outbox-dsn\"]",
 "aws_iam_role_policy.audit_export_secrets[\"postgres-audit-export-worker-dsn\"]",
 "aws_iam_role_policy.audit_exports[\"publisher\"]",
 "aws_iam_role_policy.audit_exports[\"reader\"]",
 "aws_iam_role_policy.audit_exports[\"writer\"]",
 "aws_iam_role_policy.canary_secret_sync",
 "aws_iam_role_policy.migration",
 "aws_iam_role_policy.outbox",
 "aws_iam_role_policy.policy_deployment_worker",
 "aws_iam_role_policy.projection_graph",
 "aws_iam_role_policy.projection_graph_init",
 "aws_iam_role_policy.projection_risk",
 "aws_iam_role_policy.projection_search",
 "aws_iam_role_policy.projection_search_init",
 "aws_iam_role_policy.recovery[\"recovery_backup\"]",
 "aws_iam_role_policy.recovery[\"recovery_backup_outbox\"]",
 "aws_iam_role_policy.recovery[\"recovery_restore\"]",
 "aws_iam_role_policy.recovery[\"recovery_restore_outbox\"]",
 "aws_iam_role_policy.red_team[\"adapter\"]",
 "aws_iam_role_policy.red_team[\"outbox\"]",
 "aws_iam_role_policy.red_team[\"worker\"]",
 "aws_iam_role_policy.runtime[\"archive\"]",
 "aws_iam_role_policy.runtime[\"complete\"]",
 "aws_iam_role_policy.runtime[\"coordinator\"]",
 "aws_iam_role_policy.runtime[\"correlation\"]",
 "aws_iam_role_policy.runtime[\"gateway_control\"]",
 "aws_iam_role_policy.runtime[\"index\"]",
 "aws_iam_role_policy.runtime[\"ingest\"]",
 "aws_iam_role_policy.runtime[\"outbox\"]",
 "aws_iam_role_policy.runtime[\"projection\"]",
 "aws_iam_role_policy.scheduler",
 "aws_iam_role_policy.security_agent_action_worker",
 "aws_iam_role_policy.security_agent_worker",
 "aws_iam_role_policy.worker",
 "aws_iam_role_policy_attachment.attack_lab_pod",
 "aws_iam_role_policy_attachment.eks_cluster",
 "aws_iam_role_policy_attachment.eks_nodes[\"AmazonEC2ContainerRegistryReadOnly\"]",
 "aws_iam_role_policy_attachment.eks_nodes[\"AmazonEKSWorkerNodePolicy\"]",
 "aws_iam_role_policy_attachment.eks_nodes[\"AmazonEKS_CNI_Policy\"]",
 "aws_iam_role_policy_attachment.eks_vpc_resource_controller",
 "aws_kms_alias.attack_lab",
 "aws_kms_alias.connector_oauth",
 "aws_kms_alias.recovery_signing",
 "aws_kms_alias.red_team",
 "aws_kms_alias.runtime_raw",
 "aws_kms_alias.staging",
 "aws_kms_key.attack_lab",
 "aws_kms_key.connector_oauth",
 "aws_kms_key.recovery_signing",
 "aws_kms_key.red_team",
 "aws_kms_key.runtime_raw",
 "aws_kms_key.staging",
 "aws_opensearch_domain.events",
 "aws_route_table.attack_lab",
 "aws_route_table_association.attack_lab[0]",
 "aws_route_table_association.attack_lab[1]",
 "aws_s3_bucket.attack_lab_evidence",
 "aws_s3_bucket.evidence",
 "aws_s3_bucket.red_team_evidence",
 "aws_s3_bucket.runtime_raw",
 "aws_s3_bucket_lifecycle_configuration.attack_lab_evidence",
 "aws_s3_bucket_lifecycle_configuration.evidence",
 "aws_s3_bucket_lifecycle_configuration.red_team_evidence",
 "aws_s3_bucket_lifecycle_configuration.runtime_raw",
 "aws_s3_bucket_ownership_controls.attack_lab_evidence",
 "aws_s3_bucket_ownership_controls.red_team_evidence",
 "aws_s3_bucket_ownership_controls.runtime_raw",
 "aws_s3_bucket_policy.attack_lab_evidence",
 "aws_s3_bucket_policy.red_team_evidence",
 "aws_s3_bucket_policy.runtime_raw",
 "aws_s3_bucket_public_access_block.attack_lab_evidence",
 "aws_s3_bucket_public_access_block.evidence",
 "aws_s3_bucket_public_access_block.red_team_evidence",
 "aws_s3_bucket_public_access_block.runtime_raw",
 "aws_s3_bucket_server_side_encryption_configuration.attack_lab_evidence",
 "aws_s3_bucket_server_side_encryption_configuration.evidence",
 "aws_s3_bucket_server_side_encryption_configuration.red_team_evidence",
 "aws_s3_bucket_server_side_encryption_configuration.runtime_raw",
 "aws_s3_bucket_versioning.attack_lab_evidence",
 "aws_s3_bucket_versioning.evidence",
 "aws_s3_bucket_versioning.red_team_evidence",
 "aws_s3_bucket_versioning.runtime_raw",
 "aws_secretsmanager_secret.audit_exports[\"audit-export-cursor-signing-key\"]",
 "aws_secretsmanager_secret.audit_exports[\"postgres-audit-export-outbox-dsn\"]",
 "aws_secretsmanager_secret.audit_exports[\"postgres-audit-export-worker-dsn\"]",
 "aws_secretsmanager_secret.connector_provider[\"github_app_private_key\"]",
 "aws_secretsmanager_secret.connector_provider[\"github_client_secret\"]",
 "aws_secretsmanager_secret.connector_provider[\"okta_client_secret\"]",
 "aws_secretsmanager_secret.connector_reference[\"aws_external_id\"]",
 "aws_secretsmanager_secret.connector_reference[\"kubernetes_ca\"]",
 "aws_secretsmanager_secret.connector_reference[\"kubernetes_connection\"]",
 "aws_secretsmanager_secret.connector_reference[\"kubernetes_credential\"]",
 "aws_secretsmanager_secret.neo4j_projection_runtime",
 "aws_secretsmanager_secret.neo4j_projection_schema",
 "aws_secretsmanager_secret.product[\"attack-lab-egress-signing-key\"]",
 "aws_secretsmanager_secret.product[\"attack-lab-proxy-tls-certificate\"]",
 "aws_secretsmanager_secret.product[\"attack-lab-proxy-tls-private-key\"]",
 "aws_secretsmanager_secret.product[\"canary-read-token\"]",
 "aws_secretsmanager_secret.product[\"gateway-policy-signing-private-key\"]",
 "aws_secretsmanager_secret.product[\"openrouter-security-agent-api-key\"]",
 "aws_secretsmanager_secret.product[\"postgres-api-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-attack-lab-controller-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-attack-lab-outbox-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-attack-lab-proxy-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-gateway-control-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-migration-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-outbox-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-policy-deployment-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-projection-graph-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-projection-risk-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-projection-search-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-recovery-outbox-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-recovery-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-red-team-adapter-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-red-team-outbox-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-red-team-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-runtime-archive-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-runtime-coordinator-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-runtime-correlation-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-runtime-gateway-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-runtime-index-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-runtime-ingest-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-runtime-projection-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-runtime-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-scheduler-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-security-agent-action-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-security-agent-api-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-security-agent-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"postgres-worker-dsn\"]",
 "aws_secretsmanager_secret.product[\"red-team-adapter-tls-certificate\"]",
 "aws_secretsmanager_secret.product[\"red-team-adapter-tls-private-key\"]",
 "aws_secretsmanager_secret.product[\"red-team-adapter-token\"]",
 "aws_secretsmanager_secret.product[\"stytch-organization-id\"]",
 "aws_secretsmanager_secret.product[\"stytch-project-id\"]",
 "aws_secretsmanager_secret.product[\"stytch-public-token\"]",
 "aws_secretsmanager_secret.product[\"stytch-secret\"]",
 "aws_secretsmanager_secret.product[\"stytch-webhook-secret\"]",
 "aws_secretsmanager_secret.product[\"token-reveal-key\"]",
 "aws_secretsmanager_secret.product[\"workflow-signing-key\"]",
 "aws_secretsmanager_secret.recovery_neon_api",
 "aws_secretsmanager_secret.red_team_readiness_target",
 "aws_security_group.attack_lab",
 "aws_security_group.attack_lab_ecr_endpoints",
 "aws_security_group.attack_lab_proxy",
 "aws_security_group.opensearch",
 "aws_security_group.vpc_endpoints",
 "aws_sqs_queue.dead_letter[\"attack-lab-jobs\"]",
 "aws_sqs_queue.dead_letter[\"audit-exports\"]",
 "aws_sqs_queue.dead_letter[\"background\"]",
 "aws_sqs_queue.dead_letter[\"discovery-jobs\"]",
 "aws_sqs_queue.dead_letter[\"recovery-backup-jobs\"]",
 "aws_sqs_queue.dead_letter[\"recovery-restore-jobs\"]",
 "aws_sqs_queue.dead_letter[\"red-team-tests\"]",
 "aws_sqs_queue.dead_letter[\"runtime-events\"]",
 "aws_sqs_queue.dead_letter[\"tests\"]",
 "aws_sqs_queue.work[\"attack-lab-jobs\"]",
 "aws_sqs_queue.work[\"audit-exports\"]",
 "aws_sqs_queue.work[\"background\"]",
 "aws_sqs_queue.work[\"discovery-jobs\"]",
 "aws_sqs_queue.work[\"recovery-backup-jobs\"]",
 "aws_sqs_queue.work[\"recovery-restore-jobs\"]",
 "aws_sqs_queue.work[\"red-team-tests\"]",
 "aws_sqs_queue.work[\"runtime-events\"]",
 "aws_sqs_queue.work[\"tests\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"attack-lab-jobs\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"audit-exports\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"background\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"discovery-jobs\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"recovery-backup-jobs\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"recovery-restore-jobs\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"red-team-tests\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"runtime-events\"]",
 "aws_sqs_queue_redrive_allow_policy.dead_letter[\"tests\"]",
 "aws_subnet.attack_lab[0]",
 "aws_subnet.attack_lab[1]",
 "aws_subnet.private[0]",
 "aws_subnet.private[1]",
 "aws_vpc.staging",
 "aws_vpc_endpoint.attack_lab_s3",
 "aws_vpc_endpoint.private_services[\"ecr.api\"]",
 "aws_vpc_endpoint.private_services[\"ecr.dkr\"]",
 "aws_vpc_endpoint.private_services[\"kms\"]",
 "aws_vpc_endpoint.private_services[\"logs\"]",
 "aws_vpc_endpoint.private_services[\"secretsmanager\"]",
 "aws_vpc_endpoint.private_services[\"sqs\"]",
 "aws_vpc_endpoint.private_services[\"sts\"]",
 "aws_vpc_endpoint.s3",
 "aws_vpc_security_group_egress_rule.attack_lab_proxy_database[\"10.30.0.0/24\"]",
 "aws_vpc_security_group_egress_rule.attack_lab_proxy_dns_tcp",
 "aws_vpc_security_group_egress_rule.attack_lab_proxy_dns_udp",
 "aws_vpc_security_group_egress_rule.attack_lab_proxy_endpoints",
 "aws_vpc_security_group_egress_rule.attack_lab_proxy_targets[\"203.0.113.0/28\"]",
 "aws_vpc_security_group_egress_rule.attack_lab_runner_control_plane",
 "aws_vpc_security_group_egress_rule.attack_lab_runner_dns_tcp",
 "aws_vpc_security_group_egress_rule.attack_lab_runner_dns_udp",
 "aws_vpc_security_group_egress_rule.attack_lab_runner_ecr",
 "aws_vpc_security_group_egress_rule.attack_lab_runner_proxy",
 "aws_vpc_security_group_egress_rule.attack_lab_runner_s3",
 "aws_vpc_security_group_ingress_rule.attack_lab_control_plane_runner",
 "aws_vpc_security_group_ingress_rule.attack_lab_dns_proxy_tcp",
 "aws_vpc_security_group_ingress_rule.attack_lab_dns_proxy_udp",
 "aws_vpc_security_group_ingress_rule.attack_lab_dns_runner_tcp",
 "aws_vpc_security_group_ingress_rule.attack_lab_dns_runner_udp",
 "aws_vpc_security_group_ingress_rule.attack_lab_ecr_runner",
 "aws_vpc_security_group_ingress_rule.attack_lab_proxy_internal",
 "aws_vpc_security_group_ingress_rule.attack_lab_proxy_runner",
 "aws_vpc_security_group_ingress_rule.attack_lab_runner_kubelet",
 "data.tls_certificate.eks"
];
export const workloadRoles = [
 "aws_iam_role.api",
 "aws_iam_role.api_connectors",
 "aws_iam_role.attack_lab[\"controller\"]",
 "aws_iam_role.attack_lab[\"outbox\"]",
 "aws_iam_role.attack_lab[\"proxy\"]",
 "aws_iam_role.attack_lab_runner_test",
 "aws_iam_role.audit_exports[\"publisher\"]",
 "aws_iam_role.audit_exports[\"reader\"]",
 "aws_iam_role.audit_exports[\"writer\"]",
 "aws_iam_role.canary_secret_sync",
 "aws_iam_role.migration",
 "aws_iam_role.outbox",
 "aws_iam_role.policy_deployment_worker",
 "aws_iam_role.projection_graph",
 "aws_iam_role.projection_graph_init",
 "aws_iam_role.projection_risk",
 "aws_iam_role.projection_search",
 "aws_iam_role.projection_search_init",
 "aws_iam_role.recovery[\"recovery_backup\"]",
 "aws_iam_role.recovery[\"recovery_backup_outbox\"]",
 "aws_iam_role.recovery[\"recovery_restore\"]",
 "aws_iam_role.recovery[\"recovery_restore_outbox\"]",
 "aws_iam_role.red_team[\"adapter\"]",
 "aws_iam_role.red_team[\"outbox\"]",
 "aws_iam_role.red_team[\"worker\"]",
 "aws_iam_role.runtime[\"archive\"]",
 "aws_iam_role.runtime[\"complete\"]",
 "aws_iam_role.runtime[\"coordinator\"]",
 "aws_iam_role.runtime[\"correlation\"]",
 "aws_iam_role.runtime[\"gateway_control\"]",
 "aws_iam_role.runtime[\"index\"]",
 "aws_iam_role.runtime[\"ingest\"]",
 "aws_iam_role.runtime[\"outbox\"]",
 "aws_iam_role.runtime[\"projection\"]",
 "aws_iam_role.scheduler",
 "aws_iam_role.security_agent_action_worker",
 "aws_iam_role.security_agent_worker",
 "aws_iam_role.worker"
];
const fixtureBindings = [
 {
  "address": "aws_iam_openid_connect_provider.eks",
  "values": {
   "arn": "arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/staging-union"
  }
 },
 {
  "address": "aws_iam_policy.attack_lab_runner_test_boundary",
  "values": {
   "arn": "arn:aws:iam::000000000000:policy/zasp-staging-attack-lab-runner-test-boundary",
   "id": "arn:aws:iam::000000000000:policy/zasp-staging-attack-lab-runner-test-boundary"
  }
 },
 {
  "address": "aws_iam_role.api",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-api",
   "id": "zasp-staging-api"
  }
 },
 {
  "address": "aws_iam_role.api_connectors",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-api-connectors",
   "id": "zasp-staging-api-connectors"
  }
 },
 {
  "address": "aws_iam_role.attack_lab[\"controller\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-controller",
   "id": "zasp-staging-attack-lab-controller"
  }
 },
 {
  "address": "aws_iam_role.attack_lab[\"outbox\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-outbox",
   "id": "zasp-staging-attack-lab-outbox"
  }
 },
 {
  "address": "aws_iam_role.attack_lab[\"proxy\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-proxy",
   "id": "zasp-staging-attack-lab-proxy"
  }
 },
 {
  "address": "aws_iam_role.attack_lab_pod",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-pod",
   "id": "zasp-staging-attack-lab-pod"
  }
 },
 {
  "address": "aws_iam_role.attack_lab_runner_test",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-attack-lab-runner-test",
   "id": "zasp-staging-attack-lab-runner-test"
  }
 },
 {
  "address": "aws_iam_role.audit_exports[\"publisher\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-audit-export-publisher",
   "id": "zasp-staging-audit-export-publisher"
  }
 },
 {
  "address": "aws_iam_role.audit_exports[\"reader\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-audit-export-reader",
   "id": "zasp-staging-audit-export-reader"
  }
 },
 {
  "address": "aws_iam_role.audit_exports[\"writer\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-audit-export-writer",
   "id": "zasp-staging-audit-export-writer"
  }
 },
 {
  "address": "aws_iam_role.canary_secret_sync",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-canary-secret-sync",
   "id": "zasp-staging-canary-secret-sync"
  }
 },
 {
  "address": "aws_iam_role.eks_cluster",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-cluster",
   "id": "zasp-staging-cluster"
  }
 },
 {
  "address": "aws_iam_role.eks_nodes",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-nodes",
   "id": "zasp-staging-nodes"
  }
 },
 {
  "address": "aws_iam_role.migration",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-migration",
   "id": "zasp-staging-migration"
  }
 },
 {
  "address": "aws_iam_role.outbox",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-outbox",
   "id": "zasp-staging-outbox"
  }
 },
 {
  "address": "aws_iam_role.policy_deployment_worker",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-policy-deployment-worker",
   "id": "zasp-staging-policy-deployment-worker"
  }
 },
 {
  "address": "aws_iam_role.projection_graph",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-graph",
   "id": "zasp-staging-projection-graph"
  }
 },
 {
  "address": "aws_iam_role.projection_graph_init",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-graph-init",
   "id": "zasp-staging-projection-graph-init"
  }
 },
 {
  "address": "aws_iam_role.projection_risk",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-risk",
   "id": "zasp-staging-projection-risk"
  }
 },
 {
  "address": "aws_iam_role.projection_search",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-search",
   "id": "zasp-staging-projection-search"
  }
 },
 {
  "address": "aws_iam_role.projection_search_init",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-projection-search-init",
   "id": "zasp-staging-projection-search-init"
  }
 },
 {
  "address": "aws_iam_role.recovery[\"recovery_backup\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-recovery-backup",
   "id": "zasp-staging-recovery-backup"
  }
 },
 {
  "address": "aws_iam_role.recovery[\"recovery_backup_outbox\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-recovery-backup-outbox",
   "id": "zasp-staging-recovery-backup-outbox"
  }
 },
 {
  "address": "aws_iam_role.recovery[\"recovery_restore\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-recovery-restore",
   "id": "zasp-staging-recovery-restore"
  }
 },
 {
  "address": "aws_iam_role.recovery[\"recovery_restore_outbox\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-recovery-restore-outbox",
   "id": "zasp-staging-recovery-restore-outbox"
  }
 },
 {
  "address": "aws_iam_role.red_team[\"adapter\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-red-team-adapter",
   "id": "zasp-staging-red-team-adapter"
  }
 },
 {
  "address": "aws_iam_role.red_team[\"outbox\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-red-team-outbox",
   "id": "zasp-staging-red-team-outbox"
  }
 },
 {
  "address": "aws_iam_role.red_team[\"worker\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-red-team-worker",
   "id": "zasp-staging-red-team-worker"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"archive\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-archive",
   "id": "zasp-staging-runtime-archive"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"complete\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-complete",
   "id": "zasp-staging-runtime-complete"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"coordinator\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-coordinator",
   "id": "zasp-staging-runtime-coordinator"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"correlation\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-correlation",
   "id": "zasp-staging-runtime-correlation"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"gateway_control\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-gateway-control",
   "id": "zasp-staging-gateway-control"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"index\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-index",
   "id": "zasp-staging-runtime-index"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"ingest\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-ingest",
   "id": "zasp-staging-runtime-ingest"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"outbox\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-outbox",
   "id": "zasp-staging-runtime-outbox"
  }
 },
 {
  "address": "aws_iam_role.runtime[\"projection\"]",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-runtime-projection",
   "id": "zasp-staging-runtime-projection"
  }
 },
 {
  "address": "aws_iam_role.scheduler",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-discovery-scheduler",
   "id": "zasp-staging-discovery-scheduler"
  }
 },
 {
  "address": "aws_iam_role.security_agent_action_worker",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-security-agent-action-worker",
   "id": "zasp-staging-security-agent-action-worker"
  }
 },
 {
  "address": "aws_iam_role.security_agent_worker",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-security-agent-worker",
   "id": "zasp-staging-security-agent-worker"
  }
 },
 {
  "address": "aws_iam_role.worker",
  "values": {
   "arn": "arn:aws:iam::000000000000:role/zasp-staging-discovery-worker",
   "id": "zasp-staging-discovery-worker"
  }
 },
 {
  "address": "aws_kms_key.attack_lab",
  "values": {
   "arn": "arn:aws:kms:us-west-2:000000000000:key/19b5c7c4-bd0f-43c1-8997-00d89c60de3c",
   "id": "19b5c7c4-bd0f-43c1-8997-00d89c60de3c"
  }
 },
 {
  "address": "aws_kms_key.connector_oauth",
  "values": {
   "arn": "arn:aws:kms:us-west-2:000000000000:key/63500a26-5cc2-ab1e-0e23-d07574fc6f55",
   "id": "63500a26-5cc2-ab1e-0e23-d07574fc6f55"
  }
 },
 {
  "address": "aws_kms_key.recovery_signing",
  "values": {
   "arn": "arn:aws:kms:us-west-2:000000000000:key/10befce7-852e-cf7c-e6cc-e5a05dd4a230",
   "id": "10befce7-852e-cf7c-e6cc-e5a05dd4a230"
  }
 },
 {
  "address": "aws_kms_key.red_team",
  "values": {
   "arn": "arn:aws:kms:us-west-2:000000000000:key/2d07a082-d7d9-37bd-2e7a-903b1c558b15",
   "id": "2d07a082-d7d9-37bd-2e7a-903b1c558b15"
  }
 },
 {
  "address": "aws_kms_key.runtime_raw",
  "values": {
   "arn": "arn:aws:kms:us-west-2:000000000000:key/c225b472-d20b-912e-bc20-91ff5159034e",
   "id": "c225b472-d20b-912e-bc20-91ff5159034e"
  }
 },
 {
  "address": "aws_kms_key.staging",
  "values": {
   "arn": "arn:aws:kms:us-west-2:000000000000:key/c824037f-f668-5b41-f364-7e25f1707b38",
   "id": "c824037f-f668-5b41-f364-7e25f1707b38"
  }
 },
 {
  "address": "aws_opensearch_domain.events",
  "values": {
   "arn": "arn:aws:es:us-west-2:000000000000:domain/zasp-staging-events",
   "endpoint": "zasp-staging-events.us-west-2.es.amazonaws.com"
  }
 },
 {
  "address": "aws_s3_bucket.attack_lab_evidence",
  "values": {
   "arn": "arn:aws:s3:::zasp-attack-lab-evidence-35b9ab5a36f3234dd26db357fd4a0dc1",
   "id": "zasp-attack-lab-evidence-35b9ab5a36f3234dd26db357fd4a0dc1"
  }
 },
 {
  "address": "aws_s3_bucket.evidence",
  "values": {
   "arn": "arn:aws:s3:::zasp-product-data-35b9ab5a36f3234dd26db357fd4a0dc1",
   "id": "zasp-product-data-35b9ab5a36f3234dd26db357fd4a0dc1"
  }
 },
 {
  "address": "aws_s3_bucket.red_team_evidence",
  "values": {
   "arn": "arn:aws:s3:::zasp-red-team-evidence-35b9ab5a36f3234dd26db357fd4a0dc1",
   "id": "zasp-red-team-evidence-35b9ab5a36f3234dd26db357fd4a0dc1"
  }
 },
 {
  "address": "aws_s3_bucket.runtime_raw",
  "values": {
   "arn": "arn:aws:s3:::zasp-runtime-raw-35b9ab5a36f3234dd26db357fd4a0dc1",
   "id": "zasp-runtime-raw-35b9ab5a36f3234dd26db357fd4a0dc1"
  }
 },
 {
  "address": "aws_secretsmanager_secret.audit_exports[\"audit-export-cursor-signing-key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/audit-export-cursor-signing-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/audit-export-cursor-signing-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.audit_exports[\"postgres-audit-export-outbox-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-audit-export-outbox-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-audit-export-outbox-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.audit_exports[\"postgres-audit-export-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-audit-export-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-audit-export-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.connector_provider[\"github_app_private_key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/github/app-private-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/github/app-private-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.connector_provider[\"github_client_secret\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/github/client-secret-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/github/client-secret-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.connector_provider[\"okta_client_secret\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/okta/client-secret-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/okta/client-secret-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.connector_reference[\"aws_external_id\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/aws/external-id/customer-0001-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/aws/external-id/customer-0001-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.connector_reference[\"kubernetes_ca\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/ca/customer-0001-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/ca/customer-0001-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.connector_reference[\"kubernetes_connection\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/connection/customer-0001-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/connection/customer-0001-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.connector_reference[\"kubernetes_credential\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/credential/customer-0001-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/kubernetes/credential/customer-0001-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.neo4j_projection_runtime",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/projection/neo4j/auth/runtime-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/projection/neo4j/auth/runtime-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.neo4j_projection_schema",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/projection/neo4j/auth/schema-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/projection/neo4j/auth/schema-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"attack-lab-egress-signing-key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-egress-signing-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-egress-signing-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"attack-lab-proxy-tls-certificate\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-proxy-tls-certificate-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-proxy-tls-certificate-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"attack-lab-proxy-tls-private-key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-proxy-tls-private-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/attack-lab-proxy-tls-private-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"canary-read-token\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/canary-read-token-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/canary-read-token-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"gateway-policy-signing-private-key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/gateway-policy-signing-private-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/gateway-policy-signing-private-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"openrouter-security-agent-api-key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/openrouter-security-agent-api-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/openrouter-security-agent-api-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-api-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-api-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-api-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-attack-lab-controller-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-controller-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-controller-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-attack-lab-outbox-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-outbox-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-outbox-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-attack-lab-proxy-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-proxy-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-attack-lab-proxy-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-gateway-control-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-gateway-control-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-gateway-control-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-migration-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-migration-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-migration-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-outbox-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-outbox-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-outbox-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-policy-deployment-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-policy-deployment-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-policy-deployment-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-projection-graph-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-graph-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-graph-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-projection-risk-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-risk-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-risk-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-projection-search-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-search-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-projection-search-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-recovery-outbox-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-recovery-outbox-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-recovery-outbox-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-recovery-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-recovery-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-recovery-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-red-team-adapter-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-adapter-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-adapter-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-red-team-outbox-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-outbox-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-outbox-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-red-team-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-red-team-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-runtime-archive-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-archive-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-archive-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-runtime-coordinator-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-coordinator-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-coordinator-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-runtime-correlation-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-correlation-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-correlation-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-runtime-gateway-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-gateway-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-gateway-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-runtime-index-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-index-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-index-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-runtime-ingest-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-ingest-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-ingest-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-runtime-projection-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-projection-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-projection-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-runtime-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-runtime-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-scheduler-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-scheduler-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-scheduler-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-security-agent-action-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-action-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-action-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-security-agent-api-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-api-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-api-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-security-agent-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-security-agent-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"postgres-worker-dsn\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-worker-dsn-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/postgres-worker-dsn-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"red-team-adapter-tls-certificate\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-tls-certificate-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-tls-certificate-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"red-team-adapter-tls-private-key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-tls-private-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-tls-private-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"red-team-adapter-token\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-token-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/red-team-adapter-token-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"stytch-organization-id\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-organization-id-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-organization-id-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"stytch-project-id\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-project-id-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-project-id-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"stytch-public-token\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-public-token-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-public-token-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"stytch-secret\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-secret-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-secret-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"stytch-webhook-secret\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-webhook-secret-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/stytch-webhook-secret-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"token-reveal-key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/token-reveal-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/token-reveal-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.product[\"workflow-signing-key\"]",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/workflow-signing-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/workflow-signing-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.recovery_neon_api",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-recovery/neon/project-api-key-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-recovery/neon/project-api-key-mock00"
  }
 },
 {
  "address": "aws_secretsmanager_secret.red_team_readiness_target",
  "values": {
   "arn": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp/red-team/targets/readiness-0001-mock00",
   "id": "arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp/red-team/targets/readiness-0001-mock00"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"attack-lab-jobs\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-attack-lab-jobs-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-attack-lab-jobs-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"audit-exports\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-audit-exports-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-audit-exports-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"background\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-background-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-background-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"discovery-jobs\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-discovery-jobs-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-discovery-jobs-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"recovery-backup-jobs\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-recovery-backup-jobs-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-recovery-backup-jobs-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"recovery-restore-jobs\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-recovery-restore-jobs-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-recovery-restore-jobs-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"red-team-tests\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-red-team-tests-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-red-team-tests-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"runtime-events\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-runtime-events-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-runtime-events-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.dead_letter[\"tests\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-tests-dlq",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-tests-dlq"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"attack-lab-jobs\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-attack-lab-jobs",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-attack-lab-jobs"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"audit-exports\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-audit-exports",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-audit-exports"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"background\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-background",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-background"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"discovery-jobs\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-discovery-jobs",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-discovery-jobs"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"recovery-backup-jobs\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-recovery-backup-jobs",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-recovery-backup-jobs"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"recovery-restore-jobs\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-recovery-restore-jobs",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-recovery-restore-jobs"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"red-team-tests\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-red-team-tests",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-red-team-tests"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"runtime-events\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-runtime-events",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-runtime-events"
  }
 },
 {
  "address": "aws_sqs_queue.work[\"tests\"]",
  "values": {
   "arn": "arn:aws:sqs:us-west-2:000000000000:agentsec-tests",
   "id": "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-tests"
  }
 }
];
const canonical = value => Array.isArray(value) ? value.map(canonical) : object(value) ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const same = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const policyAddress = role => role.replace('aws_iam_role.', 'aws_iam_role_policy.');
const secondaryPolicies = {
 'aws_iam_role_policy.audit_export_secrets["audit-export-cursor-signing-key"]': 'aws_iam_role.api',
 'aws_iam_role_policy.audit_export_secrets["postgres-audit-export-outbox-dsn"]': 'aws_iam_role.audit_exports["publisher"]',
 'aws_iam_role_policy.audit_export_secrets["postgres-audit-export-worker-dsn"]': 'aws_iam_role.audit_exports["writer"]',
};
// Exact original service-account split; API/connectors/audit reader remain different roles.
const workloadSubjects = {
 "aws_iam_role.api": "system:serviceaccount:agentsec:agentsec-api",
 "aws_iam_role.api_connectors": "system:serviceaccount:agentsec:agentsec-api",
 "aws_iam_role.attack_lab[\"controller\"]": "system:serviceaccount:agentsec:zasp-attack-lab-controller",
 "aws_iam_role.attack_lab[\"outbox\"]": "system:serviceaccount:agentsec:zasp-attack-lab-outbox",
 "aws_iam_role.attack_lab[\"proxy\"]": "system:serviceaccount:agentsec:zasp-attack-lab-proxy",
 "aws_iam_role.attack_lab_runner_test": "system:serviceaccount:zasp-attack-lab:agentsec-attack-lab-runner",
 "aws_iam_role.audit_exports[\"publisher\"]": "system:serviceaccount:agentsec:zasp-audit-export-outbox",
 "aws_iam_role.audit_exports[\"reader\"]": "system:serviceaccount:agentsec:agentsec-api",
 "aws_iam_role.audit_exports[\"writer\"]": "system:serviceaccount:agentsec:zasp-audit-export-worker",
 "aws_iam_role.canary_secret_sync": "system:serviceaccount:agentsec:agentsec-canary-secret-sync",
 "aws_iam_role.migration": "system:serviceaccount:agentsec:agentsec-migration",
 "aws_iam_role.outbox": "system:serviceaccount:agentsec:zasp-outbox-publisher",
 "aws_iam_role.policy_deployment_worker": "system:serviceaccount:agentsec:zasp-policy-deployment",
 "aws_iam_role.projection_graph": "system:serviceaccount:agentsec:zasp-projection-graph",
 "aws_iam_role.projection_graph_init": "system:serviceaccount:agentsec:agentsec-projection-graph-init",
 "aws_iam_role.projection_risk": "system:serviceaccount:agentsec:zasp-projection-risk",
 "aws_iam_role.projection_search": "system:serviceaccount:agentsec:zasp-projection-search",
 "aws_iam_role.projection_search_init": "system:serviceaccount:agentsec:agentsec-projection-search-init",
 "aws_iam_role.recovery[\"recovery_backup\"]": "system:serviceaccount:agentsec:zasp-recovery-backup",
 "aws_iam_role.recovery[\"recovery_backup_outbox\"]": "system:serviceaccount:agentsec:zasp-recovery-backup-outbox",
 "aws_iam_role.recovery[\"recovery_restore\"]": "system:serviceaccount:agentsec:zasp-recovery-restore",
 "aws_iam_role.recovery[\"recovery_restore_outbox\"]": "system:serviceaccount:agentsec:zasp-recovery-restore-outbox",
 "aws_iam_role.red_team[\"adapter\"]": "system:serviceaccount:agentsec:zasp-red-team-adapter",
 "aws_iam_role.red_team[\"outbox\"]": "system:serviceaccount:agentsec:zasp-red-team-outbox",
 "aws_iam_role.red_team[\"worker\"]": "system:serviceaccount:agentsec:zasp-red-team-worker",
 "aws_iam_role.runtime[\"archive\"]": "system:serviceaccount:agentsec:zasp-runtime-archive",
 "aws_iam_role.runtime[\"complete\"]": "system:serviceaccount:agentsec:zasp-runtime-complete",
 "aws_iam_role.runtime[\"coordinator\"]": "system:serviceaccount:agentsec:zasp-runtime-coordinator",
 "aws_iam_role.runtime[\"correlation\"]": "system:serviceaccount:agentsec:zasp-runtime-correlation",
 "aws_iam_role.runtime[\"gateway_control\"]": "system:serviceaccount:agentsec:zasp-gateway-control",
 "aws_iam_role.runtime[\"index\"]": "system:serviceaccount:agentsec:zasp-runtime-index",
 "aws_iam_role.runtime[\"ingest\"]": "system:serviceaccount:agentsec:zasp-runtime-ingest",
 "aws_iam_role.runtime[\"outbox\"]": "system:serviceaccount:agentsec:zasp-runtime-outbox",
 "aws_iam_role.runtime[\"projection\"]": "system:serviceaccount:agentsec:zasp-runtime-projection",
 "aws_iam_role.scheduler": "system:serviceaccount:agentsec:zasp-discovery-scheduler",
 "aws_iam_role.security_agent_action_worker": "system:serviceaccount:agentsec:zasp-security-agent-action",
 "aws_iam_role.security_agent_worker": "system:serviceaccount:agentsec:zasp-security-agent",
 "aws_iam_role.worker": "system:serviceaccount:agentsec:zasp-discovery-worker"
};
const infrastructure = ['aws_iam_role.eks_cluster', 'aws_iam_role.eks_nodes', 'aws_iam_role.attack_lab_pod'];
const infrastructureAttachments = {
 'aws_iam_role_policy_attachment.attack_lab_pod': ['aws_iam_role.attack_lab_pod', 'AmazonEKSFargatePodExecutionRolePolicy'],
 'aws_iam_role_policy_attachment.eks_cluster': ['aws_iam_role.eks_cluster', 'AmazonEKSClusterPolicy'],
 'aws_iam_role_policy_attachment.eks_nodes["AmazonEC2ContainerRegistryReadOnly"]': ['aws_iam_role.eks_nodes', 'AmazonEC2ContainerRegistryReadOnly'],
 'aws_iam_role_policy_attachment.eks_nodes["AmazonEKSWorkerNodePolicy"]': ['aws_iam_role.eks_nodes', 'AmazonEKSWorkerNodePolicy'],
 'aws_iam_role_policy_attachment.eks_nodes["AmazonEKS_CNI_Policy"]': ['aws_iam_role.eks_nodes', 'AmazonEKS_CNI_Policy'],
 'aws_iam_role_policy_attachment.eks_vpc_resource_controller': ['aws_iam_role.eks_cluster', 'AmazonEKSVPCResourceController'],
};
const parsePolicy = text => { let value; try { value = strictJSON(text); } catch { fail('policy JSON'); } validatePolicy(value); return value; };

const flagged = v => v === undefined || v === false || v === null ? false : v === true ? true : Array.isArray(v) ? v.some(flagged) : object(v) ? Object.values(v).some(flagged) : true;
export function bindMockPlan(plan) {
 if (!object(plan) || plan.plan_format_version !== '1.2' || plan.provider_format_version !== '1.0' || !same(Object.keys(plan.provider_schemas ?? {}).sort(), ['registry.terraform.io/hashicorp/aws', 'registry.terraform.io/hashicorp/tls'])) fail('mock schema/format');
 const rows = plan.resource_changes;
 if (!Array.isArray(rows) || !same(rows.map(r => r.address).sort(), resourceRoster)) fail('resource roster: extra/missing/duplicate address');
 const resources = new Map();
 for (const row of rows) {
  const data = row.address.startsWith('data.');
  const expectedType = row.address.split('.')[data ? 1 : 0];
  if (row.type !== expectedType || row.mode !== (data ? 'data' : 'managed') || row.provider_name !== `registry.terraform.io/hashicorp/${expectedType.startsWith('aws_') ? 'aws' : 'tls'}`) fail(`resource type/provider ${row.address}`);
  if (row.change?.actions?.length !== 1 || row.change.actions[0] !== (row.mode === 'data' ? 'read' : 'create') || !object(row.change.after)) fail(`mock change ${row.address}`);
  resources.set(row.address, row.change.after);
 }
 const get = address => { if (!resources.has(address)) fail(`unbound resource ${address}`); return resources.get(address); };
 for (const { address, values } of fixtureBindings) {
  const actual = get(address);
  const row = rows.find(r => r.address === address);
  for (const key of Object.keys(values)) if (flagged(row.change.after_unknown?.[key]) || flagged(row.change.after_sensitive?.[key])) fail(`unknown fixture ${address}.${key}`);
  for (const [key, value] of Object.entries(values)) if (!same(actual[key], value)) fail(`fixture identity ${address}.${key}`);
 }
 const arnValues = fixtureBindings.flatMap(r => Object.values(r.values).filter(x => typeof x === 'string' && x.startsWith('arn:')).slice(0, 1));
 if (new Set(arnValues).size !== arnValues.length) fail('colliding resource ARN');
 const ids = [...workloadRoles, ...infrastructure].map(a => get(a).id);
 if (new Set(ids).size !== 41) fail('colliding role ID');
 const unions = new Map(workloadRoles.map(a => [a, []]));
 const expectedInline = new Map([...workloadRoles.map(a => [policyAddress(a), a]), ...Object.entries(secondaryPolicies)]);
 for (const row of rows) {
  const after = row.change.after;
  if (row.type === 'aws_iam_role_policy') {
   const role = expectedInline.get(row.address);
   if (!role || after.role !== get(role).id || typeof after.policy !== 'string' || (flagged(row.change.after_unknown?.policy) || flagged(row.change.after_unknown?.role) || flagged(row.change.after_sensitive?.policy))) fail(`unbound inline policy ${row.address}`);
   unions.get(role).push(parsePolicy(after.policy));
  }
  if (row.type === 'aws_iam_role_policy_attachment') {
   const excluded = infrastructureAttachments[row.address];
   if (!excluded || after.role !== get(excluded[0]).id || after.policy_arn !== `arn:aws:iam::aws:policy/${excluded[1]}`) fail(`unresolved/unapproved managed attachment ${row.address}`);
  }
 }
 const boundaryAddress = 'aws_iam_policy.attack_lab_runner_test_boundary';
 for (const role of workloadRoles) {
  const after = get(role);
  const roleRow = rows.find(r => r.address === role);
  for (const field of ['assume_role_policy', 'inline_policy', 'managed_policy_arns', 'permissions_boundary']) if (flagged(roleRow.change.after_unknown?.[field]) || flagged(roleRow.change.after_sensitive?.[field])) fail(`unknown role authority ${role}.${field}`);
  let trust; try { trust = strictJSON(after.assume_role_policy); } catch { fail(`trust JSON ${role}`); }
  const issuer = 'oidc.eks.us-west-2.amazonaws.com/id/staging-union';
  const expectedTrust = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Federated: `arn:aws:iam::000000000000:oidc-provider/${issuer}` }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { StringEquals: { [`${issuer}:aud`]: 'sts.amazonaws.com', [`${issuer}:sub`]: workloadSubjects[role] } } }] };
  if (!same(trust, expectedTrust)) fail(`OIDC trust identity ${role}`);
  if (!same(after.inline_policy, []) || !same(after.managed_policy_arns, [])) fail(`unlisted embedded policy/attachment ${role}`);
  if (role === 'aws_iam_role.attack_lab_runner_test') {
   if (after.permissions_boundary !== get(boundaryAddress).arn) fail('runner boundary binding');
   const boundaryRow = rows.find(r => r.address === boundaryAddress);
   if (flagged(boundaryRow.change.after_unknown?.policy) || flagged(boundaryRow.change.after_sensitive?.policy)) fail('unknown boundary policy');
   const boundary = parsePolicy(get(boundaryAddress).policy);
   if (!same(boundary, { Statement: [{ Action: '*', Effect: 'Deny', Resource: '*' }], Version: '2012-10-17' })) fail('runner deny-all boundary');
  } else if (after.permissions_boundary !== null) fail(`unreviewed permissions boundary ${role}`);
  if (!unions.get(role).length) fail(`empty union ${role}`);
 }
 return { resources, get, unions };
}

// Normative workload requests originate in the original B04 product contracts, main.tf workload split,
// audit_exports.tf and the existing exact session-search assertions. They do not inspect Allow rows.
function matrix(bound) {
 const { get } = bound;
 const cases = [];
 const role = x => `aws_iam_role.${x}`;
 const arn = x => get(x).arn;
 const productSecret = name => arn(`aws_secretsmanager_secret.product["${name}"]`);
 const key = name => arn(`aws_kms_key.${name}`);
 const queue = name => arn(`aws_sqs_queue.work["${name}"]`);
 const bucket = name => arn(`aws_s3_bucket.${name}`);
 const es = arn('aws_opensearch_domain.events');
 const add = (r, label, expected, action, resource, context = {}) => cases.push({ role: role(r), label, expected, request: { action, resource, context } });
 const allow = (r, label, action, resource, context) => add(r, label, 'allowed', action, resource, context);
 const deny = (r, label, action, resource, context) => add(r, label, 'denied', action, resource, context);
 const contexts = (r, label, action, resource, context) => {
  allow(r, `${label}:valid`, action, resource, context);
  deny(r, `${label}:absent`, action, resource);
  for (const k of Object.keys(context)) {
   const missing = { ...context }; delete missing[k];
   deny(r, `${label}:missing:${k}`, action, resource, missing);
   deny(r, `${label}:wrong:${k}`, action, resource, { ...context, [k]: 'foreign-context' });
  }
  deny(r, `${label}:foreign-key`, action, 'arn:aws:kms:us-west-2:111111111111:key/foreign', context);
 };
 const secret = (r, name, kms = 'staging', constrained = true) => {
  const resource = name.startsWith('aws_') ? arn(name) : productSecret(name);
  allow(r, `own-secret:${name}`, 'secretsmanager:GetSecretValue', resource);
  deny(r, `foreign-secret:${name}`, 'secretsmanager:GetSecretValue', 'arn:aws:secretsmanager:us-west-2:111111111111:secret:foreign');
  contexts(r, `secret-kms:${name}`, 'kms:Decrypt', key(kms), { 'kms:ViaService': 'secretsmanager.us-west-2.amazonaws.com', ...(constrained ? { 'kms:EncryptionContext:SecretARN': resource } : {}) });
 };
 const simpleSecrets = {
  api: ['postgres-api-dsn', 'postgres-security-agent-api-dsn', 'stytch-organization-id', 'stytch-project-id', 'stytch-public-token', 'stytch-secret', 'stytch-webhook-secret', 'token-reveal-key', 'workflow-signing-key'],
  scheduler: ['postgres-scheduler-dsn'], migration: ['postgres-migration-dsn'], canary_secret_sync: ['canary-read-token'],
  worker: ['postgres-worker-dsn'], outbox: ['postgres-outbox-worker-dsn'],
  security_agent_worker: ['postgres-security-agent-worker-dsn', 'openrouter-security-agent-api-key'],
  security_agent_action_worker: ['postgres-security-agent-action-worker-dsn', 'gateway-policy-signing-private-key'],
  policy_deployment_worker: ['postgres-policy-deployment-worker-dsn', 'gateway-policy-signing-private-key'],
  projection_risk: ['postgres-projection-risk-dsn'], projection_graph: ['postgres-projection-graph-dsn', 'aws_secretsmanager_secret.neo4j_projection_runtime'],
  projection_graph_init: ['aws_secretsmanager_secret.neo4j_projection_schema'], projection_search: ['postgres-projection-search-dsn'],
 };
 for (const [r, names] of Object.entries(simpleSecrets)) for (const name of names) secret(r, name, 'staging', !['api', 'scheduler', 'migration', 'canary_secret_sync', 'worker'].includes(r));
 for (const [r, names] of Object.entries({ api: ['audit-export-cursor-signing-key'], 'audit_exports["writer"]': ['postgres-audit-export-worker-dsn'], 'audit_exports["publisher"]': ['postgres-audit-export-outbox-dsn'] })) for (const name of names) secret(r, `aws_secretsmanager_secret.audit_exports["${name}"]`, 'staging', r !== 'api');
 const runtimeDB = { ingest: 'ingest', gateway_control: 'gateway-control', outbox: 'worker', coordinator: 'coordinator', archive: 'archive', index: 'index', correlation: 'correlation', projection: 'projection', complete: 'coordinator' };
 for (const [name, db] of Object.entries(runtimeDB)) secret(`runtime["${name}"]`, name === 'gateway_control' ? 'postgres-gateway-control-dsn' : name === 'outbox' ? 'postgres-outbox-worker-dsn' : `postgres-runtime-${db}-dsn`);
 for (const name of ['correlation', 'projection']) secret(`runtime["${name}"]`, 'aws_secretsmanager_secret.neo4j_projection_runtime');
 const sqs = (r, name, producer, kms) => {
  for (const action of ['sqs:GetQueueAttributes', ...(producer ? ['sqs:SendMessage'] : ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:ChangeMessageVisibility'])]) allow(r, `queue:${name}:${action}`, action, queue(name));
  deny(r, `queue-reversal:${name}`, producer ? 'sqs:ReceiveMessage' : 'sqs:SendMessage', queue(name));
  deny(r, `foreign-queue:${name}`, producer ? 'sqs:SendMessage' : 'sqs:ReceiveMessage', 'arn:aws:sqs:us-west-2:111111111111:foreign');
  for (const action of ['kms:Decrypt', ...(producer ? ['kms:GenerateDataKey'] : [])]) contexts(r, `queue-kms:${name}:${action}`, action, key(kms), { 'kms:ViaService': 'sqs.us-west-2.amazonaws.com', 'kms:EncryptionContext:aws:sqs:arn': queue(name) });
 };
 sqs('outbox', 'discovery-jobs', true, 'staging'); sqs('worker', 'discovery-jobs', false, 'staging');
 sqs('runtime["outbox"]', 'runtime-events', true, 'staging'); sqs('runtime["coordinator"]', 'runtime-events', false, 'staging');
 const objects = (r, b, path, writable, kms, contextPath = path) => {
  const target = `${bucket(b)}/${path}`;
  allow(r, `object-read:${b}`, 's3:GetObject', target);
  add(r, `object-write:${b}`, writable ? 'allowed' : 'denied', 's3:PutObject', target);
  deny(r, `foreign-prefix:${b}`, 's3:GetObject', `${bucket(b)}/foreign/file`);
  deny(r, `foreign-bucket:${b}`, 's3:GetObject', 'arn:aws:s3:::foreign/organizations/example/file');
  for (const action of ['kms:Decrypt', ...(writable ? ['kms:GenerateDataKey'] : [])]) contexts(r, `object-kms:${b}:${action}`, action, key(kms), { 'kms:ViaService': 's3.us-west-2.amazonaws.com', 'kms:EncryptionContext:aws:s3:arn': `${bucket(b)}/${contextPath}` });
 };
 objects('worker', 'evidence', 'organizations/example/file', true, 'staging');
 for (const name of ['ingest', 'archive', 'index', 'correlation', 'projection', 'complete']) objects(`runtime["${name}"]`, 'runtime_raw', 'runtime/v15/example', name !== 'archive', 'runtime_raw');
 for (const name of ['backup', 'restore']) {
  secret(`recovery["recovery_${name}"]`, 'postgres-recovery-worker-dsn'); secret(`recovery["recovery_${name}_outbox"]`, 'postgres-recovery-outbox-worker-dsn');
  sqs(`recovery["recovery_${name}"]`, `recovery-${name}-jobs`, false, 'staging'); sqs(`recovery["recovery_${name}_outbox"]`, `recovery-${name}-jobs`, true, 'staging');
  objects(`recovery["recovery_${name}"]`, 'evidence', 'organizations/example/recovery/file', name === 'backup', 'staging');
  allow(`recovery["recovery_${name}"]`, 'recovery-signing', name === 'backup' ? 'kms:Sign' : 'kms:Verify', key('recovery_signing'));
  deny(`recovery["recovery_${name}"]`, 'recovery-signing-reversal', name === 'backup' ? 'kms:Verify' : 'kms:Sign', key('recovery_signing'));
 }
 secret('recovery["recovery_restore"]', 'aws_secretsmanager_secret.recovery_neon_api');
 for (const [family, consumer, queueName, kms] of [['red_team', 'worker', 'red-team-tests', 'red_team'], ['attack_lab', 'controller', 'attack-lab-jobs', 'attack_lab']]) {
  for (const name of ['outbox', consumer, family === 'red_team' ? 'adapter' : 'proxy']) secret(`${family}["${name}"]`, `postgres-${family.replace('_', '-')}-${name}-dsn`, family === 'attack_lab' ? 'attack_lab' : 'staging');
  sqs(`${family}["outbox"]`, queueName, true, kms); sqs(`${family}["${consumer}"]`, queueName, false, kms);
  objects(`${family}["${consumer}"]`, `${family}_evidence`, 'organizations/example/file', true, kms);
 }
 for (const name of ['reader', 'writer', 'publisher']) {
  const r = `audit_exports["${name}"]`; const prefix = `${bucket('evidence')}/organizations/example/workspaces/example/environments/example/exports/file`;
  for (const action of ['s3:GetObject', 's3:GetObjectVersion']) add(r, `audit:${action}`, name === 'publisher' ? 'denied' : 'allowed', action, prefix);
  deny(r, 'audit:foreign-prefix', 's3:GetObject', `${bucket('evidence')}/organizations/example/private/file`);
  deny(r, 'audit:foreign-bucket', 's3:GetObject', 'arn:aws:s3:::foreign/organizations/example/workspaces/example/environments/example/exports/file');
  if (name === 'writer') contexts(r, 'audit:sse', 's3:PutObject', prefix, { 's3:x-amz-server-side-encryption': 'aws:kms', 's3:x-amz-server-side-encryption-aws-kms-key-id': key('staging') });
  else deny(r, 'audit:no-write', 's3:PutObject', prefix);
  if (name !== 'publisher') for (const action of ['kms:Decrypt', ...(name === 'writer' ? ['kms:GenerateDataKey'] : [])]) contexts(r, `audit:kms:${action}`, action, key('staging'), { 'kms:ViaService': 's3.us-west-2.amazonaws.com', 'kms:EncryptionContext:aws:s3:arn': bucket('evidence') });
  if (name !== 'reader') sqs(r, 'audit-exports', name === 'publisher', 'staging');
  else deny(r, 'audit:no-queue', 'sqs:SendMessage', queue('audit-exports'));
 }
 for (const name of ['github_app_private_key', 'github_client_secret', 'okta_client_secret']) secret('api_connectors', `aws_secretsmanager_secret.connector_provider["${name}"]`, 'connector_oauth');
 for (const name of ['aws_external_id', 'kubernetes_ca', 'kubernetes_connection', 'kubernetes_credential']) secret('api_connectors', `aws_secretsmanager_secret.connector_reference["${name}"]`, 'connector_oauth');
 for (const r of ['api_connectors', 'worker']) {
  allow(r, 'reviewed-customer-assume-role', 'sts:AssumeRole', 'arn:aws:iam::111111111111:role/zasp-reference/customer-0001');
  deny(r, 'foreign-assume-role', 'sts:AssumeRole', 'arn:aws:iam::222222222222:role/foreign');
 }
 const oauth = 'arn:aws:secretsmanager:us-west-2:000000000000:secret:zasp-staging/connectors/oauth/example';
 for (const action of ['secretsmanager:CreateSecret', 'secretsmanager:GetSecretValue', 'secretsmanager:DeleteSecret']) allow('api_connectors', 'connector-oauth-owned', action, oauth);
 contexts('api_connectors', 'connector-oauth-kms', 'kms:GenerateDataKey', key('connector_oauth'), { 'kms:ViaService': 'secretsmanager.us-west-2.amazonaws.com', 'kms:EncryptionContext:SecretARN': oauth });
 for (const index of ['zasp-runtime-sessions-v1', 'zasp-runtime-sessions-v2']) {
  const marker = index.endsWith('v1') ? '_zasp_session_schema_v1' : '_zasp_session_schema_v2';
  for (const r of ['api_connectors', 'runtime["index"]', 'projection_search_init']) for (const path of ['_mapping', `_doc/${marker}`]) allow(r, 'session-schema-read', 'es:ESHttpGet', `${es}/${index}/${path}`);
  allow('api_connectors', 'session-search', 'es:ESHttpPost', `${es}/${index}/_search`);
  deny('runtime["index"]', 'session-index-no-search', 'es:ESHttpPost', `${es}/${index}/_search`);
  for (const path of ['_bulk', '_mget', '_refresh']) {
   allow('runtime["index"]', 'session-index-ingest', 'es:ESHttpPost', `${es}/${index}/${path}`);
   deny('api_connectors', 'session-search-no-ingest', 'es:ESHttpPost', `${es}/${index}/${path}`);
  }
  for (const r of ['api_connectors', 'runtime["index"]']) for (const action of ['es:ESHttpPut', 'es:ESHttpDelete']) deny(r, 'session-no-put-delete', action, `${es}/${index}/_doc/example`);
 }
 for (const action of ['es:ESHttpGet', 'es:ESHttpPost', 'es:ESHttpPut']) allow('runtime["index"]', 'legacy-event-method', action, `${es}/zasp-runtime-events-v1/_doc/example`);
 for (const path of ['_bulk', '_mget', '_search', '_delete_by_query']) allow('projection_search', 'inventory-runtime-post', 'es:ESHttpPost', `${es}/zasp-inventory-v1/${path}`);
 for (const action of ['es:ESHttpGet', 'es:ESHttpPut']) allow('projection_search', 'inventory-active-document', action, `${es}/zasp-inventory-v1/_doc/active_example`);
 deny('projection_search', 'inventory-no-unscoped-doc', 'es:ESHttpPut', `${es}/zasp-inventory-v1/_doc/foreign_example`);
 for (const index of ['zasp-inventory-v1', 'zasp-runtime-events-v1', 'zasp-runtime-sessions-v1', 'zasp-runtime-sessions-v2']) {
  const marker = index.includes('sessions') ? index.endsWith('v1') ? '_zasp_session_schema_v1' : '_zasp_session_schema_v2' : '_zasp_schema_v1';
  allow('projection_search_init', 'schema-index-create', 'es:ESHttpPut', `${es}/${index}`);
  allow('projection_search_init', 'schema-marker-write', 'es:ESHttpPut', `${es}/${index}/_doc/${marker}`);
  deny('projection_search_init', 'schema-no-document-write', 'es:ESHttpPut', `${es}/${index}/_doc/active_example`);
  for (const action of ['es:ESHttpPost', 'es:ESHttpDelete']) deny('projection_search_init', 'schema-no-runtime-method', action, `${es}/${index}/_search`);
 }
 // Every role receives independent unrelated-write requests, including secret-only and deny-all roles.
 for (const fullRole of workloadRoles) {
  const r = fullRole.slice('aws_iam_role.'.length);
  for (const [action, own, foreign] of [
   ['iam:CreateUser', 'arn:aws:iam::000000000000:user/unrelated', 'arn:aws:iam::111111111111:user/unrelated'],
   ['iam:AttachRolePolicy', get(fullRole).arn, 'arn:aws:iam::111111111111:role/foreign'],
   ['s3:DeleteObject', `${bucket('evidence')}/organizations/example/file`, 'arn:aws:s3:::foreign/file'],
   ['s3:DeleteBucket', bucket('evidence'), 'arn:aws:s3:::foreign'],
   ['sqs:PurgeQueue', queue('discovery-jobs'), 'arn:aws:sqs:us-west-2:111111111111:foreign'],
   ['sqs:CreateQueue', queue('discovery-jobs'), 'arn:aws:sqs:us-west-2:111111111111:foreign'],
   ['es:DeleteDomain', es, 'arn:aws:es:us-west-2:111111111111:domain/foreign'],
   ['es:UpdateDomainConfig', es, 'arn:aws:es:us-west-2:111111111111:domain/foreign'],
  ]) for (const resource of [own, foreign]) deny(r, `unrelated:${action}:${resource}`, action, resource);
  for (const b of ['evidence', 'runtime_raw', 'red_team_evidence', 'attack_lab_evidence']) {
   deny(r, `all-buckets:no-delete-object:${b}`, 's3:DeleteObject', `${bucket(b)}/${b === 'runtime_raw' ? 'runtime/v15/example' : 'organizations/example/file'}`);
   deny(r, `all-buckets:no-delete-bucket:${b}`, 's3:DeleteBucket', bucket(b));
  }
  for (const name of ['background', 'discovery-jobs', 'runtime-events', 'red-team-tests', 'attack-lab-jobs', 'recovery-backup-jobs', 'recovery-restore-jobs', 'audit-exports', 'tests']) {
   deny(r, `all-queues:no-purge:${name}`, 'sqs:PurgeQueue', queue(name));
   deny(r, `all-queues:no-create:${name}`, 'sqs:CreateQueue', queue(name));
  }
  if (!['worker', 'runtime["index"]', 'api_connectors', 'projection_search', 'projection_search_init'].includes(r)) deny(r, 'no-unrelated-index-write', 'es:ESHttpPut', `${es}/zasp-runtime-events-v1/_doc/example`);
 }
 for (const r of ['api', 'scheduler', 'migration', 'canary_secret_sync', 'security_agent_worker', 'security_agent_action_worker', 'policy_deployment_worker', 'projection_risk', 'projection_graph', 'projection_graph_init', 'runtime["gateway_control"]', 'red_team["adapter"]', 'attack_lab["proxy"]', 'attack_lab_runner_test']) {
  deny(r, 'secret-only:no-object-put', 's3:PutObject', `${bucket('evidence')}/organizations/example/file`);
  deny(r, 'secret-only:no-queue-send', 'sqs:SendMessage', queue('discovery-jobs'));
  deny(r, 'secret-only:no-queue-consume', 'sqs:ReceiveMessage', queue('discovery-jobs'));
 }
 deny('attack_lab_runner_test', 'runner:no-secret', 'secretsmanager:GetSecretValue', productSecret('postgres-api-dsn'));
 return cases;
}
export function verifyMockPlan(plan) {
 const bound = bindMockPlan(plan);
 const cases = matrix(bound);
 const failures = [];
 for (const row of cases) {
  const actual = evaluateUnion(bound.unions.get(row.role), row.request);
  if (actual !== row.expected) failures.push({ role: row.role, label: row.label, expected: row.expected, actual });
 }
 if (failures.length) fail(`decision matrix ${JSON.stringify(failures.slice(0, 12))}; total=${failures.length}`);
 return { version: 'staging-iam-policy-union-v1', workloadRoles: 38, infrastructureExcluded: 3, inlinePolicies: 41, locallyResolvedBoundaries: 1, workloadManagedAttachments: 0, decisionCases: cases.length, mockSourceOnly: true, cloudAccepted: false, nativeAccepted: false, productionAccepted: false };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
 try {
  if (process.argv.length !== 4 || process.argv[2] !== '--plan') fail('CLI requires --plan complete Terraform JSONL');
  const input = fs.readFileSync(process.argv[3]);
  const text = input.toString('utf8');
  if (!Buffer.from(text).equals(input)) fail('mock non-UTF8 bytes');
  const receipt = verifyMockPlan(parseMockPlan(text));
  console.log(JSON.stringify({ ...receipt, planSHA256: crypto.createHash('sha256').update(input).digest('hex'), planBytes: input.length }));
 } catch (error) { console.error(error.message); process.exitCode = 1; }
}
