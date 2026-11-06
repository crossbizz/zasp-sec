package preflight

import "strings"

// The original closed deployment union contains38IRSA subjects and3service roles.
// Purpose omissions never reduce the compiled required inventory.
var compiledAWSRoleRequirements = [...]awsRoleRequirement{
	{"aws_iam_role.api", "system:serviceaccount:agentsec:agentsec-api", "irsa"},
	{"aws_iam_role.api_connectors", "system:serviceaccount:agentsec:agentsec-api", "irsa"},
	{"aws_iam_role.attack_lab[\"controller\"]", "system:serviceaccount:agentsec:zasp-attack-lab-controller", "irsa"},
	{"aws_iam_role.attack_lab[\"outbox\"]", "system:serviceaccount:agentsec:zasp-attack-lab-outbox", "irsa"},
	{"aws_iam_role.attack_lab[\"proxy\"]", "system:serviceaccount:agentsec:zasp-attack-lab-proxy", "irsa"},
	{"aws_iam_role.attack_lab_runner_test", "system:serviceaccount:zasp-attack-lab:agentsec-attack-lab-runner", "irsa"},
	{"aws_iam_role.audit_exports[\"publisher\"]", "system:serviceaccount:agentsec:zasp-audit-export-outbox", "irsa"},
	{"aws_iam_role.audit_exports[\"reader\"]", "system:serviceaccount:agentsec:agentsec-api", "irsa"},
	{"aws_iam_role.audit_exports[\"writer\"]", "system:serviceaccount:agentsec:zasp-audit-export-worker", "irsa"},
	{"aws_iam_role.canary_secret_sync", "system:serviceaccount:agentsec:agentsec-canary-secret-sync", "irsa"},
	{"aws_iam_role.migration", "system:serviceaccount:agentsec:agentsec-migration", "irsa"},
	{"aws_iam_role.outbox", "system:serviceaccount:agentsec:zasp-outbox-publisher", "irsa"},
	{"aws_iam_role.policy_deployment_worker", "system:serviceaccount:agentsec:zasp-policy-deployment", "irsa"},
	{"aws_iam_role.projection_graph", "system:serviceaccount:agentsec:zasp-projection-graph", "irsa"},
	{"aws_iam_role.projection_graph_init", "system:serviceaccount:agentsec:agentsec-projection-graph-init", "irsa"},
	{"aws_iam_role.projection_risk", "system:serviceaccount:agentsec:zasp-projection-risk", "irsa"},
	{"aws_iam_role.projection_search", "system:serviceaccount:agentsec:zasp-projection-search", "irsa"},
	{"aws_iam_role.projection_search_init", "system:serviceaccount:agentsec:agentsec-projection-search-init", "irsa"},
	{"aws_iam_role.recovery[\"recovery_backup\"]", "system:serviceaccount:agentsec:zasp-recovery-backup", "irsa"},
	{"aws_iam_role.recovery[\"recovery_backup_outbox\"]", "system:serviceaccount:agentsec:zasp-recovery-backup-outbox", "irsa"},
	{"aws_iam_role.recovery[\"recovery_restore\"]", "system:serviceaccount:agentsec:zasp-recovery-restore", "irsa"},
	{"aws_iam_role.recovery[\"recovery_restore_outbox\"]", "system:serviceaccount:agentsec:zasp-recovery-restore-outbox", "irsa"},
	{"aws_iam_role.red_team[\"adapter\"]", "system:serviceaccount:agentsec:zasp-red-team-adapter", "irsa"},
	{"aws_iam_role.red_team[\"outbox\"]", "system:serviceaccount:agentsec:zasp-red-team-outbox", "irsa"},
	{"aws_iam_role.red_team[\"worker\"]", "system:serviceaccount:agentsec:zasp-red-team-worker", "irsa"},
	{"aws_iam_role.runtime[\"archive\"]", "system:serviceaccount:agentsec:zasp-runtime-archive", "irsa"},
	{"aws_iam_role.runtime[\"complete\"]", "system:serviceaccount:agentsec:zasp-runtime-complete", "irsa"},
	{"aws_iam_role.runtime[\"coordinator\"]", "system:serviceaccount:agentsec:zasp-runtime-coordinator", "irsa"},
	{"aws_iam_role.runtime[\"correlation\"]", "system:serviceaccount:agentsec:zasp-runtime-correlation", "irsa"},
	{"aws_iam_role.runtime[\"gateway_control\"]", "system:serviceaccount:agentsec:zasp-gateway-control", "irsa"},
	{"aws_iam_role.runtime[\"index\"]", "system:serviceaccount:agentsec:zasp-runtime-index", "irsa"},
	{"aws_iam_role.runtime[\"ingest\"]", "system:serviceaccount:agentsec:zasp-runtime-ingest", "irsa"},
	{"aws_iam_role.runtime[\"outbox\"]", "system:serviceaccount:agentsec:zasp-runtime-outbox", "irsa"},
	{"aws_iam_role.runtime[\"projection\"]", "system:serviceaccount:agentsec:zasp-runtime-projection", "irsa"},
	{"aws_iam_role.scheduler", "system:serviceaccount:agentsec:zasp-discovery-scheduler", "irsa"},
	{"aws_iam_role.security_agent_action_worker", "system:serviceaccount:agentsec:zasp-security-agent-action", "irsa"},
	{"aws_iam_role.security_agent_worker", "system:serviceaccount:agentsec:zasp-security-agent", "irsa"},
	{"aws_iam_role.worker", "system:serviceaccount:agentsec:zasp-discovery-worker", "irsa"},
	{"aws_iam_role.eks_cluster", "", "eks"},
	{"aws_iam_role.eks_nodes", "", "ec2"},
	{"aws_iam_role.attack_lab_pod", "", "fargate"},
}

func requiredAWSRoleInventory(attackLab bool) []awsRoleRequirement {
	out := make([]awsRoleRequirement, 0, len(compiledAWSRoleRequirements))
	for _, role := range compiledAWSRoleRequirements {
		if !attackLab && (strings.HasPrefix(role.purpose, "aws_iam_role.attack_lab[") || role.purpose == "aws_iam_role.attack_lab_runner_test" || role.purpose == "aws_iam_role.attack_lab_pod") {
			continue
		}
		out = append(out, role)
	}
	return out
}
