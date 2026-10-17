package preflight

import (
	"context"
	"time"
)

func attackLabObservation(name, code, identity string, target any, passed, attempted bool) Observation {
	o := Observation{Name: name, Status: "unobserved", Kind: "unobserved", Code: code, IdentityKind: "none", TargetDigest: singleTargetDigest(target)}
	if attempted {
		o.Status = "fail"
		o.Kind = "provider-read"
		o.IdentityKind = identity
		now := time.Now().UTC()
		o.ObservedAt = &now
		if passed {
			o.Status = "pass"
			o.Code = "observed_configuration_prerequisites"
		}
	}
	return o
}
func (r *Runner) observeAttackLabConfiguration(ctx context.Context, report *Report, authority *awsAuthorityEvidence, k KubernetesIdentityReader) {
	summary := &AttackLabConfigurationSummary{NetworkEnforcement: "unobserved", CanaryAndCleanup: "unobserved"}
	report.AttackLabConfiguration = summary
	summary.Profile = attackLabObservation("fargate_profile", "attack_lab_authority_or_configuration_required", "operator", nil, false, false)
	summary.Namespace = attackLabObservation("attack_lab_namespace", "attack_lab_authority_or_configuration_required", "operator-kubernetes", "zasp-attack-lab", false, false)
	summary.RunnerIdentity = attackLabObservation("runner_identity", "attack_lab_authority_or_configuration_required", "operator", nil, false, false)
	summary.SecurityGroupPolicies = attackLabObservation("security_group_policies", "attack_lab_authority_or_configuration_required", "operator-kubernetes", nil, false, false)
	summary.TopologyMetadata = attackLabObservation("topology_metadata", "attack_lab_authority_or_configuration_required", "operator", nil, false, false)
	if r.config.Features.AttackLab == "disabled" {
		for _, o := range []*Observation{&summary.Profile, &summary.Namespace, &summary.RunnerIdentity, &summary.SecurityGroupPolicies, &summary.TopologyMetadata} {
			o.Status = "disabled"
			o.Kind = "disabled"
			o.Code = "feature_disabled"
		}
		summary.NetworkEnforcement = "disabled"
		summary.CanaryAndCleanup = "disabled"
		return
	}
	defer func() {
		for i := range report.Checks {
			for j := range report.Checks[i].Observations {
				o := &report.Checks[i].Observations[j]
				switch o.Name {
				case "fargate_profile":
					*o = summary.Profile
				case "attack_lab_namespace":
					*o = summary.Namespace
				case "private_networking":
					o.Status = "unobserved"
					o.Kind = "unobserved"
					o.Code = "network_enforcement_not_observed"
					o.ObservedAt = nil
					o.IdentityKind = "none"
				}
			}
		}
	}()
	c := r.config.AWSAuthority
	reader, ok := k.(*awsKubernetesIdentityReader)
	if c == nil || c.Fargate == nil || authority == nil || !authority.clusterVerified || authority.inspectionSDK == nil || !ok || reader == nil || ctx == nil || ctx.Err() != nil {
		return
	}
	t := c.Fargate
	sdk := *authority.inspectionSDK
	profile := r.observeAttackLabProfile(ctx, sdk, c, t, true)
	identity := r.observeAttackLabIsolationIdentity(ctx, sdk, c, t, true)
	objects := r.observeAttackLabKubernetes(ctx, reader, c, t, true)
	topology := r.observeAttackLabTopology(ctx, sdk, c, t, authority.clusterSecurityGroupID, true)
	kubeIdentity := "operator-kubernetes"
	if r.config.Kubernetes != nil && r.config.Kubernetes.Credentials.Kind == "existing_service_account" {
		kubeIdentity = "workload-kubernetes"
	}
	summary.Profile = attackLabObservation("fargate_profile", "attack_lab_profile_or_addon_unavailable", "operator", t.ProfileARN, profile.profile, profile.profileAttempted)
	summary.Profile.Failures = profile.failures
	summary.Namespace = attackLabObservation("attack_lab_namespace", "attack_lab_namespace_unavailable", kubeIdentity, "zasp-attack-lab", objects.namespace, objects.namespaceAttempted)
	role := ""
	for _, v := range c.Roles {
		if v.Purpose == "aws_iam_role.attack_lab_runner_test" {
			role = v.RoleARN
		}
	}
	summary.RunnerIdentity = attackLabObservation("runner_identity", "attack_lab_runner_isolation_unavailable", "operator", role, identity.runner, identity.runnerAttempted)
	summary.SecurityGroupPolicies = attackLabObservation("security_group_policies", "attack_lab_kubernetes_prerequisites_unavailable", kubeIdentity, t.RunnerSecurityGroupID, objects.policy, objects.policyAttempted)
	summary.TopologyMetadata = attackLabObservation("topology_metadata", "attack_lab_topology_unavailable", "operator", c.Cluster.VPCID, topology.topology, topology.topologyAttempted)
	summary.TopologyMetadata.Failures = topology.failures
	summary.RunnerIdentity.Failures = identity.failures
	summary.SecurityGroupPolicies.Failures = objects.failures
	if !objects.namespace && objects.namespaceAttempted {
		summary.Namespace.Failures = objects.failures
	}

}
