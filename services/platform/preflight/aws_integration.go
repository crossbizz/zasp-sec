package preflight

import "context"

// Inspector clients use only separately selected explicit operator credentials.
// Kubernetes trust is the same independently configured authority as the sensor,
// bound here to the selected EKS endpoint, CA digest and cluster UID.
func (r *Runner) openAWSIdentityReader() (KubernetesIdentityReader, func()) {
	c, k := r.config.AWSAuthority, r.config.Kubernetes
	if c == nil || !validKubernetesAuthority(k) || k.ClusterUID != c.Cluster.ClusterUID || k.Endpoint != c.Cluster.Endpoint {
		return nil, func() {}
	}
	ca, err := readKubernetesCA(k)
	if err != nil {
		return nil, func() {}
	}
	defer clear(ca)
	reader, err := newAWSKubernetesIdentityReader(k.Endpoint, ca, func(ctx context.Context) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ErrRejected
		}
		return readKubernetesToken(k)
	}, c, requiredAWSRoleInventory(r.config.Features.AttackLab == "enabled"))
	if err != nil {
		return nil, func() {}
	}
	return reader, reader.Close
}
func (r *Runner) finishAWSAuthority(report *Report, e *awsAuthorityEvidence) {
	if r.config.AWSAuthority == nil || e == nil {
		return
	}
	report.AWSAuthority = &AWSAuthoritySummary{RequiredRoles: e.requiredRoles, ObservedRoles: e.observedRoles, RequiredTrust: e.requiredTrust, ObservedTrust: e.observedTrust, SelectedServiceAccountExchange: e.selectedExchangeVerified, SelectedDeployedSpec: e.selectedSpecVerified}
	// A's selected GetCallerIdentity is necessary but cannot overwrite a missing
	// original role catalog. This final merge only reduces a selected-role pass.
	if e.observedRoles != e.requiredRoles {
		if e.inspectionAttempted {
			r.record(report, "iam_role", false, "required_role_inventory_incomplete", "operator", r.config.AWSAuthority.Roles, true)
		} else {
			for i := range report.Checks {
				for j := range report.Checks[i].Observations {
					o := &report.Checks[i].Observations[j]
					if o.Name == "iam_role" && o.Status != "fail" {
						o.Status = "unobserved"
						o.Kind = "unobserved"
						o.Code = "required_role_inventory_unobserved"
						o.IdentityKind = "none"
						o.ObservedAt = nil
					}
				}
			}
		}
	}
}
