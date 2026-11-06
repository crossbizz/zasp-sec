package preflight

var roster = []struct {
	name, hint string
	names      []string
}{
	{"iam_irsa", "verify exact role identity, trust and actual Kubernetes workload binding", []string{"iam_role", "irsa_trust", "irsa_binding"}},
	{"s3_kms_secrets", "configure exact versioned encrypted buckets, KMS keys and secret references", []string{"s3_evidence", "kms", "secrets"}},
	{"sqs", "configure exact queue/DLQ pairs and verify scoped producer/consumer actions", []string{"queues", "dead_letter_queue", "queue_permissions"}},
	{"opensearch", "verify private endpoint and required index operations with the selected workload", []string{"opensearch_reachable", "opensearch_index_access"}},
	{"eks_fargate", "verify supported EKS, Attack Lab Fargate selector and private networking", []string{"eks_version_supported", "fargate_profile", "attack_lab_namespace", "private_networking"}},
	{"neon", "verify supported migrations, principal and pooled database access", []string{"neon_migration_compatible", "neon_pool_reachable"}},
	{"stytch", "verify intended Stytch project and nonrenewing session observation", []string{"stytch_project_reachable", "stytch_session_reachable"}},
	{"sensor", "verify the selected EC2 node kernel, BTF and Tetragon report", []string{"kernel_supported", "btf_present", "tetragon_supported"}},
}

func initialReport(c Config, mode string) Report {
	report := Report{Schema: "agentsec-preflight-report-v1", Mode: mode, Source: "live-probes", Checks: make([]Check, 0, len(roster))}
	for _, r := range roster {
		required := r.name != "eks_fargate" && r.name != "sensor" || r.name == "eks_fargate" && c.Features.AttackLab == "enabled" || r.name == "sensor" && c.Features.SensorMode == "required"
		check := Check{Name: r.name, Status: "fail", Required: required, Hint: r.hint, Observations: make([]Observation, 0, len(r.names))}
		disabled := r.name == "eks_fargate" && c.Features.AttackLab == "disabled" || r.name == "sensor" && c.Features.SensorMode == "disabled"
		for _, name := range r.names {
			o := Observation{Name: name, Status: "unobserved", Kind: "unobserved", Code: "probe_unavailable", IdentityKind: "none"}
			if disabled {
				o.Status = "disabled"
				o.Kind = "disabled"
				o.Code = "feature_disabled"
			}
			check.Observations = append(check.Observations, o)
		}
		if disabled {
			check.Status = "warn"
		}
		if r.name == "sqs" && c.SQSPermissions != nil {
			check.PermissionDiagnostic = &SQSPermissionDiagnostic{Observation: Observation{Name: "sqs_identity_policy_simulation", Status: "unobserved", Kind: "unobserved", Code: "verified_authority_unavailable", IdentityKind: "none"}}
		}
		report.Checks = append(report.Checks, check)
	}
	return report
}
func finishReport(report *Report) {
	for i := range report.Checks {
		c := &report.Checks[i]
		passed := true
		disabled := true
		for _, o := range c.Observations {
			passed = passed && o.Status == "pass"
			disabled = disabled && o.Status == "disabled"
		}
		if passed {
			c.Status = "pass"
		} else if disabled || !c.Required {
			c.Status = "warn"
		} else {
			c.Status = "fail"
		}
	}
}
