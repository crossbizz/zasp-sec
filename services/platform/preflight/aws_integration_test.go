package preflight

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAWSAuthorityConfigAndInventoryCannotBeReplacedBySelectedRole(t *testing.T) {
	for _, mode := range []string{"configured-missing-kubernetes", "wrong-private-inspector", "duplicate-purpose", "legacy-unconfigured"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _ := awsAuthorityFixtureConfig(t)
			base := sdkContractConfig(t)
			// The live Runner must preserve the original API when this optional
			// authority is absent, and must reject malformed new authority explicitly.
			raw, _ := encodeAWSAuthorityConfigForTest(base, c, mode)
			parsed, e := DecodeConfig(raw)
			if mode == "legacy-unconfigured" {
				if e != nil {
					t.Fatal("legacy explicit config rejected")
				}
				return
			}
			if mode == "configured-missing-kubernetes" {
				if e != nil {
					t.Fatal("missing Kubernetes observation became config failure")
				}
				r, e := NewRunner(parsed)
				if e != nil {
					t.Fatal("valid authority configuration not accepted")
				}
				defer r.Close()
				// No network: fail selected credentials first using an empty local provider;
				// missing Kubernetes authority must remain unknown, never an inventory pass.
				r.http = &http.Client{Transport: awsNeverNetworkTransport{}}
				report, _ := r.Run(context.Background(), "before-install")
				if report.AWSAuthority == nil || report.AWSAuthority.RequiredRoles != 41 || report.AWSAuthority.ObservedRoles != 0 || report.Checks[0].Observations[0].Status == "pass" {
					t.Fatal("missing cluster authority became full role coverage")
				}
			} else if e == nil {
				t.Fatal("malformed explicit authority accepted")
			}
		})
	}
}

func encodeAWSAuthorityConfigForTest(base Config, c *AWSAuthorityConfig, mode string) ([]byte, error) {
	base.AWSAuthority = c
	switch mode {
	case "legacy-unconfigured":
		base.AWSAuthority = nil
	case "wrong-private-inspector":
		c.Inspection.Kind = "workload_web_identity"
	case "duplicate-purpose":
		c.Roles = append(c.Roles, c.Roles[0])
	}
	return json.Marshal(base)
}

type awsNeverNetworkTransport struct{}

func (awsNeverNetworkTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, ErrRejected
}

func TestAWSAuthorityFinalMergePreservesActualFailures(t *testing.T) {
	for _, mode := range []string{"selected-sts-failure", "credentials-failure", "selected-pass", "not-attempted"} {
		t.Run(mode, func(t *testing.T) {
			authority, _, _ := awsAuthorityFixtureConfig(t)
			base := sdkContractConfig(t)
			base.AWSAuthority = authority
			r := &Runner{config: base}
			report := initialReport(base, "installed")
			switch mode {
			case "selected-sts-failure":
				r.record(&report, "iam_role", false, "identity_mismatch_or_unavailable", "workload", base.Credentials.ExpectedRoleARN, true)
			case "credentials-failure":
				r.record(&report, "iam_role", false, "credentials_unavailable", "none", base.Credentials.ExpectedRoleARN, false)
			case "selected-pass":
				r.record(&report, "iam_role", true, "", "workload", base.Credentials.ExpectedRoleARN, true)
			}
			before := report.Checks[0].Observations[0]
			r.finishAWSAuthority(&report, &awsAuthorityEvidence{requiredRoles: 41, requiredTrust: 38})
			after := report.Checks[0].Observations[0]
			if mode == "selected-sts-failure" || mode == "credentials-failure" {
				if after.Status != "fail" || after.Code != before.Code || after.ObservedAt != before.ObservedAt || after.Kind != before.Kind {
					t.Fatal("known selected failure hidden by missing inspector observation")
				}
			} else if after.Status != "unobserved" || after.Kind != "unobserved" || after.ObservedAt != nil {
				t.Fatal("absent original inventory became observed authority")
			}
		})
	}
}

func TestAWSAuthorityKubernetesFailuresNameActualReadOperation(t *testing.T) {
	for _, mode := range []string{"wrong-kube-cluster", "wrong-sa-annotation", "wrong-pod-spec"} {
		t.Run(mode, func(t *testing.T) {
			c, k, tr := awsAuthorityFixtureConfig(t)
			tr.mode = mode
			k.mode = mode
			base := sdkContractConfig(t)
			purpose := `aws_iam_role.runtime["index"]`
			c.Selected = &AWSSelectedWorkload{Purpose: purpose, PodName: "preflight-pod", PodUID: "33333333-3333-4333-8333-333333333333"}
			base.Credentials = CredentialConfig{Kind: "workload_web_identity", ExpectedRoleARN: k.bindings[purpose], Namespace: "agentsec", ServiceAccount: "zasp-runtime-index"}
			r := &Runner{config: base, http: &http.Client{Transport: tr}}
			report := initialReport(base, "installed")
			evidence := r.inspectAWSAuthority(context.Background(), &report, c, k)
			if mode == "wrong-pod-spec" {
				_, proof, e := r.exchangeAWSWebIdentity(context.Background(), base.Credentials.ExpectedRoleARN, []byte(strings.Repeat("opaque_", 16)))
				if e != nil {
					t.Fatal("fixture exchange absent")
				}
				r.observeSelectedAWSBinding(context.Background(), &report, c, evidence, proof, k)
			}
			expected := "kubernetes:GetServiceAccount"
			if mode == "wrong-kube-cluster" {
				expected = "kubernetes:GetNamespace"
			}
			if mode == "wrong-pod-spec" {
				expected = "kubernetes:GetPod"
			}
			found := false
			for _, check := range report.Checks {
				for _, o := range check.Observations {
					for _, f := range o.Failures {
						found = found || f.Operation == expected
						if f.Operation == "iam:GetRole" {
							t.Fatal("successful IAM read blamed for Kubernetes mismatch")
						}
					}
				}
			}
			if !found {
				t.Fatal("actual fixed Kubernetes read missing from actionable failure")
			}
		})
	}
}
