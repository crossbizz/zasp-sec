package preflight

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSameExchangeServiceAccountProofAndSeparatePodSpec(t *testing.T) {
	for _, mode := range []string{"observed", "wrong-subject", "wrong-audience", "wrong-issuer", "missing-subject", "short-expiry", "wrong-pod-spec", "aux-api-role", "partial-inventory"} {
		t.Run(mode, func(t *testing.T) {
			config, k, tr := awsAuthorityFixtureConfig(t)
			tr.mode = mode
			k.mode = mode
			purpose := "aws_iam_role.runtime[\"index\"]"
			sa := "zasp-runtime-index"
			if mode == "aux-api-role" {
				purpose = "aws_iam_role.api_connectors"
				sa = "agentsec-api"
			}
			config.Selected = &AWSSelectedWorkload{Purpose: purpose, PodName: "preflight-pod", PodUID: "33333333-3333-4333-8333-333333333333"}
			base := sdkContractConfig(t)
			base.Credentials = CredentialConfig{Kind: "workload_web_identity", ExpectedRoleARN: k.bindings[purpose], TokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", Namespace: "agentsec", ServiceAccount: sa}
			if mode == "partial-inventory" {
				for _, role := range config.Roles {
					if role.Purpose == purpose {
						config.Roles = []AWSRoleBinding{role}
						break
					}
				}
			}
			r := &Runner{config: base, http: &http.Client{Transport: tr}}
			report := initialReport(base, "installed")
			evidence := r.inspectAWSAuthority(context.Background(), &report, config, k)
			// This opaque synthetic token is deliberately not decoded for its claims.
			// Only the actual signed STS service-output subject/audience/issuer may bind.
			token := []byte(strings.Repeat("untrusted_token_claims_", 4))
			credentials, proof, e := r.exchangeAWSWebIdentity(context.Background(), base.Credentials.ExpectedRoleARN, token)
			clear(token)
			exchanges := 0
			for _, call := range tr.calls {
				if call == "AssumeRoleWithWebIdentity" {
					exchanges++
				}
			}
			if exchanges != 1 || tr.forbidden {
				t.Fatal("exchange absent, duplicated or used forbidden provider action")
			}
			if mode == "short-expiry" {
				if e == nil || proof != nil {
					t.Fatal("short-lived credential result became proof")
				}
				return
			}
			if e != nil || !credentials.HasKeys() {
				t.Fatal("original valid temporary credentials lost")
			}
			if mode == "missing-subject" {
				if proof != nil {
					t.Fatal("missing signed subject minted workload proof")
				}
				return
			}
			if proof == nil {
				t.Fatal("same successful exchange metadata was discarded")
			}
			r.observeSelectedAWSBinding(context.Background(), &report, config, evidence, proof, k)
			if mode == "observed" || mode == "aux-api-role" {
				if !evidence.selectedExchangeVerified || !evidence.selectedSpecVerified {
					t.Fatal("selected service-account exchange or separate deployed spec not bound")
				}
			} else if mode == "partial-inventory" {
				if report.Checks[0].Observations[2].Status == "pass" {
					t.Fatal("one supplied role became complete required inventory")
				}
			} else if evidence.selectedExchangeVerified && evidence.selectedSpecVerified {
				t.Fatal("mismatched signed facts or deployed spec accepted")
			}
			raw, _ := json.Marshal(report)
			for _, forbidden := range []string{"fixture-workload-secret", "fixture-workload-session", "system:serviceaccount:", "untrusted_token_claims"} {
				if strings.Contains(string(raw), forbidden) {
					t.Fatal("secret or private exchange claims leaked")
				}
			}
			if report.ProductionEndToEndVerified || report.Ready {
				t.Fatal("service-account proof became launch or Pod-token revocation proof")
			}
		})
	}
}
