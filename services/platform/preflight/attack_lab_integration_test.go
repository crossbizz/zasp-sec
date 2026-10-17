package preflight

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func attackLabIntegrationConfig(t *testing.T) Config {
	t.Helper()
	base := sdkContractConfig(t)
	authority, _, _ := awsAuthorityFixtureConfig(t)
	base.AWSAuthority = authority
	target := attackLabTopologyTarget()
	target.RunnerBoundaryPolicyARN = "arn:aws:iam::123456789012:policy/zasp-production-attack-lab-runner-test-boundary"
	target.ProxyCASHA256 = strings.Repeat("1", 64)
	authority.Fargate = target
	for i := range authority.Roles {
		switch authority.Roles[i].Purpose {
		case "aws_iam_role.attack_lab_pod":
			authority.Roles[i].RoleARN = "arn:aws:iam::123456789012:role/zasp-production-attack-lab-pod"
		case "aws_iam_role.attack_lab_runner_test":
			authority.Roles[i].RoleARN = "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test"
		}
	}
	base.Credentials.Kind = "operator_file"
	base.Credentials.File = filepath.Join(t.TempDir(), "missing-private-file.json")
	return base
}
func TestAttackLabMountedConfigurationAndNeverAttemptedTruthfulness(t *testing.T) {
	for _, mode := range []string{"enabled-missing-kubernetes", "disabled", "missing-addon-build", "duplicate-subnet", "foreign-boundary", "wide-target-cidr", "unknown-endpoint-purpose"} {
		t.Run(mode, func(t *testing.T) {
			config := attackLabIntegrationConfig(t)
			target := config.AWSAuthority.Fargate
			switch mode {
			case "disabled":
				config.Features.AttackLab = "disabled"
				known := map[string]bool{}
				for _, v := range requiredAWSRoleInventory(false) {
					known[v.purpose] = true
				}
				roles := []AWSRoleBinding{}
				for _, v := range config.AWSAuthority.Roles {
					if known[v.Purpose] {
						roles = append(roles, v)
					}
				}
				config.AWSAuthority.Roles = roles
			case "missing-addon-build":
				target.ExpectedCNIAddonVersion = ""
			case "duplicate-subnet":
				target.SubnetIDs[1] = target.SubnetIDs[0]
			case "foreign-boundary":
				target.RunnerBoundaryPolicyARN = "arn:aws:iam::999999999999:policy/foreign"
			case "wide-target-cidr":
				target.TargetCIDRs = []string{"0.0.0.0/0"}
			case "unknown-endpoint-purpose":
				target.EndpointIDs["arbitrary"] = target.EndpointIDs["sts"]
				delete(target.EndpointIDs, "sts")
			}
			raw, _ := json.Marshal(config)
			parsed, e := DecodeConfig(raw)
			if mode != "enabled-missing-kubernetes" && mode != "disabled" {
				if e == nil {
					t.Fatal("unbound Fargate target config accepted")
				}
				return
			}
			if e != nil {
				t.Fatal("valid intended config rejected before authority observation")
			}
			r, e := NewRunner(parsed)
			if e != nil {
				t.Fatal("valid config not mounted")
			}
			defer r.Close()
			tr := &attackLabNoProviderTransport{}
			r.http = &http.Client{Transport: tr}
			report, e := r.Run(context.Background(), "before-install")
			if e == nil || tr.calls != 0 || len(report.Checks) != 8 || report.Ready || report.ProductionEndToEndVerified {
				t.Fatal("local authority failure caused provider I/O, lost original roster or became readiness")
			}
			summary := report.AttackLabConfiguration
			if summary == nil {
				t.Fatal("mounted feature config missing original prerequisite report")
			}
			expected := "unobserved"
			if mode == "disabled" {
				expected = "disabled"
			}
			for _, observation := range []Observation{summary.Profile, summary.Namespace, summary.RunnerIdentity, summary.SecurityGroupPolicies, summary.TopologyMetadata} {
				if observation.Status != expected || observation.ObservedAt != nil {
					t.Fatal("never-invoked provider read became observation")
				}
			}
			if summary.NetworkEnforcement != expected || summary.CanaryAndCleanup != expected {
				t.Fatal("configuration became actual packet/canary/cleanup proof")
			}
		})
	}
}

type attackLabNoProviderTransport struct{ calls int }

func (t *attackLabNoProviderTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, ErrRejected
}

func TestAttackLabSameInspectorCaptureSurvivesInspectionAndReleases(t *testing.T) {
	authority, k, tr := awsAuthorityFixtureConfig(t)
	authority.Fargate = attackLabTopologyTarget()
	base := sdkContractConfig(t)
	r := &Runner{config: base, http: &http.Client{Transport: tr}}
	report := initialReport(base, "installed")
	evidence := r.inspectAWSAuthority(context.Background(), &report, authority, k)
	if evidence.inspectionSDK == nil || evidence.inspectionRelease == nil || !evidence.clusterVerified {
		t.Fatal("same verified inspector SDK lifetime not preserved")
	}
	defer evidence.inspectionRelease()
	selected := authority.Roles[0].RoleARN
	name := selected[strings.LastIndex(selected, "/")+1:]
	api := iam.NewFromConfig(*evidence.inspectionSDK)
	out, e := api.GetRole(context.Background(), &iam.GetRoleInput{RoleName: aws.String(name)})
	if e != nil || out == nil || out.Role == nil || aws.ToString(out.Role.Arn) != selected {
		t.Fatal("post-inspection signed read lost its captured credentials")
	}
	identities := 0
	for _, op := range tr.calls {
		if op == "GetCallerIdentity" {
			identities++
		}
	}
	if identities != 1 {
		t.Fatal("capture repeated inspector identity or silently fell back")
	}
	evidence.inspectionRelease()
	before := len(tr.calls)
	_, e = api.GetRole(context.Background(), &iam.GetRoleInput{RoleName: aws.String(name)})
	if e == nil || len(tr.calls) != before {
		t.Fatal("released inspector credentials reloaded or reached provider")
	}
}
