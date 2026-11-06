package preflight

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type attackLabSDKTransport struct {
	mode      string
	calls     []string
	forbidden bool
	authority *AWSAuthorityConfig
	target    *AWSAttackLabTarget
}

func (tr *attackLabSDKTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	operation := ""
	var answer any
	switch req.URL.Path {
	case "/clusters/preflight/fargate-profiles/attack-lab":
		operation = "eks:DescribeFargateProfile"
		profile := map[string]any{"clusterName": "preflight", "fargateProfileName": "attack-lab", "fargateProfileArn": tr.target.ProfileARN, "podExecutionRoleArn": "arn:aws:iam::123456789012:role/zasp-production-attack-lab-pod", "status": "ACTIVE", "subnets": []string{"subnet-11111111111111111", "subnet-22222222222222222"}, "selectors": []any{map[string]any{"namespace": "zasp-attack-lab", "labels": map[string]string{"zasp.io/execution": "attack-lab"}}}, "health": map[string]any{"issues": []any{}}}
		switch tr.mode {
		case "wrong-profile-name":
			profile["fargateProfileName"] = "foreign"
		case "wrong-profile-arn":
			profile["fargateProfileArn"] = "arn:aws:eks:us-west-2:999999999999:fargateprofile/preflight/attack-lab/foreign"
		case "wrong-cluster":
			profile["clusterName"] = "foreign"
		case "wrong-execution-role":
			profile["podExecutionRoleArn"] = "arn:aws:iam::123456789012:role/product-worker"
		case "wrong-subnets":
			profile["subnets"] = []string{"subnet-11111111111111111"}
		case "selector-widening":
			profile["selectors"] = []any{map[string]any{"namespace": "zasp-attack-lab"}}
		case "extra-selector":
			profile["selectors"] = []any{map[string]any{"namespace": "zasp-attack-lab", "labels": map[string]string{"zasp.io/execution": "attack-lab"}}, map[string]any{"namespace": "agentsec"}}
		case "not-active":
			profile["status"] = "CREATING"
		case "unhealthy":
			profile["health"] = map[string]any{"issues": []any{map[string]string{"code": "PodExecutionRoleAlreadyInUse", "message": "NEVER_REFLECT_PROVIDER_TEXT"}}}
		}
		answer = map[string]any{"fargateProfile": profile}
	case "/clusters/preflight/addons/vpc-cni":
		operation = "eks:DescribeAddon"
		config := `{"env":{"ENABLE_POD_ENI":"true","POD_SECURITY_GROUP_ENFORCING_MODE":"strict"}}`
		version := tr.target.ExpectedCNIAddonVersion
		if tr.mode == "wrong-cni-build" {
			version = "v1.0.0-eksbuild.1"
		}
		if tr.mode == "cni-not-strict" {
			config = `{"env":{"ENABLE_POD_ENI":"true","POD_SECURITY_GROUP_ENFORCING_MODE":"standard"}}`
		}
		answer = map[string]any{"addon": map[string]any{"addonName": "vpc-cni", "clusterName": "preflight", "addonArn": "arn:aws:eks:us-west-2:123456789012:addon/preflight/vpc-cni/11111111-1111-4111-8111-111111111111", "addonVersion": version, "status": "ACTIVE", "configurationValues": config, "health": map[string]any{"issues": []any{}}}}
	default:
		tr.forbidden = true
		return nil, ErrRejected
	}
	tr.calls = append(tr.calls, operation)
	if req.Method != "GET" {
		tr.forbidden = true
		return nil, ErrRejected
	}
	status := 200
	raw, _ := json.Marshal(answer)
	if tr.mode == "denied" {
		status = 403
		raw = []byte(`{"message":"NEVER_REFLECT_PROVIDER_TEXT"}`)
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw))), Request: req}, nil
}
func attackLabTargetFixture() *AWSAttackLabTarget {
	return &AWSAttackLabTarget{ProfileARN: "arn:aws:eks:us-west-2:123456789012:fargateprofile/preflight/attack-lab/11111111-1111-4111-8111-111111111111", ExpectedCNIAddonVersion: "v1.22.4-eksbuild.3", SubnetIDs: []string{"subnet-11111111111111111", "subnet-22222222222222222"}}
}
func TestAttackLabActualProfileCompleteBindingAndDisabledZeroIO(t *testing.T) {
	for _, mode := range []string{"observed", "wrong-profile-name", "wrong-profile-arn", "wrong-cluster", "wrong-execution-role", "wrong-subnets", "selector-widening", "extra-selector", "not-active", "unhealthy", "wrong-cni-build", "cni-not-strict", "denied", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _ := awsAuthorityFixtureConfig(t)
			for i := range c.Roles {
				if c.Roles[i].Purpose == "aws_iam_role.attack_lab_pod" {
					c.Roles[i].RoleARN = "arn:aws:iam::123456789012:role/zasp-production-attack-lab-pod"
				}
			}
			target := attackLabTargetFixture()
			tr := &attackLabSDKTransport{mode: mode, authority: c, target: target}
			r := &Runner{config: sdkContractConfig(t), http: &http.Client{Transport: tr}}
			sdk := aws.Config{Region: "us-west-2", HTTPClient: r.http, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "fixture-inspector-key", SecretAccessKey: "fixture-inspector-secret"}, nil
			}), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
			evidence := r.observeAttackLabProfile(context.Background(), sdk, c, target, mode != "disabled")
			if mode == "disabled" {
				if len(tr.calls) != 0 || tr.forbidden || evidence.profile {
					t.Fatal("disabled feature performed profile I/O or became observed")
				}
				return
			}
			if len(tr.calls) == 0 || tr.forbidden {
				t.Fatal("official read-only SDK boundary absent or escaped")
			}
			if mode == "observed" {
				if !evidence.profile {
					t.Fatal("actual complete profile/add-on metadata not observed")
				}
			} else if evidence.profile {
				t.Fatal("partial or mismatched profile/add-on became complete")
			}
		})
	}
}
func TestAttackLabRunnerDenyAllCannotBecomeProductAuthority(t *testing.T) {
	exact := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	for _, mode := range []string{"observed", "url-encoded", "allow", "conditional", "missing-resource", "partial-action", "extra-statement", "alias", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			raw := exact
			switch mode {
			case "url-encoded":
				raw = url.QueryEscape(raw)
			case "allow":
				raw = strings.Replace(raw, `"Deny"`, `"Allow"`, 1)
			case "conditional":
				raw = strings.Replace(raw, `"Resource":"*"`, `"Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-west-2"}}`, 1)
			case "missing-resource":
				raw = strings.Replace(raw, `,"Resource":"*"`, "", 1)
			case "partial-action":
				raw = strings.Replace(raw, `"Action":"*"`, `"Action":"s3:*"`, 1)
			case "extra-statement":
				raw = strings.Replace(raw, `}]`, `},{"Effect":"Allow","Action":"*","Resource":"*"}]`, 1)
			case "alias":
				raw = strings.Replace(raw, `"Effect"`, `"EFFECT"`, 1)
			case "duplicate":
				raw = strings.Replace(raw, `"Effect":"Deny"`, `"Effect":"Allow","Effect":"Deny"`, 1)
			}
			expected := mode == "observed" || mode == "url-encoded"
			if exactRunnerDenyAllPolicy(raw) != expected {
				t.Fatal("runner DenyAll boundary was lost or broadened")
			}
		})
	}
}
