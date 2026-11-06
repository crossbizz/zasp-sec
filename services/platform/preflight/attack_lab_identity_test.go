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

type attackLabIAMTransport struct {
	mode      string
	calls     []string
	forbidden bool
	pages     int
	boundary  string
}

func (tr *attackLabIAMTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(io.LimitReader(req.Body, 65537))
	q, _ := url.ParseQuery(string(raw))
	action := q.Get("Action")
	tr.calls = append(tr.calls, action)
	if req.Method != "POST" {
		tr.forbidden = true
		return nil, ErrRejected
	}
	deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	if tr.mode == "boundary-allow" {
		deny = strings.Replace(deny, `"Deny"`, `"Allow"`, 1)
	}
	answer := ""
	switch action {
	case "GetRole":
		name := q.Get("RoleName")
		role := "arn:aws:iam::123456789012:role/" + name
		if name != "zasp-production-attack-lab-pod" && name != "zasp-production-attack-lab-runner-test" {
			tr.forbidden = true
			return nil, ErrRejected
		}
		principal := "eks-fargate-pods.amazonaws.com"
		source := "arn:aws:eks:us-west-2:123456789012:fargateprofile/preflight/*"
		if tr.mode == "execution-principal" {
			principal = "ec2.amazonaws.com"
		}
		if tr.mode == "execution-source-widened" {
			source = "*"
		}
		doc, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]string{"Service": principal}, "Action": "sts:AssumeRole", "Condition": map[string]any{"ArnLike": map[string]string{"aws:SourceArn": source}, "StringEquals": map[string]string{"aws:SourceAccount": "123456789012"}}}}})
		boundary := ""
		if name == "zasp-production-attack-lab-runner-test" {
			pin := tr.boundary
			if tr.mode == "wrong-boundary" {
				pin = "arn:aws:iam::123456789012:policy/foreign"
			}
			boundary = `<PermissionsBoundary><PermissionsBoundaryType>PermissionsBoundaryPolicy</PermissionsBoundaryType><PermissionsBoundaryArn>` + pin + `</PermissionsBoundaryArn></PermissionsBoundary>`
		}
		if tr.mode == "wrong-role-arn" {
			role = "arn:aws:iam::999999999999:role/" + name
		}
		answer = `<GetRoleResponse><GetRoleResult><Role><Arn>` + role + `</Arn><RoleName>` + name + `</RoleName><RoleId>AROAFIXTURE00000000</RoleId><AssumeRolePolicyDocument>` + url.QueryEscape(string(doc)) + `</AssumeRolePolicyDocument>` + boundary + `</Role></GetRoleResult></GetRoleResponse>`
	case "GetPolicy":
		if q.Get("PolicyArn") != tr.boundary {
			tr.forbidden = true
			return nil, ErrRejected
		}
		answer = `<GetPolicyResponse><GetPolicyResult><Policy><Arn>` + tr.boundary + `</Arn><DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>`
	case "GetPolicyVersion":
		if q.Get("PolicyArn") != tr.boundary || q.Get("VersionId") != "v1" {
			tr.forbidden = true
			return nil, ErrRejected
		}
		answer = `<GetPolicyVersionResponse><GetPolicyVersionResult><PolicyVersion><VersionId>v1</VersionId><IsDefaultVersion>true</IsDefaultVersion><Document>` + url.QueryEscape(deny) + `</Document></PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>`
	case "GetRolePolicy":
		name := "zasp-production-attack-lab-runner-test"
		if q.Get("RoleName") != name || q.Get("PolicyName") != name+"-deny" {
			tr.forbidden = true
			return nil, ErrRejected
		}
		inline := deny
		if tr.mode == "inline-missing-deny" {
			inline = `{"Version":"2012-10-17","Statement":[]}`
		}
		answer = `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>` + name + `</RoleName><PolicyName>` + name + `-deny</PolicyName><PolicyDocument>` + url.QueryEscape(inline) + `</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`
	case "ListAttachedRolePolicies":
		if q.Get("RoleName") != "zasp-production-attack-lab-pod" {
			tr.forbidden = true
			return nil, ErrRejected
		}
		tr.pages++
		policy := "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
		if tr.mode == "wrong-managed-policy" {
			policy = "arn:aws:iam::aws:policy/AdministratorAccess"
		}
		members := `<member><PolicyArn>` + policy + `</PolicyArn><PolicyName>AmazonEKSFargatePodExecutionRolePolicy</PolicyName></member>`
		truncated := "false"
		marker := ""
		if tr.mode == "paged" && tr.pages == 1 {
			members = ""
			truncated = "true"
			marker = "second"
		}
		if tr.mode == "repeated-marker" {
			members = ""
			truncated = "true"
			marker = "repeated"
		}
		if tr.mode == "truncated-no-marker" {
			members = ""
			truncated = "true"
		}
		answer = `<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies>` + members + `</AttachedPolicies><IsTruncated>` + truncated + `</IsTruncated><Marker>` + marker + `</Marker></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`
	default:
		tr.forbidden = true
		return nil, ErrRejected
	}
	status := 200
	if tr.mode == "denied" {
		status = 403
		answer = `<ErrorResponse><Error><Code>AccessDenied</Code><Message>NEVER_REFLECT_PROVIDER_TEXT</Message></Error></ErrorResponse>`
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"text/xml"}}, Body: io.NopCloser(strings.NewReader(answer)), Request: req}, nil
}
func TestAttackLabActualRunnerDenyAllAndExecutionRoleInspection(t *testing.T) {
	for _, mode := range []string{"observed", "paged", "wrong-role-arn", "wrong-boundary", "boundary-allow", "inline-missing-deny", "execution-principal", "execution-source-widened", "wrong-managed-policy", "repeated-marker", "truncated-no-marker", "denied", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _ := awsAuthorityFixtureConfig(t)
			for i := range c.Roles {
				switch c.Roles[i].Purpose {
				case "aws_iam_role.attack_lab_pod":
					c.Roles[i].RoleARN = "arn:aws:iam::123456789012:role/zasp-production-attack-lab-pod"
				case "aws_iam_role.attack_lab_runner_test":
					c.Roles[i].RoleARN = "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test"
				}
			}
			target := attackLabTargetFixture()
			target.RunnerBoundaryPolicyARN = "arn:aws:iam::123456789012:policy/zasp-production-attack-lab-runner-test-boundary"
			tr := &attackLabIAMTransport{mode: mode, boundary: target.RunnerBoundaryPolicyARN}
			r := &Runner{config: sdkContractConfig(t), http: &http.Client{Transport: tr}}
			sdk := aws.Config{Region: "us-west-2", HTTPClient: r.http, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "fixture-inspector-key", SecretAccessKey: "fixture-inspector-secret"}, nil
			}), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
			evidence := r.observeAttackLabIsolationIdentity(context.Background(), sdk, c, target, mode != "disabled")
			if mode == "disabled" {
				if len(tr.calls) != 0 || evidence.runner {
					t.Fatal("disabled feature inspected IAM or became proved")
				}
				return
			}
			if len(tr.calls) == 0 || tr.forbidden || tr.pages > 4 {
				t.Fatal("read-only exact IAM boundary absent or escaped finite scope")
			}
			expected := mode == "observed" || mode == "paged"
			if evidence.runner != expected {
				t.Fatal("original DenyAll/execution-role recipe not proved or widened recipe accepted")
			}
		})
	}
}
