package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// The deployment union's closed catalog is the independent expected authority
// roster; the product inventory may not define its own smaller acceptance set.
func originalAWSRoleInventory(t *testing.T) map[string]string {
	t.Helper()
	source, e := os.ReadFile("../../../deploy/staging/iam-policy-union-v1.mjs")
	if e != nil {
		t.Fatal("original deployment role contract unavailable")
	}
	start := strings.Index(string(source), "const workloadSubjects = ")
	if start < 0 {
		t.Fatal("original deployment subject contract absent")
	}
	value := string(source)[start+len("const workloadSubjects = "):]
	end := strings.Index(value, "\n};")
	if end < 0 {
		t.Fatal("original deployment subject contract malformed")
	}
	var subjects map[string]string
	if json.Unmarshal([]byte(value[:end+2]), &subjects) != nil || len(subjects) != 38 {
		t.Fatal("original38IRSA roster changed or omitted")
	}
	return subjects
}
func TestCompiledAWSRoleInventoryPreservesDeploymentScope(t *testing.T) {
	expected := originalAWSRoleInventory(t)
	inventory := requiredAWSRoleInventory(true)
	if len(inventory) != 41 {
		t.Fatal("required38IRSA plus3service roles were reduced")
	}
	observed := map[string]string{}
	infra := 0
	for _, role := range inventory {
		if _, ok := observed[role.purpose]; ok {
			t.Fatal("duplicate compiled purpose")
		}
		observed[role.purpose] = role.subject
		if role.trustClass == "irsa" {
			if expected[role.purpose] != role.subject {
				t.Fatal("compiled subject changed from existing deployment")
			}
		} else {
			infra++
		}
	}
	if infra != 3 {
		t.Fatal("service-role families omitted or conflated with IRSA")
	}
	for purpose, subject := range expected {
		if observed[purpose] != subject {
			t.Fatal("required deployment purpose missing")
		}
	}
}

type awsAuthorityFixtureReader struct {
	cluster  string
	mode     string
	subjects map[string]string
	bindings map[string]string
}

func (k *awsAuthorityFixtureReader) ClusterUID(context.Context) (string, error) {
	if k.mode == "wrong-kube-cluster" {
		return "99999999-9999-4999-8999-999999999999", nil
	}
	return k.cluster, nil
}
func (k *awsAuthorityFixtureReader) ServiceAccount(_ context.Context, namespace, name string) (KubernetesServiceAccountBinding, error) {
	subject := "system:serviceaccount:" + namespace + ":" + name
	role := ""
	for purpose, s := range k.subjects {
		if s == subject {
			if purpose == "aws_iam_role.api" {
				role = k.bindings[purpose]
				break
			}
			if purpose != "aws_iam_role.api_connectors" && purpose != "aws_iam_role.audit_exports[\"reader\"]" {
				role = k.bindings[purpose]
			}
		}
	}
	if k.mode == "wrong-sa-annotation" {
		role = "arn:aws:iam::123456789012:role/foreign"
	}
	return KubernetesServiceAccountBinding{Namespace: namespace, Name: name, UID: "22222222-2222-4222-8222-222222222222", RoleARN: role}, nil
}
func (k *awsAuthorityFixtureReader) Pod(_ context.Context, namespace, name string) (KubernetesWorkloadBinding, error) {
	serviceAccount := "zasp-runtime-index"
	if k.mode == "aux-api-role" {
		serviceAccount = "agentsec-api"
	}
	if k.mode == "wrong-pod-spec" {
		serviceAccount = "foreign"
	}
	return KubernetesWorkloadBinding{Namespace: namespace, Name: name, UID: "33333333-3333-4333-8333-333333333333", ServiceAccount: serviceAccount, Phase: "Running", ProjectedAudience: "sts.amazonaws.com"}, nil
}

type awsAuthorityFixtureTransport struct {
	mode            string
	target          AWSClusterTarget
	subjects, roles map[string]string
	calls           []string
	forbidden       bool
}

func (tr *awsAuthorityFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var b []byte
	if req.Body != nil {
		b, _ = io.ReadAll(io.LimitReader(req.Body, 65537))
	}
	q, _ := url.ParseQuery(string(b))
	action := q.Get("Action")
	content := "text/xml"
	status := 200
	answer := ""
	if req.Method == "GET" && req.URL.Path == "/clusters/preflight" {
		action = "eks:DescribeCluster"
		content = "application/json"
		version := "1.34"
		if tr.mode == "unsupported-cluster" {
			version = "1.33"
		}
		cluster := map[string]any{"name": tr.target.Name, "arn": tr.target.ARN, "status": "ACTIVE", "version": version, "endpoint": tr.target.Endpoint, "certificateAuthority": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("fixture-cluster-ca"))}, "identity": map[string]any{"oidc": map[string]string{"issuer": tr.target.Issuer}}, "resourcesVpcConfig": map[string]any{"vpcId": tr.target.VPCID, "endpointPrivateAccess": tr.mode != "private-endpoint-disabled", "endpointPublicAccess": tr.mode == "public-endpoint"}}
		encoded, _ := json.Marshal(map[string]any{"cluster": cluster})
		answer = string(encoded)
	} else {
		switch action {
		case "GetCallerIdentity":
			answer = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/zasp-preflight-inspector/check</Arn><UserId>fixture</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`
		case "GetOpenIDConnectProvider":
			answer = `<GetOpenIDConnectProviderResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetOpenIDConnectProviderResult><Url>` + strings.TrimPrefix(tr.target.Issuer, "https://") + `</Url><ClientIDList><member>sts.amazonaws.com</member></ClientIDList><ThumbprintList><member>1111111111111111111111111111111111111111</member></ThumbprintList></GetOpenIDConnectProviderResult></GetOpenIDConnectProviderResponse>`

		case "AssumeRoleWithWebIdentity":
			requested := q.Get("RoleArn")
			roleName := requested[strings.LastIndex(requested, "/")+1:]
			purpose := tr.roles[roleName]
			subject := tr.subjects[purpose]
			audience, issuer := "sts.amazonaws.com", tr.target.Issuer
			expiry := time.Now().UTC().Add(15 * time.Minute)
			switch tr.mode {
			case "wrong-subject":
				subject = "system:serviceaccount:foreign:foreign"
			case "wrong-audience":
				audience = "foreign"
			case "wrong-issuer":
				issuer = "https://foreign.invalid"
			case "missing-subject":
				subject = ""
			case "short-expiry":
				expiry = time.Now().UTC().Add(30 * time.Second)
			}
			answer = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>fixture-workload-key</AccessKeyId><SecretAccessKey>fixture-workload-secret</SecretAccessKey><SessionToken>fixture-workload-session</SessionToken><Expiration>` + expiry.Format(time.RFC3339) + `</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/` + roleName + `/zasp-preflight-inspector</Arn><AssumedRoleId>AROAEXAMPLE00000000:fixture</AssumedRoleId></AssumedRoleUser><SubjectFromWebIdentityToken>` + subject + `</SubjectFromWebIdentityToken><Audience>` + audience + `</Audience><Provider>` + issuer + `</Provider></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`
		case "GetRole":
			name := q.Get("RoleName")
			purpose := tr.roles[name]
			roleARN := "arn:aws:iam::123456789012:role/" + name
			subject, irsa := tr.subjects[purpose]
			var doc any
			if irsa {
				aud := "sts.amazonaws.com"
				if tr.mode == "wrong-trust" {
					aud = "foreign"
				}
				doc = map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": map[string]string{"Federated": "arn:aws:iam::123456789012:oidc-provider/" + strings.TrimPrefix(tr.target.Issuer, "https://")}, "Condition": map[string]any{"StringEquals": map[string]string{strings.TrimPrefix(tr.target.Issuer, "https://") + ":aud": aud, strings.TrimPrefix(tr.target.Issuer, "https://") + ":sub": subject}}}}}
			} else {
				doc = map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]string{"Service": "eks.amazonaws.com"}}}}
			}
			encoded, _ := json.Marshal(doc)
			answer = `<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetRoleResult><Role><Arn>` + roleARN + `</Arn><Path>/</Path><RoleName>` + name + `</RoleName><RoleId>AROAEXAMPLE00000000</RoleId><AssumeRolePolicyDocument>` + url.QueryEscape(string(encoded)) + `</AssumeRolePolicyDocument></Role></GetRoleResult></GetRoleResponse>`
		default:
			tr.forbidden = true
			status = 400
		}
	}
	tr.calls = append(tr.calls, action)
	if strings.Contains(action, "Create") || strings.Contains(action, "Put") || strings.Contains(action, "Delete") || action == "AssumeRole" {
		tr.forbidden = true
	}
	if tr.mode == "denied" {
		status = 403
		answer = `<ErrorResponse><Error><Code>AccessDenied</Code><Message>NEVER_REFLECT_AUTHORITY_TEXT</Message></Error></ErrorResponse>`
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{content}}, Body: io.NopCloser(strings.NewReader(answer)), Request: req}, nil
}
func awsAuthorityFixtureConfig(t *testing.T) (*AWSAuthorityConfig, *awsAuthorityFixtureReader, *awsAuthorityFixtureTransport) {
	t.Helper()
	subjects := originalAWSRoleInventory(t)
	purposes := make([]string, 0, len(subjects)+3)
	for purpose := range subjects {
		purposes = append(purposes, purpose)
	}
	purposes = append(purposes, "aws_iam_role.eks_cluster", "aws_iam_role.eks_nodes", "aws_iam_role.attack_lab_pod")
	sum := sha256.Sum256([]byte("fixture-cluster-ca"))
	target := AWSClusterTarget{Name: "preflight", ARN: "arn:aws:eks:us-west-2:123456789012:cluster/preflight", VPCID: "vpc-11111111111111111", Issuer: "https://oidc.eks.us-west-2.amazonaws.com/id/11111111111111111111111111111111", Endpoint: "https://fixture.us-west-2.eks.amazonaws.com", CASHA256: hex.EncodeToString(sum[:]), ClusterUID: "11111111-1111-4111-8111-111111111111"}
	config := &AWSAuthorityConfig{Inspection: CredentialConfig{Kind: "operator_environment", ExpectedRoleARN: "arn:aws:iam::123456789012:role/zasp-preflight-inspector"}, Cluster: target}
	bindings := map[string]string{}
	roles := map[string]string{}
	for i, purpose := range purposes {
		name := fmt.Sprintf("fixture-role-%02d", i)
		arn := "arn:aws:iam::123456789012:role/" + name
		config.Roles = append(config.Roles, AWSRoleBinding{Purpose: purpose, RoleARN: arn})
		bindings[purpose] = arn
		roles[name] = purpose
	}
	return config, &awsAuthorityFixtureReader{cluster: target.ClusterUID, subjects: subjects, bindings: bindings}, &awsAuthorityFixtureTransport{target: target, subjects: subjects, roles: roles}
}
func TestActualAWSAuthorityInventoryAndClusterContract(t *testing.T) {
	for _, mode := range []string{"observed", "one-purpose-only", "unsupported-cluster", "public-endpoint", "private-endpoint-disabled", "wrong-kube-cluster", "wrong-sa-annotation", "wrong-trust", "denied"} {
		t.Run(mode, func(t *testing.T) {
			config, k, tr := awsAuthorityFixtureConfig(t)
			tr.mode = mode
			k.mode = mode
			if mode == "one-purpose-only" {
				config.Roles = config.Roles[:1]
			}
			base := sdkContractConfig(t)
			r := &Runner{config: base, http: &http.Client{Transport: tr}}
			report := initialReport(base, "installed")
			evidence := r.inspectAWSAuthority(context.Background(), &report, config, k)
			if len(tr.calls) == 0 || tr.forbidden {
				t.Fatal("authority probe skipped SDK boundary or mutated provider")
			}
			if evidence == nil {
				t.Fatal("closed authority evidence unavailable")
			}
			if mode == "observed" {
				if !evidence.clusterVerified || evidence.requiredRoles != 41 || evidence.observedRoles != 41 || evidence.requiredTrust != 38 || evidence.observedTrust != 38 {
					t.Fatal("full original role inventory or exact current cluster not observed")
				}
			} else if evidence.clusterVerified && evidence.requiredRoles == evidence.observedRoles && evidence.requiredTrust == evidence.observedTrust {
				t.Fatal("partial, mismatched or denied authority became complete")
			}
			raw, _ := json.Marshal(report)
			if strings.Contains(string(raw), "NEVER_REFLECT_AUTHORITY_TEXT") || report.Ready || report.ProductionEndToEndVerified {
				t.Fatal("provider details leaked or inspection became deployment acceptance")
			}
		})
	}
}
