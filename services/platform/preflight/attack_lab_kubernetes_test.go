package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAttackLabUsesOneBoundedKubernetesAuthorityAndFixedPrerequisites(t *testing.T) {
	for _, mode := range []string{"observed", "unknown-null", "disabled", "wrong-namespace", "product-credentials", "wrong-ca-digest", "wrong-selector", "extra-security-group", "wrong-proxy-group", "alias", "wrong-version", "denied"} {
		t.Run(mode, func(t *testing.T) {
			var requests []string
			forbidden := false
			var ca string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests = append(requests, req.URL.Path)
				if req.Method != "GET" || req.Header.Get("Authorization") != "Bearer fixture-shared-kubernetes-token" {
					forbidden = true
					w.WriteHeader(403)
					return
				}
				if mode == "denied" {
					w.WriteHeader(403)
					return
				}
				var v map[string]any
				metadata := func(name, namespace string) map[string]any {
					return map[string]any{"name": name, "namespace": namespace, "uid": "223e4567-e89b-12d3-a456-426614174000"}
				}
				switch req.URL.Path {
				case "/version":
					minor := "34+"
					if mode == "wrong-version" {
						minor = "30"
					}
					v = map[string]any{"major": "1", "minor": minor}
				case "/api/v1/namespaces/zasp-attack-lab":
					m := metadata("zasp-attack-lab", "")
					m["labels"] = map[string]string{"kubernetes.io/metadata.name": "zasp-attack-lab", "zasp.io/execution": "attack-lab"}
					if mode == "wrong-namespace" {
						m["name"] = "foreign"
					}
					v = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": m, "status": map[string]string{"phase": "Active"}}
				case "/api/v1/namespaces/zasp-attack-lab/serviceaccounts/agentsec-attack-lab-runner":
					m := metadata("agentsec-attack-lab-runner", "zasp-attack-lab")
					m["labels"] = map[string]string{"zasp.io/execution": "attack-lab"}
					m["annotations"] = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test"}
					v = map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": m, "automountServiceAccountToken": false}
					if mode == "product-credentials" {
						v["secrets"] = []any{map[string]string{"name": "product"}}
					}
				case "/api/v1/namespaces/zasp-attack-lab/configmaps/agentsec-attack-lab-proxy-ca":
					v = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata("agentsec-attack-lab-proxy-ca", "zasp-attack-lab"), "immutable": true, "data": map[string]string{"proxy-ca.crt": ca}}
				case "/apis/vpcresources.k8s.aws/v1beta1/namespaces/zasp-attack-lab/securitygrouppolicies/agentsec-attack-lab-egress", "/apis/vpcresources.k8s.aws/v1beta1/namespaces/agentsec/securitygrouppolicies/agentsec-attack-lab-proxy":
					proxy := strings.Contains(req.URL.Path, "/namespaces/agentsec/")
					name, namespace, group := "agentsec-attack-lab-egress", "zasp-attack-lab", "sg-1234abcd"
					labels := map[string]string{"zasp.io/execution": "attack-lab"}
					if proxy {
						name, namespace, group = "agentsec-attack-lab-proxy", "agentsec", "sg-2345bcde"
						labels = map[string]string{"app.kubernetes.io/name": "agentsec-attack-lab-proxy"}
					}
					if mode == "wrong-selector" && !proxy {
						labels = map[string]string{}
					}
					groups := []string{group}
					if mode == "extra-security-group" && !proxy {
						groups = append(groups, "sg-3456cdef")
					}
					if mode == "wrong-proxy-group" && proxy {
						groups = []string{"sg-3456cdef"}
					}
					v = map[string]any{"apiVersion": "vpcresources.k8s.aws/v1beta1", "kind": "SecurityGroupPolicy", "metadata": metadata(name, namespace), "spec": map[string]any{"podSelector": map[string]any{"matchLabels": labels}, "securityGroups": map[string]any{"groupIds": groups}}}
				default:
					forbidden = true
					w.WriteHeader(404)
					return
				}
				if mode == "unknown-null" {
					v["unrelated_extension"] = nil
				}
				raw, _ := json.Marshal(v)
				if mode == "alias" {
					raw = []byte(strings.Replace(string(raw), `"uid":`, `"UID":`, 1))
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			caBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			ca = string(caBytes)
			digest := sha256.Sum256(caBytes)
			authority, _, _ := awsAuthorityFixtureConfig(t)
			authority.Cluster.Endpoint = server.URL
			authority.Cluster.CASHA256 = hex.EncodeToString(digest[:])
			for i := range authority.Roles {
				if authority.Roles[i].Purpose == "aws_iam_role.attack_lab_runner_test" {
					authority.Roles[i].RoleARN = "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test"
				}
			}
			target := attackLabTargetFixture()
			target.RunnerSecurityGroupID = "sg-1234abcd"
			target.ProxySecurityGroupID = "sg-2345bcde"
			target.ProxyCASHA256 = hex.EncodeToString(digest[:])
			if mode == "wrong-ca-digest" {
				target.ProxyCASHA256 = strings.Repeat("0", 64)
			}
			reader, e := newAWSKubernetesIdentityReader(server.URL, caBytes, func(context.Context) ([]byte, error) { return []byte("fixture-shared-kubernetes-token"), nil }, authority, requiredAWSRoleInventory(true))
			if e != nil {
				t.Fatal("bound shared authority not constructed")
			}
			defer reader.Close()
			r := &Runner{config: sdkContractConfig(t)}
			evidence := r.observeAttackLabKubernetes(context.Background(), reader, authority, target, mode != "disabled")
			if mode == "disabled" {
				if len(requests) != 0 || evidence.namespace || evidence.policy {
					t.Fatal("disabled feature read Kubernetes or became proved")
				}
				return
			}
			if len(requests) == 0 || len(requests) > 6 || forbidden {
				t.Fatal("fixed bounded shared Kubernetes boundary absent or widened")
			}
			expected := mode == "observed" || mode == "unknown-null"
			if expected {
				if !evidence.namespace || !evidence.policy {
					t.Fatal("complete actual Kubernetes prerequisites not observed")
				}
			} else if evidence.namespace && evidence.policy {
				t.Fatal("unbound, malformed or broadened Kubernetes prerequisites accepted")
			}
		})
	}
}
