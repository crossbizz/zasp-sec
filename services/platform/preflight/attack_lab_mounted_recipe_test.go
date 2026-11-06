package preflight

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The combined fixture exercises Run's actual SDK ordering and shared Kubernetes
// authority; it never substitutes configuration booleans for a provider read.
func TestAttackLabMountedSameInspectorMetadataRecipe(t *testing.T) {
	for _, mode := range []string{"observed", "profile-denied", "runner-denied", "topology-denied", "kubernetes-denied", "policy-denied", "policy-credentials-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			config := attackLabIntegrationConfig(t)
			target := config.AWSAuthority.Fargate
			_, _, base := awsAuthorityFixtureConfig(t)
			base.target = config.AWSAuthority.Cluster
			base.roles = map[string]string{}
			bindings := map[string]string{}
			for _, r := range config.AWSAuthority.Roles {
				base.roles[r.RoleARN[strings.LastIndex(r.RoleARN, "/")+1:]] = r.Purpose
				bindings[r.Purpose] = r.RoleARN
			}
			var ca string
			forbidden := false
			var loseToken atomic.Bool
			var attackLabPhase atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "GET" || req.Header.Get("Authorization") != "Bearer fixture-shared-kubernetes-token" {
					forbidden = true
					w.WriteHeader(403)
					return
				}
				if mode == "kubernetes-denied" && req.URL.Path == "/version" {
					w.WriteHeader(403)
					return
				}
				if mode == "policy-denied" && strings.Contains(req.URL.Path, "/configmaps/") {
					w.WriteHeader(403)
					return
				}
				var v map[string]any
				metadata := func(name, namespace string) map[string]any {
					return map[string]any{"name": name, "namespace": namespace, "uid": "223e4567-e89b-12d3-a456-426614174000"}
				}
				switch req.URL.Path {
				case "/api/v1/namespaces/kube-system":
					v = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "kube-system", "uid": config.AWSAuthority.Cluster.ClusterUID}}
				case "/version":
					attackLabPhase.Store(true)
					minor := "34+"
					if "observed" == "wrong-version" {
						minor = "30"
					}
					v = map[string]any{"major": "1", "minor": minor}
				case "/api/v1/namespaces/zasp-attack-lab":
					m := metadata("zasp-attack-lab", "")
					m["labels"] = map[string]string{"kubernetes.io/metadata.name": "zasp-attack-lab", "zasp.io/execution": "attack-lab"}
					if "observed" == "wrong-namespace" {
						m["name"] = "foreign"
					}
					v = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": m, "status": map[string]string{"phase": "Active"}}
				case "/api/v1/namespaces/zasp-attack-lab/serviceaccounts/agentsec-attack-lab-runner":
					if mode == "policy-credentials-unavailable" && attackLabPhase.Load() {
						loseToken.Store(true)
					}
					m := metadata("agentsec-attack-lab-runner", "zasp-attack-lab")
					m["labels"] = map[string]string{"zasp.io/execution": "attack-lab"}
					m["annotations"] = map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/zasp-production-attack-lab-runner-test"}
					v = map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": m, "automountServiceAccountToken": false}
					if "observed" == "product-credentials" {
						v["secrets"] = []any{map[string]string{"name": "product"}}
					}
				case "/api/v1/namespaces/zasp-attack-lab/configmaps/agentsec-attack-lab-proxy-ca":
					v = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata("agentsec-attack-lab-proxy-ca", "zasp-attack-lab"), "immutable": true, "data": map[string]string{"proxy-ca.crt": ca}}
				case "/apis/vpcresources.k8s.aws/v1beta1/namespaces/zasp-attack-lab/securitygrouppolicies/agentsec-attack-lab-egress", "/apis/vpcresources.k8s.aws/v1beta1/namespaces/agentsec/securitygrouppolicies/agentsec-attack-lab-proxy":
					proxy := strings.Contains(req.URL.Path, "/namespaces/agentsec/")
					name, namespace, group := "agentsec-attack-lab-egress", "zasp-attack-lab", target.RunnerSecurityGroupID
					labels := map[string]string{"zasp.io/execution": "attack-lab"}
					if proxy {
						name, namespace, group = "agentsec-attack-lab-proxy", "agentsec", target.ProxySecurityGroupID
						labels = map[string]string{"app.kubernetes.io/name": "agentsec-attack-lab-proxy"}
					}
					if "observed" == "wrong-selector" && !proxy {
						labels = map[string]string{}
					}
					groups := []string{group}
					if "observed" == "extra-security-group" && !proxy {
						groups = append(groups, "sg-3456cdef")
					}
					if "observed" == "wrong-proxy-group" && proxy {
						groups = []string{"sg-3456cdef"}
					}
					v = map[string]any{"apiVersion": "vpcresources.k8s.aws/v1beta1", "kind": "SecurityGroupPolicy", "metadata": metadata(name, namespace), "spec": map[string]any{"podSelector": map[string]any{"matchLabels": labels}, "securityGroups": map[string]any{"groupIds": groups}}}
				default:
					parts := strings.Split(req.URL.Path, "/")
					if len(parts) == 7 && parts[1] == "api" && parts[2] == "v1" && parts[3] == "namespaces" && parts[5] == "serviceaccounts" {
						subject := "system:serviceaccount:" + parts[4] + ":" + parts[6]
						role := primarySARole(subject, bindings, requiredAWSRoleInventory(true))
						if role != "" {
							v = map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": parts[6], "namespace": parts[4], "uid": "22222222-2222-4222-8222-222222222222", "annotations": map[string]string{"eks.amazonaws.com/role-arn": role}}}
							break
						}
					}
					forbidden = true
					w.WriteHeader(404)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(v)
			}))
			defer server.Close()
			caBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			ca = string(caBytes)
			digest := sha256.Sum256(caBytes)
			// Public endpoint validation remains unchanged; only the private protocol
			// opener maps this exact test authority onto the local TLS listener.
			config.AWSAuthority.Cluster.CASHA256 = hex.EncodeToString(digest[:])
			target.ProxyCASHA256 = hex.EncodeToString(digest[:])
			base.target = config.AWSAuthority.Cluster
			dir := t.TempDir()
			caFile := filepath.Join(dir, "ca.pem")
			tokenFile := filepath.Join(dir, "token")
			if os.WriteFile(caFile, caBytes, 0600) != nil || os.WriteFile(tokenFile, []byte("fixture-shared-kubernetes-token"), 0600) != nil {
				t.Fatal("fixture authority files unavailable")
			}
			config.Kubernetes = &KubernetesAuthority{Endpoint: config.AWSAuthority.Cluster.Endpoint, CAFile: caFile, ClusterUID: config.AWSAuthority.Cluster.ClusterUID, Credentials: KubernetesCredentials{Kind: "explicit_bearer_file", TokenFile: tokenFile}}
			t.Setenv("AWS_ACCESS_KEY_ID", "fixture-inspector-key")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-inspector-secret")
			t.Setenv("AWS_SESSION_TOKEN", "")
			profile := &attackLabSDKTransport{mode: "observed", authority: config.AWSAuthority, target: target}
			identity := &attackLabIAMTransport{mode: "observed", boundary: target.RunnerBoundaryPolicyARN}
			topology := &attackLabTopologyTransport{mode: "observed", target: target}
			transport := &attackLabMountedTransport{base: base, profile: profile, identity: identity, topology: topology, ca: caBytes, mode: mode}
			r, e := NewRunner(config)
			if e != nil {
				t.Fatal("connected fixture config rejected")
			}
			defer r.Close()
			r.http = &http.Client{Transport: transport}
			report, e := r.runWithIdentityReader(context.Background(), "installed", func() (KubernetesIdentityReader, func()) {
				local := *config.AWSAuthority
				local.Cluster.Endpoint = server.URL
				reader, err := newAWSKubernetesIdentityReader(server.URL, caBytes, func(context.Context) ([]byte, error) {
					if loseToken.Load() {
						return nil, ErrRejected
					}
					return []byte("fixture-shared-kubernetes-token"), nil
				}, &local, requiredAWSRoleInventory(true))
				if err != nil {
					t.Fatal("private protocol authority construction failed")
				}
				return reader, reader.Close
			})
			serialized, _ := json.Marshal(report)
			for _, canary := range []string{"NEVER_REFLECT_PROVIDER_TEXT", "fixture-inspector-key", "fixture-inspector-secret", "fixture-shared-kubernetes-token"} {
				if strings.Contains(string(serialized), canary) {
					t.Fatal("private credential or dependency text leaked into report")
				}
			}
			s := report.AttackLabConfiguration
			if e == nil || s == nil || report.Ready || report.ProductionEndToEndVerified || forbidden || base.forbidden || profile.forbidden || identity.forbidden || topology.forbidden {
				t.Fatal("mounted metadata escaped closed authority or became full acceptance")
			}
			identities := 0
			for _, op := range base.calls {
				if op == "GetCallerIdentity" {
					identities++
				}
			}
			if identities != 1 {
				t.Fatal("inspector identity reloaded or fallback used")
			}
			if s.NetworkEnforcement != "unobserved" || s.CanaryAndCleanup != "unobserved" {
				t.Fatal("metadata became packet or cleanup proof")
			}
			for name, o := range map[string]Observation{"profile": s.Profile, "namespace": s.Namespace, "runner": s.RunnerIdentity, "policy": s.SecurityGroupPolicies, "topology": s.TopologyMetadata} {
				expectedFail := mode == "profile-denied" && name == "profile" || mode == "runner-denied" && name == "runner" || mode == "topology-denied" && name == "topology" || mode == "kubernetes-denied" && name == "policy" || mode == "policy-denied" && name == "policy"
				expectedUnknown := mode == "kubernetes-denied" && name == "namespace" || mode == "policy-credentials-unavailable" && name == "policy"
				if expectedUnknown {
					if o.Status != "unobserved" || o.ObservedAt != nil {
						t.Fatal("unattempted downstream Kubernetes read became proof")
					}
					continue
				}
				if expectedFail {
					if o.Status != "fail" || o.ObservedAt == nil || len(o.Failures) == 0 || o.Failures[0].Outcome != "denied" {
						t.Fatal("actual denied read lost bounded actionable failure")
					}
					continue
				}
				if o.Status != "pass" || o.ObservedAt == nil {
					t.Fatalf("actual mounted metadata not observed: component=%s status=%s code=%s", name, o.Status, o.Code)
				}
			}
		})
	}
}

type attackLabMountedTransport struct {
	base     *awsAuthorityFixtureTransport
	profile  *attackLabSDKTransport
	identity *attackLabIAMTransport
	topology *attackLabTopologyTransport
	ca       []byte
	mode     string
}

func (t *attackLabMountedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	raw := []byte{}
	if req.Body != nil {
		raw, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(raw))
	}
	q, _ := url.ParseQuery(string(raw))
	op := q.Get("Action")
	denied := t.mode == "profile-denied" && strings.Contains(req.URL.Path, "fargate-profiles") || t.mode == "runner-denied" && op == "GetPolicy" || t.mode == "topology-denied" && op == "DescribeVpcs"
	if denied {
		return &http.Response{StatusCode: 403, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"message":"NEVER_REFLECT_PROVIDER_TEXT"}`)), Request: req}, nil
	}
	if strings.Contains(req.URL.Path, "/fargate-profiles/") || strings.Contains(req.URL.Path, "/addons/") {
		return t.profile.RoundTrip(req)
	}
	if strings.HasPrefix(op, "Describe") {
		return t.topology.RoundTrip(req)
	}
	if op == "GetPolicy" || op == "GetPolicyVersion" || op == "GetRolePolicy" || op == "ListAttachedRolePolicies" || op == "GetRole" && q.Get("RoleName") == "zasp-production-attack-lab-pod" {
		return t.identity.RoundTrip(req)
	}
	out, e := t.base.RoundTrip(req)
	if e != nil {
		return out, e
	}
	body, _ := io.ReadAll(out.Body)
	_ = out.Body.Close()
	if req.URL.Path == "/clusters/preflight" {
		var v map[string]any
		_ = json.Unmarshal(body, &v)
		cluster := v["cluster"].(map[string]any)
		cluster["certificateAuthority"] = map[string]string{"data": base64.StdEncoding.EncodeToString(t.ca)}
		cluster["resourcesVpcConfig"].(map[string]any)["clusterSecurityGroupId"] = "sg-55555555555555555"
		body, _ = json.Marshal(v)
	}
	if op == "GetRole" && q.Get("RoleName") == "zasp-production-attack-lab-runner-test" {
		boundary := `<PermissionsBoundary><PermissionsBoundaryType>PermissionsBoundaryPolicy</PermissionsBoundaryType><PermissionsBoundaryArn>` + t.identity.boundary + `</PermissionsBoundaryArn></PermissionsBoundary>`
		body = []byte(strings.Replace(string(body), "</Role>", boundary+"</Role>", 1))
	}
	out.Body = io.NopCloser(bytes.NewReader(body))
	return out, nil
}
