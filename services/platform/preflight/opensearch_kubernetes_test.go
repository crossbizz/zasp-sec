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

func TestOpenSearchSelectedPodReadsOnlyLiteralAllowlistedAuthority(t *testing.T) {
	for _, mode := range []string{"exact", "unrelated secret ref", "indirect endpoint", "envFrom", "duplicate endpoint", "wrong UID", "wrong container", "alias", "foreign pod"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _ := awsAuthorityFixtureConfig(t)
			c.Selected = &AWSSelectedWorkload{Purpose: `aws_iam_role.runtime["index"]`, PodName: "preflight-pod", PodUID: "33333333-3333-4333-8333-333333333333"}
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/agentsec/pods/preflight-pod" || r.Header.Get("Authorization") != "Bearer fixture-kubernetes-credential" {
					w.WriteHeader(403)
					return
				}
				endpoint := map[string]any{"name": "ZASP_OPENSEARCH_ENDPOINT", "value": "https://vpc-product-events.us-west-2.es.amazonaws.com"}
				env := []any{endpoint, map[string]string{"name": "ZASP_OPENSEARCH_INDEX", "value": "zasp-runtime-events-v1"}, map[string]string{"name": "ZASP_RUNTIME_SESSION_INDEX", "value": "zasp-runtime-sessions-v1"}, map[string]string{"name": "ZASP_RUNTIME_STAGE_VERSION", "value": "runtime-index-v1"}, map[string]string{"name": "ZASP_WORKER_MODE", "value": "runtime-index"}, map[string]string{"name": "UNRELATED_SECRET", "value": "provider-secret-not-for-report"}}
				if mode == "unrelated secret ref" {
					env = append(env, map[string]any{"name": "ZASP_POSTGRES_DSN", "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "private", "key": "private"}}})
				}
				if mode == "indirect endpoint" {
					delete(endpoint, "value")
					endpoint["valueFrom"] = map[string]any{"secretKeyRef": map[string]string{"name": "private", "key": "endpoint"}}
				}
				if mode == "duplicate endpoint" {
					env = append(env, endpoint)
				}
				container := map[string]any{"name": "runtime-index", "image": "example/worker@sha256:" + strings.Repeat("a", 64), "env": env}
				if mode == "envFrom" {
					container["envFrom"] = []any{map[string]any{"secretRef": map[string]string{"name": "private"}}}
				}
				if mode == "wrong container" {
					container["name"] = "foreign"
				}
				uid := c.Selected.PodUID
				if mode == "wrong UID" {
					uid = "44444444-4444-4444-8444-444444444444"
				}
				pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]string{"namespace": "agentsec", "name": "preflight-pod", "uid": uid}, "spec": map[string]any{"serviceAccountName": "zasp-runtime-index", "containers": []any{container}}, "status": map[string]string{"phase": "Running"}}
				b, _ := json.Marshal(pod)
				if mode == "alias" {
					b = []byte(strings.Replace(string(b), `"containers":`, `"Containers":`, 1))
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			digest := sha256.Sum256(ca)
			c.Cluster.Endpoint, c.Cluster.CASHA256 = server.URL, hex.EncodeToString(digest[:])
			reader, e := newAWSKubernetesIdentityReader(server.URL, ca, func(context.Context) ([]byte, error) { return []byte("fixture-kubernetes-credential"), nil }, c, requiredAWSRoleInventory(true))
			if e != nil {
				t.Fatal(e)
			}
			defer reader.Close()
			selected := *c.Selected
			name := "preflight-pod"
			if mode == "foreign pod" {
				name = "foreign"
			}
			selected.PodName = name
			got, e := reader.OpenSearchWorkload(context.Background(), selected, "runtime-index")
			if mode == "exact" || mode == "unrelated secret ref" {
				if e != nil || len(got.Env) != 5 || got.PodUID != c.Selected.PodUID {
					t.Fatal("actual literal selected footprint not decoded")
				}
				b, _ := json.Marshal(got)
				if strings.Contains(string(b), "provider-secret") || strings.Contains(string(b), "ZASP_POSTGRES_DSN") {
					t.Fatal("raw unrelated Pod environment escaped")
				}
			} else if e == nil {
				t.Fatal("indirect or misbound Pod authority accepted")
			}
			if e != nil && mode != "foreign pod" {
				expected := "binding_mismatch"
				if mode == "alias" || mode == "duplicate endpoint" {
					expected = "malformed"
				}
				assertAWSKubeFailureOutcome(t, e, "kubernetes:GetPod", expected)
			}
			if mode == "foreign pod" && calls != 0 {
				t.Fatal("foreign selectedPod reached API")
			}
		})
	}
}
