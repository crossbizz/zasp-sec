package preflight

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAWSKubernetesReaderClosedIdentityBoundary(t *testing.T) {
	for _, mode := range []string{"observed", "denied", "unauthorized", "namespace-denied", "wrong-ca", "foreign-path", "duplicate", "alias", "redirect", "oversize", "wrong-kind", "deleting", "wrong-audience"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "denied" || mode == "namespace-denied" && strings.HasSuffix(r.URL.Path, "/kube-system") {
					w.WriteHeader(403)
					return
				}
				if mode == "unauthorized" {
					w.WriteHeader(401)
					return
				}
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer fixture-kubernetes-credential" {
					t.Error("wrong request method or credential binding")
					w.WriteHeader(403)
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", "https://foreign.invalid")
					w.WriteHeader(302)
					return
				}
				if mode == "oversize" {
					_, _ = w.Write([]byte(strings.Repeat("x", 1048577)))
					return
				}
				body := `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"zasp-runtime-index","namespace":"agentsec","uid":"22222222-2222-4222-8222-222222222222","annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::123456789012:role/index"}},"vendor_extra":null}`
				if strings.HasSuffix(r.URL.Path, "/kube-system") {
					body = `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system","uid":"11111111-1111-4111-8111-111111111111"}}`
				}
				if strings.Contains(r.URL.Path, "/pods/") {
					body = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"preflight-pod","namespace":"agentsec","uid":"33333333-3333-4333-8333-333333333333"},"spec":{"serviceAccountName":"zasp-runtime-index","volumes":[{"projected":{"sources":[{"serviceAccountToken":{"audience":"sts.amazonaws.com"}}]}}]},"status":{"phase":"Running"}}`
				}
				if mode == "duplicate" {
					body = strings.Replace(body, `"kind":"`, `"kind":"forged","kind":"`, 1)
				}
				if mode == "alias" {
					body = strings.Replace(body, `"uid":`, `"UID":`, 1)
				}
				if mode == "wrong-kind" {
					body = strings.Replace(body, `"kind":"ServiceAccount"`, `"kind":"Pod"`, 1)
				}
				if mode == "deleting" {
					body = strings.Replace(body, `"annotations":`, `"deletionTimestamp":"2026-10-17T00:00:00Z","annotations":`, 1)
				}
				if mode == "wrong-audience" {
					body = strings.ReplaceAll(body, `sts.amazonaws.com`, `foreign`)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			sum := sha256.Sum256(cert)
			hash := hex.EncodeToString(sum[:])
			if mode == "wrong-ca" {
				hash = strings.Repeat("0", 64)
			}
			c, _, _ := awsAuthorityFixtureConfig(t)
			c.Cluster.Endpoint = server.URL
			c.Cluster.CASHA256 = hash
			c.Selected = &AWSSelectedWorkload{Purpose: `aws_iam_role.runtime["index"]`, PodName: "preflight-pod", PodUID: "33333333-3333-4333-8333-333333333333"}
			reader, e := newAWSKubernetesIdentityReader(server.URL, cert, func(context.Context) ([]byte, error) { return []byte("fixture-kubernetes-credential"), nil }, c, requiredAWSRoleInventory(true))
			if mode == "wrong-ca" {
				if e == nil {
					reader.Close()
					t.Fatal("foreign CA became bound authority")
				}
				return
			}
			if e != nil {
				t.Fatal("configured reader not constructed")
			}
			defer reader.Close()
			if mode == "foreign-path" {
				_, e = reader.ServiceAccount(context.Background(), "foreign", "foreign")
				if e == nil || calls != 0 {
					t.Fatal("reader escaped configured fixed paths")
				}
				return
			}
			sa, e := reader.ServiceAccount(context.Background(), "agentsec", "zasp-runtime-index")
			if mode == "observed" || mode == "wrong-audience" || mode == "namespace-denied" {
				if e != nil || sa.Name != "zasp-runtime-index" || sa.RoleARN == "" {
					t.Fatal("exact service account observation missing")
				}
				uid, e := reader.ClusterUID(context.Background())
				if mode == "namespace-denied" {
					assertAWSKubeFailureOutcome(t, e, "kubernetes:GetNamespace", "denied")
					return
				}
				if e != nil || uid != c.Cluster.ClusterUID {
					t.Fatal("cluster namespace identity not bound")
				}
				pod, e := reader.Pod(context.Background(), "agentsec", "preflight-pod")
				if mode == "wrong-audience" {
					if e == nil && pod.ProjectedAudience == "sts.amazonaws.com" {
						t.Fatal("foreign audience became expected projection")
					}
					return
				}
				if e != nil || pod.UID != c.Selected.PodUID || pod.ProjectedAudience != "sts.amazonaws.com" {
					t.Fatal("exact deployed spec missing")
				}
			} else if e == nil && !sa.Deleting {
				t.Fatal("hostile identity response accepted")
			} else {
				expected := ""
				switch mode {
				case "denied", "unauthorized":
					expected = "denied"
				case "duplicate", "alias", "oversize":
					expected = "malformed"
				case "wrong-kind":
					expected = "binding_mismatch"
				}
				if expected != "" {
					assertAWSKubeFailureOutcome(t, e, "kubernetes:GetServiceAccount", expected)
				}
			}
		})
	}
}

func assertAWSKubeFailureOutcome(t *testing.T, e error, operation, expected string) {
	t.Helper()
	base := sdkContractConfig(t)
	r := &Runner{config: base}
	report := initialReport(base, "installed")
	r.authorityFailure(&report, "irsa_trust", operation, "fixed-test-target", e, false)
	failures := report.Checks[0].Observations[1].Failures
	if len(failures) != 1 || failures[0].Outcome != expected || failures[0].Operation != operation {
		t.Fatal("actual HTTP outcome lost before fixed actionable failure")
	}
}
