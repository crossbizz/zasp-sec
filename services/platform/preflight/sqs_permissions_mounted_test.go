package preflight

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/aws/aws-sdk-go-v2/aws"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sqsMountedReader struct {
	*awsAuthorityFixtureReader
	actual *awsKubernetesIdentityReader
}

func (r *sqsMountedReader) Pod(ctx context.Context, ns, name string) (KubernetesWorkloadBinding, error) {
	return r.actual.Pod(ctx, ns, name)
}
func (r *sqsMountedReader) SQSWorkload(ctx context.Context, s AWSSelectedWorkload) (sqsPermissionWorkload, error) {
	return r.actual.SQSWorkload(ctx, s)
}

type sqsMountedTransport struct {
	base                                               *awsAuthorityFixtureTransport
	simulation                                         *sqsSimulationTransport
	ca                                                 []byte
	mode                                               string
	inspectorIdentities, selectedIdentities, exchanges int
}

func (tr *sqsMountedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	raw := []byte{}
	if req.Body != nil {
		raw, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(raw))
	}
	form, _ := url.ParseQuery(string(raw))
	op := form.Get("Action")
	if op == "SimulatePrincipalPolicy" {
		if !strings.Contains(req.Header.Get("Authorization"), "fixture-inspector-key") {
			return nil, ErrRejected
		}
		return tr.simulation.RoundTrip(req)
	}
	if op == "AssumeRoleWithWebIdentity" {
		tr.exchanges++
	}
	if op == "GetCallerIdentity" {
		if strings.Contains(req.Header.Get("Authorization"), "fixture-workload-key") {
			tr.selectedIdentities++
			answer := `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/selected-worker/actual-run</Arn><UserId>fixture</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/xml"}}, Body: io.NopCloser(strings.NewReader(answer)), Request: req}, nil
		}
		tr.inspectorIdentities++
	}
	// Existing queue metadata is a separate SDK action, never an application job.
	if strings.HasSuffix(req.Header.Get("X-Amz-Target"), "GetQueueAttributes") {
		return (&sdkContractTransport{}).RoundTrip(req)
	}
	out, e := tr.base.RoundTrip(req)
	if e != nil {
		return out, e
	}
	if req.URL.Path == "/clusters/preflight" {
		body, _ := io.ReadAll(out.Body)
		out.Body.Close()
		var v map[string]any
		_ = json.Unmarshal(body, &v)
		v["cluster"].(map[string]any)["certificateAuthority"] = map[string]string{"data": base64.StdEncoding.EncodeToString(tr.ca)}
		body, _ = json.Marshal(v)
		out.Body = io.NopCloser(bytes.NewReader(body))
	}
	return out, nil
}
func TestSQSMountedSameInvocationPermissionDiagnosticsNeverProveQueueAuthority(t *testing.T) {
	for _, mode := range []string{"allow", "explicit-deny", "implicit-deny", "truncated", "http-denied", "missing-inspector", "missing-selected-exchange", "wrong-pod-uid", "indirect-queue", "unrelated-secret-ref", "disabled-diagnostic"} {
		t.Run(mode, func(t *testing.T) {
			c := sdkContractConfig(t)
			authority, k, base := awsAuthorityFixtureConfig(t)
			selected := AWSSelectedWorkload{Purpose: "aws_iam_role.outbox", PodName: "selected-pod", PodUID: "33333333-3333-4333-8333-333333333333"}
			authority.Selected = &selected
			role := "arn:aws:iam::123456789012:role/selected-worker"
			for i, b := range authority.Roles {
				if b.Purpose == selected.Purpose {
					delete(base.roles, b.RoleARN[strings.LastIndex(b.RoleARN, "/")+1:])
					authority.Roles[i].RoleARN = role
					k.bindings[b.Purpose] = role
					base.roles["selected-worker"] = b.Purpose
				}
			}
			c.AWSAuthority = authority
			c.AWS.Buckets = nil
			c.AWS.Secrets = nil
			c.Credentials = CredentialConfig{Kind: "workload_web_identity", ExpectedRoleARN: role, TokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", Namespace: "agentsec", ServiceAccount: "zasp-outbox-publisher"}
			image := "registry.example/worker@sha256:" + strings.Repeat("a", 64)
			c.SQSPermissions = &SQSConfig{Image: image}
			if mode == "disabled-diagnostic" {
				c.SQSPermissions = nil
			}
			q := c.AWS.Queues[0]
			q.Purpose = "producer"
			c.AWS.Queues = []Queue{q}
			calls := 0
			forbidden := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls++
				if req.Method != "GET" || req.URL.Path != "/api/v1/namespaces/agentsec/pods/selected-pod" || req.Header.Get("Authorization") != "Bearer fixture-kube-token" {
					forbidden = true
					w.WriteHeader(403)
					return
				}
				uid := selected.PodUID
				if mode == "wrong-pod-uid" {
					uid = "44444444-4444-4444-8444-444444444444"
				}
				queue := map[string]any{"name": "ZASP_DISCOVERY_QUEUE_URL", "value": q.URL}
				if mode == "indirect-queue" {
					delete(queue, "value")
					queue["valueFrom"] = map[string]any{"secretKeyRef": map[string]string{"name": "private", "key": "queue"}}
				}
				env := []any{map[string]string{"name": "ZASP_WORKER_MODE", "value": "outbox"}, queue}
				if mode == "unrelated-secret-ref" {
					env = append(env, map[string]any{"name": "ZASP_POSTGRES_DSN", "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "private", "key": "dsn"}}})
				}
				pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]string{"name": selected.PodName, "namespace": "agentsec", "uid": uid}, "spec": map[string]any{"serviceAccountName": "zasp-outbox-publisher", "containers": []any{map[string]any{"name": "outbox-publisher", "image": image, "env": env}}, "volumes": []any{map[string]any{"name": "aws-token", "projected": map[string]any{"sources": []any{map[string]any{"serviceAccountToken": map[string]string{"audience": "sts.amazonaws.com"}}}}}}}, "status": map[string]string{"phase": "Running"}}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(pod)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			sum := sha256.Sum256(ca)
			authority.Cluster.CASHA256 = hex.EncodeToString(sum[:])
			dir := t.TempDir()
			caFile := filepath.Join(dir, "ca.pem")
			tokenFile := filepath.Join(dir, "token")
			if os.WriteFile(caFile, ca, 0600) != nil || os.WriteFile(tokenFile, []byte("fixture-kube-token"), 0600) != nil {
				t.Fatal("private explicit Kubernetes fixture files unavailable")
			}
			c.Kubernetes = &KubernetesAuthority{Endpoint: authority.Cluster.Endpoint, CAFile: caFile, ClusterUID: authority.Cluster.ClusterUID, Credentials: KubernetesCredentials{Kind: "explicit_bearer_file", TokenFile: tokenFile}}

			base.target = authority.Cluster
			t.Setenv("AWS_ACCESS_KEY_ID", "fixture-inspector-key")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-inspector-secret")
			t.Setenv("AWS_SESSION_TOKEN", "")
			if mode == "missing-inspector" {
				t.Setenv("AWS_ACCESS_KEY_ID", "")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "")
			}
			simulationMode := mode
			if mode == "allow" || mode == "unrelated-secret-ref" {
				simulationMode = "allow-template"
			}
			tr := &sqsMountedTransport{base: base, simulation: &sqsSimulationTransport{mode: simulationMode}, ca: ca, mode: mode}
			r, e := NewRunner(c)
			if e != nil {
				t.Fatal("valid mounted fixture configuration rejected")
			}
			defer r.Close()
			r.http = &http.Client{Transport: tr}
			report, e := r.runWithAuthorities(context.Background(), "installed", func() (KubernetesIdentityReader, func()) {
				local := *authority
				local.Cluster.Endpoint = server.URL
				actual, err := newAWSKubernetesIdentityReader(server.URL, ca, func(context.Context) ([]byte, error) { return privateFile(tokenFile, 16384) }, &local, requiredAWSRoleInventory(true))
				if err != nil {
					t.Fatal("private same-loop protocol opener failed")
				}
				return &sqsMountedReader{awsAuthorityFixtureReader: k, actual: actual}, actual.Close
			}, func(ctx context.Context) (aws.Credentials, *awsWebIdentityProof, error) {
				if mode == "missing-selected-exchange" {
					return aws.Credentials{}, nil, ErrRejected
				}
				return r.exchangeAWSWebIdentity(ctx, role, []byte(strings.Repeat("opaque_fixture_token_", 8)))
			})
			if e == nil || report.Ready || report.ProductionEndToEndVerified || len(report.Checks) != 8 || forbidden || base.forbidden || tr.simulation.invalid {
				t.Fatal("diagnostic escaped original scope or became production readiness")
			}
			diagnostic := report.Checks[2].PermissionDiagnostic
			if mode == "disabled-diagnostic" {
				if diagnostic != nil || tr.simulation.calls != 0 {
					t.Fatal("disabled diagnostic made calls")
				}
				return
			}
			if diagnostic == nil || diagnostic.EffectiveAuthorityObserved {
				t.Fatal("mounted diagnostic absent or became effective queue permission proof")
			}
			permission := report.Checks[2].Observations[2]
			if permission.Status == "pass" {
				t.Fatal("simulator allowed original unexercised queue permissions")
			}
			attempted := mode == "allow" || mode == "unrelated-secret-ref" || mode == "explicit-deny" || mode == "implicit-deny" || mode == "truncated" || mode == "http-denied"
			if attempted && (diagnostic.AuthorityObservation == nil || diagnostic.AuthorityObservation.IdentityKind != "operator-kubernetes") {
				t.Fatal("explicit operator Kubernetes bearer was mislabeled as selected AWS workload authority")
			}
			if attempted {
				if tr.simulation.calls != 1 || tr.inspectorIdentities != 1 || tr.exchanges != 1 || tr.selectedIdentities != 1 || calls != 2 {
					t.Fatal("same invocation inspector/exchange/actualPod recipe absent or duplicated")
				}
				o := diagnostic.Observation
				if o.ObservedAt == nil || o.Kind != "provider-read" {
					t.Fatal("actual simulation read lost attempt metadata")
				}
				switch mode {
				case "allow", "unrelated-secret-ref":
					if len(diagnostic.Decisions) != 2 || diagnostic.Decisions[0].Decision != "allowed" || o.Code != "simulated_identity_policy_only" {
						t.Fatal("complete simulation decision not reported separately")
					}
				case "explicit-deny", "implicit-deny":
					if len(diagnostic.Decisions) != 2 || o.Code != "simulated_action_denied" || o.Status != "fail" {
						t.Fatal("exact denied action diagnosis lost")
					}
				case "truncated":
					if len(diagnostic.Decisions) != 0 || o.Code != "simulation_indeterminate" {
						t.Fatal("truncated results became complete permission evidence")
					}
				case "http-denied":
					if len(o.Failures) != 1 || o.Failures[0].Operation != "iam:SimulatePrincipalPolicy" || o.Failures[0].Outcome != "denied" {
						t.Fatal("actual permission denied response misclassified")
					}
				}
			} else {
				if tr.simulation.calls != 0 || len(diagnostic.Decisions) != 0 || diagnostic.Observation.ObservedAt != nil {
					t.Fatal("unverified authority manufactured simulation observation")
				}
			}
			b, _ := json.Marshal(report)
			for _, secret := range []string{"fixture-inspector-secret", "fixture-workload-secret", "fixture-kube-token", "DO_NOT_REFLECT_POLICY_TEXT", "ZASP_POSTGRES_DSN"} {
				if strings.Contains(string(b), secret) {
					t.Fatal("private authority or unrelated env leaked")
				}
			}
		})
	}
}
