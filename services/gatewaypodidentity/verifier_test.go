package gatewaypodidentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const clusterUID = "11111111-1111-1111-1111-111111111111"
const saUID = "22222222-2222-2222-2222-222222222222"
const podUID = "33333333-3333-3333-3333-333333333333"
const rsUID = "44444444-4444-4444-4444-444444444444"
const deploymentUID = "55555555-5555-5555-5555-555555555555"
const nodeUID = "66666666-6666-6666-6666-666666666666"
const bootID = "77777777-7777-7777-7777-777777777777"

var paths = []string{"/api/v1/namespaces/kube-system", "/api/v1/namespaces/team/serviceaccounts/agent.sa", "/api/v1/namespaces/team/pods/agent.pod", "/apis/apps/v1/namespaces/team/replicasets/agent-rs", "/apis/apps/v1/namespaces/team/deployments/agent", "/api/v1/nodes/worker"}

type fixture struct {
	server        *httptest.Server
	config        Config
	token         string
	mu            sync.Mutex
	calls         []string
	protocolError string
	mutate        func(int, string, map[string]any) []byte
	status        int
	delay         time.Duration
}

func metadata(name, ns, uid string) map[string]any {
	m := map[string]any{"name": name, "uid": uid, "resourceVersion": "1", "labels": map[string]any{"unrelated": "allowed"}}
	if ns != "" {
		m["namespace"] = ns
	}
	return m
}
func owner(kind, name, uid string) []any {
	return []any{map[string]any{"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": true, "blockOwnerDeletion": true}}
}
func object(path string) map[string]any {
	o := map[string]any{"apiVersion": "v1", "status": map[string]any{}, "spec": map[string]any{}}
	switch path {
	case paths[0]:
		o["kind"] = "Namespace"
		o["metadata"] = metadata("kube-system", "", clusterUID)
	case paths[1]:
		o["kind"] = "ServiceAccount"
		o["metadata"] = metadata("agent.sa", "team", saUID)
	case paths[2]:
		o["kind"] = "Pod"
		o["status"] = map[string]any{"phase": "Running"}
		m := metadata("agent.pod", "team", podUID)
		m["ownerReferences"] = owner("ReplicaSet", "agent-rs", rsUID)
		o["metadata"] = m
		o["spec"] = map[string]any{"serviceAccountName": "agent.sa", "nodeName": "worker", "containers": []any{}}
	case paths[3]:
		o["apiVersion"] = "apps/v1"
		o["kind"] = "ReplicaSet"
		m := metadata("agent-rs", "team", rsUID)
		m["ownerReferences"] = owner("Deployment", "agent", deploymentUID)
		o["metadata"] = m
		o["spec"] = map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "agent.sa"}}}
	case paths[4]:
		o["apiVersion"] = "apps/v1"
		o["kind"] = "Deployment"
		m := metadata("agent", "team", deploymentUID)
		m["labels"] = map[string]any{"zasp.ai/entity-kind": "agent"}
		o["metadata"] = m
		o["spec"] = map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "agent.sa"}}}
	case paths[5]:
		o["kind"] = "Node"
		o["metadata"] = metadata("worker", "", nodeUID)
		o["status"] = map[string]any{"nodeInfo": map[string]any{"bootID": bootID, "kernelVersion": "allowed"}}
	}
	return o
}
func jwt(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString([]byte("provider-authenticated-signature"))
}
func projectedToken(exp int64) string {
	return jwt(fmt.Sprintf(`{"iss":"https://issuer.example/cluster","aud":["zasp-gateway"],"sub":"system:serviceaccount:team:agent.sa","exp":%d,"kubernetes.io":{"namespace":"team","serviceaccount":{"name":"agent.sa","uid":%q},"pod":{"name":"agent.pod","uid":%q}}}`, exp, saUID, podUID))
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{token: projectedToken(time.Now().Add(time.Hour).Unix())}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.URL.Path)
		n := len(f.calls)
		if r.Header.Get("Authorization") != "Bearer fixture-reviewer" {
			f.protocolError = "missing reviewer authentication"
		}
		var o map[string]any
		if n == 1 {
			if r.Method != "POST" || r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
				f.protocolError = "TokenReview not first"
			}
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 65537))
			var request struct {
				APIVersion, Kind string
				Spec             struct {
					Token     string
					Audiences []string
				}
			}
			if json.Unmarshal(raw, &request) != nil || request.APIVersion != "authentication.k8s.io/v1" || request.Kind != "TokenReview" || request.Spec.Token != f.token || len(request.Spec.Audiences) != 1 || request.Spec.Audiences[0] != "zasp-gateway" {
				f.protocolError = "wrong TokenReview request"
			}
			o = map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": map[string]any{"token": f.token}, "status": map[string]any{"authenticated": true, "audiences": []string{"zasp-gateway"}, "user": map[string]any{"username": "system:serviceaccount:team:agent.sa", "uid": saUID, "groups": []string{"system:authenticated"}, "extra": map[string]any{"authentication.kubernetes.io/pod-name": []string{"agent.pod"}, "authentication.kubernetes.io/pod-uid": []string{podUID}}}}}
		} else {
			if n > 13 || r.Method != "GET" || r.URL.Path != paths[(n-2)%6] {
				f.protocolError = "unexpected identity request"
			}
			o = object(r.URL.Path)
		}
		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-r.Context().Done():
				return
			}
		}
		var raw []byte
		if f.mutate != nil {
			raw = f.mutate(n, r.URL.Path, o)
		}
		if raw == nil {
			raw, _ = json.Marshal(o)
		}
		w.Header().Set("Content-Type", "application/json")
		if f.status != 0 {
			w.WriteHeader(f.status)
		}
		_, _ = w.Write(raw)
	}))
	t.Cleanup(f.server.Close)
	file := filepath.Join(t.TempDir(), "reviewer")
	if err := os.WriteFile(file, []byte("fixture-reviewer"), 0600); err != nil {
		t.Fatal(err)
	}
	f.config = Config{IntegrationID: "pid_88888888-8888-4888-8888-888888888888", Endpoint: f.server.URL, CABundlePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), AllowedCIDRs: []string{"127.0.0.0/8"}, ClusterUID: clusterUID, Issuer: "https://issuer.example/cluster", Audience: "zasp-gateway", Namespace: "team", ReviewerCredentialFile: file}
	return f
}
func (f *fixture) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }
func (f *fixture) verify(t *testing.T, ctx context.Context) (VerifiedPod, error) {
	t.Helper()
	v, err := New(f.config)
	if err != nil {
		t.Fatalf("configured verifier: %v", err)
	}
	defer v.Close()
	sum := sha256.Sum256(nil)
	proof, err := NewProof([]byte(f.token), RequestBinding{RequestID: "pid_99999999-9999-4999-8999-999999999999", Method: "POST", ExactTarget: "/v1/tools?mode=read", BodySHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	return v.Verify(ctx, proof)
}

func TestProjectedPodIdentityThirteenCallChain(t *testing.T) {
	f := newFixture(t)
	f.mutate = func(n int, p string, o map[string]any) []byte {
		if n > 7 {
			o["metadata"].(map[string]any)["resourceVersion"] = "changed"
		}
		return nil
	}
	start := time.Now()
	got, err := f.verify(t, context.Background())
	if err != nil {
		t.Fatalf("valid actual HTTPS chain: %v", err)
	}
	if f.count() != 13 || f.protocolError != "" {
		t.Fatalf("calls=%d protocol=%s", f.count(), f.protocolError)
	}
	if got.Profile != Profile || got.IntegrationID != f.config.IntegrationID || got.ClusterUID != clusterUID || got.Namespace != "team" || got.ServiceAccountName != "agent.sa" || got.ServiceAccountUID != saUID || got.PodName != "agent.pod" || got.PodUID != podUID || got.ReplicaSetUID != rsUID || got.DeploymentUID != deploymentUID || got.NodeUID != nodeUID || got.BootID != bootID {
		t.Fatalf("incorrect verified facts: %+v", got)
	}
	if got.ObservedAt.Before(start.Truncate(time.Microsecond)) || got.ObservedAt.After(time.Now()) || got.ObservedAt.Nanosecond()%1000 != 0 || got.ExpiresAt != got.ObservedAt.Add(5*time.Second) || got.TokenExpiresAt.Unix() <= time.Now().Unix() || len(got.FactsSHA256) != 64 {
		t.Fatalf("invalid observation validity: %+v", got)
	}
	// No positive cache: a second proof must authenticate and read all facts again.
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	if _, err = f.verify(t, context.Background()); err != nil || f.count() != 13 {
		t.Fatalf("second verification skipped provider: %v %d", err, f.count())
	}
}
func TestProjectedPodIdentityAuthenticatedClaimsAndJSON(t *testing.T) {
	for _, mode := range []string{"unauthenticated", "audience", "extra", "review-duplicate", "review-alias", "review-utf", "expired", "jwt-duplicate", "jwt-surrogate", "jwt-sa", "jwt-padding", "jwt-issuer", "jwt-audience", "review-audience-string", "jwt-exp-overflow"} {
		f := newFixture(t)
		if mode == "jwt-exp-overflow" {
			f.token = projectedToken(253402300800)
		}
		if mode == "expired" {
			f.token = projectedToken(time.Now().Add(-time.Second).Unix())
		}
		if mode == "jwt-duplicate" {
			f.token = jwt(`{"exp":1,"exp":2}`)
		}
		if mode == "jwt-surrogate" {
			f.token = jwt(`{"sub":"\ud800","exp":9999999999}`)
		}
		if mode == "jwt-sa" {
			payload := fmt.Sprintf(`{"sub":"system:serviceaccount:team:other","exp":%d}`, time.Now().Add(time.Hour).Unix())
			f.token = jwt(payload)
		}
		if mode == "jwt-issuer" || mode == "jwt-audience" {
			raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(f.token, ".")[1])
			text := string(raw)
			if mode == "jwt-issuer" {
				text = strings.ReplaceAll(text, "issuer.example", "other.example")
			} else {
				text = strings.ReplaceAll(text, "zasp-gateway", "wrong-audience")
			}
			f.token = jwt(text)
		}
		if mode == "jwt-padding" {
			f.token += "="
		}
		f.mutate = func(n int, p string, o map[string]any) []byte {
			if n != 1 {
				return nil
			}
			s := o["status"].(map[string]any)
			switch mode {
			case "unauthenticated":
				s["authenticated"] = false
			case "review-audience-string":
				s["audiences"] = "zasp-gateway"
			case "audience":
				s["audiences"] = []string{"other"}
			case "extra":
				s["user"].(map[string]any)["extra"] = map[string]any{}
			case "review-duplicate":
				return []byte(`{"status":{},"status":{}}`)
			case "review-alias":
				return []byte(`{"status":{},"Status":{}}`)
			case "review-utf":
				return []byte{'{', '"', 'x', '"', ':', '"', 255, '"', '}'}
			}
			return nil
		}
		_, err := f.verify(t, context.Background())
		if err == nil || f.count() != 1 {
			t.Fatalf("%s accepted or read unauthenticated identities: %v calls=%d", mode, err, f.count())
		}
		f.server.Close()
	}
}
func TestProjectedPodIdentityCurrentOwnershipAndDoubleRead(t *testing.T) {
	for _, mode := range []string{"cluster", "sa", "pod-owner", "rs-owner", "label", "template-sa", "nodeboot", "pod-delete", "second-label", "second-node", "second-sa", "second-pod", "pod-not-running", "second-not-running"} {
		f := newFixture(t)
		f.mutate = func(n int, p string, o map[string]any) []byte {
			if n == 1 {
				return nil
			}
			m := o["metadata"].(map[string]any)
			switch {
			case mode == "pod-not-running" && n == 4 || mode == "second-not-running" && n == 10:
				o["status"].(map[string]any)["phase"] = "Pending"
			case mode == "cluster" && n == 2:
				m["uid"] = nodeUID
			case mode == "sa" && n == 3:
				m["uid"] = nodeUID
			case mode == "pod-owner" && n == 4:
				m["ownerReferences"] = []any{}
			case mode == "rs-owner" && n == 5:
				m["ownerReferences"] = owner("Deployment", "agent", nodeUID)
			case mode == "label" && n == 6:
				m["labels"] = map[string]any{}
			case mode == "template-sa" && n == 6:
				o["spec"].(map[string]any)["template"] = map[string]any{"spec": map[string]any{"serviceAccountName": "other"}}
			case mode == "nodeboot" && n == 7:
				o["status"].(map[string]any)["nodeInfo"] = map[string]any{"bootID": ""}
			case mode == "pod-delete" && n == 4:
				m["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
			case mode == "second-label" && n == 12:
				m["labels"] = map[string]any{}
			case mode == "second-node" && n == 13:
				m["uid"] = saUID
			case mode == "second-sa" && n == 9:
				m["uid"] = nodeUID
			case mode == "second-pod" && n == 10:
				o["spec"].(map[string]any)["nodeName"] = "other"
			}
			return nil
		}
		if _, err := f.verify(t, context.Background()); err == nil || f.count() > 13 {
			t.Fatalf("%s accepted or over budget", mode)
		}
		f.server.Close()
	}
}
func TestProjectedPodIdentityTransportBoundsAndDeadline(t *testing.T) {
	for _, mode := range []string{"redirect", "review-oversize", "object-oversize", "deadline", "cidr", "ca"} {
		f := newFixture(t)
		switch mode {
		case "redirect":
			f.status = 302
		case "review-oversize":
			f.mutate = func(n int, p string, o map[string]any) []byte {
				if n == 1 {
					return []byte(strings.Repeat(" ", 65537))
				}
				return nil
			}
		case "object-oversize":
			f.mutate = func(n int, p string, o map[string]any) []byte {
				if n == 2 {
					return []byte(strings.Repeat(" ", (1<<20)+1))
				}
				return nil
			}
		case "deadline":
			f.delay = 100 * time.Millisecond
		case "cidr":
			f.config.AllowedCIDRs = []string{"192.0.2.0/24"}
		case "ca":
			// Keep endpoint, hostname, CIDRs and server certificate identical to
			// the passing chain: only the configured trust anchor changes.
			pub, key, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now()
			ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
			if e != nil {
				t.Fatal(e)
			}
			f.config.CABundlePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		ctx := context.Background()
		cancel := func() {}
		if mode == "deadline" {
			ctx, cancel = context.WithTimeout(ctx, 20*time.Millisecond)
		}
		start := time.Now()
		_, err := f.verify(t, ctx)
		cancel()
		if err == nil || time.Since(start) > 5*time.Second || f.count() > 13 {
			t.Fatalf("%s transport guard: %v", mode, err)
		}
		if mode == "cidr" && f.count() != 0 {
			t.Fatal("CIDR refused after sending credential")
		}
		f.server.Close()
	}
}
func TestProjectedPodIdentitySecretReadinessAndLifecycle(t *testing.T) {
	var zero Verifier
	if e := zero.Close(); e != nil {
		t.Fatal(e)
	}
	if e := zero.Ready(context.Background()); e == nil {
		t.Fatal("zero verifier ready")
	}
	f := newFixture(t)
	badCA := f.config
	badCA.CABundlePEM = append([]byte("unexpected-prefix\n"), f.config.CABundlePEM...)
	if _, e := New(badCA); e == nil {
		t.Fatal("CA prefix accepted")
	}
	v, err := New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err = v.Ready(context.Background()); err != nil || f.count() != 0 {
		t.Fatalf("local readiness: %v", err)
	}
	proof, err := NewProof([]byte(f.token), RequestBinding{RequestID: "pid_99999999-9999-4999-8999-999999999999", Method: "GET", ExactTarget: "/", BodySHA256: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprint(proof), fmt.Sprintf("%#v", proof), fmt.Sprintf("%+v", proof)} {
		if strings.Contains(s, f.token) || strings.Contains(s, "provider-authenticated") {
			t.Fatal("proof disclosed token")
		}
	}
	if err = os.Chmod(f.config.ReviewerCredentialFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(context.Background(), proof); err == nil || f.count() != 0 {
		t.Fatal("unprotected reviewer credential used")
	}
	if err = os.Chmod(f.config.ReviewerCredentialFile, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.config.ReviewerCredentialFile, []byte("rotated-reviewer"), 0600); err != nil {
		t.Fatal(err)
	}
	f.mutate = func(n int, p string, o map[string]any) []byte {
		if n == 1 {
			o["status"].(map[string]any)["authenticated"] = false
		}
		return nil
	}
	_, _ = v.Verify(context.Background(), proof)
	if f.protocolError != "missing reviewer authentication" {
		t.Fatal("reviewer rotation was cached")
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	before := f.count()
	if _, err = v.Verify(context.Background(), proof); err == nil || f.count() != before {
		t.Fatal("closed verifier performed provider IO")
	}
}
