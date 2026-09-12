package sandboxcutover

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/testprocess"
)

// TLS and the JSON Patch boundary are real. The server is an owned Kubernetes
// fixture, not a live cluster or a production provenance verifier.
const oldAPITemplate = `{"metadata":{"annotations":{"zasp.io/schema-version":"50"},"labels":{"app":"agentsec-api"}},"spec":{"containers":[{"env":[{"name":"ZASP_RUNTIME_SESSION_INDEX","value":"zasp-runtime-sessions-v1"}],"image":"example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"api"}]}}`

type kubeFixture struct {
	t            *testing.T
	mu           sync.Mutex
	server       *httptest.Server
	config       KubernetesConfig
	deployment   map[string]any
	namespaceUID string
	patches      int
	beforePatch  func()
	status       int
	redirect     string
}

func newKubeFixture(t *testing.T) *kubeFixture {
	t.Helper()
	f := &kubeFixture{t: t, namespaceUID: "namespace-1"}
	var template map[string]any
	if err := json.Unmarshal([]byte(oldAPITemplate), &template); err != nil {
		t.Fatal(err)
	}
	f.deployment = map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "agentsec-api", "namespace": "agentsec", "uid": "api-1", "resourceVersion": "opaque:old/~", "annotations": map[string]any{"another.example/keep~me": "untouched"}, "labels": map[string]any{"keep": "value"}}, "spec": map[string]any{"replicas": float64(3), "template": template}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	b := newFixture(t).release
	b.KubernetesServer = f.server.URL
	sum := sha256.Sum256(f.server.Certificate().Raw)
	b.KubernetesCADigest = hex.EncodeToString(sum[:])
	newTemplate := strings.Replace(oldAPITemplate, "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2", 1)
	oldSum, newSum := sha256.Sum256([]byte(oldAPITemplate)), sha256.Sum256([]byte(newTemplate))
	b.From.APITemplateDigest, b.To.APITemplateDigest = hex.EncodeToString(oldSum[:]), hex.EncodeToString(newSum[:])
	f.config = KubernetesConfig{Binding: b, FromTemplateJSON: oldAPITemplate, ToTemplateJSON: newTemplate, CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})), BearerToken: "owned-fixture-token"}
	return f
}

func (f *kubeFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer owned-fixture-token" {
		f.t.Error("wrong credential")
		w.WriteHeader(401)
		return
	}
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, 307)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "GET" && r.URL.Path == "/api/v1/namespaces/agentsec" {
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "agentsec", "uid": f.namespaceUID}})
		return
	}
	if r.URL.Path != "/apis/apps/v1/namespaces/agentsec/deployments/agentsec-api" || r.URL.RawQuery != "" {
		f.t.Error("unowned request", r.Method, r.URL)
		w.WriteHeader(404)
		return
	}
	if r.Method == "GET" {
		_ = json.NewEncoder(w).Encode(f.deployment)
		return
	}
	if r.Method != "PATCH" {
		f.t.Error("unexpected method", r.Method)
		w.WriteHeader(405)
		return
	}
	f.patches++
	if f.beforePatch != nil {
		f.beforePatch()
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "code": f.status, "reason": "Conflict"})
		return
	}
	if r.Header.Get("Content-Type") != "application/json-patch+json" {
		f.t.Error("wrong patch type")
		w.WriteHeader(415)
		return
	}
	var ops []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&ops); err != nil {
		f.t.Error(err)
		w.WriteHeader(400)
		return
	}
	meta := f.deployment["metadata"].(map[string]any)
	spec := f.deployment["spec"].(map[string]any)
	// Independently enforce Kubernetes JSON Patch test semantics. A changed
	// resourceVersion or template must stop every subsequent mutation.
	position := 0
	for position < len(ops) && ops[position].Op == "test" {
		op := ops[position]
		actual := map[string]any{"/metadata/uid": meta["uid"], "/metadata/resourceVersion": meta["resourceVersion"], "/spec/template": spec["template"]}[op.Path]
		if actual == nil || !reflect.DeepEqual(op.Value, actual) {
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "code": 409, "reason": "Conflict"})
			return
		}
		position++
	}
	if position >= len(ops) || ops[position].Op != "replace" || ops[position].Path != "/spec/template" {
		f.t.Error("unbounded replacement")
		w.WriteHeader(400)
		return
	}
	annotations, _ := meta["annotations"].(map[string]any)
	for _, op := range ops[position+1:] {
		if op.Op != "add" {
			f.t.Error("unexpected annotation operation")
			w.WriteHeader(400)
			return
		}
		if op.Path == "/metadata/annotations" {
			if annotations != nil {
				f.t.Error("overwrote existing annotations")
				w.WriteHeader(400)
				return
			}
			annotations = op.Value.(map[string]any)
			continue
		}
		if !strings.HasPrefix(op.Path, "/metadata/annotations/zasp.io~1cutover-") {
			f.t.Error("unowned metadata write", op.Path)
			w.WriteHeader(400)
			return
		}
		key := strings.ReplaceAll(strings.ReplaceAll(strings.TrimPrefix(op.Path, "/metadata/annotations/"), "~1", "/"), "~0", "~")
		annotations[key] = op.Value
	}
	spec["template"] = ops[position].Value
	meta["annotations"] = annotations
	meta["resourceVersion"] = "opaque:new/~"
	_ = json.NewEncoder(w).Encode(f.deployment)
}

func (f *kubeFixture) client(t *testing.T) *KubernetesClient {
	t.Helper()
	c, err := NewKubernetes(f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}
func (f *kubeFixture) audit() Audit {
	b := f.config.Binding
	return Audit{TransitionID: "transition-1", ReleaseDigest: b.ArtifactDigest, ReceiptSetDigest: strings.Repeat("f", 64), ReceiptCount: 7, AuthorizedAt: time.Now().UTC(), DatabaseIdentity: b.DatabaseIdentity, ProviderIdentity: b.ProviderIdentity, APIUID: "api-1", SourceResourceVersion: "opaque:old/~", TargetTemplateDigest: b.To.APITemplateDigest}
}
func (f *kubeFixture) old() APIIdentity {
	return APIIdentity{"api-1", "opaque:old/~", f.config.Binding.From.APITemplateDigest}
}

func TestCutoverKubernetesCASUsesOriginalIdentity(t *testing.T) {
	for _, race := range []bool{false, true} {
		t.Run(map[bool]string{false: "applied", true: "changed-version"}[race], func(t *testing.T) {
			f := newKubeFixture(t)
			c := f.client(t)
			a := f.audit()
			if race {
				f.beforePatch = func() {
					f.deployment["metadata"].(map[string]any)["resourceVersion"] = "changed-between-read-and-patch"
				}
			}
			state, err := c.DispatchQuery(context.Background(), f.config.Binding, f.old(), a)
			if race {
				if !errors.Is(err, ErrCASRefused) {
					t.Fatal("stale CAS not refused", state, err)
				}
				return
			}
			if err != nil || !matches(state, a) || f.patches != 1 {
				t.Fatal(state, err, f.patches)
			}
			meta := f.deployment["metadata"].(map[string]any)
			if meta["annotations"].(map[string]any)["another.example/keep~me"] != "untouched" || meta["labels"].(map[string]any)["keep"] != "value" || f.deployment["spec"].(map[string]any)["replicas"] != float64(3) {
				t.Fatal("unrelated fields changed")
			}
			read, err := c.Reconcile(context.Background(), f.config.Binding, a)
			if err != nil || !matches(read, a) || f.patches != 1 {
				t.Fatal("read-only reconciliation", read, err, f.patches)
			}
		})
	}
}

func TestCutoverPinsKubernetesTransport(t *testing.T) {
	for _, fault := range []string{"wrong-ca", "wrong-server", "namespace-uid", "redirect", "replaced-binding"} {
		t.Run(fault, func(t *testing.T) {
			f := newKubeFixture(t)
			foreignCalls := 0
			foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignCalls++; w.WriteHeader(500) }))
			defer foreign.Close()
			switch fault {
			case "wrong-ca":
				f.config.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Certificate().Raw}))
				f.config.Binding.KubernetesCADigest = strings.Repeat("a", 64)
			case "wrong-server":
				f.config.Binding.KubernetesServer += "/unexpected"
			case "namespace-uid":
				f.namespaceUID = "replaced"
			case "redirect":
				f.redirect = foreign.URL
			}
			c, err := NewKubernetes(f.config)
			if err == nil {
				defer c.Close()
				b := f.config.Binding
				if fault == "replaced-binding" {
					b.KubernetesServer = foreign.URL
				}
				_, err = c.DispatchQuery(context.Background(), b, f.old(), f.audit())
			}
			if err == nil || f.patches != 0 || foreignCalls != 0 {
				t.Fatal("transport pin escaped", err, f.patches, foreignCalls)
			}
		})
	}
}

func TestCutoverKubernetesRejectsARealDifferentTrustRoot(t *testing.T) {
	f := newKubeFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "unrelated owned CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.config.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	sum := sha256.Sum256(der)
	f.config.Binding.KubernetesCADigest = hex.EncodeToString(sum[:])
	c := f.client(t)
	if _, err := c.DispatchQuery(context.Background(), f.config.Binding, f.old(), f.audit()); err == nil || f.patches != 0 {
		t.Fatal("unrelated CA trusted", err, f.patches)
	}
}

func TestCutoverKubernetesRefusesChangedTemplatesAndReadback(t *testing.T) {
	for _, fault := range []string{"old-template", "old-uid", "no-annotations", "wrong-transition", "wrong-receipt-count", "wrong-readback-uid", "wrong-readback-template"} {
		t.Run(fault, func(t *testing.T) {
			f := newKubeFixture(t)
			c := f.client(t)
			a := f.audit()
			meta := f.deployment["metadata"].(map[string]any)
			switch fault {
			case "old-template":
				f.deployment["spec"].(map[string]any)["template"].(map[string]any)["extra"] = true
			case "old-uid":
				meta["uid"] = "replacement"
			case "no-annotations":
				delete(meta, "annotations")
			}
			state, err := c.DispatchQuery(context.Background(), f.config.Binding, f.old(), a)
			if fault == "old-template" || fault == "old-uid" {
				if !errors.Is(err, ErrCASRefused) || f.patches != 0 {
					t.Fatal(state, err, f.patches)
				}
				return
			}
			if err != nil || !matches(state, a) {
				t.Fatal(state, err)
			}
			switch fault {
			case "wrong-transition":
				meta["annotations"].(map[string]any)["zasp.io/cutover-transition-id"] = "other"
			case "wrong-receipt-count":
				meta["annotations"].(map[string]any)["zasp.io/cutover-receipt-count"] = "8"
			case "wrong-readback-uid":
				meta["uid"] = "other"
			case "wrong-readback-template":
				f.deployment["spec"].(map[string]any)["template"] = map[string]any{}
			}
			state, err = c.Reconcile(context.Background(), f.config.Binding, a)
			if fault == "no-annotations" {
				if err != nil || !matches(state, a) {
					t.Fatal(state, err)
				}
			} else if err == nil {
				t.Fatal("unrelated readback credited", state)
			}
			if f.patches != 1 {
				t.Fatal("reconcile dispatched", f.patches)
			}
		})
	}
}

func TestCutoverKubernetesConstructorCannotAuthorizeOtherTemplateChanges(t *testing.T) {
	for _, fault := range []string{"other-env", "extra-container", "duplicate-selector", "noncanonical", "duplicate-key", "template-digest", "server-user", "server-query", "server-fragment", "namespace-path", "token-newline", "extra-ca"} {
		t.Run(fault, func(t *testing.T) {
			f := newKubeFixture(t)
			c := f.config
			switch fault {
			case "other-env":
				c.ToTemplateJSON = strings.Replace(c.ToTemplateJSON, `"name":"api"`, `"name":"changed"`, 1)
			case "extra-container":
				c.ToTemplateJSON = strings.Replace(c.ToTemplateJSON, `"name":"api"}]`, `"name":"api"},{"name":"other"}]`, 1)
			case "duplicate-selector":
				c.ToTemplateJSON = strings.Replace(c.ToTemplateJSON, `"env":[`, `"env":[{"name":"ZASP_RUNTIME_SESSION_INDEX","value":"zasp-runtime-sessions-v2"},`, 1)
			case "noncanonical":
				c.ToTemplateJSON += "\n"
			case "duplicate-key":
				c.ToTemplateJSON = strings.Replace(c.ToTemplateJSON, `"name":"api"`, `"name":"wrong","name":"api"`, 1)
			case "template-digest":
				c.Binding.To.APITemplateDigest = strings.Repeat("0", 64)
			case "server-user":
				c.Binding.KubernetesServer = strings.Replace(c.Binding.KubernetesServer, "https://", "https://user@", 1)
			case "server-query":
				c.Binding.KubernetesServer += "?x=1"
			case "server-fragment":
				c.Binding.KubernetesServer += "#x"
			case "namespace-path":
				c.Binding.Namespace = "../foreign"
			case "token-newline":
				c.BearerToken += "\n"
			case "extra-ca":
				c.CAPEM += c.CAPEM
			}
			if fault != "template-digest" {
				sum := sha256.Sum256([]byte(c.ToTemplateJSON))
				c.Binding.To.APITemplateDigest = hex.EncodeToString(sum[:])
			}
			client, err := NewKubernetes(c)
			if err == nil {
				client.Close()
				t.Fatal("invalid config authorized", fault)
			}
		})
	}
}

func TestCutoverKubernetesLatePersistenceIsIndeterminate(t *testing.T) {
	f := newKubeFixture(t)
	f.deployment["metadata"].(map[string]any)["resourceVersion"] = "opaque-version"
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	original := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			original.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		close(entered)
		<-release
		original.ServeHTTP(w, r)
		close(finished)
	})
	c := f.client(t)
	core := newFixture(t)
	core.release = f.config.Binding
	deps := core.deps()
	deps.Kubernetes = c
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	result := make(chan Result, 1)
	go func() { result <- ExecuteSandboxQueryCutover(ctx, Request{"approved-fixture"}, deps) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("PATCH never arrived")
	}
	var r Result
	select {
	case r = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("timed-out invocation did not return")
	}
	if r.Outcome != Indeterminate || !r.CleanupConfirmed || core.cleanup != 1 {
		t.Fatal("timeout hid uncertain application or cleanup", r, core.cleanup)
	}
	unblock()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("released server request did not finish")
	}
	read, err := c.Reconcile(context.Background(), f.config.Binding, r.Audit)
	if err != nil || !matches(read, r.Audit) || f.patches != 1 {
		t.Fatal("late persistence not reconciled read-only", read, err, f.patches)
	}
}

func TestCutoverKubernetesDelayedPersistenceOverlap(t *testing.T) {
	for _, winner := range []int{0, 1} {
		t.Run(strconv.Itoa(winner), func(t *testing.T) {
			f := newKubeFixture(t)
			c := f.client(t)
			entered := make(chan int, 2)
			release := []chan struct{}{make(chan struct{}), make(chan struct{})}
			releaseOnce := []sync.Once{{}, {}}
			unblock := func(i int) { releaseOnce[i].Do(func() { close(release[i]) }) }
			t.Cleanup(func() { unblock(0); unblock(1) })
			done := make(chan int, 2)
			var gateMu sync.Mutex
			calls := 0
			original := f.server.Config.Handler
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PATCH" {
					original.ServeHTTP(w, r)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				gateMu.Lock()
				index := calls
				calls++
				gateMu.Unlock()
				if index >= 2 {
					t.Error("mutation retried")
					w.WriteHeader(500)
					return
				}
				entered <- index
				<-release[index]
				original.ServeHTTP(w, r)
				done <- index
			})
			a := f.audit()
			b := a
			b.TransitionID = "transition-2"
			b.ReceiptSetDigest = strings.Repeat("9", 64)
			for _, audit := range []Audit{a, b} {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				_, err := c.DispatchQuery(ctx, f.config.Binding, f.old(), audit)
				cancel()
				if err == nil {
					t.Fatal("paused PATCH appeared applied")
				}
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("PATCH never reached overlap gate")
				}
			}
			unblock(winner)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("winner did not finish")
			}
			unblock(1 - winner)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("loser did not finish")
			}
			for index, audit := range []Audit{a, b} {
				state, err := c.Reconcile(context.Background(), f.config.Binding, audit)
				if index == winner {
					if err != nil || !matches(state, audit) {
						t.Fatal("winner not proven", state, err)
					}
				} else if err == nil {
					t.Fatal("loser credited winner", state)
				}
			}
			if f.patches != 2 {
				t.Fatal("must have two invocations, two attempts, one applied CAS", f.patches)
			}
		})
	}
}

func TestCutoverKubernetesMalformedReadAndClosedClientNeverPatch(t *testing.T) {
	for _, fault := range []string{"duplicate-key", "oversized", "wrong-kind", "closed", "canceled", "slow-read"} {
		t.Run(fault, func(t *testing.T) {
			f := newKubeFixture(t)
			c := f.client(t)
			original := f.server.Config.Handler
			if fault != "closed" && fault != "canceled" {
				f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "GET" || !strings.Contains(r.URL.Path, "/deployments/") {
						original.ServeHTTP(w, r)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					switch fault {
					case "duplicate-key":
						_, _ = io.WriteString(w, `{"apiVersion":"wrong","apiVersion":"apps/v1","kind":"Deployment"}`)
					case "oversized":
						// Otherwise valid Deployment, so malformed JSON cannot mask
						// the response allocation bound under test.
						f.deployment["metadata"].(map[string]any)["annotations"].(map[string]any)["example/large"] = strings.Repeat("x", 4<<20)
						_ = json.NewEncoder(w).Encode(f.deployment)
					case "wrong-kind":
						_, _ = io.WriteString(w, `{"apiVersion":"apps/v1","kind":"Secret"}`)
					case "slow-read":
						<-r.Context().Done()
					}
				})
			}
			timeout := 2 * time.Second
			if fault == "slow-read" {
				timeout = 50 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if fault == "closed" {
				c.Close()
				c.Close()
			}
			if fault == "canceled" {
				cancel()
			}
			_, err := c.DispatchQuery(ctx, f.config.Binding, f.old(), f.audit())
			if !errors.Is(err, ErrCASRefused) || f.patches != 0 {
				t.Fatal("preflight fault reached PATCH", err, f.patches)
			}
		})
	}
}

func TestCutoverKubernetesCloseCancelsOwnedActiveRead(t *testing.T) {
	f := newKubeFixture(t)
	c := f.client(t)
	entered, finished := make(chan struct{}), make(chan struct{})
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(finished) })
	done := make(chan error, 1)
	go func() {
		_, err := c.DispatchQuery(context.Background(), f.config.Binding, f.old(), f.audit())
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("read never entered")
	}
	c.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrCASRefused) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel active request")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("HTTP handler did not observe cancellation")
	}
}

func TestCutoverKubernetesAcceptsActualRenderedTemplates(t *testing.T) {
	// This command owns and joins Node/Helm descendants. It produces templates,
	// not an approval record; the test's release verifier remains a fixture.
	for _, program := range []string{"node", "helm"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Skip("explicit rendered-template fixture requires node and helm")
		}
	}
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	program := `import {renderRelease} from './deploy/production/release-contract.mjs';
import {productionReleaseFixture} from './deploy/production/release-fixture.mjs';
import {templateDigest} from './deploy/production/compatibility-observation.mjs';
const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const templates=[];
for(const phase of ['backfill','query']){const rows=await renderRelease(productionReleaseFixture,{schemaVersion:50,sessionSearchPhase:phase});templates.push(rows.find(x=>x.kind==='Deployment'&&x.metadata.name==='agentsec-api').spec.template);}
const outputs=[];
for(const unicode of [false,true]){const pair=structuredClone(templates);if(unicode){for(const value of pair)value.metadata.annotations['example/unicode']='line\u2028paragraph\u2029<literal>\\u2028';}outputs.push(pair.map(value=>({body:JSON.stringify(stable(value)),digest:templateDigest(value)})));}
process.stdout.write(JSON.stringify(outputs));`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.Command("node", "--input-type=module", "-e", program)
	command.Dir = root
	body, err := testprocess.Run(ctx, command)
	if err != nil {
		t.Fatal("owned render command", err, string(body))
	}
	var pairs [][]struct{ Body, Digest string }
	if err := json.Unmarshal(body, &pairs); err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 2 {
		t.Fatal("missing render variants")
	}
	for i, pair := range pairs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if len(pair) != 2 {
				t.Fatal("missing phases")
			}
			f := newKubeFixture(t)
			f.config.FromTemplateJSON = pair[0].Body
			f.config.ToTemplateJSON = pair[1].Body
			f.config.Binding.From.APITemplateDigest = pair[0].Digest
			f.config.Binding.To.APITemplateDigest = pair[1].Digest
			var actual map[string]any
			if err := json.Unmarshal([]byte(pair[0].Body), &actual); err != nil {
				t.Fatal(err)
			}
			f.deployment["spec"].(map[string]any)["template"] = actual
			c := f.client(t)
			a := f.audit()
			state, err := c.DispatchQuery(context.Background(), f.config.Binding, f.old(), a)
			if err != nil || !matches(state, a) {
				t.Fatal("actual rendered templates rejected", state, err)
			}
		})
	}
}
