package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery/neondriver"
)

const recoveryKubernetesSourcePostgresDSN = "postgres" + "://recovery:secret@ep-main.us-west-2.aws.neon.tech/zasp?sslmode=verify-full"

type recoveryKubernetesTransportCall struct {
	Method string
	Path   string
	Body   []byte
}

type recoveryKubernetesTransportFake struct {
	mu      sync.Mutex
	calls   []recoveryKubernetesTransportCall
	jobID   int
	deleted bool
}

type recoveryKubernetesTransportFunc func(context.Context, string, string, []byte) ([]byte, int, error)

func (function recoveryKubernetesTransportFunc) Request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	return function(ctx, method, path, body)
}

func (fake *recoveryKubernetesTransportFake) Request(_ context.Context, method, path string, body []byte) ([]byte, int, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls = append(fake.calls, recoveryKubernetesTransportCall{Method: method, Path: path, Body: append([]byte(nil), body...)})
	namespace := "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a"
	labels := `"app.kubernetes.io/managed-by":"agentsec-recovery","zasp.io/recovery-id":"pid_71000004-0000-4000-8000-000000000004","zasp.io/recovery-scope":"2ab417588f8aeb63"`
	switch {
	case method == http.MethodGet && path == "/version":
		return []byte(`{"major":"1","minor":"34","gitVersion":"v1.34.1"}`), http.StatusOK, nil
	case method == http.MethodPost && path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
		return []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","status":{"allowed":true,"denied":false}}`), http.StatusCreated, nil
	case method == http.MethodPost && path == "/api/v1/namespaces":
		return []byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"` + namespace + `","uid":"11111111-2222-4333-8444-555555555555","labels":{` + labels + `}},"status":{"phase":"Active"}}`), http.StatusCreated, nil
	case method == http.MethodPost && path == "/apis/rbac.authorization.k8s.io/v1/namespaces/"+namespace+"/rolebindings":
		return recoveryKubernetesCreatedResponse(body, "18111111-2222-4333-8444-555555555555"), http.StatusCreated, nil
	case method == http.MethodPost && path == "/api/v1/namespaces/"+namespace+"/serviceaccounts":
		return recoveryKubernetesCreatedResponse(body, "19111111-2222-4333-8444-555555555555"), http.StatusCreated, nil
	case method == http.MethodPost && path == "/apis/networking.k8s.io/v1/namespaces/"+namespace+"/networkpolicies":
		return recoveryKubernetesCreatedResponse(body, "21111111-2222-4333-8444-555555555555"), http.StatusCreated, nil
	case method == http.MethodPost && path == "/api/v1/namespaces/"+namespace+"/secrets":
		return recoveryKubernetesCreatedResponse(body, "31111111-2222-4333-8444-555555555555"), http.StatusCreated, nil
	case method == http.MethodPost && path == "/apis/batch/v1/namespaces/"+namespace+"/jobs":
		fake.jobID++
		return recoveryKubernetesCreatedResponse(body, fmt.Sprintf("41111111-2222-4333-8444-%012d", fake.jobID)), http.StatusCreated, nil
	case method == http.MethodGet && strings.Contains(path, "/jobs/"):
		name := path[strings.LastIndex(path, "/")+1:]
		return []byte(fmt.Sprintf(`{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":%q,"namespace":%q,"uid":%q,"labels":{%s}},"status":{"succeeded":1,"failed":0,"conditions":[{"type":"Complete","status":"True"}]}}`, name, namespace, fmt.Sprintf("41111111-2222-4333-8444-%012d", fake.jobID), labels)), http.StatusOK, nil
	case method == http.MethodGet && strings.Contains(path, "/pods?"):
		evidenceDigest := sha256.Sum256([]byte("[]"))
		message := `{"schema_version":"recovery_projection_job_v1","kind":"graph","projection_sha256":"` + strings.Repeat("2", 64) + `","evidence_sample_sha256":"` + fmt.Sprintf("%x", evidenceDigest) + `"}`
		if strings.Contains(path, "postgres-validation") {
			message = `{"schema_version":"recovery_validation_job_v1","counts":{"assets":3,"findings":2,"policies":1},"evidence_sample_sha256":"` + fmt.Sprintf("%x", evidenceDigest) + `"}`
		} else if strings.Contains(path, "search") {
			message = `{"schema_version":"recovery_projection_job_v1","kind":"search","projection_sha256":"` + strings.Repeat("2", 64) + `","evidence_sample_sha256":"` + fmt.Sprintf("%x", evidenceDigest) + `"}`
		}
		decodedQuery, _ := url.QueryUnescape(strings.SplitN(path, "?", 2)[1])
		jobName := strings.TrimPrefix(decodedQuery, "labelSelector=job-name=")
		return []byte(`{"apiVersion":"v1","kind":"PodList","metadata":{"continue":""},"items":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"result","namespace":"` + namespace + `","uid":"51111111-2222-4333-8444-555555555555","labels":{"app.kubernetes.io/managed-by":"agentsec-recovery","job-name":` + fmt.Sprintf("%q", jobName) + `,"zasp.io/recovery-id":"pid_71000004-0000-4000-8000-000000000004","zasp.io/recovery-scope":"2ab417588f8aeb63"}},"status":{"phase":"Succeeded","containerStatuses":[{"name":"runner","ready":false,"restartCount":0,"state":{"terminated":{"exitCode":0,"reason":"Completed","message":` + fmt.Sprintf("%q", message) + `}}}]}}]}`), http.StatusOK, nil
	case method == http.MethodGet && path == "/api/v1/namespaces/"+namespace:
		if fake.deleted {
			return []byte(`{"kind":"Status","status":"Failure","reason":"NotFound"}`), http.StatusNotFound, nil
		}
		return []byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"` + namespace + `","uid":"11111111-2222-4333-8444-555555555555","labels":{` + labels + `}},"status":{"phase":"Active"}}`), http.StatusOK, nil
	case method == http.MethodDelete && path == "/api/v1/namespaces/"+namespace:
		fake.deleted = true
		return []byte(`{"kind":"Status","status":"Success"}`), http.StatusOK, nil
	default:
		return nil, http.StatusNotFound, nil
	}
}

func TestRecoveryKubernetesAPIProvisionsValidatesRebuildsAndUIDCleans(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	store := &recoveryArtifactStoreFake{}
	transport := &recoveryKubernetesTransportFake{}
	api, err := newRecoveryKubernetesAPI(recoveryKubernetesAPIConfig{
		Transport: transport, Store: store, RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/agentsec-worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "agentsec-recovery-runner",
		SourcePostgresDSN: recoveryKubernetesSourcePostgresDSN, NeonCIDRs: []string{"10.24.8.0/24"}, PollInterval: time.Millisecond, Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.24.8.8"), net.ParseIP("10.24.8.7")}, nil
		},
	})
	if err != nil || api.Ready(context.Background()) != nil {
		t.Fatalf("api=%#v err=%v", api, err)
	}
	branch := recoveryNeonBranch("ep-recovery.us-west-2.aws.neon.tech", manifest)
	evidenceDigest := sha256.Sum256([]byte("[]"))
	plan := newRecoveryKubernetesPlan(recoveryRestoreProvisionRequest{Scope: claim, TargetEnvironment: claim.TargetEnvironment, Manifest: manifest, EvidenceSampleDigest: evidenceDigest}, branch, "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a", "2ab417588f8aeb63")
	uid, err := api.Provision(context.Background(), plan)
	if err != nil || uid != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("uid=%q err=%v", uid, err)
	}
	counts, evidence, err := api.Validate(context.Background(), plan, uid)
	if err != nil || counts != (apiserver.RecoveryCounts{Assets: 3, Findings: 2, Policies: 1}) || evidence.Schema != "recovery_validation_v1" {
		t.Fatalf("counts=%#v evidence=%#v err=%v", counts, evidence, err)
	}
	digest, err := api.Rebuild(context.Background(), plan, uid)
	if err != nil || digest != manifest.Projection.SHA256 {
		t.Fatalf("digest=%x err=%v", digest, err)
	}
	cleanup, err := api.Cleanup(context.Background(), plan, uid)
	if err != nil || cleanup.State != "deleted" || cleanup.Evidence.Schema != "recovery_cleanup_v1" {
		t.Fatalf("cleanup=%#v err=%v", cleanup, err)
	}
	if len(store.puts) != 2 || store.puts[0].MediaType != "application/json" || store.puts[1].MediaType != "application/json" {
		t.Fatalf("puts=%#v", store.puts)
	}
	if !recoveryKubernetesCallsContainSecretDSN(t, transport.calls, "ep-recovery.us-west-2.aws.neon.tech") {
		t.Fatalf("calls=%#v", transport.calls)
	}
	if !recoveryKubernetesCallsContainExactReviews(t, transport.calls) {
		t.Fatalf("calls=%#v", transport.calls)
	}
	if !recoveryKubernetesCallsContainDisposableTargets(t, transport.calls) {
		t.Fatalf("disposable targets missing: %#v", transport.calls)
	}
	if !recoveryKubernetesCallsContainNamespaceRunner(t, transport.calls, plan.Namespace, "agentsec-recovery-runner", plan.Labels) {
		t.Fatalf("namespace runner missing: %#v", transport.calls)
	}
	if !recoveryKubernetesCallsContainNamespaceAuthorityBinding(t, transport.calls, plan.Namespace, plan.Labels) {
		t.Fatalf("namespace authority binding missing: %#v", transport.calls)
	}
}

func TestRecoveryKubernetesAPIReturnsNoCleanupEvidenceWhenArtifactWriteFails(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	store := &recoveryArtifactStoreFake{putErr: errors.New("artifact unavailable")}
	transport := &recoveryKubernetesTransportFake{}
	api, err := newRecoveryKubernetesAPI(recoveryKubernetesAPIConfig{
		Transport: transport, Store: store, RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/agentsec-worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "agentsec-recovery-runner",
		SourcePostgresDSN: "postgres://recovery:secret@ep-main.us-west-2.aws.neon.tech/zasp?sslmode=verify-full", NeonCIDRs: []string{"10.24.8.0/24"}, PollInterval: time.Millisecond, Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.24.8.8")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	branch := recoveryNeonBranch("ep-recovery.us-west-2.aws.neon.tech", manifest)
	evidenceDigest := sha256.Sum256([]byte("[]"))
	plan := newRecoveryKubernetesPlan(recoveryRestoreProvisionRequest{Scope: claim, TargetEnvironment: claim.TargetEnvironment, Manifest: manifest, EvidenceSampleDigest: evidenceDigest}, branch, "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a", "2ab417588f8aeb63")
	cleanup, err := api.Cleanup(context.Background(), plan, "11111111-2222-4333-8444-555555555555")
	if !errors.Is(err, errWorkerExecution) || cleanup != (apiserver.RecoveryCleanupEvidence{}) || len(store.puts) != 1 || !transport.deleted {
		t.Fatalf("cleanup=%#v puts=%d deleted=%t err=%v", cleanup, len(store.puts), transport.deleted, err)
	}
}

func TestRecoveryKubernetesAPIRejectsEveryBranchAddressOutsidePinnedNetworksBeforeSecretWrite(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	transport := &recoveryKubernetesTransportFake{}
	api, err := newRecoveryKubernetesAPI(recoveryKubernetesAPIConfig{
		Transport: transport, Store: &recoveryArtifactStoreFake{}, RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/agentsec-worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "agentsec-recovery-runner",
		SourcePostgresDSN: recoveryKubernetesSourcePostgresDSN, NeonCIDRs: []string{"10.24.8.0/24"}, PollInterval: time.Millisecond, Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.24.8.7"), net.ParseIP("10.25.8.7")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	branch := recoveryNeonBranch("ep-recovery.us-west-2.aws.neon.tech", manifest)
	evidenceDigest := sha256.Sum256([]byte("[]"))
	plan := newRecoveryKubernetesPlan(recoveryRestoreProvisionRequest{Scope: claim, TargetEnvironment: claim.TargetEnvironment, Manifest: manifest, EvidenceSampleDigest: evidenceDigest}, branch, "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a", "2ab417588f8aeb63")
	uid, err := api.Provision(context.Background(), plan)
	if !errors.Is(err, errWorkerExecution) || uid != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("uid=%q err=%v", uid, err)
	}
	for _, call := range transport.calls {
		if call.Method == http.MethodPost && strings.HasSuffix(call.Path, "/secrets") {
			t.Fatalf("secret write after rejected resolution: %#v", call)
		}
	}
}

func TestRecoveryKubernetesAPIStopsBeforeNamespaceResourcesWhenDelegatedAuthorityIsDenied(t *testing.T) {
	scope := recoveryWorkerScope(t)
	manifest := recoveryRestoreManifest(t, scope)
	claim := recoveryRestoreClaim(scope)
	base := &recoveryKubernetesTransportFake{}
	namespace := "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a"
	transport := recoveryKubernetesTransportFunc(func(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
		if method == http.MethodPost && path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review struct {
				Spec struct {
					ResourceAttributes struct {
						Namespace string `json:"namespace"`
						Resource  string `json:"resource"`
					} `json:"resourceAttributes"`
				} `json:"spec"`
			}
			if json.Unmarshal(body, &review) == nil && review.Spec.ResourceAttributes.Namespace == namespace && review.Spec.ResourceAttributes.Resource == "serviceaccounts" {
				base.mu.Lock()
				base.calls = append(base.calls, recoveryKubernetesTransportCall{Method: method, Path: path, Body: append([]byte(nil), body...)})
				base.mu.Unlock()
				return []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","status":{"allowed":false,"denied":true}}`), http.StatusCreated, nil
			}
		}
		return base.Request(ctx, method, path, body)
	})
	api, err := newRecoveryKubernetesAPI(recoveryKubernetesAPIConfig{
		Transport: transport, Store: &recoveryArtifactStoreFake{}, RunnerImage: "123456789012.dkr.ecr.us-west-2.amazonaws.com/zasp/agentsec-worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "agentsec-recovery-runner",
		SourcePostgresDSN: recoveryKubernetesSourcePostgresDSN, NeonCIDRs: []string{"10.24.8.0/24"}, PollInterval: time.Millisecond, Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.24.8.8")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	branch := recoveryNeonBranch("ep-recovery.us-west-2.aws.neon.tech", manifest)
	evidenceDigest := sha256.Sum256([]byte("[]"))
	plan := newRecoveryKubernetesPlan(recoveryRestoreProvisionRequest{Scope: claim, TargetEnvironment: claim.TargetEnvironment, Manifest: manifest, EvidenceSampleDigest: evidenceDigest}, branch, namespace, "2ab417588f8aeb63")
	uid, err := api.Provision(context.Background(), plan)
	if !errors.Is(err, errWorkerExecution) || uid != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("uid=%q err=%v", uid, err)
	}
	for _, call := range base.calls {
		if call.Method == http.MethodPost && (strings.HasSuffix(call.Path, "/serviceaccounts") || strings.HasSuffix(call.Path, "/networkpolicies") || strings.HasSuffix(call.Path, "/secrets") || strings.HasSuffix(call.Path, "/jobs")) {
			t.Fatalf("namespace child mutation after denied delegated authority: %#v", call)
		}
	}
}

func TestRecoveryKubernetesHTTPTransportPinsTLSBearerOriginAndRejectsRedirect(t *testing.T) {
	var authorization string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("Authorization")
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/redirect" {
			http.Redirect(response, request, "/version", http.StatusFound)
			return
		}
		_, _ = response.Write([]byte(`{"major":"1","minor":"34"}`))
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenFile := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenFile, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	transport, err := newRecoveryKubernetesHTTPTransport(recoveryKubernetesHTTPConfig{Endpoint: server.URL, TokenFile: tokenFile, RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	body, status, err := transport.Request(context.Background(), http.MethodGet, "/version", nil)
	if err != nil || status != http.StatusOK || string(body) != `{"major":"1","minor":"34"}` || authorization != "Bearer "+strings.Repeat("a", 64) {
		t.Fatalf("body=%s status=%d auth=%q err=%v", body, status, authorization, err)
	}
	if _, _, err := transport.Request(context.Background(), http.MethodGet, "/redirect", nil); err == nil {
		t.Fatal("redirect accepted")
	}
}

func TestRecoveryKubernetesAPIReconcilesUncertainCreateBeforeRetryingMutation(t *testing.T) {
	labels := map[string]string{"app.kubernetes.io/managed-by": "agentsec-recovery", "zasp.io/recovery-id": "pid_71000004-0000-4000-8000-000000000004", "zasp.io/recovery-scope": "2ab417588f8aeb63"}
	manifest := map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a", "labels": labels}}
	posts, gets := 0, 0
	transport := recoveryKubernetesTransportFunc(func(_ context.Context, method, path string, body []byte) ([]byte, int, error) {
		switch {
		case method == http.MethodPost && path == "/api/v1/namespaces":
			posts++
			return []byte(`{"kind":"Status","status":"Failure","reason":"ServiceUnavailable"}`), http.StatusServiceUnavailable, nil
		case method == http.MethodGet && path == "/api/v1/namespaces/zasp-recovery-2ab417588f8aeb633da32b8fe349c25a":
			gets++
			return recoveryKubernetesCreatedResponse(mustRecoveryJSON(t, manifest), "11111111-2222-4333-8444-555555555555"), http.StatusOK, nil
		default:
			return nil, 0, errors.New("unexpected request")
		}
	})
	api := &productionRecoveryKubernetesAPI{config: recoveryKubernetesAPIConfig{Transport: transport}}
	resource, err := api.createOrReconcile(context.Background(), "/api/v1/namespaces", "/api/v1/namespaces/zasp-recovery-2ab417588f8aeb633da32b8fe349c25a", manifest, "v1", "Namespace", "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a", "", labels)
	if err != nil || resource.Metadata.UID != "11111111-2222-4333-8444-555555555555" || posts != 1 || gets != 1 {
		t.Fatalf("resource=%#v posts=%d gets=%d err=%v", resource, posts, gets, err)
	}
}

func recoveryKubernetesCallsContainSecretDSN(t *testing.T, calls []recoveryKubernetesTransportCall, host string) bool {
	t.Helper()
	for _, call := range calls {
		if call.Method != http.MethodPost || !strings.HasSuffix(call.Path, "/secrets") {
			continue
		}
		var value struct {
			StringData map[string]string `json:"stringData"`
		}
		if json.Unmarshal(call.Body, &value) == nil && strings.Contains(value.StringData["dsn"], host) && !strings.Contains(value.StringData["dsn"], "ep-main") && value.StringData["branch_ip"] == "10.24.8.7" {
			return true
		}
	}
	return false
}

func recoveryKubernetesCallsContainExactReviews(t *testing.T, calls []recoveryKubernetesTransportCall) bool {
	t.Helper()
	namespace := "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a"
	want := map[string]bool{
		"create\x1fnamespaces\x1f\x1f": false, "get\x1fnamespaces\x1f\x1f": false, "delete\x1fnamespaces\x1f\x1f": false,
		"create\x1frolebindings\x1fzasp-recovery-authority-check\x1f": false, "get\x1frolebindings\x1fzasp-recovery-authority-check\x1f": false,
		"bind\x1fclusterroles\x1f\x1fagentsec-recovery-namespace-operator": false,
		"create\x1fserviceaccounts\x1f" + namespace + "\x1f":               false, "get\x1fserviceaccounts\x1f" + namespace + "\x1f": false,
		"create\x1fnetworkpolicies\x1f" + namespace + "\x1f": false, "get\x1fnetworkpolicies\x1f" + namespace + "\x1f": false,
		"create\x1fsecrets\x1f" + namespace + "\x1f": false, "get\x1fsecrets\x1f" + namespace + "\x1f": false,
		"create\x1fjobs\x1f" + namespace + "\x1f": false, "get\x1fjobs\x1f" + namespace + "\x1f": false,
		"list\x1fpods\x1f" + namespace + "\x1f": false,
	}
	for _, call := range calls {
		if call.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			continue
		}
		var value struct {
			Spec struct {
				ResourceAttributes struct {
					Namespace string `json:"namespace"`
					Name      string `json:"name"`
					Resource  string `json:"resource"`
					Verb      string `json:"verb"`
				} `json:"resourceAttributes"`
			} `json:"spec"`
		}
		if json.Unmarshal(call.Body, &value) != nil {
			return false
		}
		key := strings.Join([]string{value.Spec.ResourceAttributes.Verb, value.Spec.ResourceAttributes.Resource, value.Spec.ResourceAttributes.Namespace, value.Spec.ResourceAttributes.Name}, "\x1f")
		if _, exists := want[key]; !exists || want[key] {
			return false
		}
		want[key] = true
	}
	for _, seen := range want {
		if !seen {
			return false
		}
	}
	return true
}

func recoveryKubernetesCallsContainNamespaceRunner(t *testing.T, calls []recoveryKubernetesTransportCall, namespace, name string, labels map[string]string) bool {
	t.Helper()
	for _, call := range calls {
		if call.Method != http.MethodPost || call.Path != "/api/v1/namespaces/"+namespace+"/serviceaccounts" {
			continue
		}
		var value struct {
			APIVersion string                     `json:"apiVersion"`
			Kind       string                     `json:"kind"`
			Metadata   recoveryKubernetesMetadata `json:"metadata"`
			Automount  *bool                      `json:"automountServiceAccountToken"`
		}
		return json.Unmarshal(call.Body, &value) == nil && value.APIVersion == "v1" && value.Kind == "ServiceAccount" && value.Metadata.Name == name && value.Metadata.Namespace == namespace && reflect.DeepEqual(value.Metadata.Labels, labels) && value.Automount != nil && !*value.Automount
	}
	return false
}

func recoveryKubernetesCallsContainNamespaceAuthorityBinding(t *testing.T, calls []recoveryKubernetesTransportCall, namespace string, labels map[string]string) bool {
	t.Helper()
	for _, call := range calls {
		if call.Method != http.MethodPost || call.Path != "/apis/rbac.authorization.k8s.io/v1/namespaces/"+namespace+"/rolebindings" {
			continue
		}
		var value struct {
			APIVersion string                     `json:"apiVersion"`
			Kind       string                     `json:"kind"`
			Metadata   recoveryKubernetesMetadata `json:"metadata"`
			RoleRef    map[string]string          `json:"roleRef"`
			Subjects   []map[string]string        `json:"subjects"`
		}
		return json.Unmarshal(call.Body, &value) == nil && value.APIVersion == "rbac.authorization.k8s.io/v1" && value.Kind == "RoleBinding" && value.Metadata.Name == "agentsec-recovery-controller" && value.Metadata.Namespace == namespace && reflect.DeepEqual(value.Metadata.Labels, labels) && reflect.DeepEqual(value.RoleRef, map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "agentsec-recovery-namespace-operator"}) && reflect.DeepEqual(value.Subjects, []map[string]string{{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "system:serviceaccount:agentsec:zasp-recovery-restore"}})
	}
	return false
}

func recoveryKubernetesCallsContainDisposableTargets(t *testing.T, calls []recoveryKubernetesTransportCall) bool {
	t.Helper()
	seen := 0
	for _, call := range calls {
		if call.Method != http.MethodPost || !strings.Contains(call.Path, "/jobs") {
			continue
		}
		var value struct {
			Spec struct {
				Template struct {
					Spec struct {
						Volumes []struct {
							Name     string `json:"name"`
							EmptyDir struct {
								SizeLimit string `json:"sizeLimit"`
							} `json:"emptyDir"`
						} `json:"volumes"`
						Containers []struct {
							Env []struct {
								Name  string `json:"name"`
								Value string `json:"value"`
							} `json:"env"`
							VolumeMounts []struct {
								Name      string `json:"name"`
								MountPath string `json:"mountPath"`
							} `json:"volumeMounts"`
						} `json:"containers"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		}
		if json.Unmarshal(call.Body, &value) != nil || len(value.Spec.Template.Spec.Volumes) != 1 || value.Spec.Template.Spec.Volumes[0].Name != "recovery-target" || value.Spec.Template.Spec.Volumes[0].EmptyDir.SizeLimit != "256Mi" || len(value.Spec.Template.Spec.Containers) != 1 || len(value.Spec.Template.Spec.Containers[0].VolumeMounts) != 1 || value.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name != "recovery-target" || value.Spec.Template.Spec.Containers[0].VolumeMounts[0].MountPath != "/var/lib/zasp-recovery" {
			return false
		}
		foundDirectory, foundEvidenceDigest := false, false
		for _, environment := range value.Spec.Template.Spec.Containers[0].Env {
			if environment.Name == "ZASP_RECOVERY_TARGET_DIRECTORY" && environment.Value == "/var/lib/zasp-recovery" {
				foundDirectory = true
			}
			if environment.Name == "ZASP_RECOVERY_EVIDENCE_SAMPLE_SHA256" && environment.Value == fmt.Sprintf("%x", sha256.Sum256([]byte("[]"))) {
				foundEvidenceDigest = true
			}
		}
		if !foundDirectory || !foundEvidenceDigest {
			return false
		}
		seen++
	}
	return seen == 3
}

func recoveryKubernetesCreatedResponse(body []byte, uid string) []byte {
	var value map[string]any
	_ = json.Unmarshal(body, &value)
	metadata, _ := value["metadata"].(map[string]any)
	metadata["uid"] = uid
	if stringData, ok := value["stringData"].(map[string]any); ok {
		data := make(map[string]string, len(stringData))
		for key, item := range stringData {
			data[key] = base64.StdEncoding.EncodeToString([]byte(item.(string)))
		}
		value["data"] = data
		delete(value, "stringData")
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func mustRecoveryJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func recoveryNeonBranch(host string, manifest recovery.Manifest) neondriver.Branch {
	return neondriver.Branch{ID: "br-recovery-123456", ProjectID: manifest.NeonProjectID, ParentID: manifest.NeonBranchID, ParentLSN: manifest.PostgresLSN, Name: "zasp-recovery-2ab417588f8aeb633da32b8fe349c25a", Endpoints: []neondriver.Endpoint{{ID: "ep-recovery-123456", BranchID: "br-recovery-123456", Type: "read_write", Host: host}}}
}

var _ artifactstore.ObjectReferencingArtifactStore = (*recoveryArtifactStoreFake)(nil)
