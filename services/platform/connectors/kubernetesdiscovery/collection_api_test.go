package kubernetesdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

type kubernetesRoundTripper struct {
	mu        sync.Mutex
	requests  []*http.Request
	responses []kubernetesHTTPResponse
}

type kubernetesHTTPResponse struct {
	status int
	body   string
	header http.Header
}

func (roundTripper *kubernetesRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	roundTripper.mu.Lock()
	defer roundTripper.mu.Unlock()
	roundTripper.requests = append(roundTripper.requests, request.Clone(request.Context()))
	if len(roundTripper.responses) == 0 {
		return nil, errors.New("kubernetes-provider-secret")
	}
	response := roundTripper.responses[0]
	roundTripper.responses = roundTripper.responses[1:]
	return &http.Response{StatusCode: response.status, Header: response.header, Body: io.NopCloser(strings.NewReader(response.body)), Request: request}, nil
}

func TestKubernetesCollectionAPIPaginatesNamespacesThenWorkloadsCanonically(t *testing.T) {
	t.Parallel()
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{
		{status: http.StatusOK, body: `{"apiVersion":"v1","kind":"NamespaceList","metadata":{"continue":""},"items":[{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"11111111-1111-4111-8111-111111111111","name":"default"}}]}`},
		{status: http.StatusOK, body: `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"22222222-2222-4222-8222-222222222222","namespace":"default","name":"api"}}]}`},
	}}
	api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err != nil {
		t.Fatalf("newKubernetesCollectionAPI() error = %v", err)
	}
	credential := []byte("kubernetes-bearer-secret-value")
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 5, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	first, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(namespaces) error = %v", err)
	}
	if first.Complete || first.Cursor != nextKubernetesPageCursor(request.Subject, "serviceaccounts", 2, "start", request.Cursor) || len(first.Entities) != 2 || len(first.Relationships) != 1 || bytes.Contains(first.Raw, credential) || !bytes.Equal(first.Raw, mustKubernetesCollectionPage(t, first).Raw) {
		t.Fatalf("namespace page = %#v / %s", first, first.Raw)
	}
	request.Cursor = nextKubernetesPageCursor(request.Subject, "deployments", 7, "start")
	request.Page = 7
	request.RemainingItems = 3
	second, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(deployments) error = %v", err)
	}
	if second.Complete || second.Cursor != nextKubernetesPageCursor(request.Subject, "statefulsets", 8, "start", request.Cursor) || len(second.Entities) != 1 || len(second.Relationships) != 2 || bytes.Contains(second.Raw, credential) || !bytes.Equal(second.Raw, mustKubernetesCollectionPage(t, second).Raw) {
		t.Fatalf("deployment page = %#v / %s", second, second.Raw)
	}
	if len(roundTripper.requests) != 2 {
		t.Fatalf("provider calls = %d", len(roundTripper.requests))
	}
	wantURLs := []string{"https://cluster.example/api/v1/namespaces?limit=4", "https://cluster.example/apis/apps/v1/deployments?limit=3"}
	for index, providerRequest := range roundTripper.requests {
		if providerRequest.Method != http.MethodGet || providerRequest.URL.String() != wantURLs[index] || providerRequest.Header.Get("Authorization") != "Bearer "+string(credential) || providerRequest.Header.Get("Accept") != "application/json" {
			t.Fatalf("request %d = %#v", index, providerRequest)
		}
	}
}

func TestKubernetesCollectionAPITraversesEveryLaunchInventoryPhaseBeforeComplete(t *testing.T) {
	t.Parallel()
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{
		{status: http.StatusOK, body: `{"apiVersion":"v1","kind":"NamespaceList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"v1","kind":"ServiceAccountList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBindingList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"apps/v1","kind":"StatefulSetList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"apps/v1","kind":"DaemonSetList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"batch/v1","kind":"JobList","metadata":{"continue":""},"items":[]}`},
		{status: http.StatusOK, body: `{"apiVersion":"batch/v1","kind":"CronJobList","metadata":{"continue":""},"items":[]}`},
	}}
	api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Page: 1, RemainingItems: 32, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	remainingPhases := []string{"serviceaccounts", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs"}
	for index := 0; index < 11; index++ {
		page, fetchErr := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
		if fetchErr != nil {
			t.Fatalf("FetchCollectionPage(page %d) error = %v", request.Page, fetchErr)
		}
		if index < len(remainingPhases) {
			wantCursor := nextKubernetesPageCursor(subject, remainingPhases[index], request.Page+1, "start", request.Cursor)
			if page.Complete || page.Cursor != wantCursor {
				t.Fatalf("page %d complete/cursor = %t / %#v, want false / %#v", request.Page, page.Complete, page.Cursor, wantCursor)
			}
		} else if !page.Complete || !strings.HasPrefix(page.Cursor.Value, "kubernetes:complete:") {
			t.Fatalf("final page = %#v", page)
		}
		request.Cursor = page.Cursor
		request.Page++
	}
	wantURLs := []string{
		"https://cluster.example/api/v1/namespaces?limit=31",
		"https://cluster.example/api/v1/serviceaccounts?limit=32",
		"https://cluster.example/apis/rbac.authorization.k8s.io/v1/roles?limit=32",
		"https://cluster.example/apis/rbac.authorization.k8s.io/v1/clusterroles?limit=32",
		"https://cluster.example/apis/rbac.authorization.k8s.io/v1/rolebindings?limit=1",
		"https://cluster.example/apis/rbac.authorization.k8s.io/v1/clusterrolebindings?limit=1",
		"https://cluster.example/apis/apps/v1/deployments?limit=32",
		"https://cluster.example/apis/apps/v1/statefulsets?limit=32",
		"https://cluster.example/apis/apps/v1/daemonsets?limit=32",
		"https://cluster.example/apis/batch/v1/jobs?limit=32",
		"https://cluster.example/apis/batch/v1/cronjobs?limit=32",
	}
	if len(roundTripper.requests) != len(wantURLs) {
		t.Fatalf("provider calls = %d, want %d", len(roundTripper.requests), len(wantURLs))
	}
	for index, providerRequest := range roundTripper.requests {
		if got := providerRequest.URL.String(); got != wantURLs[index] {
			t.Fatalf("request %d URL = %s, want %s", index, got, wantURLs[index])
		}
	}
}

func TestKubernetesCollectionAPINormalizesIdentityRBACAndEveryLaunchWorkload(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	tests := []struct {
		phase             string
		page              int
		body              string
		wantEntityKinds   string
		wantRelationKinds string
	}{
		{"serviceaccounts", 2, `{"apiVersion":"v1","kind":"ServiceAccountList","metadata":{"continue":""},"items":[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"uid":"21000000-0000-4000-8000-000000000001","namespace":"default","name":"api"}}]}`, "[kubernetes_service_account]", "[contains]"},
		{"roles", 3, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleList","metadata":{"continue":""},"items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"uid":"22000000-0000-4000-8000-000000000001","namespace":"default","name":"reader"}}]}`, "[kubernetes_role]", "[contains]"},
		{"clusterroles", 4, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleList","metadata":{"continue":""},"items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"uid":"23000000-0000-4000-8000-000000000001","name":"view"}}]}`, "[kubernetes_cluster_role]", "[contains]"},
		{"rolebindings", 5, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","metadata":{"continue":""},"items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"uid":"24000000-0000-4000-8000-000000000001","namespace":"default","name":"readers"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},"subjects":[{"kind":"ServiceAccount","name":"api","namespace":"default"},{"apiGroup":"rbac.authorization.k8s.io","kind":"User","name":"alice"},{"apiGroup":"rbac.authorization.k8s.io","kind":"Group","name":"developers"}]}]}`, "[kubernetes_group kubernetes_role_binding kubernetes_service_account kubernetes_user]", "[assigned_to assigned_to assigned_to binds contains]"},
		{"clusterrolebindings", 6, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBindingList","metadata":{"continue":""},"items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"uid":"25000000-0000-4000-8000-000000000001","name":"viewers"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"view"},"subjects":[{"apiGroup":"rbac.authorization.k8s.io","kind":"Group","name":"auditors"}]}]}`, "[kubernetes_cluster_role_binding kubernetes_group]", "[assigned_to binds contains]"},
		{"deployments", 7, `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"26000000-0000-4000-8000-000000000001","namespace":"default","name":"api"},"spec":{"template":{"spec":{"serviceAccountName":"api"}}}}]}`, "[kubernetes_workload]", "[attached_to uses_identity]"},
		{"statefulsets", 8, `{"apiVersion":"apps/v1","kind":"StatefulSetList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"uid":"27000000-0000-4000-8000-000000000001","namespace":"default","name":"db"},"spec":{"template":{"spec":{"serviceAccountName":"api"}}}}]}`, "[kubernetes_workload]", "[attached_to uses_identity]"},
		{"daemonsets", 9, `{"apiVersion":"apps/v1","kind":"DaemonSetList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"uid":"28000000-0000-4000-8000-000000000001","namespace":"default","name":"sensor"},"spec":{"template":{"spec":{"serviceAccountName":"api"}}}}]}`, "[kubernetes_workload]", "[attached_to uses_identity]"},
		{"jobs", 10, `{"apiVersion":"batch/v1","kind":"JobList","metadata":{"continue":""},"items":[{"apiVersion":"batch/v1","kind":"Job","metadata":{"uid":"29000000-0000-4000-8000-000000000001","namespace":"default","name":"scan"},"spec":{"template":{"spec":{"serviceAccountName":"api"}}}}]}`, "[kubernetes_workload]", "[attached_to uses_identity]"},
		{"cronjobs", 11, `{"apiVersion":"batch/v1","kind":"CronJobList","metadata":{"continue":""},"items":[{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"uid":"30000000-0000-4000-8000-000000000001","namespace":"default","name":"nightly"},"spec":{"jobTemplate":{"spec":{"template":{"spec":{"serviceAccountName":"api"}}}}}}]}`, "[kubernetes_workload]", "[attached_to uses_identity]"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.phase, func(t *testing.T) {
			t.Parallel()
			roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: test.body}}}
			api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, test.phase, test.page, "start"), Page: test.page, RemainingItems: 32, RemainingRelationships: 64, RemainingBytes: 1 << 20}
			page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
			if err != nil {
				t.Fatalf("FetchCollectionPage() error = %v", err)
			}
			if got := fmt.Sprint(kubernetesInventoryKinds(page.Entities)); got != test.wantEntityKinds {
				t.Fatalf("entity kinds = %s, want %s", got, test.wantEntityKinds)
			}
			if got := fmt.Sprint(kubernetesInventoryKinds(page.Relationships)); got != test.wantRelationKinds {
				t.Fatalf("relationship kinds = %s, want %s", got, test.wantRelationKinds)
			}
		})
	}
}

func TestKubernetesCollectionAPIClassifiesOnlyExactlyLabeledAgentDeployments(t *testing.T) {
	t.Parallel()
	body := `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[` +
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"22222222-2222-4222-8222-222222222222","namespace":"default","name":"agent","labels":{"zasp.ai/entity-kind":"agent"}}},` +
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"33333333-3333-4333-8333-333333333333","namespace":"default","name":"ordinary","labels":{"zasp.ai/entity-kind":"Agent","other":"agent"}}}]}`
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
	api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "deployments", 7, "start"), Page: 7, RemainingItems: 4, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, raw := range page.Entities {
		var entity struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &entity) != nil {
			t.Fatalf("entity = %s", raw)
		}
		kinds = append(kinds, entity.Kind)
	}
	if fmt.Sprint(kinds) != "[kubernetes_agent kubernetes_workload]" {
		t.Fatalf("entity kinds = %v", kinds)
	}
}

func TestKubernetesCollectionAPIBindsEndpointCursorAndRejectsSecrets(t *testing.T) {
	t.Parallel()
	const credential = "kubernetes-bearer-secret-value"
	valid := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}, Cursor: collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingRelationships: 64, RemainingBytes: 4096}
	for name, request := range map[string]CollectionPageRequest{
		"foreign host":     func() CollectionPageRequest { value := valid; value.Subject.ID = "other.example/prod"; return value }(),
		"foreign provider": func() CollectionPageRequest { value := valid; value.Provider = collection.ProviderAWS; return value }(),
		"bad cursor": func() CollectionPageRequest {
			value := valid
			value.Cursor.Value = "kubernetes:namespaces:../secret"
			return value
		}(),
		"bad page": func() CollectionPageRequest { value := valid; value.Page = 2; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			roundTripper := &kubernetesRoundTripper{}
			api, _ := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
			if _, err := api.FetchCollectionPage(context.Background(), []byte(credential), request); !errors.Is(err, ErrInvalid) || len(roundTripper.requests) != 0 {
				t.Fatalf("FetchCollectionPage() error/calls = %v / %d", err, len(roundTripper.requests))
			}
		})
	}
	for name, providerBody := range map[string]string{
		"secret kind":     `{"apiVersion":"v1","kind":"NamespaceList","metadata":{"continue":""},"items":[{"apiVersion":"v1","kind":"Secret","metadata":{"uid":"11111111-1111-4111-8111-111111111111","name":"credential"}}]}`,
		"credential echo": `{"apiVersion":"v1","kind":"NamespaceList","metadata":{"continue":""},"items":[{"apiVersion":"v1","kind":"Namespace","metadata":{"uid":"11111111-1111-4111-8111-111111111111","name":"kubernetes-bearer-secret-value"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: providerBody}}}
			api, _ := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
			if _, err := api.FetchCollectionPage(context.Background(), []byte(credential), valid); !kubernetesFailureHasCode(err, collection.FailureMalformed) || strings.Contains(err.Error(), credential) || len(roundTripper.requests) != 1 {
				t.Fatalf("secret response error/calls = %q / %d", err, len(roundTripper.requests))
			}
		})
	}
	foreignCursor := nextKubernetesPageCursor(collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/other"}, "deployments", 7, "start")
	foreign := valid
	foreign.Cursor = foreignCursor
	foreign.Page = 7
	roundTripper := &kubernetesRoundTripper{}
	api, _ := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if _, err := api.FetchCollectionPage(context.Background(), []byte(credential), foreign); !errors.Is(err, ErrInvalid) || len(roundTripper.requests) != 0 {
		t.Fatalf("foreign cursor error/calls = %v / %d", err, len(roundTripper.requests))
	}
	jump := valid
	jump.Cursor = nextKubernetesPageCursor(jump.Subject, "deployments", 7, "start")
	jump.Page = 8
	if _, err := api.FetchCollectionPage(context.Background(), []byte(credential), jump); !errors.Is(err, ErrInvalid) || len(roundTripper.requests) != 0 {
		t.Fatalf("jump cursor error/calls = %v / %d", err, len(roundTripper.requests))
	}
}

func TestKubernetesCollectionAPIClassifiesRateLimitAndServerFailures(t *testing.T) {
	t.Parallel()
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}, Cursor: collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingRelationships: 64, RemainingBytes: 4096}
	for name, test := range map[string]struct {
		response kubernetesHTTPResponse
		code     collection.FailureCode
	}{
		"rate limited": {response: kubernetesHTTPResponse{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"2"}}, body: `{}`}, code: collection.FailureRateLimited},
		"server":       {response: kubernetesHTTPResponse{status: http.StatusServiceUnavailable, body: `{}`}, code: collection.FailureRetryable},
	} {
		t.Run(name, func(t *testing.T) {
			roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{test.response}}
			api, _ := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
			_, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
			if !kubernetesFailureHasCode(err, test.code) {
				t.Fatalf("failure = %v, want %s", err, test.code)
			}
		})
	}
}

func TestKubernetesCollectionAPIRejectsMalformedServiceAccountBindingSubject(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	body := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","metadata":{"continue":""},"items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"uid":"24000000-0000-4000-8000-000000000001","namespace":"default","name":"readers"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},"subjects":[{"kind":"ServiceAccount","name":"bad:name","namespace":"default"}]}]}`
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
	api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "rolebindings", 5, "start"), Page: 5, RemainingItems: 32, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	if _, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request); !kubernetesFailureHasCode(err, collection.FailureMalformed) || len(roundTripper.requests) != 1 {
		t.Fatalf("malformed service account error/calls = %v / %d", err, len(roundTripper.requests))
	}
}

func TestKubernetesCollectionAPICapturesCanonicalRoleRules(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	body := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleList","metadata":{"continue":""},"items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"uid":"22000000-0000-4000-8000-000000000001","namespace":"default","name":"reader"},"rules":[{"apiGroups":["apps",""],"resources":["deployments","pods","pods"],"verbs":["list","get"],"resourceNames":["api"]},{"nonResourceURLs":["/healthz"],"verbs":["get"]}]}]}`
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
	api, _ := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "roles", 3, "start"), Page: 3, RemainingItems: 8, RemainingRelationships: 16, RemainingBytes: 1 << 20}
	page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entities) != 1 || !bytes.Contains(page.Entities[0], []byte(`"rules":[{"api_groups":["","apps"],"non_resource_urls":[],"resource_names":["api"],"resources":["deployments","pods"],"verbs":["get","list"]},{"api_groups":[],"non_resource_urls":["/healthz"],"resource_names":[],"resources":[],"verbs":["get"]}]`)) {
		t.Fatalf("role entity = %s", page.Entities[0])
	}
}

func TestKubernetesCollectionAPICoalescesRepeatedPrincipalsAndAcceptsEmptyBindings(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	body := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","metadata":{"continue":""},"items":[` +
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"uid":"24000000-0000-4000-8000-000000000001","namespace":"default","name":"one"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},"subjects":[{"apiGroup":"rbac.authorization.k8s.io","kind":"Group","name":"system:authenticated"}]},` +
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"uid":"24000000-0000-4000-8000-000000000002","namespace":"default","name":"two"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},"subjects":[{"apiGroup":"rbac.authorization.k8s.io","kind":"Group","name":"system:authenticated"}]},` +
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"uid":"24000000-0000-4000-8000-000000000003","namespace":"default","name":"empty"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"missing"},"subjects":[]}]}`
	var payload kubernetesCollectionList
	if !decodeKubernetesCollectionResponse([]byte(body), &payload) {
		t.Fatal("fixture did not decode")
	}
	entities, _, ok := normalizeKubernetesCollectionPage(subject, "rolebindings", false, payload)
	if !ok {
		t.Fatal("normalizeKubernetesCollectionPage rejected valid repeated and empty bindings")
	}
	if got := fmt.Sprint(kubernetesInventoryKinds(entities)); got != "[kubernetes_group kubernetes_role_binding kubernetes_role_binding kubernetes_role_binding]" {
		t.Fatalf("entity kinds = %s", got)
	}
}

func TestKubernetesCollectionAPIFencesNormalizedBindingExpansionAgainstExactBudgets(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	body := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","metadata":{"continue":"next"},"items":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"uid":"24000000-0000-4000-8000-000000000001","namespace":"default","name":"readers"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"},"subjects":[{"apiGroup":"rbac.authorization.k8s.io","kind":"User","name":"alice"}]}]}`
	for name, test := range map[string]struct {
		items         int
		relationships int
		wantCapacity  bool
	}{
		"exact":              {items: 2, relationships: 3},
		"item exhausted":     {items: 1, relationships: 3, wantCapacity: true},
		"zero relationships": {items: 2, relationships: 0, wantCapacity: true},
		"relation exhausted": {items: 2, relationships: 2, wantCapacity: true},
	} {
		t.Run(name, func(t *testing.T) {
			roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
			api, _ := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
			request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "rolebindings", 5, "start"), Page: 5, RemainingItems: test.items, RemainingRelationships: test.relationships, RemainingBytes: 1 << 20}
			page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
			if test.wantCapacity {
				if !errors.Is(err, providercollection.ErrPageCapacity) || len(roundTripper.requests) != 1 {
					t.Fatalf("capacity error/calls = %v / %d", err, len(roundTripper.requests))
				}
				return
			}
			if err != nil || len(page.Entities) != 2 || len(page.Relationships) != 3 || roundTripper.requests[0].URL.Query().Get("limit") != "1" {
				t.Fatalf("exact page/error = %#v / %v", page, err)
			}
		})
	}
}

func TestKubernetesCollectionAPIReadinessUsesExactVersionEndpointWithoutCredential(t *testing.T) {
	t.Parallel()
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: `{"gitVersion":"v1.30.1"}`}}}
	api, _ := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err := api.CheckCollectionReadiness(context.Background()); err != nil {
		t.Fatalf("CheckCollectionReadiness() error = %v", err)
	}
	if len(roundTripper.requests) != 1 || roundTripper.requests[0].URL.String() != "https://cluster.example/version" || roundTripper.requests[0].Header.Get("Authorization") != "" {
		t.Fatalf("readiness requests = %#v", roundTripper.requests)
	}
}

func mustKubernetesCollectionPage(t *testing.T, page CollectionPage) CollectionPage {
	t.Helper()
	canonical, err := NewCollectionPage(page.Subject, page.Cursor, page.Complete, page.Entities, page.Relationships)
	if err != nil {
		t.Fatalf("NewCollectionPage() error = %v", err)
	}
	return canonical
}

func kubernetesFailureHasCode(err error, code collection.FailureCode) bool {
	var failure *collection.Failure
	return errors.As(err, &failure) && failure.Code() == code
}

func kubernetesInventoryKinds(values []json.RawMessage) []string {
	kinds := make([]string, 0, len(values))
	for _, raw := range values {
		var value struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &value) == nil {
			kinds = append(kinds, value.Kind)
		}
	}
	sort.Strings(kinds)
	return kinds
}
