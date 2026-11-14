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
	// The runtime observation lookup is answered apart from the queue: a
	// cluster without the sensor role has no such ConfigMaps to list.
	egressRequests []*http.Request
	egress         *kubernetesHTTPResponse
}

type kubernetesHTTPResponse struct {
	status int
	body   string
	header http.Header
}

func (roundTripper *kubernetesRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	roundTripper.mu.Lock()
	defer roundTripper.mu.Unlock()
	if request.URL.Path == "/api/v1/configmaps" {
		roundTripper.egressRequests = append(roundTripper.egressRequests, request.Clone(request.Context()))
		response := kubernetesHTTPResponse{status: http.StatusForbidden, body: `{"kind":"Status","status":"Failure","code":403}`}
		if roundTripper.egress != nil {
			response = *roundTripper.egress
		}
		return &http.Response{StatusCode: response.status, Header: response.header, Body: io.NopCloser(strings.NewReader(response.body)), Request: request}, nil
	}
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

func TestKubernetesCollectionAPIDerivesExactAgentPostureFactsFromWorkloadAuthority(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	body := `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"26000000-0000-4000-8000-000000000099","namespace":"production","name":"release-agent","labels":{"zasp.ai/entity-kind":"agent","zasp.ai/runtime-policy":"supported"}},"spec":{"template":{"spec":{"serviceAccountName":"release-agent","hostNetwork":true,"containers":[{"name":"runner","command":["/bin/sh","-c"],"securityContext":{"privileged":true}}],"volumes":[{"name":"workspace","hostPath":{"path":"/var/lib/builds"}}]}}}}]}`
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
	api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "deployments", 7, "start"), Page: 7, RemainingItems: 4, RemainingRelationships: 8, RemainingBytes: 1 << 20}
	page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
	if err != nil || len(page.Entities) != 1 {
		t.Fatalf("agent posture page=%#v err=%v", page, err)
	}
	var entity struct {
		Kind       string `json:"kind"`
		Attributes struct {
			Namespaced bool `json:"namespaced"`
			Posture    struct {
				HumanCredential       bool   `json:"human_credential"`
				CredentialFingerprint string `json:"credential_fingerprint"`
				ShellExecution        bool   `json:"shell_execution"`
				ProductionCredential  bool   `json:"production_credential"`
				UnrestrictedEgress    bool   `json:"unrestricted_egress"`
				RuntimeControl        bool   `json:"runtime_control"`
				ProductionAgent       bool   `json:"production_agent"`
				RuntimePolicy         bool   `json:"runtime_policy_supported"`
				HostFilesystem        bool   `json:"host_filesystem"`
				Privileged            bool   `json:"privileged"`
				CredentialActive      bool   `json:"credential_active"`
			} `json:"posture"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal(page.Entities[0], &entity); err != nil {
		t.Fatal(err)
	}
	posture := entity.Attributes.Posture
	if entity.Kind != "kubernetes_agent" || !entity.Attributes.Namespaced || posture.HumanCredential || !strings.HasPrefix(posture.CredentialFingerprint, "sha256:") || len(posture.CredentialFingerprint) != 71 || !posture.ShellExecution || !posture.ProductionCredential || !posture.UnrestrictedEgress || !posture.RuntimeControl || !posture.ProductionAgent || !posture.RuntimePolicy || !posture.HostFilesystem || !posture.Privileged || !posture.CredentialActive {
		t.Fatalf("agent posture entity=%s", page.Entities[0])
	}
}

func TestKubernetesCollectionAPIDiscoversOnlyExplicitBoundedRedTeamTargetBindings(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	body := `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[` +
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"26000000-0000-4000-8000-000000000091","namespace":"staging","name":"test-agent","labels":{"zasp.ai/entity-kind":"agent"},"annotations":{"zasp.ai/red-team-enabled":"true","zasp.ai/red-team-endpoint":"https://adapter.customer.example/v1/evaluate","zasp.ai/red-team-credential-reference":"ref:red-team/target-0001","zasp.ai/red-team-target-kinds":"agent_endpoint,coding_agent"}}},` +
		`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"26000000-0000-4000-8000-000000000092","namespace":"staging","name":"unsafe-agent","labels":{"zasp.ai/entity-kind":"agent"},"annotations":{"zasp.ai/red-team-enabled":"true","zasp.ai/red-team-endpoint":"http://169.254.169.254/latest","zasp.ai/red-team-credential-reference":"inline-secret","zasp.ai/red-team-target-kinds":"agent_endpoint"}}}]}`
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
	api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "deployments", 7, "start"), Page: 7, RemainingItems: 4, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
	if err != nil || len(page.Entities) != 2 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	type redTeamBinding struct {
		Enabled             bool     `json:"enabled"`
		Endpoint            string   `json:"endpoint"`
		CredentialReference string   `json:"credential_reference"`
		TargetKinds         []string `json:"target_kinds"`
	}
	for index, raw := range page.Entities {
		var entity struct {
			Attributes struct {
				RedTeam *redTeamBinding `json:"red_team,omitempty"`
			} `json:"attributes"`
		}
		if json.Unmarshal(raw, &entity) != nil {
			t.Fatal(string(raw))
		}
		if index == 0 {
			if entity.Attributes.RedTeam == nil || !entity.Attributes.RedTeam.Enabled || entity.Attributes.RedTeam.Endpoint != "https://adapter.customer.example/v1/evaluate" || entity.Attributes.RedTeam.CredentialReference != "ref:red-team/target-0001" || fmt.Sprint(entity.Attributes.RedTeam.TargetKinds) != "[agent_endpoint coding_agent]" {
				t.Fatalf("binding = %#v", entity.Attributes.RedTeam)
			}
		} else if entity.Attributes.RedTeam != nil {
			t.Fatalf("unsafe binding was discovered: %#v", entity.Attributes.RedTeam)
		}
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
	entities, _, ok := normalizeKubernetesCollectionPage(subject, "rolebindings", false, payload, nil, "")
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

func fetchKubernetesWorkloadPage(t *testing.T, phase string, page int, body string) CollectionPage {
	t.Helper()
	roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
	api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, phase, page, "start"), Page: page, RemainingItems: 16, RemainingRelationships: 64, RemainingBytes: 1 << 20}
	result, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(%s) error = %v", phase, err)
	}
	if !bytes.Equal(result.Raw, mustKubernetesCollectionPage(t, result).Raw) {
		t.Fatalf("%s page is not canonical: %s", phase, result.Raw)
	}
	return result
}

func kubernetesEntityKindsAndSignals(t *testing.T, values []json.RawMessage) []string {
	t.Helper()
	result := make([]string, 0, len(values))
	for _, raw := range values {
		var entity struct {
			Kind       string `json:"kind"`
			Attributes struct {
				Discovery *struct {
					Method   string   `json:"method"`
					Platform string   `json:"platform"`
					Signals  []string `json:"signals"`
				} `json:"discovery"`
				Posture *json.RawMessage `json:"posture"`
				RedTeam *json.RawMessage `json:"red_team"`
			} `json:"attributes"`
		}
		if json.Unmarshal(raw, &entity) != nil {
			t.Fatalf("entity = %s", raw)
		}
		described := entity.Kind
		if discovery := entity.Attributes.Discovery; discovery != nil {
			if entity.Kind != "kubernetes_inferred_agent" || discovery.Method != "inferred" || discovery.Platform != "kubernetes_workload" || entity.Attributes.Posture == nil || entity.Attributes.RedTeam != nil {
				t.Fatalf("discovery on %s", raw)
			}
			described += fmt.Sprint(discovery.Signals)
		} else if entity.Kind == "kubernetes_inferred_agent" {
			t.Fatalf("inferred agent without discovery: %s", raw)
		}
		result = append(result, described)
	}
	return result
}

func TestKubernetesCollectionAPIInfersUnlabelledLangGraphDeploymentExactly(t *testing.T) {
	t.Parallel()
	body := `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"26000000-0000-4000-8000-000000000101","namespace":"default","name":"graph","annotations":{"zasp.ai/red-team-enabled":"true","zasp.ai/red-team-endpoint":"https://adapter.customer.example/v1/evaluate","zasp.ai/red-team-credential-reference":"ref:red-team/target-0001","zasp.ai/red-team-target-kinds":"agent_endpoint"}},"spec":{"template":{"spec":{"serviceAccountName":"graph","containers":[{"name":"api","image":"langchain/langgraph-api:1"}]}}}}]}`
	page := fetchKubernetesWorkloadPage(t, "deployments", 7, body)
	wantEntity := `{"id":"pid_6bf5e336-03af-4703-98b2-c235bd755062","kind":"kubernetes_inferred_agent","source_native_id":"kubernetes:deployment:26000000-0000-4000-8000-000000000101","display_name":"default/graph","stable_fields":{"api_group":"apps","api_version":"v1","cluster":"cluster.example/prod","name":"graph","namespace":"default","resource_kind":"Deployment","service_account":"graph"},"attributes":{"discovery":{"method":"inferred","platform":"kubernetes_workload","signals":["image:langgraph"]},"namespaced":true,"posture":{"cicd_write":false,"credential_active":true,"credential_fingerprint":"sha256:6bdf164c96d7a27d759b4feae63e4dd54366bf00139454ef7265c4a89808f3e5","destructive_tool":false,"host_filesystem":false,"human_credential":false,"privileged":false,"production_agent":false,"production_credential":false,"production_secret_reach":false,"production_write":false,"runtime_control":false,"runtime_policy_supported":false,"sensitive_data_reach":false,"shell_execution":false,"unapproved_remote_tool":false,"unrestricted_egress":false,"untrusted_input":false}}}`
	wantRelationships := []string{
		`{"id":"pid_18a347c9-e35e-44ef-aba5-cdfc39e12e05","kind":"attached_to","source_native_id":"kubernetes:deployment:26000000-0000-4000-8000-000000000101:namespace:default","from_entity_id":"pid_5e5a6616-0116-4c5a-850b-386933af2b2c","to_entity_id":"pid_6bf5e336-03af-4703-98b2-c235bd755062","attributes":{"type":"namespace_workload"}}`,
		`{"id":"pid_369fe244-585f-4bb7-bdac-281f09068fae","kind":"uses_identity","source_native_id":"kubernetes:deployment:26000000-0000-4000-8000-000000000101:serviceaccount:graph","from_entity_id":"pid_6bf5e336-03af-4703-98b2-c235bd755062","to_entity_id":"pid_4c44e474-3a5e-4972-beb6-8182780aeb74","attributes":{"type":"workload_service_account"}}`,
	}
	if len(page.Entities) != 1 || string(page.Entities[0]) != wantEntity {
		t.Fatalf("entities = %s\nwant %s", page.Entities, wantEntity)
	}
	if len(page.Relationships) != 2 || string(page.Relationships[0]) != wantRelationships[0] || string(page.Relationships[1]) != wantRelationships[1] {
		t.Fatalf("relationships = %s", page.Relationships)
	}
	// The identifiers are the workload scheme under the inferred kind, and the
	// relationships point at the same namespace and service account a workload
	// or a declared agent would.
	subject := page.Subject
	for id, want := range map[string]string{
		"pid_6bf5e336-03af-4703-98b2-c235bd755062": deterministicKubernetesInventoryID(subject, "kubernetes_inferred_agent", "26000000-0000-4000-8000-000000000101"),
		"pid_5e5a6616-0116-4c5a-850b-386933af2b2c": deterministicKubernetesInventoryID(subject, "kubernetes_namespace", "namespace:default"),
		"pid_4c44e474-3a5e-4972-beb6-8182780aeb74": deterministicKubernetesInventoryID(subject, "kubernetes_service_account", "default/graph"),
		"pid_18a347c9-e35e-44ef-aba5-cdfc39e12e05": deterministicKubernetesInventoryID(subject, "attached_to", "Deployment:26000000-0000-4000-8000-000000000101"),
		"pid_369fe244-585f-4bb7-bdac-281f09068fae": deterministicKubernetesInventoryID(subject, "uses_identity", "Deployment:26000000-0000-4000-8000-000000000101"),
	} {
		if id != want {
			t.Fatalf("identifier %s, scheme gives %s", id, want)
		}
	}
	if id := deterministicKubernetesInventoryID(subject, "kubernetes_workload", "26000000-0000-4000-8000-000000000101"); strings.Contains(string(page.Raw), id) {
		t.Fatalf("inferred agent reuses the workload identifier %s", id)
	}
}

func TestKubernetesCollectionAPIInfersFromEnvironmentNamesWithoutRetainingValues(t *testing.T) {
	t.Parallel()
	const sentinel, secretName, configName = "sk-do-not-leak", "provider-secret-do-not-leak", "config-do-not-leak"
	body := `{"apiVersion":"apps/v1","kind":"StatefulSetList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"uid":"27000000-0000-4000-8000-000000000102","namespace":"production","name":"assistant"},"spec":{"template":{"spec":{"serviceAccountName":"assistant","containers":[{"name":"assistant","image":"registry.example/assistant:3","env":[` +
		`{"name":"OPENAI_API_KEY","value":"` + sentinel + `"},` +
		`{"name":"DATABASE_PASSWORD","valueFrom":{"secretKeyRef":{"name":"` + secretName + `","key":"MCP_TOKEN"}}},` +
		`{"name":"LOG_LEVEL","value":"ANTHROPIC_API_KEY"}],` +
		`"envFrom":[{"secretRef":{"name":"` + secretName + `"}},{"prefix":"LANGCHAIN_","configMapRef":{"name":"` + configName + `"}}]}]}}}}]}`
	page := fetchKubernetesWorkloadPage(t, "statefulsets", 8, body)
	if got := fmt.Sprint(kubernetesEntityKindsAndSignals(t, page.Entities)); got != "[kubernetes_inferred_agent[env:openai]]" {
		t.Fatalf("entities = %s", got)
	}
	var entity struct {
		StableFields struct {
			ResourceKind string `json:"resource_kind"`
		} `json:"stable_fields"`
		Attributes struct {
			Posture struct {
				ProductionAgent      bool `json:"production_agent"`
				ProductionCredential bool `json:"production_credential"`
				CredentialActive     bool `json:"credential_active"`
			} `json:"posture"`
		} `json:"attributes"`
	}
	if json.Unmarshal(page.Entities[0], &entity) != nil || entity.StableFields.ResourceKind != "StatefulSet" || !entity.Attributes.Posture.ProductionAgent || !entity.Attributes.Posture.ProductionCredential || !entity.Attributes.Posture.CredentialActive {
		t.Fatalf("entity = %s", page.Entities[0])
	}
	retained := []json.RawMessage{page.Raw}
	retained = append(retained, page.Entities...)
	retained = append(retained, page.Relationships...)
	retained = append(retained, page.Findings...)
	for _, value := range retained {
		for _, forbidden := range []string{sentinel, secretName, configName, "OPENAI_API_KEY", "DATABASE_PASSWORD", "MCP_TOKEN", "LOG_LEVEL", "ANTHROPIC", "LANGCHAIN", "registry.example"} {
			if bytes.Contains(value, []byte(forbidden)) {
				t.Fatalf("page retains %q: %s", forbidden, value)
			}
		}
	}
	var decoded kubernetesCollectionList
	if !decodeKubernetesCollectionResponse([]byte(body), &decoded) {
		t.Fatal("fixture did not decode")
	}
	if dump := fmt.Sprintf("%+v", decoded); strings.Contains(dump, sentinel) || strings.Contains(dump, secretName) || strings.Contains(dump, configName) || strings.Contains(dump, "MCP_TOKEN") || strings.Contains(dump, "ANTHROPIC") || strings.Contains(dump, "LANGCHAIN") {
		t.Fatalf("decoded pod template retains an environment value or source: %s", dump)
	}
}

func TestKubernetesCollectionAPIInfersAgentsOnlyFromSufficientPodTemplateSignals(t *testing.T) {
	t.Parallel()
	deployment := func(uid int, labels, podSpec string) string {
		return fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"26000000-0000-4000-8000-%012d","namespace":"default","name":"item-%d"%s},"spec":{"template":{"spec":%s}}}`, uid, uid, labels, podSpec)
	}
	for _, test := range []struct{ name, labels, podSpec, want string }{
		{"plain nginx", ``, `{"containers":[{"name":"web","image":"nginx:1.27","command":["nginx","-g","daemon off;"],"env":[{"name":"NGINX_HOST","value":"example.com"}],"ports":[{"containerPort":80}]}]}`, "[kubernetes_workload]"},
		{"one weak port", ``, `{"containers":[{"name":"proxy","image":"example/proxy:1","ports":[{"containerPort":4000}]}]}`, "[kubernetes_workload]"},
		{"two weak signals of one class", ``, `{"containers":[{"name":"proxy","image":"example/proxy:1","ports":[{"containerPort":4000},{"containerPort":7860}]}]}`, "[kubernetes_workload]"},
		{"weak signals of two classes", ``, `{"containers":[{"name":"proxy","image":"ghcr.io/berriai/litellm:main","ports":[{"containerPort":4000}]}]}`, "[kubernetes_inferred_agent[image:litellm port:litellm]]"},
		{"no pod template", ``, `{}`, "[kubernetes_workload]"},
		{"opted out as workload", `,"labels":{"zasp.ai/entity-kind":"workload"}`, `{"containers":[{"name":"api","image":"langchain/langgraph-api:1"}]}`, "[kubernetes_workload]"},
		{"opted out by any other value", `,"labels":{"zasp.ai/entity-kind":"Agent"}`, `{"containers":[{"name":"api","image":"langchain/langgraph-api:1","env":[{"name":"OPENAI_API_KEY"}]}]}`, "[kubernetes_workload]"},
		{"opted out by empty value", `,"labels":{"zasp.ai/entity-kind":""}`, `{"containers":[{"name":"api","image":"langchain/langgraph-api:1"}]}`, "[kubernetes_workload]"},
		{"unrelated labels", `,"labels":{"app":"graph","other":"workload"}`, `{"containers":[{"name":"api","image":"langchain/langgraph-api:1"}]}`, "[kubernetes_inferred_agent[image:langgraph]]"},
		{"image digest and registry port", ``, `{"containers":[{"name":"api","image":"registry.example:5000/LangChain/LangGraph-API@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}`, "[kubernetes_inferred_agent[image:langgraph]]"},
		{"init container image", ``, `{"containers":[{"name":"web","image":"nginx:1.27"}],"initContainers":[{"name":"seed","image":"ghcr.io/all-hands-ai/openhands:0.9"}]}`, "[kubernetes_inferred_agent[image:openhands]]"},
		{"init container environment", ``, `{"containers":[{"name":"web","image":"nginx:1.27"}],"initContainers":[{"name":"seed","image":"busybox:1","env":[{"name":"ANTHROPIC_API_KEY","valueFrom":{"secretKeyRef":{"name":"keys","key":"anthropic"}}}]}]}`, "[kubernetes_inferred_agent[env:anthropic]]"},
		{"command and args", ``, `{"containers":[{"name":"files","image":"node:22","command":["npx"],"args":["-y","@modelcontextprotocol/server-filesystem","/data"]}]}`, "[kubernetes_inferred_agent[process:mcp_server]]"},
		{"command alone", ``, `{"containers":[{"name":"files","image":"node:22","command":["npx","-y","@modelcontextprotocol/server-filesystem"]}]}`, "[kubernetes_inferred_agent[process:mcp_server]]"},
		{"multi-line args", ``, `{"containers":[{"name":"runner","image":"python:3.13","command":["/bin/sh","-c"],"args":["set -e\npip install crewai\nexec crewai run\n"]}]}`, "[kubernetes_inferred_agent[process:crewai]]"},
		{"every class sorted", ``, `{"containers":[{"name":"graph","image":"langchain/langgraph-api:1","args":["langgraph","up"],"env":[{"name":"OPENAI_API_KEY"},{"name":"LANGSMITH_TRACING"}],"ports":[{"containerPort":8123}]}]}`, "[kubernetes_inferred_agent[env:langchain env:openai image:langgraph port:langgraph process:langgraph]]"},
	} {
		page := fetchKubernetesWorkloadPage(t, "deployments", 7, `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[`+deployment(1, test.labels, test.podSpec)+`]}`)
		if got := fmt.Sprint(kubernetesEntityKindsAndSignals(t, page.Entities)); got != test.want || len(page.Relationships) != 2 {
			t.Fatalf("%s: entities = %s, want %s (relationships %d)", test.name, got, test.want, len(page.Relationships))
		}
	}
}

func TestKubernetesCollectionAPIInfersAgentsInEveryWorkloadPhase(t *testing.T) {
	t.Parallel()
	const podSpec = `{"serviceAccountName":"bot","containers":[{"name":"bot","image":"example/bot:1","env":[{"name":"OPENAI_API_KEY","value":"sk-do-not-leak"}]}]}`
	for _, test := range []struct {
		phase                string
		page                 int
		apiVersion, kind     string
		spec                 string
		labels, wantEntities string
	}{
		{"deployments", 7, "apps/v1", "Deployment", `{"template":{"spec":` + podSpec + `}}`, ``, "[kubernetes_inferred_agent[env:openai]]"},
		{"statefulsets", 8, "apps/v1", "StatefulSet", `{"template":{"spec":` + podSpec + `}}`, ``, "[kubernetes_inferred_agent[env:openai]]"},
		{"daemonsets", 9, "apps/v1", "DaemonSet", `{"template":{"spec":` + podSpec + `}}`, ``, "[kubernetes_inferred_agent[env:openai]]"},
		{"jobs", 10, "batch/v1", "Job", `{"template":{"spec":` + podSpec + `}}`, ``, "[kubernetes_inferred_agent[env:openai]]"},
		{"cronjobs", 11, "batch/v1", "CronJob", `{"jobTemplate":{"spec":{"template":{"spec":` + podSpec + `}}}}`, ``, "[kubernetes_inferred_agent[env:openai]]"},
		// A CronJob's own spec.template is not its pod template.
		{"cronjobs", 11, "batch/v1", "CronJob", `{"template":{"spec":` + podSpec + `},"jobTemplate":{"spec":{"template":{"spec":{"serviceAccountName":"bot"}}}}}`, ``, "[kubernetes_workload]"},
		// Only a Deployment can declare an agent; elsewhere the label neither
		// declares nor opts out.
		{"statefulsets", 8, "apps/v1", "StatefulSet", `{"template":{"spec":` + podSpec + `}}`, `,"labels":{"zasp.ai/entity-kind":"agent"}`, "[kubernetes_inferred_agent[env:openai]]"},
		{"statefulsets", 8, "apps/v1", "StatefulSet", `{"template":{"spec":{"serviceAccountName":"bot"}}}`, `,"labels":{"zasp.ai/entity-kind":"agent"}`, "[kubernetes_workload]"},
		{"jobs", 10, "batch/v1", "Job", `{"template":{"spec":` + podSpec + `}}`, `,"labels":{"zasp.ai/entity-kind":"workload"}`, "[kubernetes_workload]"},
	} {
		body := fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"continue":""},"items":[{"apiVersion":%q,"kind":%q,"metadata":{"uid":"31000000-0000-4000-8000-000000000001","namespace":"default","name":"bot"%s},"spec":%s}]}`, test.apiVersion, test.kind+"List", test.apiVersion, test.kind, test.labels, test.spec)
		page := fetchKubernetesWorkloadPage(t, test.phase, test.page, body)
		if got := fmt.Sprint(kubernetesEntityKindsAndSignals(t, page.Entities)); got != test.wantEntities || bytes.Contains(page.Raw, []byte("sk-do-not-leak")) {
			t.Fatalf("%s %s: entities = %s, want %s", test.phase, test.spec, got, test.wantEntities)
		}
		if test.wantEntities == "[kubernetes_workload]" {
			continue
		}
		var entity struct {
			ID           string `json:"id"`
			SourceNative string `json:"source_native_id"`
			StableFields struct {
				ResourceKind   string `json:"resource_kind"`
				ServiceAccount string `json:"service_account"`
			} `json:"stable_fields"`
		}
		if json.Unmarshal(page.Entities[0], &entity) != nil || entity.ID != deterministicKubernetesInventoryID(page.Subject, "kubernetes_inferred_agent", "31000000-0000-4000-8000-000000000001") || entity.SourceNative != "kubernetes:"+strings.ToLower(test.kind)+":31000000-0000-4000-8000-000000000001" || entity.StableFields.ResourceKind != test.kind || entity.StableFields.ServiceAccount != "bot" {
			t.Fatalf("%s entity = %s", test.phase, page.Entities[0])
		}
	}
}

func TestKubernetesCollectionAPIKeepsDeclaredAgentsUnchangedBesideInferredAgents(t *testing.T) {
	t.Parallel()
	const podSpec = `{"serviceAccountName":"graph","initContainers":[{"name":"seed","image":"ghcr.io/all-hands-ai/openhands:0.9"}],"containers":[{"name":"api","image":"langchain/langgraph-api:1","command":["/bin/sh","-c"],"args":["langgraph up"],"env":[{"name":"OPENAI_API_KEY","value":"sk-do-not-leak"}],"ports":[{"containerPort":8123}],"securityContext":{"privileged":true}}]}`
	item := func(uid, name, labels, spec string) string {
		return `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"` + uid + `","namespace":"default","name":"` + name + `"` + labels + `},"spec":{"template":{"spec":` + spec + `}}}`
	}
	list := func(items ...string) string {
		return `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[` + strings.Join(items, ",") + `]}`
	}
	const declaredLabels = `,"labels":{"zasp.ai/entity-kind":"agent"}`
	// The same declared Deployment with a pod template the collector read
	// before inference existed (no image, args, env, ports or initContainers).
	const legacyPodSpec = `{"serviceAccountName":"graph","containers":[{"name":"api","command":["/bin/sh","-c"],"securityContext":{"privileged":true}}]}`
	legacy := fetchKubernetesWorkloadPage(t, "deployments", 7, list(item("26000000-0000-4000-8000-000000000201", "declared", declaredLabels, legacyPodSpec)))
	page := fetchKubernetesWorkloadPage(t, "deployments", 7, list(
		item("26000000-0000-4000-8000-000000000201", "declared", declaredLabels, podSpec),
		item("26000000-0000-4000-8000-000000000202", "inferred", ``, podSpec),
	))
	if got := fmt.Sprint(kubernetesEntityKindsAndSignals(t, page.Entities)); got != "[kubernetes_agent kubernetes_inferred_agent[env:openai image:langgraph image:openhands port:langgraph process:langgraph]]" {
		t.Fatalf("entities = %s", got)
	}
	wantDeclared := `{"id":"` + deterministicKubernetesInventoryID(page.Subject, "kubernetes_agent", "26000000-0000-4000-8000-000000000201") + `","kind":"kubernetes_agent","source_native_id":"kubernetes:deployment:26000000-0000-4000-8000-000000000201","display_name":"default/declared","stable_fields":{"api_group":"apps","api_version":"v1","cluster":"cluster.example/prod","name":"declared","namespace":"default","resource_kind":"Deployment","service_account":"graph"},"attributes":{"namespaced":true,"posture":{"cicd_write":false,"credential_active":true,"credential_fingerprint":"sha256:6bdf164c96d7a27d759b4feae63e4dd54366bf00139454ef7265c4a89808f3e5","destructive_tool":false,"host_filesystem":false,"human_credential":false,"privileged":true,"production_agent":false,"production_credential":false,"production_secret_reach":false,"production_write":false,"runtime_control":false,"runtime_policy_supported":false,"sensitive_data_reach":false,"shell_execution":true,"unapproved_remote_tool":false,"unrestricted_egress":false,"untrusted_input":false}}}`
	if string(page.Entities[0]) != wantDeclared || string(legacy.Entities[0]) != wantDeclared || len(legacy.Relationships) != 2 || !bytes.Equal(page.Relationships[0], legacy.Relationships[0]) || !bytes.Equal(page.Relationships[1], legacy.Relationships[1]) {
		t.Fatalf("declared agent changed:\n%s\n%s\nwant %s", page.Entities[0], legacy.Entities[0], wantDeclared)
	}
	// An inferred agent carries the posture a declared agent with the same pod
	// template does.
	var declared, inferred struct {
		Attributes struct {
			Posture json.RawMessage `json:"posture"`
		} `json:"attributes"`
	}
	if json.Unmarshal(page.Entities[0], &declared) != nil || json.Unmarshal(page.Entities[1], &inferred) != nil || len(declared.Attributes.Posture) == 0 || !bytes.Equal(declared.Attributes.Posture, inferred.Attributes.Posture) {
		t.Fatalf("posture differs: %s / %s", page.Entities[0], page.Entities[1])
	}
	if bytes.Contains(page.Raw, []byte("sk-do-not-leak")) || bytes.Contains(page.Raw, []byte("OPENAI_API_KEY")) {
		t.Fatalf("page retains environment: %s", page.Raw)
	}
}

func TestKubernetesCollectionAPIKeepsPodTemplateValidationForInferenceInputs(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}
	for name, podSpec := range map[string]string{
		"invalid container name":   `{"containers":[{"name":"Not_A_Name","image":"langchain/langgraph-api:1"}]}`,
		"empty command element":    `{"containers":[{"name":"api","image":"langchain/langgraph-api:1","command":[""]}]}`,
		"oversized command":        `{"containers":[{"name":"api","image":"langchain/langgraph-api:1","command":["` + strings.Repeat("a", 1025) + `"]}]}`,
		"relative host path":       `{"containers":[{"name":"api","image":"langchain/langgraph-api:1"}],"volumes":[{"name":"data","hostPath":{"path":"relative"}}]}`,
		"environment not a list":   `{"containers":[{"name":"api","image":"langchain/langgraph-api:1","env":{"OPENAI_API_KEY":"sk-do-not-leak"}}]}`,
		"port not a number":        `{"containers":[{"name":"api","image":"langchain/langgraph-api:1","ports":[{"containerPort":"8123"}]}]}`,
		"image not a string":       `{"containers":[{"name":"api","image":["langchain/langgraph-api:1"]}]}`,
		"init containers not list": `{"containers":[{"name":"api","image":"nginx:1"}],"initContainers":{"name":"seed"}}`,
	} {
		body := `{"apiVersion":"apps/v1","kind":"DeploymentList","metadata":{"continue":""},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"26000000-0000-4000-8000-000000000301","namespace":"default","name":"graph"},"spec":{"template":{"spec":` + podSpec + `}}}]}`
		roundTripper := &kubernetesRoundTripper{responses: []kubernetesHTTPResponse{{status: http.StatusOK, body: body}}}
		api, err := newKubernetesCollectionAPI("https://cluster.example", roundTripper, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: subject, Cursor: nextKubernetesPageCursor(subject, "deployments", 7, "start"), Page: 7, RemainingItems: 4, RemainingRelationships: 8, RemainingBytes: 1 << 20}
		page, err := api.FetchCollectionPage(context.Background(), []byte("kubernetes-bearer-secret-value"), request)
		if !kubernetesFailureHasCode(err, collection.FailureMalformed) || len(page.Entities) != 0 || strings.Contains(fmt.Sprint(err), "sk-do-not-leak") {
			t.Fatalf("%s: page=%#v err=%v", name, page, err)
		}
	}
}
