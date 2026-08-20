package kubernetesdiscovery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
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
	request := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}, Cursor: collection.Cursor{}, Page: 1, RemainingItems: 5, RemainingBytes: 1 << 20}
	first, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(namespaces) error = %v", err)
	}
	if first.Complete || first.Cursor.Value != "kubernetes:deployments:start" || len(first.Entities) != 2 || len(first.Relationships) != 1 || bytes.Contains(first.Raw, credential) || !bytes.Equal(first.Raw, mustKubernetesCollectionPage(t, first).Raw) {
		t.Fatalf("namespace page = %#v / %s", first, first.Raw)
	}
	request.Cursor = first.Cursor
	request.Page = 2
	request.RemainingItems = 3
	second, err := api.FetchCollectionPage(context.Background(), credential, request)
	if err != nil {
		t.Fatalf("FetchCollectionPage(deployments) error = %v", err)
	}
	if !second.Complete || !strings.HasPrefix(second.Cursor.Value, "kubernetes:complete:") || len(second.Entities) != 1 || len(second.Relationships) != 1 || bytes.Contains(second.Raw, credential) || !bytes.Equal(second.Raw, mustKubernetesCollectionPage(t, second).Raw) {
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

func TestKubernetesCollectionAPIBindsEndpointCursorAndRejectsSecrets(t *testing.T) {
	t.Parallel()
	const credential = "kubernetes-bearer-secret-value"
	valid := CollectionPageRequest{Provider: collection.ProviderKubernetes, Subject: collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "cluster.example/prod"}, Cursor: collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1", Value: "initial"}, Page: 1, RemainingItems: 4, RemainingBytes: 4096}
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
			if _, err := api.FetchCollectionPage(context.Background(), []byte(credential), valid); !errors.Is(err, ErrDenied) || strings.Contains(err.Error(), credential) || len(roundTripper.requests) != 1 {
				t.Fatalf("secret response error/calls = %q / %d", err, len(roundTripper.requests))
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
