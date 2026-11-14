// Package saastest is the test kit of a SaaS platform definition. It runs a
// whole collection of one platform the way the discovery worker does: the
// generic collector, the allow-listed Nango adapter and the production Nango
// proxy client, against a stand-in Nango HTTP server that plays the provider.
// The result is the typed snapshot the pipeline would apply.
//
// A platform's test declares the provider responses per path and asserts on
// the entities of the snapshot. See docs/operations/saas-connectors.md.
package saastest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/saasdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	// ConnectionReference is the Nango connection every test collects with.
	ConnectionReference = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	connectionID        = "11111111-1111-4111-8111-111111111111"
	serviceKey          = "stand-in-nango-service-key-0001"
	// ProviderToken is the token the stand-in "provider" would hold. No
	// artifact and no request the collector makes may contain it.
	ProviderToken = "provider-token-held-by-nango-only"
)

// Response is what the stand-in provider answers.
type Response struct {
	// Status defaults to 200.
	Status     int
	Body       string
	Link       string
	RetryAfter string
}

// Route answers the requests of one provider path. It receives the request
// query and the number of earlier calls of the path.
type Route func(query url.Values, call int) Response

// Call is one request the stand-in Nango received.
type Call struct {
	Path  string
	Query url.Values
	// Key is the Provider-Config-Key header: the platform's Nango key.
	Key string
}

// Nango is a stand-in Nango server: it accepts exactly the proxy requests
// the production client makes (service key, connection id, provider config
// key) and answers them from routes.
type Nango struct {
	t      testing.TB
	server *httptest.Server
	mu     sync.Mutex
	routes map[string]Route
	calls  []Call
	proxy  *nango.Adapter
}

type staticSecret struct{}

func (staticSecret) Resolve(context.Context, string) ([]byte, error) { return []byte(serviceKey), nil }

type publicResolver struct{}

func (publicResolver) LookupIP(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

// NewNango starts the stand-in for the platforms of registry. routes maps a
// provider path to its answers; a path without a route answers 404.
func NewNango(t testing.TB, registry *saasdiscovery.Registry, routes map[string]Route) *Nango {
	t.Helper()
	standIn := &Nango{t: t, routes: routes}
	standIn.server = httptest.NewServer(http.HandlerFunc(standIn.serve))
	t.Cleanup(standIn.server.Close)
	address := standIn.server.Listener.Addr().String()
	// The production client dials the cluster-local Nango host; the test
	// transport sends that connection to the stand-in.
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client, err := nango.NewProxyClientWithHTTP(staticSecret{}, &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	if err != nil {
		t.Fatal(err)
	}
	standIn.proxy, err = nango.NewAdapter(nango.Config{BaseURL: "http://nango.zasp.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "prod", Entries: registry.NangoEntries()}, publicResolver{}, client, 5*time.Second)
	if err != nil {
		t.Fatalf("Nango adapter refused the registry's entries: %v", err)
	}
	return standIn
}

func (standIn *Nango) serve(writer http.ResponseWriter, request *http.Request) {
	path, isProxy := strings.CutPrefix(request.URL.Path, "/proxy")
	if !isProxy || request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer "+serviceKey || request.Header.Get("Connection-Id") != connectionID || request.Header.Get("Provider-Config-Key") == "" || request.Header.Get("Nango-Is-Sync") != "false" {
		standIn.t.Errorf("stand-in Nango received a request the proxy client must not make: %s %s %v", request.Method, request.URL, request.Header)
		http.Error(writer, "refused", http.StatusBadRequest)
		return
	}
	if strings.Contains(request.URL.String(), ProviderToken) {
		standIn.t.Errorf("request carries the provider token: %s", request.URL)
	}
	standIn.mu.Lock()
	earlier := 0
	for _, call := range standIn.calls {
		if call.Path == path {
			earlier++
		}
	}
	standIn.calls = append(standIn.calls, Call{Path: path, Query: request.URL.Query(), Key: request.Header.Get("Provider-Config-Key")})
	route := standIn.routes[path]
	standIn.mu.Unlock()
	if route == nil {
		http.Error(writer, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	response := route(request.URL.Query(), earlier)
	if response.Status == 0 {
		response.Status = http.StatusOK
	}
	if response.Link != "" {
		writer.Header().Set("Link", response.Link)
	}
	if response.RetryAfter != "" {
		writer.Header().Set("Retry-After", response.RetryAfter)
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(response.Status)
	_, _ = writer.Write([]byte(response.Body))
}

// Proxy is the allow-listed adapter in front of the stand-in.
func (standIn *Nango) Proxy() saasdiscovery.Proxy { return standIn.proxy }

// Calls are the requests received so far, in order.
func (standIn *Nango) Calls() []Call {
	standIn.mu.Lock()
	defer standIn.mu.Unlock()
	return append([]Call(nil), standIn.calls...)
}

// Static answers every call of a path with one 200 body.
func Static(body string) Route {
	return func(url.Values, int) Response { return Response{Body: body} }
}

// Entity is one entity of a typed snapshot.
type Entity struct {
	ID                    string         `json:"id"`
	Kind                  string         `json:"kind"`
	SourceNativeID        string         `json:"source_native_id"`
	DisplayName           string         `json:"display_name"`
	StableFields          map[string]any `json:"stable_fields"`
	Attributes            map[string]any `json:"attributes"`
	IdentityNamespace     string         `json:"identity_namespace"`
	ProductKind           string         `json:"product_kind"`
	ConfidenceBasisPoints int            `json:"confidence_basis_points"`
	ObservedAt            string         `json:"observed_at"`
	FreshUntil            string         `json:"fresh_until"`
	EvidenceID            string         `json:"evidence_id"`
}

// Relationship is one relationship of a typed snapshot.
type Relationship struct {
	Kind         string `json:"kind"`
	FromEntityID string `json:"from_entity_id"`
	ToEntityID   string `json:"to_entity_id"`
}

// Snapshot is a decoded typed snapshot.
type Snapshot struct {
	Entities      []Entity
	Relationships []Relationship
	// Raw is the snapshot's entity document, for byte-level assertions.
	Raw []byte
	// Result is the complete collection outcome the pipeline would apply.
	Result collection.CompleteResult
}

// Kind returns the entities of one kind.
func (snapshot Snapshot) Kind(kind string) []Entity {
	var result []Entity
	for _, entity := range snapshot.Entities {
		if entity.Kind == kind {
			result = append(result, entity)
		}
	}
	return result
}

// Named returns the entity of a kind with a display name.
func (snapshot Snapshot) Named(t testing.TB, kind, name string) Entity {
	t.Helper()
	for _, entity := range snapshot.Entities {
		if entity.Kind == kind && entity.DisplayName == name {
			return entity
		}
	}
	t.Fatalf("snapshot has no %s named %q: %s", kind, name, snapshot.Raw)
	return Entity{}
}

type artifacts struct {
	mu      sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *artifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object.VersionID = fmt.Sprintf("version-%x", object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}

func (store *artifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	object, ok := store.objects[locator.Key+"/"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("missing owned artifact")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}

func (store *artifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}

func (*artifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://saas-discovery-evidence/" + locator.Key, nil
}

// Request is the typed collection request of a tenant of a platform.
func Request(t testing.TB, platform saasdiscovery.Platform, tenantID string) collection.Request {
	t.Helper()
	ids := make([]domain.ProductID, 6)
	for index := range ids {
		var err error
		if ids[index], err = domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", index+1, index+1)); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	request := collection.Request{Scope: scope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderSaaS, CollectorVersion: "collector_v1",
		CredentialClass: collection.CredentialNangoConnection, CredentialReference: ConnectionReference, ExpectedSubject: collection.SubjectBinding{Kind: "saas_tenant", ID: platform.SubjectID(tenantID)},
		ParserVersion: "parser_v1", ToolVersion: "tool_v1", ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 200, MaxItems: 5000, MaxRawBytes: 64 << 20, Timeout: 10 * time.Second}}
	if err := request.Validate(); err != nil {
		t.Fatalf("collection request rejected: %v", err)
	}
	return request
}

// Run collects one tenant of a platform through the stand-in and returns the
// collection outcome as the worker would receive it.
func Run(t testing.TB, standIn *Nango, registry *saasdiscovery.Registry, platform saasdiscovery.Platform, tenantID string) (collection.Outcome, error) {
	t.Helper()
	outcome, _, err := run(t, standIn, registry, platform, tenantID)
	return outcome, err
}

func run(t testing.TB, standIn *Nango, registry *saasdiscovery.Registry, platform saasdiscovery.Platform, tenantID string) (collection.Outcome, *artifacts, error) {
	t.Helper()
	api, err := saasdiscovery.NewCollectionAPI(saasdiscovery.CollectionAPIConfig{Registry: registry, Proxy: standIn.Proxy()})
	if err != nil {
		t.Fatal(err)
	}
	driver := &artifacts{objects: map[string]artifactstore.DriverObject{}}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := saasdiscovery.NewCollectionClient(api, store, saasdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), Request(t, platform, tenantID), []byte(ConnectionReference))
	return outcome, driver, err
}

// Collect runs a whole collection and requires it to end in a typed
// snapshot: every entity carries the identity rule's envelope, canonical
// stable fields and attributes, the platform and the tenant; every entity
// but the tenant is contained in the tenant; and no stored artifact holds
// the connection reference or the provider token.
func Collect(t testing.TB, standIn *Nango, registry *saasdiscovery.Registry, platform saasdiscovery.Platform, tenantID string) Snapshot {
	t.Helper()
	outcome, driver, err := run(t, standIn, registry, platform, tenantID)
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	candidate := complete.Snapshot()
	snapshot := Snapshot{Raw: candidate.Entities(), Result: complete}
	if err := json.Unmarshal(candidate.Entities(), &snapshot.Entities); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(candidate.Relationships(), &snapshot.Relationships); err != nil {
		t.Fatal(err)
	}
	if !candidate.TypedObservations() || candidate.EntityCount() != len(snapshot.Entities) || candidate.RelationshipCount() != len(snapshot.Relationships) || candidate.EvidenceCount() < len(snapshot.Entities) {
		t.Fatalf("snapshot typed=%t entities=%d relationships=%d evidence=%d", candidate.TypedObservations(), candidate.EntityCount(), candidate.RelationshipCount(), candidate.EvidenceCount())
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, []byte(ConnectionReference)) || bytes.Contains(object.Body, []byte(ProviderToken)) || bytes.Contains(object.Body, []byte(serviceKey)) {
			t.Fatalf("artifact %s stores a credential", key)
		}
	}
	envelopes := map[string]struct {
		product    string
		confidence int
	}{"saas_tenant": {"asset", 9500}, "saas_agent": {"agent", 9500}, "saas_ai_application": {"agent", 7000}, "saas_mcp_server": {"tool", 9500}}
	contained := map[string]bool{}
	tenantEntity := ""
	for _, entity := range snapshot.Entities {
		if entity.Kind == "saas_tenant" {
			tenantEntity = entity.ID
		}
	}
	for _, relationship := range snapshot.Relationships {
		if relationship.Kind != "contains" || relationship.FromEntityID != tenantEntity {
			t.Fatalf("relationship = %+v", relationship)
		}
		contained[relationship.ToEntityID] = true
	}
	var raw []struct {
		Kind         string          `json:"kind"`
		StableFields json.RawMessage `json:"stable_fields"`
		Attributes   json.RawMessage `json:"attributes"`
	}
	if err := json.Unmarshal(candidate.Entities(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, entity := range raw {
		for name, document := range map[string]json.RawMessage{"stable_fields": entity.StableFields, "attributes": entity.Attributes} {
			var decoded map[string]any
			decoder := json.NewDecoder(bytes.NewReader(document))
			decoder.UseNumber()
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			if canonical, err := json.Marshal(decoded); err != nil || !bytes.Equal(canonical, document) {
				t.Fatalf("%s %s is not canonical JSON: %s", entity.Kind, name, document)
			}
		}
	}
	tenants := 0
	for _, entity := range snapshot.Entities {
		envelope, known := envelopes[entity.Kind]
		if !known || entity.IdentityNamespace != entity.Kind || entity.ProductKind != envelope.product || entity.ConfidenceBasisPoints != envelope.confidence || entity.ObservedAt == "" || entity.FreshUntil <= entity.ObservedAt || entity.EvidenceID == "" {
			t.Fatalf("entity envelope = %+v", entity)
		}
		if entity.StableFields["platform"] != platform.Token || entity.StableFields["tenant"] != tenantID {
			t.Fatalf("%s %q is not bound to %s/%s: %v", entity.Kind, entity.DisplayName, platform.Token, tenantID, entity.StableFields)
		}
		if entity.Kind == "saas_tenant" {
			tenants++
			continue
		}
		if !contained[entity.ID] {
			t.Fatalf("%s %q has no tenant relationship", entity.Kind, entity.DisplayName)
		}
		if entity.Kind == "saas_mcp_server" {
			continue
		}
		discovery, _ := entity.Attributes["discovery"].(map[string]any)
		posture, _ := entity.Attributes["posture"].(map[string]any)
		wantMethod := "provider_api"
		if entity.Kind == "saas_ai_application" {
			wantMethod = "inferred"
		}
		if discovery["platform"] != platform.Token || discovery["method"] != wantMethod || len(posture) != 18 {
			t.Fatalf("%s %q discovery=%v posture keys=%d", entity.Kind, entity.DisplayName, discovery, len(posture))
		}
	}
	if tenants != 1 || len(contained) != len(snapshot.Entities)-1 {
		t.Fatalf("tenants=%d contained=%d entities=%d", tenants, len(contained), len(snapshot.Entities))
	}
	return snapshot
}
