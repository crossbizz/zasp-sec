// Package gcptest is the test kit of the Google Cloud collector: a fake of
// the Google APIs it reads, and a helper that runs a whole collection
// against the fake to a typed snapshot. Tests of other packages (the SQL
// that applies a snapshot, for instance) use it to obtain the snapshot the
// real collector produces.
package gcptest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/gcpdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// AccessToken is the token the fake accepts. It is not a real token shape.
const AccessToken = "gcptest-access-token-0123456789abcdef"

// Google is a fake of the Google APIs: a real HTTP server whose routes are
// "host path" of the request the collector meant to send. A request without
// the test token is refused with 401 and an unknown route with 404, as
// Google does.
type Google struct {
	mutex  sync.Mutex
	routes map[string]route
	calls  map[string]int
	server *httptest.Server
}

type route struct {
	status int
	body   string
}

func NewGoogle(t testing.TB) *Google {
	t.Helper()
	fake := &Google{routes: map[string]route{}, calls: map[string]int{}}
	fake.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		key := request.Header.Get("X-Fake-Host") + " " + request.URL.Path
		fake.mutex.Lock()
		answer, found := fake.routes[key]
		fake.calls[key]++
		fake.mutex.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Header.Get("Authorization") != "Bearer "+AccessToken:
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`)
		case !found:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"error":{"code":404,"status":"NOT_FOUND"}}`)
		default:
			writer.WriteHeader(answer.status)
			_, _ = io.WriteString(writer, answer.body)
		}
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// OK answers GET or POST host+path with a 200 and body.
func (fake *Google) OK(host, path, body string) {
	fake.set(host, path, route{http.StatusOK, body})
}

// Denied answers with the 403 of a missing IAM permission.
func (fake *Google) Denied(host, path string) {
	fake.set(host, path, route{http.StatusForbidden, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"IAM_PERMISSION_DENIED","domain":"iam.googleapis.com"}]}}`})
}

// Disabled answers with the 403 of an API that is switched off in the project.
func (fake *Google) Disabled(host, path string) {
	fake.set(host, path, route{http.StatusForbidden, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED","domain":"googleapis.com"}]}}`})
}

func (fake *Google) set(host, path string, answer route) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.routes[host+" "+path] = answer
}

// Calls is how often host+path was requested.
func (fake *Google) Calls(host, path string) int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return fake.calls[host+" "+path]
}

// RoundTrip sends the collector's request to the fake server, keeping the
// host the collector addressed in a header. Only https is accepted.
func (fake *Google) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" {
		return nil, errors.New("the collector must use https")
	}
	clone := request.Clone(request.Context())
	clone.Header.Set("X-Fake-Host", request.URL.Host)
	target := *request.URL
	target.Scheme, target.Host = "http", strings.TrimPrefix(fake.server.URL, "http://")
	clone.URL, clone.Host = &target, target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

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
	EvidenceID            string         `json:"evidence_id"`
}

// Snapshot is a completed collection and its decoded entities.
type Snapshot struct {
	Result   collection.CompleteResult
	Entities []Entity
}

type artifacts struct {
	mutex   sync.Mutex
	objects map[string]artifactstore.DriverObject
}

func (store *artifacts) Put(_ context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object.VersionID = fmt.Sprintf("version-%x", object.SHA256[:8])
	object.Body = bytes.Clone(object.Body)
	store.objects[object.Key+"/"+object.VersionID] = object
	return object, nil
}

func (store *artifacts) Get(_ context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object, ok := store.objects[locator.Key+"/"+locator.VersionID]
	if !ok {
		return artifactstore.DriverObject{}, errors.New("missing owned artifact")
	}
	object.Body = bytes.Clone(object.Body)
	return object, nil
}

func (store *artifacts) Delete(_ context.Context, locator artifactstore.DriverLocator) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	delete(store.objects, locator.Key+"/"+locator.VersionID)
	return nil
}

func (*artifacts) ObjectReference(locator artifactstore.DriverLocator) (string, error) {
	return "s3://gcp-discovery-evidence/" + locator.Key, nil
}

// Collect runs a whole collection of scope against the fake, driven by the
// shared collection client the way the worker drives it, and requires it to
// end in a typed snapshot whose stored artifacts hold no token and whose
// stable fields and attributes are canonical JSON.
func Collect(t testing.TB, fake *Google, scope string) Snapshot {
	t.Helper()
	api, err := gcpdiscovery.NewGCPCollectionAPI(gcpdiscovery.CollectionAPIConfig{Transport: fake, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	driver := &artifacts{objects: map[string]artifactstore.DriverObject{}}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	client, err := gcpdiscovery.NewGCPCollectionClient(api, store, gcpdiscovery.CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]domain.ProductID, 6)
	for index := range ids {
		if ids[index], err = domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", index+1, index+1)); err != nil {
			t.Fatal(err)
		}
	}
	productScope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	request := collection.Request{Scope: productScope, IntegrationID: ids[3], ConnectionID: ids[4], JobID: ids[5], Attempt: 1, Provider: collection.ProviderGCP, CollectorVersion: "collector_v1", CredentialClass: collection.CredentialGCPAccessToken,
		CredentialReference: "ref:gcp/workload-identity/acme-security/zasp-reader", ExpectedSubject: collection.SubjectBinding{Kind: "gcp_scope", ID: scope}, ParserVersion: "parser_v1", ToolVersion: "tool_v1",
		ObservationTime: time.Now().UTC().Truncate(time.Second), Bounds: collection.Bounds{MaxPages: 100, MaxItems: 1000, MaxRawBytes: 64 << 20, Timeout: 30 * time.Second}}
	if err := request.Validate(); err != nil {
		t.Fatalf("request rejected: %v", err)
	}
	credential, ok := gcpdiscovery.EncodeCredential([]byte(AccessToken))
	if !ok {
		t.Fatal("test credential")
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, credential)
	complete, isComplete := outcome.(collection.CompleteResult)
	if err != nil || !isComplete {
		t.Fatalf("collection outcome = %T, %v", outcome, err)
	}
	candidate := complete.Snapshot()
	snapshot := Snapshot{Result: complete}
	if err := json.Unmarshal(candidate.Entities(), &snapshot.Entities); err != nil {
		t.Fatal(err)
	}
	if !candidate.TypedObservations() || candidate.EntityCount() != len(snapshot.Entities) {
		t.Fatalf("snapshot typed=%t entities=%d", candidate.TypedObservations(), candidate.EntityCount())
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, []byte(AccessToken)) {
			t.Fatalf("artifact %s stores the access token", key)
		}
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
	return snapshot
}
