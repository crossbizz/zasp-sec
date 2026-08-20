package providercollection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestClientWritesRawPagesThenManifestAndReturnsBoundCompleteSnapshot(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	steps := []string{}
	store := &recordingArtifacts{bucket: "zasp-evidence", steps: &steps}
	api := &recordingAPI{steps: &steps, pages: []Page{
		{
			Subject:  request.ExpectedSubject,
			Cursor:   collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "page-2"},
			Raw:      []byte(`{"accounts":[{"id":"123456789012"}]}`),
			Entities: []json.RawMessage{json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}`)},
		},
		{
			Subject:       request.ExpectedSubject,
			Cursor:        collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "complete"},
			Raw:           []byte(`{"roles":[{"arn":"arn:aws:iam::123456789012:role/read"}]}`),
			Entities:      []json.RawMessage{json.RawMessage(`{"id":"pid_40000002-0000-4000-8000-000000000002","kind":"aws_role","source_native_id":"arn:aws:iam::123456789012:role/read","display_name":"read","stable_fields":{},"attributes":{}}`)},
			Relationships: []json.RawMessage{json.RawMessage(`{"id":"pid_40000003-0000-4000-8000-000000000003","kind":"contains","source_native_id":"123456789012/read","from_entity_id":"pid_40000001-0000-4000-8000-000000000001","to_entity_id":"pid_40000002-0000-4000-8000-000000000002","attributes":{}}`)},
			Complete:      true,
		},
	}}
	client, err := New(Config{Provider: collection.ProviderAWS, API: api, Artifacts: store, Bucket: store.bucket, CollectorVersion: "collector_v1", Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("temporary-aws-credential")
	outcome, err := client.CollectWithCredential(context.Background(), request, credential)
	if err != nil {
		t.Fatal(err)
	}
	complete, ok := outcome.(collection.CompleteResult)
	if !ok {
		t.Fatalf("outcome = %T, want collection.CompleteResult", outcome)
	}
	if complete.Subject() != request.ExpectedSubject || complete.NextCursor().Value != "complete" || complete.Snapshot().EntityCount() != 2 || complete.Snapshot().RelationshipCount() != 1 || complete.Snapshot().EvidenceCount() != 2 {
		t.Fatalf("complete result drifted: subject=%#v cursor=%#v counts=%d/%d/%d", complete.Subject(), complete.NextCursor(), complete.Snapshot().EntityCount(), complete.Snapshot().RelationshipCount(), complete.Snapshot().EvidenceCount())
	}
	if len(complete.Manifest().Objects()) != 2 || len(store.requests) != 3 {
		t.Fatalf("manifest/artifact count = %d/%d", len(complete.Manifest().Objects()), len(store.requests))
	}
	if fmt.Sprint(steps) != "[fetch:1 put:raw fetch:2 put:raw put:manifest]" {
		t.Fatalf("steps = %v", steps)
	}
	if !bytes.Equal(credential, []byte("temporary-aws-credential")) {
		t.Fatal("client mutated caller credential")
	}
	for _, request := range store.requests {
		if bytes.Contains(request.Body, credential) {
			t.Fatal("credential reached artifact body")
		}
	}
}

func TestClientReturnsPartialOnlyAfterManifestLastWhenPageBoundIsReached(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderKubernetes)
	request.Bounds.MaxPages = 1
	steps := []string{}
	store := &recordingArtifacts{bucket: "zasp-evidence", steps: &steps}
	api := &recordingAPI{steps: &steps, pages: []Page{{
		Subject: request.ExpectedSubject,
		Cursor:  collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "continue"},
		Raw:     []byte(`{"items":[]}`),
	}}}
	client, err := New(Config{Provider: request.Provider, API: api, Artifacts: store, Bucket: store.bucket, CollectorVersion: "collector_v1", Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte("cluster-credential"))
	if err != nil {
		t.Fatal(err)
	}
	partial, ok := outcome.(collection.PartialResult)
	if !ok || partial.Reason() != collection.FailurePartial || partial.NextCursor().Value != "continue" || len(partial.Manifest().Objects()) != 1 {
		t.Fatalf("partial outcome = %#v (%T)", outcome, outcome)
	}
	if fmt.Sprint(steps) != "[fetch:1 put:raw put:manifest]" {
		t.Fatalf("steps = %v", steps)
	}
}

func TestClientRejectsHostileProviderOutputBeforeArtifactMutation(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderGitHub)
	for name, mutate := range map[string]func(*Page){
		"wrong subject": func(page *Page) { page.Subject.ID = "42" },
		"invalid raw":   func(page *Page) { page.Raw = []byte(`{"token":"secret"`) },
		"secret field":  func(page *Page) { page.Raw = []byte(`{"access_token":"provider-secret"}`) },
		"credential echo": func(page *Page) {
			page.Raw = []byte(`{"value":"installation-token"}`)
		},
		"missing cursor": func(page *Page) { page.Cursor = collection.Cursor{} },
		"too many items": func(page *Page) {
			page.Entities = make([]json.RawMessage, request.Bounds.MaxItems+1)
			for index := range page.Entities {
				page.Entities[index] = json.RawMessage(`{}`)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			page := Page{Subject: request.ExpectedSubject, Cursor: collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, Raw: []byte(`{"repositories":[]}`), Complete: true}
			mutate(&page)
			store := &recordingArtifacts{bucket: "zasp-evidence"}
			client, err := New(Config{Provider: request.Provider, API: &recordingAPI{pages: []Page{page}}, Artifacts: store, Bucket: store.bucket, CollectorVersion: "collector_v1", Clock: fixedClock})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.CollectWithCredential(context.Background(), request, []byte("installation-token")); !errors.Is(err, collection.ErrContract) {
				t.Fatalf("error = %v, want collection.ErrContract", err)
			}
			if len(store.requests) != 0 {
				t.Fatalf("hostile provider output wrote %d artifacts", len(store.requests))
			}
		})
	}
}

func TestClientNeverWritesManifestAfterRawArtifactFailure(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderOkta)
	steps := []string{}
	store := &recordingArtifacts{bucket: "zasp-evidence", steps: &steps, failAt: 1}
	page := Page{Subject: request.ExpectedSubject, Cursor: collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, Raw: []byte(`{"users":[]}`), Complete: true}
	client, err := New(Config{Provider: request.Provider, API: &recordingAPI{steps: &steps, pages: []Page{page}}, Artifacts: store, Bucket: store.bucket, CollectorVersion: "collector_v1", Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CollectWithCredential(context.Background(), request, []byte("okta-refresh-material")); !failureHasCode(err, collection.FailureOutcomeUnknown) {
		t.Fatalf("error = %v, want outcome_unknown", err)
	}
	if fmt.Sprint(steps) != "[fetch:1 put:raw]" {
		t.Fatalf("steps = %v", steps)
	}
}

func TestClientReplayIsByteIdenticalAcrossClockAdvance(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	page := Page{Subject: request.ExpectedSubject, Cursor: collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, Raw: []byte(`{"accounts":[]}`), Complete: true}
	api := &recordingAPI{pages: []Page{page}}
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	now := fixedClock()
	client, err := New(Config{Provider: request.Provider, API: api, Artifacts: store, Bucket: store.bucket, CollectorVersion: "collector_v1", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential"))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	api.calls = 0
	second, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential"))
	if err != nil {
		t.Fatal(err)
	}
	firstComplete, firstOK := first.(collection.CompleteResult)
	secondComplete, secondOK := second.(collection.CompleteResult)
	if !firstOK || !secondOK || firstComplete.Manifest().Descriptor().VersionID() != secondComplete.Manifest().Descriptor().VersionID() || firstComplete.Snapshot().Digest() != secondComplete.Snapshot().Digest() {
		t.Fatalf("replay drifted: first=%#v second=%#v", first, second)
	}
}

func failureHasCode(err error, code collection.FailureCode) bool {
	var failure *collection.Failure
	return errors.As(err, &failure) && failure.Code() == code
}

type recordingAPI struct {
	pages []Page
	steps *[]string
	calls int
}

func (api *recordingAPI) FetchCollectionPage(_ context.Context, credential []byte, request PageRequest) (Page, error) {
	api.calls++
	if api.steps != nil {
		*api.steps = append(*api.steps, fmt.Sprintf("fetch:%d", api.calls))
	}
	if len(credential) == 0 || request.Page != api.calls || api.calls > len(api.pages) {
		return Page{}, collection.ErrContract
	}
	return api.pages[api.calls-1], nil
}

func (*recordingAPI) CheckCollectionReadiness(context.Context) error { return nil }

type recordingArtifacts struct {
	bucket   string
	steps    *[]string
	requests []artifactstore.PutRequest
	failAt   int
	objects  map[string]artifactstore.Artifact
}

func (store *recordingArtifacts) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	store.requests = append(store.requests, request)
	kind := "raw"
	if bytes.Contains(request.Body, []byte(`"objects"`)) {
		kind = "manifest"
	}
	if store.steps != nil {
		*store.steps = append(*store.steps, "put:"+kind)
	}
	if store.failAt == len(store.requests) {
		return artifactstore.Artifact{}, artifactstore.ErrPut
	}
	if store.objects == nil {
		store.objects = make(map[string]artifactstore.Artifact)
	}
	key := request.Reference.String()
	if existing, ok := store.objects[key]; ok {
		if existing.Scope != request.Scope || existing.MediaType != request.MediaType || !bytes.Equal(existing.Body, request.Body) {
			return artifactstore.Artifact{}, artifactstore.ErrPut
		}
		return existing, nil
	}
	artifact := artifactstore.Artifact{Locator: artifactstore.Locator{Scope: request.Scope, Reference: request.Reference, VersionID: fmt.Sprintf("s3-version-%d", len(store.objects)+1)}, MediaType: request.MediaType, Body: bytes.Clone(request.Body), Size: int64(len(request.Body)), SHA256: sha256.Sum256(request.Body)}
	store.objects[key] = artifact
	return artifact, nil
}

func (*recordingArtifacts) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, artifactstore.ErrGet
}
func (*recordingArtifacts) Delete(context.Context, artifactstore.Locator) error {
	return artifactstore.ErrDelete
}

func testRequest(t *testing.T, provider collection.Provider) collection.Request {
	t.Helper()
	scope, err := domain.NewScope(mustID(t, "pid_10000001-0000-4000-8000-000000000001"), mustID(t, "pid_10000002-0000-4000-8000-000000000002"), mustID(t, "pid_10000003-0000-4000-8000-000000000003"))
	if err != nil {
		t.Fatal(err)
	}
	subject := map[collection.Provider]collection.SubjectBinding{
		collection.ProviderAWS:        {Kind: "aws_account", ID: "123456789012"},
		collection.ProviderKubernetes: {Kind: "kubernetes_cluster", ID: "api.example.com/production"},
		collection.ProviderGitHub:     {Kind: "github_installation", ID: "123456"},
		collection.ProviderOkta:       {Kind: "okta_tenant", ID: "customer.okta.com"},
	}[provider]
	class := map[collection.Provider]collection.CredentialClass{
		collection.ProviderAWS: collection.CredentialAWSAssumeRole, collection.ProviderKubernetes: collection.CredentialKubernetesCluster,
		collection.ProviderGitHub: collection.CredentialGitHubInstallation, collection.ProviderOkta: collection.CredentialOktaRefresh,
	}[provider]
	request := collection.Request{
		Scope: scope, IntegrationID: mustID(t, "pid_20000001-0000-4000-8000-000000000001"), ConnectionID: mustID(t, "pid_20000002-0000-4000-8000-000000000002"), JobID: mustID(t, "pid_20000003-0000-4000-8000-000000000003"),
		Attempt: 1, Provider: provider, CollectorVersion: "collector_v1", CredentialClass: class, CredentialReference: "ref:" + string(provider) + "/connection/customer-0001", ExpectedSubject: subject,
		Cursor: collection.Cursor{Provider: provider, Version: "cursor_v1", Value: "initial"}, ParserVersion: "parser_v1", ToolVersion: "tool_v1", Bounds: collection.Bounds{MaxPages: 4, MaxItems: 8, MaxRawBytes: 1 << 20, Timeout: time.Second},
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	return request
}

func mustID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func fixedClock() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }
