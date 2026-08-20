package providercollection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
		mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "page-2"}, false,
			[]json.RawMessage{json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}`)}, nil),
		mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "complete"}, true,
			[]json.RawMessage{json.RawMessage(`{"id":"pid_40000002-0000-4000-8000-000000000002","kind":"aws_role","source_native_id":"arn:aws:iam::123456789012:role/read","display_name":"read","stable_fields":{},"attributes":{}}`)},
			[]json.RawMessage{json.RawMessage(`{"id":"pid_40000003-0000-4000-8000-000000000003","kind":"contains","source_native_id":"123456789012/read","from_entity_id":"pid_40000001-0000-4000-8000-000000000001","to_entity_id":"pid_40000002-0000-4000-8000-000000000002","attributes":{}}`)}),
	}}
	client, err := New(Config{Provider: collection.ProviderAWS, API: api, Artifacts: store, CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: fixedClock})
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

func TestClientSupportsMaximumPageBoundWhenTheActualCollectionIsSmall(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	request.Bounds.MaxPages = 10_000
	request.Bounds.MaxRawBytes = 16 * 1024
	page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true, nil, nil)
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	client, err := New(Config{Provider: request.Provider, API: &recordingAPI{pages: []Page{page}}, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential")); err != nil {
		t.Fatalf("small one-page collection with max page bound failed: %v", err)
	}
	if len(store.requests) != 2 {
		t.Fatalf("artifact writes = %d, want raw+manifest", len(store.requests))
	}
}

func TestClientCheckpointsBeforeAnEscapeHeavyNextCursorCanOverflowTheManifest(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	first := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "short"}, false, nil, nil)
	maximumCursor := collection.Cursor{Provider: request.Provider, Version: strings.Repeat("a", 64), Value: strings.Repeat("<", 2048)}
	second := mustPage(t, request.Provider, request.ExpectedSubject, maximumCursor, true, nil, nil)

	for range 3 {
		reserve, err := nextManifestDescriptorReserve(request)
		if err != nil {
			t.Fatal(err)
		}
		reference, err := deterministicEvidenceReference(request, "raw-page-000001")
		if err != nil {
			t.Fatal(err)
		}
		locator := artifactstore.Locator{Scope: request.Scope, Reference: reference}
		artifact := artifactstore.Artifact{Locator: artifactstore.Locator{Scope: request.Scope, Reference: reference, VersionID: "s3-version-1"}, MediaType: "application/json", Body: bytes.Clone(first.Raw), Size: int64(len(first.Raw)), SHA256: sha256.Sum256(first.Raw)}
		object, err := rawObjectFromArtifact(request, locator, artifact, rawSchemaVersion, &recordingArtifacts{bucket: "zasp-evidence"})
		if err != nil {
			t.Fatal(err)
		}
		currentManifest, err := marshalManifest(request, first.Cursor, []collection.RawObject{object})
		if err != nil {
			t.Fatal(err)
		}
		request.Bounds.MaxRawBytes = int64(len(first.Raw)+len(currentManifest)+len(second.Raw)) + reserve
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	api := &recordingAPI{pages: []Page{first, second}}
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	client, err := New(Config{Provider: request.Provider, API: api, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential"))
	if err != nil {
		t.Fatal(err)
	}
	partial, ok := outcome.(collection.PartialResult)
	if !ok || api.calls != 2 || partial.NextCursor() != first.Cursor || len(store.requests) != 2 {
		t.Fatalf("result=%T calls=%d cursor=%#v writes=%d", outcome, api.calls, partial.NextCursor(), len(store.requests))
	}
}

func TestSnapshotBudgetIsCumulativeAcrossPages(t *testing.T) {
	t.Parallel()
	budget := newSnapshotBudget(64)
	if !budget.addPage([]json.RawMessage{json.RawMessage(`{"id":"one"}`)}, nil, []int{16}) {
		t.Fatal("first page should fit")
	}
	if budget.addPage([]json.RawMessage{json.RawMessage(`{"id":"two-two-two"}`)}, []json.RawMessage{json.RawMessage(`{"id":"edge"}`)}, []int{24}) {
		t.Fatal("second page exceeded the shared snapshot budget")
	}
}

func TestClientRejectsCrossPageIdentityDriftAndDanglingRelationshipsAsMalformed(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	first := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "page-2"}, false,
		[]json.RawMessage{json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"same-native-id","display_name":"first","stable_fields":{},"attributes":{}}`)}, nil)
	duplicateSource := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true,
		[]json.RawMessage{json.RawMessage(`{"id":"pid_40000002-0000-4000-8000-000000000002","kind":"aws_role","source_native_id":"same-native-id","display_name":"second","stable_fields":{},"attributes":{}}`)}, nil)
	dangling := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true, nil,
		[]json.RawMessage{json.RawMessage(`{"id":"pid_40000003-0000-4000-8000-000000000003","kind":"contains","source_native_id":"dangling-edge","from_entity_id":"pid_40000004-0000-4000-8000-000000000004","to_entity_id":"pid_40000005-0000-4000-8000-000000000005","attributes":{}}`)})

	for name, pages := range map[string][]Page{
		"duplicate source identity": {first, duplicateSource},
		"dangling relationship":     {dangling},
	} {
		t.Run(name, func(t *testing.T) {
			store := &recordingArtifacts{bucket: "zasp-evidence"}
			client, err := New(Config{Provider: request.Provider, API: &recordingAPI{pages: pages}, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential")); !failureHasCode(err, collection.FailureMalformed) {
				t.Fatalf("error = %v, want malformed", err)
			}
			for _, write := range store.requests {
				if bytes.Contains(write.Body, []byte(`"objects"`)) {
					t.Fatal("malformed provider output persisted a manifest")
				}
			}
		})
	}
}

func TestNewPageRejectsWhitespaceAndControlInventoryText(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}
	cursor := collection.Cursor{Provider: collection.ProviderAWS, Version: "cursor_v1", Value: "done"}
	for name, entity := range map[string]json.RawMessage{
		"whitespace source": json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":" 123456789012","display_name":"Production","stable_fields":{},"attributes":{}}`),
		"control display":   json.RawMessage("{\"id\":\"pid_40000001-0000-4000-8000-000000000001\",\"kind\":\"aws_account\",\"source_native_id\":\"123456789012\",\"display_name\":\"Prod\\u0000uction\",\"stable_fields\":{},\"attributes\":{}}"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPage(collection.ProviderAWS, subject, cursor, true, []json.RawMessage{entity}, nil); !errors.Is(err, collection.ErrContract) {
				t.Fatalf("NewPage error = %v, want contract rejection", err)
			}
		})
	}
}

func TestClientReturnsPartialOnlyAfterManifestLastWhenPageBoundIsReached(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderKubernetes)
	request.Bounds.MaxPages = 1
	steps := []string{}
	store := &recordingArtifacts{bucket: "zasp-evidence", steps: &steps}
	api := &recordingAPI{steps: &steps, pages: []Page{mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "continue"}, false, nil, nil)}}
	client, err := New(Config{Provider: request.Provider, API: api, Artifacts: store, CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: fixedClock})
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

func TestClientStopsAtExactItemBudgetAndPublishesPartialWithoutAnotherProviderCall(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	request.Bounds.MaxItems = 1
	page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "continue"}, false,
		[]json.RawMessage{json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}`)}, nil)
	api := &recordingAPI{pages: []Page{page}}
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	client, err := New(Config{Provider: request.Provider, API: api, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential"))
	if err != nil {
		t.Fatal(err)
	}
	partial, ok := outcome.(collection.PartialResult)
	if !ok || partial.NextCursor() != page.Cursor || api.calls != 1 || len(store.requests) != 2 {
		t.Fatalf("result=%T cursor=%#v calls=%d writes=%d", outcome, partial.NextCursor(), api.calls, len(store.requests))
	}
}

func TestClientResumesFromVersionPinnedManifestAndReturnsExactUnion(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	request.Bounds.MaxPages = 2
	firstEntity := json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{},"attributes":{}}`)
	firstPage := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "page-2"}, false, []json.RawMessage{firstEntity}, nil)
	secondEntity := json.RawMessage(`{"id":"pid_40000002-0000-4000-8000-000000000002","kind":"aws_role","source_native_id":"arn:aws:iam::123456789012:role/read","display_name":"read","stable_fields":{},"attributes":{}}`)
	secondPage := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "continue"}, false, []json.RawMessage{secondEntity}, nil)
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	firstClient, err := New(Config{Provider: request.Provider, API: &recordingAPI{pages: []Page{firstPage, secondPage}}, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := firstClient.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential"))
	partial, ok := outcome.(collection.PartialResult)
	if err != nil || !ok {
		t.Fatalf("first outcome = %T / %v", outcome, err)
	}
	descriptor := partial.Manifest().Descriptor()
	checksum := descriptor.Checksum()
	seed := ResumeSeed{CheckpointVersion: 1, CheckpointDigest: bytes.Repeat([]byte{7}, sha256.Size), Cursor: partial.NextCursor(), ManifestReference: descriptor.ObjectReference(), ManifestKey: descriptor.Key(), ManifestVersionID: descriptor.VersionID(), ManifestChecksum: checksum[:], ManifestSizeBytes: descriptor.Size(), ManifestMediaType: descriptor.MediaType(), ManifestSchema: descriptor.SchemaVersion(), ParserVersion: descriptor.ParserVersion(), ToolVersion: descriptor.ToolVersion()}

	request.Attempt++
	request.Cursor = partial.NextCursor()
	request.Bounds.MaxPages = 3
	thirdEntity := json.RawMessage(`{"id":"pid_40000003-0000-4000-8000-000000000003","kind":"aws_role","source_native_id":"arn:aws:iam::123456789012:role/audit","display_name":"audit","stable_fields":{},"attributes":{}}`)
	tail := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "complete"}, true, []json.RawMessage{thirdEntity}, nil)
	api := &recordingAPI{pages: []Page{tail}, pageOffset: 2}
	base, _ := New(Config{Provider: request.Provider, API: api, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	resumed, err := base.WithResumeSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err = resumed.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential"))
	complete, ok := outcome.(collection.CompleteResult)
	if err != nil || !ok || complete.Snapshot().EntityCount() != 3 || len(complete.Manifest().Objects()) != 3 || api.calls != 1 || len(api.requests) != 1 || api.requests[0].Page != 3 {
		t.Fatalf("resumed = %T / %v entities=%d objects=%d calls=%d", outcome, err, complete.Snapshot().EntityCount(), len(complete.Manifest().Objects()), api.calls)
	}

	priorObject := partial.Manifest().Objects()[0]
	priorArtifact := store.objects[priorObject.Reference().String()]
	delete(store.objects, priorObject.Reference().String())
	api = &recordingAPI{pages: []Page{tail}, pageOffset: 2}
	base, _ = New(Config{Provider: request.Provider, API: api, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	resumed, _ = base.WithResumeSeed(seed)
	if _, err := resumed.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential")); !failureHasCode(err, collection.FailureOutcomeUnknown) || api.calls != 0 {
		t.Fatalf("missing pinned page error/calls = %v / %d", err, api.calls)
	}
	store.objects[priorObject.Reference().String()] = priorArtifact
}

func TestClientReservesManifestCapacityBeforeFetchingOrWritingRawPages(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderKubernetes)
	request.Bounds.MaxPages = 1
	request.Bounds.MaxRawBytes = 64 * 1024
	page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "continue"}, false, nil, nil)
	api := &recordingAPI{pages: []Page{page}}
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	client, err := New(Config{Provider: request.Provider, API: api, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CollectWithCredential(context.Background(), request, []byte("cluster-credential")); err != nil {
		t.Fatal(err)
	}
	if len(api.requests) != 1 || api.requests[0].RemainingBytes <= 0 || api.requests[0].RemainingBytes >= request.Bounds.MaxRawBytes {
		t.Fatalf("provider raw budget = %#v, max=%d", api.requests, request.Bounds.MaxRawBytes)
	}
	var used int64
	for _, put := range store.requests {
		used += int64(len(put.Body))
	}
	if used > request.Bounds.MaxRawBytes {
		t.Fatalf("artifact bytes = %d, max=%d", used, request.Bounds.MaxRawBytes)
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
			page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true, nil, nil)
			mutate(&page)
			store := &recordingArtifacts{bucket: "zasp-evidence"}
			client, err := New(Config{Provider: request.Provider, API: &recordingAPI{pages: []Page{page}}, Artifacts: store, CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: fixedClock})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.CollectWithCredential(context.Background(), request, []byte("installation-token")); !failureHasCode(err, collection.FailureMalformed) {
				t.Fatalf("error = %v, want malformed", err)
			}
			if len(store.requests) != 0 {
				t.Fatalf("hostile provider output wrote %d artifacts", len(store.requests))
			}
		})
	}
}

func TestNewPageAllowsOnlyCanonicalProviderInventoryWithoutSecrets(t *testing.T) {
	t.Parallel()
	subject := collection.SubjectBinding{Kind: "aws_account", ID: "123456789012"}
	cursor := collection.Cursor{Provider: collection.ProviderAWS, Version: "cursor_v1", Value: "done"}
	valid := json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{"account_id":"123456789012"},"attributes":{"state":"active"}}`)
	page, err := NewPage(collection.ProviderAWS, subject, cursor, true, []json.RawMessage{valid}, nil)
	if err != nil || len(page.Raw) == 0 || !bytes.Contains(page.Raw, valid) {
		t.Fatalf("NewPage(valid) = %#v, %v", page, err)
	}
	for name, entity := range map[string]json.RawMessage{
		"token":             json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{"token":"secret"},"attributes":{}}`),
		"secret access key": json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{"secret_access_key":"secret"},"attributes":{}}`),
		"client key data":   json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{"client_key_data":"secret"},"attributes":{}}`),
		"nested data":       json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"aws_account","source_native_id":"123456789012","display_name":"Production","stable_fields":{"account_id":{"data":"secret"}},"attributes":{}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPage(collection.ProviderAWS, subject, cursor, true, []json.RawMessage{entity}, nil); !errors.Is(err, collection.ErrContract) {
				t.Fatalf("NewPage(secret) error = %v", err)
			}
		})
	}
	kubernetesSubject := collection.SubjectBinding{Kind: "kubernetes_cluster", ID: "api.example.com/production"}
	kubernetesCursor := collection.Cursor{Provider: collection.ProviderKubernetes, Version: "cursor_v1", Value: "done"}
	secretResource := json.RawMessage(`{"id":"pid_40000001-0000-4000-8000-000000000001","kind":"kubernetes_resource","source_native_id":"default/secret","display_name":"secret","stable_fields":{"cluster":"api.example.com/production","namespace":"default","resource_kind":"Secret","name":"secret"},"attributes":{}}`)
	if _, err := NewPage(collection.ProviderKubernetes, kubernetesSubject, kubernetesCursor, true, []json.RawMessage{secretResource}, nil); !errors.Is(err, collection.ErrContract) {
		t.Fatalf("NewPage(kubernetes Secret) error = %v", err)
	}
}

func TestClientNeverWritesManifestAfterRawArtifactFailure(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderOkta)
	steps := []string{}
	store := &recordingArtifacts{bucket: "zasp-evidence", steps: &steps, failAt: 1}
	page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true, nil, nil)
	client, err := New(Config{Provider: request.Provider, API: &recordingAPI{steps: &steps, pages: []Page{page}}, Artifacts: store, CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: fixedClock})
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

func TestClientRejectsAnArtifactStoredUnderADifferentLocator(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderOkta)
	wrongReference, err := domain.NewEvidenceRef(mustID(t, "pid_40000004-0000-4000-8000-000000000004"))
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingArtifacts{bucket: "zasp-evidence", mutateArtifact: func(value *artifactstore.Artifact) {
		value.Reference = wrongReference
	}}
	page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true, nil, nil)
	client, err := New(Config{Provider: request.Provider, API: &recordingAPI{pages: []Page{page}}, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CollectWithCredential(context.Background(), request, []byte("okta-refresh-material")); !failureHasCode(err, collection.FailureOutcomeUnknown) {
		t.Fatalf("mismatched artifact locator error = %v", err)
	}
}

func TestClientUsesTheArtifactAuthorityForTheExactObjectReference(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true, nil, nil)
	client, err := New(Config{Provider: request.Provider, API: &recordingAPI{pages: []Page{page}}, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential"))
	if err != nil {
		t.Fatal(err)
	}
	complete := outcome.(collection.CompleteResult)
	descriptor := complete.Manifest().Descriptor()
	want := "s3://zasp-evidence/" + descriptor.Key()
	if descriptor.ObjectReference() != want {
		t.Fatalf("object reference = %q, want %q", descriptor.ObjectReference(), want)
	}
}

func TestClientReplayIsByteIdenticalAcrossClockAdvance(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true, nil, nil)
	api := &recordingAPI{pages: []Page{page}}
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	now := fixedClock()
	client, err := New(Config{Provider: request.Provider, API: api, Artifacts: store, CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return now }})
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

func TestClientArtifactIdentityBindsTheEntireCollectionRequest(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	page := mustPage(t, request.Provider, request.ExpectedSubject, collection.Cursor{Provider: request.Provider, Version: "cursor_v1", Value: "done"}, true, nil, nil)
	api := &recordingAPI{pages: []Page{page}}
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	client, err := New(Config{Provider: request.Provider, API: api, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential")); err != nil {
		t.Fatal(err)
	}
	firstRaw := store.requests[0].Reference
	firstManifest := store.requests[1].Reference
	var manifest struct {
		Attempt          int    `json:"attempt"`
		CollectorVersion string `json:"collector_version"`
		RequestDigest    string `json:"request_digest"`
	}
	if err := json.Unmarshal(store.requests[1].Body, &manifest); err != nil || manifest.Attempt != request.Attempt || manifest.CollectorVersion != request.CollectorVersion || len(manifest.RequestDigest) != 64 {
		t.Fatalf("manifest request authority = %#v, err=%v", manifest, err)
	}

	request.Attempt++
	api.calls = 0
	if _, err := client.CollectWithCredential(context.Background(), request, []byte("temporary-aws-credential")); err != nil {
		t.Fatal(err)
	}
	if store.requests[2].Reference == firstRaw || store.requests[3].Reference == firstManifest {
		t.Fatalf("attempt change reused artifact identity: raw=%s manifest=%s", store.requests[2].Reference.String(), store.requests[3].Reference.String())
	}
}

func TestArtifactIdentityChangesForEveryIndependentRequestAuthority(t *testing.T) {
	t.Parallel()
	base := testRequest(t, collection.ProviderAWS)
	want, err := deterministicEvidenceReference(base, "raw-page-000001")
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*collection.Request){
		"scope": func(value *collection.Request) {
			value.Scope, _ = domain.NewScope(mustID(t, "pid_10000011-0000-4000-8000-000000000011"), value.Scope.WorkspaceID(), value.Scope.EnvironmentID())
		},
		"integration": func(value *collection.Request) {
			value.IntegrationID = mustID(t, "pid_20000011-0000-4000-8000-000000000011")
		},
		"connection": func(value *collection.Request) {
			value.ConnectionID = mustID(t, "pid_20000012-0000-4000-8000-000000000012")
		},
		"job":                  func(value *collection.Request) { value.JobID = mustID(t, "pid_20000013-0000-4000-8000-000000000013") },
		"attempt":              func(value *collection.Request) { value.Attempt++ },
		"collector":            func(value *collection.Request) { value.CollectorVersion = "collector_v2" },
		"credential reference": func(value *collection.Request) { value.CredentialReference = "ref:aws/connection/customer-0002" },
		"subject":              func(value *collection.Request) { value.ExpectedSubject.ID = "210987654321" },
		"cursor":               func(value *collection.Request) { value.Cursor.Value = "next" },
		"parser":               func(value *collection.Request) { value.ParserVersion = "parser_v2" },
		"tool":                 func(value *collection.Request) { value.ToolVersion = "tool_v2" },
		"bounds":               func(value *collection.Request) { value.Bounds.MaxItems++ },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if err := changed.Validate(); err != nil {
				t.Fatalf("changed request invalid: %v", err)
			}
			got, err := deterministicEvidenceReference(changed, "raw-page-000001")
			if err != nil || got == want {
				t.Fatalf("artifact identity = %s, base=%s, err=%v", got.String(), want.String(), err)
			}
		})
	}
}

func TestClientRejectsCollectorParserAndToolVersionDriftBeforeProviderIO(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	api := &recordingAPI{}
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	client, err := New(Config{
		Provider: request.Provider, API: api, Artifacts: store,
		CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*collection.Request){
		"collector": func(value *collection.Request) { value.CollectorVersion = "collector_v2" },
		"parser":    func(value *collection.Request) { value.ParserVersion = "parser_v2" },
		"tool":      func(value *collection.Request) { value.ToolVersion = "tool_v2" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if _, err := client.CollectWithCredential(context.Background(), changed, []byte("temporary-aws-credential")); !errors.Is(err, collection.ErrContract) {
				t.Fatalf("version drift error = %v", err)
			}
		})
	}
	if api.calls != 0 || len(store.requests) != 0 {
		t.Fatalf("version drift reached dependencies: api=%d artifacts=%d", api.calls, len(store.requests))
	}
}

func TestClientReadinessDistinguishesProviderContractFailureFromOutage(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	store := &recordingArtifacts{bucket: "zasp-evidence"}
	for name, test := range map[string]struct {
		readiness func(context.Context) error
		want      collection.ReadinessCode
	}{
		"contract": {readiness: func(context.Context) error { return collection.ErrContract }, want: collection.ReadinessContractInvalid},
		"panic":    {readiness: func(context.Context) error { panic("provider-secret") }, want: collection.ReadinessContractInvalid},
		"outage":   {readiness: func(context.Context) error { return errors.New("provider-secret") }, want: collection.ReadinessDependencyUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := New(Config{Provider: request.Provider, API: &recordingAPI{readiness: test.readiness}, Artifacts: store, CollectorVersion: request.CollectorVersion, ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock})
			if err != nil {
				t.Fatal(err)
			}
			status := client.Check(context.Background())
			if status.Ready || status.Code != test.want {
				t.Fatalf("readiness = %#v, want %s", status, test.want)
			}
		})
	}
}

func TestClientReadinessDoesNotReportReadyAfterConcurrentCancellation(t *testing.T) {
	t.Parallel()
	request := testRequest(t, collection.ProviderAWS)
	ctx, cancel := context.WithCancel(context.Background())
	client, err := New(Config{
		Provider: request.Provider,
		API: &recordingAPI{readiness: func(context.Context) error {
			cancel()
			return nil
		}},
		Artifacts: &recordingArtifacts{bucket: "zasp-evidence"}, CollectorVersion: request.CollectorVersion,
		ParserVersion: request.ParserVersion, ToolVersion: request.ToolVersion, Clock: fixedClock,
	})
	if err != nil {
		t.Fatal(err)
	}
	status := client.Check(ctx)
	if status.Ready || status.Code != collection.ReadinessCancelled {
		t.Fatalf("readiness = %#v, want cancelled", status)
	}
}

func failureHasCode(err error, code collection.FailureCode) bool {
	var failure *collection.Failure
	return errors.As(err, &failure) && failure.Code() == code
}

type recordingAPI struct {
	pages      []Page
	steps      *[]string
	calls      int
	requests   []PageRequest
	readiness  func(context.Context) error
	pageOffset int
}

func (api *recordingAPI) FetchCollectionPage(_ context.Context, credential []byte, request PageRequest) (Page, error) {
	api.calls++
	api.requests = append(api.requests, request)
	if api.steps != nil {
		*api.steps = append(*api.steps, fmt.Sprintf("fetch:%d", api.calls))
	}
	if len(credential) == 0 || request.Page != api.calls+api.pageOffset || api.calls > len(api.pages) {
		return Page{}, collection.ErrContract
	}
	return api.pages[api.calls-1], nil
}

func (api *recordingAPI) CheckCollectionReadiness(ctx context.Context) error {
	if api.readiness != nil {
		return api.readiness(ctx)
	}
	return nil
}

type recordingArtifacts struct {
	bucket         string
	steps          *[]string
	requests       []artifactstore.PutRequest
	failAt         int
	objects        map[string]artifactstore.Artifact
	mutateArtifact func(*artifactstore.Artifact)
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
	if store.mutateArtifact != nil {
		store.mutateArtifact(&artifact)
	}
	return artifact, nil
}

func (store *recordingArtifacts) Get(_ context.Context, locator artifactstore.Locator) (artifactstore.Artifact, error) {
	artifact, ok := store.objects[locator.Reference.String()]
	if !ok || artifact.Locator != locator {
		return artifactstore.Artifact{}, artifactstore.ErrGet
	}
	artifact.Body = bytes.Clone(artifact.Body)
	return artifact, nil
}
func (*recordingArtifacts) Delete(context.Context, artifactstore.Locator) error {
	return artifactstore.ErrDelete
}

func (store *recordingArtifacts) ObjectReference(locator artifactstore.Locator) (string, error) {
	if store == nil || store.bucket != "zasp-evidence" || locator.Scope.Validate() != nil || locator.Reference.Validate() != nil || locator.VersionID == "" {
		return "", artifactstore.ErrArtifact
	}
	return "s3://" + store.bucket + "/" + artifactKey(locator.Scope, locator.Reference), nil
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

func mustPage(t *testing.T, provider collection.Provider, subject collection.SubjectBinding, cursor collection.Cursor, complete bool, entities, relationships []json.RawMessage) Page {
	t.Helper()
	page, err := NewPage(provider, subject, cursor, complete, entities, relationships)
	if err != nil {
		t.Fatal(err)
	}
	return page
}
