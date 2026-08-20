package riskprojection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProjectorAppliesCompleteSourceOwnedInputInCanonicalOrder(t *testing.T) {
	scope := riskProjectionScope(t)
	integrationID := riskProjectionID(t, "pid_91000001-0000-4000-8000-000000000001")
	snapshotID := riskProjectionID(t, "pid_91000002-0000-4000-8000-000000000002")
	inputDigest := sha256.Sum256([]byte("candidate"))
	contentDigest := sha256.Sum256([]byte("stored-risk-input"))
	store := &recordingStore{result: ApplyResult{
		SnapshotID: snapshotID, IntegrationID: integrationID, Source: "aws", Generation: 7,
		InputDigest: inputDigest, ContentDigest: contentDigest, Receipt: "postgres:risk-input:pid_91000002-0000-4000-8000-000000000002:sha256:" + strings.Repeat("a", 64),
	}}
	projector, err := NewProjector(store)
	if err != nil {
		t.Fatal(err)
	}
	candidate := Candidate{
		Scope: scope, IntegrationID: integrationID, SnapshotID: snapshotID, Source: "aws", Generation: 7,
		Version: "v1", Worker: "projection-risk-01", LeaseToken: "projection-token-00000001", InputDigest: inputDigest,
		Entities: []json.RawMessage{
			json.RawMessage(`{"id":"pid_91000004-0000-4000-8000-000000000004","kind":"bucket"}`),
			json.RawMessage(`{"id":"pid_91000003-0000-4000-8000-000000000003","kind":"role"}`),
		},
		Relationships: []json.RawMessage{json.RawMessage(`{"id":"pid_91000005-0000-4000-8000-000000000005","kind":"contains"}`)},
		Evidence:      []json.RawMessage{},
	}
	result, err := projector.Project(context.Background(), candidate)
	if err != nil || result.Receipt != store.result.Receipt || result.Digest != contentDigest {
		t.Fatalf("Project() = %#v, %v", result, err)
	}
	wantOrder := []string{
		"entities:pid_91000003-0000-4000-8000-000000000003",
		"entities:pid_91000004-0000-4000-8000-000000000004",
		"relationships:pid_91000005-0000-4000-8000-000000000005",
	}
	gotOrder := make([]string, len(store.input.Items))
	for index, item := range store.input.Items {
		gotOrder[index] = item.Section + ":" + item.ID.String()
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) || !bytes.Equal(store.input.Items[0].Payload, candidate.Entities[1]) {
		t.Fatalf("canonical items = %#v", store.input.Items)
	}

	candidate.Generation++
	candidate.SnapshotID = riskProjectionID(t, "pid_91000006-0000-4000-8000-000000000006")
	store.result.SnapshotID = candidate.SnapshotID
	store.result.Generation = candidate.Generation
	candidate.Entities = []json.RawMessage{}
	candidate.Relationships = []json.RawMessage{}
	candidate.Evidence = []json.RawMessage{}
	if _, err := projector.Project(context.Background(), candidate); err != nil || store.input.Items == nil || len(store.input.Items) != 0 {
		t.Fatalf("complete empty projection input=%#v err=%v", store.input.Items, err)
	}
}

func TestProjectorRejectsUnboundOrMalformedRiskInput(t *testing.T) {
	scope := riskProjectionScope(t)
	integrationID := riskProjectionID(t, "pid_92000001-0000-4000-8000-000000000001")
	snapshotID := riskProjectionID(t, "pid_92000002-0000-4000-8000-000000000002")
	digest := sha256.Sum256([]byte("candidate"))
	valid := Candidate{
		Scope: scope, IntegrationID: integrationID, SnapshotID: snapshotID, Source: "okta", Generation: 1,
		Version: "v1", Worker: "projection-risk-01", LeaseToken: "projection-token-00000001", InputDigest: digest,
		Entities: []json.RawMessage{json.RawMessage(`{"id":"pid_92000003-0000-4000-8000-000000000003"}`)}, Relationships: []json.RawMessage{}, Evidence: []json.RawMessage{},
	}
	store := &recordingStore{result: ApplyResult{SnapshotID: snapshotID, IntegrationID: integrationID, Source: "okta", Generation: 1, InputDigest: digest, ContentDigest: digest, Receipt: "postgres:risk-input:pid_92000002-0000-4000-8000-000000000002:sha256:" + strings.Repeat("a", 64)}}
	projector, err := NewProjector(store)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Candidate){
		"wrong source":  func(value *Candidate) { value.Source = "nango" },
		"missing lease": func(value *Candidate) { value.LeaseToken = "" },
		"zero digest":   func(value *Candidate) { value.InputDigest = [sha256.Size]byte{} },
		"duplicate id":  func(value *Candidate) { value.Evidence = append(value.Evidence, value.Entities[0]) },
		"malformed envelope": func(value *Candidate) {
			value.Entities[0] = json.RawMessage(`{"id":"pid_92000003-0000-4000-8000-000000000003"} trailing`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Entities = append([]json.RawMessage(nil), valid.Entities...)
			candidate.Relationships = append([]json.RawMessage(nil), valid.Relationships...)
			candidate.Evidence = append([]json.RawMessage(nil), valid.Evidence...)
			mutate(&candidate)
			if _, err := projector.Project(context.Background(), candidate); !errors.Is(err, ErrRejected) {
				t.Fatalf("Project() error = %v", err)
			}
		})
	}
}

type recordingStore struct {
	input  CompleteInput
	result ApplyResult
	err    error
}

func (store *recordingStore) ApplyComplete(_ context.Context, input CompleteInput) (ApplyResult, error) {
	store.input = input
	return store.result, store.err
}

func riskProjectionScope(t *testing.T) domain.Scope {
	t.Helper()
	organization := riskProjectionID(t, "pid_90000001-0000-4000-8000-000000000001")
	workspace := riskProjectionID(t, "pid_90000002-0000-4000-8000-000000000002")
	environment := riskProjectionID(t, "pid_90000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func riskProjectionID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
