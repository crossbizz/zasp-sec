package sessioncontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestSessionsComplianceAndDataControlBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	events := []SessionEvent{
		{ID: "event-2", SessionID: "session-1", Class: "policy", Label: "Blocked shell", EvidenceID: "evidence-2", Source: "runtime", Confidence: ConfidenceStrong, At: now.Add(time.Second)},
		{ID: "event-1", SessionID: "session-1", Class: "tool", Label: "Shell requested", EvidenceID: "evidence-1", Source: "semantic", Confidence: ConfidenceExact, At: now},
	}
	projector := NewProjector()
	for range 2 {
		if _, err := projector.Project(context.Background(), "session-1", "agent-1", "principal-1", events); err != nil {
			t.Fatal(err)
		}
	}
	session, err := projector.Get(context.Background(), "session-1")
	if err != nil || len(session.Events) != 2 || session.Events[0].ID != "event-1" || session.Events[1].Confidence != ConfidenceStrong {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	filter, err := BuildSessionFilter(SessionFilter{AgentID: "agent-1", Tool: "shell", Decision: "block", From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	if err != nil || filter["agent_id"] != "agent-1" {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
	if _, err := BuildSessionFilter(SessionFilter{RawQuery: "*:*"}); err == nil {
		t.Fatal("raw query accepted")
	}

	controls := []ComplianceControl{{ID: "soc2-security", Framework: "SOC 2", Name: "Security", EvidenceIDs: []string{"evidence-1"}, FreshUntil: now.Add(time.Hour)}, {ID: "hipaa-safeguard", Framework: "HIPAA", Name: "Technical safeguard", EvidenceIDs: []string{"evidence-stale"}, FreshUntil: now.Add(-time.Hour)}}
	assembled, err := AssembleComplianceEvidence(controls, []EvidenceRecord{{ID: "evidence-1", AssetID: "agent-1", Source: "runtime", At: now}, {ID: "evidence-stale", AssetID: "agent-1", Source: "audit", At: now.Add(-48 * time.Hour)}}, now)
	if err != nil || assembled[1].Freshness != "stale" {
		t.Fatalf("assembled=%+v err=%v", assembled, err)
	}
	exported, err := BuildComplianceExport("export-1", assembled)
	if err != nil || len(exported.JSON) == 0 || len(exported.CSV) == 0 || exported.Human == "" {
		t.Fatalf("export=%+v err=%v", exported, err)
	}
	if containsCertificationLanguage(exported.Human) {
		t.Fatal("export claimed certification")
	}

	data := NewDataControlStore()
	settings := DataControls{EnvironmentID: "environment-1", EnvironmentClass: "production", CollectionMode: "metadata_only", RetentionDays: 30, DeletionEnabled: true}
	if err := data.Update(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if got, err := data.Get(context.Background(), "environment-1"); err != nil || got.CollectionMode != "metadata_only" {
		t.Fatalf("settings=%+v err=%v", got, err)
	}
}

func TestComplianceExportPersistsExactArtifact(t *testing.T) {
	values := []ComplianceEvidence{{
		Control:  ComplianceControl{ID: "soc2-security", Framework: "SOC 2", Name: "Security", EvidenceIDs: []string{"evidence-1"}, FreshUntil: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)},
		Evidence: []EvidenceRecord{{ID: "evidence-1", AssetID: "asset-1", Source: "runtime", At: time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)}}, Freshness: "fresh",
	}}
	exported, err := BuildComplianceExport("export-1", values)
	if err != nil {
		t.Fatal(err)
	}
	locator := complianceExportLocator(t)
	store := &complianceArtifactStore{}
	artifact, err := WriteComplianceExportArtifact(context.Background(), store, locator.Scope, locator.Reference, exported)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.request.Locator != locator || store.request.MediaType != "application/json" || !bytes.Equal(store.request.Body, artifact.Body) {
		t.Fatalf("request=%+v artifact=%+v", store.request, artifact)
	}
	if artifact.Size != int64(len(artifact.Body)) || artifact.SHA256 != sha256.Sum256(artifact.Body) ||
		!bytes.Contains(artifact.Body, []byte("evidence-1")) || !bytes.Contains(artifact.Body, []byte("2026-08-18T00:00:00Z")) ||
		!bytes.Contains(artifact.Body, []byte("control_id,framework,freshness,evidence_count")) || containsCertificationLanguage(string(artifact.Body)) {
		t.Fatalf("artifact=%s", artifact.Body)
	}
	store.mutate = true
	if _, err := WriteComplianceExportArtifact(context.Background(), store, locator.Scope, locator.Reference, exported); !errors.Is(err, ErrRejected) {
		t.Fatalf("mutated store result error=%v", err)
	}
}

type complianceArtifactStore struct {
	calls   int
	request artifactstore.PutRequest
	mutate  bool
}

func (s *complianceArtifactStore) Put(_ context.Context, request artifactstore.PutRequest) (artifactstore.Artifact, error) {
	s.calls++
	s.request = request
	body := bytes.Clone(request.Body)
	if s.mutate {
		body = append(body, 'x')
	}
	return artifactstore.Artifact{Locator: request.Locator, MediaType: request.MediaType, Body: body, Size: int64(len(body)), SHA256: sha256.Sum256(body)}, nil
}
func (*complianceArtifactStore) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	return artifactstore.Artifact{}, errors.New("unexpected get")
}
func (*complianceArtifactStore) Delete(context.Context, artifactstore.Locator) error {
	return errors.New("unexpected delete")
}

func complianceExportLocator(t *testing.T) artifactstore.Locator {
	t.Helper()
	ids := make([]domain.ProductID, 4)
	for index := range ids {
		value, err := domain.ParseProductID("pid_00000000-0000-4000-8000-00000000000" + string(rune('1'+index)))
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = value
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	reference, err := domain.NewEvidenceRef(ids[3])
	if err != nil {
		t.Fatal(err)
	}
	return artifactstore.Locator{Scope: scope, Reference: reference}
}
