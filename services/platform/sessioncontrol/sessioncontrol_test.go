package sessioncontrol

import (
	"context"
	"testing"
	"time"
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
