package reconciliation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestCanonicalReconciliationPreservesScopedIDsAndEvidence(t *testing.T) {
	store := NewMemoryStore()
	scope := fixtureScope(t, 1)
	input := SourceAsset{Scope: scope, Source: "aws", SourceID: "arn:aws:lambda:us-east-1:000000000000:function:agent", Kind: KindAsset, Name: "Agent runtime", EvidenceID: fixtureID(t, 9), SeenAt: fixtureTime()}
	first, err := store.Reconcile(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	input.Name = "Agent runtime updated"
	input.SeenAt = fixtureTime().Add(time.Millisecond)
	second, err := store.Reconcile(context.Background(), input)
	if err != nil || first.ID != second.ID || second.Name != input.Name || second.EvidenceID != input.EvidenceID {
		t.Fatalf("first=%+v second=%+v err=%v", first, second, err)
	}
	foreign := input
	foreign.Scope = fixtureScope(t, 20)
	third, err := store.Reconcile(context.Background(), foreign)
	if err != nil || third.ID == first.ID {
		t.Fatalf("cross-scope identity collision: %+v %v", third, err)
	}
}

func TestTypedAgentToolIdentityAndRuntimeReconciliation(t *testing.T) {
	store := NewMemoryStore()
	scope := fixtureScope(t, 1)
	values := []SourceAsset{
		{Scope: scope, Source: "aws", SourceID: "agent-1", Kind: KindAgent, Name: "Support agent", Owner: "security", Team: "agent-platform", Tags: []string{"production", "reviewed"}, EvidenceID: fixtureID(t, 9), SeenAt: fixtureTime()},
		{Scope: scope, Source: "github", SourceID: "tool-1", Kind: KindTool, Name: "Issue tool", EvidenceID: fixtureID(t, 10), SeenAt: fixtureTime()},
		{Scope: scope, Source: "idp", SourceID: "identity-1", Kind: KindIdentity, Name: "Agent service principal", CredentialReference: "connection_ref_identity", CredentialFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EvidenceID: fixtureID(t, 11), SeenAt: fixtureTime()},
		{Scope: scope, Source: "kubernetes", SourceID: "runtime-1", Kind: KindRuntime, Name: "agent-pod", WorkloadID: "pod/agent-1", SandboxID: "sandbox-1", Isolation: "container", EvidenceID: fixtureID(t, 12), SeenAt: fixtureTime()},
	}
	for _, value := range values {
		first, err := store.Reconcile(context.Background(), value)
		second, replayErr := store.Reconcile(context.Background(), value)
		if err != nil || replayErr != nil || first.ID != second.ID || first.Kind != value.Kind {
			t.Fatalf("kind=%s first=%+v second=%+v err=%v/%v", value.Kind, first, second, err, replayErr)
		}
	}
	forged := values[2]
	forged.RawCredential = "must-never-cross-boundary"
	if _, err := store.Reconcile(context.Background(), forged); err == nil {
		t.Fatal("raw credential was retained")
	}
}

func TestReconciliationRejectsCrossKindFieldsAndNoncanonicalValues(t *testing.T) {
	store := NewMemoryStore()
	scope := fixtureScope(t, 1)
	base := SourceAsset{Scope: scope, Source: "idp", SourceID: "identity-1", Kind: KindIdentity, Name: "Agent identity", CredentialReference: "connection_ref_identity", CredentialFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EvidenceID: fixtureID(t, 11), SeenAt: fixtureTime()}

	mutations := []func(*SourceAsset){
		func(value *SourceAsset) {
			value.CredentialFingerprint = "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
		},
		func(value *SourceAsset) {
			value.CredentialFingerprint = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		func(value *SourceAsset) { value.SandboxID = "identity-cannot-own-a-sandbox" },
		func(value *SourceAsset) { value.SeenAt = value.SeenAt.Add(time.Nanosecond) },
	}
	for index, mutate := range mutations {
		forged := base
		mutate(&forged)
		if _, err := store.Reconcile(context.Background(), forged); err == nil {
			t.Fatalf("mutation %d passed", index)
		}
	}

	agent := SourceAsset{Scope: scope, Source: "aws", SourceID: "agent-1", Kind: KindAgent, Name: "Agent", EvidenceID: fixtureID(t, 9), SeenAt: fixtureTime(), Isolation: "container"}
	if _, err := store.Reconcile(context.Background(), agent); err == nil {
		t.Fatal("agent accepted a runtime-only field")
	}
}

func TestOwnershipAuditAndRelationshipProjectionAreIdempotent(t *testing.T) {
	store := NewMemoryStore()
	scope := fixtureScope(t, 1)
	agent, err := store.Reconcile(context.Background(), SourceAsset{Scope: scope, Source: "aws", SourceID: "agent-1", Kind: KindAgent, Name: "Agent", EvidenceID: fixtureID(t, 9), SeenAt: fixtureTime()})
	if err != nil {
		t.Fatal(err)
	}
	tool, err := store.Reconcile(context.Background(), SourceAsset{Scope: scope, Source: "github", SourceID: "tool-1", Kind: KindTool, Name: "Tool", EvidenceID: fixtureID(t, 10), SeenAt: fixtureTime()})
	if err != nil {
		t.Fatal(err)
	}
	updated, audit, err := store.UpdateOwnership(context.Background(), scope, agent.ID, "security", "agent-platform", []string{"critical", "production"}, fixtureTime().Add(time.Millisecond))
	if err != nil || updated.Owner != "security" || audit.AssetID != agent.ID || audit.Scope != scope {
		t.Fatalf("updated=%+v audit=%+v err=%v", updated, audit, err)
	}
	projector := NewMemoryProjector()
	relationships := []Relationship{{From: agent.ID, Type: "uses", To: tool.ID, EvidenceID: fixtureID(t, 13)}}
	for range 2 {
		if err := ProjectRelationships(context.Background(), projector, scope, relationships); err != nil {
			t.Fatal(err)
		}
	}
	if projector.Count(scope) != 1 {
		t.Fatalf("relationship replay count=%d", projector.Count(scope))
	}
}

func TestRelationshipProjectionValidatesTheWholeSetBeforeWriting(t *testing.T) {
	projector := NewMemoryProjector()
	scope := fixtureScope(t, 1)
	values := []Relationship{
		{From: fixtureID(t, 9), Type: "uses", To: fixtureID(t, 10), EvidenceID: fixtureID(t, 11)},
		{From: fixtureID(t, 12), Type: "uses", To: fixtureID(t, 12), EvidenceID: fixtureID(t, 13)},
	}
	if err := ProjectRelationships(context.Background(), projector, scope, values); err == nil {
		t.Fatal("invalid relationship set was accepted")
	}
	if projector.Count(scope) != 0 {
		t.Fatalf("invalid set partially projected %d relationships", projector.Count(scope))
	}
}

func fixtureTime() time.Time { return time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC) }

func fixtureScope(t *testing.T, seed int) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(fixtureID(t, seed), fixtureID(t, seed+1), fixtureID(t, seed+2))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func fixtureID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
