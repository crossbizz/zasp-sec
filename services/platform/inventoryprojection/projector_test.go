package inventoryprojection

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProjectRequiresExplicitProviderAwareIdentityBindings(t *testing.T) {
	scope := projectionScope(t, 1)
	aws := projectionObservation(t, scope, 10, "aws", "accounts", KindAsset, "account", "shared-native", 20)
	github := projectionObservation(t, scope, 11, "github", "installations", KindAsset, "installation", "shared-native", 21)

	projected, err := projectCurrent([]Observation{aws, github})
	if err != nil || len(projected) != 2 || projected[0].ID == projected[1].ID {
		t.Fatalf("projected=%+v err=%v", projected, err)
	}

	conflict := aws
	conflict.Binding.CanonicalID = projectionID(t, 99)
	if _, err := projectCurrent([]Observation{aws, conflict}); err == nil {
		t.Fatal("one exact provider/source identity bound to two canonical IDs")
	}
	kindDrift := aws
	kindDrift.Binding.Kind = KindAgent
	kindDrift.Binding.CanonicalID = projectionID(t, 98)
	if _, err := projectCurrent([]Observation{aws, kindDrift}); err == nil {
		t.Fatal("one reviewed namespace identity drifted across kind and canonical ID")
	}

	wrongScope := aws
	wrongScope.Binding.Scope = projectionScope(t, 30)
	if _, err := projectCurrent([]Observation{aws, wrongScope}); err != nil {
		t.Fatalf("independent scopes should not conflict: %v", err)
	}
	crossIntegration := aws
	crossIntegration.Binding.IntegrationID = projectionID(t, 12)
	crossIntegration.Binding.CanonicalID = projectionID(t, 97)
	if _, err := projectCurrent([]Observation{aws, crossIntegration}); err == nil {
		t.Fatal("one provider/source namespace identity drifted across integrations")
	}
}

func TestProjectIsDeterministicAcrossSourceArrivalOrder(t *testing.T) {
	scope := projectionScope(t, 1)
	preferred := projectionObservation(t, scope, 10, "aws", "accounts", "asset", "account", "123456789012", 20)
	preferred.DisplayName = "Production account"
	preferred.Binding.Priority = 10
	preferred.ConfidenceBasisPoints = 9600
	secondary := projectionObservation(t, scope, 11, "kubernetes", "clusters", "asset", "account", "cluster-production", 20)
	secondary.DisplayName = "prod"
	secondary.Binding.Priority = 20
	secondary.ConfidenceBasisPoints = 9000

	first, err := projectCurrent([]Observation{secondary, preferred})
	if err != nil {
		t.Fatal(err)
	}
	second, err := projectCurrent([]Observation{preferred, secondary})
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("first=%+v second=%+v err=%v", first, second, err)
	}
	if len(first) != 1 || first[0].DisplayName != "Production account" || first[0].ConfidenceBasisPoints != 9600 || len(first[0].Sources) != 2 {
		t.Fatalf("projection=%+v", first)
	}
	if first[0].Sources[0].Provider != "aws" || first[0].Sources[1].Provider != "kubernetes" {
		t.Fatalf("sources not canonical: %+v", first[0].Sources)
	}
}

func TestProjectCompleteEmptyAndSourceRemovalPreserveOtherSources(t *testing.T) {
	scope := projectionScope(t, 1)
	aws := projectionObservation(t, scope, 10, "aws", "accounts", "asset", "account", "shared", 20)
	kubernetes := projectionObservation(t, scope, 11, "kubernetes", "clusters", "asset", "account", "shared", 20)

	both, err := projectCurrent([]Observation{aws, kubernetes})
	if err != nil || len(both) != 1 || len(both[0].Sources) != 2 {
		t.Fatalf("both=%+v err=%v", both, err)
	}
	remaining, err := projectCurrent([]Observation{kubernetes})
	if err != nil || len(remaining) != 1 || len(remaining[0].Sources) != 1 || remaining[0].Sources[0].Provider != "kubernetes" {
		t.Fatalf("remaining=%+v err=%v", remaining, err)
	}
	emptyFence := sourceFenceFor(aws)
	emptyFence.ObservationCount = 0
	empty, err := Project([]SourceFence{emptyFence}, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
}

func TestProjectRejectsMissingEvidenceFreshnessConfidenceAndBindingDrift(t *testing.T) {
	scope := projectionScope(t, 1)
	base := projectionObservation(t, scope, 10, "aws", "accounts", "asset", "account", "123456789012", 20)
	mutations := []func(*Observation){
		func(value *Observation) { value.EvidenceID = domain.ProductID{} },
		func(value *Observation) { value.SnapshotID = domain.ProductID{} },
		func(value *Observation) { value.ConfidenceBasisPoints = 10001 },
		func(value *Observation) { value.FreshUntil = value.ObservedAt.Add(-time.Second) },
		func(value *Observation) { value.ObservedAt = value.ObservedAt.Add(time.Nanosecond) },
		func(value *Observation) { value.Binding.Provider = "AWS" },
		func(value *Observation) { value.Binding.Namespace = "account/unsafe" },
		func(value *Observation) { value.Binding.RuleVersion = 0 },
		func(value *Observation) { value.DisplayName = " token=must-not-pass " },
	}
	for index, mutate := range mutations {
		candidate := base
		mutate(&candidate)
		if _, err := projectCurrent([]Observation{candidate}); err == nil {
			t.Fatalf("mutation %d passed: %+v", index, candidate)
		}
	}

	otherKind := base
	otherKind.Binding.IntegrationID = projectionID(t, 12)
	otherKind.Binding.Kind = KindAgent
	if _, err := projectCurrent([]Observation{base, otherKind}); err == nil {
		t.Fatal("one canonical ID accepted conflicting kinds")
	}
}

func TestProjectClonesInputsAndEmitsStableTypedAnnotations(t *testing.T) {
	scope := projectionScope(t, 1)
	observation := projectionObservation(t, scope, 10, "aws", "accounts", "agent", "agent", "agent-1", 20)
	annotation := Annotation{Scope: scope, EntityID: observation.Binding.CanonicalID, Owner: "security", Team: "agent-platform", Tags: []string{"production", "critical"}, Version: 3}
	projected, err := ProjectWithAnnotations(fencesFor([]Observation{observation}), []Observation{observation}, []Annotation{annotation})
	if err != nil || len(projected) != 1 {
		t.Fatalf("projected=%+v err=%v", projected, err)
	}
	annotation.Tags[0] = "mutated"
	if !reflect.DeepEqual(projected[0].Tags, []string{"critical", "production"}) || projected[0].Owner != "security" || projected[0].Team != "agent-platform" {
		t.Fatalf("annotation=%+v", projected[0])
	}

	duplicate := annotation
	duplicate.Version++
	if _, err := ProjectWithAnnotations(fencesFor([]Observation{observation}), []Observation{observation}, []Annotation{annotation, duplicate}); err == nil {
		t.Fatal("multiple annotation authorities accepted")
	}
	emptyFence := sourceFenceFor(observation)
	emptyFence.ObservationCount = 0
	empty, err := ProjectWithAnnotations([]SourceFence{emptyFence}, nil, []Annotation{annotation})
	if err != nil || len(empty) != 0 {
		t.Fatalf("annotation blocked complete empty: %+v err=%v", empty, err)
	}
}

func TestProjectRejectsMixedCurrentSnapshotAuthority(t *testing.T) {
	scope := projectionScope(t, 1)
	first := projectionObservation(t, scope, 10, "aws", "accounts", KindAsset, "account", "one", 20)
	second := projectionObservation(t, scope, 10, "aws", "accounts", KindAsset, "account", "two", 21)
	fence := sourceFenceFor(first)
	fence.ObservationCount = 2
	second.SnapshotID = projectionID(t, 999)
	second.Generation++
	if _, err := Project([]SourceFence{fence}, []Observation{first, second}); err == nil {
		t.Fatal("mixed complete snapshots were accepted")
	}
	if _, err := Project([]SourceFence{fence}, []Observation{first}); err == nil {
		t.Fatal("missing current observation was accepted")
	}
}

func TestProjectBindsSummaryAuthorityToWinningSource(t *testing.T) {
	scope := projectionScope(t, 1)
	winner := projectionObservation(t, scope, 10, "aws", "accounts", KindAsset, "account", "one", 20)
	winner.Binding.Priority = 1
	secondary := projectionObservation(t, scope, 11, "kubernetes", "clusters", KindAsset, "account", "two", 20)
	secondary.Binding.Priority = 2
	secondary.EvidenceID = projectionID(t, 998)
	secondary.ConfidenceBasisPoints = 10000
	secondary.ObservedAt = winner.ObservedAt.Add(time.Hour)
	secondary.LastSeen = secondary.ObservedAt
	secondary.FreshUntil = secondary.ObservedAt.Add(2 * time.Hour)
	secondary.SourceProjectionVersion = 99

	projected, err := projectCurrent([]Observation{secondary, winner})
	if err != nil || len(projected) != 1 {
		t.Fatalf("projected=%+v err=%v", projected, err)
	}
	value := projected[0]
	if value.WinningEvidenceID != winner.EvidenceID || value.ConfidenceBasisPoints != winner.ConfidenceBasisPoints || value.ObservedAt != winner.ObservedAt || value.FreshUntil != winner.FreshUntil || value.ProjectionVersion != winner.SourceProjectionVersion {
		t.Fatalf("summary authority mixed sources: %+v", value)
	}
	if value.AggregateFirstSeen != winner.FirstSeen || value.AggregateLastSeen != secondary.LastSeen {
		t.Fatalf("aggregate lifecycle incorrect: %+v", value)
	}
}

func projectionObservation(t *testing.T, scope domain.Scope, integrationSeed int, provider, source string, kind Kind, namespace, nativeID string, canonicalSeed int) Observation {
	t.Helper()
	observed := time.Date(2026, 8, 19, 20, 0, 0, 0, time.UTC)
	return Observation{
		Binding: IdentityBinding{
			Scope:          scope,
			IntegrationID:  projectionID(t, integrationSeed),
			Provider:       provider,
			Source:         source,
			Kind:           kind,
			Namespace:      namespace,
			SourceNativeID: nativeID,
			CanonicalID:    projectionID(t, canonicalSeed),
			RuleVersion:    1,
			Priority:       100,
		},
		SnapshotID:              projectionID(t, integrationSeed+100),
		SnapshotContentDigest:   sha256.Sum256([]byte(fmt.Sprintf("snapshot-%d", integrationSeed))),
		Generation:              7,
		DisplayName:             "Production",
		EvidenceID:              projectionID(t, integrationSeed+200),
		ConfidenceBasisPoints:   9500,
		FirstSeen:               observed.Add(-time.Hour),
		LastSeen:                observed,
		ObservedAt:              observed,
		FreshUntil:              observed.Add(time.Hour),
		SourceProjectionVersion: 1,
	}
}

func projectCurrent(observations []Observation) ([]EntityProjection, error) {
	return Project(fencesFor(observations), observations)
}

func fencesFor(observations []Observation) []SourceFence {
	bySource := map[string]SourceFence{}
	for _, observation := range observations {
		key := fmt.Sprintf("%s/%s/%s/%s", observation.Binding.Scope.OrganizationID(), observation.Binding.IntegrationID, observation.Binding.Provider, observation.Binding.Source)
		fence, exists := bySource[key]
		if !exists {
			fence = sourceFenceFor(observation)
		}
		fence.ObservationCount++
		bySource[key] = fence
	}
	result := make([]SourceFence, 0, len(bySource))
	for _, fence := range bySource {
		result = append(result, fence)
	}
	return result
}

func sourceFenceFor(observation Observation) SourceFence {
	return SourceFence{
		Scope:             observation.Binding.Scope,
		IntegrationID:     observation.Binding.IntegrationID,
		Provider:          observation.Binding.Provider,
		Source:            observation.Binding.Source,
		SnapshotID:        observation.SnapshotID,
		Generation:        observation.Generation,
		ContentDigest:     observation.SnapshotContentDigest,
		ProjectionVersion: observation.SourceProjectionVersion,
	}
}

func projectionScope(t *testing.T, seed int) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(projectionID(t, seed), projectionID(t, seed+1), projectionID(t, seed+2))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func projectionID(t *testing.T, seed int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", seed, seed))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
