package connectormaintenance

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type pinFreshnessFixture struct {
	facts                             Facts
	revision                          authorization.Revision
	events                            []string
	mutate                            string
	factsReads, revisionReads, checks int
}

func (f *pinFreshnessFixture) Facts(context.Context, Reference) (Facts, error) {
	f.events = append(f.events, "facts")
	f.factsReads++
	result := f.facts
	if f.factsReads == 2 && f.mutate == "facts" {
		result.ContextDigest = strings.Repeat("b", 64)
	}
	if f.mutate == "expired" {
		result.Expires = time.Now().Add(-time.Second)
	}
	return result, nil
}
func (f *pinFreshnessFixture) Revision(context.Context, string) (authorization.Revision, error) {
	f.events = append(f.events, "revision")
	f.revisionReads++
	result := f.revision
	if f.revisionReads == 2 && f.mutate == "revision" {
		result.Generation++
	}
	return result, nil
}
func (f *pinFreshnessFixture) Observe(ctx context.Context, ref Reference) (Facts, authorization.Revision, error) {
	facts, err := f.Facts(ctx, ref)
	if err != nil {
		return Facts{}, authorization.Revision{}, err
	}
	revision, err := f.Revision(ctx, ref.Organization)
	return facts, revision, err
}
func (f *pinFreshnessFixture) Check(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
	f.events = append(f.events, q.PrincipalKind)
	f.checks++
	return authorization.Decision{Allowed: !(f.mutate == q.PrincipalKind), ModelID: f.revision.ModelID}, nil
}
func newPinFreshnessFixture(sourcePin string) *pinFreshnessFixture {
	id := "pid_78219301-0000-4000-8000-000000000001"
	d := strings.Repeat("a", 64)
	ref := Reference{Organization: id, Workspace: "pid_78219302-0000-4000-8000-000000000002", Environment: "pid_78219303-0000-4000-8000-000000000003", Effect: id, Integration: id, Owner: "worker", Token: d, IntentDigest: d}
	return &pinFreshnessFixture{facts: Facts{ContextDigest: d, Profile: d, Reference: ref, Task: id, Purpose: "connector_reconciliation", Grantor: id, Service: id, SourceProfile: sourcePin, SourceProofDigest: d, CommittedRequestDigest: d, CommittedEffectDigest: d, Operation: "pkce_cleanup", Expires: time.Now().Add(time.Minute), SessionUser: "registered_worker"}, revision: authorization.Revision{OrganizationID: id, Desired: 1, Applied: 1, Generation: 1, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"}}
}
func TestCompiledPinKeepsFreshConnectorAuthority(t *testing.T) {
	compiled := migrations.ProductionAuthorizationEnforcement().Checksum()
	t.Run("constructor captures exact compiled pin and source mismatch denies", func(t *testing.T) {
		f := newPinFreshnessFixture(compiled)
		a, err := NewAuthority(f, f, f.revision.StoreID, f.revision.ModelID, f.facts.Profile, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		if a.sourceProfile != compiled {
			t.Fatal("constructor changed compiled pin")
		}
		for _, expected := range []string{"", strings.Repeat("b", 64)} {
			if validFacts(f.facts, f.facts.Reference, f.facts.Profile, expected) {
				t.Fatal("missing or mismatched source pin admitted")
			}
		}
		f.facts.SourceProfile = strings.Repeat("b", 64)
		if _, err = a.Authorize(context.Background(), f.facts.Reference, BeforeSecretFailure); !errors.Is(err, ErrUnavailable) {
			t.Fatal("wrong native source admitted")
		}
	})
	for _, mutation := range []string{"", "user", "service", "revision", "facts", "expired"} {
		t.Run("live checks "+mutation, func(t *testing.T) {
			f := newPinFreshnessFixture(compiled)
			f.mutate = mutation
			a, err := NewAuthority(f, f, f.revision.StoreID, f.revision.ModelID, f.facts.Profile, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			proof, err := a.Authorize(context.Background(), f.facts.Reference, BeforeSecretFailure)
			if mutation != "" {
				if err == nil || len(proof) != 0 {
					t.Fatal("changed current authority admitted")
				}
				return
			}
			if err != nil || len(proof) == 0 {
				t.Fatalf("current authority refused: %v; stages %v", err, f.events)
			}
			want := []string{"facts", "revision", "user", "service", "facts", "revision"}
			if !reflect.DeepEqual(f.events, want) {
				t.Fatal("fresh authorization sequence changed")
			}
			if _, err = a.Authorize(context.Background(), f.facts.Reference, BeforeProvider); err != nil {
				t.Fatal(err)
			}
			if f.factsReads != 4 || f.revisionReads != 4 || f.checks != 4 {
				t.Fatal("subsequent phase reused live authority")
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err = a.Authorize(canceled, f.facts.Reference, BeforeProvider); err == nil {
				t.Fatal("canceled provider admitted")
			}
		})
	}
}
func BenchmarkCompiledConnectorFacts(b *testing.B) {
	compiled := migrations.ProductionAuthorizationEnforcement().Checksum()
	f := newPinFreshnessFixture(compiled)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !validFacts(f.facts, f.facts.Reference, f.facts.Profile, compiled) {
			b.Fatal("live facts refused")
		}
	}
}
