package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

type retentionSearchPages struct {
	pages      []searchdriver.SessionSearchPage
	after      []string
	limits     []int
	scopes     []domain.Scope
	rechecks   int
	recheckErr error
}

func (p *retentionSearchPages) RecheckRetainedCandidates(context.Context, domain.Scope, []searchdriver.SessionSearchPage) error {
	p.rechecks++
	return p.recheckErr
}

func (p *retentionSearchPages) Search(_ context.Context, scope domain.Scope, _ sessionsearch.Filters, after string, limit int) (searchdriver.SessionSearchPage, error) {
	n := len(p.after)
	p.after = append(p.after, after)
	p.limits = append(p.limits, limit)
	p.scopes = append(p.scopes, scope)
	if n >= len(p.pages) {
		return searchdriver.SessionSearchPage{}, ErrRepositoryUnavailable
	}
	return p.pages[n], nil
}

func TestRetentionSessionSearchPreservesVisiblePaginationAndCurrentHydration(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	a := "pid_99000001-0000-4000-8000-000000000001"
	b := "pid_99000001-0000-4000-8000-000000000002"
	c := "pid_99000001-0000-4000-8000-000000000003"
	for _, tc := range []struct {
		name    string
		pages   []searchdriver.SessionSearchPage
		want    []string
		cursors []string
		limits  []int
	}{
		{"hidden then live then end", []searchdriver.SessionSearchPage{{InvestigationIDs: []string{}, After: a}, {InvestigationIDs: []string{b}, After: c}, {InvestigationIDs: []string{}}}, []string{b}, []string{"", a, c}, []int{2, 2, 1}},
		{"visible lookahead fills public page", []searchdriver.SessionSearchPage{{InvestigationIDs: []string{a}, After: a}, {InvestigationIDs: []string{b}, After: c}}, []string{a, b}, []string{"", a}, []int{2, 1}},
		{"only hidden true end", []searchdriver.SessionSearchPage{{InvestigationIDs: []string{}, After: a}, {InvestigationIDs: []string{}}}, []string{}, []string{"", a}, []int{2, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &retentionSearchPages{pages: tc.pages}
			index, err := NewRetentionRuntimeSessionSearchIndex(provider)
			if err != nil {
				t.Fatal(err)
			}
			status := sessionQueryStatusFixture(t)
			items := make([]json.RawMessage, 0, len(tc.want))
			for _, id := range tc.want {
				items = append(items, sessionQuerySummaryFixture(t, identity, id))
			}
			db := &sessionQueryDatabase{responses: []json.RawMessage{status, sessionQueryPageFixture(t, status, items...)}}
			repo, err := NewPostgresRepositoryWithRuntimeSessionSearch(db, index)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = repo.ReadAdministration(context.Background(), identity, "listSessions", map[string]string{"kind": "runtime", "limit": "1"}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(provider.after, tc.cursors) || !reflect.DeepEqual(provider.limits, tc.limits) {
				t.Fatalf("lost provider continuation: %#v %#v", provider.after, provider.limits)
			}
			for _, scope := range provider.scopes {
				if scope != identity.Scope {
					t.Fatal("tenant scope changed")
				}
			}
			if len(db.calls) != 2 || !reflect.DeepEqual(db.arguments[1][4], tc.want) {
				t.Fatal("canonical hydration did not use the complete visible candidate set")
			}
		})
	}
}

func TestRetentionSessionSearchNeverConvertsIncompleteScanToPublicEnd(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	a := "pid_99000001-0000-4000-8000-000000000001"
	for _, tc := range []struct {
		name  string
		pages []searchdriver.SessionSearchPage
	}{
		{"stalled hidden cursor", []searchdriver.SessionSearchPage{{InvestigationIDs: []string{}, After: a}, {InvestigationIDs: []string{}, After: a}}},
		{"foreign allowed cursor", []searchdriver.SessionSearchPage{{InvestigationIDs: []string{}, After: "unattributed"}}},
		{"missing provider end", []searchdriver.SessionSearchPage{{InvestigationIDs: []string{a}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &retentionSearchPages{pages: tc.pages}
			index, _ := NewRetentionRuntimeSessionSearchIndex(provider)
			filters := sessionsearch.Filters{}
			if tc.name == "foreign allowed cursor" {
				filters.AuthorizationRestricted = true
				filters.AllowedInvestigationIDs = []string{a}
			}
			page, err := index.Search(context.Background(), identity.Scope, filters, "", 2)
			if !errors.Is(err, ErrRepositoryUnavailable) || page.InvestigationIDs != nil {
				t.Fatal("incomplete scan became public results")
			}
		})
	}
	pages := make([]searchdriver.SessionSearchPage, retentionSessionSearchPageBudget)
	for n := range pages {
		pages[n] = searchdriver.SessionSearchPage{InvestigationIDs: []string{}, After: fmt.Sprintf("pid_99000001-0000-4000-8000-%012d", n+1)}
	}
	provider := &retentionSearchPages{pages: pages}
	index, _ := NewRetentionRuntimeSessionSearchIndex(provider)
	page, err := index.Search(context.Background(), identity.Scope, sessionsearch.Filters{}, "", 2)
	if !errors.Is(err, ErrRepositoryUnavailable) || page.InvestigationIDs != nil || len(provider.after) != retentionSessionSearchPageBudget {
		t.Fatal("work budget became false final page")
	}
}
