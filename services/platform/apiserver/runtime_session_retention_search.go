package apiserver

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	searchdriver "github.com/zasp-ai/zasp-sec/services/platform/runtimeindex/opensearchdriver"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

const retentionSessionSearchPageBudget = 8

type retentionCandidateRechecker interface {
	RecheckRetainedCandidates(context.Context, domain.Scope, []searchdriver.SessionSearchPage) error
}

// NewRetentionRuntimeSessionSearchIndex composes an explicitly retention-aware
// index with bounded pagination. Hidden matching buckets may consume provider
// pages; a short public page is returned only after an authoritative provider
// end. Exhausting the work budget returns unavailable rather than a false end.
func NewRetentionRuntimeSessionSearchIndex(index RuntimeSessionSearchIndex) (RuntimeSessionSearchIndex, error) {
	if nilInterface(index) {
		return nil, ErrRepositoryConfiguration
	}
	if _, ok := index.(retentionCandidateRechecker); !ok {
		return nil, ErrRepositoryConfiguration
	}
	return &retentionRuntimeSessionSearchIndex{next: index}, nil
}

type retentionRuntimeSessionSearchIndex struct{ next RuntimeSessionSearchIndex }

func (index *retentionRuntimeSessionSearchIndex) Search(ctx context.Context, scope domain.Scope, filters sessionsearch.Filters, after string, limit int) (searchdriver.SessionSearchPage, error) {
	if ctx == nil || ctx.Err() != nil || index == nil || nilInterface(index.next) {
		return searchdriver.SessionSearchPage{}, ErrRepositoryUnavailable
	}
	if _, err := sessionsearch.BuildQuery(scope, filters, after, limit); err != nil {
		return searchdriver.SessionSearchPage{}, ErrRepositoryOperation
	}
	allowed := make(map[string]bool, len(filters.AllowedInvestigationIDs))
	for _, id := range filters.AllowedInvestigationIDs {
		allowed[id] = true
	}
	result := searchdriver.SessionSearchPage{InvestigationIDs: make([]string, 0, limit)}
	cursor := after
	lastProviderAfter := ""
	retainedPages := make([]searchdriver.SessionSearchPage, 0, retentionSessionSearchPageBudget)
	finish := func() (searchdriver.SessionSearchPage, error) {
		if len(result.InvestigationIDs) != 0 {
			if err := index.next.(retentionCandidateRechecker).RecheckRetainedCandidates(ctx, scope, retainedPages); err != nil || ctx.Err() != nil {
				return searchdriver.SessionSearchPage{}, ErrRepositoryUnavailable
			}
		}
		return result, nil
	}
	for scanned := 0; scanned < retentionSessionSearchPageBudget; scanned++ {
		remaining := limit - len(result.InvestigationIDs)
		page, err := index.next.Search(ctx, scope, filters, cursor, remaining)
		if err != nil || ctx.Err() != nil || page.InvestigationIDs == nil || len(page.InvestigationIDs) > remaining {
			return searchdriver.SessionSearchPage{}, ErrRepositoryUnavailable
		}
		previous := cursor
		for _, id := range page.InvestigationIDs {
			if !runtimeSessionTarget(id) || id <= previous || filters.AuthorizationRestricted && !allowed[id] {
				return searchdriver.SessionSearchPage{}, ErrRepositoryUnavailable
			}
			previous = id
		}
		if page.After == "" {
			if len(page.InvestigationIDs) != 0 {
				return searchdriver.SessionSearchPage{}, ErrRepositoryUnavailable
			}
			// Preserve the last actual continuation for canonical hydration's
			// candidate contract. It is not the public signed page cursor.
			if len(result.InvestigationIDs) != 0 {
				result.After = lastProviderAfter
			}
			return finish()
		}
		if !runtimeSessionTarget(page.After) || page.After <= cursor || page.After < previous || filters.AuthorizationRestricted && !allowed[page.After] {
			return searchdriver.SessionSearchPage{}, ErrRepositoryUnavailable
		}
		result.InvestigationIDs = append(result.InvestigationIDs, page.InvestigationIDs...)
		if len(page.InvestigationIDs) != 0 {
			retainedPages = append(retainedPages, page)
		}
		lastProviderAfter = page.After
		if len(result.InvestigationIDs) == limit {
			result.After = page.After
			return finish()
		}
		cursor = page.After
	}
	return searchdriver.SessionSearchPage{}, ErrRepositoryUnavailable
}
