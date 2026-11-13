package apiserver

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type requestAuthorizerContextKey struct{}

// secondaryRequestAuthorization obtains a second attested decision inside a
// request that already carries one. It is for a statement that needs targets
// the request's own proof does not name: a statement on the other database,
// or an object named in the request body. The second decision is made by the
// same authorizer for the same principal and credential, against current
// state, and is attested separately; nothing is copied from the first proof.
// A request that was not authorized by the router has no second decision.
func secondaryRequestAuthorization(ctx context.Context, identity RequestIdentity, route RoutedOperation) (RequestAuthorization, error) {
	if ctx == nil {
		return RequestAuthorization{}, ErrAuthorizationDenied
	}
	primary, checked := requestAuthorizationFromContext(ctx)
	authorizer, available := ctx.Value(requestAuthorizerContextKey{}).(RequestAuthorizer)
	if !checked || !available || nilInterface(authorizer) || primary.Identity.PrincipalID != identity.PrincipalID || primary.Identity.Scope != identity.Scope || primary.Credential.Kind != identity.CredentialKind {
		return RequestAuthorization{}, ErrAuthorizationDenied
	}
	grant, err := authorizer.Authorize(ctx, identity, primary.Credential, route)
	if err != nil {
		return RequestAuthorization{}, err
	}
	if grant.OperationID != route.OperationID || grant.Identity.PrincipalID != identity.PrincipalID || grant.Identity.Scope != identity.Scope {
		return RequestAuthorization{}, ErrAuthorizationDenied
	}
	// Both decisions of one request are made at one projection revision.
	if grant.Revision != primary.Revision {
		return RequestAuthorization{}, authorization.ErrConflict
	}
	return grant, nil
}

// secondaryAuthorizationError maps a refused second decision onto the errors
// a repository returns: a denial stays a denial, a moved revision is a
// retryable conflict, anything else is unavailable.
func secondaryAuthorizationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrAuthorizationDenied):
		return ErrRepositoryAuthorization
	case errors.Is(err, ErrRepositoryNotFound):
		return ErrRepositoryNotFound
	case authorization.RetryableConflict(err):
		return ErrRepositoryConflict
	default:
		return ErrRepositoryUnavailable
	}
}

const currentSecurityAgentHomeSummarySQL = `SELECT zasp_authorization80.security_agent_home_summary($1,$2,$3)`

// securityAgentHomeReader serves the Security Agent counts of the home
// summary from the Security Agent database, with a proof of its own whose
// targets that database resolved. The product database cannot read
// Temporal-owned runs, so its own summary cannot count them.
type securityAgentHomeReader struct{ database JSONDatabase }

type securityAgentHomeCounts struct {
	PendingApprovals         int64 `json:"pending_approvals"`
	OldestApprovalAgeSeconds int64 `json:"oldest_approval_age_seconds"`
	NeedsHumanRuns           int64 `json:"needs_human_runs"`
	FailedRuns               int64 `json:"failed_runs"`
	InconclusiveRuns         int64 `json:"inconclusive_runs"`
	RecentContained          int64 `json:"recent_contained"`
	RecentRemediated         int64 `json:"recent_remediated"`
}

// counts reads the Security Agent counts under their own proof. It reports
// false for a request without current authorization: the legacy reader counted
// runs and approvals itself.
func (reader *securityAgentHomeReader) counts(ctx context.Context, identity RequestIdentity) (securityAgentHomeCounts, bool, error) {
	if reader == nil || nilInterface(reader.database) {
		return securityAgentHomeCounts{}, false, nil
	}
	if _, checked := requestAuthorizationFromContext(ctx); !checked {
		return securityAgentHomeCounts{}, false, nil
	}
	grant, err := secondaryRequestAuthorization(withSecurityAgentAuthorization(ctx), identity, RoutedOperation{OperationID: "getHomeSummary"})
	if err != nil {
		return securityAgentHomeCounts{}, false, secondaryAuthorizationError(err)
	}
	scope := identity.Scope
	payload, err := reader.database.QueryJSON(context.WithValue(ctx, requestAuthorizationContextKey{}, grant), currentSecurityAgentHomeSummarySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		return securityAgentHomeCounts{}, false, inventoryProviderError(err)
	}
	var counts securityAgentHomeCounts
	if !exactJSONFields(payload, "failed_runs", "inconclusive_runs", "needs_human_runs", "oldest_approval_age_seconds", "pending_approvals", "recent_contained", "recent_remediated") || json.Unmarshal(payload, &counts) != nil {
		return securityAgentHomeCounts{}, false, ErrRepositoryUnavailable
	}
	return counts, true, nil
}

// apply replaces the run and approval counts of a summary with the Security
// Agent database's. A request without current authorization keeps the summary
// it has.
func (reader *securityAgentHomeReader) apply(ctx context.Context, identity RequestIdentity, summary HomeSummary) (HomeSummary, error) {
	counts, found, err := reader.counts(ctx, identity)
	if err != nil {
		return HomeSummary{}, err
	}
	if !found {
		return summary, nil
	}
	return mergeSecurityAgentHomeCounts(summary, counts)
}

func mergeSecurityAgentHomeCounts(summary HomeSummary, counts securityAgentHomeCounts) (HomeSummary, error) {
	summary.PendingApprovals, summary.OldestApprovalAgeSeconds = counts.PendingApprovals, counts.OldestApprovalAgeSeconds
	summary.NeedsHumanRuns, summary.FailedRuns, summary.InconclusiveRuns = counts.NeedsHumanRuns, counts.FailedRuns, counts.InconclusiveRuns
	summary.RecentContained, summary.RecentRemediated = counts.RecentContained, counts.RecentRemediated
	if !summary.environmentHealthUnavailable {
		summary.AttentionRequired = summary.HighRiskPaths > 0 || summary.PendingApprovals > 0 || summary.NeedsHumanRuns > 0 || summary.FailedRuns > 0 || summary.InconclusiveRuns > 0
		summary.Healthy = !summary.AttentionRequired
	}
	if !validHomeSummary(summary) {
		return HomeSummary{}, ErrRepositoryUnavailable
	}
	return summary, nil
}
