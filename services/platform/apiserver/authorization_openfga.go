package apiserver

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var ErrAuthorizationDenied = errors.New("current authorization denied")

type requestAuthorizationContextKey struct{}

func requestAuthorizationFromContext(ctx context.Context) (RequestAuthorization, bool) {
	grant, ok := ctx.Value(requestAuthorizationContextKey{}).(RequestAuthorization)
	return grant, ok
}

// CredentialBinding is private request evidence, never an API response or log.
type CredentialBinding struct {
	Kind       CredentialKind
	ID         string
	Digest     [32]byte
	PATCeiling []string
}
type AuthorizationTarget struct {
	Scope    domain.Scope
	Kind, ID string
	Version  int64
	// SourceID is the exact stored key when a product-owned non-product-ID row
	// (such as the unattributed investigation bucket) has a canonical FGA ID.
	SourceID string
}
type AuthorizationTargets struct {
	Collection bool
	Complete   bool
	Targets    []AuthorizationTarget
}
type AuthorizationTargetResolver interface {
	ResolveAuthorization(context.Context, RequestIdentity, RoutedOperation) (AuthorizationTargets, error)
}
type RequestAuthorization struct {
	OperationID string
	Credential  CredentialBinding
	Identity    RequestIdentity
	Revision    authorization.Revision
	Decisions   []authorization.CheckedDecision
	Targets     []AuthorizationTarget
	Allowed     []AuthorizationTarget
	Collection  bool
	// WorkspaceSelector binds hierarchy queries even when no candidate exists.
	// It is not an authorization target or an environment-wide permission.
	WorkspaceSelector string
	PathParameters    map[string]string
	// EnvironmentView is a separate current Check, never inferred from a
	// collection's allowed resource keys. It controls scope-wide metadata only.
	EnvironmentView bool
	attestation     []byte
	decisionDigest  [32]byte
}
type RequestAuthorizer interface {
	Authorize(context.Context, RequestIdentity, CredentialBinding, RoutedOperation) (RequestAuthorization, error)
}

// authorizationCheckConcurrency bounds the concurrent decision readers of one
// large collection. Smaller collections and single objects are checked in
// order by the request's own goroutine.
const authorizationCheckConcurrency = 8

type authorizationTargetCheck struct {
	decisions []authorization.CheckedDecision
	err       error
}

type OpenFGAAuthorizer struct {
	Reader           authorization.RevisionReader
	Checker          authorization.Checker
	Resolver         AuthorizationTargetResolver
	StoreID, ModelID string
	AttestationKey   *authorization.AttestationKey
}

func (a *OpenFGAAuthorizer) Authorize(ctx context.Context, identity RequestIdentity, credential CredentialBinding, route RoutedOperation) (RequestAuthorization, error) {
	if a == nil || ctx == nil || a.Reader == nil || a.Checker == nil || a.Resolver == nil || !validRequestIdentity(identity, false) || credential.Kind != identity.CredentialKind || credential.ID == "" || credential.Digest == ([32]byte{}) {
		return RequestAuthorization{}, authorization.ErrInvalid
	}
	policy, err := authorization.LookupOperation(route.OperationID)
	if err != nil {
		return RequestAuthorization{}, err
	}
	if policy.Relation == "" {
		return RequestAuthorization{OperationID: route.OperationID, Credential: credential, Identity: identity}, nil
	}
	permissions := currentRequiredPermissions(route.OperationID, policy.Permission)
	for _, permission := range permissions {
		if credential.Kind == CredentialBearerToken && !slices.Contains(credential.PATCeiling, permission) {
			return RequestAuthorization{}, ErrAuthorizationDenied
		}
	}
	if policy.Relation != policy.Permission {
		// The operation's permission is a permission of an API token only
		// (checked above against the token). The principal is checked for the
		// relation the inventory names for it.
		if authorization.TokenPermissionOperations[route.OperationID] != policy.Relation || credential.Kind != CredentialBearerToken {
			return RequestAuthorization{}, ErrAuthorizationDenied
		}
		permissions = []string{policy.Relation}
	}
	targets, err := a.Resolver.ResolveAuthorization(ctx, identity, route)
	if err != nil {
		return RequestAuthorization{}, err
	}
	if !targets.Complete || len(targets.Targets) > 10000 {
		return RequestAuthorization{}, authorization.ErrUnavailable
	}
	if !targets.Collection && len(targets.Targets) == 0 {
		return RequestAuthorization{}, a.missingTarget(ctx, identity, route.OperationID, permissions)
	}
	grant := RequestAuthorization{OperationID: route.OperationID, Credential: credential, Identity: identity, Targets: append([]AuthorizationTarget(nil), targets.Targets...), Collection: targets.Collection}
	grant.PathParameters = make(map[string]string, len(route.PathParameters))
	for name, value := range route.PathParameters {
		grant.PathParameters[name] = value
	}
	if route.OperationID == "listEnvironments" {
		grant.WorkspaceSelector, err = authorizationWorkspaceSelector(ctx, identity)
		if err != nil {
			return RequestAuthorization{}, err
		}
	}
	// Every target is checked for every required permission against one
	// projection revision. A large collection (home, search, audit) is
	// checked by a bounded number of concurrent readers; the decisions are
	// then read in target order, so the grant and its allowed set are exactly
	// those of checking one target after another, and a failure of any
	// target refuses the request.
	checks := make([]authorizationTargetCheck, len(targets.Targets))
	checkTarget := func(n int) {
		target := targets.Targets[n]
		if target.Scope.Validate() != nil || target.Scope.OrganizationID() != identity.Scope.OrganizationID() {
			checks[n].err = authorization.ErrInvalid
			return
		}
		requests := make([]authorization.CheckRequest, 0, len(permissions))
		for _, permission := range permissions {
			requests = append(requests, authorization.CheckRequest{PrincipalKind: "user", PrincipalID: identity.PrincipalID.String(), OrganizationID: target.Scope.OrganizationID().String(), WorkspaceID: target.Scope.WorkspaceID().String(), EnvironmentID: target.Scope.EnvironmentID().String(), ResourceType: target.Kind, ResourceID: target.ID, Permission: permission})
		}
		if len(requests) > 1 {
			// The permissions of one target share one pair of revision reads.
			checks[n].decisions, checks[n].err = authorization.CheckRevisionAll(ctx, a.Reader, a.Checker, requests, a.StoreID, a.ModelID)
			return
		}
		for _, request := range requests {
			checked, err := authorization.CheckRevision(ctx, a.Reader, a.Checker, request, a.StoreID, a.ModelID)
			if err != nil {
				checks[n].err = err
				return
			}
			checks[n].decisions = append(checks[n].decisions, checked)
		}
	}
	concurrent := targets.Collection && len(targets.Targets) > authorizationCheckConcurrency
	if concurrent {
		var next atomic.Int64
		var failed atomic.Bool
		var readers sync.WaitGroup
		for range authorizationCheckConcurrency {
			readers.Add(1)
			go func() {
				defer readers.Done()
				for {
					n := int(next.Add(1)) - 1
					if n >= len(checks) || failed.Load() {
						return
					}
					checkTarget(n)
					if checks[n].err != nil {
						failed.Store(true)
					}
				}
			}()
		}
		readers.Wait()
		// Readers stop at the first failure, so a target may be unchecked
		// only when some target failed: the request is refused before any
		// decision is used.
		for n := range checks {
			if checks[n].err != nil {
				return RequestAuthorization{}, checks[n].err
			}
		}
	}
	for n, target := range targets.Targets {
		if !concurrent {
			checkTarget(n)
			if checks[n].err != nil {
				return RequestAuthorization{}, checks[n].err
			}
		}
		if len(checks[n].decisions) != len(permissions) {
			return RequestAuthorization{}, authorization.ErrUnavailable
		}
		allowed := true
		for _, checked := range checks[n].decisions {
			if grant.Revision.OrganizationID != "" && grant.Revision != checked.Revision {
				return RequestAuthorization{}, authorization.ErrConflict
			}
			grant.Revision = checked.Revision
			grant.Decisions = append(grant.Decisions, checked)
			allowed = allowed && checked.Decision.Allowed
		}
		if allowed {
			grant.Allowed = append(grant.Allowed, target)
		} else if !targets.Collection {
			return RequestAuthorization{}, authorizationTargetDenied(route.OperationID)
		}
	}
	// Even an empty collection needs a current revision proof. It never borrows
	// an environment allow and never interprets no candidates as unrestricted.
	if len(targets.Targets) == 0 {
		revision, err := a.Reader.Revision(ctx, identity.Scope.OrganizationID().String())
		if err != nil {
			return RequestAuthorization{}, authorization.ErrUnavailable
		}
		if revision.OrganizationID != identity.Scope.OrganizationID().String() || revision.Desired != revision.Applied || revision.Desired < 1 || revision.Generation < 1 || revision.StoreID != a.StoreID || revision.ModelID != a.ModelID {
			return RequestAuthorization{}, authorization.ErrPending
		}
		grant.Revision = revision
	}
	if (route.OperationID == "listSessions" || route.OperationID == "getHomeSummary") && (credential.Kind != CredentialBearerToken || slices.Contains(credential.PATCeiling, "view")) {
		metadataTargets, err := a.Resolver.ResolveAuthorization(ctx, identity, RoutedOperation{OperationID: "getEnvironment", PathParameters: map[string]string{"id": identity.Scope.EnvironmentID().String()}})
		if err != nil {
			return RequestAuthorization{}, err
		}
		if !metadataTargets.Complete || metadataTargets.Collection || len(metadataTargets.Targets) != 1 {
			return RequestAuthorization{}, authorization.ErrUnavailable
		}
		environment := metadataTargets.Targets[0]
		if environment.Kind != "environment" || environment.Scope != identity.Scope || environment.ID != identity.Scope.EnvironmentID().String() {
			return RequestAuthorization{}, authorization.ErrInvalid
		}
		checked, err := authorization.CheckRevision(ctx, a.Reader, a.Checker, authorization.CheckRequest{PrincipalKind: "user", PrincipalID: identity.PrincipalID.String(), OrganizationID: identity.Scope.OrganizationID().String(), WorkspaceID: identity.Scope.WorkspaceID().String(), EnvironmentID: identity.Scope.EnvironmentID().String(), ResourceType: "environment", ResourceID: environment.ID, Permission: "view"}, a.StoreID, a.ModelID)
		if err != nil {
			return RequestAuthorization{}, err
		}
		if checked.Revision != grant.Revision {
			return RequestAuthorization{}, authorization.ErrConflict
		}
		grant.Decisions = append(grant.Decisions, checked)
		grant.EnvironmentView = checked.Decision.Allowed
		if grant.EnvironmentView {
			grant.Targets = append(grant.Targets, environment)
		}
	}
	current, err := a.Reader.Revision(ctx, identity.Scope.OrganizationID().String())
	if err != nil {
		return RequestAuthorization{}, authorization.ErrUnavailable
	}
	if current != grant.Revision {
		return RequestAuthorization{}, authorization.ErrConflict
	}
	return attestAuthorization(grant, a.AttestationKey, time.Now().UTC())
}

// Session detail and event readers have an established hidden-or-missing 404
// contract. Credential ceilings and collection admission remain separate 403s.
func authorizationTargetDenied(operation string) error {
	switch operation {
	case "getSession", "listSessionEvents", "getSessionEvent":
		return ErrRepositoryNotFound
	default:
		return ErrAuthorizationDenied
	}
}

// missingObjectOperations are the reads of one object by its ID that answer
// 404 when the object is not in the caller's Environment and the caller holds
// the operation's permission on that Environment.
var missingObjectOperations = map[string]bool{"getPolicy": true, "getIntegration": true, "getSecurityAgent": true, "getFinding": true}

// missingTarget decides the answer when the object of a request resolves to
// nothing in the caller's own scope: it does not exist, it was deleted, or it
// belongs to another Environment, Workspace or Organization. The resolver
// reads only the caller's scope, so these cases are indistinguishable here
// and get one answer; nothing about another tenant can be inferred from it.
//
// The answer was always 403, which a client cannot tell from a missing
// permission. A caller that holds the operation's permission on the
// Environment itself (checked against the current projection revision) is
// allowed to read every such object there, so telling it "not found" reveals
// nothing it could not list. Every other caller keeps the 403. A check that
// cannot be decided (the projection is behind, as it is for a moment after
// the object was deleted, or the checker is unavailable) is reported as
// such, the way it is for an object that exists: the router answers that
// with a retryable error, and the repeated request gets the decided answer.
func (a *OpenFGAAuthorizer) missingTarget(ctx context.Context, identity RequestIdentity, operation string, permissions []string) error {
	denied := authorizationTargetDenied(operation)
	if !missingObjectOperations[operation] || len(permissions) == 0 {
		return denied
	}
	scope := identity.Scope
	for _, permission := range permissions {
		checked, err := authorization.CheckRevision(ctx, a.Reader, a.Checker, authorization.CheckRequest{PrincipalKind: "user", PrincipalID: identity.PrincipalID.String(), OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), ResourceType: "environment", ResourceID: scope.EnvironmentID().String(), Permission: permission}, a.StoreID, a.ModelID)
		if err != nil {
			return err
		}
		if !checked.Decision.Allowed {
			return denied
		}
	}
	return ErrRepositoryNotFound
}

// The operation inventory names the primary permission. Compliance's existing
// source/export contract additionally requires view and view_audit independently.
func currentRequiredPermissions(operation, primary string) []string {
	switch operation {
	case "listComplianceControls", "listComplianceEvidence", "getComplianceEvidence", "createComplianceExport", "getComplianceExport", "createComplianceDownloadGrant", "downloadComplianceExport":
		return []string{"view", "view_audit", "view_compliance"}
	default:
		return []string{primary}
	}
}

// This permits a checked handler to issue its restricted read, not a blanket
// capability claim. Empty collections remain empty in SQL. Fixture-only callers
// without a private proof retain their existing legacy contract.
func currentRequestHasPermission(ctx context.Context, identity RequestIdentity, permission string) bool {
	grant, ok := requestAuthorizationFromContext(ctx)
	if !ok {
		return slices.Contains(identity.Permissions, permission)
	}
	policy, err := authorization.LookupOperation(grant.OperationID)
	return err == nil && grant.Identity.PrincipalID == identity.PrincipalID && grant.Identity.Scope == identity.Scope && grant.Credential.Kind == identity.CredentialKind && slices.Contains(currentRequiredPermissions(grant.OperationID, policy.Permission), permission)
}
