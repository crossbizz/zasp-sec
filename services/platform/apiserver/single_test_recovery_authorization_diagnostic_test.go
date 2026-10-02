package apiserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type singleRecoveryAuthorizationObservation struct {
	Stage, ErrorClass                        string
	ResolverCalls, ReaderCalls, CheckerCalls int
	TargetCount                              int
	TargetsComplete, TargetsCollection       bool
	TargetShape                              bool
	RevisionScope, RevisionBalanced          bool
	RevisionAuthority                        bool
	CheckAllowed, CheckModel                 bool
}

func (o singleRecoveryAuthorizationObservation) String() string {
	return fmt.Sprintf("stage=%s class=%s resolver=%d reader=%d checker=%d targets=%d complete=%t collection=%t target_shape=%t revision_scope=%t revision_balanced=%t revision_authority=%t check_allowed=%t check_model=%t", o.Stage, o.ErrorClass, o.ResolverCalls, o.ReaderCalls, o.CheckerCalls, o.TargetCount, o.TargetsComplete, o.TargetsCollection, o.TargetShape, o.RevisionScope, o.RevisionBalanced, o.RevisionAuthority, o.CheckAllowed, o.CheckModel)
}

func singleRecoveryAuthorizationErrorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, authorization.ErrInvalid):
		return "invalid"
	case errors.Is(err, authorization.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, authorization.ErrPending):
		return "pending"
	case errors.Is(err, authorization.ErrConflict):
		return "conflict"
	case errors.Is(err, ErrAuthorizationDenied):
		return "denied"
	case errors.Is(err, ErrRepositoryNotFound):
		return "not-found"
	default:
		return "unclassified"
	}
}

type singleRecoveryDiagnosticResolver struct {
	delegate AuthorizationTargetResolver
	observe  *singleRecoveryAuthorizationObservation
	identity RequestIdentity
	route    RoutedOperation
}

func (d *singleRecoveryDiagnosticResolver) ResolveAuthorization(ctx context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
	if d.observe.ResolverCalls < 9 {
		d.observe.ResolverCalls++
	}
	targets, err := d.delegate.ResolveAuthorization(ctx, identity, route)
	if err != nil {
		d.observe.Stage = "resolver"
		return targets, err
	}
	d.observe.TargetsComplete = targets.Complete
	d.observe.TargetsCollection = targets.Collection
	d.observe.TargetCount = len(targets.Targets)
	if d.observe.TargetCount > 10001 {
		d.observe.TargetCount = 10001
	}
	d.observe.TargetShape = len(targets.Targets) == 1 && !targets.Collection && targets.Targets[0].Scope == d.identity.Scope && targets.Targets[0].Kind == "security_agent_run" && targets.Targets[0].ID == d.route.PathParameters["id"]
	return targets, nil
}

type singleRecoveryDiagnosticReader struct {
	delegate authorization.RevisionReader
	observe  *singleRecoveryAuthorizationObservation
	identity RequestIdentity
	storeID  string
	modelID  string
}

func (d *singleRecoveryDiagnosticReader) Revision(ctx context.Context, organization string) (authorization.Revision, error) {
	if d.observe.ReaderCalls < 9 {
		d.observe.ReaderCalls++
	}
	revision, err := d.delegate.Revision(ctx, organization)
	if err != nil {
		d.observe.Stage = "reader"
		return revision, err
	}
	d.observe.RevisionScope = revision.OrganizationID == d.identity.Scope.OrganizationID().String()
	d.observe.RevisionBalanced = revision.Desired == revision.Applied
	d.observe.RevisionAuthority = revision.StoreID == d.storeID && revision.ModelID == d.modelID
	return revision, nil
}

type singleRecoveryDiagnosticChecker struct {
	delegate authorization.Checker
	observe  *singleRecoveryAuthorizationObservation
	modelID  string
}

func (d *singleRecoveryDiagnosticChecker) Check(ctx context.Context, request authorization.CheckRequest) (authorization.Decision, error) {
	if d.observe.CheckerCalls < 9 {
		d.observe.CheckerCalls++
	}
	decision, err := d.delegate.Check(ctx, request)
	if err != nil {
		d.observe.Stage = "checker"
		return decision, err
	}
	d.observe.CheckAllowed = decision.Allowed
	d.observe.CheckModel = decision.ModelID == d.modelID
	return decision, nil
}

func singleRecoveryAuthorizeDiagnostic(ctx context.Context, authorizer *OpenFGAAuthorizer, identity RequestIdentity, credential CredentialBinding, route RoutedOperation) (RequestAuthorization, singleRecoveryAuthorizationObservation, error) {
	observation := singleRecoveryAuthorizationObservation{Stage: "entry", ErrorClass: "none"}
	if authorizer == nil || authorizer.Reader == nil || authorizer.Resolver == nil || authorizer.Checker == nil {
		grant, err := authorizer.Authorize(ctx, identity, credential, route)
		observation.ErrorClass = singleRecoveryAuthorizationErrorClass(err)
		return grant, observation, err
	}
	instrumented := *authorizer
	instrumented.Resolver = &singleRecoveryDiagnosticResolver{delegate: authorizer.Resolver, observe: &observation, identity: identity, route: route}
	instrumented.Reader = &singleRecoveryDiagnosticReader{delegate: authorizer.Reader, observe: &observation, identity: identity, storeID: authorizer.StoreID, modelID: authorizer.ModelID}
	instrumented.Checker = &singleRecoveryDiagnosticChecker{delegate: authorizer.Checker, observe: &observation, modelID: authorizer.ModelID}
	grant, err := instrumented.Authorize(ctx, identity, credential, route)
	observation.ErrorClass = singleRecoveryAuthorizationErrorClass(err)
	if err == nil {
		observation.Stage = "complete"
	} else if observation.Stage == "entry" {
		switch {
		case observation.ResolverCalls == 0:
			observation.Stage = "entry"
		case observation.ReaderCalls == 0 && observation.CheckerCalls == 0:
			observation.Stage = "targets"
		case observation.CheckerCalls == 0 || observation.ReaderCalls < 3:
			observation.Stage = "revision"
		default:
			observation.Stage = "final"
		}
	}
	return grant, observation, err
}

type singleRecoveryAuthorizationRevisionFunc func(context.Context, string) (authorization.Revision, error)

func (f singleRecoveryAuthorizationRevisionFunc) Revision(ctx context.Context, organization string) (authorization.Revision, error) {
	return f(ctx, organization)
}

func singleRecoveryAuthorizationDiagnosticFixture(t *testing.T) (*OpenFGAAuthorizer, RequestIdentity, CredentialBinding, RoutedOperation, authorization.Revision) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "diagnostic-session", Digest: [32]byte{1}}
	revision := authorization.Revision{OrganizationID: identity.Scope.OrganizationID().String(), Desired: 3, Applied: 3, Generation: 2, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	target := AuthorizationTarget{Scope: identity.Scope, Kind: "security_agent_run", ID: "pid_89000000-0000-4000-8000-000000000001", Version: 1}
	authorizer := &OpenFGAAuthorizer{
		Reader:         authorizationRevisionFixture{revision},
		Resolver:       authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{target}}},
		Checker:        authorizationDecisionFixture{allow: map[string]bool{target.ID: true}, model: revision.ModelID},
		StoreID:        revision.StoreID,
		ModelID:        revision.ModelID,
		AttestationKey: authorizationFixtureAttestor(t),
	}
	return authorizer, identity, credential, RoutedOperation{OperationID: "getSingleTestCleanupRecovery", PathParameters: map[string]string{"id": target.ID}}, revision
}

func TestSingleRecoveryAuthorizationDiagnosticForwardsStages(t *testing.T) {
	authorizer, identity, credential, route, _ := singleRecoveryAuthorizationDiagnosticFixture(t)
	grant, observation, err := singleRecoveryAuthorizeDiagnostic(context.Background(), authorizer, identity, credential, route)
	if err != nil || len(grant.Allowed) != 1 {
		t.Fatal("delegated authorization changed", err)
	}
	if observation.Stage != "complete" || observation.ErrorClass != "none" || observation.ResolverCalls != 1 || observation.ReaderCalls != 3 || observation.CheckerCalls != 1 || observation.TargetCount != 1 || !observation.TargetsComplete || observation.TargetsCollection || !observation.TargetShape || !observation.RevisionScope || !observation.RevisionBalanced || !observation.RevisionAuthority || !observation.CheckAllowed || !observation.CheckModel {
		t.Fatal("successful diagnostic lost a fixed stage or bounded observation", observation)
	}
	if authorizer.AttestationKey == nil {
		t.Fatal("diagnostic dropped the original attestation authority")
	}
}

func TestSingleRecoveryAuthorizationDiagnosticClassifiesAndSanitizes(t *testing.T) {
	for _, test := range []struct {
		name, stage, class string
		mutate             func(*OpenFGAAuthorizer)
	}{
		{"resolver", "resolver", "unclassified", func(a *OpenFGAAuthorizer) {
			a.Resolver = authorizationTargetFunc(func(context.Context, RequestIdentity, RoutedOperation) (AuthorizationTargets, error) {
				return AuthorizationTargets{}, errors.New("secret resolver payload")
			})
		}},
		{"reader", "reader", "unavailable", func(a *OpenFGAAuthorizer) {
			a.Reader = singleRecoveryAuthorizationRevisionFunc(func(context.Context, string) (authorization.Revision, error) {
				return authorization.Revision{}, authorization.ErrUnavailable
			})
		}},
		{"checker", "checker", "conflict", func(a *OpenFGAAuthorizer) {
			a.Checker = authorizationDecisionFunc(func(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
				return authorization.Decision{}, authorization.ErrConflict
			})
		}},
		{"final", "final", "unavailable", func(a *OpenFGAAuthorizer) { a.AttestationKey = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorizer, identity, credential, route, _ := singleRecoveryAuthorizationDiagnosticFixture(t)
			test.mutate(authorizer)
			_, observation, err := singleRecoveryAuthorizeDiagnostic(context.Background(), authorizer, identity, credential, route)
			if err == nil || observation.Stage != test.stage || observation.ErrorClass != test.class {
				t.Fatalf("bounded failure classification=%s error-present=%t", observation, err != nil)
			}
			if text := observation.String(); strings.Contains(text, "secret") || len(text) > 512 {
				t.Fatal("diagnostic disclosed raw error material or exceeded its bound")
			}
		})
	}
}
