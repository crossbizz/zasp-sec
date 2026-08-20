package apiserver

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type ConnectorReconciliationRepository interface {
	ClaimReconciliation(context.Context, string, int, int) ([]ConnectorEffectLease, error)
	CompleteOAuthReconciliation(context.Context, ConnectorEffectLease, OAuthCompletion) (OAuthCompletionRecord, error)
	FailConnectorReconciliation(context.Context, ConnectorEffectLease, string) (ConnectorEffectTransition, error)
	CompleteConnectorRevocation(context.Context, ConnectorEffectLease) (ConnectorEffectTransition, error)
}

type ConnectorReconcilerConfig struct {
	Repository   ConnectorReconciliationRepository
	Workflows    connectorWorkflowReader
	Registry     *ConnectorProviderRegistry
	Owner        string
	LeaseSeconds int
	Limit        int
	Interval     time.Duration
}

type ConnectorReconciler struct {
	repository   ConnectorReconciliationRepository
	workflows    connectorWorkflowReader
	registry     *ConnectorProviderRegistry
	owner        string
	leaseSeconds int
	limit        int
	interval     time.Duration
	ready        atomic.Bool
}

func NewConnectorReconciler(config ConnectorReconcilerConfig) (*ConnectorReconciler, error) {
	if nilInterface(config.Repository) || nilInterface(config.Workflows) || config.Registry == nil || len(config.Owner) < 3 || len(config.Owner) > 128 || config.LeaseSeconds < 5 || config.LeaseSeconds > 300 || config.Limit < 1 || config.Limit > 100 || config.Interval < 10*time.Millisecond || config.Interval > time.Minute {
		return nil, ErrRepositoryConfiguration
	}
	return &ConnectorReconciler{repository: config.Repository, workflows: config.Workflows, registry: config.Registry, owner: config.Owner, leaseSeconds: config.LeaseSeconds, limit: config.Limit, interval: config.Interval}, nil
}

func (reconciler *ConnectorReconciler) Ready() bool {
	return reconciler != nil && reconciler.ready.Load()
}

func (reconciler *ConnectorReconciler) Run(ctx context.Context) error {
	if reconciler == nil || ctx == nil {
		return ErrRepositoryConfiguration
	}
	delay := reconciler.interval
	for {
		if err := reconciler.reconcileOnce(ctx); err != nil {
			reconciler.ready.Store(false)
			if delay < 30*time.Second {
				delay *= 2
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
			}
		} else {
			reconciler.ready.Store(true)
			delay = reconciler.interval
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (reconciler *ConnectorReconciler) reconcileOnce(ctx context.Context) error {
	if reconciler == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryOperation
	}
	leases, err := reconciler.repository.ClaimReconciliation(ctx, reconciler.owner, reconciler.leaseSeconds, reconciler.limit)
	if err != nil {
		return err
	}
	for _, lease := range leases {
		if err := reconciler.reconcileLease(ctx, lease); err != nil {
			return err
		}
	}
	return nil
}

func (reconciler *ConnectorReconciler) reconcileLease(ctx context.Context, lease ConnectorEffectLease) error {
	if lease.Operation == "revoke" {
		return reconciler.reconcileRevocation(ctx, lease)
	}
	if lease.Operation != "authorize" {
		return reconciler.failAfterCleanup(ctx, lease, nil, "unsupported_reconciliation")
	}
	scope, err := connectorLeaseScope(lease)
	if err != nil {
		return err
	}
	workflow, err := reconciler.workflows.GetWorkflow(ctx, scope, "integration", lease.IntegrationID)
	providerKey, configuration, valid := authorizedOAuthIntegration(workflow, lease.IntegrationID)
	definition, ready := reconciler.registry.Provider(ctx, providerKey)
	if err != nil || !valid || !ready || providerKey != lease.Provider || !equalStringSet(definition.RequestedScopes, lease.RequestedScopes) {
		return reconciler.failAfterCleanup(ctx, lease, nil, "authorization_intent_changed")
	}
	expected := connectorAuthorizationIntentDigestValues(scope, lease.PrincipalID, workflow, lease.IntegrationID, lease.OAuthAttemptID, lease.Provider, configuration, definition.RequestedScopes)
	actual, decodeErr := hex.DecodeString(lease.RequestDigest)
	provider, providerErr := connectorOAuthProvider(definition, configuration)
	if decodeErr != nil || subtle.ConstantTimeCompare(actual, expected[:]) != 1 || providerErr != nil {
		return reconciler.failAfterCleanup(ctx, lease, provider, "authorization_intent_changed")
	}
	grant, recoverErr := provider.Recover(ctx, lease.ID)
	if errors.Is(recoverErr, ErrConnectorOutcomeNotFound) {
		return reconciler.failAfterCleanup(ctx, lease, provider, "provider_outcome_unrecoverable")
	}
	if recoverErr != nil || !validConnectorOAuthGrant(grant, definition.CredentialClass) {
		if lease.Attempt >= 100 {
			return reconciler.failAfterCleanup(ctx, lease, provider, "reconciliation_exhausted")
		}
		return recoverErr
	}
	completion := OAuthCompletion{AttemptID: lease.OAuthAttemptID, EffectID: lease.ID, ConnectionID: connectorDeterministicID(scope, lease.OAuthAttemptID, "connection"), ConnectionReference: grant.ConnectionReference, ProviderSubject: grant.ProviderSubject, CredentialID: connectorDeterministicID(scope, lease.OAuthAttemptID, "credential"), CredentialClass: grant.CredentialClass, Metadata: grant.Metadata}
	if _, err := reconciler.repository.CompleteOAuthReconciliation(ctx, lease, completion); err != nil {
		return err
	}
	if err := provider.Discard(ctx, lease.ID, false); err != nil {
		return err
	}
	return nil
}

func (reconciler *ConnectorReconciler) reconcileRevocation(ctx context.Context, lease ConnectorEffectLease) error {
	scope, err := connectorLeaseScope(lease)
	if err != nil {
		return err
	}
	workflow, err := reconciler.workflows.GetWorkflow(ctx, scope, "integration", lease.IntegrationID)
	providerKey, configuration, valid := authorizedOAuthIntegrationStatus(workflow, lease.IntegrationID, "revoking")
	definition, ready := reconciler.registry.Provider(ctx, providerKey)
	provider, providerErr := connectorOAuthProvider(definition, configuration)
	if err != nil || !valid || !ready || providerKey != lease.Provider || providerErr != nil {
		if lease.Attempt >= 100 {
			_, failErr := reconciler.repository.FailConnectorReconciliation(ctx, lease, "revocation_intent_unavailable")
			return failErr
		}
		return ErrRepositoryUnavailable
	}
	if err := provider.Revoke(ctx, lease.ConnectionReference); err != nil {
		if lease.Attempt >= 100 {
			_, failErr := reconciler.repository.FailConnectorReconciliation(ctx, lease, "revocation_exhausted")
			return failErr
		}
		return err
	}
	_, err = reconciler.repository.CompleteConnectorRevocation(ctx, lease)
	return err
}

func (reconciler *ConnectorReconciler) failAfterCleanup(ctx context.Context, lease ConnectorEffectLease, provider ConnectorOAuthProvider, reason string) error {
	if provider == nil {
		definition, ready := reconciler.registry.Provider(ctx, lease.Provider)
		if ready {
			workflow, err := reconciler.workflows.GetWorkflow(ctx, mustConnectorLeaseScope(lease), "integration", lease.IntegrationID)
			_, configuration, valid := authorizedOAuthIntegration(workflow, lease.IntegrationID)
			if err == nil && valid {
				provider, _ = connectorOAuthProvider(definition, configuration)
			}
		}
	}
	if provider != nil {
		if err := provider.Discard(ctx, lease.ID, true); err != nil {
			return err
		}
	}
	_, err := reconciler.repository.FailConnectorReconciliation(ctx, lease, reason)
	return err
}

func connectorLeaseScope(lease ConnectorEffectLease) (domain.Scope, error) {
	organizationID, organizationErr := domain.ParseProductID(lease.OrganizationID)
	workspaceID, workspaceErr := domain.ParseProductID(lease.WorkspaceID)
	environmentID, environmentErr := domain.ParseProductID(lease.EnvironmentID)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil {
		return domain.Scope{}, ErrRepositoryUnavailable
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		return domain.Scope{}, ErrRepositoryUnavailable
	}
	return scope, nil
}

func mustConnectorLeaseScope(lease ConnectorEffectLease) domain.Scope {
	scope, _ := connectorLeaseScope(lease)
	return scope
}
