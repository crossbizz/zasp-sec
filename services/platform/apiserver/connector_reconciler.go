package apiserver

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type ConnectorReconciliationRepository interface {
	ClaimReconciliation(context.Context, string, int, int) ([]ConnectorEffectLease, error)
	CompleteOAuthReconciliation(context.Context, ConnectorEffectLease, OAuthCompletion) (OAuthCompletionRecord, error)
	CompleteConnectorCleanupReconciliation(context.Context, ConnectorEffectLease) (ConnectorEffectTransition, error)
	CompletePKCECleanupReconciliation(context.Context, ConnectorEffectLease) (ConnectorEffectTransition, error)
	QuarantineConnectorReconciliation(context.Context, ConnectorEffectLease, string) (ConnectorEffectTransition, error)
	FailConnectorReconciliation(context.Context, ConnectorEffectLease, string) (ConnectorEffectTransition, error)
	CompleteConnectorRevocation(context.Context, ConnectorEffectLease) (ConnectorEffectTransition, error)
}

type ConnectorReconcilerConfig struct {
	Repository   ConnectorReconciliationRepository
	Workflows    connectorWorkflowReader
	Registry     *ConnectorProviderRegistry
	Secrets      ConnectorOAuthSecretStore
	Owner        string
	LeaseSeconds int
	Limit        int
	Interval     time.Duration
}

type ConnectorReconciler struct {
	repository   ConnectorReconciliationRepository
	workflows    connectorWorkflowReader
	registry     *ConnectorProviderRegistry
	secrets      ConnectorOAuthSecretStore
	owner        string
	leaseSeconds int
	limit        int
	interval     time.Duration
	ready        atomic.Bool
}

func NewConnectorReconciler(config ConnectorReconcilerConfig) (*ConnectorReconciler, error) {
	if nilInterface(config.Repository) || nilInterface(config.Workflows) || nilInterface(config.Secrets) || config.Registry == nil || len(config.Owner) < 3 || len(config.Owner) > 128 || config.LeaseSeconds < 5 || config.LeaseSeconds > 300 || config.Limit < 1 || config.Limit > 100 || config.Interval < 10*time.Millisecond || config.Interval > time.Minute {
		return nil, ErrRepositoryConfiguration
	}
	return &ConnectorReconciler{repository: config.Repository, workflows: config.Workflows, registry: config.Registry, secrets: config.Secrets, owner: config.Owner, leaseSeconds: config.LeaseSeconds, limit: config.Limit, interval: config.Interval}, nil
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
		claimHealthy, err := reconciler.reconcileBatch(ctx)
		if err != nil && !claimHealthy {
			reconciler.ready.Store(claimHealthy)
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
	_, err := reconciler.reconcileBatch(ctx)
	return err
}

func (reconciler *ConnectorReconciler) reconcileBatch(ctx context.Context) (bool, error) {
	if reconciler == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryOperation
	}
	leases, err := reconciler.repository.ClaimReconciliation(ctx, reconciler.owner, reconciler.leaseSeconds, reconciler.limit)
	if err != nil {
		return false, err
	}
	if len(leases) == 0 {
		return true, nil
	}
	return true, runConnectorReconciliationBatch(ctx, leases, reconciler.reconcileLease)
}

func runConnectorReconciliationBatch(ctx context.Context, leases []ConnectorEffectLease, reconcile func(context.Context, ConnectorEffectLease) error) error {
	results := make(chan error, len(leases))
	var workers sync.WaitGroup
	workers.Add(len(leases))
	for _, lease := range leases {
		go func(item ConnectorEffectLease) {
			defer workers.Done()
			results <- reconcile(ctx, item)
		}(lease)
	}
	workers.Wait()
	close(results)
	var result error
	for err := range results {
		result = errors.Join(result, err)
	}
	return result
}

func (reconciler *ConnectorReconciler) reconcileLease(ctx context.Context, lease ConnectorEffectLease) error {
	now := time.Now()
	finalizationDeadline := lease.LeaseExpiresAt.Add(-100 * time.Millisecond)
	if !finalizationDeadline.After(now) {
		return reconciler.quarantineExpiredFinalAttempt(ctx, lease)
	}
	providerReserve := 2 * time.Second
	if available := finalizationDeadline.Sub(now); providerReserve >= available {
		providerReserve = available / 3
	}
	providerDeadline := finalizationDeadline.Add(-providerReserve)
	if !providerDeadline.After(now) {
		return reconciler.quarantineExpiredFinalAttempt(ctx, lease)
	}
	providerContext, cancel := context.WithDeadline(ctx, providerDeadline)
	defer cancel()
	finalizationContext, finalize := context.WithDeadline(ctx, finalizationDeadline)
	defer finalize()
	if lease.Operation == "pkce_cleanup" {
		if err := reconciler.secrets.Delete(providerContext, lease.ConnectionReference); err != nil {
			if lease.Attempt >= 100 {
				_, quarantineErr := reconciler.repository.QuarantineConnectorReconciliation(finalizationContext, lease, "pkce_cleanup_ambiguous")
				return quarantineErr
			}
			return err
		}
		_, err := reconciler.repository.CompletePKCECleanupReconciliation(finalizationContext, lease)
		return reconciler.quarantineFinalAttempt(finalizationContext, lease, "pkce_cleanup_ambiguous", err)
	}
	if lease.Operation == "revoke" {
		return reconciler.reconcileRevocation(providerContext, finalizationContext, lease)
	}
	if lease.Operation != "authorize" {
		return reconciler.failAfterCleanup(providerContext, finalizationContext, lease, nil, "unsupported_reconciliation")
	}
	scope, err := connectorLeaseScope(lease)
	if err != nil {
		return err
	}
	workflow, err := reconciler.workflows.GetWorkflow(providerContext, scope, "integration", lease.IntegrationID)
	providerKey, configuration, valid := authorizedOAuthIntegration(workflow, lease.IntegrationID)
	definition, ready := reconciler.registry.Provider(providerContext, providerKey)
	if lease.LastErrorCode == "cleanup_pending" {
		provider, providerErr := connectorOAuthProvider(definition, configuration)
		if err != nil || !valid || !ready || providerKey != lease.Provider || providerErr != nil {
			return reconciler.quarantineFinalAttempt(finalizationContext, lease, "provider_cleanup_ambiguous", ErrRepositoryUnavailable)
		}
		if err := provider.Discard(providerContext, lease.ID, false); err != nil {
			if lease.Attempt >= 100 {
				_, quarantineErr := reconciler.repository.QuarantineConnectorReconciliation(finalizationContext, lease, "provider_cleanup_ambiguous")
				return quarantineErr
			}
			return err
		}
		_, err = reconciler.repository.CompleteConnectorCleanupReconciliation(finalizationContext, lease)
		return reconciler.quarantineFinalAttempt(finalizationContext, lease, "provider_cleanup_ambiguous", err)
	}
	if err != nil || !valid || !ready || providerKey != lease.Provider || !equalStringSet(definition.RequestedScopes, lease.RequestedScopes) {
		return reconciler.failAfterCleanup(providerContext, finalizationContext, lease, nil, "authorization_intent_changed")
	}
	expected := connectorAuthorizationIntentDigestValues(scope, lease.PrincipalID, workflow, lease.IntegrationID, lease.OAuthAttemptID, lease.Provider, configuration, definition.RequestedScopes)
	actual, decodeErr := hex.DecodeString(lease.RequestDigest)
	provider, providerErr := connectorOAuthProvider(definition, configuration)
	if decodeErr != nil || subtle.ConstantTimeCompare(actual, expected[:]) != 1 || providerErr != nil {
		return reconciler.failAfterCleanup(providerContext, finalizationContext, lease, provider, "authorization_intent_changed")
	}
	grant, recoverErr := provider.Recover(providerContext, lease.ID)
	if errors.Is(recoverErr, ErrConnectorOutcomeNotFound) {
		if lease.Attempt < 100 {
			return recoverErr
		}
		_, err := reconciler.repository.QuarantineConnectorReconciliation(finalizationContext, lease, "provider_outcome_ambiguous")
		return err
	}
	if recoverErr != nil || !validConnectorOAuthGrant(grant, definition.CredentialClass) {
		if lease.Attempt >= 100 {
			return reconciler.failAfterCleanup(providerContext, finalizationContext, lease, provider, "reconciliation_exhausted")
		}
		if recoverErr != nil {
			return recoverErr
		}
		return ErrRepositoryUnavailable
	}
	completion := OAuthCompletion{AttemptID: lease.OAuthAttemptID, EffectID: lease.ID, ConnectionID: connectorDeterministicID(scope, lease.OAuthAttemptID, "connection"), ConnectionReference: grant.ConnectionReference, ProviderSubject: grant.ProviderSubject, CredentialID: connectorDeterministicID(scope, lease.OAuthAttemptID, "credential"), CredentialClass: grant.CredentialClass, Metadata: grant.Metadata}
	if _, err := reconciler.repository.CompleteOAuthReconciliation(finalizationContext, lease, completion); err != nil {
		return reconciler.quarantineFinalAttempt(finalizationContext, lease, "provider_outcome_ambiguous", err)
	}
	if err := provider.Discard(providerContext, lease.ID, false); err != nil {
		return reconciler.quarantineFinalAttempt(finalizationContext, lease, "provider_cleanup_ambiguous", err)
	}
	_, err = reconciler.repository.CompleteConnectorCleanupReconciliation(finalizationContext, lease)
	return reconciler.quarantineFinalAttempt(finalizationContext, lease, "provider_cleanup_ambiguous", err)
}

func (reconciler *ConnectorReconciler) quarantineExpiredFinalAttempt(ctx context.Context, lease ConnectorEffectLease) error {
	if lease.Attempt < 100 {
		return ErrRepositoryConflict
	}
	code := "provider_outcome_ambiguous"
	if lease.Operation == "pkce_cleanup" {
		code = "pkce_cleanup_ambiguous"
	} else if lease.Operation == "revoke" {
		code = "provider_revocation_ambiguous"
	} else if lease.LastErrorCode == "cleanup_pending" {
		code = "provider_cleanup_ambiguous"
	}
	finalizationContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := reconciler.repository.QuarantineConnectorReconciliation(finalizationContext, lease, code)
	return err
}

func (reconciler *ConnectorReconciler) reconcileRevocation(providerContext, finalizationContext context.Context, lease ConnectorEffectLease) error {
	scope, err := connectorLeaseScope(lease)
	if err != nil {
		return err
	}
	workflow, err := reconciler.workflows.GetWorkflow(providerContext, scope, "integration", lease.IntegrationID)
	providerKey, configuration, valid := authorizedOAuthIntegrationStatus(workflow, lease.IntegrationID, "revoking")
	definition, ready := reconciler.registry.Provider(providerContext, providerKey)
	provider, providerErr := connectorOAuthProvider(definition, configuration)
	if err != nil || !valid || !ready || providerKey != lease.Provider || providerErr != nil {
		if lease.Attempt >= 100 {
			_, quarantineErr := reconciler.repository.QuarantineConnectorReconciliation(finalizationContext, lease, "provider_revocation_ambiguous")
			return quarantineErr
		}
		return ErrRepositoryUnavailable
	}
	if err := provider.Revoke(providerContext, lease.ConnectionReference); err != nil {
		if lease.Attempt >= 100 {
			_, quarantineErr := reconciler.repository.QuarantineConnectorReconciliation(finalizationContext, lease, "provider_revocation_ambiguous")
			return quarantineErr
		}
		return err
	}
	_, err = reconciler.repository.CompleteConnectorRevocation(finalizationContext, lease)
	return reconciler.quarantineFinalAttempt(finalizationContext, lease, "provider_revocation_ambiguous", err)
}

func (reconciler *ConnectorReconciler) failAfterCleanup(providerContext, finalizationContext context.Context, lease ConnectorEffectLease, provider ConnectorOAuthProvider, reason string) error {
	if provider == nil {
		definition, ready := reconciler.registry.Provider(providerContext, lease.Provider)
		if ready {
			workflow, err := reconciler.workflows.GetWorkflow(providerContext, mustConnectorLeaseScope(lease), "integration", lease.IntegrationID)
			_, configuration, valid := authorizedOAuthIntegration(workflow, lease.IntegrationID)
			if err == nil && valid {
				provider, _ = connectorOAuthProvider(definition, configuration)
			}
		}
	}
	if provider != nil {
		if err := provider.Discard(providerContext, lease.ID, true); err != nil {
			return reconciler.quarantineFinalAttempt(finalizationContext, lease, "provider_cleanup_ambiguous", err)
		}
	}
	_, err := reconciler.repository.FailConnectorReconciliation(finalizationContext, lease, reason)
	return reconciler.quarantineFinalAttempt(finalizationContext, lease, "provider_outcome_ambiguous", err)
}

func (reconciler *ConnectorReconciler) quarantineFinalAttempt(ctx context.Context, lease ConnectorEffectLease, code string, cause error) error {
	if cause == nil || lease.Attempt < 100 {
		return cause
	}
	_, err := reconciler.repository.QuarantineConnectorReconciliation(ctx, lease, code)
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
