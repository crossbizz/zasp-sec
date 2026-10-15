package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenancecutover"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Application acceptance uses genuine signed admission, an owned official FGA
// server and controlled one-writer cutover. Secret deletion is a component stub;
// this does not establish provider, fleet restart or deployed acceptance.
func TestConnectorMaintenancePKCERestartRecoveryPostgres(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned native PostgreSQL/OpenFGA runtime")
	}
	owned := newConnectorLifecycleFGA(t)
	f := newIntegrationClientFixture(t, true)
	runner, err := migrations.NewRunner(&integrationMigrationDatabase{connection: f.owner})
	if err != nil {
		t.Fatal("native migration runner refused")
	}
	for _, install := range []func() error{func() error { return runner.UpProductionAuthorizationWorkerAuditProfile(f.ctx) }, func() error { return runner.UpProductionApprovalMaintenanceProfile(f.ctx) }, func() error { return runner.UpProductionConnectorMaintenance(f.ctx) }} {
		if install() != nil {
			t.Fatal("native lifecycle profile composition refused")
		}
	}
	var forward, captured [32]byte
	if _, err := rand.Read(forward[:]); err != nil {
		t.Fatal("native forward key unavailable")
	}
	if _, err := rand.Read(captured[:]); err != nil {
		t.Fatal("native captured key unavailable")
	}
	defer clear(forward[:])
	defer clear(captured[:])
	fv, cv := sha256.Sum256(forward[:]), sha256.Sum256(captured[:])
	tx, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal("operator registration transaction refused")
	}
	if _, err = tx.Exec(f.ctx, `SET LOCAL ROLE zasp_discovery_authority`); err == nil {
		_, err = tx.Exec(f.ctx, `SELECT zasp_connector_maintenance.register_principal('auth80_outbox',$1,$2,$3,$4)`, hex.EncodeToString(fv[:]), hex.EncodeToString(cv[:]), forward[:], captured[:])
	}
	if err != nil {
		connectorProvenanceRollback(tx)
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal("registered native worker purpose refused")
	}
	if tx.Commit(f.ctx) != nil {
		t.Fatal("native worker registration commit refused")
	}
	pin, err := migrations.ConnectorMaintenanceProfileChecksum()
	if err != nil {
		t.Fatal("native source checksum unavailable")
	}
	approvalPin := migrations.ApprovalMaintenanceProfileChecksum()
	o, w, e := f.browser.Scope.OrganizationID().String(), f.browser.Scope.WorkspaceID().String(), f.browser.Scope.EnvironmentID().String()
	var store, model string
	if f.owner.QueryRow(f.ctx, `SELECT store_id,model_id FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&store, &model) != nil {
		t.Fatal("original organization pins unavailable")
	}
	config, err := pgxpool.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal("native pool config unavailable")
	}
	config.ConnConfig.User = "auth80_outbox"
	config.MaxConns = 3
	workerPool, err := pgxpool.NewWithConfig(f.ctx, config)
	if err != nil {
		t.Fatal("native worker pool refused")
	}
	t.Cleanup(workerPool.Close)
	operatorPool, err := pgxpool.New(f.ctx, f.dsn)
	if err != nil {
		t.Fatal("operator pool refused")
	}
	t.Cleanup(operatorPool.Close)
	client, pins := connectorLifecycleOfficialClient(t, owned, store, model)
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal("official tuple writer refused")
	}
	checker, err := authorization.NewOpenFGA(client, pins)
	if err != nil {
		t.Fatal("official worker checker refused")
	}

	catalogBefore := connectorCatalogCapture(f)
	f.freshReferenceSession(t)
	grant, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": integrationClientExisting}})
	if err != nil {
		t.Fatal("genuine cleanup admission refused")
	}
	raw, err := authorizationProofJSON(grant)
	if err != nil {
		t.Fatal("genuine cleanup proof unavailable")
	}
	var version int64
	var configuration json.RawMessage
	if f.owner.QueryRow(f.ctx, `SELECT version,body->'configuration' FROM public.zasp_workflow_records WHERE(organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4) AND deleted_at IS NULL`, o, w, e, integrationClientExisting).Scan(&version, &configuration) != nil {
		t.Fatal("original integration intent unavailable")
	}
	attempt := "pid_78219301-0000-4000-8000-000000000001"
	cleanup := connectorDeterministicID(f.browser.Scope, attempt, "pkce-cleanup")
	authorize := connectorDeterministicID(f.browser.Scope, attempt, "oauth-effect")
	request := sha256.Sum256([]byte("native PKCE restart original request"))
	state := sha256.Sum256([]byte("native PKCE restart original state"))
	var response []byte
	if err := f.api.QueryRow(f.ctx, `SELECT zasp_connector_maintenance.start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17,$18)`, string(raw), o, w, e, attempt, integrationClientExisting, "github", f.browser.PrincipalID.String(), f.browser.credentialBinding.Digest[:], state[:], "ref:oauth/pkce/native-restart", request[:], `["read:org"]`, time.Now().UTC().Add(5*time.Minute), version, configuration, cleanup, authorize).Scan(&response); err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		connectorCatalogReport(t, f, catalogBefore)
		t.Fatal("original signed enqueue refused")
	}
	if err := f.api.QueryRow(f.ctx, `SELECT zasp_connector_maintenance.handoff_pkce($1,$2,$3,$4,$5)`, string(raw), o, w, e, cleanup).Scan(&response); err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal("original cleanup handoff refused")
	}
	cutover, closeCutover, err := connectormaintenancecutover.NewControlled(connectormaintenancecutover.Config{Endpoint: owned.endpoint, StoreID: store, ModelID: model, OldTokenFile: owned.oldFile, NewTokenFile: owned.newFile, ProfileChecksum: pin, ApprovalProfileChecksum: approvalPin, OperatorPool: operatorPool})
	if err != nil {
		t.Fatal("controlled cutover refused")
	}
	defer closeCutover()
	pid, stopWriter := startConnectorLifecycleWriter(t, f.dsn, owned.endpoint, owned.oldFile, o, store, model)
	permit, err := cutover.Prepare(f.ctx, o, pid)
	if err != nil {
		t.Log("connector cutover prepare stage=" + connectormaintenancecutover.PrepareRefusalStage(err))
		t.Fatal("authentic writer preparation refused")
	}
	stopWriter()
	owned.withdrawOld(t)
	if err := cutover.Activate(f.ctx, permit); err != nil {
		t.Log("connector cutover activation stage=" + connectormaintenancecutover.ActivationRefusalStage(err))
		t.Fatal("controlled activation refused")
	}
	projection, err := authorization.NewCurrentMaintenanceProjectionRepository(f.ctx, workerPool, approvalPin, pin)
	if err != nil {
		t.Fatal("composed projection refused")
	}
	receipt, err := authorization.Reconcile(f.ctx, projection, writer, o, store, model)
	if err != nil || !receipt.Applied {
		t.Fatal("initial composed projection refused")
	}
	executor, err := connectormaintenance.NewExecutor(f.ctx, workerPool, pin, forward[:])
	if err != nil {
		t.Fatal("native executor refused")
	}
	authority, err := connectormaintenance.NewAuthority(executor, checker, store, model, pin, forward[:])
	if err != nil {
		t.Fatal("native authority refused")
	}
	defer authority.Close()
	newRepository := func(t *testing.T) *NativeConnectorRepository {
		t.Helper()
		repo, err := NewNativeConnectorRepository(f.ctx, executor, authority)
		if err != nil {
			t.Fatal("reconstructed native repository refused")
		}
		return repo
	}
	claim := func(t *testing.T, repo *NativeConnectorRepository, owner string) ConnectorEffectLease {
		t.Helper()
		// Preserve the original 15 s cooldown. A 10 s lease stays within
		// the existing 5..300 s range and covers the direct native denials.
		deadline := time.Now().Add(22 * time.Second)
		for time.Now().Before(deadline) {
			items, err := repo.ClaimReconciliation(f.ctx, owner, 10, 10)
			if err != nil {
				t.Fatal("owned reconciliation claim refused")
			}
			for _, item := range items {
				if item.ID == cleanup {
					return item
				}
			}
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-f.ctx.Done():
				timer.Stop()
				t.Fatal("owned claim context expired")
			case <-timer.C:
			}
		}
		t.Fatal("original cooldown elapsed without exact cleanup claim")
		return ConnectorEffectLease{}
	}
	original := newRepository(t)
	var lease ConnectorEffectLease
	var originalReceipt string
	t.Run("live preparation failure retries before captured provider admission and excludes live lease adoption", func(t *testing.T) {
		lease = claim(t, original, "native-pkce-original-worker")
		if lease.Attempt != 0 {
			t.Fatal("reservation consumed an attempt")
		}
		providerDeadline := lease.LeaseExpiresAt.Add(-2100 * time.Millisecond)
		if err := original.finishPreparation(f.ctx, lease, ErrRepositoryUnavailable, providerDeadline); err != nil {
			t.Log("connector preparation stage=" + connectorPreparationFailureStage(err))
			t.Fatal("genuine live preparation failure could not record finite attempt")
		}
		failed, ok := original.reservation(nativeConnectorKey(lease))
		if !ok || failed.lease.Attempt != 1 || len(failed.captured) == 0 {
			t.Fatal("preparation failure did not capture exactly one attempt")
		}
		var failedKind string
		if f.owner.QueryRow(f.ctx, `SELECT convert_from(decode(captured_receipt->>'body','base64'),'UTF8')::jsonb->>'kind' FROM zasp_connector_maintenance.reservations WHERE effect_id=$1`, cleanup).Scan(&failedKind) != nil || failedKind != "secret_failure" {
			t.Fatal("genuine preparation failure receipt missing")
		}
		original = newRepository(t)
		lease = claim(t, original, "native-pkce-preparation-retry")
		retry, ok := original.reservation(nativeConnectorKey(lease))
		if !ok || lease.Attempt != 1 || len(retry.captured) != 0 {
			t.Fatal("preparation retry gained captured compensation or lost attempt budget")
		}
		if original.prepare(f.ctx, &lease, true) != nil || lease.Attempt != 2 {
			t.Fatal("fresh live authority did not begin next bounded attempt")
		}
		if f.owner.QueryRow(f.ctx, `SELECT captured_receipt::text FROM zasp_connector_maintenance.reservations WHERE effect_id=$1`, cleanup).Scan(&originalReceipt) != nil || originalReceipt == "" {
			t.Fatal("original captured lineage missing")
		}
		other := newRepository(t)
		if other.compensation(f.ctx, lease) == nil || other.prepare(f.ctx, &lease, true) == nil {
			t.Fatal("new repository adopted another live lease")
		}
		items, err := other.ClaimReconciliation(f.ctx, "native-pkce-live-contender", 5, 10)
		if err != nil {
			t.Fatal("live contender claim failed")
		}
		for _, item := range items {
			if item.ID == cleanup {
				t.Fatal("live captured lease was stolen")
			}
		}
	})
	if t.Failed() {
		return
	}
	f.exec(`UPDATE public.zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, f.browser.PrincipalID.String(), o)
	receipt, err = authorization.Reconcile(f.ctx, projection, writer, o, store, model)
	if err != nil || !receipt.Applied {
		t.Fatal("grantor revocation projection refused")
	}
	var firstRecovered ConnectorEffectLease
	t.Run("restart after revocation permits only exact captured deletion without settlement on failure", func(t *testing.T) {
		restarted := newRepository(t)
		firstRecovered = claim(t, restarted, "native-pkce-restarted-worker")
		if firstRecovered.Attempt != 2 || firstRecovered.LeaseToken == lease.LeaseToken || firstRecovered.ConnectionReference != lease.ConnectionReference {
			t.Fatal("recovery changed attempt, reference or retained expired lease")
		}
		if restarted.prepare(f.ctx, &firstRecovered, true) == nil {
			t.Fatal("captured recovery reopened forward authority")
		}
		altered := firstRecovered
		altered.EnvironmentID = "pid_78219309-0000-4000-8000-000000000009"
		if restarted.compensation(f.ctx, altered) == nil {
			t.Fatal("captured recovery crossed tenant scope")
		}
		altered = firstRecovered
		altered.ConnectionReference = "ref:oauth/pkce/unowned-restart"
		if restarted.compensation(f.ctx, altered) == nil {
			t.Fatal("captured recovery changed secret reference")
		}
		if restarted.compensation(f.ctx, firstRecovered) != nil {
			t.Fatal("exact captured recovery refused after revocation")
		}
		secrets := &connectorSecretStub{deleteErr: ErrRepositoryUnavailable}
		worker, boundaries := connectorPKCERecoveryWorker(t, f.ctx, restarted, secrets)
		if worker.reconcileLease(f.ctx, firstRecovered) == nil {
			t.Fatal("failed secret deletion reported successful cleanup")
		}
		if secrets.taken || len(secrets.deleted) != 1 || secrets.deleted[0] != lease.ConnectionReference || boundaries.providerCalls.Load() != 0 || boundaries.workflowCalls.Load() != 0 {
			t.Fatal("failed recovery accessed another secret or consumed verifier")
		}
		var valid bool
		if f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE id=$1 AND status='unknown' AND attempt=2) AND NOT EXISTS(SELECT 1 FROM public.zasp_connector_audit WHERE effect_id=$1 AND event_kind='pkce_cleanup_completed') AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.reservations WHERE effect_id=$1 AND origin_receipt::text=$2 AND state='attempted')`, cleanup, originalReceipt).Scan(&valid) != nil || !valid {
			t.Fatal("failed deletion settled cleanup or lost original lineage")
		}
	})
	if t.Failed() {
		return
	}
	// Restoring the genuine membership must not turn a recovery receipt into a
	// new forward grant. The first restart above ran with revocation applied.
	f.exec(`UPDATE public.zasp_identity_memberships SET active=true WHERE principal_id=$1 AND organization_id=$2`, f.browser.PrincipalID.String(), o)
	receipt, err = authorization.Reconcile(f.ctx, projection, writer, o, store, model)
	if err != nil || !receipt.Applied {
		t.Fatal("restored grantor projection refused")
	}
	t.Run("second restart preserves original lineage and settles exact cleanup once", func(t *testing.T) {
		restarted := newRepository(t)
		recovered := claim(t, restarted, "native-pkce-second-restart")
		if recovered.Attempt != 2 || recovered.LeaseToken == firstRecovered.LeaseToken {
			t.Fatal("second recovery incremented attempt or reused expired lease")
		}
		if original.compensation(f.ctx, lease) == nil {
			t.Fatal("original expired receipt remained usable")
		}
		if restarted.prepare(f.ctx, &recovered, false) == nil {
			t.Fatal("recovery permitted provider forward boundary")
		}
		state, ok := restarted.reservation(nativeConnectorKey(recovered))
		if !ok || len(state.captured) == 0 {
			t.Fatal("owned recovery receipt missing")
		}
		ref, _ := json.Marshal(state.reference)
		if _, err := executor.Invoke(f.ctx, connectormaintenance.BeforeCompensation, ref, state.captured); err != nil {
			t.Fatal("native captured compensation refused")
		}
		if _, err := executor.Facts(f.ctx, state.reference); !errors.Is(err, connectormaintenance.ErrDenied) {
			t.Fatal("native recovery source admitted forward facts after grant restoration")
		}
		for _, op := range []connectormaintenance.Operation{connectormaintenance.CompleteCleanup, connectormaintenance.CompleteRevocation, connectormaintenance.Fail, connectormaintenance.Quarantine} {
			payload := any(struct{}{})
			if op == connectormaintenance.Fail || op == connectormaintenance.Quarantine {
				payload = map[string]string{"reason": "pkce_cleanup_ambiguous"}
			}
			request, _ := json.Marshal(map[string]any{"reference": state.reference, "payload": payload})
			if _, err := executor.Invoke(f.ctx, op, request, state.captured); !errors.Is(err, connectormaintenance.ErrDenied) {
				t.Fatal("native recovery receipt admitted unrelated settlement or failed outside permission guard")
			}
		}
		secrets := &connectorSecretStub{}
		worker, boundaries := connectorPKCERecoveryWorker(t, f.ctx, restarted, secrets)
		if worker.reconcileLease(f.ctx, recovered) != nil {
			t.Fatal("captured recovery worker did not settle cleanup")
		}
		if secrets.taken || len(secrets.deleted) != 1 || secrets.deleted[0] != lease.ConnectionReference || boundaries.providerCalls.Load() != 0 || boundaries.workflowCalls.Load() != 0 {
			t.Fatal("recovery consumed verifier, exchanged provider or changed reference")
		}
		var valid bool
		if f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE id=$1 AND status='reconciled' AND attempt=2) AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.tasks WHERE effect_id=$1 AND state='settled') AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.reservations WHERE effect_id=$1 AND origin_receipt::text=$2 AND state='settled') AND (SELECT count(*)=1 FROM public.zasp_connector_audit WHERE effect_id=$1 AND event_kind='pkce_cleanup_completed')`, cleanup, originalReceipt).Scan(&valid) != nil || !valid {
			t.Fatal("exact cleanup state, original lineage or single audit missing")
		}
		if restarted.compensation(f.ctx, recovered) == nil {
			t.Fatal("settled compensation receipt replay admitted")
		}
		if _, err := restarted.CompletePKCECleanupReconciliation(f.ctx, recovered); err == nil {
			t.Fatal("settled cleanup replay admitted")
		}
		items, err := newRepository(t).ClaimReconciliation(f.ctx, "native-pkce-terminal-contender", 5, 10)
		if err != nil {
			t.Fatal("terminal claim failed")
		}
		for _, item := range items {
			if item.ID == cleanup {
				t.Fatal("settled cleanup recovered again")
			}
		}
	})
}

func connectorPKCERecoveryWorker(t *testing.T, ctx context.Context, repo *NativeConnectorRepository, secrets ConnectorOAuthSecretStore) (*ConnectorReconciler, *connectorPKCERecoveryBoundaries) {
	t.Helper()
	boundaries := &connectorPKCERecoveryBoundaries{}
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: boundaries, RequestedScopes: []string{"read:org"}, CredentialClass: "github_installation_reference"}}, nil)
	if err != nil {
		t.Fatal("component provider registry refused")
	}
	worker, err := NewAuthorizedConnectorReconciler(ctx, repo, ConnectorReconcilerConfig{Registry: registry, Secrets: secrets, Owner: "native-pkce-recovery-worker", LeaseSeconds: 10, Limit: 10, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal("authorized recovery worker refused")
	}
	worker.workflows = boundaries
	return worker, boundaries
}

// These are the actual provider and workflow dependencies used by the worker.
// Every unexpected access is counted and refused, including recovery/discard.
type connectorPKCERecoveryBoundaries struct {
	providerCalls atomic.Int64
	workflowCalls atomic.Int64
}

func (b *connectorPKCERecoveryBoundaries) AuthorizationURL(string, string) (string, error) {
	b.providerCalls.Add(1)
	return "", ErrRepositoryUnavailable
}
func (b *connectorPKCERecoveryBoundaries) Complete(context.Context, string, string, []byte) (ConnectorOAuthGrant, error) {
	b.providerCalls.Add(1)
	return ConnectorOAuthGrant{}, ErrRepositoryUnavailable
}
func (b *connectorPKCERecoveryBoundaries) Recover(context.Context, string) (ConnectorOAuthGrant, error) {
	b.providerCalls.Add(1)
	return ConnectorOAuthGrant{}, ErrRepositoryUnavailable
}
func (b *connectorPKCERecoveryBoundaries) Discard(context.Context, string, bool) error {
	b.providerCalls.Add(1)
	return ErrRepositoryUnavailable
}
func (b *connectorPKCERecoveryBoundaries) Revoke(context.Context, string) error {
	b.providerCalls.Add(1)
	return ErrRepositoryUnavailable
}
func (b *connectorPKCERecoveryBoundaries) GetWorkflow(context.Context, domain.Scope, string, string) (WorkflowValue, error) {
	b.workflowCalls.Add(1)
	return WorkflowValue{}, ErrRepositoryUnavailable
}
