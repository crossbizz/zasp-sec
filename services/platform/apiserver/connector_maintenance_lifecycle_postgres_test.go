package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenancecutover"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This is application integration acceptance using an owned official server and
// the original signed admission. Its controlled one-writer activation is NOT
// deployment/fleet evidence. No task, origin, delegation or approval is seeded.
func TestConnectorMaintenanceNativeLifecyclePostgres(t *testing.T) {
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
	var cleanup string
	var callbackContext context.Context
	var callbackConsumed OAuthConsumption
	var callbackRepository *ConnectorRepository
	var callbackIntegration, callbackCleanup string
	callbackState := strings.Repeat("c", 43)
	t.Run("genuine enqueue controlled cutover and composed projection", func(t *testing.T) {
		f.freshReferenceSession(t)
		created := f.invoke(f.browser, "createIntegration", "", "native-lifecycle-callback-create", integrationClientBody, 0)
		if created.Code != 201 {
			t.Fatal("original callback integration creation refused")
		}
		var callbackValue struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(created.Body.Bytes(), &callbackValue) != nil || !validProductID(callbackValue.ID) {
			t.Fatal("original callback integration identity unavailable")
		}
		callbackIntegration = callbackValue.ID
		f.reconcile()
		proof := func() []byte {
			grant, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": integrationClientExisting}})
			if err != nil {
				t.Fatal("genuine browser admission refused")
			}
			raw, err := authorizationProofJSON(grant)
			if err != nil {
				t.Fatal("genuine browser proof unavailable")
			}
			return raw
		}
		raw := proof()
		var version int64
		var configuration json.RawMessage
		if f.owner.QueryRow(f.ctx, `SELECT version,body->'configuration' FROM public.zasp_workflow_records WHERE(organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4) AND deleted_at IS NULL`, o, w, e, integrationClientExisting).Scan(&version, &configuration) != nil {
			t.Fatal("original integration intent unavailable")
		}
		attempt := "pid_78219101-0000-4000-8000-000000000001"
		cleanup = connectorDeterministicID(f.browser.Scope, attempt, "pkce-cleanup")
		authorize := connectorDeterministicID(f.browser.Scope, attempt, "oauth-effect")
		request := sha256.Sum256([]byte("native lifecycle original OAuth request"))
		state := sha256.Sum256([]byte("native lifecycle original OAuth state"))
		var response []byte
		if err := f.api.QueryRow(f.ctx, `SELECT zasp_connector_maintenance.start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17,$18)`, string(raw), o, w, e, attempt, integrationClientExisting, "github", f.browser.PrincipalID.String(), f.browser.credentialBinding.Digest[:], state[:], "ref:oauth/pkce/native-lifecycle", request[:], `["read:org"]`, time.Now().UTC().Add(5*time.Minute), version, configuration, cleanup, authorize).Scan(&response); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("original authenticated enqueue refused")
		}
		if err := f.api.QueryRow(f.ctx, `SELECT zasp_connector_maintenance.handoff_pkce($1,$2,$3,$4,$5)`, string(proof()), o, w, e, cleanup).Scan(&response); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("genuine preparation cleanup handoff refused")
		}
		callbackGrant, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": callbackIntegration}})
		if err != nil {
			t.Fatal("genuine callback enqueue admission refused")
		}
		callbackProof, err := authorizationProofJSON(callbackGrant)
		if err != nil {
			t.Fatal("genuine callback enqueue proof unavailable")
		}
		var callbackVersion int64
		var callbackConfiguration json.RawMessage
		if f.owner.QueryRow(f.ctx, `SELECT version,body->'configuration' FROM public.zasp_workflow_records WHERE(organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4) AND deleted_at IS NULL`, o, w, e, callbackIntegration).Scan(&callbackVersion, &callbackConfiguration) != nil {
			t.Fatal("original callback integration intent unavailable")
		}
		callbackAttempt := "pid_78219102-0000-4000-8000-000000000002"
		callbackCleanup = connectorDeterministicID(f.browser.Scope, callbackAttempt, "pkce-cleanup")
		callbackEffect := connectorDeterministicID(f.browser.Scope, callbackAttempt, "oauth-effect")
		callbackRequest := sha256.Sum256([]byte("native captured callback rejected intent"))
		callbackStateDigest := sha256.Sum256([]byte(callbackState))
		if err := f.api.QueryRow(f.ctx, `SELECT zasp_connector_maintenance.start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17,$18)`, string(callbackProof), o, w, e, callbackAttempt, callbackIntegration, "github", f.browser.PrincipalID.String(), callbackGrant.Credential.Digest[:], callbackStateDigest[:], "ref:oauth/pkce/native-callback-lifecycle", callbackRequest[:], `["read:org"]`, time.Now().UTC().Add(5*time.Minute), callbackVersion, callbackConfiguration, callbackCleanup, callbackEffect).Scan(&response); err != nil {
			connectorFixtureErrorDiagnostic(t, err)
			t.Fatal("genuine callback enqueue refused")
		}

		cutover, closeCutover, err := connectormaintenancecutover.NewControlled(connectormaintenancecutover.Config{Endpoint: owned.endpoint, StoreID: store, ModelID: model, OldTokenFile: owned.oldFile, NewTokenFile: owned.newFile, ProfileChecksum: pin, ApprovalProfileChecksum: approvalPin, OperatorPool: operatorPool})
		if err != nil {
			t.Fatal("controlled cutover construction refused")
		}
		defer closeCutover()
		pid, stopWriter := startConnectorLifecycleWriter(t, f.dsn, owned.endpoint, owned.oldFile, o, store, model)
		permit, err := cutover.Prepare(f.ctx, o, pid)
		if err != nil {
			t.Log("connector cutover prepare stage=" + connectormaintenancecutover.PrepareRefusalStage(err))
			t.Fatal("authentic old writer preparation refused")
		}
		stopWriter()
		owned.withdrawOld(t)
		if err := cutover.Activate(f.ctx, permit); err != nil {
			t.Fatal("controlled measured activation refused")
		}
		projection, err := authorization.NewCurrentMaintenanceProjectionRepository(f.ctx, workerPool, approvalPin, pin)
		if err != nil {
			t.Fatal("composed maintenance projection selection refused")
		}
		receipt, err := authorization.Reconcile(f.ctx, projection, writer, o, store, model)
		if err != nil || !receipt.Applied {
			t.Fatal("composed Reconcile Stage Ack refused")
		}
		var valid bool
		if f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_connector_maintenance.tasks WHERE effect_id=$1 AND state='active') AND EXISTS(SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$2 AND desired=applied)`, cleanup, o).Scan(&valid) != nil || !valid {
			t.Fatal("active task and complete applied projection unavailable")
		}
	})
	if cleanup == "" || t.Failed() {
		return
	}
	t.Run("genuine callback consumption captures only its original effects", func(t *testing.T) {
		base, err := NewPostgresJSONDatabase(f.driver)
		if err != nil || base.RequireCurrentAuthorization() != nil {
			t.Fatal("callback base authority refused")
		}
		native, err := NewConnectorMaintenanceEnqueueDatabase(f.ctx, base, pin)
		if err != nil {
			t.Fatal("active callback adapter refused")
		}
		callbackRepository, err = NewConnectorRepository(native)
		if err != nil {
			t.Fatal("native callback repository refused")
		}
		resolver, err := NewConnectorMaintenanceCallbackResolver(f.authorizer.Resolver, base, pin)
		if err != nil {
			t.Fatal("genuine callback target resolver refused")
		}
		projection, err := authorization.NewCurrentMaintenanceProjectionRepository(f.ctx, workerPool, approvalPin, pin)
		if err != nil {
			t.Fatal("callback current projection refused")
		}
		callbackAuthorizer := *f.authorizer
		callbackAuthorizer.Resolver = resolver
		callbackAuthorizer.Reader = projection
		callbackAuthorizer.Checker = checker
		queryContext := context.WithValue(f.ctx, authorizationQueryContextKey{}, url.Values{"state": {callbackState}, "code": {"provider-code-0001"}})
		grant, err := callbackAuthorizer.Authorize(queryContext, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "completeIntegrationOAuthCallback"})
		if err != nil {
			t.Fatal("genuine callback signed authorization refused")
		}
		callbackContext = context.WithValue(queryContext, requestAuthorizationContextKey{}, grant)
		state := sha256.Sum256([]byte(callbackState))
		callbackConsumed, err = callbackRepository.ConsumeOAuth(callbackContext, f.browser, state[:], grant.Credential.Digest[:])
		if err != nil {
			t.Fatal("genuine callback captured consumption refused")
		}
		if callbackConsumed.IntegrationID != callbackIntegration || callbackConsumed.ID == "" {
			t.Fatal("callback consumed a different integration")
		}
	})
	if t.Failed() {
		return
	}

	executor, err := connectormaintenance.NewExecutor(f.ctx, workerPool, pin, forward[:])
	if err != nil {
		t.Fatal("registered native executor refused")
	}
	authority, err := connectormaintenance.NewAuthority(executor, checker, store, model, pin, forward[:])
	if err != nil {
		t.Fatal("native worker authority refused")
	}
	defer authority.Close()
	repo, err := NewNativeConnectorRepository(f.ctx, executor, authority)
	if err != nil {
		t.Fatal("native worker repository refused")
	}
	var lease ConnectorEffectLease
	t.Run("reserve without attempt and deny cross scope or unowned replay", func(t *testing.T) {
		// Original product reconciliation intentionally waits 15 seconds before
		// inspecting an unknown effect. Do not forge updated_at or relax that fence.
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			items, err := repo.ClaimReconciliation(f.ctx, "native-lifecycle-owned-worker", 30, 10)
			if err != nil {
				t.Fatal("registered native reservation refused")
			}
			for _, item := range items {
				if item.ID == cleanup {
					lease = item
					break
				}
			}
			if lease.ID != "" {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if lease.ID == "" || lease.Attempt != 0 {
			t.Fatal("genuine cleanup reservation missing or attempt consumed early")
		}
		altered := lease
		altered.EnvironmentID = "pid_78219109-0000-4000-8000-000000000009"
		if repo.prepare(f.ctx, &altered, true) == nil {
			t.Fatal("cross scope reservation admitted")
		}
		reconstructed, err := NewNativeConnectorRepository(f.ctx, executor, authority)
		if err != nil {
			t.Fatal("reconstructed repository refused")
		}
		if reconstructed.prepare(f.ctx, &lease, true) == nil {
			t.Fatal("unowned reservation adopted after repository reconstruction")
		}
		if err := repo.prepare(f.ctx, &lease, true); err != nil || lease.Attempt != 1 {
			t.Fatal("live grantor and task service did not begin exactly one attempt")
		}
	})
	if lease.ID == "" || t.Failed() {
		return
	}
	t.Run("revocation blocks forward work while exact captured cleanup settles", func(t *testing.T) {
		f.exec(`UPDATE public.zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, f.browser.PrincipalID.String(), o)
		if repo.prepare(f.ctx, &lease, true) == nil {
			t.Fatal("pending revocation admitted secret forward boundary")
		}
		projection, err := authorization.NewCurrentMaintenanceProjectionRepository(f.ctx, workerPool, approvalPin, pin)
		if err != nil {
			t.Fatal("composed revocation projection refused")
		}
		receipt, err := authorization.Reconcile(f.ctx, projection, writer, o, store, model)
		if err != nil || !receipt.Applied {
			t.Fatal("revocation Reconcile Stage Ack refused")
		}
		if repo.prepare(f.ctx, &lease, true) == nil {
			t.Fatal("applied grantor revocation admitted forward work")
		}
		wrong := lease
		wrong.ID = "pid_78219108-0000-4000-8000-000000000008"
		if repo.compensation(f.ctx, wrong) == nil {
			t.Fatal("captured cleanup admitted different effect")
		}
		if repo.compensation(f.ctx, lease) != nil {
			t.Fatal("exact retained compensation authority refused after revocation")
		}
		secrets := &connectorSecretStub{}
		if secrets.Delete(f.ctx, lease.ConnectionReference) != nil {
			t.Fatal("fixture PKCE deletion refused")
		}
		transition, err := repo.CompletePKCECleanupReconciliation(f.ctx, lease)
		if err != nil || transition.Status != "reconciled" || transition.Attempt != 1 {
			t.Fatal("captured native cleanup settlement refused")
		}
		if len(secrets.deleted) != 1 || secrets.deleted[0] != lease.ConnectionReference {
			t.Fatal("cleanup touched a different PKCE reference")
		}
		var valid bool
		if f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_connector_maintenance.tasks WHERE effect_id=$1 AND state='settled') AND EXISTS(SELECT 1 FROM zasp_connector_maintenance.reservations WHERE effect_id=$1 AND state='settled' AND captured_receipt IS NOT NULL) AND EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE id=$1 AND status='reconciled' AND attempt=1) AND EXISTS(SELECT 1 FROM public.zasp_connector_audit WHERE effect_id=$1 AND event_kind='pkce_cleanup_completed')`, lease.ID).Scan(&valid) != nil || !valid {
			t.Fatal("native settlement receipt and product state missing")
		}
		if _, err := repo.CompletePKCECleanupReconciliation(f.ctx, lease); err == nil {
			t.Fatal("settled captured reservation replay admitted")
		}
	})
	if t.Failed() {
		return
	}
	t.Run("consumed callback revocation retains only exact rejection cleanup", func(t *testing.T) {
		if callbackRepository.PrepareConnectorOAuthCallback(callbackContext, "secret", callbackConsumed) == nil {
			t.Fatal("revoked callback admitted forward secret access")
		}
		if callbackRepository.PrepareConnectorOAuthCallback(callbackContext, "provider", callbackConsumed) == nil {
			t.Fatal("revoked callback admitted provider exchange")
		}
		wrong := callbackConsumed
		wrong.PKCEVerifierReference = "ref:oauth/pkce/different-callback"
		if callbackRepository.PrepareConnectorOAuthCallback(callbackContext, "reject_secret", wrong) == nil {
			t.Fatal("captured callback admitted different secret reference")
		}
		wrong = callbackConsumed
		wrong.EffectID = cleanup
		if callbackRepository.PrepareConnectorOAuthCallback(callbackContext, "reject_secret", wrong) == nil {
			t.Fatal("captured callback admitted another effect")
		}
		if callbackRepository.PrepareConnectorOAuthCallback(callbackContext, "reject_secret", callbackConsumed) != nil {
			t.Fatal("captured callback rejection cleanup refused after revocation")
		}
		secrets := &connectorSecretStub{}
		if secrets.Delete(callbackContext, callbackConsumed.PKCEVerifierReference) != nil {
			t.Fatal("fixture rejection PKCE deletion refused")
		}
		if _, err := callbackRepository.CompletePKCECleanup(callbackContext, f.browser.Scope, callbackCleanup); err != nil {
			t.Fatal("captured callback PKCE settlement refused")
		}
		if callbackRepository.PrepareConnectorOAuthCallback(callbackContext, "provider", callbackConsumed) == nil {
			t.Fatal("rejection secret settlement unlocked provider exchange")
		}
		if _, err := callbackRepository.ResolveConnectorEffect(callbackContext, f.browser.Scope, ConnectorEffectResolution{ID: callbackConsumed.EffectID, Status: "failed", ErrorCode: "authorization_intent_changed", Metadata: json.RawMessage(`{}`)}); err != nil {
			t.Fatal("captured callback rejection resolution refused")
		}
		if secrets.taken || len(secrets.deleted) != 1 || secrets.deleted[0] != callbackConsumed.PKCEVerifierReference || f.providerCalls.Load() != 0 {
			t.Fatal("callback cleanup consumed verifier, exchanged with provider or deleted another secret")
		}
		var valid bool
		if f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_connector_maintenance.callbacks WHERE attempt_id=$1 AND phase='rejected') AND EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE id=$2 AND status='failed') AND EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE id=$3 AND status='reconciled') AND EXISTS(SELECT 1 FROM public.zasp_connector_audit WHERE effect_id=$3 AND event_kind='pkce_cleanup_completed') AND EXISTS(SELECT 1 FROM public.zasp_connector_audit WHERE effect_id=$2 AND event_kind='authorization_rejected')`, callbackConsumed.ID, callbackConsumed.EffectID, callbackCleanup).Scan(&valid) != nil || !valid {
			t.Fatal("captured callback terminal product state or audit evidence missing")
		}
		if callbackRepository.PrepareConnectorOAuthCallback(callbackContext, "reject_secret", callbackConsumed) == nil {
			t.Fatal("terminal callback receipt replay admitted")
		}
	})

}
