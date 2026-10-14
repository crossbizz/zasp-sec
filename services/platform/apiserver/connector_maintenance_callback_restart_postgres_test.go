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

// Native application acceptance preserves real callback expiry and exercises
// process-local adapter loss. Owned secrets are a component dependency; this
// does not establish real provider, fleet exclusivity or deployed acceptance.
func TestConnectorMaintenanceCallbackRestartRecoveryPostgres(t *testing.T) {
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

	f.freshReferenceSession(t)
	grant, err := f.authorizer.Authorize(f.ctx, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": integrationClientExisting}})
	if err != nil {
		t.Fatal("genuine OAuth admission refused")
	}
	raw, err := authorizationProofJSON(grant)
	if err != nil {
		t.Fatal("genuine OAuth proof unavailable")
	}
	var version int64
	var configuration json.RawMessage
	if f.owner.QueryRow(f.ctx, `SELECT version,body->'configuration' FROM public.zasp_workflow_records WHERE(organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4) AND deleted_at IS NULL`, o, w, e, integrationClientExisting).Scan(&version, &configuration) != nil {
		t.Fatal("original integration unavailable")
	}
	attempt := "pid_78219401-0000-4000-8000-000000000001"
	cleanup := connectorDeterministicID(f.browser.Scope, attempt, "pkce-cleanup")
	effect := connectorDeterministicID(f.browser.Scope, attempt, "oauth-effect")
	state := strings.Repeat("r", 43)
	stateHash := sha256.Sum256([]byte(state))
	request := sha256.Sum256([]byte("native callback restart signed admission"))
	const reference = "ref:oauth/pkce/native-callback-restart"
	var response []byte
	if err := f.api.QueryRow(f.ctx, `SELECT zasp_connector_maintenance.start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17,$18)`, string(raw), o, w, e, attempt, integrationClientExisting, "github", f.browser.PrincipalID.String(), grant.Credential.Digest[:], stateHash[:], reference, request[:], `["read:org"]`, time.Now().UTC().Add(5*time.Minute), version, configuration, cleanup, effect).Scan(&response); err != nil {
		connectorFixtureErrorDiagnostic(t, err)
		t.Fatal("original signed OAuth enqueue refused")
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
	if cutover.Activate(f.ctx, permit) != nil {
		t.Fatal("controlled activation refused")
	}
	projection, err := authorization.NewCurrentMaintenanceProjectionRepository(f.ctx, workerPool, approvalPin, pin)
	if err != nil {
		t.Fatal("composed projection refused")
	}
	reconcile := func(t *testing.T) {
		t.Helper()
		receipt, err := authorization.Reconcile(f.ctx, projection, writer, o, store, model)
		if err != nil || !receipt.Applied {
			t.Fatal("composed projection did not apply")
		}
	}
	reconcile(t)
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
			t.Fatal("reconstructed worker repository refused")
		}
		return repo
	}
	var consumed OAuthConsumption
	var expires time.Time
	var callbackContext context.Context
	t.Run("genuine callback consumption survives discarded API adapter", func(t *testing.T) {
		base, err := NewPostgresJSONDatabase(f.driver)
		if err != nil || base.RequireCurrentAuthorization() != nil {
			t.Fatal("callback base authority refused")
		}
		native, err := NewConnectorMaintenanceEnqueueDatabase(f.ctx, base, pin)
		if err != nil {
			t.Fatal("native callback adapter refused")
		}
		repository, err := NewConnectorRepository(native)
		if err != nil {
			t.Fatal("native callback repository refused")
		}
		resolver, err := NewConnectorMaintenanceCallbackResolver(f.authorizer.Resolver, base, pin)
		if err != nil {
			t.Fatal("native callback resolver refused")
		}
		authorizer := *f.authorizer
		authorizer.Resolver = resolver
		authorizer.Reader = projection
		authorizer.Checker = checker
		query := context.WithValue(f.ctx, authorizationQueryContextKey{}, url.Values{"state": {state}, "code": {"native-provider-code"}})
		admission, err := authorizer.Authorize(query, f.browser, f.browser.credentialBinding, RoutedOperation{OperationID: "completeIntegrationOAuthCallback"})
		if err != nil {
			t.Fatal("genuine callback authorization refused")
		}
		callbackContext = context.WithValue(query, requestAuthorizationContextKey{}, admission)
		consumed, err = repository.ConsumeOAuth(callbackContext, f.browser, stateHash[:], admission.Credential.Digest[:])
		if err != nil || consumed.ID != attempt || consumed.EffectID != effect || consumed.PKCEVerifierReference != reference {
			t.Fatal("genuine callback consumption refused or changed intent")
		}
		if f.owner.QueryRow(f.ctx, `SELECT expires_at FROM zasp_connector_maintenance.callbacks WHERE attempt_id=$1 AND phase='consumed'`, attempt).Scan(&expires) != nil {
			t.Fatal("durable original callback expiry missing")
		}
		// A fresh API adapter has no authority to adopt another process's permit.
		replacement, err := NewConnectorMaintenanceEnqueueDatabase(f.ctx, base, pin)
		if err != nil {
			t.Fatal("replacement API adapter refused")
		}
		replacementRepository, err := NewConnectorRepository(replacement)
		if err != nil {
			t.Fatal("replacement API repository refused")
		}
		for _, phase := range []string{"secret", "provider", "reject_secret"} {
			if replacementRepository.PrepareConnectorOAuthCallback(callbackContext, phase, consumed) == nil {
				t.Fatal("replacement API adapter adopted lost forward or compensation permit")
			}
		}
		// Both original adapters go out of scope here. No secret or provider ran.
		page, _ := json.Marshal(map[string]any{"owner": "native-callback-live-contender", "seconds": 10, "limit": 10})
		result, err := newRepository(t).invokeCallbackRecovery(f.ctx, callbackRecoveryClaim, page, nil)
		items, decodeErr := decodeConnectorCallbackRecovery(result, "native-callback-live-contender", 10, 10)
		if err != nil || decodeErr != nil || len(items) != 0 {
			t.Fatal("live original callback admitted recovery")
		}
	})
	if t.Failed() {
		return
	}
	f.exec(`UPDATE public.zasp_identity_memberships SET active=false WHERE principal_id=$1 AND organization_id=$2`, f.browser.PrincipalID.String(), o)
	reconcile(t)
	// Wait on the stored real deadline; no SQL clock or lease mutation is used.
	wait := func(t *testing.T, deadline time.Time) {
		t.Helper()
		delay := time.Until(deadline.Add(30 * time.Millisecond))
		if delay <= 0 {
			return
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-f.ctx.Done():
			t.Fatal("owned native recovery context expired")
		case <-timer.C:
		}
	}
	wait(t, expires)
	var first connectorCallbackRecoveryItem
	t.Run("expired revoked callback permits exact deletion but failure never settles", func(t *testing.T) {
		recorder := &connectorCallbackNativeRecoveryRecorder{repository: newRepository(t)}
		secrets := &connectorSecretStub{deleteErr: ErrRepositoryUnavailable}
		count, err := runConnectorCallbackRecovery(f.ctx, recorder, secrets, "native-callback-first-restart", 10, 10)
		if err == nil || count != 0 || secrets.taken || len(secrets.deleted) != 1 || secrets.deleted[0] != reference || len(recorder.items) != 1 {
			t.Fatal("failed callback deletion settled or changed secret")
		}
		first = recorder.items[0]
		if first.AttemptID != attempt || first.AuthorizeEffectID != effect || first.CleanupEffectID != cleanup || first.PKCEReference != reference {
			t.Fatal("native recovery changed original callback intent")
		}
		var valid bool
		if f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_connector_maintenance.callbacks WHERE attempt_id=$1 AND phase='consumed') AND NOT EXISTS(SELECT 1 FROM public.zasp_connector_audit WHERE effect_id IN($2,$3) AND event_kind IN('pkce_cleanup_completed','authorization_rejected'))`, attempt, cleanup, effect).Scan(&valid) != nil || !valid {
			t.Fatal("failed deletion changed callback phase or emitted terminal audit")
		}
	})
	if t.Failed() {
		return
	}
	wait(t, first.LeaseExpiresAt)
	t.Run("second worker restart rotates receipts and atomically rejects once", func(t *testing.T) {
		repo := newRepository(t)
		old := first
		proof := append(json.RawMessage(nil), old.CapturedProof...)
		old.CapturedProof = nil
		q, _ := json.Marshal(old)
		for _, op := range []connectorCallbackRecoveryOperation{callbackRecoveryBefore, callbackRecoverySettle} {
			if _, err := repo.invokeCallbackRecovery(f.ctx, op, q, proof); err == nil {
				t.Fatal("expired worker receipt admitted replay")
			}
		}
		recorder := &connectorCallbackNativeRecoveryRecorder{repository: repo, check: func(item connectorCallbackRecoveryItem) {
			if item.LeaseToken == first.LeaseToken || item.AttemptID != first.AttemptID || item.PKCEReference != reference {
				t.Fatal("restarted callback recovery reused ownership or changed intent")
			}
			for _, mutate := range []func(*connectorCallbackRecoveryItem){func(i *connectorCallbackRecoveryItem) { i.EnvironmentID = "pid_78219409-0000-4000-8000-000000000009" }, func(i *connectorCallbackRecoveryItem) { i.PKCEReference = "ref:oauth/pkce/unowned-callback" }, func(i *connectorCallbackRecoveryItem) { i.AuthorizeEffectID = cleanup }} {
				changed := item
				mutate(&changed)
				captured := changed.CapturedProof
				changed.CapturedProof = nil
				request, _ := json.Marshal(changed)
				if _, err := repo.invokeCallbackRecovery(f.ctx, callbackRecoveryBefore, request, captured); err == nil {
					t.Fatal("callback recovery crossed scope, reference or effect purpose")
				}
			}
		}}
		secrets := &connectorSecretStub{}
		count, err := runConnectorCallbackRecovery(f.ctx, recorder, secrets, "native-callback-second-restart", 10, 10)
		if err != nil || count != 1 || secrets.taken || len(secrets.deleted) != 1 || secrets.deleted[0] != reference || f.providerCalls.Load() != 0 {
			t.Fatal("exact callback restart did not settle without consumption or provider exchange")
		}
		var valid bool
		if f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_connector_maintenance.callbacks WHERE attempt_id=$1 AND phase='rejected') AND EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE id=$2 AND status='failed') AND EXISTS(SELECT 1 FROM public.zasp_connector_effects WHERE id=$3 AND status='reconciled') AND (SELECT count(*)=1 FROM public.zasp_connector_audit WHERE effect_id=$3 AND event_kind='pkce_cleanup_completed') AND (SELECT count(*)=1 FROM public.zasp_connector_audit WHERE effect_id=$2 AND event_kind='authorization_rejected')`, attempt, effect, cleanup).Scan(&valid) != nil || !valid {
			t.Fatal("atomic rejected callback state and exactly once audit missing")
		}
		terminal := recorder.items[0]
		captured := terminal.CapturedProof
		terminal.CapturedProof = nil
		request, _ := json.Marshal(terminal)
		if _, err := repo.invokeCallbackRecovery(f.ctx, callbackRecoverySettle, request, captured); err == nil {
			t.Fatal("terminal callback settlement receipt replay admitted")
		}
		count, err = runConnectorCallbackRecovery(f.ctx, newRepository(t), secrets, "native-callback-terminal-contender", 10, 10)
		if err != nil || count != 0 || len(secrets.deleted) != 1 {
			t.Fatal("terminal callback was recovered or deleted again")
		}
	})
}

type connectorCallbackNativeRecoveryRecorder struct {
	repository *NativeConnectorRepository
	items      []connectorCallbackRecoveryItem
	check      func(connectorCallbackRecoveryItem)
}

func (r *connectorCallbackNativeRecoveryRecorder) invokeCallbackRecovery(ctx context.Context, op connectorCallbackRecoveryOperation, q, proof json.RawMessage) (json.RawMessage, error) {
	result, err := r.repository.invokeCallbackRecovery(ctx, op, q, proof)
	if err == nil && op == callbackRecoveryClaim {
		var request struct {
			Owner   string `json:"owner"`
			Seconds int    `json:"seconds"`
			Limit   int    `json:"limit"`
		}
		if json.Unmarshal(q, &request) != nil {
			return nil, ErrRepositoryOperation
		}
		items, decodeErr := decodeConnectorCallbackRecovery(result, request.Owner, request.Seconds, request.Limit)
		if decodeErr != nil {
			return nil, decodeErr
		}
		r.items = items
		if r.check != nil {
			for _, item := range items {
				r.check(item)
			}
		}
	}
	return result, err
}
