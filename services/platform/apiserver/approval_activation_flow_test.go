package apiserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/approvalmaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenancecutover"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// Full owned application flow, using genuine native planning and the official
// persistent FGA server. This is not deployed provider or fleet evidence.
func TestApprovalActivationNativeFindingDeliveryFlow(t *testing.T) {
	if os.Getenv("ZASP_P7_MODEL_TEST") != "1" {
		t.Skip("requires owned native PostgreSQL/OpenFGA runtime")
	}
	owned := newConnectorLifecycleFGA(t)
	runFindingResponseFixtureConfigured(t, nil, func(ctx context.Context, f findingResponseFixture, original, finding string) {
		runner := workerMigrationRunner(t, f.owner)
		for _, up := range []func(context.Context) error{runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile, runner.UpProductionApprovalMaintenanceProfile, runner.UpProductionConnectorMaintenance, runner.UpProductionApprovalActivationProfile} {
			if err := up(ctx); err != nil {
				t.Fatal("native maintenance composition refused", err)
			}
		}
		var predecessorBefore, predecessorAfter string
		const predecessorObservation = `SELECT jsonb_build_array(zasp_approval_activation_v1.fingerprint(),zasp_approval_maintenance.fingerprint(),zasp_connector_maintenance.fingerprint(),zasp_authorization79.fingerprint(),zasp_authorization80.fingerprint())::text`
		if err := f.owner.QueryRow(ctx, predecessorObservation).Scan(&predecessorBefore); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := runner.UpProductionApprovalSettlementAuditProfile(ctx); err != nil {
				t.Fatal("additive audit installation/idempotency refused", err)
			}
		}
		if err := f.owner.QueryRow(ctx, predecessorObservation).Scan(&predecessorAfter); err != nil || predecessorBefore != predecessorAfter {
			t.Fatal("additive audit installer changed predecessor catalog", err)
		}
		if _, err := f.owner.Exec(ctx, `INSERT INTO public.zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Owned approval delivery','connector_key','generic-webhook','status','configured','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_approval_fixture')))`, f.o, f.w, f.e, f.next()); err != nil {
			t.Fatal("original webhook configuration refused", err)
		}
		var outbox string
		if err := f.owner.QueryRow(ctx, `SELECT principal_name FROM public.zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
			t.Fatal("original projection principal unavailable", err)
		}
		poolFor := func(login string) *pgxpool.Pool {
			t.Helper()
			cfg, err := pgxpool.ParseConfig(f.owner.Config().ConnString())
			if err != nil {
				t.Fatal(err)
			}
			cfg.ConnConfig.User = login
			cfg.MaxConns = 2
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			return pool
		}
		outboxPool, operatorPool, plannerPool := poolFor(outbox), poolFor(f.owner.Config().User), poolFor("finding78_executor")
		client, pins := newApprovalMaintenanceOwnedFGA(t)
		checker, err := authorization.NewOpenFGA(client, pins)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := authorization.NewOpenFGATupleWriter(client, pins)
		if err != nil {
			t.Fatal(err)
		}
		projection, err := authorization.NewPostgresProjectionRepository(outboxPool)
		if err != nil {
			t.Fatal(err)
		}
		var activeProjection authorization.ProjectionRepository = projection
		reconcile := func() {
			t.Helper()
			receipt, err := authorization.Reconcile(ctx, activeProjection, writer, f.o, pins.StoreID, pins.ModelID)
			if err != nil || !receipt.Applied {
				t.Fatal("complete native projection acknowledgement refused", err)
			}
		}
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, f.o, pins.StoreID, pins.ModelID); err != nil {
			t.Fatal(err)
		}
		key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.WorkerForward), key.Version(), key.Verifier()); err != nil {
			t.Fatal(err)
		}
		approvalPin := migrations.ApprovalMaintenanceProfileChecksum()
		connectorPin, err := migrations.ConnectorMaintenanceProfileChecksum()
		if err != nil {
			t.Fatal(err)
		}
		activationPin, err := migrations.ApprovalActivationProfileChecksum()
		if err != nil {
			t.Fatal(err)
		}
		planner, err := authorization.NewApprovalOriginWorkerExecutor(ctx, plannerPool, checker, pins.StoreID, pins.ModelID, key, approvalPin)
		if err != nil {
			t.Fatal(err)
		}
		var pricing json.RawMessage
		if err := f.owner.QueryRow(ctx, `SELECT lookup_request-'body'-'body_digest' FROM zasp_temporal78.planning_jobs WHERE run_id=$1`, original).Scan(&pricing); err != nil {
			t.Fatal(err)
		}
		plan := func() string { return approvalActivationPlanFinding(t, ctx, f, original, planner, pricing, reconcile) }
		first := plan()
		var inactive bool
		if err := f.owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(status='captured_inactive' AND delegation IS NOT NULL) FROM zasp_approval_maintenance.origins WHERE run_id=$1`, first).Scan(&inactive); err != nil || !inactive {
			t.Fatal("genuine inactive enqueue absent", err)
		}
		// Dedicated native login and independent purpose keys; no origins or grants
		// are manufactured by registration.
		if _, err := f.owner.Exec(ctx, `CREATE ROLE approval_activation_delivery LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;GRANT zasp_approval_maintenance_worker TO approval_activation_delivery`); err != nil {
			t.Fatal(err)
		}
		var af, ac, cf, cc [32]byte
		for _, k := range []*[32]byte{&af, &ac, &cf, &cc} {
			if _, err := rand.Read(k[:]); err != nil {
				t.Fatal(err)
			}
			defer clear(k[:])
		}
		for _, v := range []struct {
			purpose string
			key     []byte
		}{{"approval-forward", af[:]}, {"approval-captured", ac[:]}} {
			sum := sha256.Sum256(v.key)
			if _, err := f.owner.Exec(ctx, `SELECT zasp_approval_maintenance.register_verifier($1,$2,$3)`, v.purpose, hex.EncodeToString(sum[:]), v.key); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := f.owner.Exec(ctx, `SELECT zasp_approval_maintenance.register_principal('approval_activation_delivery')`); err != nil {
			t.Fatal(err)
		}
		fv, cv := sha256.Sum256(cf[:]), sha256.Sum256(cc[:])
		if _, err := f.owner.Exec(ctx, `SELECT zasp_connector_maintenance.register_principal($1,$2,$3,$4,$5)`, outbox, hex.EncodeToString(fv[:]), hex.EncodeToString(cv[:]), cf[:], cc[:]); err != nil {
			t.Fatal(err)
		}
		reconcile()
		t.Run("measured combined activation and complete projection", func(t *testing.T) {
			cutover, closeCutover, err := connectormaintenancecutover.NewCombinedControlled(connectormaintenancecutover.Config{Endpoint: owned.endpoint, StoreID: pins.StoreID, ModelID: pins.ModelID, OldTokenFile: owned.oldFile, NewTokenFile: owned.newFile, ProfileChecksum: connectorPin, ApprovalProfileChecksum: approvalPin, OperatorPool: operatorPool}, activationPin)
			if err != nil {
				t.Fatal(err)
			}
			defer closeCutover()
			pid, stop := startApprovalActivationWriter(t, f.owner.Config().ConnString(), outbox, owned, pins, f.o)
			permit, err := cutover.Prepare(ctx, f.o, pid)
			if err != nil {
				t.Log("connector cutover prepare stage=" + connectormaintenancecutover.PrepareRefusalStage(err))
				t.Fatal("real old writer observation refused")
			}
			stop()
			owned.withdrawOld(t)
			if err := cutover.Activate(ctx, permit); err != nil {
				t.Log("connector cutover activation stage=" + connectormaintenancecutover.ActivationRefusalStage(err))
				t.Fatal("combined measured activation refused")
			}
			composed, err := authorization.NewCurrentMaintenanceProjectionRepository(ctx, outboxPool, approvalPin, connectorPin)
			if err != nil {
				t.Fatal(err)
			}
			activeProjection = composed
			reconcile()
			var valid bool
			if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_approval_maintenance.origins WHERE run_id=$1 AND status='active') AND EXISTS(SELECT 1 FROM zasp_approval_activation_v1.organizations WHERE organization_id=$2) AND EXISTS(SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$2 AND desired=applied)`, first, f.o).Scan(&valid); err != nil || !valid {
				t.Fatal("activated captured origin or applied revision missing", err)
			}
		})
		if t.Failed() {
			return
		}
		native, err := approvalmaintenance.NewActivatedExecutor(ctx, poolFor("approval_activation_delivery"), checker, pins.StoreID, pins.ModelID, approvalPin, af[:], activationPin)
		if err != nil {
			t.Fatal(err)
		}
		defer native.Close()
		token := func() (string, error) {
			var v [32]byte
			_, err := rand.Read(v[:])
			return hex.EncodeToString(v[:]), err
		}
		adapter := approvalmaintenance.NativeAdapter{Caller: native, Owner: "owned-approval-activation", LeaseSeconds: 60, Token: token}
		// Read the first real payload behind its live gate, then release its unused
		// lease. The reconciler must reserve and authorize again before actual HTTP.
		reservation, found, err := adapter.Reserve(ctx)
		if err != nil || !found {
			t.Fatal("active native reservation unavailable", err)
		}
		payload, err := native.LoadDelivery(ctx, reservation)
		if err != nil || payload.RunID != first {
			t.Log(approvalActivationFailureObservation(ctx, reservation, err, payload.RunID == first))
			t.Fatal("live original payload unavailable")
		}
		if err := adapter.ReleaseUnattempted(ctx, reservation); err != nil {
			t.Fatal(err)
		}
		webhook, calls := maintenanceOrderOwnedWebhook(t, payload, http.StatusNoContent, "")
		secrets := &findingTicketSecretResolverStub{material: bytes.Repeat([]byte{0xa5}, 32)}
		reconciler, err := NewAuthorizedApprovalNotificationReconciler(ctx, AuthorizedApprovalNotificationConfig{Native: native, Secrets: secrets, Webhook: webhook, Owner: adapter.Owner, LeaseSeconds: 60, NewLeaseToken: token})
		if err != nil {
			t.Fatal(err)
		}
		t.Run("native signed delivery settles exact receipt", func(t *testing.T) {
			if err := reconciler.ReconcileOnce(ctx); err != nil {
				t.Fatal("authorized signed webhook refused", err)
			}
			var settled bool
			if err := f.owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(n.state='delivered' AND n.attempt=1 AND n.completed_at IS NOT NULL AND r.state='settled' AND r.attempt=1 AND r.kind='delivery' AND r.receipt IS NOT NULL) FROM public.zasp_security_agent_approval_notifications n JOIN zasp_approval_maintenance.reservations r USING(organization_id,workspace_id,environment_id,delivery_id) WHERE n.run_id=$1 AND r.state='settled'`, first).Scan(&settled); err != nil || !settled || calls.Load() != 1 || secrets.calls != 1 {
				t.Fatal("signed delivery lacks exact durable settlement", err)
			}
			assertApprovalActivationSettlementAudit(t, ctx, f, first, "delivered")
			if err := reconciler.ReconcileOnce(ctx); err != nil || calls.Load() != 1 {
				t.Fatal("settled notification resent", err)
			}
		})
		if t.Failed() {
			return
		}
		reconcile()
		planner, err = authorization.NewActivatedCurrentMaintenanceWorkerExecutor(ctx, plannerPool, checker, pins.StoreID, pins.ModelID, key, approvalPin, connectorPin, activationPin)
		if err != nil {
			t.Fatal("activated actual planner selection refused", err)
		}
		second := plan()
		reconcile()
		t.Run("future native enqueue inherits organization activation", func(t *testing.T) {
			var valid bool
			if err := f.owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(status='active' AND family='finding78' AND delegation IS NOT NULL) FROM zasp_approval_maintenance.origins WHERE run_id=$1`, second).Scan(&valid); err != nil || !valid {
				t.Fatal("future genuine native enqueue not activated", err)
			}
		})
		if t.Failed() {
			return
		}
		t.Run("permission revocation preserves membership and prevents send", func(t *testing.T) {
			if _, err := f.owner.Exec(ctx, `UPDATE public.zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2 AND active`, f.o, f.actor); err != nil {
				t.Fatal(err)
			}
			reconcile()
			var service, task string
			if err := f.owner.QueryRow(ctx, `SELECT delegation->>'principal_id',delegation->>'task_id' FROM zasp_approval_maintenance.origins WHERE run_id=$1`, second).Scan(&service, &task); err != nil {
				t.Fatal(err)
			}
			for _, principal := range []struct {
				kind, id, task string
				allowed        bool
			}{{"user", f.actor, "", false}, {"service", service, task, true}} {
				decision, err := checker.Check(ctx, authorization.CheckRequest{PrincipalKind: principal.kind, PrincipalID: principal.id, TaskID: principal.task, OrganizationID: f.o, WorkspaceID: f.w, EnvironmentID: f.e, ResourceType: "security_agent", ResourceID: f.definition, Permission: "manage_workflows"})
				if err != nil || decision.Allowed != principal.allowed || decision.ModelID != pins.ModelID {
					t.Fatal("actual grantor permission was not withdrawn independently of live service delegation", err)
				}
			}
			var auditBefore int
			if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM public.zasp_security_agent_audit WHERE run_id=$1`, second).Scan(&auditBefore); err != nil {
				t.Fatal(err)
			}
			beforeSecrets, beforeCalls := secrets.calls, calls.Load()
			if err := reconciler.ReconcileOnce(ctx); !errors.Is(err, approvalmaintenance.ErrDenied) {
				t.Fatal("live permission revocation was not denied", err)
			}
			var valid bool
			if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2 AND active AND role='read_only_viewer') AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.origins x JOIN public.zasp_security_agent_approval_notifications n USING(organization_id,workspace_id,environment_id,delivery_id) WHERE x.run_id=$3 AND x.status='paused_denied' AND n.attempt=0 AND n.completed_at IS NULL AND n.state='retryable') AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.reservations WHERE delivery_id IN(SELECT delivery_id FROM public.zasp_security_agent_approval_notifications WHERE run_id=$3) AND state='attempted')`, f.o, f.actor, second).Scan(&valid); err != nil || !valid || secrets.calls != beforeSecrets || calls.Load() != beforeCalls {
				t.Fatal("permission denial consumed attempt, secret, send or false completion", err)
			}
			var auditAfter int
			if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM public.zasp_security_agent_audit WHERE run_id=$1`, second).Scan(&auditAfter); err != nil || auditAfter != auditBefore {
				t.Fatal("denied send published an audit completion", err)
			}
		})
		if t.Failed() {
			return
		}
		// Restore the fixture's original role through the original identity row,
		// project real authorization, and hold one genuine delivery attempt receipt.
		if _, err := f.owner.Exec(ctx, `UPDATE public.zasp_identity_memberships SET role='organization_admin' WHERE organization_id=$1 AND principal_id=$2 AND active`, f.o, f.actor); err != nil {
			t.Fatal(err)
		}
		reconcile()
		t.Run("captured attempt settles after permission revocation without fresh authority", func(t *testing.T) {
			r, found, err := adapter.Reserve(ctx)
			if err != nil || !found {
				t.Fatal(err)
			}
			p, err := native.LoadDelivery(ctx, r)
			if err != nil || p.RunID != second {
				t.Fatal(err)
			}
			proof, err := adapter.Authorize(ctx, r, approvalmaintenance.BeforeDelivery)
			if err != nil {
				t.Fatal(err)
			}
			attempt, err := adapter.BeginAttempt(ctx, r, approvalmaintenance.DeliveryAttempt, proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.Exec(ctx, `UPDATE public.zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2 AND active`, f.o, f.actor); err != nil {
				t.Fatal(err)
			}
			reconcile()
			if _, err := adapter.Authorize(ctx, r, approvalmaintenance.BeforeDelivery); !errors.Is(err, approvalmaintenance.ErrDenied) {
				t.Fatal("captured receipt recreated forward permission", err)
			}
			assertApprovalSettlementRefusalAtomicity(t, ctx, f, r, attempt)
			// Fail, never Complete: no provider call was made for this held attempt.
			if err := adapter.Fail(ctx, r, attempt); err != nil {
				t.Fatal("original captured settlement lost after revocation", err)
			}
			var valid bool
			if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.zasp_security_agent_approval_notifications WHERE run_id=$1 AND attempt=1 AND state='retryable' AND completed_at IS NULL) AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.reservations r JOIN public.zasp_security_agent_approval_notifications n USING(organization_id,workspace_id,environment_id,delivery_id) WHERE n.run_id=$1 AND r.state='settled' AND r.attempt=1 AND r.receipt IS NOT NULL)`, second).Scan(&valid); err != nil || !valid || calls.Load() != 1 {
				t.Fatal("captured settlement altered attempt/outcome or sent after revocation", err)
			}
			assertApprovalActivationSettlementAudit(t, ctx, f, second, "retryable")
			if err := adapter.Fail(ctx, r, attempt); err == nil {
				t.Fatal("committed captured settlement replay was accepted")
			}
			assertApprovalActivationSettlementAudit(t, ctx, f, second, "retryable")
		})
	}, true, 3)
}

// Small orchestration helper using the original signed finding operation set.
// Provider body is controlled fixture input; all admission/source/proof/effect
// validation remains in the actual worker executor and original SQL.
func approvalActivationPlanFinding(t *testing.T, ctx context.Context, f findingResponseFixture, original string, executor *authorization.WorkerExecutor, pricing json.RawMessage, reconcile func()) string {
	t.Helper()
	run, ref := admitWorkerFindingTask(t, ctx, f, original)
	if err := executor.PrepareFinding(ctx, ref); err != nil {
		t.Fatal("original finding preparation refused", err)
	}
	reconcile()
	var identity map[string]any
	if json.Unmarshal(ref, &identity) != nil {
		t.Fatal("native run identity invalid")
	}
	delete(identity, "input_digest")
	call := func(op string, payload any) map[string]any {
		t.Helper()
		q := map[string]any{}
		for k, v := range identity {
			q[k] = v
		}
		q["operation"] = op
		if op != "load" && op != "recovery" {
			q["payload"] = payload
		}
		raw, _ := json.Marshal(q)
		decision, err := executor.Authorize(ctx, authorization.WorkerOperation("finding.planning."+op), raw)
		if err != nil {
			t.Fatal("original signed finding authorization refused", op, err)
		}
		result, err := executor.Execute(ctx, decision)
		if err != nil {
			t.Fatal("original signed finding execution refused", op, err)
		}
		var body map[string]any
		if json.Unmarshal(result, &body) != nil {
			t.Fatal("original result invalid")
		}
		return body
	}
	if body := call("load", nil); body["state"] != "loaded" {
		t.Fatal("original context not loaded")
	}
	reconcile()
	var selection any
	if json.Unmarshal(pricing, &selection) != nil {
		t.Fatal("original pricing invalid")
	}
	if body := call("prepare", map[string]any{"pricing": selection, "input_version": "approval-activation-input-v1"}); body["state"] != "prepared" {
		t.Fatal("original planner preparation refused")
	}
	if body := call("start", map[string]any{}); body["send_permit"] != true {
		t.Fatal("original one-use provider permit refused")
	}
	var finding string
	if err := f.owner.QueryRow(ctx, `SELECT trigger_id FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&finding); err != nil {
		t.Fatal(err)
	}
	candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Assign investigation", "steps": []any{map[string]any{"index": 0, "action": "update_finding_response", "target_id": finding, "assignee_id": f.actor, "status": "investigating", "note": "Investigate the credential exposure"}}})
	provider, _ := json.Marshal(map[string]any{"id": "approval-activation-" + run, "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
	call("result", map[string]any{"raw": string(provider)})
	settled := call("settle", map[string]any{})
	call("artifacts", map[string]any{"input_version": "approval-activation-input-v1", "output_version": "approval-activation-output-v1", "output_digest": settled["output_digest"]})
	if receipt := call("admit", map[string]any{}); receipt["outcome"] != "admitted" || receipt["contract_version"] != float64(78) {
		t.Fatal("genuine supervised planning did not admit")
	}
	return run
}

// The held child runs the original canonical projection before acknowledging
// readiness. Closing stdin joins the exact observed old writer normally.
func startApprovalActivationWriter(t *testing.T, dsn, login string, owned *connectorLifecycleFGA, pins runtimeservices.Config, org string) (int, func()) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-test.run=^TestApprovalActivationOldWriterProcess$", "-test.timeout=2m")
	command.Env = append(os.Environ(), "ZASP_APPROVAL_ACTIVATION_WRITER=1", "ZASP_APPROVAL_ACTIVATION_DSN="+dsn, "ZASP_APPROVAL_ACTIVATION_LOGIN="+login, "ZASP_APPROVAL_ACTIVATION_ORG="+org, "ZASP_APPROVAL_ACTIVATION_URL="+owned.endpoint, "ZASP_APPROVAL_ACTIVATION_TOKEN_FILE="+owned.oldFile, "ZASP_APPROVAL_ACTIVATION_STORE="+pins.StoreID, "ZASP_APPROVAL_ACTIVATION_MODEL="+pins.ModelID)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal("original owned writer unavailable")
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = input.Close()
		if err := command.Wait(); err != nil {
			t.Error("original owned writer did not join normally")
		}
	}
	t.Cleanup(stop)
	ready := make(chan bool, 1)
	go func() {
		var marker [1]byte
		_, err := io.ReadFull(output, marker[:])
		ready <- err == nil && marker[0] == 'R'
		_, _ = io.Copy(io.Discard, output)
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("original owned writer reconciliation refused")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("original owned writer readiness deadline")
	}
	return command.Process.Pid, stop
}

func TestApprovalActivationOldWriterProcess(t *testing.T) {
	if os.Getenv("ZASP_APPROVAL_ACTIVATION_WRITER") != "1" {
		t.Skip("owned subprocess helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(os.Getenv("ZASP_APPROVAL_ACTIVATION_DSN"))
	if err != nil {
		t.Fatal("owned writer database config refused")
	}
	cfg.ConnConfig.User = os.Getenv("ZASP_APPROVAL_ACTIVATION_LOGIN")
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("owned writer pool refused")
	}
	defer pool.Close()
	token, err := os.ReadFile(os.Getenv("ZASP_APPROVAL_ACTIVATION_TOKEN_FILE"))
	if err != nil {
		t.Fatal("owned writer credential unavailable")
	}
	defer clear(token)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	pins := runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-approval-activation", TaskQueue: "zasp-agent", DiscoveryTaskQueue: "zasp-discovery", FGATokenFile: os.Getenv("ZASP_APPROVAL_ACTIVATION_TOKEN_FILE"), Timeout: 5 * time.Second, FGAURL: os.Getenv("ZASP_APPROVAL_ACTIVATION_URL"), StoreID: os.Getenv("ZASP_APPROVAL_ACTIVATION_STORE"), ModelID: os.Getenv("ZASP_APPROVAL_ACTIVATION_MODEL")}
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: pins.FGAURL, StoreId: pins.StoreID, AuthorizationModelId: pins.ModelID, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: string(token)}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal("official writer SDK refused")
	}
	repo, err := authorization.NewPostgresProjectionRepository(pool)
	if err != nil {
		t.Fatal("original writer repository refused")
	}
	writer, err := authorization.NewOpenFGATupleWriter(client, pins)
	if err != nil {
		t.Fatal("original tuple writer refused")
	}
	receipt, err := authorization.Reconcile(ctx, repo, writer, os.Getenv("ZASP_APPROVAL_ACTIVATION_ORG"), pins.StoreID, pins.ModelID)
	if err != nil || !receipt.Applied {
		t.Fatal("original actual projection failed")
	}
	if _, err := os.Stdout.Write([]byte("R")); err != nil {
		t.Fatal("owned writer acknowledgement failed")
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal("owned writer close refused")
	}
}

func assertApprovalActivationSettlementAudit(t *testing.T, ctx context.Context, f findingResponseFixture, run, transition string) {
	t.Helper()
	var valid bool
	const exactAudit = `WITH expected AS (
 SELECT n.*,r.kind,r.receipt,o.source_digest,o.delegation->>'principal_id' actor,a.step_id,
 public.zasp_discovery_canonical_id(n.organization_id,n.workspace_id,n.environment_id,'approval_delivery_audit',n.delivery_id||chr(31)||r.attempt::text||chr(31)||r.kind||chr(31)||n.state) aid,
 public.zasp_discovery_canonical_id(n.organization_id,n.workspace_id,n.environment_id,'approval_delivery_attempt',n.delivery_id||chr(31)||r.attempt::text||chr(31)||r.kind) cid,
 jsonb_build_object('delivery_id',n.delivery_id,'run_id',n.run_id,'approval_id',n.approval_id,'step_id',a.step_id,'attempt',r.attempt,'kind',r.kind,'transition',n.state,'payload_digest','sha256:'||encode(n.payload_digest,'hex'),'source_digest','sha256:'||o.source_digest,'receipt_digest','sha256:'||encode(digest(convert_to(r.receipt::text,'UTF8'),'sha256'),'hex')) evidence
 FROM public.zasp_security_agent_approval_notifications n JOIN zasp_approval_maintenance.reservations r USING(organization_id,workspace_id,environment_id,delivery_id)
 JOIN zasp_approval_maintenance.origins o USING(organization_id,workspace_id,environment_id,delivery_id)
 JOIN public.zasp_security_agent_approvals a ON(a.organization_id,a.workspace_id,a.environment_id,a.approval_id,a.run_id)=(n.organization_id,n.workspace_id,n.environment_id,n.approval_id,n.run_id)
 WHERE n.run_id=$1 AND r.state='settled')
 SELECT count(*)=1 AND bool_and(x.state=$2 AND
 (v.organization_id,v.workspace_id,v.environment_id,v.audit_id,v.correlation_id,v.run_id,v.step_id,v.approval_id,v.actor_id,v.event_kind,v.body) IS NOT DISTINCT FROM
 (x.organization_id,x.workspace_id,x.environment_id,x.aid,x.cid,x.run_id,x.step_id,x.approval_id,x.actor,'approval_notification_'||x.state,x.evidence)
 AND v.event_digest=digest(convert_to(jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'audit_id',x.aid,'correlation_id',x.cid,'actor_id',x.actor,'event_kind','approval_notification_'||x.state,'body',x.evidence)::text,'UTF8'),'sha256'))
 FROM expected x JOIN public.zasp_security_agent_audit v ON(v.organization_id,v.audit_id)=(x.organization_id,x.aid)`
	if err := f.owner.QueryRow(ctx, exactAudit, run, transition).Scan(&valid); err != nil || !valid {
		t.Fatal("settlement audit missing exact canonical scope, actor, receipt digest or outcome", err)
	}
	var count int
	if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM public.zasp_security_agent_audit WHERE run_id=$1 AND event_kind LIKE 'approval_notification_%'`, run).Scan(&count); err != nil || count != 1 {
		t.Fatal("settlement audit duplicated", err)
	}
}

// Corrupt evidence exists only inside a rollback-only negative transaction.
// It is never accepted as a receipt, committed, deleted or rewritten. The real
// stored captured attempt remains the sole authority for the settlement call.
func assertApprovalSettlementRefusalAtomicity(t *testing.T, ctx context.Context, f findingResponseFixture, r approvalmaintenance.Reservation, attempt approvalmaintenance.Attempt) {
	t.Helper()
	pin, err := migrations.ApprovalSettlementAuditProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	read := func() string {
		t.Helper()
		var snapshot string
		if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_array(to_jsonb(n),to_jsonb(a),(SELECT jsonb_agg(to_jsonb(v) ORDER BY audit_id) FROM public.zasp_security_agent_audit v WHERE(v.organization_id,v.run_id)=(n.organization_id,n.run_id)),(SELECT to_jsonb(v) FROM zasp_authorization79.organizations v WHERE v.organization_id=n.organization_id))::text FROM public.zasp_security_agent_approval_notifications n JOIN zasp_approval_maintenance.reservations a USING(organization_id,workspace_id,environment_id,delivery_id) WHERE(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,a.lease_token)=($1::jsonb->>'organization_id',$1::jsonb->>'workspace_id',$1::jsonb->>'environment_id',$1::jsonb->>'delivery_id',$1::jsonb->>'lease_token')`, r.Reference).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	before := read()
	for _, mode := range []string{"wrong-audit-pin", "foreign-scope", "audit-conflict"} {
		tx, err := f.owner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		if mode == "audit-conflict" {
			// Rollback-only security negative: exercise the original delivered
			// branch's revision touch, then force an audit conflict. No HTTP
			// success or delivery outcome is accepted or committed here.
			_, err = tx.Exec(ctx, `INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body)
 SELECT n.organization_id,n.workspace_id,n.environment_id,
 public.zasp_discovery_canonical_id(n.organization_id,n.workspace_id,n.environment_id,'approval_delivery_audit',n.delivery_id||chr(31)||r.attempt::text||chr(31)||r.kind||chr(31)||'delivered'),
 public.zasp_discovery_canonical_id(n.organization_id,n.workspace_id,n.environment_id,'approval_delivery_attempt',n.delivery_id||chr(31)||r.attempt::text||chr(31)||r.kind),n.run_id,a.step_id,n.approval_id,o.delegation->>'principal_id','approval_notification_delivered',decode(repeat('00',32),'hex'),'{}'::jsonb
 FROM public.zasp_security_agent_approval_notifications n JOIN zasp_approval_maintenance.reservations r USING(organization_id,workspace_id,environment_id,delivery_id)
 JOIN zasp_approval_maintenance.origins o USING(organization_id,workspace_id,environment_id,delivery_id)
 JOIN public.zasp_security_agent_approvals a ON(a.organization_id,a.workspace_id,a.environment_id,a.approval_id,a.run_id)=(n.organization_id,n.workspace_id,n.environment_id,n.approval_id,n.run_id)
 WHERE(n.organization_id,n.workspace_id,n.environment_id,n.delivery_id,r.lease_token)=($1::jsonb->>'organization_id',$1::jsonb->>'workspace_id',$1::jsonb->>'environment_id',$1::jsonb->>'delivery_id',$1::jsonb->>'lease_token')`, r.Reference)
			if err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("rollback-only audit conflict fixture refused", err)
			}
		}
		if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION approval_activation_delivery;SET LOCAL ROLE zasp_approval_maintenance_worker`); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("original registered native caller context refused", err)
		}
		q, auditPin := r.Reference, pin
		if mode == "wrong-audit-pin" {
			auditPin = hex.EncodeToString(make([]byte, 32))
		}
		if mode == "foreign-scope" {
			var fields map[string]any
			if json.Unmarshal([]byte(q), &fields) != nil {
				_ = tx.Rollback(ctx)
				t.Fatal("original reference invalid")
			}
			fields["workspace_id"] = f.next()
			raw, _ := json.Marshal(fields)
			q = string(raw)
		}
		var result json.RawMessage
		err = tx.QueryRow(ctx, `SELECT zasp_approval_settlement_v1.settle($1::jsonb,$2::json,$3,$4)`, q, json.RawMessage(attempt.CapturedProof), mode == "audit-conflict", auditPin).Scan(&result)
		var native *pgconn.PgError
		expected := "42501"
		if mode == "audit-conflict" {
			expected = "40001"
		}
		if mode == "foreign-scope" {
			expected = "P0002"
		}
		refused := errors.As(err, &native) && native.Code == expected
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if !refused {
			t.Fatal("audited settlement did not reject exact refusal case", mode, err)
		}
		if after := read(); after != before {
			t.Fatal("refused/conflicting audit mutated original attempt, revision or durable evidence", mode)
		}
	}
	// Confirm the negative fixture cannot alter either immutable predecessor.
	var ready bool
	if err := f.owner.QueryRow(ctx, `SELECT zasp_approval_settlement_v1.catalog_ready($1)`, pin).Scan(&ready); err != nil || !ready {
		t.Fatal("negative audit fixture changed catalog", err)
	}
}
