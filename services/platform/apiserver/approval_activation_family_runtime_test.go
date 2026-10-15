package apiserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/approvalmaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenancecutover"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// A shared owned application harness; producers must supply genuine original
// native admissions. It cannot manufacture an origin, delegation or task.
// Independent deployed identity/provider/fleet evidence remains required.
type approvalActivationFamilyRuntime struct {
	t                                        *testing.T
	ctx                                      context.Context
	owner                                    *pgx.Conn
	o, w, e, actor, outbox, originalRole     string
	owned                                    *connectorLifecycleFGA
	pins                                     runtimeservices.Config
	checker                                  authorization.Checker
	writer                                   authorization.TupleWriter
	poolFor                                  func(string) *pgxpool.Pool
	projection                               authorization.ProjectionRepository
	approvalPin, connectorPin, activationPin string
	key                                      []byte
	active                                   bool
}

func newApprovalActivationFamilyRuntime(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, actor string, owned *connectorLifecycleFGA, pins runtimeservices.Config) *approvalActivationFamilyRuntime {
	f := &approvalActivationFamilyRuntime{t: t, ctx: ctx, owner: owner, o: o, w: w, e: e, actor: actor, owned: owned, approvalPin: migrations.ApprovalMaintenanceProfileChecksum()}
	runner := workerMigrationRunner(t, owner)
	for _, up := range []func(context.Context) error{runner.UpProductionApprovalMaintenanceProfile, runner.UpProductionConnectorMaintenance, runner.UpProductionApprovalActivationProfile, runner.UpProductionApprovalSettlementAuditProfile} {
		if err := up(ctx); err != nil {
			t.Fatal("native family maintenance composition refused", err)
		}
	}
	var err error
	f.connectorPin, err = migrations.ConnectorMaintenanceProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	f.activationPin, err = migrations.ApprovalActivationProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM public.zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&f.outbox); err != nil {
		t.Fatal("actual family projection principal unavailable", err)
	}
	if err := owner.QueryRow(ctx, `SELECT role FROM public.zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2 AND active`, o, actor).Scan(&f.originalRole); err != nil {
		t.Fatal("actual native grantor unavailable", err)
	}
	f.poolFor = func(login string) *pgxpool.Pool {
		t.Helper()
		cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User, cfg.MaxConns = login, 2
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	if pins.StoreID == "" && pins.ModelID == "" {
		client, actual := newApprovalMaintenanceOwnedFGA(t)
		pins = actual
		f.checker, err = authorization.NewOpenFGA(client, pins)
		if err != nil {
			t.Fatal(err)
		}
		f.writer, err = authorization.NewOpenFGATupleWriter(client, pins)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		client, actual := connectorLifecycleOfficialClient(t, owned, pins.StoreID, pins.ModelID)
		pins = actual
		f.checker, err = authorization.NewOpenFGA(client, pins)
		if err != nil {
			t.Fatal(err)
		}
		f.writer, err = authorization.NewOpenFGATupleWriter(client, pins)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.pins = pins
	f.projection, err = authorization.NewPostgresProjectionRepository(f.poolFor(f.outbox))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, o, pins.StoreID, pins.ModelID); err != nil {
		t.Fatal("native family store/model configuration refused", err)
	}
	if _, err := owner.Exec(ctx, `CREATE ROLE approval_family_delivery LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;GRANT zasp_approval_maintenance_worker TO approval_family_delivery`); err != nil {
		t.Fatal("dedicated native family worker login unavailable", err)
	}
	var af, ac, cf, cc [32]byte
	for _, v := range []*[32]byte{&af, &ac, &cf, &cc} {
		if _, err := rand.Read(v[:]); err != nil {
			t.Fatal(err)
		}
		defer clear(v[:])
	}
	f.key = bytes.Clone(af[:])
	t.Cleanup(func() { clear(f.key) })
	for _, v := range []struct {
		purpose string
		key     []byte
	}{{"approval-forward", af[:]}, {"approval-captured", ac[:]}} {
		version := sha256.Sum256(v.key)
		if _, err := owner.Exec(ctx, `SELECT zasp_approval_maintenance.register_verifier($1,$2,$3)`, v.purpose, hex.EncodeToString(version[:]), v.key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(ctx, `SELECT zasp_approval_maintenance.register_principal('approval_family_delivery')`); err != nil {
		t.Fatal(err)
	}
	fv, cv := sha256.Sum256(cf[:]), sha256.Sum256(cc[:])
	if _, err := owner.Exec(ctx, `SELECT zasp_connector_maintenance.register_principal($1,$2,$3,$4,$5)`, f.outbox, hex.EncodeToString(fv[:]), hex.EncodeToString(cv[:]), cf[:], cc[:]); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *approvalActivationFamilyRuntime) Reconcile() {
	f.t.Helper()
	receipt, err := authorization.Reconcile(f.ctx, f.projection, f.writer, f.o, f.pins.StoreID, f.pins.ModelID)
	if err != nil || !receipt.Applied {
		f.t.Fatal("native full family projection acknowledgement refused", err)
	}
}
func (f *approvalActivationFamilyRuntime) Activate() {
	f.t.Helper()
	f.Reconcile()
	cutover, closeCutover, err := connectormaintenancecutover.NewCombinedControlled(connectormaintenancecutover.Config{Endpoint: f.owned.endpoint, StoreID: f.pins.StoreID, ModelID: f.pins.ModelID, OldTokenFile: f.owned.oldFile, NewTokenFile: f.owned.newFile, ProfileChecksum: f.connectorPin, ApprovalProfileChecksum: f.approvalPin, OperatorPool: f.poolFor(f.owner.Config().User)}, f.activationPin)
	if err != nil {
		f.t.Fatal(err)
	}
	defer closeCutover()
	pid, stop := startApprovalActivationWriter(f.t, f.owner.Config().ConnString(), f.outbox, f.owned, f.pins, f.o)
	permit, err := cutover.Prepare(f.ctx, f.o, pid)
	if err != nil {
		f.t.Log("connector cutover prepare stage=" + connectormaintenancecutover.PrepareRefusalStage(err))
		f.t.Fatal("actual old family writer observation refused")
	}
	stop()
	f.owned.withdrawOld(f.t)
	if err := cutover.Activate(f.ctx, permit); err != nil {
		f.t.Log("connector cutover activation stage=" + connectormaintenancecutover.ActivationRefusalStage(err))
		f.t.Fatal("actual combined family activation refused")
	}
	f.projection, err = authorization.NewCurrentMaintenanceProjectionRepository(f.ctx, f.poolFor(f.outbox), f.approvalPin, f.connectorPin)
	if err != nil {
		f.t.Fatal(err)
	}
	f.active = true
	f.Reconcile()
}
func (f *approvalActivationFamilyRuntime) AssertCapture(run, family, state string) {
	f.t.Helper()
	var valid bool
	if err := f.owner.QueryRow(f.ctx, `SELECT count(*)=1 AND bool_and(x.family=$2 AND x.status=$3 AND x.delegation IS NOT NULL AND x.delegation->>'purpose'='approval_notification_delivery' AND x.delegation->>'grantor_id'=$4 AND x.source_digest=x.facts->>'source_digest' AND x.payload_digest=n.payload_digest AND x.run_id=n.run_id AND jsonb_array_length(x.facts->'checks') BETWEEN 2 AND 128) FROM zasp_approval_maintenance.origins x JOIN public.zasp_security_agent_approval_notifications n USING(organization_id,workspace_id,environment_id,delivery_id) WHERE x.run_id=$1`, run, family, state, f.actor).Scan(&valid); err != nil || !valid {
		f.t.Fatal("genuine full family capture unavailable", err)
	}
}
func (f *approvalActivationFamilyRuntime) Deliver(run, family string) { f.deliver(run, family, false) }
func (f *approvalActivationFamilyRuntime) DeliverWithRevocation(run, family string) {
	f.deliver(run, family, true)
}
func (f *approvalActivationFamilyRuntime) deliver(run, family string, revoke bool) {
	t, ctx := f.t, f.ctx
	t.Helper()
	if !f.active {
		t.Fatal("family delivery requires real measured activation")
	}
	f.AssertCapture(run, family, "active")
	native, err := approvalmaintenance.NewActivatedExecutor(ctx, f.poolFor("approval_family_delivery"), f.checker, f.pins.StoreID, f.pins.ModelID, f.approvalPin, f.key, f.activationPin)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	token := func() (string, error) {
		var v [32]byte
		_, err := rand.Read(v[:])
		return hex.EncodeToString(v[:]), err
	}
	adapter := approvalmaintenance.NativeAdapter{Caller: native, Owner: "owned-approval-family", LeaseSeconds: 60, Token: token}
	r, found, err := adapter.Reserve(ctx)
	if err != nil || !found {
		t.Fatal("genuine family reservation refused", err)
	}
	payload, err := native.LoadDelivery(ctx, r)
	if err != nil || payload.RunID != run {
		t.Fatal("genuine family live payload unavailable", err)
	}
	if err := adapter.ReleaseUnattempted(ctx, r); err != nil {
		t.Fatal(err)
	}
	webhook, calls := maintenanceOrderOwnedWebhook(t, payload, http.StatusNoContent, "")
	secrets := &findingTicketSecretResolverStub{material: bytes.Repeat([]byte{0xa5}, 32)}
	setRole := func(role string) {
		t.Helper()
		tag, err := f.owner.Exec(ctx, `UPDATE public.zasp_identity_memberships SET role=$3 WHERE organization_id=$1 AND principal_id=$2 AND active`, f.o, f.actor, role)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("actual grantor permission transition unavailable", err)
		}
		f.Reconcile()
	}
	var transport ApprovalNotificationWebhook = webhook
	if revoke {
		transport = approvalActivationAfterWebhook{webhook, func() { setRole("read_only_viewer"); f.assertGrantorDeniedServiceAllowed(run) }}
	}
	reconciler, err := NewAuthorizedApprovalNotificationReconciler(ctx, AuthorizedApprovalNotificationConfig{Native: native, Secrets: secrets, Webhook: transport, Owner: adapter.Owner, LeaseSeconds: 60, NewLeaseToken: token})
	if err != nil {
		t.Fatal(err)
	}
	if revoke {
		setRole("read_only_viewer")
		f.assertGrantorDeniedServiceAllowed(run)
		if err := reconciler.ReconcileOnce(ctx); !errors.Is(err, approvalmaintenance.ErrDenied) {
			t.Fatal("family fresh permission revocation did not deny", err)
		}
		var unchanged bool
		if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2 AND active AND role='read_only_viewer') AND EXISTS(SELECT 1 FROM zasp_approval_maintenance.origins o JOIN public.zasp_security_agent_approval_notifications n USING(organization_id,workspace_id,environment_id,delivery_id) WHERE n.run_id=$3 AND o.status='paused_denied' AND n.attempt=0 AND n.completed_at IS NULL) AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE run_id=$3 AND event_kind LIKE 'approval_notification_%')`, f.o, f.actor, run).Scan(&unchanged); err != nil || !unchanged || calls.Load() != 0 || secrets.calls != 0 {
			t.Fatal("revoked family reached secret, HTTP, attempt or completion audit", err)
		}
		setRole(f.originalRole)
	}
	if err := reconciler.ReconcileOnce(ctx); err != nil || calls.Load() != 1 || secrets.calls != 1 {
		t.Fatal("actual signed family delivery/captured settlement refused", err)
	}
	assertApprovalActivationSettlementAudit(t, ctx, findingResponseFixture{owner: f.owner}, run, "delivered")
	if err := reconciler.ReconcileOnce(ctx); err != nil || calls.Load() != 1 {
		t.Fatal("settled family notification resent", err)
	}
	if revoke {
		var retained bool
		if err := f.owner.QueryRow(ctx, `SELECT active AND role='read_only_viewer' FROM public.zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2`, f.o, f.actor).Scan(&retained); err != nil || !retained {
			t.Fatal("captured successful settlement required restored permission", err)
		}
		setRole(f.originalRole)
	} else {
		f.Reconcile()
	}
}

func (f *approvalActivationFamilyRuntime) assertGrantorDeniedServiceAllowed(run string) {
	f.t.Helper()
	var definition, service, task string
	if err := f.owner.QueryRow(f.ctx, `SELECT facts->>'definition_id',delegation->>'principal_id',delegation->>'task_id' FROM zasp_approval_maintenance.origins WHERE run_id=$1`, run).Scan(&definition, &service, &task); err != nil {
		f.t.Fatal(err)
	}
	for _, principal := range []struct {
		kind, id, task string
		allowed        bool
	}{{"user", f.actor, "", false}, {"service", service, task, true}} {
		decision, err := f.checker.Check(f.ctx, authorization.CheckRequest{PrincipalKind: principal.kind, PrincipalID: principal.id, TaskID: principal.task, OrganizationID: f.o, WorkspaceID: f.w, EnvironmentID: f.e, ResourceType: "security_agent", ResourceID: definition, Permission: "manage_workflows"})
		if err != nil || decision.Allowed != principal.allowed || decision.ModelID != f.pins.ModelID {
			f.t.Fatal("actual family grantor permission was not withdrawn independently of native service delegation", err)
		}
	}
}

type approvalActivationAfterWebhook struct {
	native ApprovalNotificationWebhook
	after  func()
}

func (w approvalActivationAfterWebhook) DeliverApprovalNotification(ctx context.Context, destination, payload, digest, id string, key []byte) error {
	if err := w.native.DeliverApprovalNotification(ctx, destination, payload, digest, id, key); err != nil {
		return err
	}
	w.after()
	return nil
}
