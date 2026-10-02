package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func exerciseGroupMappingReplacement(t *testing.T, ctx context.Context, owner, api *pgx.Conn, repo *PostgresRepository, scope domain.Scope, invoke func(string, string, int) *httptest.ResponseRecorder, freshAdmin func(), auditCount func() int, trace *mappingDeadlockTrace) {
	const group = "scim-group-test-mapping-regression"
	const member = "pid_6a000092-0000-4000-8000-000000000092"
	org, workspace, environment := scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($2,$1,'organization-mapping-regression','member-mapping-group-only','read_only_viewer')`, org, member)
	newGroupSession := func(wantWrite bool) (string, RequestIdentity) {
		t.Helper()
		var raw json.RawMessage
		if err := api.QueryRow(ctx, `SELECT zasp_identity_admin_resolve_session('organization-mapping-regression','member-mapping-group-only','["scim-group-test-mapping-regression"]')`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		permissions := []string{"view"}
		if wantWrite {
			permissions = append(permissions, "manage_workflows")
		}
		cookie, err := repo.CreateSession(ctx, SessionGrant{PrincipalID: integrationProductID(t, member), Scope: scope, Permissions: permissions, ExpiresAt: time.Now().UTC().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		identity, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: cookie})
		if err != nil || stringIn("manage_workflows", identity.Permissions...) != wantWrite {
			t.Fatalf("group-only effective permissions=%v wantWrite=%t err=%v", identity.Permissions, wantWrite, err)
		}
		return cookie, identity
	}
	oldGroupCookie, _ := newGroupSession(false)
	exec(`INSERT INTO zasp_product_api_tokens(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('mapping-pat-old','sha256'),$4,$1,$2,$3,'["view"]',clock_timestamp()+interval '1 hour')`, org, workspace, environment, member)
	freshAdmin()
	promoted := invoke(group, "security_engineer", 2)
	if promoted.Code != 200 || promoted.Header().Get("ETag") != `"3"` || auditCount() != 3 {
		t.Fatalf("successive update: %d %s", promoted.Code, promoted.Body)
	}
	var patRevoked bool
	if err := owner.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM zasp_product_api_tokens WHERE token_digest=digest('mapping-pat-old','sha256')`).Scan(&patRevoked); err != nil || !patRevoked {
		t.Fatalf("mapping update PAT revocation=%t err=%v", patRevoked, err)
	}
	if _, err := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: oldGroupCookie}); !errors.Is(err, ErrRepositoryAuthentication) {
		t.Fatalf("mapping update must revoke group session: %v", err)
	}
	groupCookie, groupIdentity := newGroupSession(true)
	t.Log("successive version2→3 update audited/revoked session+PAT; real resolve/CreateSession/Authenticate changes group-only effective manage_workflows from false to true")
	freshAdmin()
	for _, tc := range []struct {
		name            string
		version, status int
	}{{group, 2, 409}, {group, 0, 409}, {"scim-group-test-missing", 1, 404}, {"scim-group-test-foreign", 1, 404}} {
		w := invoke(tc.name, "read_only_viewer", tc.version)
		if w.Code != tc.status || auditCount() != 3 {
			t.Fatalf("denied update group=%s version=%d status=%d want%d body=%s", tc.name, tc.version, w.Code, tc.status, w.Body)
		}
	}
	t.Run("audit_failure_rolls_back_mapping_and_credentials", func(t *testing.T) {
		exec(`INSERT INTO zasp_product_api_tokens(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('mapping-pat-rollback','sha256'),$4,$1,$2,$3,'["view"]',clock_timestamp()+interval '1 hour')`, org, workspace, environment, member)
		w := connectorRejectionBlockedHTTP(t, ctx, owner, api, `LOCK TABLE zasp_admin_audit IN SHARE MODE`, nil, func(context.Context) *httptest.ResponseRecorder { return invoke(group, "read_only_viewer", 3) }, nil, true)
		var role string
		var version int
		var revoked bool
		if err := owner.QueryRow(ctx, `SELECT role,version FROM zasp_group_mappings WHERE organization_id=$1 AND group_reference=$2`, org, group).Scan(&role, &version); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM zasp_product_api_tokens WHERE token_digest=digest('mapping-pat-rollback','sha256')`).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		_, authErr := repo.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: groupCookie})
		if w.Code != 503 || role != "security_engineer" || version != 3 || auditCount() != 3 || revoked || authErr != nil {
			t.Fatalf("atomic rollback status=%d role=%s version=%d audit=%d PATrevoked=%t session=%v", w.Code, role, version, auditCount(), revoked, authErr)
		}
	})
	t.Run("registered_mapper_and_rejection_lock_order", func(t *testing.T) {
		call, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		cfg := api.Config().Copy()
		cfg.Tracer = trace
		auditConn, err := pgx.ConnectConfig(call, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer auditConn.Close(context.Background())
		locked, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		driver := &mappingPauseDriver{connectorRejectionPGDriver: connectorRejectionPGDriver{&integrationPostgresDriver{connection: auditConn}}, locked: locked, release: release}
		db, err := NewPostgresJSONDatabase(driver)
		if err != nil {
			t.Fatal(err)
		}
		auditRepo, err := NewPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		workflow, err := newWorkflowHTTPHandler(auditRepo, []byte(strings.Repeat("k", 32)), nil)
		if err != nil {
			t.Fatal(err)
		}
		router, err := NewComposition(Dependencies{Session: handlerResponse("s"), Identity: handlerResponse("i"), Inventory: handlerResponse("v"), Risk: handlerResponse("r"), Workflow: workflow, Connector: handlerResponse("c")})
		if err != nil {
			t.Fatal(err)
		}
		mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, Authenticate: auditRepo.Authenticate, GenerateCorrelationID: func() string { return "pid_8c000002-0000-4000-8000-000000000002" }}, router)
		if err != nil {
			t.Fatal(err)
		}
		auditDone, mapperDone := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
		auditJoined, mapperStarted, mapperJoined := false, false, false
		defer func() {
			unblock()
			cancel()
			if !auditJoined {
				select {
				case <-auditDone:
				case <-time.After(5 * time.Second):
					t.Error("audit goroutine failed join")
				}
			}
			if mapperStarted && !mapperJoined {
				select {
				case <-mapperDone:
				case <-time.After(5 * time.Second):
					t.Error("mapper goroutine failed join")
				}
			}
		}()
		go func() {
			r := httptest.NewRequest("POST", "/api/v1/integrations", strings.NewReader(`{"connector_key":"github","name":"rejected","configuration":{"provider_url":"https://invalid.test"}}`)).WithContext(call)
			r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: groupCookie})
			r.Header.Set(expectedScopeHeader, org+"/"+workspace+"/"+environment)
			r.Header.Set("Origin", "https://console.example.test")
			r.Header.Set("X-CSRF-Token", groupIdentity.CSRFToken)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "mapping-contention-rejection")
			w := httptest.NewRecorder()
			mounted.ServeHTTP(w, r)
			auditDone <- w
		}()
		select {
		case <-locked:
		case <-call.Done():
			t.Fatal("audit did not reach actual credential share lock")
		}
		mapperStarted = true
		go func() { mapperDone <- invoke(group, "read_only_viewer", 3) }()
		connectorRejectionAwaitBlocker(t, call, owner, api.PgConn().PID(), auditConn.PgConn().PID())
		t.Log("observed actual registered mapper backend blocked by rejection transaction after real credential share lock")
		unblock()
		var a, m *httptest.ResponseRecorder
		select {
		case a = <-auditDone:
			auditJoined = true
		case <-call.Done():
			t.Fatal("audit did not join")
		}
		select {
		case m = <-mapperDone:
			mapperJoined = true
		case <-call.Done():
			t.Fatal("mapper did not join")
		}
		deadlock := ""
		select {
		case deadlock = <-trace.codes:
		default:
		}
		if a.Code != 400 || m.Code != 200 || deadlock != "" {
			t.Fatalf("mapping/rejection lock order: rejectionHTTP=%d want400 mapperHTTP=%d want200 observed_SQLSTATE=%q (40P01 proves deadlock; other failure is not intended RED)", a.Code, m.Code, deadlock)
		}
	})
}

type mappingDeadlockTrace struct{ codes chan string }

func (tr *mappingDeadlockTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}
func (tr *mappingDeadlockTrace) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	var e *pgconn.PgError
	if errors.As(data.Err, &e) && e.Code == "40P01" {
		select {
		case tr.codes <- e.Code:
		default:
		}
	}
}

type mappingPauseDriver struct {
	connectorRejectionPGDriver
	locked  chan struct{}
	release <-chan struct{}
}

func (d *mappingPauseDriver) BeginReadCommitted(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.connectorRejectionPGDriver.BeginReadCommitted(ctx)
	if err != nil {
		return nil, err
	}
	return &mappingPauseTx{Tx: tx, ctx: ctx, locked: d.locked, release: d.release}, nil
}

type mappingPauseTx struct {
	pgx.Tx
	ctx     context.Context
	locked  chan struct{}
	release <-chan struct{}
}

func (tx *mappingPauseTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := tx.Tx.QueryRow(ctx, sql, args...)
	if strings.Contains(sql, "FROM public.zasp_product_sessions") && strings.HasSuffix(sql, " FOR SHARE") {
		return mappingPauseRow{Row: row, tx: tx}
	}
	return row
}

type mappingPauseRow struct {
	pgx.Row
	tx *mappingPauseTx
}

func (r mappingPauseRow) Scan(dest ...any) error {
	if err := r.Row.Scan(dest...); err != nil {
		return err
	}
	close(r.tx.locked)
	select {
	case <-r.tx.release:
		return nil
	case <-r.tx.ctx.Done():
		return r.tx.ctx.Err()
	}
}
