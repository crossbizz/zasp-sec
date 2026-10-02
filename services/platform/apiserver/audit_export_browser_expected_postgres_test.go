//go:build darwin || linux

package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

func auditBrowserMixedConnection(t *testing.T, ctx context.Context, f auditExportPG) *pgx.Conn {
	t.Helper()
	conn, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := conn.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	return conn
}

func auditBrowserMixedOracle(t *testing.T, ctx context.Context, conn *pgx.Conn, org string) *auditHTTPSizeExpected {
	t.Helper()
	e, err := newAuditBrowserMixedExpected(ctx, conn, org)
	if err != nil {
		t.Fatal("mixed original snapshot rejected actual producers", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	return e
}

func auditBrowserMixedBinaries(t *testing.T) {
	t.Helper()
	for _, binary := range []string{"initdb", "postgres", "pg_isready", "pg_ctl", "node"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatal("required owned-PG executable absent", binary)
		}
	}
}

// Catches losing any original producer family, changing public mapping, taking
// the snapshot at Reset, or changing byte order/accounting. These are repository
// and released SQL producer calls on owned PG, not native browser interactions.
func TestAuditHTTPSizeExpectedMixedActualProducersPostgres(t *testing.T) {
	auditBrowserMixedBinaries(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	f, retained := auditExportRetainedIdentityFixture(t, ctx)
	want := auditExportPublicPolicyMutations(t, ctx, f)
	want = append(want, auditExportPublicTestMutations(t, ctx, f)...)
	if len(retained) != 5 || len(want) != 11 {
		t.Fatal("actual producer fixture count", len(retained), len(want))
	}

	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: f.api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	args := f.createArgs()
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) SELECT organization_id,workspace_id,id,environment_class,'metadata_only',30,true FROM zasp_environments WHERE (organization_id,workspace_id,id)=($1,$2,$3) ON CONFLICT DO NOTHING`, args[:3]...); err != nil {
		t.Fatal(err)
	}
	var version int64
	var environmentClass string
	if err := f.admin.QueryRow(ctx, `SELECT version,environment_class FROM zasp_data_controls WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, args[:3]...).Scan(&version, &environmentClass); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.MutateAdministration(ctx, f.identity, administrationMutation{Operation: "updateDataControls", CollectionMode: "metadata_only", RetentionDays: 45, DeletionEnabled: true, ExpectedVersion: version, EnvironmentClass: environmentClass, AuditID: auditHTTPSizeTestID(9500)}); err != nil {
		t.Fatal("actual configuration producer", err)
	}

	// Remove expired owned receipts through their released cleanup operation.
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_workflow_receipts SET created_at=transaction_timestamp()-interval '8 days',expires_at=transaction_timestamp()-interval '1 day' WHERE resource_id='policy-public-history'`); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := f.admin.QueryRow(ctx, `SELECT zasp_workflow_receipt_cleanup(1000)`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	worker, _ := auditExportWorkerConnections(t, ctx, f)
	request, _ := auditExportClaimForCapture(t, ctx, f, worker, auditExportTestPolicy())
	for _, raw := range auditExportIdentitySource(t, ctx, f) {
		event, err := audit.DecodeExportEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, event)
	}
	if len(want) != 18 {
		t.Fatal("five identity, configuration, request, five policy and six test rows required", len(want))
	}
	conn := auditBrowserMixedConnection(t, ctx, f)
	e := auditBrowserMixedOracle(t, ctx, conn, args[0].(string))
	var isolation, readOnly string
	if err := conn.QueryRow(ctx, `SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')`).Scan(&isolation, &readOnly); err != nil || isolation != "repeatable read" || readOnly != "on" {
		t.Fatal("snapshot isolation", isolation, readOnly, err)
	}

	// Owner edits commit after construction, before the first cursor declaration.
	for _, statement := range []string{
		`UPDATE zasp_admin_audit SET target_id='changed' WHERE organization_id=$1`,
		`UPDATE zasp_workflow_audit SET resource_version=999 WHERE organization_id=$1`,
		`UPDATE zasp_red_team_audit SET event_digest=decode(repeat('ff',32),'hex') WHERE organization_id=$1`,
	} {
		if _, err := f.admin.Exec(ctx, statement, args[0]); err != nil {
			t.Fatal("later committed producer mutation", err)
		}
	}
	if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_workflow_audit WHERE organization_id=$1 AND operation='deletePolicy'`, args[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit SELECT organization_id,workspace_id,environment_id,$2,$3,principal_id,operation,resource_kind,'policy-later',1,clock_timestamp() FROM zasp_workflow_audit WHERE organization_id=$1 AND operation='createPolicy'`, args[0], auditHTTPSizeTestID(9600), auditHTTPSizeTestID(9601)); err != nil {
		t.Fatal(err)
	}
	binding := auditHTTPSizeTestBinding()
	binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, binding.ExportID = request[0].(string), request[1].(string), request[2].(string), request[7].(string)
	sort.Slice(want, func(i, j int) bool {
		if want[i].OccurredAt == want[j].OccurredAt {
			return want[i].ID > want[j].ID
		}
		return want[i].OccurredAt > want[j].OccurredAt
	})
	for i := range want {
		want[i].Ordinal = int64(i + 1)
	}
	// Use plain JSON and SHA-256 on independent raw-producer expectations. Do not
	// ask the mixed source, SQL export encoder, view, or returned chunks for wants.
	wantChunk, err := json.Marshal(audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: 1, FirstEvent: 1, EventCount: 18, PreviousDigest: audit.ExportZeroDigest, Events: want})
	if err != nil {
		t.Fatal(err)
	}
	chunkHash := sha256.Sum256(wantChunk)
	wantManifest, err := json.Marshal(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: 18, ChunkCount: 1, ChunkBytes: int64(len(wantChunk)), ChainRoot: hex.EncodeToString(chunkHash[:])})
	if err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		if err := e.Reset(ctx, binding); err != nil {
			t.Fatal(err)
		}
		requestCtx, stop := context.WithCancel(ctx)
		chunk, err := e.Next(requestCtx)
		stop()
		if err != nil || !bytes.Equal(chunk, wantChunk) {
			t.Fatalf("mixed canonical chunk differs, pass=%d: %v\ngot=%s\nwant=%s", pass, err, chunk, wantChunk)
		}
		if conn.PgConn().IsBusy() {
			t.Fatal("FETCH survived request")
		}
		if _, err := e.Next(ctx); !errors.Is(err, io.EOF) {
			t.Fatal("mixed source EOF", err)
		}
		manifest, summary, err := e.Manifest()
		hash := sha256.Sum256(wantManifest)
		if err != nil || !bytes.Equal(manifest, wantManifest) || summary != (auditHTTPSizeSummary{Events: 18, Chunks: 1, ChunkBytes: int64(len(wantChunk)), ChainRoot: hex.EncodeToString(chunkHash[:]), ManifestSHA256: hex.EncodeToString(hash[:])}) {
			t.Fatal("mixed manifest/accounting", summary, err)
		}
	}
	auditBrowserMixedBindings(t, ctx, f, request, e)
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var one int
	if conn.PgConn().TxStatus() != 'I' || conn.QueryRow(ctx, `SELECT 1`).Scan(&one) != nil || one != 1 {
		t.Fatal("borrowed snapshot connection not reusable")
	}
}

// A forged snapshot interface cannot obtain DB-backed provider authority, even
// if it points to an open actual connection owned by this fixture.
type auditBrowserForgedSnapshot struct {
	auditHTTPSizeGeneratedSource
	conn *pgx.Conn
}

func (s *auditBrowserForgedSnapshot) snapshotConnection() *pgx.Conn { return s.conn }
func (s *auditBrowserForgedSnapshot) snapshotCount() int64          { return 0 }

func auditBrowserMixedBindings(t *testing.T, ctx context.Context, f auditExportPG, args []any, e *auditHTTPSizeExpected) {
	t.Helper()
	conn := e.source.(auditHTTPSizeSnapshotSource).snapshotConnection()
	observer := auditBrowserMixedConnection(t, ctx, f)
	bind := func(t *testing.T, observer *pgx.Conn, candidate *auditHTTPSizeExpected, accepted bool) {
		t.Helper()
		p, err := newAuditHTTPSizeProvider(ctx, observer, auditExportTestPolicy())
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := p.Close(cleanup); err != nil {
				t.Error(err)
			}
		}()
		if err := p.Bind(args, candidate); (err == nil) != accepted {
			t.Fatal("mixed provider binding acceptance", accepted, err)
		}
	}
	t.Run("bind-distinct-mixed-snapshot", func(t *testing.T) { bind(t, observer, e, true) })
	t.Run("bind-same-connection", func(t *testing.T) { bind(t, conn, e, false) })
	for _, tc := range []struct {
		name   string
		source auditHTTPSizeSource
	}{
		{"nil-source", nil},
		{"nil-pg", (*auditHTTPSizePGSource)(nil)},
		{"nil-mixed", (*auditBrowserMixedSource)(nil)},
		{"unbacked-pg", &auditHTTPSizePGSource{organization: e.organization}},
		{"unbacked-mixed", &auditBrowserMixedSource{organization: e.organization}},
		{"generated", &auditHTTPSizeGeneratedSource{}},
		{"forged-snapshot", &auditBrowserForgedSnapshot{conn: conn}},
	} {
		t.Run("bind-"+tc.name, func(t *testing.T) {
			bind(t, observer, &auditHTTPSizeExpected{source: tc.source, organization: e.organization}, false)
		})
	}
	t.Run("bind-closed-oracle", func(t *testing.T) {
		closed := *e
		closed.closed = true
		bind(t, observer, &closed, false)
	})
	t.Run("bind-wrong-organization", func(t *testing.T) {
		foreign := *e
		foreign.organization = auditHTTPSizeTestID(9999)
		bind(t, observer, &foreign, false)
	})
	t.Run("bind-ended-transaction", func(t *testing.T) {
		ended := auditBrowserMixedOracle(t, ctx, auditBrowserMixedConnection(t, ctx, f), e.organization)
		if err := ended.Close(ctx); err != nil {
			t.Fatal(err)
		}
		// Even forgetting the outer lifetime flag must not authorize an idle conn.
		candidate := *ended
		candidate.closed = false
		bind(t, observer, &candidate, false)
	})
	t.Run("bind-closed-connection", func(t *testing.T) {
		closedConn := auditBrowserMixedConnection(t, ctx, f)
		ended := auditBrowserMixedOracle(t, ctx, closedConn, e.organization)
		if err := ended.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if err := closedConn.Close(ctx); err != nil {
			t.Fatal(err)
		}
		candidate := *ended
		candidate.closed = false
		bind(t, observer, &candidate, false)
	})
}

// Catches duplicate IDs across producer families even with different timestamps.
// This is the same-organization rule; the scoped test below has foreign twins.
func TestAuditHTTPSizeExpectedMixedDuplicatePostgres(t *testing.T) {
	auditBrowserMixedBinaries(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	args := f.createArgs()
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,$4,$5,'policy.create','policy-owned','succeeded','{}','2026-01-01Z')`, args[0], args[1], args[2], auditHTTPSizeTestID(9700), args[3]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version,created_at) VALUES($1,$2,$3,$4,$5,$6,'createPolicy','policy','policy-owned',1,'2026-01-02Z')`, args[0], args[1], args[2], auditHTTPSizeTestID(9700), auditHTTPSizeTestID(9701), args[3]); err != nil {
		t.Fatal(err)
	}
	conn := auditBrowserMixedConnection(t, ctx, f)
	for _, stamp := range []string{"2026-01-02Z", "2026-01-01Z"} {
		if _, err := f.admin.Exec(ctx, `UPDATE zasp_workflow_audit SET created_at=$1`, stamp); err != nil {
			t.Fatal(err)
		}
		e, err := newAuditBrowserMixedExpected(ctx, conn, args[0].(string))
		if e != nil {
			_ = e.Close(ctx)
		}
		if err == nil || e != nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatal("same-org duplicate ID accepted", stamp, err)
		}
		var one int
		if conn.PgConn().TxStatus() != 'I' || conn.QueryRow(ctx, `SELECT 1`).Scan(&one) != nil || one != 1 {
			t.Fatal("duplicate rejection leaked borrowed transaction")
		}
	}
}

// Catches workspace narrowing, foreign collision leakage, wrong C-ID tie order,
// request-context retention, and count mismatch escaping through mixed sources.
func TestAuditHTTPSizeExpectedMixedScopeLifetimePostgres(t *testing.T) {
	auditBrowserMixedBinaries(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	args := f.createArgs()
	binding := auditHTTPSizeTestBinding()
	binding.OrganizationID = args[0].(string)
	// 1100 same-time policy rows span two source workspaces. No raw body is used.
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version,created_at)
 SELECT $1,CASE WHEN n%2=0 THEN $2 ELSE $3 END,$4,'pid_'||lpad(to_hex(4001-n),8,'0')||'-0000-4000-8000-000000000001','pid_'||lpad(to_hex(6001-n),8,'0')||'-0000-4000-8000-000000000001',$5,'updatePolicy','policy','policy-scoped',n,'2026-09-12T13:14:15.000123Z' FROM generate_series(1,1100)n`, args[0], binding.WorkspaceID, auditHTTPSizeTestID(9900), binding.EnvironmentID, args[3]); err != nil {
		t.Fatal(err)
	}
	// Noneligible malformed workflow records do not become policy history.
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit SELECT organization_id,workspace_id,environment_id,$2,$3,principal_id,'notASelectedPolicyOperation','wrong','bad',0,created_at FROM zasp_workflow_audit WHERE organization_id=$1 LIMIT 1`, args[0], auditHTTPSizeTestID(9901), auditHTTPSizeTestID(9902)); err != nil {
		t.Fatal(err)
	}
	// Foreign records collide with a scoped ID and have newer timestamps.
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit SELECT $2,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version,'2027-01-01Z' FROM zasp_workflow_audit WHERE organization_id=$1`, args[0], auditHTTPSizeTestID(9903)); err != nil {
		t.Fatal(err)
	}
	conn := auditBrowserMixedConnection(t, ctx, f)
	e := auditBrowserMixedOracle(t, ctx, conn, args[0].(string))
	source := e.source.(*auditBrowserMixedSource)
	if source.snapshotCount() != 1100 {
		t.Fatal("eligible original count", source.snapshotCount())
	}
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal(err)
	}
	previous := audit.ExportZeroDigest
	var total int64
	var firstHash [32]byte
	for index, count := range []int{1000, 100} {
		request, stop := context.WithCancel(ctx)
		body, err := e.Next(request)
		stop()
		if err != nil {
			t.Fatal("fresh mixed request", index, err)
		}
		if conn.PgConn().IsBusy() {
			t.Fatal("completed mixed request retained FETCH")
		}
		want := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: int64(index + 1), FirstEvent: int64(index*1000 + 1), EventCount: int64(count), PreviousDigest: previous, Events: []audit.ExportEvent{}}
		for n := index*1000 + 1; n <= index*1000+count; n++ {
			workspace := binding.WorkspaceID
			if n%2 != 0 {
				workspace = auditHTTPSizeTestID(9900)
			}
			want.Events = append(want.Events, audit.ExportEvent{Ordinal: int64(n), ID: auditHTTPSizeTestID(4001 - n), OrganizationID: binding.OrganizationID, WorkspaceID: workspace, EnvironmentID: binding.EnvironmentID, ActorID: args[3].(string), Action: "policy.update", TargetID: "policy-scoped", Outcome: "succeeded", OccurredAt: "2026-09-12T13:14:15.000123Z", Metadata: map[string]string{"source": "workflow_policy", "source_operation": "updatePolicy", "correlation_id": auditHTTPSizeTestID(6001 - n), "resource_version": fmt.Sprint(n)}})
		}
		canonical, marshalErr := json.Marshal(want)
		if marshalErr != nil || !bytes.Equal(body, canonical) {
			t.Fatal("scoped canonical chunk mismatch", index, marshalErr)
		}
		sum := sha256.Sum256(canonical)
		if index == 0 {
			firstHash = sum
			if e.lookahead == nil || e.read != 1001 {
				t.Fatal("mixed lookahead was not bounded", e.read)
			}
		}
		previous = hex.EncodeToString(sum[:])
		total += int64(len(canonical))
	}
	if _, err := e.Next(ctx); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	manifest, summary, err := e.Manifest()
	wantManifest, marshalErr := json.Marshal(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: 1100, ChunkCount: 2, ChunkBytes: total, ChainRoot: previous})
	if err != nil || marshalErr != nil || !bytes.Equal(manifest, wantManifest) || summary.Events != 1100 {
		t.Fatal("scope manifest", err, marshalErr)
	}
	t.Run("count-mismatch", func(t *testing.T) {
		source.count++
		defer func() { source.count-- }()
		if err := e.Reset(ctx, binding); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Next(ctx); err != nil {
			t.Fatal(err)
		}
		body, err := e.Next(ctx)
		if body != nil || err == nil || !strings.Contains(err.Error(), "count mismatch") {
			t.Fatal("mixed snapshot count mismatch accepted", err)
		}
		if _, _, err := e.Manifest(); err == nil {
			t.Fatal("count mismatch earned manifest")
		}
	})
	t.Run("cancel-during-next", func(t *testing.T) {
		if err := e.Reset(ctx, binding); err != nil {
			t.Fatal(err)
		}
		request, stop := context.WithCancel(ctx)
		defer stop()
		e.source = &auditHTTPSizeCancelAfterRow{auditHTTPSizeSource: source, cancel: stop}
		body, err := e.Next(request)
		e.source = source
		if body != nil || !errors.Is(err, context.Canceled) || e.summary.Chunks != 0 {
			t.Fatal("canceled mixed FETCH earned chunk", err)
		}
		if conn.PgConn().IsBusy() {
			t.Fatal("canceled request retained FETCH")
		}
		if _, _, err := e.Manifest(); err == nil {
			t.Fatal("cancellation earned manifest")
		}
		if _, err := e.Next(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation not sticky", err)
		}
	})
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal(err)
	}
	body, err := e.Next(ctx)
	if err != nil || sha256.Sum256(body) != firstHash {
		t.Fatal("reset after cancellation changed source", err)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var cursors int
	if conn.PgConn().TxStatus() != 'I' || conn.PgConn().IsBusy() || conn.QueryRow(ctx, `SELECT count(*) FROM pg_cursors WHERE name='audit_browser_mixed_original'`).Scan(&cursors) != nil || cursors != 0 {
		t.Fatal("close with lookahead leaked cursor/transaction")
	}
}

// A malformed row with an eligible operation must still count, then fail its
// traversal. Filtering validity in SQL would turn every case into an empty pass.
func TestAuditHTTPSizeExpectedMixedMalformedPostgres(t *testing.T) {
	auditBrowserMixedBinaries(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	args := f.createArgs()
	conn := auditBrowserMixedConnection(t, ctx, f)
	binding := auditHTTPSizeTestBinding()
	binding.OrganizationID = args[0].(string)
	for _, tc := range []struct {
		name, kind, target, correlation string
		version                         int64
	}{
		{"resource-kind", "integration", "policy-owned", auditHTTPSizeTestID(9802), 1},
		{"policy-id", "policy", "bad", auditHTTPSizeTestID(9802), 1},
		{"zero-version", "policy", "policy-owned", auditHTTPSizeTestID(9802), 0},
		{"negative-version", "policy", "policy-owned", auditHTTPSizeTestID(9802), -1},
		{"correlation", "policy", "policy-owned", "bad", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version) VALUES($1,$2,$3,$4,$5,$6,'createPolicy',$7,$8,$9) ON CONFLICT (organization_id,audit_id) DO UPDATE SET correlation_id=EXCLUDED.correlation_id,resource_kind=EXCLUDED.resource_kind,resource_id=EXCLUDED.resource_id,resource_version=EXCLUDED.resource_version`, args[0], args[1], args[2], auditHTTPSizeTestID(9801), tc.correlation, args[3], tc.kind, tc.target, tc.version); err != nil {
				t.Fatal(err)
			}
			e := auditBrowserMixedOracle(t, ctx, conn, binding.OrganizationID)
			if e.source.(auditHTTPSizeSnapshotSource).snapshotCount() != 1 {
				t.Fatal("malformed eligible source omitted from count")
			}
			if err := e.Reset(ctx, binding); err != nil {
				t.Fatal(err)
			}
			if body, err := e.Next(ctx); err == nil || body != nil {
				t.Fatal("malformed eligible source accepted", err)
			}
			if _, _, err := e.Manifest(); err == nil {
				t.Fatal("malformed eligible source earned manifest")
			}
			if err := e.Close(ctx); err != nil {
				t.Fatal(err)
			}
			var one int
			if conn.PgConn().TxStatus() != 'I' || conn.PgConn().IsBusy() || conn.QueryRow(ctx, `SELECT 1`).Scan(&one) != nil || one != 1 {
				t.Fatal("malformed scan leaked rows/transaction")
			}
		})
	}
	t.Run("constructor-inputs", func(t *testing.T) {
		for _, org := range []string{"", "bad"} {
			e, err := newAuditBrowserMixedExpected(ctx, conn, org)
			if e != nil || err == nil || conn.PgConn().TxStatus() != 'I' {
				t.Fatal("invalid organization borrowed transaction", err)
			}
		}
		if e, err := newAuditBrowserMixedExpected(ctx, nil, binding.OrganizationID); e != nil || err == nil {
			t.Fatal("nil connection accepted", err)
		}
		closed := auditBrowserMixedConnection(t, ctx, f)
		if err := closed.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if e, err := newAuditBrowserMixedExpected(ctx, closed, binding.OrganizationID); e != nil || err == nil {
			t.Fatal("closed connection accepted", err)
		}
	})
}

// All three raw families follow organization scope, not the export workspace.
// Foreign ID twins must neither leak nor trigger the same-org duplicate guard.
func TestAuditHTTPSizeExpectedMixedFamiliesScopePostgres(t *testing.T) {
	auditBrowserMixedBinaries(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	args := f.createArgs()
	binding := auditHTTPSizeTestBinding()
	binding.OrganizationID = args[0].(string)
	workspace, environment := auditHTTPSizeTestID(9850), auditHTTPSizeTestID(9851)
	base := []any{args[0], workspace, environment, args[3]}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,actor_id,id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,$4,$5,'policy.update','retained-admin','rejected','{"verified":true}','2026-09-12T13:14:15.000123Z')`, append(base, auditHTTPSizeTestID(9854))...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,principal_id,audit_id,correlation_id,operation,resource_kind,resource_id,resource_version,created_at) VALUES($1,$2,$3,$4,$5,$6,'createPolicy','policy','policy-retained',7,'2026-09-12T13:14:15.000123Z')`, append(base, auditHTTPSizeTestID(9853), auditHTTPSizeTestID(9855))...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_red_team_audit(organization_id,workspace_id,environment_id,actor_id,audit_id,correlation_id,receipt_id,resource_id,event_kind,event_digest,body,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'red_team_definition_created',decode(repeat('ab',32),'hex'),'{"private":"not-read"}','2026-09-12T13:14:15.000123Z')`, append(base, auditHTTPSizeTestID(9852), auditHTTPSizeTestID(9856), auditHTTPSizeTestID(9857), auditHTTPSizeTestID(9858))...); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO zasp_admin_audit SELECT $2,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,'2027-01-01Z' FROM zasp_admin_audit WHERE organization_id=$1`,
		`INSERT INTO zasp_workflow_audit SELECT $2,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version,'2027-01-01Z' FROM zasp_workflow_audit WHERE organization_id=$1`,
		`INSERT INTO zasp_red_team_audit SELECT $2,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body,'2027-01-01Z' FROM zasp_red_team_audit WHERE organization_id=$1`,
	} {
		if _, err := f.admin.Exec(ctx, statement, args[0], auditHTTPSizeTestID(9859)); err != nil {
			t.Fatal(err)
		}
	}
	// Current producers forbid other Red Team kinds. Remove only that check in
	// this owned throwaway fixture to prove the fixed selector excludes one.
	var constraint string
	if err := f.admin.QueryRow(ctx, `SELECT conname FROM pg_constraint WHERE conrelid='zasp_red_team_audit'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%event_kind%'`).Scan(&constraint); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, "ALTER TABLE zasp_red_team_audit DROP CONSTRAINT "+pgx.Identifier{constraint}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_red_team_audit SELECT organization_id,workspace_id,environment_id,$2,correlation_id,$3,actor_id,'unselected_kind',resource_id,event_digest,body,created_at FROM zasp_red_team_audit WHERE organization_id=$1`, args[0], auditHTTPSizeTestID(9860), auditHTTPSizeTestID(9861)); err != nil {
		t.Fatal(err)
	}
	e := auditBrowserMixedOracle(t, ctx, auditBrowserMixedConnection(t, ctx, f), binding.OrganizationID)
	if e.source.(auditHTTPSizeSnapshotSource).snapshotCount() != 3 {
		t.Fatal("family scope/eligibility count")
	}
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal(err)
	}
	body, err := e.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	events := []audit.ExportEvent{
		{ID: auditHTTPSizeTestID(9854), Action: "policy.update", TargetID: "retained-admin", Outcome: "denied", Metadata: map[string]string{"verified": "true"}},
		{ID: auditHTTPSizeTestID(9853), Action: "policy.create", TargetID: "policy-retained", Outcome: "succeeded", Metadata: map[string]string{"source": "workflow_policy", "source_operation": "createPolicy", "correlation_id": auditHTTPSizeTestID(9855), "resource_version": "7"}},
		{ID: auditHTTPSizeTestID(9852), Action: "test.create", TargetID: auditHTTPSizeTestID(9858), Outcome: "succeeded", Metadata: map[string]string{"source": "red_team_mutation", "source_event_kind": "red_team_definition_created", "correlation_id": auditHTTPSizeTestID(9856), "receipt_id": auditHTTPSizeTestID(9857), "event_sha256": strings.Repeat("ab", 32)}},
	}
	for i := range events {
		events[i].Ordinal = int64(i + 1)
		events[i].OrganizationID, events[i].WorkspaceID, events[i].EnvironmentID = binding.OrganizationID, workspace, environment
		events[i].ActorID, events[i].OccurredAt = args[3].(string), "2026-09-12T13:14:15.000123Z"
	}
	want, marshalErr := json.Marshal(audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: 1, FirstEvent: 1, EventCount: 3, PreviousDigest: audit.ExportZeroDigest, Events: events})
	if marshalErr != nil || !bytes.Equal(body, want) {
		t.Fatal("mixed families lost stored workspace/order", marshalErr)
	}
	if _, err := e.Next(ctx); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}
