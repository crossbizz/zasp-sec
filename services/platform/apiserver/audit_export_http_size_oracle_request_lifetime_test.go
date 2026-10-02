package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

// A partially consumed FETCH must not borrow the previous request's context.
// Expected bytes come from literal original fields, never the PG source adapter.
func TestAuditHTTPSizeOracleRequestLifetimePostgres(t *testing.T) {
	for _, binary := range []string{"initdb", "postgres", "pg_isready", "pg_ctl", "node"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Fatal("required owned-PG fixture executable absent", binary)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	binding := auditHTTPSizeTestBinding()
	binding.OrganizationID = f.createArgs()[0].(string)
	_, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at)
 SELECT $1,$2,$3,'pid_'||lpad(to_hex(2001-n),8,'0')||'-0000-4000-8000-000000000001',$4,'policy.update','original','rejected',
 '{"counter":9007199254740993,"verified":true,"token":"owned-secret-never-exported","quote":"<>&\"\\ café\u2028\u2029"}'::jsonb,
 '2026-09-12T13:14:15.000123Z'::timestamptz FROM generate_series(1,1100)n`, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, auditHTTPSizeTestID(6))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, f.admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := conn.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	e, err := newAuditHTTPSizeExpected(ctx, conn, binding.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := e.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	source := e.source.(*auditHTTPSizePGSource)
	// Commit a change after the snapshot so replay cannot quietly move to a new one.
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET target_id='changed' WHERE organization_id=$1`, binding.OrganizationID); err != nil {
		t.Fatal(err)
	}
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal(err)
	}
	var firstHash [32]byte
	previous := audit.ExportZeroDigest
	var total int64
	for index, count := range []int{1000, 100} {
		request, stop := context.WithTimeout(ctx, auditHTTPSizeProviderTimeout)
		started := time.Now()
		body, err := e.Next(request)
		elapsed := time.Since(started)
		stop()
		<-request.Done()
		t.Logf("chunk=%d bytes=%d elapsed=%s deadline=%s source_read=%d", index+1, len(body), elapsed, auditHTTPSizeProviderTimeout, e.read)
		if err != nil {
			t.Fatalf("fresh request %d failed after previous request cancellation: %v", index+1, err)
		}
		// Error, not Fatal, lets RED also observe the next request's cancellation.
		if source.rows != nil || conn.PgConn().IsBusy() {
			t.Error("completed request retained active FETCH rows or busy connection")
		}
		want := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: binding, Ordinal: int64(index + 1), FirstEvent: int64(index*1000 + 1), EventCount: int64(count), PreviousDigest: previous, Events: []audit.ExportEvent{}}
		for n := index * 1000; n < index*1000+count; n++ {
			want.Events = append(want.Events, audit.ExportEvent{Ordinal: int64(n + 1), ID: auditHTTPSizeTestID(2000 - n), OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, ActorID: auditHTTPSizeTestID(6), Action: "policy.update", TargetID: "original", Outcome: "denied", OccurredAt: "2026-09-12T13:14:15.000123Z", Metadata: map[string]string{"counter": "9007199254740993", "verified": "true", "token": "[REDACTED]", "quote": "<>&\"\\ café\u2028\u2029"}})
		}
		expected, err := json.Marshal(want)
		if err != nil || !bytes.Equal(body, expected) {
			t.Fatal("fresh request changed original canonical chunk bytes", index+1, err)
		}
		sum := sha256.Sum256(expected)
		if index == 0 {
			firstHash = sum
		}
		previous = hex.EncodeToString(sum[:])
		total += int64(len(expected))
	}
	request, stop := context.WithTimeout(ctx, auditHTTPSizeProviderTimeout)
	_, err = e.Next(request)
	stop()
	if !errors.Is(err, io.EOF) || e.read != 1100 {
		t.Fatal("original source count/EOF lost across requests", e.read, err)
	}
	auditHTTPSizeOracleIdle(t, ctx, conn, source)
	manifest, summary, err := e.Manifest()
	wantManifest, marshalErr := json.Marshal(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, EventCount: 1100, ChunkCount: 2, ChunkBytes: total, ChainRoot: previous})
	manifestHash := sha256.Sum256(wantManifest)
	if err != nil || marshalErr != nil || !bytes.Equal(manifest, wantManifest) || summary != (auditHTTPSizeSummary{Events: 1100, Chunks: 2, ChunkBytes: total, ChainRoot: previous, ManifestSHA256: hex.EncodeToString(manifestHash[:])}) {
		t.Fatal("manifest lost original bytes/accounting", summary, err, marshalErr)
	}

	t.Run("cancel-during-next", func(t *testing.T) {
		if err := e.Reset(ctx, binding); err != nil {
			t.Fatal(err)
		}
		request, stop := context.WithTimeout(ctx, auditHTTPSizeProviderTimeout)
		defer stop()
		// The wrapper runs the real PG read, then cancels while Next is assembling
		// its first chunk. It does not substitute query results or cleanup behavior.
		e.source = &auditHTTPSizeCancelAfterRow{auditHTTPSizeSource: source, cancel: stop}
		body, err := e.Next(request)
		e.source = source
		if !errors.Is(err, context.Canceled) || request.Err() != context.Canceled || body != nil || e.summary.Chunks != 0 {
			t.Fatal("in-request cancellation earned chunk credit", len(body), e.summary, err)
		}
		if _, _, err := e.Manifest(); err == nil {
			t.Fatal("canceled request earned manifest credit")
		}
		if _, err := e.Next(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled traversal failure was not sticky", err)
		}
		auditHTTPSizeOracleIdle(t, ctx, conn, source)
	})
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal("reset after completed query cancellation", err)
	}
	request, stop = context.WithTimeout(ctx, auditHTTPSizeProviderTimeout)
	body, err := e.Next(request)
	stop()
	if err != nil || sha256.Sum256(body) != firstHash {
		t.Fatal("Reset changed original first chunk", err)
	}
	auditHTTPSizeOracleIdle(t, ctx, conn, source)
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal("Reset with pending lookahead", err)
	}
	auditHTTPSizeOracleIdle(t, ctx, conn, source)
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if conn.PgConn().TxStatus() != 'I' {
		t.Fatal("Close leaked original snapshot transaction")
	}
	auditHTTPSizeOracleIdle(t, ctx, conn, source)
	var cursors int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_cursors WHERE name='audit_http_size_original'`).Scan(&cursors); err != nil || cursors != 0 {
		t.Fatal("Close leaked original cursor", cursors, err)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatal("repeated Close", err)
	}
}

func auditHTTPSizeOracleIdle(t *testing.T, ctx context.Context, conn *pgx.Conn, source *auditHTTPSizePGSource) {
	t.Helper()
	if source.rows != nil || conn.IsClosed() || conn.PgConn().IsBusy() {
		t.Fatal("oracle retained active query or lost borrowed connection")
	}
	var one int
	if err := conn.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatal("borrowed connection is not reusable between requests", err)
	}
}

type auditHTTPSizeCancelAfterRow struct {
	auditHTTPSizeSource
	cancel context.CancelFunc
}

func (s *auditHTTPSizeCancelAfterRow) next(ctx context.Context) (auditHTTPSizeSourceRow, error) {
	row, err := s.auditHTTPSizeSource.next(ctx)
	s.cancel()
	return row, err
}
