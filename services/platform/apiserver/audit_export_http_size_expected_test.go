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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

type auditHTTPSizeSummary struct {
	Events, Chunks, ChunkBytes int64
	ChainRoot, ManifestSHA256  string
}
type auditHTTPSizeSourceRow struct {
	event    audit.ExportEvent
	metadata []byte
	stamp    time.Time
}
type auditHTTPSizeSource interface {
	reset(context.Context) error
	next(context.Context) (auditHTTPSizeSourceRow, error)
	close(context.Context) error
}

// Count and connection access do not grant provider authority. Bind separately
// restricts acceptance to the two concrete original PostgreSQL source types.
type auditHTTPSizeSnapshotSource interface {
	auditHTTPSizeSource
	snapshotConnection() *pgx.Conn
	snapshotCount() int64
}

// The caller serializes access and lends an exclusive connection until Close.
// Only one projected lookahead survives Next; the current chunk is byte-bounded.
// Each one-row FETCH is fully consumed and closed within the calling request.
type auditHTTPSizeExpected struct {
	source             auditHTTPSizeSource
	organization       string
	binding            audit.ExportBinding
	summary            auditHTTPSizeSummary
	lookahead          *audit.ExportEvent
	lookBytes          int
	read               int64
	lastStamp          time.Time
	lastID             string
	ready, eof, closed bool
	failure            error
}
type auditHTTPSizePGSource struct {
	tx           pgx.Tx
	organization string
	count        int64
	rows         pgx.Rows
	fetched      int
	cursor, eof  bool
}

func (s *auditHTTPSizePGSource) snapshotConnection() *pgx.Conn {
	if s.tx == nil {
		return nil
	}
	return s.tx.Conn()
}
func (s *auditHTTPSizePGSource) snapshotCount() int64 { return s.count }

func newAuditHTTPSizeExpected(ctx context.Context, conn *pgx.Conn, organizationID string) (*auditHTTPSizeExpected, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	s := &auditHTTPSizePGSource{tx: tx, organization: organizationID}
	var workflow, redTeam int64
	// This query establishes the original snapshot before Reset or owner writes.
	// This fixture intentionally covers admin only; other source tests stay separate.
	err = tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM zasp_admin_audit WHERE organization_id=$1),
 (SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1),
 (SELECT count(*) FROM zasp_red_team_audit WHERE organization_id=$1)`, organizationID).Scan(&s.count, &workflow, &redTeam)
	if err == nil && (workflow != 0 || redTeam != 0) {
		err = fmt.Errorf("HTTP size fixture requires zero scoped workflow/red-team rows: %d/%d", workflow, redTeam)
	}
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return nil, errors.Join(err, tx.Rollback(cleanup))
	}
	return &auditHTTPSizeExpected{source: s, organization: organizationID}, nil
}
func (s *auditHTTPSizePGSource) closeRows() {
	if s.rows != nil {
		s.rows.Close()
		s.rows = nil
	}
}
func (s *auditHTTPSizePGSource) reset(ctx context.Context) error {
	s.closeRows()
	if s.cursor {
		if _, err := s.tx.Exec(ctx, `CLOSE audit_http_size_original`); err != nil {
			return err
		}
		s.cursor = false
	}
	_, err := s.tx.Exec(ctx, `DECLARE audit_http_size_original NO SCROLL CURSOR FOR
 SELECT id,organization_id,workspace_id,environment_id,actor_id,action,target_id,outcome,metadata,occurred_at
 FROM zasp_admin_audit WHERE organization_id=$1 ORDER BY occurred_at DESC,id COLLATE "C" DESC`, s.organization)
	if err == nil {
		s.cursor, s.eof, s.fetched = true, false, 0
	}
	return err
}
func (s *auditHTTPSizePGSource) next(ctx context.Context) (auditHTTPSizeSourceRow, error) {
	if s.eof {
		return auditHTTPSizeSourceRow{}, io.EOF
	}
	var err error
	s.rows, err = s.tx.Query(ctx, `FETCH FORWARD 1 FROM audit_http_size_original`)
	// No query transport may retain ctx after this method returns, including
	// scan/error paths. The transaction and server cursor span requests, rows don't.
	defer s.closeRows()
	if err != nil {
		return auditHTTPSizeSourceRow{}, err
	}
	s.fetched = 0
	if !s.rows.Next() {
		if err := s.rows.Err(); err != nil {
			return auditHTTPSizeSourceRow{}, err
		}
		s.eof = true
		return auditHTTPSizeSourceRow{}, io.EOF
	}
	s.fetched = 1
	var row auditHTTPSizeSourceRow
	if err := s.rows.Scan(&row.event.ID, &row.event.OrganizationID, &row.event.WorkspaceID, &row.event.EnvironmentID, &row.event.ActorID, &row.event.Action, &row.event.TargetID, &row.event.Outcome, &row.metadata, &row.stamp); err != nil {
		return auditHTTPSizeSourceRow{}, err
	}
	// Read the command completion before crediting the row; errors after Scan
	// (including request cancellation) must fail closed too.
	if s.rows.Next() {
		return auditHTTPSizeSourceRow{}, errors.New("one-row original FETCH returned extra rows")
	}
	if err := s.rows.Err(); err != nil {
		return auditHTTPSizeSourceRow{}, err
	}
	return row, nil
}
func (s *auditHTTPSizePGSource) close(ctx context.Context) error {
	s.closeRows()
	return s.tx.Rollback(ctx) // Rollback closes the transaction-owned cursor too.
}
func (e *auditHTTPSizeExpected) Reset(ctx context.Context, binding audit.ExportBinding) error {
	if e.closed {
		return errors.New("HTTP size oracle is closed")
	}
	if binding.OrganizationID != e.organization {
		return errors.New("HTTP size oracle binding organization mismatch")
	}
	if _, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: binding, ChainRoot: audit.ExportZeroDigest}); err != nil {
		return err
	}
	e.ready = false
	if err := e.source.reset(ctx); err != nil {
		e.failure = err
		return err
	}
	e.binding, e.summary = binding, auditHTTPSizeSummary{ChainRoot: audit.ExportZeroDigest}
	e.lookahead, e.lookBytes, e.read = nil, 0, 0
	e.lastStamp, e.lastID = time.Time{}, ""
	e.ready, e.eof, e.failure = true, false, nil
	return nil
}
func (e *auditHTTPSizeExpected) readLookahead(ctx context.Context) error {
	row, err := e.source.next(ctx)
	if errors.Is(err, io.EOF) {
		e.eof = true
		if source, ok := e.source.(auditHTTPSizeSnapshotSource); ok && e.read != source.snapshotCount() {
			return fmt.Errorf("original snapshot count mismatch: read=%d expected=%d", e.read, source.snapshotCount())
		}
		return nil
	}
	if err != nil {
		return err
	}
	if e.read > 0 && (row.stamp.After(e.lastStamp) || row.stamp.Equal(e.lastStamp) && row.event.ID >= e.lastID) {
		return errors.New("original source contains duplicate or out-of-order keys")
	}
	if row.event.OrganizationID != e.organization {
		return errors.New("original source organization mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(row.metadata))
	decoder.UseNumber()
	var stored map[string]any
	if err := decoder.Decode(&stored); err != nil {
		return err
	}
	if stored == nil {
		return errors.New("original source metadata must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("original source metadata contains trailing JSON")
	}
	row.event.Metadata = make(map[string]string, len(stored))
	for key, value := range stored {
		switch v := value.(type) {
		case string:
			row.event.Metadata[key] = v
		case json.Number:
			row.event.Metadata[key] = v.String()
		case bool:
			row.event.Metadata[key] = strconv.FormatBool(v)
		default:
			return errors.New("unsupported original source metadata value")
		}
	}
	row.event.Ordinal = e.read + 1
	row.event.OccurredAt = row.stamp.UTC().Format("2006-01-02T15:04:05.000000Z")
	projected, err := audit.ProjectExportEvent(row.event)
	if err != nil {
		return err
	}
	encoded, err := audit.EncodeExportEvent(projected)
	if err != nil || len(encoded) > audit.ExportMaximumEventBytes {
		return errors.Join(errors.New("original source event encoding rejected"), err)
	}
	e.read++
	e.lastStamp, e.lastID = row.stamp, row.event.ID
	e.lookahead, e.lookBytes = &projected, len(encoded)
	return nil
}
func (e *auditHTTPSizeExpected) Next(ctx context.Context) ([]byte, error) {
	if e.closed || !e.ready {
		return nil, errors.New("HTTP size oracle requires an open Reset")
	}
	if e.failure != nil {
		return nil, e.failure
	}
	chunk := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: e.binding, Ordinal: e.summary.Chunks + 1, FirstEvent: e.summary.Events + 1, PreviousDigest: e.summary.ChainRoot, Events: []audit.ExportEvent{}}
	eventBytes := 0
	for {
		if err := ctx.Err(); err != nil {
			e.failure = err
			return nil, err
		}
		if e.lookahead == nil && !e.eof {
			if err := e.readLookahead(ctx); err != nil {
				e.failure = err
				return nil, err
			}
		}
		if e.lookahead == nil {
			break
		}
		header := chunk
		header.EventCount++
		header.Events = []audit.ExportEvent{}
		envelope, err := json.Marshal(header)
		if err != nil {
			e.failure = err
			return nil, err
		}
		// Empty [] is already in the envelope; n events need n-1 commas.
		candidateBytes := len(envelope) + eventBytes + e.lookBytes + int(chunk.EventCount)
		if header.EventCount > audit.ExportMaximumChunkEvents || candidateBytes > audit.ExportMaximumChunkBytes {
			if chunk.EventCount == 0 {
				e.failure = errors.New("one source event exceeds chunk bound")
				return nil, e.failure
			}
			break
		}
		chunk.EventCount++
		chunk.Events = append(chunk.Events, *e.lookahead)
		eventBytes += e.lookBytes
		e.lookahead, e.lookBytes = nil, 0
	}
	if chunk.EventCount == 0 {
		return nil, io.EOF
	}
	body, err := audit.EncodeExportChunk(chunk)
	if err != nil {
		e.failure = err
		return nil, err
	}
	sum := sha256.Sum256(body)
	e.summary.Events += chunk.EventCount
	e.summary.Chunks++
	e.summary.ChunkBytes += int64(len(body))
	e.summary.ChainRoot = hex.EncodeToString(sum[:])
	return body, nil
}
func (e *auditHTTPSizeExpected) Manifest() ([]byte, auditHTTPSizeSummary, error) {
	if e.closed || !e.ready || !e.eof || e.lookahead != nil || e.failure != nil {
		return nil, auditHTTPSizeSummary{}, errors.New("HTTP size oracle has not completed a successful traversal")
	}
	body, err := audit.EncodeExportManifest(audit.ExportManifest{Schema: audit.ExportManifestSchema, Binding: e.binding, EventCount: e.summary.Events, ChunkCount: e.summary.Chunks, ChunkBytes: e.summary.ChunkBytes, ChainRoot: e.summary.ChainRoot})
	if err != nil {
		return nil, auditHTTPSizeSummary{}, err
	}
	summary := e.summary
	sum := sha256.Sum256(body)
	summary.ManifestSHA256 = hex.EncodeToString(sum[:])
	return body, summary, nil
}
func (e *auditHTTPSizeExpected) Close(ctx context.Context) error {
	if e.closed {
		return nil
	}
	e.closed, e.lookahead = true, nil
	return e.source.close(ctx)
}

type auditHTTPSizeGeneratedSource struct {
	count, index int
	row          func(int) auditHTTPSizeSourceRow
}

func (s *auditHTTPSizeGeneratedSource) reset(context.Context) error { s.index = 0; return nil }
func (s *auditHTTPSizeGeneratedSource) close(context.Context) error { return nil }
func (s *auditHTTPSizeGeneratedSource) next(context.Context) (auditHTTPSizeSourceRow, error) {
	if s.index == s.count {
		return auditHTTPSizeSourceRow{}, io.EOF
	}
	row := s.row(s.index)
	s.index++
	return row, nil
}
func auditHTTPSizeTestID(n int) string { return fmt.Sprintf("pid_%08x-0000-4000-8000-000000000001", n) }
func auditHTTPSizeTestBinding() audit.ExportBinding {
	return audit.ExportBinding{OrganizationID: auditHTTPSizeTestID(1), WorkspaceID: auditHTTPSizeTestID(2), EnvironmentID: auditHTTPSizeTestID(3), ExportID: auditHTTPSizeTestID(4), CaptureID: auditHTTPSizeTestID(5)}
}
func auditHTTPSizeTestRow(n int) auditHTTPSizeSourceRow {
	return auditHTTPSizeSourceRow{event: audit.ExportEvent{ID: auditHTTPSizeTestID(2000 - n), OrganizationID: auditHTTPSizeTestID(1), WorkspaceID: auditHTTPSizeTestID(2), EnvironmentID: auditHTTPSizeTestID(3), ActorID: auditHTTPSizeTestID(6), Action: "policy.update", TargetID: "original", Outcome: "rejected"}, metadata: []byte(`{"counter":9007199254740993,"verified":true,"token":"owned-secret-never-exported","quote":"<>&\"\\ café\u2028\u2029"}`), stamp: time.Date(2026, 9, 12, 13, 14, 15, 123000, time.UTC)}
}
func auditHTTPSizeTestOracle(t *testing.T, count int, row func(int) auditHTTPSizeSourceRow) *auditHTTPSizeExpected {
	t.Helper()
	e := &auditHTTPSizeExpected{source: &auditHTTPSizeGeneratedSource{count: count, row: row}, organization: auditHTTPSizeTestID(1)}
	if err := e.Reset(context.Background(), auditHTTPSizeTestBinding()); err != nil {
		t.Fatal(err)
	}
	return e
}

// Catches empty-source loss, count/digit growth mistakes, byte overflow,
// cross-chunk order loss, and projection drift using original source fields.
func TestAuditHTTPSizeExpectedBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, count := range []int{0, 1, 1001} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			e := auditHTTPSizeTestOracle(t, count, auditHTTPSizeTestRow)
			if _, _, err := e.Manifest(); err == nil {
				t.Fatal("manifest available before source EOF")
			}
			var events, chunks, total int64
			previous := audit.ExportZeroDigest
			for {
				body, err := e.Next(ctx)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				chunk, err := audit.DecodeExportChunk(body)
				if err != nil {
					t.Fatal(err)
				}
				wantCount := min(int64(count)-events, 1000)
				if chunk.EventCount != wantCount || chunk.Ordinal != chunks+1 || chunk.FirstEvent != events+1 || chunk.PreviousDigest != previous || chunk.Binding != auditHTTPSizeTestBinding() {
					t.Fatal("chunk authority/count mismatch")
				}
				for _, event := range chunk.Events {
					events++
					if event.Ordinal != events || event.ID != auditHTTPSizeTestID(2001-int(events)) || event.TargetID != "original" || event.Outcome != "denied" || event.OccurredAt != "2026-09-12T13:14:15.000123Z" || event.Metadata["counter"] != "9007199254740993" || event.Metadata["verified"] != "true" || event.Metadata["token"] != "[REDACTED]" || event.Metadata["quote"] != "<>&\"\\ café\u2028\u2029" {
						t.Fatalf("source projection/contiguous ordinal mismatch: %+v", event)
					}
				}
				if !bytes.Contains(body, []byte(`"quote":"\u003c\u003e\u0026\"\\ café\u2028\u2029"`)) || bytes.Contains(body, []byte("owned-secret-never-exported")) {
					t.Fatal("canonical escaping or redaction mismatch")
				}
				sum := sha256.Sum256(body)
				previous = hex.EncodeToString(sum[:])
				chunks++
				total += int64(len(body))
			}
			body, summary, err := e.Manifest()
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := audit.DecodeExportManifest(body)
			sum := sha256.Sum256(body)
			if err != nil || events != int64(count) || summary.Events != events || summary.Chunks != chunks || summary.ChunkBytes != total || summary.ChainRoot != previous || summary.ManifestSHA256 != hex.EncodeToString(sum[:]) || manifest.Binding != auditHTTPSizeTestBinding() || manifest.EventCount != events || manifest.ChunkCount != chunks || manifest.ChunkBytes != total || manifest.ChainRoot != previous {
				t.Fatalf("manifest/accounting mismatch: %+v %v", summary, err)
			}
		})
	}
	// Hand-size a valid wire fixture: one-character values account for all
	// key/separator bytes first, then plain x bytes fill the remaining space.
	rows := make([]auditHTTPSizeSourceRow, 70)
	want := audit.ExportChunk{Schema: audit.ExportChunkSchema, Binding: auditHTTPSizeTestBinding(), Ordinal: 1, FirstEvent: 1, EventCount: 70, PreviousDigest: audit.ExportZeroDigest}
	for i := range rows {
		rows[i] = auditHTTPSizeTestRow(i)
		event := rows[i].event
		event.Ordinal, event.Outcome, event.OccurredAt = int64(i+1), "denied", "2026-09-12T13:14:15.000123Z"
		event.Metadata = map[string]string{}
		for key := 0; key < 32; key++ {
			event.Metadata[fmt.Sprintf("field%02d", key)] = "x"
		}
		want.Events = append(want.Events, event)
	}
	base, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	remaining := (1 << 20) - len(base)
	for i := range want.Events {
		for key := 0; key < 32; key++ {
			fill := min(511, remaining)
			want.Events[i].Metadata[fmt.Sprintf("field%02d", key)] = strings.Repeat("x", 1+fill)
			remaining -= fill
		}
		rows[i].metadata, err = json.Marshal(want.Events[i].Metadata)
		if err != nil {
			t.Fatal(err)
		}
	}
	exact, err := json.Marshal(want)
	if err != nil || remaining != 0 || len(exact) != 1<<20 {
		t.Fatal("invalid exact-byte fixture", err, remaining, len(exact))
	}
	for _, overflow := range []bool{false, true} {
		t.Run(fmt.Sprintf("byte-overflow-%t", overflow), func(t *testing.T) {
			e := auditHTTPSizeTestOracle(t, len(rows), func(i int) auditHTTPSizeSourceRow {
				row := rows[i]
				if overflow && i == len(rows)-1 {
					row.event.TargetID += "x"
				}
				return row
			})
			body, err := e.Next(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !overflow {
				if !bytes.Equal(body, exact) {
					t.Fatal("exact 1MiB chunk bytes changed", len(body))
				}
			} else {
				chunk, err := audit.DecodeExportChunk(body)
				if err != nil || chunk.EventCount != 69 {
					t.Fatal("one-byte overflow must split before event70", err)
				}
				sum := sha256.Sum256(body)
				next, err := e.Next(ctx)
				if err != nil {
					t.Fatal(err)
				}
				chunk, err = audit.DecodeExportChunk(next)
				if err != nil || chunk.Ordinal != 2 || chunk.FirstEvent != 70 || chunk.EventCount != 1 || chunk.Events[0].Ordinal != 70 || chunk.Events[0].TargetID != "originalx" || chunk.PreviousDigest != hex.EncodeToString(sum[:]) {
					t.Fatal("overflow continuation mismatch", err)
				}
			}
			if _, err := e.Next(ctx); !errors.Is(err, io.EOF) {
				t.Fatal("source did not end", err)
			}
		})
	}
	for _, mode := range []string{"duplicate", "reversed-id", "reversed-time", "cross-chunk"} {
		t.Run(mode, func(t *testing.T) {
			count := 2
			if mode == "cross-chunk" {
				count = 1002
			}
			e := auditHTTPSizeTestOracle(t, count, func(i int) auditHTTPSizeSourceRow {
				row := auditHTTPSizeTestRow(i)
				if i == count-1 {
					switch mode {
					case "duplicate", "cross-chunk":
						row.event.ID = auditHTTPSizeTestRow(i - 1).event.ID
					case "reversed-id":
						row.event.ID = auditHTTPSizeTestID(3000)
					case "reversed-time":
						row.stamp = row.stamp.Add(time.Second)
					}
				}
				return row
			})
			if mode == "cross-chunk" {
				if _, err := e.Next(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.Next(ctx); err == nil || errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "out-of-order") {
				t.Fatal("invalid source order accepted", err)
			}
			if _, _, err := e.Manifest(); err == nil {
				t.Fatal("failed traversal produced manifest")
			}
			if _, err := e.Next(ctx); err == nil || errors.Is(err, io.EOF) {
				t.Fatal("source error was not sticky", err)
			}
		})
	}
	t.Run("time-before-id", func(t *testing.T) {
		e := auditHTTPSizeTestOracle(t, 2, func(i int) auditHTTPSizeSourceRow {
			row := auditHTTPSizeTestRow(i)
			if i == 1 {
				row.event.ID = auditHTTPSizeTestID(3000)
				row.stamp = row.stamp.Add(-time.Second)
			}
			return row
		})
		body, err := e.Next(ctx)
		if err != nil {
			t.Fatal("older event with larger ID rejected", err)
		}
		chunk, err := audit.DecodeExportChunk(body)
		if err != nil || chunk.EventCount != 2 || chunk.Events[1].ID != auditHTTPSizeTestID(3000) || chunk.Events[1].OccurredAt != "2026-09-12T13:14:14.000123Z" {
			t.Fatal("timestamp is not the primary order key", err)
		}
	})
	for _, metadata := range []string{`null`, `{"nested":{}}`, `{"array":[]}`, `{"number":null}`, `{} {}`, `{"broken":`} {
		t.Run("invalid-metadata-"+metadata, func(t *testing.T) {
			e := auditHTTPSizeTestOracle(t, 1, func(i int) auditHTTPSizeSourceRow {
				row := auditHTTPSizeTestRow(i)
				row.metadata = []byte(metadata)
				return row
			})
			if _, err := e.Next(ctx); err == nil || errors.Is(err, io.EOF) {
				t.Fatal("malformed original metadata accepted", err)
			}
			if _, _, err := e.Manifest(); err == nil {
				t.Fatal("invalid metadata produced manifest")
			}
		})
	}
}

// Catches a late snapshot, read-committed Reset, wrong scope/order SQL, lossy
// source projection, and leaked query/cursor ownership on Reset or Close.
func TestAuditHTTPSizeExpectedOriginalSnapshotPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	f := auditExportPGFixture(t, ctx)
	args := f.createArgs()
	binding := auditHTTPSizeTestBinding()
	binding.OrganizationID = args[0].(string)
	metadata := `{"counter":9007199254740993,"verified":true,"token":"owned-secret-never-exported","quote":"<>&\"\\ café\u2028\u2029"}`
	_, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at)
		SELECT $1,$2,$3,'pid_'||lpad(to_hex(2001-n),8,'0')||'-0000-4000-8000-000000000001',$4,'policy.update','original','rejected',$5::jsonb,'2026-09-12T13:14:15.000123Z'::timestamptz FROM generate_series(1,1100)n`, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, args[3], metadata)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata)
		VALUES($1,$2,$3,$4,$5,'policy.update','foreign excluded','succeeded','{}')`, auditHTTPSizeTestID(9000), binding.WorkspaceID, binding.EnvironmentID, auditHTTPSizeTestID(9001), args[3])
	if err != nil {
		t.Fatal(err)
	}
	var workflow, redTeam int64
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1),(SELECT count(*) FROM zasp_red_team_audit WHERE organization_id=$1)`, binding.OrganizationID).Scan(&workflow, &redTeam); err != nil || workflow != 0 || redTeam != 0 {
		t.Fatal("fixture must have zero scoped workflow/red-team sources", workflow, redTeam, err)
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
	var isolation, readOnly string
	if err := conn.QueryRow(ctx, `SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')`).Scan(&isolation, &readOnly); err != nil || isolation != "repeatable read" || readOnly != "on" {
		t.Fatal("oracle transaction modes", isolation, readOnly, err)
	}
	// All three changes commit before the first cursor declaration. A transaction
	// that merely starts before these writes, without a snapshot query, is wrong.
	if _, err := f.admin.Exec(ctx, `UPDATE zasp_admin_audit SET target_id='changed' WHERE organization_id=$1 AND id=$2`, binding.OrganizationID, auditHTTPSizeTestID(2000)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_admin_audit WHERE organization_id=$1 AND id=$2`, binding.OrganizationID, auditHTTPSizeTestID(1999)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,$4,$5,'policy.update','appended','succeeded','{}','2026-09-13T13:14:15.000123Z')`, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, auditHTTPSizeTestID(9002), args[3]); err != nil {
		t.Fatal(err)
	}
	var changed bool
	if err := f.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_admin_audit WHERE organization_id=$1 AND id=$2 AND target_id='changed') AND NOT EXISTS(SELECT 1 FROM zasp_admin_audit WHERE organization_id=$1 AND id=$3) AND EXISTS(SELECT 1 FROM zasp_admin_audit WHERE organization_id=$1 AND id=$4 AND target_id='appended')`, binding.OrganizationID, auditHTTPSizeTestID(2000), auditHTTPSizeTestID(1999), auditHTTPSizeTestID(9002)).Scan(&changed); err != nil || !changed {
		t.Fatal("owner mutations did not commit", err)
	}
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal(err)
	}
	first, err := e.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstHash := sha256.Sum256(first)
	first = nil
	// A pending lookahead survives a chunk; its database result must not.
	if e.read != 1001 || e.lookahead == nil {
		t.Fatal("fixture did not leave a projected lookahead", e.read)
	}
	auditHTTPSizeOracleIdle(t, ctx, conn, e.source.(*auditHTTPSizePGSource))
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal("reset with pending lookahead", err)
	}
	var seen int64
	for {
		body, err := e.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if seen == 0 && sha256.Sum256(body) != firstHash {
			t.Fatal("Reset changed original first chunk bytes")
		}
		chunk, err := audit.DecodeExportChunk(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range chunk.Events {
			seen++
			if event.Ordinal != seen || event.ID != auditHTTPSizeTestID(2001-int(seen)) || event.OrganizationID != binding.OrganizationID || event.WorkspaceID != binding.WorkspaceID || event.EnvironmentID != binding.EnvironmentID || event.ActorID != args[3].(string) || event.Action != "policy.update" || event.TargetID != "original" || event.Outcome != "denied" || event.OccurredAt != "2026-09-12T13:14:15.000123Z" || event.Metadata["counter"] != "9007199254740993" || event.Metadata["verified"] != "true" || event.Metadata["token"] != "[REDACTED]" || event.Metadata["quote"] != "<>&\"\\ café\u2028\u2029" {
				t.Fatalf("original source row %d changed: %+v", seen, event)
			}
		}
	}
	manifest, summary, err := e.Manifest()
	if err != nil || seen != 1100 || summary.Events != 1100 || summary.Chunks != 2 {
		t.Fatal("original snapshot incomplete", seen, summary, err)
	}
	// A complete second traversal must produce the same bytes/accounting too.
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := e.Next(ctx); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	replayed, replaySummary, err := e.Manifest()
	if err != nil || !bytes.Equal(replayed, manifest) || replaySummary != summary {
		t.Fatal("completed Reset changed original manifest", err)
	}
	if err := e.Reset(ctx, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Next(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatal("close with pending lookahead", err)
	}
	var one int
	if conn.IsClosed() || conn.PgConn().TxStatus() != 'I' {
		t.Fatal("Close must release transaction and preserve borrowed connection")
	}
	if err := conn.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatal("borrowed connection not reusable after Close", err)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatal("repeated Close", err)
	}
	if err := e.Reset(ctx, binding); err == nil {
		t.Fatal("Reset after Close accepted")
	}
	if _, err := e.Next(ctx); err == nil {
		t.Fatal("Next after Close accepted")
	}
	if _, _, err := e.Manifest(); err == nil {
		t.Fatal("Manifest after Close accepted")
	}
	// Each unsupported scoped source must refuse construction and roll back its
	// own transaction, leaving the borrowed connection ready for another caller.
	for _, source := range []string{"workflow", "red-team"} {
		t.Run("refuse-"+source, func(t *testing.T) {
			if source == "workflow" {
				_, err = f.admin.Exec(ctx, `INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version) VALUES($1,$2,$3,$4,$5,$6,'createPolicy','policy','policy-owned',1)`, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, auditHTTPSizeTestID(9010), auditHTTPSizeTestID(9011), args[3])
			} else {
				_, err = f.admin.Exec(ctx, `INSERT INTO zasp_red_team_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body) VALUES($1,$2,$3,$4,$5,$6,$7,'red_team_definition_created',$8,$9,'{}')`, binding.OrganizationID, binding.WorkspaceID, binding.EnvironmentID, auditHTTPSizeTestID(9020), auditHTTPSizeTestID(9021), auditHTTPSizeTestID(9022), args[3], auditHTTPSizeTestID(9023), make([]byte, 32))
			}
			if err != nil {
				t.Fatal("unsupported source fixture", err)
			}
			candidate, err := newAuditHTTPSizeExpected(ctx, conn, binding.OrganizationID)
			if err == nil || candidate != nil || !strings.Contains(err.Error(), "zero scoped workflow/red-team") {
				if candidate != nil {
					_ = candidate.Close(ctx)
				}
				t.Fatal("unsupported scoped source accepted", err)
			}
			if conn.PgConn().TxStatus() != 'I' {
				t.Fatal("failed constructor leaked transaction")
			}
			if err := conn.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
				t.Fatal("failed constructor retained borrowed connection", err)
			}
			if source == "workflow" {
				if _, err := f.admin.Exec(ctx, `DELETE FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$2`, binding.OrganizationID, auditHTTPSizeTestID(9010)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
