package apiserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestP7OrderedCurrentConsolidatedReferenceCapture(t *testing.T) {
	controls := map[string]string{}
	for _, key := range consolidatedReferenceOverlapControls {
		controls[key] = os.Getenv(key)
	}
	enabled, err := consolidatedReferenceMode(os.Getenv("ZASP_ORDERED_CONSOLIDATED_REFERENCE"), controls)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skip("explicit consolidated reference-only capture required")
	}
	directory := os.Getenv("ZASP_ORDERED_CONSOLIDATED_REFERENCE_DIR")
	input, err := loadConsolidatedReference(directory)
	if err != nil {
		t.Fatal(err)
	}
	output := os.Getenv("ZASP_ORDERED_CONSOLIDATED_REFERENCE_OUTPUT")
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		t.Fatal("absolute consolidated reference output required")
	}
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("new consolidated reference output required")
	}
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CAPTURE", "catalog")
	t.Setenv("ZASP_ORDERED_PREDECESSOR_RELEASE", filepath.Join(directory, consolidatedReferenceP7, "ordered-current-inventory-compiled.json"))
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", output)
	// Root's counted frozen overlay replaces the sole existing callback with
	// captureOrderedConsolidatedReferenceOrPrevious before any authorized run.
	runOrdered68PolicyBoundary(t, true, false, false)
	if t.Failed() {
		return
	}
	raw, err := readOrderedSupplementFile(output, input.MaxBytes)
	var envelope map[string]json.RawMessage
	if err != nil || consolidatedDecodeJSON(raw, &envelope) != nil || string(envelope["format"]) != `"ordered-current-complete-reference-v1"` || string(envelope["packetManifestSHA256"]) != `"`+input.ManifestSHA256+`"` || string(envelope["contractSHA256"]) != `"`+input.ContractSHA256+`"` || string(envelope["readOnly"]) != "true" || string(envelope["rolledBack"]) != "true" || string(envelope["frameRestored"]) != "true" {
		t.Fatal("consolidated reference completion witness")
	}
}

// Root's frozen overlay calls this once. Its disabled branch preserves the
// accepted callback chain byte-for-byte in the existing harness.
func captureOrderedConsolidatedReferenceOrPrevious(t *testing.T, ctx context.Context, owner *pgx.Conn, destination string) {
	t.Helper()
	if os.Getenv("ZASP_ORDERED_CONSOLIDATED_REFERENCE") == "" {
		captureOrderedTransformAcceptanceOrPrevious(t, ctx, owner, destination)
		return
	}
	if ctx == nil || owner == nil {
		t.Fatal("consolidated reference dependencies")
	}
	published := false
	defer func() {
		if !published {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			if owner.Close(cleanup) != nil {
				t.Error("consolidated reference disposal")
			}
		}
	}()
	controls := map[string]string{}
	for _, key := range consolidatedReferenceOverlapControls {
		controls[key] = os.Getenv(key)
	}
	for _, key := range []string{"ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT"} {
		delete(controls, key)
	}
	enabled, err := consolidatedReferenceMode(os.Getenv("ZASP_ORDERED_CONSOLIDATED_REFERENCE"), controls)
	directory := os.Getenv("ZASP_ORDERED_CONSOLIDATED_REFERENCE_DIR")
	if err != nil || !enabled || t.Name() != "TestP7OrderedCurrentConsolidatedReferenceCapture" || os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") != "catalog" || destination != os.Getenv("ZASP_ORDERED_CONSOLIDATED_REFERENCE_OUTPUT") || destination != os.Getenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT") || os.Getenv("ZASP_ORDERED_PREDECESSOR_RELEASE") != filepath.Join(directory, consolidatedReferenceP7, "ordered-current-inventory-compiled.json") {
		t.Fatal("consolidated reference entry refused")
	}
	input, err := loadConsolidatedReference(directory)
	if err != nil {
		t.Fatal(err)
	}
	var tx pgx.Tx
	io := consolidatedReferenceIO{
		Begin: func(call context.Context) error {
			var beginErr error
			tx, beginErr = owner.BeginTx(call, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			return beginErr
		},
		Exec: func(call context.Context, statement string) error {
			_, execErr := tx.Exec(call, statement)
			return execErr
		},
		Frame: func(call context.Context) (orderedSupplementFrame, error) {
			var frame orderedSupplementFrame
			const query = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),pg_catalog.version(),current_setting('server_version_num'),(SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),current_setting('transaction_read_only')='on'`
			var row pgx.Row
			if tx == nil {
				row = owner.QueryRow(call, query)
			} else {
				row = tx.QueryRow(call, query)
			}
			scanErr := row.Scan(&frame.Session, &frame.Role, &frame.SearchPath, &frame.TimeZone, &frame.Postgres, &frame.ServerVersionNum, &frame.Pgcrypto, &frame.ReadOnly)
			return frame, scanErr
		},
		Admission: func(call context.Context) error {
			var ready bool
			scanErr := tx.QueryRow(call, `SELECT count(*)=1 AND bool_and(checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND to_regnamespace('zasp_authorization80_identity') IS NULL FROM zasp_authorization80_worker.registration`, supplementChecksum).Scan(&ready)
			if scanErr != nil || !ready {
				return consolidatedReferenceRefusal("original admission")
			}
			return nil
		},
		Collect: func(call context.Context, phase consolidatedReferencePhase, emit func(json.RawMessage) error) error {
			var rows pgx.Rows
			var queryErr error
			if phase.ID == "keys" {
				handles := make([]any, 0, len(phase.DemandHandles))
				for _, handle := range phase.DemandHandles {
					handles = append(handles, map[string]any{"ruleId": handle.RuleID, "handle": handle.Handle})
				}
				bound, encodeErr := canonicalConsolidatedJSON(handles)
				if encodeErr != nil {
					return encodeErr
				}
				rows, queryErr = tx.Query(call, string(phase.SQL), string(bound))
			} else {
				if phase.DemandHandles != nil {
					return consolidatedReferenceRefusal("unexpected bound handles")
				}
				rows, queryErr = tx.Query(call, string(phase.SQL))
			}
			if queryErr != nil {
				return queryErr
			}
			defer rows.Close()
			for rows.Next() {
				var raw json.RawMessage
				if err := rows.Scan(&raw); err != nil {
					return err
				}
				if err := emit(raw); err != nil {
					rows.Close()
					return err
				}
			}
			return rows.Err()
		},
		Rollback: func(call context.Context) error {
			err := tx.Rollback(call)
			tx = nil
			return err
		},
		Dispose: func(call context.Context) error { return owner.Close(call) },
	}
	publication, err := captureConsolidatedReference(ctx, input, io, destination)
	if err != nil {
		t.Fatal("consolidated reference boundary refused")
	}
	published = true
	t.Log("consolidated reference-only capture", "variant", input.Variant, "payloadSHA256", publication.PayloadSHA256, "fileSHA256", publication.FileSHA256, "bytes", publication.Bytes, "contractSHA256", input.ContractSHA256, "packetManifestSHA256", input.ManifestSHA256, "readOnly", true, "rollback", true, "frameRestored", true)
}
