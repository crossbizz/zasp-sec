package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestP7OrderedCurrentRemainingReferenceCapture(t *testing.T) {
	controls := map[string]string{}
	for _, key := range remainingOverlapControls {
		controls[key] = os.Getenv(key)
	}
	enabled, e := remainingReferenceMode(os.Getenv("ZASP_ORDERED_REMAINING_REFERENCE"), controls)
	if e != nil {
		t.Fatal(e)
	}
	if !enabled {
		t.Skip("explicit remaining reference-only capture required")
	}
	directory := os.Getenv("ZASP_ORDERED_REMAINING_REFERENCE_DIR")
	if _, e = loadRemainingReference(directory); e != nil {
		t.Fatal(e)
	}
	destination := os.Getenv("ZASP_ORDERED_REMAINING_REFERENCE_OUTPUT")
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		t.Fatal("absolute remaining reference output required")
	}
	if _, e = os.Lstat(destination); !os.IsNotExist(e) {
		t.Fatal("new remaining reference output required")
	}
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CAPTURE", "catalog")
	t.Setenv("ZASP_ORDERED_PREDECESSOR_RELEASE", filepath.Join(directory, remainingP7, "ordered-current-inventory-compiled.json"))
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", destination)
	// Same exact installer, real registered principals and reached/completed
	// catalog-only witnesses. The parent's sole frozen callback is substituted.
	runOrdered68PolicyBoundary(t, true, false, false)
	if t.Failed() {
		return
	}
	raw, e := readOrderedSupplementFile(destination, 16*1024*1024+1)
	if e != nil {
		t.Fatal("remaining reference output absent")
	}
	var envelope map[string]json.RawMessage
	if supplementJSON(raw, &envelope) != nil || string(envelope["format"]) != `"ordered-current-remaining-reference-v1"` || string(envelope["contractSHA256"]) != `"`+remainingContractSHA+`"` || string(envelope["packetManifestSHA256"]) != `"`+remainingManifestSHA+`"` || string(envelope["readOnly"]) != "true" || string(envelope["rolledBack"]) != "true" || string(envelope["frameRestored"]) != "true" {
		t.Fatal("remaining reference completion witness")
	}
}

// This entry is wired only by one counted replacement in a new frozen overlay.
// Its default preserves the full previously accepted callback chain unchanged.
func captureOrderedRemainingReferenceOrPrivate(t *testing.T, ctx context.Context, owner *pgx.Conn, destination string) {
	t.Helper()
	if os.Getenv("ZASP_ORDERED_REMAINING_REFERENCE") == "" {
		captureOrderedPrivateReferenceOrSupplement(t, ctx, owner, destination)
		return
	}
	if ctx == nil || owner == nil {
		t.Fatal("remaining reference dependencies")
	}
	published := false
	defer func() {
		if !published {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			if owner.Close(cleanup) != nil {
				t.Error("remaining reference disposal failed")
			}
		}
	}()
	controls := map[string]string{}
	for _, key := range remainingOverlapControls {
		controls[key] = os.Getenv(key)
	}
	// Only these three values are introduced by our exact pre-fixture entry.
	delete(controls, "ZASP_ORDERED_PREDECESSOR_CAPTURE")
	delete(controls, "ZASP_ORDERED_PREDECESSOR_RELEASE")
	delete(controls, "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT")
	enabled, e := remainingReferenceMode(os.Getenv("ZASP_ORDERED_REMAINING_REFERENCE"), controls)
	directory := os.Getenv("ZASP_ORDERED_REMAINING_REFERENCE_DIR")
	if e != nil || !enabled || t.Name() != "TestP7OrderedCurrentRemainingReferenceCapture" || os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") != "catalog" || destination != os.Getenv("ZASP_ORDERED_REMAINING_REFERENCE_OUTPUT") || destination != os.Getenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT") || os.Getenv("ZASP_ORDERED_PREDECESSOR_RELEASE") != filepath.Join(directory, remainingP7, "ordered-current-inventory-compiled.json") {
		t.Fatal("remaining reference entry refused")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	input, e := loadRemainingReference(directory)
	if e != nil {
		t.Fatal(e)
	}
	var tx pgx.Tx
	io := orderedSupplementIO{
		Begin: func(ctx context.Context) error {
			var err error
			tx, err = owner.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			return err
		},
		Exec: func(ctx context.Context, statement string) error { _, err := tx.Exec(ctx, statement); return err },
		Frame: func(ctx context.Context) (orderedSupplementFrame, error) {
			var f orderedSupplementFrame
			const query = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),pg_catalog.version(),current_setting('server_version_num'),(SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),current_setting('transaction_read_only')='on'`
			var row pgx.Row
			if tx == nil {
				row = owner.QueryRow(ctx, query)
			} else {
				row = tx.QueryRow(ctx, query)
			}
			e := row.Scan(&f.Session, &f.Role, &f.SearchPath, &f.TimeZone, &f.Postgres, &f.ServerVersionNum, &f.Pgcrypto, &f.ReadOnly)
			return f, e
		},
		Admission: func(ctx context.Context) error {
			var ready bool
			e := tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND to_regnamespace('zasp_authorization80_identity') IS NULL FROM zasp_authorization80_worker.registration`, supplementChecksum).Scan(&ready)
			if e != nil || !ready {
				return supplementRefusal("remaining original admission")
			}
			return nil
		},
		Collect: func(ctx context.Context, emit func(json.RawMessage) error) error {
			rows, e := tx.Query(ctx, string(input.SQL))
			if e != nil {
				return e
			}
			defer rows.Close()
			for rows.Next() {
				var kind, identity string
				var fact json.RawMessage
				if e = rows.Scan(&kind, &identity, &fact); e != nil {
					return e
				}
				var buf bytes.Buffer
				encoder := json.NewEncoder(&buf)
				encoder.SetEscapeHTML(false)
				if e = encoder.Encode(struct {
					Kind     string          `json:"kind"`
					Identity string          `json:"identity"`
					Fact     json.RawMessage `json:"fact"`
				}{kind, identity, fact}); e != nil {
					return e
				}
				if e = emit(bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})); e != nil {
					return e
				}
			}
			return rows.Err()
		},
		Rollback: func(ctx context.Context) error { e := tx.Rollback(ctx); tx = nil; return e },
		Dispose:  func(ctx context.Context) error { return owner.Close(ctx) },
	}
	publication, e := captureRemainingReference(ctx, input, io, destination)
	if e != nil {
		t.Fatal("remaining reference boundary refused")
	}
	published = true
	t.Log("remaining reference-only capture", "payloadSHA256", publication.PayloadSHA256, "fileSHA256", publication.FileSHA256, "bytes", publication.Bytes, "contractSHA256", remainingContractSHA, "packetManifestSHA256", remainingManifestSHA, "readOnly", true, "rollback", true, "frameRestored", true)
}
