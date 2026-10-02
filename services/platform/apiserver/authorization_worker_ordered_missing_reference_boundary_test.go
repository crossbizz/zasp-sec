package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestP7OrderedMissingReferenceNativePacketDecoderIsClosedAndLossless(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "unknown", raw: []byte(`{"unknown":1}`), want: "JSON refused"},
		{name: "trailing", raw: []byte(`{} {}`), want: "trailing JSON refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeOrderedMissingReferenceNativePacket(tc.raw, orderedMissingReferenceDigestBytes(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decode error=%v want=%q", err, tc.want)
			}
		})
	}
	if _, err := decodeOrderedMissingReferenceNativePacket([]byte(`{}`), "wrong"); err == nil || !strings.Contains(err.Error(), "authority digest refused") {
		t.Fatalf("digest refusal=%v", err)
	}
	left, err := decodeOrderedMissingReferenceLossless([]byte(`{"n":9007199254740992}`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := decodeOrderedMissingReferenceLossless([]byte(`{"n":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(left, right) {
		t.Fatal("adjacent large integers collapsed")
	}
}

func TestP7OrderedMissingReferenceNativePacketConsumesFullFixedPacket(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_MISSING_REFERENCE_PACKET") != "1" {
		t.Skip("explicit fixed missing-reference packet validation required")
	}
	if _, err := loadOrderedMissingReferenceNativePacket(t.TempDir()); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit packet validation did not refuse a missing fixed packet: %v", err)
	}
	packet, err := loadOrderedMissingReferenceNativePacket(orderedMissingReferenceNativePacketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Baseline.Rules) != 12 || packet.Counts.Rows != 204 || len(packet.WitnessProgram.Families) != 7 {
		t.Fatal("full fixed packet boundary was incomplete")
	}
}

func TestP7OrderedMissingReferenceBoundaryRejectsMalformedObservations(t *testing.T) {
	fields := []string{"name", "enabled", "nullable"}
	types := map[string]string{"name": "string", "enabled": "boolean", "nullable": "string"}
	valid := []byte(`{"identity":"x","fields":{"name":"x","enabled":true,"nullable":null}}`)
	if err := validateOrderedMissingReferenceObservation(valid, fields, types); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"identity":"","fields":{"name":"x","enabled":true,"nullable":null}}`),
		[]byte(`{"identity":"x","fields":{"name":"x","enabled":"true","nullable":null}}`),
		[]byte(`{"identity":"x","fields":{"name":"x","enabled":true,"nullable":null,"unknown":1}}`),
		[]byte(`{"identity":"x","fields":{"name":"x","enabled":true}}`),
	} {
		if err := validateOrderedMissingReferenceObservation(raw, fields, types); err == nil {
			t.Fatalf("malformed observation accepted: %s", raw)
		}
	}
}

func TestP7OrderedMissingReferenceCapturePublishesExclusivelyWithOwnerOnlyMode(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "capture.json")
	if err := publishOrderedMissingReferenceCapture(context.Background(), output, []byte("{}\n"), 16*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if err := publishOrderedMissingReferenceCapture(context.Background(), output, []byte("different\n"), 16*1024*1024, nil); err == nil {
		t.Fatal("capture overwrite accepted")
	}
}

func TestP7OrderedMissingReferenceCapturePublicationHonorsLimitAndCancellation(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "capture.json")
	if err := publishOrderedMissingReferenceCapture(context.Background(), output, []byte("12345"), 4, nil); err == nil {
		t.Fatal("oversized capture published")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := publishOrderedMissingReferenceCapture(ctx, output, []byte("{}\n"), 16*1024*1024, nil); err == nil {
		t.Fatal("cancelled capture published")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled output exists: %v", err)
	}
}

type orderedMissingReferenceRowsAtError struct{ err error }

func (rows orderedMissingReferenceRowsAtError) Close()     {}
func (rows orderedMissingReferenceRowsAtError) Err() error { return rows.err }
func (rows orderedMissingReferenceRowsAtError) CommandTag() pgconn.CommandTag {
	return pgconn.CommandTag{}
}
func (rows orderedMissingReferenceRowsAtError) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}
func (rows orderedMissingReferenceRowsAtError) Next() bool             { return false }
func (rows orderedMissingReferenceRowsAtError) Scan(...any) error      { return nil }
func (rows orderedMissingReferenceRowsAtError) Values() ([]any, error) { return nil, nil }
func (rows orderedMissingReferenceRowsAtError) RawValues() [][]byte    { return nil }
func (rows orderedMissingReferenceRowsAtError) Conn() *pgx.Conn        { return nil }

type orderedMissingReferenceQueryAtError struct{ rows pgx.Rows }

func (query orderedMissingReferenceQueryAtError) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (query orderedMissingReferenceQueryAtError) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return query.rows, nil
}
func (query orderedMissingReferenceQueryAtError) QueryRow(context.Context, string, ...any) pgx.Row {
	return nil
}

func TestP7OrderedMissingReferenceProbeAcceptsDeclaredSQLStateFromRowsErr(t *testing.T) {
	stage := orderedMissingReferenceProbeStage{Expected: &orderedMissingReferenceProbeExpected{Outcome: "error", SQLState: "21000"}}
	control, err := orderedMissingReferenceProbeOutcome(context.Background(), orderedMissingReferenceQueryAtError{rows: orderedMissingReferenceRowsAtError{err: &pgconn.PgError{Code: "21000"}}}, 1, &orderedMissingReferenceByteBudget{limit: 16}, stage)
	if err != nil || control.SQLState != "21000" {
		t.Fatalf("rows.Err SQLSTATE outcome control=%+v err=%v", control, err)
	}
}

func TestP7OrderedMissingReferenceCaptureByteBudgetIsCumulative(t *testing.T) {
	budget := &orderedMissingReferenceByteBudget{limit: 5}
	if err := budget.add([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := budget.add([]byte("de")); err != nil {
		t.Fatal(err)
	}
	if err := budget.add([]byte("f")); err == nil {
		t.Fatal("cumulative capture byte cap accepted overflow")
	}
}

func TestP7OrderedMissingReferenceProbeRequiresTemporaryShadowAndProjection(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"resolved":"pg_temp.zasp_core_payloads","temporary":false,"projection":[]}`),
		[]byte(`{"resolved":"pg_temp.zasp_core_payloads","temporary":true}`),
	} {
		if err := validateOrderedMissingReferenceShadowEvidence(raw); err == nil {
			t.Fatalf("invalid shadow evidence accepted: %s", raw)
		}
	}
	projection := make([]json.RawMessage, 34)
	for index := range projection {
		projection[index] = json.RawMessage(`{"identity":"observed"}`)
	}
	raw, err := json.Marshal(struct {
		Resolved   string            `json:"resolved"`
		Temporary  bool              `json:"temporary"`
		Projection []json.RawMessage `json:"projection"`
	}{Resolved: "pg_temp.zasp_core_payloads", Temporary: true, Projection: projection})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOrderedMissingReferenceShadowEvidence(raw); err != nil {
		t.Fatal(err)
	}
}

func TestP7OrderedMissingReferenceProbeJoinsRollbackAndRestorationFailures(t *testing.T) {
	probeErr := errors.New("probe")
	rollbackErr := errors.New("rollback")
	restoreErr := errors.New("restore")
	err := joinOrderedMissingReferenceProbeCleanup(probeErr, rollbackErr, restoreErr, true)
	for _, want := range []error{probeErr, rollbackErr, restoreErr} {
		if !errors.Is(err, want) {
			t.Fatalf("joined error %v lost %v", err, want)
		}
	}
}

func TestP7OrderedMissingReferenceNativeModeRefusesInvalidExplicitValue(t *testing.T) {
	for _, mode := range []string{"", "1", "invalid"} {
		run, err := orderedMissingReferenceNativeMode(mode)
		if mode == "" && (run || err != nil) {
			t.Fatalf("empty mode run=%t err=%v", run, err)
		}
		if mode == "1" && (!run || err != nil) {
			t.Fatalf("native mode run=%t err=%v", run, err)
		}
		if mode == "invalid" && (run || err == nil) {
			t.Fatalf("invalid mode run=%t err=%v", run, err)
		}
	}
}

func TestP7OrderedMissingReferenceCatalogCallbackUsesNamedBoundary(t *testing.T) {
	called := false
	var capture ordered68CatalogCapture = func(*testing.T, context.Context, *pgx.Conn) bool { called = true; return true }
	if !ordered68RunCatalogCaptureBoundary(t, context.Background(), nil, capture) || !called {
		t.Fatal("catalog-only callback did not complete")
	}
}
