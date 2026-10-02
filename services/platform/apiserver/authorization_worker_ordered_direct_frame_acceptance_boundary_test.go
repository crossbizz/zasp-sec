package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestP7OrderedDirectFrameOutcomePreservesRowsErrSQLState(t *testing.T) {
	if got := orderedDirectFrameErrorCode(&pgconn.PgError{Code: "ZX001"}, "row-error"); got != "ZX001" {
		t.Fatalf("SQLSTATE=%s want=ZX001", got)
	}
	if got := orderedDirectFrameErrorCode(context.Canceled, "row-error"); got != "row-error" {
		t.Fatalf("fallback=%s want=row-error", got)
	}
	for _, tc := range []struct {
		name  string
		query orderedDirectFrameErrorQueryer
	}{
		{name: "query", query: orderedDirectFrameErrorQueryer{queryErr: &pgconn.PgError{Code: "ZX001"}}},
		{name: "values", query: orderedDirectFrameErrorQueryer{rows: &orderedDirectFrameErrorRows{next: true, valuesErr: &pgconn.PgError{Code: "ZX001"}}}},
		{name: "rows", query: orderedDirectFrameErrorQueryer{rows: &orderedDirectFrameErrorRows{terminalErr: &pgconn.PgError{Code: "ZX001"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := queryOrderedDirectFrameOutcome(context.Background(), tc.query, "SELECT 1").Code; got != "ZX001" {
				t.Fatalf("SQLSTATE=%s want=ZX001", got)
			}
		})
	}
}

func TestP7OrderedDirectFrameProbeErrorDoesNotBecomeAggregateError(t *testing.T) {
	code := "23505"
	probe := orderedDirectFrameTransformCase{ExpectedOutcome: "error", ExpectedSQLState: &code, ProbeSQL: "INSERT"}
	if got := orderedDirectFrameAggregateExpectedSQLState(probe); got != nil {
		t.Fatalf("probe-only SQLSTATE leaked into aggregate expectation: %v", *got)
	}
	if !orderedDirectFrameRequiresTransformLinkage(probe) {
		t.Fatal("successful post-probe aggregate lost linkage verification")
	}
	aggregate := orderedDirectFrameTransformCase{ExpectedOutcome: "error", ExpectedSQLState: &code}
	if got := orderedDirectFrameAggregateExpectedSQLState(aggregate); got == nil || *got != code {
		t.Fatalf("aggregate SQLSTATE=%v want=%s", got, code)
	}
	if orderedDirectFrameRequiresTransformLinkage(aggregate) {
		t.Fatal("erroring aggregate attempted pre-error linkage query")
	}
}

type orderedDirectFrameErrorQueryer struct {
	rows     pgx.Rows
	queryErr error
}

func (query orderedDirectFrameErrorQueryer) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (query orderedDirectFrameErrorQueryer) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return query.rows, query.queryErr
}
func (query orderedDirectFrameErrorQueryer) QueryRow(context.Context, string, ...any) pgx.Row {
	return nil
}

type orderedDirectFrameErrorRows struct {
	next        bool
	valuesErr   error
	terminalErr error
}

func (rows *orderedDirectFrameErrorRows) Close()                                       {}
func (rows *orderedDirectFrameErrorRows) Err() error                                   { return rows.terminalErr }
func (rows *orderedDirectFrameErrorRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (rows *orderedDirectFrameErrorRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *orderedDirectFrameErrorRows) Next() bool {
	next := rows.next
	rows.next = false
	return next
}
func (rows *orderedDirectFrameErrorRows) Scan(...any) error      { return nil }
func (rows *orderedDirectFrameErrorRows) Values() ([]any, error) { return nil, rows.valuesErr }
func (rows *orderedDirectFrameErrorRows) RawValues() [][]byte    { return nil }
func (rows *orderedDirectFrameErrorRows) Conn() *pgx.Conn        { return nil }

func TestP7OrderedDirectFrameCatalogCaptureCallbackIsTypedAndCallable(t *testing.T) {
	called := false
	var capture ordered68CatalogCapture = func(*testing.T, context.Context, *pgx.Conn) bool {
		called = true
		return true
	}
	if !ordered68RunCatalogCaptureBoundary(t, context.Background(), nil, capture) {
		t.Fatal("catalog capture callback did not complete")
	}
	if !called {
		t.Fatal("catalog capture callback was not called")
	}
}

func TestP7OrderedDirectFrameConsumingSeamControls(t *testing.T) {
	var downstreamCalls, callbackCalls int
	captured, defaultRan := ordered68ConsumeCatalogCapture(t, context.Background(), nil, nil, func() { downstreamCalls++ })
	if captured || !defaultRan {
		t.Fatal("nil callback did not select the real default consumer")
	}
	if downstreamCalls != 1 {
		t.Fatalf("nil callback downstream calls=%d want=1", downstreamCalls)
	}
	downstreamCalls = 0
	captured, defaultRan = ordered68ConsumeCatalogCapture(t, context.Background(), nil, func(*testing.T, context.Context, *pgx.Conn) bool { callbackCalls++; return true }, func() { downstreamCalls++ })
	if !captured || defaultRan {
		t.Fatal("successful callback was not consumed")
	}
	if callbackCalls != 1 || downstreamCalls != 0 {
		t.Fatalf("successful callback calls=%d downstream=%d", callbackCalls, downstreamCalls)
	}
	captured, defaultRan = ordered68ConsumeCatalogCapture(t, context.Background(), nil, func(*testing.T, context.Context, *pgx.Conn) bool { callbackCalls++; return false }, func() { downstreamCalls++ })
	if captured || defaultRan {
		t.Fatal("false callback was accepted")
	}
	if callbackCalls != 2 || downstreamCalls != 0 {
		t.Fatalf("false callback calls=%d downstream=%d", callbackCalls, downstreamCalls)
	}
	if !ordered68CatalogCaptureOptionsValid(false, false, false, nil, nil, nil) || ordered68CatalogCaptureOptionsValid(true, false, false, func(*testing.T, context.Context, *pgx.Conn) bool { return true }, nil, nil) || ordered68CatalogCaptureOptionsValid(false, true, false, func(*testing.T, context.Context, *pgx.Conn) bool { return true }, nil, nil) || ordered68CatalogCaptureOptionsValid(false, false, true, func(*testing.T, context.Context, *pgx.Conn) bool { return true }, nil, nil) {
		t.Fatal("callback overlap controls changed")
	}
}

func TestP7OrderedDirectFrameGeneratedCaseProgramDecode(t *testing.T) {
	path := os.Getenv("ZASP_ORDERED_DIRECT_FRAME_CANDIDATE")
	if path == "" {
		t.Skip("round2 candidate packet not selected")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	packet, err := decodeOrderedDirectFrameAcceptancePacket(raw, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	validateOrderedDirectFrameAcceptancePacket(t, packet)
	if _, err := decodeOrderedDirectFrameCaseProgram(packet.CaseProgram); err != nil {
		t.Fatalf("generated case program refused: %v", err)
	}

	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	var program map[string]json.RawMessage
	if err := json.Unmarshal(packet.CaseProgram, &program); err != nil {
		t.Fatal(err)
	}
	var properties []map[string]json.RawMessage
	if err := json.Unmarshal(program["propertyCases"], &properties); err != nil {
		t.Fatal(err)
	}
	for index := range properties {
		var id string
		if err := json.Unmarshal(properties[index]["id"], &id); err != nil {
			t.Fatal(err)
		}
		if id == "adapter-exact-arity" {
			var stages []map[string]json.RawMessage
			if err := json.Unmarshal(properties[index]["stages"], &stages); err != nil {
				t.Fatal(err)
			}
			stages = append(stages[:4], stages[5:]...)
			properties[index]["stages"], _ = json.Marshal(stages)
		}
	}
	program["propertyCases"], _ = json.Marshal(properties)
	wire["caseProgram"], _ = json.Marshal(program)
	mutated, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	mutatedPacket, err := decodeOrderedDirectFrameAcceptancePacket(mutated, hex.EncodeToString(digestRound2Bytes(mutated)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeOrderedDirectFrameCaseProgram(mutatedPacket.CaseProgram); err == nil {
		t.Fatal("shortened generated exact-arity stages were accepted")
	}

	if err := json.Unmarshal(packet.CaseProgram, &program); err != nil {
		t.Fatal(err)
	}
	var successor map[string]json.RawMessage
	if err := json.Unmarshal(program["successorTransform"], &successor); err != nil {
		t.Fatal(err)
	}
	var cases []map[string]json.RawMessage
	if err := json.Unmarshal(successor["cases"], &cases); err != nil || len(cases) == 0 {
		t.Fatal("generated transform cases missing")
	}
	var stages []map[string]json.RawMessage
	if err := json.Unmarshal(cases[0]["stages"], &stages); err != nil || len(stages) < 2 {
		t.Fatal("generated transform stages missing")
	}
	stages[1]["action"], _ = json.Marshal("ignored-action")
	cases[0]["stages"], _ = json.Marshal(stages)
	successor["cases"], _ = json.Marshal(cases)
	program["successorTransform"], _ = json.Marshal(successor)
	wire["caseProgram"], _ = json.Marshal(program)
	mutated, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	mutatedPacket, err = decodeOrderedDirectFrameAcceptancePacket(mutated, hex.EncodeToString(digestRound2Bytes(mutated)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeOrderedDirectFrameCaseProgram(mutatedPacket.CaseProgram); err == nil {
		t.Fatal("generated transform action drift was accepted")
	}

	if err := json.Unmarshal(packet.CaseProgram, &program); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(program["successorTransform"], &successor); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(successor["cases"], &cases); err != nil || len(cases) == 0 {
		t.Fatal("generated transform cases missing")
	}
	cases[0]["mustChange"], _ = json.Marshal(true)
	successor["cases"], _ = json.Marshal(cases)
	program["successorTransform"], _ = json.Marshal(successor)
	wire["caseProgram"], _ = json.Marshal(program)
	mutated, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	mutatedPacket, err = decodeOrderedDirectFrameAcceptancePacket(mutated, hex.EncodeToString(digestRound2Bytes(mutated)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeOrderedDirectFrameCaseProgram(mutatedPacket.CaseProgram); err == nil {
		t.Fatal("generated must-change drift was accepted")
	}
}

func digestRound2Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func TestP7OrderedDirectFrameJSONComparisonIsLossless(t *testing.T) {
	if !jsonEqual([]byte(`{"n":9007199254740992}`), []byte(`{"n":9007199254740992}`)) {
		t.Fatal("equal large integers must compare equal")
	}
	if jsonEqual([]byte(`{"n":9007199254740992}`), []byte(`{"n":9007199254740993}`)) {
		t.Fatal("adjacent large integers must not collapse")
	}
	if !jsonEqual([]byte(`{"b":2,"a":[null,true]}`), []byte(`{"a":[null,true],"b":2}`)) {
		t.Fatal("object order must not affect comparison")
	}
}

func TestP7OrderedDirectFrameTransformTypedRowEncodingIsLossless(t *testing.T) {
	row, err := encodeOrderedDirectFrameTransformOriginalRow("42", json.RawMessage(`{"n":9007199254740993}`), "line")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(row, []byte(`9007199254740993`)) || bytes.Contains(row, []byte(`9007199254740992`)) {
		t.Fatalf("typed transform row lost integer precision: %s", row)
	}
	if _, err := encodeOrderedDirectFrameTransformOriginalRow("42", json.RawMessage(`{`), "line"); err == nil {
		t.Fatal("invalid typed transform JSON was accepted")
	}
}

func TestP7OrderedDirectFramePacketDecoderRefusesWireDrift(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "unknown-field", raw: []byte(`{"unknown":1}`), want: "JSON refused"},
		{name: "trailing-json", raw: []byte(`{} {}`), want: "trailing JSON refused"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeOrderedDirectFrameAcceptancePacket(tc.raw, orderedDirectFrameDigestBytes(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decode error=%v want=%q", err, tc.want)
			}
		})
	}
	if _, err := decodeOrderedDirectFrameAcceptancePacket([]byte(`{}`), "not-the-packet"); err == nil || !strings.Contains(err.Error(), "authority digest refused") {
		t.Fatalf("expected digest refusal, got %v", err)
	}
}
