package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func orderedCurrentPrivateSuccessorPacketPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("private-successor packet source path unavailable")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", ".superpowers", "sdd", "2026-09-22-temporal-openfga-execution-plan", "p7-worker-enforcement", "ordered-current-private-successor-capture-packet", "private-successor-packet.json")
}

func TestP7OrderedCurrentPrivateSuccessorPacketOfflineDecodeIsClosed(t *testing.T) {
	raw, err := os.ReadFile(orderedCurrentPrivateSuccessorPacketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := decodeOrderedCurrentPrivateSuccessorPacket(raw, orderedCurrentPrivateSuccessorPacketSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Counts.Rules != 11 || packet.Counts.Rows != 57 || packet.Counts.RoutineRows != 22 || packet.Counts.NonroutineRows != 35 || len(packet.Rules) != 11 || len(packet.ExpectedRoutineFacts) != 22 || packet.Installable || packet.CaptureStatus != "NOT-CAPTURED" {
		t.Fatal("complete private-successor packet was not decoded")
	}
	for _, rawFact := range packet.ExpectedRoutineFacts {
		var fact orderedCurrentPrivateSuccessorRow
		if err := decodeOrderedCurrentPrivateSuccessorJSON(rawFact, &fact); err != nil || fact.Kind != "routine" || len(fact.Identity) == 0 || len(fact.Fact) == 0 {
			t.Fatalf("routine parity witness decode refused: %v", err)
		}
	}
	for _, rawCase := range [][]byte{[]byte(`{"unknown":1}`), append(append([]byte{}, raw...), []byte(`{}`)...)} {
		if _, err := decodeOrderedCurrentPrivateSuccessorPacket(rawCase, digestOrderedCurrentPrivateSuccessorBytes(rawCase)); err == nil {
			t.Fatal("open or trailing packet accepted")
		}
	}
}

func TestP7OrderedCurrentPrivateSuccessorBoundaryRetainsOnlyFreshNonroutineFacts(t *testing.T) {
	packet := orderedCurrentPrivateSuccessorTestPacket(t)
	rows := orderedCurrentPrivateSuccessorRows(t, packet)
	result, err := runOrderedCurrentPrivateSuccessorBoundary(context.Background(), packet, orderedCurrentPrivateSuccessorBoundaryIO{
		Original: orderedCurrentPrivateSuccessorFrame{SessionUser: "zasp_test", Role: "zasp_test", SearchPath: "public", TimeZone: "Etc/UTC", Postgres: packet.Database.Postgres, ServerVersionNum: "180003", Pgcrypto: "1.4"},
		Rows:     rows,
		Empty:    true,
		Admitted: true,
		Restored: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ValidatedRoutineCount != 22 || len(result.Facts) != 35 || result.Installable || result.CaptureStatus != "CAPTURED-UNBOUND" {
		t.Fatal("boundary result changed source/fresh fact split")
	}
	for _, raw := range result.Facts {
		var row orderedCurrentPrivateSuccessorRow
		if err := decodeOrderedCurrentPrivateSuccessorJSON(raw, &row); err != nil || row.Kind == "routine" {
			t.Fatal("native routine witness leaked into admitted facts")
		}
	}
}

func TestP7OrderedCurrentPrivateSuccessorBoundaryRefusesStreamCleanupAndWitnessFailures(t *testing.T) {
	packet := orderedCurrentPrivateSuccessorTestPacket(t)
	for _, tc := range []struct {
		name   string
		mutate func(*orderedCurrentPrivateSuccessorBoundaryIO)
	}{
		{name: "duplicate", mutate: func(io *orderedCurrentPrivateSuccessorBoundaryIO) { io.Rows = append(io.Rows, io.Rows[0]) }},
		{name: "stream", mutate: func(io *orderedCurrentPrivateSuccessorBoundaryIO) { io.CollectErr = errors.New("rows iteration") }},
		{name: "rollback", mutate: func(io *orderedCurrentPrivateSuccessorBoundaryIO) { io.RollbackErr = errors.New("rollback") }},
		{name: "table-empty", mutate: func(io *orderedCurrentPrivateSuccessorBoundaryIO) { io.Empty = false }},
		{name: "admission", mutate: func(io *orderedCurrentPrivateSuccessorBoundaryIO) { io.Admitted = false }},
		{name: "restoration", mutate: func(io *orderedCurrentPrivateSuccessorBoundaryIO) { io.Restored = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			io := orderedCurrentPrivateSuccessorBoundaryIO{Original: orderedCurrentPrivateSuccessorFrame{SessionUser: "zasp_test", Role: "zasp_test", SearchPath: "public", TimeZone: "Etc/UTC", Postgres: packet.Database.Postgres, ServerVersionNum: "180003", Pgcrypto: "1.4"}, Rows: orderedCurrentPrivateSuccessorRows(t, packet), Empty: true, Admitted: true, Restored: true}
			tc.mutate(&io)
			if _, err := runOrderedCurrentPrivateSuccessorBoundary(context.Background(), packet, io); err == nil {
				t.Fatal("failed capture witness accepted")
			}
		})
	}
}

func TestP7OrderedCurrentPrivateSuccessorAdmissionStaysUnavailable(t *testing.T) {
	if err := admitOrderedCurrentPrivateSuccessorReference(nil); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("unbound capture admission=%v", err)
	}
}

func TestP7OrderedCurrentPrivateSuccessorEnvelopeBindsObjectDigest(t *testing.T) {
	raw, err := os.ReadFile(orderedCurrentPrivateSuccessorPacketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	packet := orderedCurrentPrivateSuccessorPacket{}
	packet.Database.ServerVersionNum = "180003"
	packet.Database.Pgcrypto = "1.4"
	packet.Database.RequiredRole = "zasp_discovery_authority"
	packet.Database.RequiredTimeZone = "UTC"
	packet.Database.Postgres = "PostgreSQL 18.3"
	packet.Database.SessionUser = "zasp_test"
	captured := orderedCurrentPrivateSuccessorNativeCapture{
		Original: orderedCurrentPrivateSuccessorFrame{
			SessionUser:      "zasp_test",
			Role:             "zasp_test",
			SearchPath:       "public",
			TimeZone:         "Etc/UTC",
			Postgres:         packet.Database.Postgres,
			ServerVersionNum: packet.Database.ServerVersionNum,
			Pgcrypto:         packet.Database.Pgcrypto,
		},
		Collector: orderedCurrentPrivateSuccessorFrame{
			SessionUser:      "zasp_test",
			Role:             packet.Database.RequiredRole,
			SearchPath:       "pg_catalog",
			TimeZone:         packet.Database.RequiredTimeZone,
			Postgres:         packet.Database.Postgres,
			ServerVersionNum: packet.Database.ServerVersionNum,
			Pgcrypto:         packet.Database.Pgcrypto,
		},
	}
	payload, err := marshalOrderedCurrentPrivateSuccessorReference(packet, raw, captured)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		PacketSHA256 string `json:"packetSHA256"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.PacketSHA256 != "8e9092c2f6110c00add421b8b8bdf1da62a9cef28aba6a3aa4c5b33709f95cde" {
		t.Fatalf("packet object digest=%s", envelope.PacketSHA256)
	}
	if envelope.PacketSHA256 == digestOrderedCurrentPrivateSuccessorBytes(raw) {
		t.Fatal("packet envelope reused the raw-file digest")
	}
}

func TestP7OrderedCurrentPrivateSuccessorFactsPreserveAndBoundJSONIntegers(t *testing.T) {
	const maxSafe = "9007199254740991"
	const firstUnsafe = "9007199254740992"
	const secondUnsafe = "9007199254740993"

	decode := func(value string) orderedCurrentPrivateSuccessorRow {
		t.Helper()
		var row orderedCurrentPrivateSuccessorRow
		raw := []byte(`{"kind":"column","identity":"[\"private-column\",\"fixture\"]","fact":{"position":` + value + `}}`)
		if err := decodeOrderedCurrentPrivateSuccessorJSON(raw, &row); err != nil {
			t.Fatal(err)
		}
		return row
	}

	safe := decode(maxSafe)
	safeNumber, ok := safe.Fact["position"].(json.Number)
	if !ok || safeNumber.String() != maxSafe {
		t.Fatalf("safe integer was not preserved losslessly: %#v", safe.Fact["position"])
	}
	if !orderedCurrentPrivateSuccessorFactTypes(safe.Fact, []string{"position"}, map[string]string{"position": "integer"}) {
		t.Fatal("maximum IEEE-754 safe integer was rejected")
	}

	unsafe := decode(firstUnsafe)
	unsafeNumber, ok := unsafe.Fact["position"].(json.Number)
	if !ok || unsafeNumber.String() != firstUnsafe {
		t.Fatalf("unsafe integer was rounded or lost: %#v", unsafe.Fact["position"])
	}
	if orderedCurrentPrivateSuccessorFactTypes(unsafe.Fact, []string{"position"}, map[string]string{"position": "integer"}) {
		t.Fatal("unsafe integer was accepted for an integer-typed field")
	}

	if orderedCurrentPrivateSuccessorJSONEqual([]byte(`{"position":`+firstUnsafe+`}`), []byte(`{"position":`+secondUnsafe+`}`)) {
		t.Fatal("lossless JSON equality collapsed distinct unsafe integers")
	}
	if !orderedCurrentPrivateSuccessorJSONEqual([]byte(`{"position":`+firstUnsafe+`}`), []byte(`{"position":`+firstUnsafe+`}`)) {
		t.Fatal("lossless JSON equality rejected identical integers")
	}
}

func orderedCurrentPrivateSuccessorTestPacket(t *testing.T) orderedCurrentPrivateSuccessorPacket {
	t.Helper()
	raw, err := os.ReadFile(orderedCurrentPrivateSuccessorPacketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := decodeOrderedCurrentPrivateSuccessorPacket(raw, orderedCurrentPrivateSuccessorPacketSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func orderedCurrentPrivateSuccessorRows(t *testing.T, packet orderedCurrentPrivateSuccessorPacket) []json.RawMessage {
	t.Helper()
	rows := append([]json.RawMessage{}, packet.ExpectedRoutineFacts...)
	for _, rule := range packet.Rules {
		if rule.Kind == "routine" {
			continue
		}
		for index := 0; index < packet.Shape.RuleMaxRows[rule.ID]; index++ {
			fields := map[string]any{}
			for _, field := range rule.Fields {
				fields[field] = orderedCurrentPrivateSuccessorTypedFixture(packet.Shape.FieldTypes[rule.Kind][field])
			}
			raw, err := json.Marshal(orderedCurrentPrivateSuccessorRow{Kind: rule.Kind, Identity: orderedCurrentPrivateSuccessorCanonicalKey(rule.ID, index), Fact: fields})
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, raw)
		}
	}
	return rows
}

func orderedCurrentPrivateSuccessorTypedFixture(kind string) any {
	switch kind {
	case "string":
		return "fixture"
	case "boolean":
		return false
	case "number", "integer":
		return 1
	case "array", "acl":
		return []any{"fixture"}
	default:
		return nil
	}
}

func orderedCurrentPrivateSuccessorCanonicalKey(rule string, index int) string {
	raw, _ := json.Marshal([]string{rule, "fixture-" + strconv.Itoa(index)})
	return string(raw)
}

func decodeOrderedCurrentPrivateSuccessorJSON(raw []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
