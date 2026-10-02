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
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const orderedCurrentPrivateSuccessorPacketSHA256 = "5071a729bbd87d1489b3ae9f4f608f73a011281525f26ae889d5d4148dcba75c"

type orderedCurrentPrivateSuccessorPacket struct {
	Format          string `json:"format"`
	Status          string `json:"status"`
	Installable     bool   `json:"installable"`
	CaptureStatus   string `json:"captureStatus"`
	SourceAuthority string `json:"sourceAuthority"`
	SourcePins      struct {
		CompilerArtifactSHA256 string `json:"compilerArtifactSHA256"`
		CompilerChecksum       string `json:"compilerChecksum"`
		CompiledSourceSHA256   string `json:"compiledSourceSHA256"`
		SourceContractSHA256   string `json:"sourceContractSHA256"`
		CatalogSHA256          string `json:"catalogSHA256"`
	} `json:"sourcePins"`
	HelperPins map[string]string `json:"helperPins"`
	Namespace  string            `json:"namespace"`
	Database   struct {
		Postgres           string   `json:"postgres"`
		ServerVersionNum   string   `json:"serverVersionNum"`
		Pgcrypto           string   `json:"pgcrypto"`
		Variant            string   `json:"variant"`
		SessionUser        string   `json:"sessionUser"`
		RequiredRole       string   `json:"requiredRole"`
		RequiredSearchPath []string `json:"requiredSearchPath"`
		RequiredTimeZone   string   `json:"requiredTimeZone"`
	} `json:"database"`
	Counts struct {
		Rules          int `json:"rules"`
		Rows           int `json:"rows"`
		RoutineRows    int `json:"routineRows"`
		NonroutineRows int `json:"nonroutineRows"`
	} `json:"counts"`
	Limits struct {
		MaxRows        int `json:"maxRows"`
		MaxBytes       int `json:"maxBytes"`
		OuterSeconds   int `json:"outerSeconds"`
		SQLSeconds     int `json:"sqlSeconds"`
		LockSeconds    int `json:"lockSeconds"`
		CleanupSeconds int `json:"cleanupSeconds"`
	} `json:"limits"`
	Shape struct {
		CategoryMaxRows map[string]int               `json:"categoryMaxRows"`
		RuleMaxRows     map[string]int               `json:"ruleMaxRows"`
		FieldTypes      map[string]map[string]string `json:"fieldTypes"`
	} `json:"shape"`
	Rules                []orderedCurrentPrivateSuccessorRule `json:"rules"`
	ExpectedRoutineFacts []json.RawMessage                    `json:"expectedRoutineFacts"`
	DDL                  struct {
		SQL                  string `json:"sql"`
		SHA256               string `json:"sha256"`
		AssemblySHA256       string `json:"assemblySHA256"`
		TemplateSHA256       string `json:"templateSHA256"`
		EmbeddedExpectations bool   `json:"embeddedExpectations"`
	} `json:"ddl"`
	Collector struct {
		SQL       string `json:"sql"`
		SHA256    string `json:"sha256"`
		Ordering  string `json:"ordering"`
		Unbounded bool   `json:"unbounded"`
	} `json:"collector"`
	Witnesses []string `json:"witnesses"`
	Output    struct {
		Format        string `json:"format"`
		Status        string `json:"status"`
		Installable   bool   `json:"installable"`
		CaptureStatus string `json:"captureStatus"`
		Publication   string `json:"publication"`
	} `json:"output"`
}

type orderedCurrentPrivateSuccessorRule struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Namespaces []string `json:"namespaces"`
	Identities []string `json:"identities"`
	Fields     []string `json:"fields"`
}

type orderedCurrentPrivateSuccessorRow struct {
	Kind     string         `json:"kind"`
	Identity string         `json:"identity"`
	Fact     map[string]any `json:"fact"`
}

func digestOrderedCurrentPrivateSuccessorBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func orderedCurrentPrivateSuccessorPacketObjectBytes(raw []byte) ([]byte, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("private-successor packet object framing refused")
	}
	object := raw[:len(raw)-1]
	decoder := json.NewDecoder(bytes.NewReader(object))
	var decoded json.RawMessage
	if err := decoder.Decode(&decoded); err != nil || !bytes.Equal(decoded, object) || decoder.InputOffset() != int64(len(object)) {
		return nil, errors.New("private-successor packet object serialization refused")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("private-successor packet object trailing JSON refused")
	}
	return object, nil
}

func decodeOrderedCurrentPrivateSuccessorPacket(raw []byte, expectedDigest string) (orderedCurrentPrivateSuccessorPacket, error) {
	var packet orderedCurrentPrivateSuccessorPacket
	if len(raw) == 0 || len(raw) > 16*1024*1024 || digestOrderedCurrentPrivateSuccessorBytes(raw) != expectedDigest {
		return packet, errors.New("private-successor packet authority digest refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&packet); err != nil {
		return packet, fmt.Errorf("private-successor packet JSON refused: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return packet, errors.New("private-successor packet trailing JSON refused")
	}
	if err := validateOrderedCurrentPrivateSuccessorPacket(packet); err != nil {
		return orderedCurrentPrivateSuccessorPacket{}, err
	}
	return packet, nil
}

func validateOrderedCurrentPrivateSuccessorPacket(packet orderedCurrentPrivateSuccessorPacket) error {
	if packet.Format != "ordered-current-private-successor-capture-v1" || packet.Status != "NATIVE-UNVERIFIED" || packet.Installable || packet.CaptureStatus != "NOT-CAPTURED" || packet.SourceAuthority != "accepted-recovery80-source-2ca-private57-capture-only" || packet.Namespace != "zasp_authorization80_ordered_current" {
		return errors.New("private-successor packet envelope refused")
	}
	if packet.SourcePins.CompilerArtifactSHA256 != "2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c" || packet.SourcePins.CompilerChecksum != "f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214" || packet.SourcePins.CompiledSourceSHA256 != "e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e" || packet.SourcePins.SourceContractSHA256 != "02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb" || packet.SourcePins.CatalogSHA256 != "9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df" {
		return errors.New("private-successor packet source pins refused")
	}
	if !reflect.DeepEqual(packet.HelperPins, map[string]string{
		"0080_authorization_worker_ordered_current_integrity.sql": "d42d975c4b9cbadf7c5b368d4f14b361cd917c65a114d9629307e73af3021e5f",
		"ordered-current-private.mjs":                             "bf436fea1d3d01364bebb80881b5872321ddfe79663c614066344eeb8a059c70",
		"ordered-current-direct-frame-v1.mjs":                     "4c15aee77f9a6d00d8c63a969487dbe9f2d024db0b0f3814aab76424fc9a533b",
		"ordered-current-deparse-frame.mjs":                       "1d84ec51e1f700ff96e84306fe606cb31279bf74bc709b3ff78f80644b8f007a",
		"build-ordered-current-integrity.mjs":                     "8f8612374b72f0b5a8c3f56b1411d2a1428227ab4675395b909829040bef82ed",
		"ordered-current-catalog.mjs":                             "90a2b21bd268ccaacbec3a0e4684486baebb5ca5c2aff2e42e2a69c15170e820",
		"ordered-current-static-catalog.mjs":                      "1512b45520124977b8b3ef09b57acf19e31a9c5db31ca54d139c218ec56aa3f6",
	}) {
		return errors.New("private-successor helper pins refused")
	}
	if packet.Database.ServerVersionNum != "180003" || packet.Database.Pgcrypto != "1.4" || packet.Database.Variant != "A" || packet.Database.SessionUser != "zasp_test" || packet.Database.RequiredRole != "zasp_discovery_authority" || !reflect.DeepEqual(packet.Database.RequiredSearchPath, []string{"pg_catalog"}) || packet.Database.RequiredTimeZone != "UTC" || packet.Database.Postgres == "" {
		return errors.New("private-successor database pin refused")
	}
	if packet.Counts.Rules != 11 || packet.Counts.Rows != 57 || packet.Counts.RoutineRows != 22 || packet.Counts.NonroutineRows != 35 || packet.Limits.MaxRows != 57 || packet.Limits.MaxBytes != 16*1024*1024 || packet.Limits.OuterSeconds != 30 || packet.Limits.SQLSeconds != 10 || packet.Limits.LockSeconds != 3 || packet.Limits.CleanupSeconds != 3 || len(packet.Rules) != 11 || len(packet.ExpectedRoutineFacts) != 22 {
		return errors.New("private-successor packet bounds refused")
	}
	if packet.DDL.SHA256 != "fc7aacc36a9a09fb86c181d531a35c34a06adeabdcd1a1289fdaf2a53bb5b724" || digestOrderedCurrentPrivateSuccessorBytes([]byte(packet.DDL.SQL)) != packet.DDL.SHA256 || packet.DDL.AssemblySHA256 != "654e2e1e2e445b4cee82a5cbbb5fe01b5ad1093a23650f4333c5ea1813d66845" || packet.DDL.TemplateSHA256 == "" || packet.DDL.EmbeddedExpectations || packet.Collector.SHA256 != "6fc2919ef45388b119126a5745dc477a990af953b63e05cbd5fd90991b7a5a8c" || digestOrderedCurrentPrivateSuccessorBytes([]byte(packet.Collector.SQL)) != packet.Collector.SHA256 || !packet.Collector.Unbounded || packet.Collector.Ordering != "capture-bag-normalized-only-after-complete-validation" {
		return errors.New("private-successor SQL pin refused")
	}
	if err := validateOrderedCurrentPrivateSuccessorShape(packet); err != nil {
		return err
	}
	if !reflect.DeepEqual(packet.Witnesses, []string{"original-source2ca-admission", "private-namespace-absent-before", "collector-frame", "private-tables-empty", "complete-57-row-stream", "22-routine-source-parity", "write-rollback", "write-frame-restored", "private-namespace-absent-after-write", "read-only-post-admission", "read-rollback", "final-frame-restored", "private-namespace-absent-final", "exclusive-0600-publication"}) || packet.Output.Format != "ordered-current-private-successor-reference-v1" || packet.Output.Status != "LOCAL-REFERENCE-ONLY" || packet.Output.Installable || packet.Output.CaptureStatus != "CAPTURED-UNBOUND" || packet.Output.Publication != "root-binds-fixed-file-after-independent-review" {
		return errors.New("private-successor output gate refused")
	}
	return nil
}

func validateOrderedCurrentPrivateSuccessorShape(packet orderedCurrentPrivateSuccessorPacket) error {
	expected := []struct {
		id, kind string
		rows     int
	}{{"private-routines", "routine", 22}, {"private-namespace", "namespace", 1}, {"private-relation", "relation", 4}, {"private-column", "column", 10}, {"private-constraint", "constraint", 14}, {"private-index", "index", 2}, {"private-policy", "policy", 0}, {"private-trigger", "trigger", 0}, {"private-view", "view", 0}, {"private-rewrite", "rewrite", 0}, {"private-type", "type", 4}}
	for index, want := range expected {
		rule := packet.Rules[index]
		if rule.ID != want.id || rule.Kind != want.kind || !reflect.DeepEqual(rule.Namespaces, []string{"zasp_authorization80_ordered_current"}) || len(rule.Identities) != 0 || len(rule.Fields) == 0 || packet.Shape.RuleMaxRows[rule.ID] != want.rows || packet.Shape.CategoryMaxRows[rule.Kind] != want.rows || len(packet.Shape.FieldTypes[rule.Kind]) != len(rule.Fields) {
			return fmt.Errorf("private-successor rule refused: %s", want.id)
		}
		for _, field := range rule.Fields {
			if packet.Shape.FieldTypes[rule.Kind][field] == "" {
				return fmt.Errorf("private-successor field type refused: %s", field)
			}
		}
	}
	if len(packet.Shape.CategoryMaxRows) != 11 || len(packet.Shape.RuleMaxRows) != 11 || len(packet.Shape.FieldTypes) != 11 {
		return errors.New("private-successor shape cardinality refused")
	}
	for _, raw := range packet.ExpectedRoutineFacts {
		var row orderedCurrentPrivateSuccessorRow
		if err := decodeOrderedCurrentPrivateSuccessorJSON(raw, &row); err != nil {
			return fmt.Errorf("private-successor routine expectation refused: decode %w", err)
		}
		if row.Kind != "routine" || !orderedCurrentPrivateSuccessorCanonicalIdentity(row.Identity) || !orderedCurrentPrivateSuccessorFactTypes(row.Fact, packet.Rules[0].Fields, packet.Shape.FieldTypes["routine"]) {
			return fmt.Errorf("private-successor routine expectation refused: kind=%q identity=%q fact=%#v", row.Kind, row.Identity, row.Fact)
		}
	}
	return nil
}

type orderedCurrentPrivateSuccessorFrame struct {
	SessionUser, Role, SearchPath, TimeZone, Postgres, ServerVersionNum, Pgcrypto string
	ReadOnly                                                                      bool
}

type orderedCurrentPrivateSuccessorBoundaryIO struct {
	Original                  orderedCurrentPrivateSuccessorFrame
	Rows                      []json.RawMessage
	Empty, Admitted, Restored bool
	CollectErr, RollbackErr   error
}

type orderedCurrentPrivateSuccessorBoundaryResult struct {
	Facts                 []json.RawMessage
	ValidatedRoutineCount int
	Installable           bool
	CaptureStatus         string
}

func runOrderedCurrentPrivateSuccessorBoundary(parent context.Context, packet orderedCurrentPrivateSuccessorPacket, io orderedCurrentPrivateSuccessorBoundaryIO) (orderedCurrentPrivateSuccessorBoundaryResult, error) {
	var result orderedCurrentPrivateSuccessorBoundaryResult
	if parent == nil {
		return result, errors.New("private-successor boundary context refused")
	}
	ctx, cancel := context.WithTimeout(parent, 30*1e9)
	defer cancel()
	original := io.Original
	if ctx.Err() != nil || original.SessionUser != "zasp_test" || original.Role != "zasp_test" || original.ReadOnly || original.Postgres != packet.Database.Postgres || original.ServerVersionNum != "180003" || original.Pgcrypto != "1.4" || !io.Admitted || !io.Empty {
		return result, errors.New("private-successor preflight refused")
	}
	if io.CollectErr != nil || io.RollbackErr != nil {
		return result, errors.New("private-successor stream or rollback refused")
	}
	if !io.Restored {
		return result, errors.New("private-successor restoration refused")
	}
	rows, facts, err := validateOrderedCurrentPrivateSuccessorRows(packet, io.Rows)
	if err != nil || rows != 57 || ctx.Err() != nil {
		return result, errors.New("private-successor capture refused")
	}
	return orderedCurrentPrivateSuccessorBoundaryResult{Facts: facts, ValidatedRoutineCount: 22, Installable: false, CaptureStatus: "CAPTURED-UNBOUND"}, nil
}

func validateOrderedCurrentPrivateSuccessorRows(packet orderedCurrentPrivateSuccessorPacket, source []json.RawMessage) (int, []json.RawMessage, error) {
	if len(source) != packet.Limits.MaxRows {
		return 0, nil, errors.New("private-successor row cardinality")
	}
	rules := make(map[string]orderedCurrentPrivateSuccessorRule, len(packet.Rules))
	for _, rule := range packet.Rules {
		rules[rule.ID] = rule
	}
	seen, categoryCounts, ruleCounts := map[string]bool{}, map[string]int{}, map[string]int{}
	routine, nonroutine := []json.RawMessage{}, []json.RawMessage{}
	for _, raw := range source {
		var row orderedCurrentPrivateSuccessorRow
		if err := decodeOrderedCurrentPrivateSuccessorJSON(raw, &row); err != nil || !orderedCurrentPrivateSuccessorCanonicalIdentity(row.Identity) || seen[row.Identity] {
			return 0, nil, errors.New("private-successor row envelope")
		}
		seen[row.Identity] = true
		var key []string
		if err := json.Unmarshal([]byte(row.Identity), &key); err != nil || len(key) != 2 {
			return 0, nil, errors.New("private-successor row identity")
		}
		rule, ok := rules[key[0]]
		if !ok || row.Kind != rule.Kind || !orderedCurrentPrivateSuccessorFactTypes(row.Fact, rule.Fields, packet.Shape.FieldTypes[rule.Kind]) {
			return 0, nil, errors.New("private-successor row fields")
		}
		categoryCounts[row.Kind]++
		ruleCounts[rule.ID]++
		if row.Kind == "routine" {
			routine = append(routine, raw)
		} else {
			nonroutine = append(nonroutine, append(json.RawMessage{}, raw...))
		}
	}
	for kind, want := range packet.Shape.CategoryMaxRows {
		if categoryCounts[kind] != want {
			return 0, nil, errors.New("private-successor category count")
		}
	}
	for id, want := range packet.Shape.RuleMaxRows {
		if ruleCounts[id] != want {
			return 0, nil, errors.New("private-successor rule count")
		}
	}
	if len(routine) != 22 || !orderedCurrentPrivateSuccessorRoutineParity(routine, packet.ExpectedRoutineFacts) || len(nonroutine) != 35 {
		return 0, nil, errors.New("private-successor routine parity")
	}
	return len(source), nonroutine, nil
}

func orderedCurrentPrivateSuccessorCanonicalIdentity(value string) bool {
	var key []string
	if json.Unmarshal([]byte(value), &key) != nil || len(key) != 2 || key[0] == "" || key[1] == "" {
		return false
	}
	raw, err := json.Marshal(key)
	return err == nil && string(raw) == value
}

func orderedCurrentPrivateSuccessorFactTypes(fact map[string]any, fields []string, types map[string]string) bool {
	if len(fact) != len(fields) {
		return false
	}
	for _, field := range fields {
		value, ok := fact[field]
		if !ok || !orderedCurrentPrivateSuccessorValueType(value, types[field]) {
			return false
		}
	}
	return true
}

func orderedCurrentPrivateSuccessorValueType(value any, kind string) bool {
	if value == nil {
		return true
	}
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		parsed, err := number.Float64()
		return err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		parsed, err := strconv.ParseInt(number.String(), 10, 64)
		return err == nil && parsed >= -(1<<53-1) && parsed <= 1<<53-1
	case "array":
		_, ok := value.([]any)
		return ok
	case "acl":
		if _, ok := value.([]any); ok {
			return true
		}
		_, ok := value.(string)
		return ok
	default:
		return false
	}
}

func orderedCurrentPrivateSuccessorRoutineParity(left, right []json.RawMessage) bool {
	if len(left) != len(right) {
		return false
	}
	byIdentity := map[string]json.RawMessage{}
	for _, raw := range right {
		var row orderedCurrentPrivateSuccessorRow
		if decodeOrderedCurrentPrivateSuccessorJSON(raw, &row) != nil || byIdentity[row.Identity] != nil {
			return false
		}
		byIdentity[row.Identity] = raw
	}
	for _, raw := range left {
		var row orderedCurrentPrivateSuccessorRow
		if decodeOrderedCurrentPrivateSuccessorJSON(raw, &row) != nil || !orderedCurrentPrivateSuccessorJSONEqual(raw, byIdentity[row.Identity]) {
			return false
		}
	}
	return true
}

func orderedCurrentPrivateSuccessorJSONEqual(left, right []byte) bool {
	decode := func(raw []byte) (any, error) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, errors.New("trailing JSON")
		}
		return value, nil
	}
	a, leftErr := decode(left)
	b, rightErr := decode(right)
	return leftErr == nil && rightErr == nil && reflect.DeepEqual(a, b)
}

func admitOrderedCurrentPrivateSuccessorReference(_ []byte) error {
	return errors.New("private-successor captured-file authority unavailable until root binds a reviewed native artifact")
}

// TestP7OrderedCurrentPrivateSuccessorCapture is deliberately opt-in. Its output
// remains local-reference-only: the unbound intake above cannot turn this run
// into generator or expected-fact authority.
func TestP7OrderedCurrentPrivateSuccessorCapture(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_PRIVATE_SUCCESSOR_CAPTURE") == "" {
		t.Skip("explicit private-successor native capture required")
	}
	if os.Getenv("ZASP_ORDERED_PRIVATE_SUCCESSOR_CAPTURE") != "1" {
		t.Fatal("private-successor native capture mode refused")
	}
	for _, name := range []string{"ZASP_ORDERED_PRIVATE_REFERENCE", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_CAPTURE", "ZASP_ORDERED_MISSING_REFERENCE_NATIVE"} {
		if os.Getenv(name) != "" {
			t.Fatal("private-successor capture overlaps another capture mode")
		}
	}
	output := os.Getenv("ZASP_ORDERED_PRIVATE_SUCCESSOR_OUTPUT")
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		t.Fatal("private-successor output must be a new absolute path")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("private-successor output already exists")
	}
	raw, err := os.ReadFile(orderedCurrentPrivateSuccessorPacketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := decodeOrderedCurrentPrivateSuccessorPacket(raw, orderedCurrentPrivateSuccessorPacketSHA256)
	if err != nil {
		t.Fatal(err)
	}
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, orderedCurrentPrivateSuccessorCatalogCapture(packet, raw, output), nil)
}

func orderedCurrentPrivateSuccessorCatalogCapture(packet orderedCurrentPrivateSuccessorPacket, packetRaw []byte, output string) ordered68CatalogCapture {
	return func(t *testing.T, parent context.Context, owner *pgx.Conn) bool {
		t.Helper()
		captured, err := captureOrderedCurrentPrivateSuccessor(t, parent, owner, packet)
		if err != nil {
			t.Fatal("private-successor capture refused")
		}
		if parent.Err() != nil {
			t.Fatal("private-successor capture cancelled before publication")
		}
		payload, err := marshalOrderedCurrentPrivateSuccessorReference(packet, packetRaw, captured)
		if err != nil {
			t.Fatal("private-successor reference envelope refused")
		}
		if err := publishOrderedCurrentPrivateSuccessorReference(parent, output, payload, packet.Limits.MaxBytes); err != nil {
			t.Fatal("private-successor publication refused")
		}
		t.Log("private-successor rollback-only capture completed", "rows", len(captured.Rows), "routineParity", 22, "freshNonroutine", 35)
		return true
	}
}

type orderedCurrentPrivateSuccessorNativeCapture struct {
	Rows      []json.RawMessage
	Original  orderedCurrentPrivateSuccessorFrame
	Collector orderedCurrentPrivateSuccessorFrame
}

func captureOrderedCurrentPrivateSuccessor(t *testing.T, parent context.Context, owner *pgx.Conn, packet orderedCurrentPrivateSuccessorPacket) (result orderedCurrentPrivateSuccessorNativeCapture, err error) {
	if parent == nil || owner == nil {
		return result, errors.New("private-successor connection refused")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(packet.Limits.OuterSeconds)*time.Second)
	defer cancel()
	original, err := orderedCurrentPrivateSuccessorFrameFrom(ctx, owner)
	if err != nil || !orderedCurrentPrivateSuccessorOriginalFrame(packet, original) || orderedCurrentPrivateSuccessorAdmission(ctx, owner, packet) != nil || orderedCurrentPrivateSuccessorNamespaceAbsent(ctx, owner) != nil {
		return result, errors.New("private-successor original witnesses refused")
	}
	tx, err := owner.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		return result, errors.New("private-successor write begin refused")
	}
	active := true
	rollback := func() error {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(packet.Limits.CleanupSeconds)*time.Second)
		defer done()
		active = false
		return tx.Rollback(cleanup)
	}
	defer func() {
		if active {
			if rollbackErr := rollback(); rollbackErr != nil {
				err = errors.Join(err, errors.New("private-successor cleanup rollback refused"))
			}
		}
		if err != nil {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(packet.Limits.CleanupSeconds)*time.Second)
			defer done()
			if owner.Close(cleanup) != nil {
				err = errors.Join(err, errors.New("private-successor connection disposal refused"))
			}
		}
	}()
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'; SELECT pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0))`); err != nil || orderedCurrentPrivateSuccessorAdmission(ctx, tx, packet) != nil || orderedCurrentPrivateSuccessorNamespaceAbsent(ctx, tx) != nil {
		return result, errors.New("private-successor write preflight refused")
	}
	if _, err = tx.Exec(ctx, packet.DDL.SQL); err != nil {
		return result, errors.New("private-successor DDL refused")
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		return result, errors.New("private-successor collector role refused")
	}
	collector, err := orderedCurrentPrivateSuccessorFrameFrom(ctx, tx)
	if err != nil || !orderedCurrentPrivateSuccessorCollectorFrame(packet, original, collector) || orderedCurrentPrivateSuccessorTablesEmpty(ctx, tx) != nil {
		return result, errors.New("private-successor collector witnesses refused")
	}
	rows, err := tx.Query(ctx, packet.Collector.SQL)
	if err != nil {
		return result, errors.New("private-successor collector query refused")
	}
	captured := make([]json.RawMessage, 0, packet.Limits.MaxRows)
	bytes := 0
	for rows.Next() {
		var kind, identity string
		var fact json.RawMessage
		if err := rows.Scan(&kind, &identity, &fact); err != nil {
			rows.Close()
			return result, errors.New("private-successor row scan refused")
		}
		raw, encodeErr := json.Marshal(orderedCurrentPrivateSuccessorRow{Kind: kind, Identity: identity, Fact: orderedCurrentPrivateSuccessorDecodeFact(fact)})
		if encodeErr != nil || len(captured) >= packet.Limits.MaxRows || bytes+len(raw) > packet.Limits.MaxBytes || ctx.Err() != nil {
			rows.Close()
			return result, errors.New("private-successor row stream bounds refused")
		}
		captured = append(captured, raw)
		bytes += len(raw)
	}
	if rows.Err() != nil {
		rows.Close()
		return result, errors.New("private-successor row iteration refused")
	}
	rows.Close()
	if _, _, err = validateOrderedCurrentPrivateSuccessorRows(packet, captured); err != nil || ctx.Err() != nil {
		return result, errors.New("private-successor row validation refused")
	}
	if err = rollback(); err != nil {
		return result, errors.New("private-successor write rollback refused")
	}
	restored, frameErr := orderedCurrentPrivateSuccessorFrameFrom(ctx, owner)
	if frameErr != nil || restored != original || orderedCurrentPrivateSuccessorNamespaceAbsent(ctx, owner) != nil {
		return result, errors.New("private-successor write restoration refused")
	}
	readTx, beginErr := owner.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if beginErr != nil {
		return result, errors.New("private-successor read begin refused")
	}
	if _, err = readTx.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'`); err != nil {
		_ = readTx.Rollback(context.WithoutCancel(ctx))
		return result, errors.New("private-successor read frame refused")
	}
	readFrame, frameErr := orderedCurrentPrivateSuccessorFrameFrom(ctx, readTx)
	if frameErr != nil || !orderedCurrentPrivateSuccessorReadFrame(packet, original, readFrame) || orderedCurrentPrivateSuccessorAdmission(ctx, readTx, packet) != nil {
		_ = readTx.Rollback(context.WithoutCancel(ctx))
		return result, errors.New("private-successor post-admission refused")
	}
	cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(packet.Limits.CleanupSeconds)*time.Second)
	readRollbackErr := readTx.Rollback(cleanup)
	done()
	if readRollbackErr != nil {
		return result, errors.New("private-successor read rollback refused")
	}
	final, frameErr := orderedCurrentPrivateSuccessorFrameFrom(ctx, owner)
	if frameErr != nil || final != original || orderedCurrentPrivateSuccessorNamespaceAbsent(ctx, owner) != nil || ctx.Err() != nil {
		return result, errors.New("private-successor final restoration refused")
	}
	return orderedCurrentPrivateSuccessorNativeCapture{Rows: captured, Original: original, Collector: collector}, nil
}

type orderedCurrentPrivateSuccessorQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func orderedCurrentPrivateSuccessorFrameFrom(ctx context.Context, queryer orderedCurrentPrivateSuccessorQueryer) (orderedCurrentPrivateSuccessorFrame, error) {
	var frame orderedCurrentPrivateSuccessorFrame
	err := queryer.QueryRow(ctx, `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),pg_catalog.version(),current_setting('server_version_num'),(SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),current_setting('transaction_read_only')='on'`).Scan(&frame.SessionUser, &frame.Role, &frame.SearchPath, &frame.TimeZone, &frame.Postgres, &frame.ServerVersionNum, &frame.Pgcrypto, &frame.ReadOnly)
	return frame, err
}

func orderedCurrentPrivateSuccessorAdmission(ctx context.Context, queryer orderedCurrentPrivateSuccessorQueryer, packet orderedCurrentPrivateSuccessorPacket) error {
	var admitted bool
	err := queryer.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND to_regnamespace('zasp_authorization80_identity') IS NULL FROM zasp_authorization80_worker.registration`, packet.SourcePins.CompilerChecksum).Scan(&admitted)
	if err != nil || !admitted {
		return errors.New("private-successor source2ca admission")
	}
	return nil
}

func orderedCurrentPrivateSuccessorNamespaceAbsent(ctx context.Context, queryer orderedCurrentPrivateSuccessorQueryer) error {
	var absent bool
	if err := queryer.QueryRow(ctx, `SELECT to_regnamespace('zasp_authorization80_ordered_current') IS NULL`).Scan(&absent); err != nil || !absent {
		return errors.New("private-successor namespace absence")
	}
	return nil
}

func orderedCurrentPrivateSuccessorTablesEmpty(ctx context.Context, queryer orderedCurrentPrivateSuccessorQueryer) error {
	var empty bool
	if err := queryer.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_authorization80_ordered_current.expected) AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_ordered_current.registration)`).Scan(&empty); err != nil || !empty {
		return errors.New("private-successor private tables empty")
	}
	return nil
}

func orderedCurrentPrivateSuccessorOriginalFrame(packet orderedCurrentPrivateSuccessorPacket, frame orderedCurrentPrivateSuccessorFrame) bool {
	return frame.SessionUser == packet.Database.SessionUser && frame.Role == packet.Database.SessionUser && !frame.ReadOnly && frame.Postgres == packet.Database.Postgres && frame.ServerVersionNum == packet.Database.ServerVersionNum && frame.Pgcrypto == packet.Database.Pgcrypto && frame.SearchPath != "" && frame.TimeZone != ""
}

func orderedCurrentPrivateSuccessorCollectorFrame(packet orderedCurrentPrivateSuccessorPacket, original, frame orderedCurrentPrivateSuccessorFrame) bool {
	return frame.SessionUser == original.SessionUser && frame.Role == packet.Database.RequiredRole && frame.SearchPath == "pg_catalog" && frame.TimeZone == packet.Database.RequiredTimeZone && !frame.ReadOnly && frame.Postgres == original.Postgres && frame.ServerVersionNum == original.ServerVersionNum && frame.Pgcrypto == original.Pgcrypto
}

func orderedCurrentPrivateSuccessorReadFrame(packet orderedCurrentPrivateSuccessorPacket, original, frame orderedCurrentPrivateSuccessorFrame) bool {
	return frame.SessionUser == original.SessionUser && frame.Role == original.Role && frame.SearchPath == "pg_catalog" && frame.TimeZone == packet.Database.RequiredTimeZone && frame.ReadOnly && frame.Postgres == original.Postgres && frame.ServerVersionNum == original.ServerVersionNum && frame.Pgcrypto == original.Pgcrypto
}

func orderedCurrentPrivateSuccessorDecodeFact(raw json.RawMessage) map[string]any {
	var fact map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&fact) != nil {
		return nil
	}
	return fact
}

func marshalOrderedCurrentPrivateSuccessorReference(packet orderedCurrentPrivateSuccessorPacket, packetRaw []byte, captured orderedCurrentPrivateSuccessorNativeCapture) ([]byte, error) {
	frame := func(value orderedCurrentPrivateSuccessorFrame) map[string]any {
		return map[string]any{"sessionUser": value.SessionUser, "role": value.Role, "searchPath": value.SearchPath, "timeZone": value.TimeZone, "postgres": value.Postgres, "serverVersionNum": value.ServerVersionNum, "pgcrypto": value.Pgcrypto, "readOnly": value.ReadOnly}
	}
	packetObject, err := orderedCurrentPrivateSuccessorPacketObjectBytes(packetRaw)
	if err != nil {
		return nil, err
	}
	envelope := map[string]any{
		"format": "ordered-current-private-successor-reference-v1", "status": "LOCAL-REFERENCE-ONLY", "installable": false, "captureStatus": "CAPTURED-UNBOUND", "variant": packet.Database.Variant, "sessionUser": packet.Database.SessionUser,
		"packetSHA256": digestOrderedCurrentPrivateSuccessorBytes(packetObject), "sourcePins": packet.SourcePins, "helperPins": packet.HelperPins, "ddlSHA256": packet.DDL.SHA256, "querySHA256": packet.Collector.SHA256,
		"postgres": packet.Database.Postgres, "serverVersionNum": packet.Database.ServerVersionNum, "pgcrypto": packet.Database.Pgcrypto, "originalFrame": frame(captured.Original), "collectorFrame": frame(captured.Collector),
		"readOnly": false, "originalAdmission": true, "writeRollback": true, "readOnlyPostAdmission": true, "postAdmission": true, "readRollback": true, "namespaceAbsent": true, "frameRestored": true, "expectedManifestRows": 0, "registrationRows": 0,
		"publication": map[string]any{"mode": "0600", "atomicNoOverwrite": true}, "rows": captured.Rows,
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(envelope); err != nil {
		return nil, errors.New("private-successor envelope encoding")
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func publishOrderedCurrentPrivateSuccessorReference(ctx context.Context, destination string, payload []byte, limit int) error {
	if ctx == nil || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || len(payload) == 0 || len(payload)+1 > limit || ctx.Err() != nil {
		return errors.New("private-successor publication preflight")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return errors.New("private-successor publication destination")
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".ordered-current-private-successor-")
	if err != nil {
		return errors.New("private-successor publication temporary")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	defer temporary.Close()
	raw := append(append([]byte{}, payload...), '\n')
	for start := 0; start < len(raw); start += 64 * 1024 {
		if ctx.Err() != nil {
			return errors.New("private-successor publication cancelled")
		}
		end := start + 64*1024
		if end > len(raw) {
			end = len(raw)
		}
		if written, writeErr := temporary.Write(raw[start:end]); writeErr != nil || written != end-start {
			return errors.New("private-successor publication write")
		}
	}
	if ctx.Err() != nil || temporary.Chmod(0o600) != nil || temporary.Sync() != nil || temporary.Close() != nil || ctx.Err() != nil {
		return errors.New("private-successor publication finish")
	}
	if err := os.Link(temporaryName, destination); err != nil {
		return errors.New("private-successor publication commit")
	}
	return nil
}
