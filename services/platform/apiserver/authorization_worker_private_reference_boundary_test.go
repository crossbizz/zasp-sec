package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

const privateReferenceContractSHA = "df377d893445cf178ec90f99f77db865e40ca203fb24f9215f0cb0c53cfcf05a"
const privateReferenceDDLSHA = "2593fe67d2904f28201b922e0ef83b083419e7958a9c85f8151b08bea988b64c"
const privateReferenceQuerySHA = "05d720b0af774b6e0292453b7829f4a2d64faf3a8b51f3224101fd3f041860b8"
const privateReferenceSnapshotSHA = "4d5e01ce253ee2aac1341f40756ebd41054e6e5359079520759712bcd342078b"
const privateReferenceNamespace = "zasp_authorization80_ordered_current"

type privateReferenceContract struct {
	Shape                                orderedSupplementShape
	Routines                             []json.RawMessage
	Postgres, ServerVersionNum, Pgcrypto string
}
type privateReferenceIO struct {
	Begin     func(context.Context, bool) error
	Exec      func(context.Context, string) error
	Frame     func(context.Context) (orderedSupplementFrame, error)
	Admission func(context.Context) error
	Absent    func(context.Context) error
	Empty     func(context.Context) error
	Collect   func(context.Context, func(json.RawMessage) error) error
	Rollback  func(context.Context) error
	Dispose   func(context.Context) error
}
type privateReferenceResult struct {
	Rows                []json.RawMessage
	Original, Collector orderedSupplementFrame
}

func privateReferenceRefusal(stage string) error {
	return errors.New("private reference refused: " + stage)
}

func verifyPrivateReferenceInput(contract, ddl, query []byte) (privateReferenceContract, error) {
	var result privateReferenceContract
	for _, pin := range []struct {
		raw []byte
		sha string
	}{{contract, privateReferenceContractSHA}, {ddl, privateReferenceDDLSHA}, {query, privateReferenceQuerySHA}} {
		if len(pin.raw) == 0 || len(pin.raw) > 1024*1024 || supplementSHA(pin.raw) != pin.sha {
			return result, privateReferenceRefusal("input pin")
		}
	}
	// Whole-file independent pins bind every provenance field and selector. Decode
	// only the capture contract; no mutable live result can supply these facts.
	var object map[string]json.RawMessage
	if supplementJSON(contract, &object) != nil {
		return result, privateReferenceRefusal("contract JSON")
	}
	var c struct {
		Format, Status, Namespace, DDLSHA256, QuerySHA256, CompilerChecksum, CompiledSourceSHA256, CompilerArtifactSHA256, SourceContractSHA256, Catalog1FileSHA256, SupplementaryReferenceFileSHA256 string
		ReferencePostgres, ServerVersionNum, Pgcrypto, RequiredRole, RequiredTimeZone                                                                                                                 string
		RequiredSearchPath                                                                                                                                                                            []string
		MaxRows, MaxBytes, ExpectedManifestRows, RegistrationRows                                                                                                                                     int
		CategoryMaxRows, RuleMaxRows                                                                                                                                                                  map[string]int
		Rules                                                                                                                                                                                         []struct {
			ID, Kind                       string
			Fields, Namespaces, Identities []string
		}
		FieldTypes           map[string]map[string]string
		ExpectedRoutineFacts []json.RawMessage
	}
	if json.Unmarshal(contract, &c) != nil || c.Format != "ordered-current-private-reference-query-v1" || c.Status != "REFERENCE-CAPTURE-ONLY" || c.Namespace != privateReferenceNamespace || c.DDLSHA256 != privateReferenceDDLSHA || c.QuerySHA256 != privateReferenceQuerySHA || c.CompilerChecksum != supplementChecksum || c.CompiledSourceSHA256 != supplementCompiledSourceSHA || c.CompilerArtifactSHA256 != supplementCompilerSHA || c.SourceContractSHA256 != supplementSourceContractSHA || c.Catalog1FileSHA256 != supplementCatalogSHA || c.SupplementaryReferenceFileSHA256 != "c544ae4e6d04907a20879d359d875135658a7a582f16a27d3263f0bc9c91edb4" || c.RequiredRole != "zasp_discovery_authority" || !reflect.DeepEqual(c.RequiredSearchPath, []string{"pg_catalog"}) || c.RequiredTimeZone != "UTC" || c.MaxRows != 39 || c.MaxBytes != 16777216 || len(c.Rules) != 11 || len(c.ExpectedRoutineFacts) != 4 || c.ExpectedManifestRows != 0 || c.RegistrationRows != 0 || c.ReferencePostgres == "" || c.ServerVersionNum != "180003" || c.Pgcrypto != "1.4" {
		return result, privateReferenceRefusal("contract shape")
	}
	result = privateReferenceContract{Routines: c.ExpectedRoutineFacts, Postgres: c.ReferencePostgres, ServerVersionNum: c.ServerVersionNum, Pgcrypto: c.Pgcrypto, Shape: orderedSupplementShape{Fields: c.FieldTypes, CategoryMaxRows: c.CategoryMaxRows, RuleMaxRows: c.RuleMaxRows, MaxRows: c.MaxRows, MaxBytes: c.MaxBytes}}
	for _, r := range c.Rules {
		if !reflect.DeepEqual(r.Namespaces, []string{privateReferenceNamespace}) || len(r.Identities) != 0 {
			return privateReferenceContract{}, privateReferenceRefusal("rule scope")
		}
		result.Shape.Rules = append(result.Shape.Rules, orderedSupplementRule{ID: r.ID, Kind: r.Kind, Fields: r.Fields})
	}
	if checkPrivateReferenceRoutineRows(result, result.Routines) != nil {
		return privateReferenceContract{}, privateReferenceRefusal("routine contract")
	}
	return result, nil
}

func checkPrivateReferenceRows(c privateReferenceContract, rows []json.RawMessage) error {
	if checkPrivateReferenceRoutineRows(c, rows) != nil {
		return privateReferenceRefusal("rows")
	}
	// These are declaration-derived counts from the independently pinned packet,
	// not target-derived expectations. A partial catalog is never a reference.
	categories, rules := map[string]int{}, map[string]int{}
	for _, raw := range rows {
		var row struct {
			Kind, Identity string
			Fact           map[string]json.RawMessage
		}
		if supplementJSON(raw, &row) != nil {
			return privateReferenceRefusal("row JSON")
		}
		var key []string
		if supplementJSON([]byte(row.Identity), &key) != nil || len(key) != 2 {
			return privateReferenceRefusal("row identity")
		}
		categories[row.Kind]++
		rules[key[0]]++
	}
	if len(rows) != c.Shape.MaxRows {
		return privateReferenceRefusal("catalog cardinality")
	}
	for kind, count := range c.Shape.CategoryMaxRows {
		if categories[kind] != count {
			return privateReferenceRefusal("category cardinality")
		}
	}
	for rule, count := range c.Shape.RuleMaxRows {
		if rules[rule] != count {
			return privateReferenceRefusal("rule cardinality")
		}
	}
	return nil
}

func checkPrivateReferenceRoutineRows(c privateReferenceContract, rows []json.RawMessage) error {
	if len(c.Routines) != 4 || checkOrderedSupplementRows(c.Shape, rows) != nil {
		return privateReferenceRefusal("rows")
	}
	expected := map[string]any{}
	for _, raw := range c.Routines {
		var row struct {
			Kind, Identity string
			Fact           map[string]any
		}
		if supplementJSON(raw, &row) != nil || row.Kind != "routine" || expected[row.Identity] != nil {
			return privateReferenceRefusal("expected routine")
		}
		expected[row.Identity] = row.Fact
	}
	found := 0
	for _, raw := range rows {
		var row struct {
			Kind, Identity string
			Fact           map[string]any
		}
		if supplementJSON(raw, &row) != nil {
			return privateReferenceRefusal("row JSON")
		}
		if row.Kind == "routine" {
			if !reflect.DeepEqual(row.Fact, expected[row.Identity]) {
				return privateReferenceRefusal("routine fact")
			}
			found++
		}
	}
	if found != 4 {
		return privateReferenceRefusal("routine cardinality")
	}
	return nil
}

func runPrivateReferenceBoundary(ctx context.Context, c privateReferenceContract, ddl string, io privateReferenceIO) (result privateReferenceResult, err error) {
	if ctx == nil || io.Begin == nil || io.Exec == nil || io.Frame == nil || io.Admission == nil || io.Absent == nil || io.Empty == nil || io.Collect == nil || io.Rollback == nil || io.Dispose == nil {
		return result, privateReferenceRefusal("dependencies")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = bounded
	active := false
	rollback := func() error {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		active = false
		if io.Rollback(cleanup) != nil {
			return privateReferenceRefusal("rollback")
		}
		return nil
	}
	defer func() {
		if active {
			err = errors.Join(err, rollback())
		}
		if err != nil {
			result = privateReferenceResult{}
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			if io.Dispose(cleanup) != nil {
				err = errors.Join(err, privateReferenceRefusal("dispose"))
			}
		}
	}()
	if ctx.Err() != nil || ddl == "" || checkPrivateReferenceRoutineRows(c, c.Routines) != nil {
		return result, privateReferenceRefusal("initial contract")
	}
	original, e := io.Frame(ctx)
	if e != nil || original.Session != "zasp_test" || original.Role != "zasp_test" || original.ReadOnly || original.Postgres != c.Postgres || original.ServerVersionNum != c.ServerVersionNum || original.Pgcrypto != c.Pgcrypto {
		return result, privateReferenceRefusal("original frame")
	}
	if io.Begin(ctx, false) != nil {
		return result, privateReferenceRefusal("write begin")
	}
	active = true
	const configure = `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'; SELECT pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0))`
	if io.Exec(ctx, configure) != nil || io.Admission(ctx) != nil || io.Absent(ctx) != nil {
		return result, privateReferenceRefusal("pre-admission")
	}
	if io.Exec(ctx, ddl) != nil || io.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`) != nil {
		return result, privateReferenceRefusal("reference DDL")
	}
	collector, e := io.Frame(ctx)
	want := original
	want.Role = "zasp_discovery_authority"
	want.SearchPath = "pg_catalog"
	want.TimeZone = "UTC"
	want.ReadOnly = false
	if e != nil || collector != want || io.Empty(ctx) != nil {
		return result, privateReferenceRefusal("collector frame/tables")
	}
	rows := []json.RawMessage{}
	size := 0
	var emitErr error
	collectErr := io.Collect(ctx, func(raw json.RawMessage) error {
		if emitErr != nil {
			return emitErr
		}
		size += len(raw)
		if ctx.Err() != nil || size > c.Shape.MaxBytes || len(rows) >= c.Shape.MaxRows || checkOrderedSupplementRows(c.Shape, []json.RawMessage{raw}) != nil {
			emitErr = privateReferenceRefusal("stream bounds")
			return emitErr
		}
		rows = append(rows, append(json.RawMessage{}, raw...))
		return nil
	})
	if collectErr != nil || emitErr != nil || ctx.Err() != nil || checkPrivateReferenceRows(c, rows) != nil {
		return result, privateReferenceRefusal("capture")
	}
	if e := rollback(); e != nil {
		return result, e
	}
	// Read-back after rollback is separate from the transaction that created the
	// namespace. Neither source facts nor original readiness run through new code.
	restored, e := io.Frame(ctx)
	if e != nil || restored != original || io.Absent(ctx) != nil {
		return result, privateReferenceRefusal("write restoration")
	}
	if io.Begin(ctx, true) != nil {
		return result, privateReferenceRefusal("read begin")
	}
	active = true
	if io.Exec(ctx, configure) != nil {
		return result, privateReferenceRefusal("read configuration")
	}
	readFrame, e := io.Frame(ctx)
	want = original
	want.ReadOnly = true
	want.SearchPath = "pg_catalog"
	want.TimeZone = "UTC"
	if e != nil || readFrame != want || io.Admission(ctx) != nil {
		return result, privateReferenceRefusal("post-admission")
	}
	if e := rollback(); e != nil {
		return result, e
	}
	restored, e = io.Frame(ctx)
	if e != nil || restored != original || io.Absent(ctx) != nil || ctx.Err() != nil {
		return result, privateReferenceRefusal("final restoration")
	}
	return privateReferenceResult{Rows: rows, Original: original, Collector: collector}, nil
}
