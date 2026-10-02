package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Replaced only after the new packet is frozen and independently hash checked.
const transformAcceptanceManifestSHA = "881b817cfe51b8587904c65a361114263bf5cae41bd0e42e8fa5e9a9156c5b3f"
const transformAcceptancePacketDirectory = "/private/tmp/zasp-transform-acceptance-packet.RInbhk"
const transformAcceptanceNode = "/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node"

// Exact build from the reviewed supplementary-query-contract3 requiredPostgres.
const transformAcceptancePostgres = "PostgreSQL 18.3 (Homebrew) on aarch64-apple-darwin25.2.0, compiled by Apple clang version 17.0.0 (clang-1700.6.3.2), 64-bit"
const transformAcceptanceBuilder = "services/platform/migrations/tools/build-ordered-current-transform-acceptance.mjs"

type transformAcceptancePacket struct {
	Format, Status, SourceContractSHA256                                        string
	MaxRows, MaxBytes, ObserverSeconds, SQLSeconds, LockSeconds, CleanupSeconds int
	Rules                                                                       []transformAcceptanceRule
	CompiledSQL, CompiledSHA256, RawSQL                                         string
	RawRules                                                                    []json.RawMessage
	Reserved                                                                    []string
	RawDisposition                                                              string
	Target                                                                      struct{ Identity, Definition, DefinitionSHA256 string }
	Cases                                                                       []transformAcceptanceCase
}
type transformAcceptanceInputs struct {
	Packet    transformAcceptancePacket
	Directory string
	Paths     []string
}

var transformAcceptanceOverlaps = []string{"ZASP_ORDERED_ENGINE_PREFLIGHT", "ZASP_P7_ORDERED_POLICY_CAPACITY", "ZASP_P7_ORDERED_POLICY_PREFIX", "ZASP_ORDERED_PRIVATE_REFERENCE_CAPTURE", "ZASP_ORDERED_REMAINING_REFERENCE", "ZASP_ORDERED_REMAINING_REFERENCE_DIR", "ZASP_ORDERED_REMAINING_REFERENCE_OUTPUT", "ZASP_ORDERED_PRIVATE_REFERENCE", "ZASP_ORDERED_PRIVATE_REFERENCE_DIR", "ZASP_ORDERED_PRIVATE_REFERENCE_OUTPUT", "ZASP_ORDERED_SUPPLEMENT_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_REFERENCE_DIR", "ZASP_ORDERED_SUPPLEMENT_OUTPUT", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", "ZASP_ORDERED_READINESS_ATTRIBUTION", "ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_READINESS_PLAN_OUTPUT", "ZASP_ORDERED_POLICY_CAPACITY", "ZASP_ORDERED_POLICY_PREFIX", "ZASP_P7_ORDERED69_RETIREMENT_ACL", "ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION", "ZASP_P7_ORDERED_BODY_CAPTURE", "ZASP_ORDERED62_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", "ZASP_ORDERED_POLICY_TRACE"}

func transformAcceptanceMode(value string, controls map[string]string) (bool, error) {
	if value == "" {
		return false, nil
	}
	if value != "1" {
		return false, supplementRefusal("transform mode")
	}
	for _, v := range controls {
		if v != "" {
			return false, supplementRefusal("transform overlap")
		}
	}
	return true, nil
}
func loadTransformAcceptance(directory string) (transformAcceptanceInputs, error) {
	var result transformAcceptanceInputs
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return result, supplementRefusal("transform directory")
	}
	raw, e := readOrderedSupplementFile(filepath.Join(directory, "snapshot-manifest.json"), 1024*1024)
	if e != nil || supplementSHA(raw) != transformAcceptanceManifestSHA {
		return result, supplementRefusal("transform manifest pin")
	}
	var manifest struct {
		Format int
		Files  map[string]string
	}
	if supplementJSON(raw, &manifest) != nil || manifest.Format != 1 || len(manifest.Files) != 15 {
		return result, supplementRefusal("transform manifest shape")
	}
	files := map[string][]byte{}
	for name, pin := range manifest.Files {
		if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.HasPrefix(name, "../") || name == ".." || len(name) > 512 {
			return result, supplementRefusal("transform path")
		}
		path := filepath.Join(directory, name)
		b, err := readOrderedSupplementFile(path, 32*1024*1024)
		if err != nil || supplementSHA(b) != pin {
			return result, supplementRefusal("transform file pin")
		}
		files[name] = b
		result.Paths = append(result.Paths, path)
	}
	result.Paths = append(result.Paths, filepath.Join(directory, "snapshot-manifest.json"))
	result.Directory = directory
	if supplementJSON(files["transform-acceptance.json"], &result.Packet) != nil {
		return transformAcceptanceInputs{}, supplementRefusal("transform packet JSON")
	}
	p := result.Packet
	if p.Format != "ordered-transform-acceptance-v1" || p.Status != "NATIVE-UNVERIFIED" || len(p.Rules) != 13 || len(p.Cases) != 19 || len(p.RawRules) != 13 || p.MaxRows != 380 || p.MaxBytes != 16777216 || p.ObserverSeconds != 30 || p.SQLSeconds != 10 || p.LockSeconds != 3 || p.CleanupSeconds != 3 || supplementSHA([]byte(p.CompiledSQL)) != p.CompiledSHA256 || p.SourceContractSHA256 != supplementSourceContractSHA || p.Target.Identity != "public.zasp_sa_multistep_live_fingerprint()" || supplementSHA([]byte(p.Target.Definition)) != p.Target.DefinitionSHA256 || !reflect.DeepEqual(p.Reserved, []string{"temporal77-demand-boundary"}) || len(files[transformAcceptanceBuilder]) == 0 {
		return transformAcceptanceInputs{}, supplementRefusal("transform packet contract")
	}
	return result, nil
}

func TestP7OrderedCurrentTransformAcceptance(t *testing.T) {
	controls := map[string]string{}
	for _, k := range transformAcceptanceOverlaps {
		controls[k] = os.Getenv(k)
	}
	enabled, e := transformAcceptanceMode(os.Getenv("ZASP_ORDERED_TRANSFORM_ACCEPTANCE"), controls)
	if e != nil {
		t.Fatal(e)
	}
	if !enabled {
		t.Skip("explicit transform acceptance required")
	}
	directory := os.Getenv("ZASP_ORDERED_TRANSFORM_ACCEPTANCE_DIR")
	if _, e = loadTransformAcceptance(directory); e != nil {
		t.Fatal(e)
	}
	destination := os.Getenv("ZASP_ORDERED_TRANSFORM_ACCEPTANCE_OUTPUT")
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		t.Fatal("transform output path")
	}
	if _, e = os.Lstat(destination); !os.IsNotExist(e) {
		t.Fatal("new transform output required")
	}
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CAPTURE", "catalog")
	t.Setenv("ZASP_ORDERED_PREDECESSOR_RELEASE", filepath.Join(directory, remainingP7, "ordered-current-inventory-compiled.json"))
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", destination)
	runOrdered68PolicyBoundary(t, true, false, false)
	if t.Failed() {
		return
	}
	raw, e := readOrderedSupplementFile(destination, 16*1024*1024+1)
	var envelope map[string]json.RawMessage
	if e != nil || supplementJSON(raw, &envelope) != nil || string(envelope["format"]) != `"ordered-transform-acceptance-result-v1"` || string(envelope["packetManifestSHA256"]) != `"`+transformAcceptanceManifestSHA+`"` || string(envelope["completedCases"]) != "19" || string(envelope["restored"]) != "true" {
		t.Fatal("transform completion witness")
	}
}

func captureOrderedTransformAcceptanceOrPrevious(t *testing.T, ctx context.Context, owner *pgx.Conn, destination string) {
	t.Helper()
	if os.Getenv("ZASP_ORDERED_TRANSFORM_ACCEPTANCE") == "" {
		captureOrderedRemainingReferenceOrPrivate(t, ctx, owner, destination)
		return
	}
	if ctx == nil || owner == nil {
		t.Fatal("transform dependencies")
	}
	published := false
	defer func() {
		if !published {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			if owner.Close(cleanup) != nil {
				t.Error("transform connection disposal")
			}
		}
	}()
	controls := map[string]string{}
	for _, k := range transformAcceptanceOverlaps {
		controls[k] = os.Getenv(k)
	}
	for _, k := range []string{"ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT"} {
		delete(controls, k)
	}
	enabled, e := transformAcceptanceMode(os.Getenv("ZASP_ORDERED_TRANSFORM_ACCEPTANCE"), controls)
	directory := os.Getenv("ZASP_ORDERED_TRANSFORM_ACCEPTANCE_DIR")
	if e != nil || !enabled || t.Name() != "TestP7OrderedCurrentTransformAcceptance" || os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") != "catalog" || destination != os.Getenv("ZASP_ORDERED_TRANSFORM_ACCEPTANCE_OUTPUT") || destination != os.Getenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT") || os.Getenv("ZASP_ORDERED_PREDECESSOR_RELEASE") != filepath.Join(directory, remainingP7, "ordered-current-inventory-compiled.json") {
		t.Fatal("transform callback refused")
	}
	input, e := loadTransformAcceptance(directory)
	if e != nil {
		t.Fatal(e)
	}
	baseline := map[string]string{}
	var rawObservations []json.RawMessage
	var tx pgx.Tx
	io := transformAcceptanceIO{
		Begin: func(c context.Context, write bool) error {
			mode := pgx.ReadOnly
			if write {
				mode = pgx.ReadWrite
			}
			var err error
			tx, err = owner.BeginTx(c, pgx.TxOptions{AccessMode: mode, IsoLevel: pgx.RepeatableRead})
			return err
		},
		Configure: func(c context.Context) error {
			_, err := tx.Exec(c, `SET LOCAL statement_timeout='10s';SET LOCAL lock_timeout='3s';SET LOCAL search_path=pg_catalog;SET LOCAL TIME ZONE 'UTC';SELECT pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0))`)
			return err
		},
		Frame: func(c context.Context) (orderedSupplementFrame, error) {
			c, cancel := context.WithTimeout(c, 10*time.Second)
			defer cancel()
			var f orderedSupplementFrame
			const sql = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),pg_catalog.version(),current_setting('server_version_num'),(SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),current_setting('transaction_read_only')='on'`
			var row pgx.Row
			if tx == nil {
				row = owner.QueryRow(c, sql)
			} else {
				row = tx.QueryRow(c, sql)
			}
			err := row.Scan(&f.Session, &f.Role, &f.SearchPath, &f.TimeZone, &f.Postgres, &f.ServerVersionNum, &f.Pgcrypto, &f.ReadOnly)
			if err == nil && f.Postgres != transformAcceptancePostgres {
				err = supplementRefusal("transform exact build")
			}
			return f, err
		},
		Admission: func(c context.Context) error {
			var ok bool
			err := tx.QueryRow(c, `SELECT count(*)=1 AND bool_and(checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND to_regnamespace('zasp_authorization80_identity') IS NULL FROM zasp_authorization80_worker.registration`, supplementChecksum).Scan(&ok)
			if err != nil || !ok {
				return errors.Join(supplementRefusal("transform original admission"), err)
			}
			return nil
		},
		Evidence: func(c context.Context) (string, error) {
			var digest, definition string
			var absent bool
			err := tx.QueryRow(c, transformAcceptanceEvidenceSQL).Scan(&digest, &definition, &absent)
			if err != nil || !absent || definition != input.Packet.Target.Definition {
				return "", errors.Join(supplementRefusal("transform exact original evidence"), err)
			}
			return digest, nil
		},
		Rollback: func(c context.Context) error { err := tx.Rollback(c); tx = nil; return err },
		Dispose:  func(c context.Context) error { return owner.Close(c) },
	}
	io.Exercise = func(c context.Context, step transformAcceptanceCase) (json.RawMessage, error) {
		return exerciseTransformAcceptance(c, tx, input, step, baseline, &rawObservations)
	}
	io.Validate = func(c context.Context, raw json.RawMessage) error {
		if tx != nil {
			return supplementRefusal("transform process under transaction")
		}
		var result map[string]json.RawMessage
		if supplementJSON(raw, &result) != nil {
			return supplementRefusal("transform local result")
		}
		var rows []json.RawMessage
		if value, ok := result["configWitnesses"]; ok && supplementJSON(value, &rows) != nil {
			return supplementRefusal("transform local witnesses")
		}
		if len(rows) == 0 {
			return nil
		}
		var nonstandard bool
		if value, ok := result["nonstandardRefused"]; ok && supplementJSON(value, &nonstandard) != nil {
			return supplementRefusal("transform local witness mode")
		}
		return checkTransformConfigWithNode(c, input, rows, nonstandard)
	}
	publication, e := runTransformAcceptanceGroup(ctx, input.Packet.Cases, io, input.Paths, destination, func(results []json.RawMessage) ([]byte, error) {
		if ctx.Err() != nil || len(results) != 19 || len(baseline) != 13 {
			return nil, supplementRefusal("transform incomplete group")
		}
		return json.Marshal(map[string]any{"format": "ordered-transform-acceptance-result-v1", "packetManifestSHA256": transformAcceptanceManifestSHA, "sourceContractSHA256": input.Packet.SourceContractSHA256, "compiledProjectionSHA256": input.Packet.CompiledSHA256, "completedCases": len(results), "restored": true, "rawInputDisposition": input.Packet.RawDisposition, "oidDisposition": "within-fixture witnesses, never release expected identities", "rawReferenceObservations": rawObservations, "comparisonEvidence": results, "reserved": input.Packet.Reserved})
	})
	if e != nil {
		var diagnostic interface{ Diagnostic() map[string]string }
		if errors.As(e, &diagnostic) {
			labels, marshalErr := json.Marshal(diagnostic.Diagnostic())
			if marshalErr == nil && len(labels) <= 2048 {
				t.Log("transform refusal", string(labels))
			}
		}
		t.Fatal("transform acceptance/publication refused")
	}
	published = true
	t.Log("transform acceptance published", "fileSHA256", publication.FileSHA256, "payloadSHA256", publication.PayloadSHA256, "bytes", publication.Bytes)
}

// Fixed source identities only. OIDs are within-fixture restoration witnesses,
// never release expected identities. Every deliberate change is rolled back.
const transformAcceptanceEvidenceSQL = `SELECT encode(public.digest(convert_to(jsonb_build_object(
 'routines',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.oid) FROM pg_catalog.pg_proc p WHERE p.oid IN('public.zasp_sa_multistep_live_fingerprint()'::regprocedure,'zasp_temporal65.capture()'::regprocedure)),
 'table',(SELECT to_jsonb(c) FROM pg_catalog.pg_class c WHERE c.oid='zasp_temporal74.predecessor_functions'::regclass),
 'saved',(SELECT jsonb_agg(to_jsonb(s) ORDER BY signature) FROM zasp_temporal74.predecessor_functions s))::text,'UTF8'),'sha256'),'hex'),
 pg_get_functiondef('public.zasp_sa_multistep_live_fingerprint()'::regprocedure),
 to_regclass('zasp_temporal74.__ordered_transform_original') IS NULL AND to_regprocedure('zasp_temporal65.__ordered_transform_capture()') IS NULL`

func transformExpectedError(ctx context.Context, tx pgx.Tx, sql, want string, query bool) error {
	if _, e := tx.Exec(ctx, "SAVEPOINT ordered_transform_error"); e != nil {
		return e
	}
	var err error
	if query {
		rows, e := tx.Query(ctx, sql)
		err = e
		if e == nil {
			for rows.Next() {
			}
			err = rows.Err()
			rows.Close()
		}
	} else {
		_, err = tx.Exec(ctx, sql)
	}
	var p *pgconn.PgError
	matched := ctx.Err() == nil && errors.As(err, &p) && p.Code == want
	if _, e := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT ordered_transform_error"); e != nil {
		return errors.Join(err, e)
	}
	if _, e := tx.Exec(ctx, "RELEASE SAVEPOINT ordered_transform_error"); e != nil {
		return errors.Join(err, e)
	}
	if !matched {
		return errors.Join(supplementRefusal("transform expected SQLSTATE"), err)
	}
	return nil
}

func exerciseTransformAcceptance(ctx context.Context, tx pgx.Tx, input transformAcceptanceInputs, step transformAcceptanceCase, baseline map[string]string, rawObservations *[]json.RawMessage) (result json.RawMessage, err error) {
	phase, ruleID := "setup", "none"
	defer func() {
		if err != nil {
			err = transformAt(ruleID, phase, err)
		}
	}()
	for _, sql := range step.Setup {
		tag, e := tx.Exec(ctx, sql)
		if e != nil {
			return nil, e
		}
		if strings.HasPrefix(sql, "UPDATE pg_catalog.pg_proc") && tag.RowsAffected() != 1 {
			return nil, supplementRefusal("transform fixed mutation cardinality")
		}
	}
	if step.Mode == "constraint" {
		phase = "constraint"
		if e := transformExpectedError(ctx, tx, step.ProbeSQL, step.SQLState, false); e != nil {
			return nil, e
		}
		return json.Marshal(map[string]any{"case": step.ID, "productionConstraintRefusal": step.SQLState, "liveContext": ctx.Err() == nil})
	}
	phase = "candidate"
	selectionFrame, e := transformSelectFrame(ctx, tx, step.Write, "pg_catalog")
	if e != nil {
		return nil, e
	}
	if step.Mode == "config" {
		phase = "witness"
		ruleID = "public:sa_multistep:function"
		rows, e := transformConfigRows(ctx, tx, step.WitnessSQL)
		if e != nil || len(rows) != 1 {
			return nil, transformFailure(ruleID, "config_text_or_empty", "config", e)
		}
		return json.Marshal(map[string]any{"case": step.ID, "artificialCatalogFault": true, "configWitnesses": rows, "nonstandardRefused": step.ExpectNonstandard, "executionFrames": map[string]orderedSupplementFrame{"config": selectionFrame}})
	}
	counts := map[string]int{}
	digests := map[string]string{}
	aggregates := map[string]string{}
	combinedOriginal := []json.RawMessage{}
	witnesses := []json.RawMessage{}
	executionFrames := map[string]map[string]orderedSupplementFrame{}
	for _, id := range step.RuleIDs {
		ruleID = id
		var rule *transformAcceptanceRule
		for i := range input.Packet.Rules {
			if input.Packet.Rules[i].ID == id {
				rule = &input.Packet.Rules[i]
				break
			}
		}
		if rule == nil {
			return nil, supplementRefusal("transform rule")
		}
		phase = "original"
		originalFrame, e := transformSelectFrame(ctx, tx, step.Write, "pg_catalog, public")
		if e != nil {
			return nil, e
		}
		executionFrames[id] = map[string]orderedSupplementFrame{"original": originalFrame}
		if step.SQLState != "" {
			if e := transformExpectedError(ctx, tx, rule.OriginalSQL, step.SQLState, true); e != nil {
				return nil, e
			}
			phase = "candidate"
			candidateFrame, e := transformSelectFrame(ctx, tx, step.Write, "pg_catalog")
			if e != nil {
				return nil, e
			}
			executionFrames[id]["candidate"] = candidateFrame
			if e := transformExpectedError(ctx, tx, rule.CandidateSQL, step.SQLState, true); e != nil {
				return nil, e
			}
			continue
		}
		original, e := transformProjectionRows(ctx, tx, rule.OriginalSQL, false, rule.Cap)
		if e != nil {
			return nil, e
		}
		var originalAggregate *string
		phase = "original-aggregate"
		if e = tx.QueryRow(ctx, rule.OriginalAggregateSQL).Scan(&originalAggregate); e != nil {
			return nil, e
		}
		phase = "candidate"
		candidateFrame, e := transformSelectFrame(ctx, tx, step.Write, "pg_catalog")
		if e != nil {
			return nil, e
		}
		executionFrames[id]["candidate"] = candidateFrame
		phase = "roster"
		roster, e := transformRoster(ctx, tx, rule.RosterSQL, rule.Cap)
		if e != nil {
			return nil, e
		}
		phase = "candidate"
		candidate, e := transformProjectionRows(ctx, tx, rule.CandidateSQL, true, rule.Cap)
		if e != nil {
			return nil, e
		}
		var candidateAggregate *string
		phase = "candidate-aggregate"
		if e = tx.QueryRow(ctx, rule.CandidateAggregateSQL).Scan(&candidateAggregate); e != nil {
			return nil, e
		}
		if e = compareTransformAggregate(id, originalAggregate, candidateAggregate); e != nil {
			return nil, e
		}
		aggregateBytes, _ := json.Marshal(originalAggregate)
		aggregates[id] = supplementSHA(aggregateBytes)
		phase = "comparison"
		digest, e := compareTransformAcceptanceRows(*rule, original, candidate, roster)
		if e != nil {
			return nil, e
		}
		counts[id] = len(candidate)
		digests[id] = digest
		if step.Mode == "pristine" {
			baseline[id] = digest
			for _, row := range candidate {
				b, e := json.Marshal(map[string]any{"kind": "routine", "identity": row.Identity, "fact": row.Fact})
				if e != nil {
					return nil, e
				}
				combinedOriginal = append(combinedOriginal, b)
			}
		} else if old, ok := baseline[id]; !ok || (digest != old) != step.MustChange {
			return nil, transformFailure(id, "none", "mutation", nil)
		}
		if rule.WitnessSQL != "" && step.Mode == "pristine" {
			phase = "witness"
			w, e := transformConfigRows(ctx, tx, rule.WitnessSQL)
			if e != nil || checkTransformWitnessRoster(w, roster) != nil {
				return nil, transformFailure(id, "config_text_or_empty", "config", e)
			}
			witnesses = append(witnesses, w...)
		}
	}
	if step.Mode == "pristine" {
		ruleID = "none"
		phase = "combined"
		if len(counts) != 13 {
			return nil, supplementRefusal("transform pristine coverage")
		}
		combined, e := transformCombinedRows(ctx, tx, input.Packet.CompiledSQL)
		if e != nil {
			return nil, e
		}
		if e = compareTransformCombinedRows(combinedOriginal, combined); e != nil {
			return nil, e
		}
		phase = "raw"
		rows, e := transformRawRows(ctx, tx, input.Packet)
		if e != nil {
			return nil, e
		}
		if e = checkTransformRawObservations(input.Packet, rows, counts); e != nil {
			return nil, e
		}
		*rawObservations = rows
	}
	return json.Marshal(map[string]any{"case": step.ID, "counts": counts, "pairedResultSHA256": digests, "pairedAggregateSHA256": aggregates, "pairedSQLState": step.SQLState, "liveContext": ctx.Err() == nil, "artificialSavedFault": strings.HasPrefix(step.ID, "saved-"), "configWitnesses": witnesses, "executionFrames": executionFrames})
}

func transformSelectFrame(ctx context.Context, tx pgx.Tx, write bool, searchPath string) (orderedSupplementFrame, error) {
	var f orderedSupplementFrame
	var sql string
	switch searchPath {
	case "pg_catalog":
		sql = `SET LOCAL ROLE zasp_discovery_authority;SET LOCAL search_path=pg_catalog;SET LOCAL TIME ZONE 'UTC'`
	case "pg_catalog, public":
		sql = `SET LOCAL ROLE zasp_discovery_authority;SET LOCAL search_path=pg_catalog, public;SET LOCAL TIME ZONE 'UTC'`
	default:
		return f, supplementRefusal("transform fixed frame")
	}
	if _, e := tx.Exec(ctx, sql); e != nil {
		return f, e
	}
	e := tx.QueryRow(ctx, `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),pg_catalog.version(),current_setting('server_version_num'),(SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),current_setting('transaction_read_only')='on'`).Scan(&f.Session, &f.Role, &f.SearchPath, &f.TimeZone, &f.Postgres, &f.ServerVersionNum, &f.Pgcrypto, &f.ReadOnly)
	if e != nil {
		return f, e
	}
	return f, checkTransformExecutionFrame(f, write, searchPath)
}

func transformCombinedRows(ctx context.Context, tx pgx.Tx, sql string) ([]json.RawMessage, error) {
	rows, e := tx.Query(ctx, sql)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	size := 0
	for rows.Next() {
		var kind, id string
		var fact json.RawMessage
		if e = rows.Scan(&kind, &id, &fact); e != nil {
			return nil, e
		}
		raw, e := json.Marshal(map[string]any{"kind": kind, "identity": id, "fact": fact})
		if e != nil {
			return nil, e
		}
		size += len(raw)
		if len(out) >= 380 || size > 16777216 {
			return nil, supplementRefusal("transform combined stream")
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

func transformProjectionRows(ctx context.Context, tx pgx.Tx, sql string, candidate bool, cap int) ([]transformAcceptanceRow, error) {
	rows, e := tx.Query(ctx, sql)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []transformAcceptanceRow{}
	size := 0
	for rows.Next() {
		var r transformAcceptanceRow
		if candidate {
			var kind string
			e = rows.Scan(&kind, &r.Identity, &r.Fact, &r.Line)
			if kind != "routine" {
				return nil, supplementRefusal("transform kind")
			}
		} else {
			e = rows.Scan(&r.OID, &r.Fact, &r.Line)
		}
		size += len(r.Fact) + len(r.Line) + len(r.Identity)
		if e != nil || len(out) >= cap || size > 16*1024*1024 {
			return nil, errors.Join(supplementRefusal("transform projection stream"), e)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func transformRoster(ctx context.Context, tx pgx.Tx, sql string, cap int) (map[string]string, error) {
	rows, e := tx.Query(ctx, sql)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]string{}
	oids := map[string]bool{}
	for rows.Next() {
		var oid, id string
		if e = rows.Scan(&oid, &id); e != nil || oid == "" || id == "" || out[id] != "" || oids[oid] || len(out) >= cap {
			return nil, errors.Join(supplementRefusal("transform roster"), e)
		}
		out[id] = oid
		oids[oid] = true
	}
	return out, rows.Err()
}
func transformConfigRows(ctx context.Context, tx pgx.Tx, sql string) ([]json.RawMessage, error) {
	rows, e := tx.Query(ctx, sql)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	size := 0
	for rows.Next() {
		var raw json.RawMessage
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		size += len(raw)
		if len(out) >= 176 || size > 1024*1024 {
			return nil, supplementRefusal("transform config bounds")
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}
func checkTransformConfigWithNode(ctx context.Context, input transformAcceptanceInputs, rows []json.RawMessage, nonstandard bool) error {
	payload, e := json.Marshal(map[string]any{"witnesses": rows, "expectNonstandard": nonstandard})
	if e != nil {
		return e
	}
	cmd := exec.CommandContext(ctx, transformAcceptanceNode, filepath.Join(input.Directory, transformAcceptanceBuilder), "--validate-observations")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(payload)
	cmd.WaitDelay = time.Second
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Run(); e != nil || ctx.Err() != nil || output.Len() > 1024 {
		return transformFailure("none", "config_text_or_empty", "config", nil)
	}
	var result struct{ Compared, Refused int }
	if supplementJSON(bytes.TrimSpace(output.Bytes()), &result) != nil || (!nonstandard && (result.Compared != len(rows) || result.Refused != 0)) || (nonstandard && (result.Compared != 0 || result.Refused != 1)) {
		return transformFailure("none", "config_text_or_empty", "config", nil)
	}
	return nil
}
func transformRawRows(ctx context.Context, tx pgx.Tx, p transformAcceptancePacket) ([]json.RawMessage, error) {
	rows, e := tx.Query(ctx, p.RawSQL)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	size := 0
	seen := map[string]bool{}
	counts := map[string]int{}
	for rows.Next() {
		var kind, id string
		var fact json.RawMessage
		if e = rows.Scan(&kind, &id, &fact); e != nil {
			return nil, e
		}
		var key []string
		if kind != "routine" || supplementJSON([]byte(id), &key) != nil || len(key) != 2 || seen[id] {
			return nil, supplementRefusal("transform raw identity")
		}
		seen[id] = true
		cap := 0
		for _, r := range p.Rules {
			if key[0] == "raw-transform:"+r.ID || (strings.HasPrefix(r.ID, "public:") && key[0] == "raw-transform:"+strings.TrimSuffix(r.ID, ":function")) {
				cap = r.Cap
				break
			}
		}
		counts[key[0]]++
		if cap == 0 || counts[key[0]] > cap {
			return nil, supplementRefusal("transform raw scope")
		}
		raw, e := json.Marshal(map[string]any{"kind": kind, "identity": id, "fact": fact})
		if e != nil {
			return nil, e
		}
		size += len(raw)
		if len(out) >= p.MaxRows || size > p.MaxBytes {
			return nil, supplementRefusal("transform raw bound")
		}
		out = append(out, raw)
	}
	if len(counts) != 13 {
		return nil, supplementRefusal("transform raw rule coverage")
	}
	return out, rows.Err()
}
