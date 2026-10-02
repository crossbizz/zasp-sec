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

const privateReferenceP7 = ".superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement"
const privateReferenceArtifacts = "services/platform/migrations/ordered_current"

type privateReferenceInputs struct {
	Contract     privateReferenceContract
	DDL, Query   []byte
	Paths        []string
	CompilerPath string
}

// The entire source snapshot is pinned independently. A path can relocate those
// exact bytes, but cannot introduce a caller-defined query, module or rule set.
func loadPrivateReferenceInputs(directory string) (privateReferenceInputs, error) {
	var result privateReferenceInputs
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return result, privateReferenceRefusal("packet directory")
	}
	manifestPath := filepath.Join(directory, "snapshot-manifest.json")
	raw, err := readOrderedSupplementFile(manifestPath, 1024*1024)
	if err != nil || supplementSHA(raw) != privateReferenceSnapshotSHA {
		return result, privateReferenceRefusal("snapshot pin")
	}
	var manifest struct {
		Format int
		Source string
		Files  map[string]string
	}
	if supplementJSON(raw, &manifest) != nil || manifest.Format != 1 || len(manifest.Files) != 23 {
		return result, privateReferenceRefusal("snapshot shape")
	}
	files := map[string][]byte{}
	for name, sha := range manifest.Files {
		if filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || len(name) > 512 {
			return result, privateReferenceRefusal("snapshot path")
		}
		path := filepath.Join(directory, name)
		relative, e := filepath.Rel(directory, path)
		if e != nil || relative != name {
			return result, privateReferenceRefusal("snapshot path")
		}
		bytes, e := readOrderedSupplementFile(path, 32*1024*1024)
		if e != nil || supplementSHA(bytes) != sha {
			return result, privateReferenceRefusal("snapshot file")
		}
		files[name] = bytes
		result.Paths = append(result.Paths, path)
	}
	result.Paths = append(result.Paths, manifestPath)
	result.DDL = files[privateReferenceArtifacts+"/private-reference-ddl.sql"]
	result.Query = files[privateReferenceArtifacts+"/private-reference-select.sql"]
	result.Contract, err = verifyPrivateReferenceInput(files[privateReferenceArtifacts+"/private-reference-contract.json"], result.DDL, result.Query)
	if err != nil {
		return privateReferenceInputs{}, err
	}
	result.CompilerPath = filepath.Join(directory, privateReferenceP7, "ordered-current-inventory-compiled.json")
	return result, nil
}

func TestP7OrderedCurrentPrivateReferenceCapture(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_PRIVATE_REFERENCE") == "" {
		t.Skip("explicit rollback-only private reference required")
	}
	if os.Getenv("ZASP_ORDERED_PRIVATE_REFERENCE") != "1" {
		t.Fatal("invalid private reference mode")
	}
	for _, name := range []string{"ZASP_ORDERED_SUPPLEMENT_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_REFERENCE_DIR", "ZASP_ORDERED_SUPPLEMENT_OUTPUT", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", "ZASP_ORDERED_READINESS_ATTRIBUTION", "ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_READINESS_PLAN_OUTPUT", "ZASP_ORDERED_POLICY_CAPACITY", "ZASP_ORDERED_POLICY_PREFIX", "ZASP_P7_ORDERED69_RETIREMENT_ACL", "ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION", "ZASP_P7_ORDERED_BODY_CAPTURE", "ZASP_ORDERED62_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", "ZASP_ORDERED_POLICY_TRACE"} {
		if os.Getenv(name) != "" {
			t.Fatal("overlapping private reference mode")
		}
	}
	input, err := loadPrivateReferenceInputs(os.Getenv("ZASP_ORDERED_PRIVATE_REFERENCE_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	output := os.Getenv("ZASP_ORDERED_PRIVATE_REFERENCE_OUTPUT")
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		t.Fatal("absolute private output required")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("new private output required")
	}
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CAPTURE", "catalog")
	t.Setenv("ZASP_ORDERED_PREDECESSOR_RELEASE", input.CompilerPath)
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", output)
	runOrdered68PolicyBoundary(t, true, false, false)
	if t.Failed() {
		return
	}
	raw, err := readOrderedSupplementFile(output, 16*1024*1024+1)
	if err != nil {
		t.Fatal("private reference output missing")
	}
	var envelope map[string]json.RawMessage
	if supplementJSON(raw, &envelope) != nil || string(envelope["format"]) != `"ordered-current-private-reference-v1"` || string(envelope["contractSHA256"]) != `"`+privateReferenceContractSHA+`"` || string(envelope["readOnly"]) != "false" {
		t.Fatal("private reference completion witness")
	}
}

// Only a single counted callback replacement in a NEW frozen overlay calls this.
func captureOrderedPrivateReferenceOrSupplement(t *testing.T, ctx context.Context, owner *pgx.Conn, destination string) {
	t.Helper()
	if os.Getenv("ZASP_ORDERED_PRIVATE_REFERENCE") == "" {
		captureOrderedSupplementOrPredecessor(t, ctx, owner, destination)
		return
	}
	if os.Getenv("ZASP_ORDERED_PRIVATE_REFERENCE") != "1" || t.Name() != "TestP7OrderedCurrentPrivateReferenceCapture" || owner == nil || os.Getenv("ZASP_ORDERED_SUPPLEMENT_CAPTURE") != "" || os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") != "catalog" || destination != os.Getenv("ZASP_ORDERED_PRIVATE_REFERENCE_OUTPUT") {
		t.Fatal("private reference entry refused")
	}
	published := false
	defer func() {
		if !published {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			if owner.Close(cleanup) != nil {
				t.Error("private reference connection disposal failed")
			}
		}
	}()
	input, err := loadPrivateReferenceInputs(os.Getenv("ZASP_ORDERED_PRIVATE_REFERENCE_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	var tx pgx.Tx
	queryRow := func(ctx context.Context, query string, args ...any) pgx.Row {
		if tx == nil {
			return owner.QueryRow(ctx, query, args...)
		}
		return tx.QueryRow(ctx, query, args...)
	}
	io := privateReferenceIO{
		Begin: func(ctx context.Context, readOnly bool) error {
			mode := pgx.ReadWrite
			if readOnly {
				mode = pgx.ReadOnly
			}
			var err error
			tx, err = owner.BeginTx(ctx, pgx.TxOptions{AccessMode: mode})
			return err
		},
		Exec: func(ctx context.Context, sql string) error { _, err := tx.Exec(ctx, sql); return err },
		Frame: func(ctx context.Context) (orderedSupplementFrame, error) {
			var f orderedSupplementFrame
			err := queryRow(ctx, `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),pg_catalog.version(),current_setting('server_version_num'),(SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),current_setting('transaction_read_only')='on'`).Scan(&f.Session, &f.Role, &f.SearchPath, &f.TimeZone, &f.Postgres, &f.ServerVersionNum, &f.Pgcrypto, &f.ReadOnly)
			return f, err
		},
		Admission: func(ctx context.Context) error {
			var ready bool
			err := tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND to_regnamespace('zasp_authorization80_identity') IS NULL FROM zasp_authorization80_worker.registration`, supplementChecksum).Scan(&ready)
			if err != nil || !ready {
				return privateReferenceRefusal("original admission")
			}
			return nil
		},
		Absent: func(ctx context.Context) error {
			var absent bool
			err := queryRow(ctx, `SELECT to_regnamespace('zasp_authorization80_ordered_current') IS NULL`).Scan(&absent)
			if err != nil || !absent {
				return privateReferenceRefusal("namespace absence")
			}
			return nil
		},
		Empty: func(ctx context.Context) error {
			var empty bool
			err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_authorization80_ordered_current.expected) AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_ordered_current.registration)`).Scan(&empty)
			if err != nil || !empty {
				return privateReferenceRefusal("private tables not empty")
			}
			return nil
		},
		Collect: func(ctx context.Context, emit func(json.RawMessage) error) error {
			rows, err := tx.Query(ctx, string(input.Query))
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var kind, identity string
				var fact json.RawMessage
				if rows.Scan(&kind, &identity, &fact) != nil {
					return privateReferenceRefusal("row scan")
				}
				var buf bytes.Buffer
				encoder := json.NewEncoder(&buf)
				encoder.SetEscapeHTML(false)
				if encoder.Encode(struct {
					Kind     string          `json:"kind"`
					Identity string          `json:"identity"`
					Fact     json.RawMessage `json:"fact"`
				}{kind, identity, fact}) != nil {
					return privateReferenceRefusal("row encoding")
				}
				if err := emit(bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})); err != nil {
					return err
				}
			}
			return rows.Err()
		},
		Rollback: func(ctx context.Context) error { err := tx.Rollback(ctx); tx = nil; return err },
		Dispose:  func(ctx context.Context) error { return owner.Close(ctx) },
	}
	result, err := runPrivateReferenceBoundary(ctx, input.Contract, string(input.DDL), io)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(f orderedSupplementFrame) map[string]any {
		return map[string]any{"sessionUser": f.Session, "role": f.Role, "searchPath": f.SearchPath, "timeZone": f.TimeZone, "postgres": f.Postgres, "serverVersionNum": f.ServerVersionNum, "pgcrypto": f.Pgcrypto, "readOnly": f.ReadOnly}
	}
	envelope := map[string]any{
		"format": "ordered-current-private-reference-v1", "variant": "A", "sessionUser": result.Original.Session,
		"contractSHA256": privateReferenceContractSHA, "ddlSHA256": privateReferenceDDLSHA, "querySHA256": privateReferenceQuerySHA, "snapshotSHA256": privateReferenceSnapshotSHA,
		"compilerArtifactSHA256": supplementCompilerSHA, "compilerChecksum": supplementChecksum, "compiledSourceSHA256": supplementCompiledSourceSHA, "catalog1FileSHA256": supplementCatalogSHA, "sourceContractSHA256": supplementSourceContractSHA, "supplementaryReferenceFileSHA256": "c544ae4e6d04907a20879d359d875135658a7a582f16a27d3263f0bc9c91edb4",
		"postgres": result.Collector.Postgres, "serverVersionNum": result.Collector.ServerVersionNum, "pgcrypto": result.Collector.Pgcrypto, "originalFrame": frame(result.Original), "collectorFrame": frame(result.Collector),
		"readOnly": false, "originalAdmission": true, "writeRollback": true, "readOnlyPostAdmission": true, "postAdmission": true, "readRollback": true, "namespaceAbsent": true, "frameRestored": true, "expectedManifestRows": 0, "registrationRows": 0, "rows": result.Rows,
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(envelope) != nil {
		t.Fatal("private reference envelope")
	}
	if ctx.Err() != nil {
		t.Fatal("private reference cancelled before publication")
	}
	publication, err := publishPrivateReference(ctx, destination, input.Paths, bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), input.Contract.Shape.MaxBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	published = true
	t.Log("private reference rollback-only capture", "rows", len(result.Rows), "bytes", publication.Bytes, "payloadSHA256", publication.PayloadSHA256, "fileSHA256", publication.FileSHA256, "contractSHA256", privateReferenceContractSHA, "writeRollback", true, "readRollback", true, "namespaceAbsent", true)
}
