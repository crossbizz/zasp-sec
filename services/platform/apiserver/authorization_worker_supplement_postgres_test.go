package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
)

// No SQL is accepted from an argument/environment variable. Only the seven
// immutable files, independently hash-verified before fixture setup and again
// after original installer admission, can reach the fixed capture operation.
func loadOrderedSupplementInputs(directory string) (orderedSupplementInputs, []string, error) {
	var input orderedSupplementInputs
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return input, nil, supplementRefusal("reference directory")
	}
	var paths []string
	for _, item := range []struct {
		name   string
		target *[]byte
		limit  int
	}{
		{"ordered-current-supplementary-query-contract2.json", &input.Contract, 1024 * 1024},
		{"ordered-current-supplementary-select2.sql", &input.SQL, 1024 * 1024},
		{"ordered-current-supplementary-rules2.json", &input.Rules, 1024 * 1024},
		{"ordered-current-supplementary-sites2.json", &input.Sites, 1024 * 1024},
		{"ordered-current-inventory-compiled.json", &input.Compiler, 2 * 1024 * 1024},
		{"ordered-current-effective-catalog1.json", &input.Catalog, 32 * 1024 * 1024},
		{"ordered-current-effective-contract3.json", &input.SourceContract, 16 * 1024 * 1024},
	} {
		path := filepath.Join(directory, item.name)
		raw, err := readOrderedSupplementFile(path, item.limit)
		if err != nil {
			return input, nil, err
		}
		*item.target = raw
		paths = append(paths, path)
	}
	if _, err := verifyOrderedSupplementInputs(input); err != nil {
		return input, nil, err
	}
	return input, paths, nil
}

func TestP7OrderedCurrentSupplementCapture(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_SUPPLEMENT_CAPTURE") == "" {
		t.Skip("explicit reference-only supplementary capture required")
	}
	if os.Getenv("ZASP_ORDERED_SUPPLEMENT_CAPTURE") != "1" {
		t.Fatal("invalid supplementary mode")
	}
	for _, key := range []string{"ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", "ZASP_ORDERED_READINESS_ATTRIBUTION", "ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_READINESS_PLAN_OUTPUT", "ZASP_ORDERED_POLICY_CAPACITY", "ZASP_ORDERED_POLICY_PREFIX", "ZASP_P7_ORDERED69_RETIREMENT_ACL", "ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION", "ZASP_P7_ORDERED_BODY_CAPTURE", "ZASP_ORDERED62_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", "ZASP_ORDERED_POLICY_TRACE"} {
		if os.Getenv(key) != "" {
			t.Fatal("overlapping supplementary mode")
		}
	}
	directory := os.Getenv("ZASP_ORDERED_SUPPLEMENT_REFERENCE_DIR")
	if _, _, err := loadOrderedSupplementInputs(directory); err != nil {
		t.Fatal(err)
	}
	destination := os.Getenv("ZASP_ORDERED_SUPPLEMENT_OUTPUT")
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		t.Fatal("explicit supplementary output required")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("new supplementary output required")
	}
	// Reuse the accepted catalog-only install branch and its exact principal setup;
	// the new overlay substitutes only its exporter callback, not production code.
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CAPTURE", "catalog")
	t.Setenv("ZASP_ORDERED_PREDECESSOR_RELEASE", filepath.Join(directory, "ordered-current-inventory-compiled.json"))
	t.Setenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", destination)
	runOrdered68PolicyBoundary(t, true, false, false)
	if t.Failed() {
		return
	}
	output, err := readOrderedSupplementFile(destination, 16*1024*1024+1)
	if err != nil {
		t.Fatal("supplementary callback did not publish")
	}
	var envelope map[string]json.RawMessage
	if supplementJSON(output, &envelope) != nil || string(envelope["format"]) != `"ordered-current-supplementary-reference-v1"` || string(envelope["contractSHA256"]) != `"`+supplementContractSHA+`"` {
		t.Fatal("supplementary completion witness")
	}
}

// Called only by one counted replacement in the NEW frozen parent overlay.
// Default behavior delegates to the unchanged accepted exporter.
func captureOrderedSupplementOrPredecessor(t *testing.T, ctx context.Context, owner *pgx.Conn, destination string) {
	t.Helper()
	mode := os.Getenv("ZASP_ORDERED_SUPPLEMENT_CAPTURE")
	if mode == "" {
		captureOrdered69PredecessorCatalog(t, ctx, owner, destination)
		return
	}
	if mode != "1" || t.Name() != "TestP7OrderedCurrentSupplementCapture" || os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") != "catalog" || destination != os.Getenv("ZASP_ORDERED_SUPPLEMENT_OUTPUT") || owner == nil {
		t.Fatal("supplementary entry boundary")
	}
	input, paths, err := loadOrderedSupplementInputs(os.Getenv("ZASP_ORDERED_SUPPLEMENT_REFERENCE_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	shape, err := verifyOrderedSupplementInputs(input)
	if err != nil {
		t.Fatal(err)
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
			var frame orderedSupplementFrame
			const query = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),pg_catalog.version(),current_setting('server_version_num'),(SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),current_setting('transaction_read_only')='on'`
			var row pgx.Row
			if tx == nil {
				row = owner.QueryRow(ctx, query)
			} else {
				row = tx.QueryRow(ctx, query)
			}
			err := row.Scan(&frame.Session, &frame.Role, &frame.SearchPath, &frame.TimeZone, &frame.Postgres, &frame.ServerVersionNum, &frame.Pgcrypto, &frame.ReadOnly)
			return frame, err
		},
		Admission: func(ctx context.Context) error {
			var ready bool
			// Exact original e12 catalog admission, separately from the direct SELECT.
			err := tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND zasp_temporal78.current_ready() AND to_regnamespace('zasp_authorization80_identity') IS NULL FROM zasp_authorization80_worker.registration`, supplementChecksum).Scan(&ready)
			if err != nil || !ready {
				return supplementRefusal("original admission")
			}
			return nil
		},
		Collect: func(ctx context.Context, emit func(json.RawMessage) error) error {
			rows, err := tx.Query(ctx, string(input.SQL))
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var kind, identity string
				var fact json.RawMessage
				if err := rows.Scan(&kind, &identity, &fact); err != nil {
					return err
				}
				var buf bytes.Buffer
				encoder := json.NewEncoder(&buf)
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(struct {
					Kind     string          `json:"kind"`
					Identity string          `json:"identity"`
					Fact     json.RawMessage `json:"fact"`
				}{kind, identity, fact}); err != nil {
					return err
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
	// Variant A only. The separately reviewed Variant B starter/witness remains
	// distinct; no env-selected migration login is introduced here.
	rows, frame, err := runOrderedSupplementBoundary(ctx, "zasp_test", shape, io)
	if err != nil {
		t.Fatal(err)
	}
	envelope := struct {
		Format            string            `json:"format"`
		QuerySHA          string            `json:"querySHA256"`
		ContractSHA       string            `json:"contractSHA256"`
		RulesSHA          string            `json:"rulesSHA256"`
		SitesSHA          string            `json:"sitesSHA256"`
		CompilerSHA       string            `json:"compilerArtifactSHA256"`
		Checksum          string            `json:"compilerChecksum"`
		SourceSHA         string            `json:"compiledSourceSHA256"`
		CatalogSHA        string            `json:"catalog1FileSHA256"`
		SourceContractSHA string            `json:"sourceContractSHA256"`
		Variant           string            `json:"variant"`
		Session           string            `json:"sessionUser"`
		Role              string            `json:"role"`
		SearchPath        []string          `json:"searchPath"`
		TimeZone          string            `json:"timeZone"`
		Postgres          string            `json:"postgres"`
		ServerVersionNum  string            `json:"serverVersionNum"`
		Pgcrypto          string            `json:"pgcrypto"`
		ReadOnly          bool              `json:"readOnly"`
		RolledBack        bool              `json:"rolledBack"`
		FrameRestored     bool              `json:"frameRestored"`
		Rows              []json.RawMessage `json:"rows"`
	}{"ordered-current-supplementary-reference-v1", supplementQuerySHA, supplementContractSHA, supplementRulesSHA, supplementSitesSHA, supplementCompilerSHA, supplementChecksum, supplementCompiledSourceSHA, supplementCatalogSHA, supplementSourceContractSHA, "A", frame.Session, frame.Role, []string{"pg_catalog"}, frame.TimeZone, frame.Postgres, frame.ServerVersionNum, frame.Pgcrypto, true, true, true, rows}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(envelope) != nil {
		t.Fatal("supplementary envelope")
	}
	payload := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	published, err := publishOrderedSupplement(destination, paths, payload, shape.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("supplementary reference-only capture", "rows", len(rows), "bytes", published.Bytes, "payloadSHA256", published.PayloadSHA256, "fileSHA256", published.FileSHA256, "querySHA256", supplementQuerySHA, "contractSHA256", supplementContractSHA, "rollback", true, "frameRestored", true)
}
