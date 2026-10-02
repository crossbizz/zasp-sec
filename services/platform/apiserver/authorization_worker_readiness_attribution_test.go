package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type readinessAttributionNode struct {
	ID      int                        `json:"id"`
	Parent  *int                       `json:"parent_id"`
	Depth   int                        `json:"depth"`
	Source  string                     `json:"source,omitempty"`
	Kind    string                     `json:"Node Type"`
	TotalMS float64                    `json:"Actual Total Time"`
	Rows    float64                    `json:"Actual Rows"`
	Loops   float64                    `json:"Actual Loops"`
	Hits    float64                    `json:"Shared Hit Blocks"`
	Reads   float64                    `json:"Shared Read Blocks"`
	Plans   []readinessAttributionNode `json:"Plans"`
	CTE     string                     `json:"CTE Name,omitempty"`
	Subplan string                     `json:"Subplan Name,omitempty"`
}
type readinessAttributionMetrics struct {
	PlanningMS  float64
	ExecutionMS float64
	Nodes       []readinessAttributionNode
}

type readinessAttributionObservedPlan struct {
	Root    string                      `json:"root"`
	Metrics readinessAttributionMetrics `json:"metrics"`
}
type readinessAttributionArtifact struct {
	Version        int                                `json:"version"`
	ManifestSHA256 string                             `json:"manifest_sha256"`
	ModuleSHA256   string                             `json:"module_sha256"`
	WorkerChecksum string                             `json:"worker_checksum"`
	Plans          []readinessAttributionObservedPlan `json:"plans"`
}

// Source identities come from the exact candidate artifact, never plan text.
func readinessAttributionSourceMap(module, manifest []byte, manifestSHA string) (map[string]string, error) {
	bad := errors.New("invalid attribution source identity")
	sum := sha256.Sum256(manifest)
	if len(module) > 8*1024*1024 || len(manifest) > 16*1024*1024 || hex.EncodeToString(sum[:]) != manifestSHA {
		return nil, bad
	}
	var candidate struct {
		Files []struct{ Path, SHA256 string }
	}
	if json.Unmarshal(manifest, &candidate) != nil {
		return nil, bad
	}
	moduleSum := sha256.Sum256(module)
	matched := 0
	for _, f := range candidate.Files {
		if f.Path == "services/platform/migrations/sql/0080_authorization_worker_readiness_graph.sql" {
			matched++
			if f.SHA256 != hex.EncodeToString(moduleSum[:]) {
				return nil, bad
			}
		}
	}
	if matched != 1 {
		return nil, bad
	}
	parts := strings.Split(string(module), "$higher_records$")
	var generated struct {
		Records []struct{ Signature string }
		Regions []struct {
			Signature, Query string
			Materialized     []string
		}
	}
	if len(parts) != 3 || json.Unmarshal([]byte(parts[1]), &generated) != nil || len(generated.Regions) != 3 {
		return nil, bad
	}
	region := generated.Regions[0]
	if region.Signature != "zasp_temporal68.predecessor_ready(text,text)" || len(region.Materialized) == 0 || len(region.Materialized) > 256 {
		return nil, bad
	}
	allowed := map[string]bool{}
	nameShape := regexp.MustCompile(`^(?:(?:public|zasp_[a-z0-9_]+)\.)?zasp_[a-z0-9_]+\([a-z0-9_, .\[\]]*\)$|^zasp_[a-z0-9_]+\.[a-z][a-z0-9_]*\([a-z0-9_, .\[\]]*\)$`)
	for _, record := range generated.Records {
		if !nameShape.MatchString(record.Signature) || allowed[record.Signature] {
			return nil, bad
		}
		allowed[record.Signature] = true
	}
	const catalog = "zasp_authorization80_worker.catalog_ready()"
	if !allowed[catalog] || strings.Count(region.Query, "higher_catalog(value) AS MATERIALIZED (") != 1 {
		return nil, bad
	}
	sources := map[string]string{"higher_catalog": catalog}
	seen := map[string]bool{}
	for i, sig := range region.Materialized {
		name := "higher_" + strconv.Itoa(i)
		if !allowed[sig] || seen[sig] || strings.Count(region.Query, name+"(value) AS MATERIALIZED (") != 1 {
			return nil, bad
		}
		seen[sig] = true
		sources[name] = sig
	}
	if len(regexp.MustCompile(`\bhigher_[0-9]+\(value\) AS MATERIALIZED \(`).FindAllString(region.Query, -1)) != len(region.Materialized) {
		return nil, bad
	}
	return sources, nil
}

func writeReadinessAttributionArtifact(path string, doc readinessAttributionArtifact) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("invalid attribution output path")
	}
	raw, err := json.Marshal(doc)
	if err != nil || len(raw) > 8*1024*1024 {
		return "", errors.New("invalid attribution artifact")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// A retirement fixture may call this once after its own controls. No output
// opt-in means no file, database, or context access. The existing attribution
// path can also consume the output option; callers must select one entry.
func captureReadinessSourceAttribution(t *testing.T, ctx context.Context, owner *pgx.Conn) bool {
	if os.Getenv("ZASP_ORDERED_READINESS_PLAN_OUTPUT") == "" {
		return false
	}
	if os.Getenv("ZASP_ORDERED_READINESS_ATTRIBUTION") != "1" {
		t.Fatal("source attribution requires explicit attribution opt-in")
	}
	return runReadinessAttribution(t, ctx, owner)
}

func readinessAttributionPlan(raw []byte, sourceMaps ...map[string]string) (readinessAttributionMetrics, error) {
	bad := errors.New("invalid bounded plan")
	if len(raw) > 8*1024*1024 {
		return readinessAttributionMetrics{}, bad
	}
	var plans []struct {
		Planning  float64 `json:"Planning Time"`
		Execution float64 `json:"Execution Time"`
		Plan      readinessAttributionNode
	}
	err := json.Unmarshal(raw, &plans)
	if err != nil {
		return readinessAttributionMetrics{}, err
	}
	out := readinessAttributionMetrics{}
	if len(plans) != 1 {
		return out, bad
	}
	out.PlanningMS, out.ExecutionMS = plans[0].Planning, plans[0].Execution
	valid := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 }
	if !valid(out.PlanningMS) || !valid(out.ExecutionMS) {
		return out, bad
	}
	if len(sourceMaps) > 1 {
		return out, bad
	}
	var sources map[string]string
	if len(sourceMaps) == 1 {
		sources = sourceMaps[0]
	}
	var walk func(readinessAttributionNode, int, *int) error
	walk = func(n readinessAttributionNode, depth int, parent *int) error {
		if depth > 64 || len(out.Nodes) >= 4096 || n.Kind == "" {
			return bad
		}
		for _, v := range []float64{n.TotalMS, n.Rows, n.Loops, n.Hits, n.Reads} {
			if !valid(v) {
				return bad
			}
		}
		switch n.Kind {
		case "Aggregate", "Append", "Bitmap Heap Scan", "Bitmap Index Scan", "CTE Scan", "Function Scan", "Gather", "Gather Merge", "Hash", "Hash Join", "Index Scan", "Index Only Scan", "Limit", "Materialize", "Memoize", "Merge Join", "Nested Loop", "Result", "Seq Scan", "SetOp", "Sort", "Subquery Scan", "Unique", "Values Scan", "WindowAgg":
		default:
			n.Kind = "other"
		}
		children := n.Plans
		n.Plans = nil
		n.ID, n.Parent, n.Depth, n.Source = len(out.Nodes), parent, depth, ""
		if source, ok := sources[n.CTE]; ok {
			n.Source = source
		} else if strings.HasPrefix(n.Subplan, "CTE ") {
			n.Source = sources[strings.TrimPrefix(n.Subplan, "CTE ")]
		}
		// Never persist server-provided names, even for an allowlisted CTE.
		n.CTE, n.Subplan = "", ""
		out.Nodes = append(out.Nodes, n)
		id := n.ID
		for _, c := range children {
			if err := walk(c, depth+1, &id); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(plans[0].Plan, 0, nil); err != nil {
		return out, err
	}
	return out, nil
}

// The reference SHA and the exact nine captured expression lines constrain
// these read-only selectors; this is not a parser accepting arbitrary SQL.
func readinessAttributionSelectors(source string) (string, error) {
	var selectors []string
	for _, line := range strings.Split(source, "\n") {
		if !strings.Contains(line, "pg_get_functiondef(p.oid)") {
			continue
		}
		if strings.Count(line, "pg_get_functiondef(p.oid)") != 1 {
			return "", errors.New("descriptor expression multiplicity")
		}
		at := strings.Index(line, " FROM pg_proc p WHERE ")
		if at < 0 {
			at = strings.Index(line, " FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE ")
		}
		if at < 0 {
			at = strings.Index(line, " FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE(")
		}
		if at < 0 || strings.Contains(line[at:], ";") {
			return "", errors.New("descriptor selector shape")
		}
		selectors = append(selectors, "SELECT p.oid"+line[at:])
	}
	unique := map[string]bool{}
	for _, s := range selectors {
		unique[s] = true
	}
	if len(selectors) != 9 || len(unique) != 8 {
		return "", errors.New("descriptor selector count")
	}
	return strings.Join(selectors, " UNION ALL "), nil
}

func TestP7OrderedReadinessAttribution(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_READINESS_ATTRIBUTION") == "" {
		t.Skip("explicit catalog attribution opt-in required")
	}
	runOrdered68PolicyBoundary(t, true, false, false)
}

func runReadinessAttribution(t *testing.T, ctx context.Context, owner *pgx.Conn) bool {
	t.Helper()
	if os.Getenv("ZASP_ORDERED_READINESS_ATTRIBUTION") == "" {
		return false
	}
	if os.Getenv("ZASP_ORDERED_READINESS_ATTRIBUTION") != "1" || os.Getenv("ZASP_ORDERED_READINESS_CAPTURE") != "" {
		t.Fatal("invalid or overlapping attribution opt-in")
	}
	raw, err := os.ReadFile(os.Getenv("ZASP_ORDERED_READINESS_REFERENCE"))
	if err != nil {
		t.Fatal("attribution reference unavailable")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != "720683fb7646085a2ecc226746cb3a71d9dd24d296a6ab2103cbf0d36573bb7c" {
		t.Fatal("attribution reference changed")
	}
	type function struct{ Signature, Source, Definition, Owner, ACL string }
	var captured struct {
		Functions     []function
		Registrations struct{ Worker []struct{ Checksum string } }
	}
	if json.Unmarshal(raw, &captured) != nil || len(captured.Registrations.Worker) != 1 {
		t.Fatal("attribution reference shape")
	}
	const catalog = "zasp_authorization80_worker.catalog_ready()"
	const predecessor = "zasp_temporal68.predecessor_ready(text,text)"
	refs := map[string]function{}
	for _, f := range captured.Functions {
		refs[f.Signature] = f
	}
	if refs[catalog].Source == "" || refs[predecessor].Source == "" {
		t.Fatal("attribution reference roots absent")
	}
	selectors, err := readinessAttributionSelectors(refs[catalog].Source)
	if err != nil {
		t.Fatal("attribution selectors changed")
	}
	module, err := os.ReadFile("../migrations/sql/0080_authorization_worker_readiness_graph.sql")
	if err != nil {
		t.Fatal("attribution module unavailable")
	}
	parts := strings.Split(string(module), "$higher_records$")
	var manifest struct {
		Regions []struct{ Signature, Prefix, OriginalExpression, Suffix, Query string }
	}
	if len(parts) != 3 || json.Unmarshal([]byte(parts[1]), &manifest) != nil || len(manifest.Regions) != 3 {
		t.Fatal("attribution module shape")
	}
	region := manifest.Regions[0]
	if region.Signature != predecessor || strings.TrimSpace(region.Prefix+region.OriginalExpression+region.Suffix) != strings.TrimSpace(refs[predecessor].Source) {
		t.Fatal("attribution original predecessor changed")
	}
	output := os.Getenv("ZASP_ORDERED_READINESS_PLAN_OUTPUT")
	var sources map[string]string
	artifact := readinessAttributionArtifact{Version: 1}
	if output != "" {
		if !filepath.IsAbs(output) || filepath.Clean(output) != output {
			t.Fatal("invalid attribution output path")
		}
		candidate, err := os.ReadFile(os.Getenv("ZASP_ORDERED_READINESS_PLAN_MANIFEST"))
		if err != nil {
			t.Fatal("attribution candidate manifest unavailable")
		}
		artifact.ManifestSHA256 = os.Getenv("ZASP_ORDERED_READINESS_PLAN_MANIFEST_SHA256")
		sources, err = readinessAttributionSourceMap(module, candidate, artifact.ManifestSHA256)
		if err != nil {
			t.Fatal("attribution candidate source map invalid")
		}
		for _, signature := range sources {
			if refs[signature].Source == "" {
				t.Fatal("attribution source outside retained reference")
			}
		}
		moduleSum := sha256.Sum256(module)
		artifact.ModuleSHA256 = hex.EncodeToString(moduleSum[:])
	}
	// No goroutines/borrowed clients: every query is joined synchronously before
	// rollback. Ten-second queries remain inside a two-minute diagnostic bound.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tx, err := owner.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("attribution transaction unavailable")
	}
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		if err := tx.Rollback(cleanup); err != nil {
			t.Error("attribution rollback failed")
		}
	}()
	safeError := func(label string, err error) {
		t.Helper()
		var pe *pgconn.PgError
		if errors.As(err, &pe) && len(pe.Code) == 5 && strings.IndexFunc(pe.Code, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z') }) < 0 {
			t.Fatalf("attribution %s SQLSTATE=%s", label, pe.Code)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("attribution %s deadline", label)
		}
		t.Fatalf("attribution %s unavailable", label)
	}
	exec := func(sql string) {
		q, c := context.WithTimeout(ctx, 10*time.Second)
		defer c()
		if _, err := tx.Exec(q, sql); err != nil {
			safeError("setup", err)
		}
	}
	exec(`SET LOCAL statement_timeout='10s'`)
	exec(`SET LOCAL ROLE zasp_discovery_authority`)
	exec(`SET LOCAL search_path=pg_catalog,public`)
	exec(`SELECT pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0))`)
	query := func(label, sql string, args []any, dest ...any) {
		q, c := context.WithTimeout(ctx, 10*time.Second)
		defer c()
		if err := tx.QueryRow(q, sql, args...).Scan(dest...); err != nil {
			safeError(label, err)
		}
	}
	var frame bool
	query("frame", `SELECT current_user='zasp_discovery_authority' AND current_setting('search_path')='pg_catalog, public' AND current_setting('transaction_read_only')='on'`, nil, &frame)
	if !frame {
		t.Fatal("attribution caller frame changed")
	}
	var checksum, liveCatalog, livePred string
	query("registration", `SELECT checksum FROM zasp_authorization80_worker.registration`, nil, &checksum)
	checksumBytes, checksumErr := hex.DecodeString(checksum)
	if checksumErr != nil || len(checksumBytes) != 32 || hex.EncodeToString(checksumBytes) != checksum {
		t.Fatal("attribution checksum shape")
	}
	for _, sig := range []string{catalog, predecessor} {
		var definition, source, acl string
		var shape bool
		query("recipe", `SELECT pg_get_functiondef(p.oid),p.prosrc,COALESCE(p.proacl::text,''),p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND NOT p.proisstrict AND p.proparallel='u' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.prorettype='boolean'::regtype AND NOT p.proretset FROM pg_proc p WHERE p.oid=$1::regprocedure`, []any{sig}, &definition, &source, &acl, &shape)
		if !shape || acl != refs[sig].ACL {
			t.Fatal("attribution recipe frame changed")
		}
		if sig == catalog {
			expected := strings.ReplaceAll(refs[sig].Definition, captured.Registrations.Worker[0].Checksum, checksum)
			if definition != expected {
				t.Fatal("attribution catalog recipe changed")
			}
			liveCatalog = source
		} else {
			livePred = source
		}
	}
	catalogHash := sha256.Sum256([]byte(liveCatalog))
	compiled := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "-- worker profile checksum", checksum), "-- worker catalog body digest", hex.EncodeToString(catalogHash[:]))
	}
	if strings.TrimSpace(livePred) != strings.TrimSpace(compiled(region.Prefix+"("+region.Query+")"+region.Suffix)) {
		t.Fatal("attribution installed region changed")
	}
	var ready bool
	query("current-catalog", `SELECT zasp_authorization80_worker.catalog_ready()`, nil, &ready)
	if !ready {
		t.Fatal("attribution current catalog false")
	}
	// Both samples force every selected deparse into an observed byte sum.
	// DISTINCT is applied to keys BEFORE deparsing; duplicate rows are retained
	// in the repeated case, including the twice-consumed stage trigger.
	for sample := -1; sample < 3; sample++ {
		order := []bool{false, true}
		if sample%2 == 1 {
			order = []bool{true, false}
		}
		for _, distinct := range order {
			keyQuery := selectors
			label := "repeated"
			if distinct {
				keyQuery = "SELECT DISTINCT oid FROM (" + selectors + ") selected"
				label = "distinct"
			}
			sql := `WITH keys AS MATERIALIZED (` + keyQuery + `), definitions AS MATERIALIZED (SELECT oid,pg_get_functiondef(oid) AS definition FROM keys) SELECT count(*),count(DISTINCT oid),COALESCE(sum(octet_length(definition)),0)::bigint FROM definitions`
			var rows, unique, bytes int64
			start := time.Now()
			query("deparse-"+label, sql, nil, &rows, &unique, &bytes)
			if rows <= 0 || unique <= 0 || unique > rows || bytes <= 0 || distinct && rows != unique {
				t.Fatal("attribution descriptor evidence invalid")
			}
			if sample >= 0 {
				t.Logf("attribution deparse kind=%s sample=%d rows=%d distinct=%d bytes=%d elapsed_ms=%d", label, sample, rows, unique, bytes, time.Since(start).Milliseconds())
			}
		}
	}
	predQuery := "SELECT (" + compiled(region.Query) + ") FROM (SELECT $1::text AS c,$2::text AS f) attribution_arguments"
	for _, spec := range []struct {
		label, sql string
		args       []any
	}{{"catalog", strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(liveCatalog), ";")), nil}, {"predecessor-static", predQuery, []any{"b0ce6cf26b4b5f7e909f2e8e8ba5fdc987318efb21878c503117b4583b1544a8", "3559e54be45e44575699fb6fad8f23edffe3e98a5b8228f2b2b96ae42057ae92"}}} {
		var plan []byte
		query("explain-"+spec.label, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+spec.sql, spec.args, &plan)
		// Catalog uses a different query, so generated predecessor CTE labels
		// cannot attribute its nodes even if a same-spelled name were present.
		var sourceMap map[string]string
		if spec.label == "predecessor-static" {
			sourceMap = sources
		}
		metrics, err := readinessAttributionPlan(plan, sourceMap)
		if err != nil {
			t.Fatal("attribution plan shape invalid")
		}
		if output != "" {
			// Keep preorder/linkage in evidence; sort only an independent copy
			// for the existing top12 summary.
			artifact.Plans = append(artifact.Plans, readinessAttributionObservedPlan{Root: spec.label, Metrics: metrics})
			metrics.Nodes = append([]readinessAttributionNode(nil), metrics.Nodes...)
		}
		t.Logf("attribution plan=%s planning_ms=%.3f execution_ms=%.3f nodes=%d", spec.label, metrics.PlanningMS, metrics.ExecutionMS, len(metrics.Nodes))
		sort.SliceStable(metrics.Nodes, func(i, j int) bool { return metrics.Nodes[i].TotalMS > metrics.Nodes[j].TotalMS })
		for i, n := range metrics.Nodes {
			if i == 12 {
				break
			}
			t.Logf("attribution plan=%s rank=%d kind=%s inclusive_ms=%.3f rows=%.0f loops=%.0f hit_blocks=%.0f read_blocks=%.0f", spec.label, i, n.Kind, n.TotalMS, n.Rows, n.Loops, n.Hits, n.Reads)
		}
	}
	if output != "" {
		artifact.WorkerChecksum = checksum
		hash, err := writeReadinessAttributionArtifact(output, artifact)
		if err != nil {
			t.Fatal("attribution sanitized artifact write failed")
		}
		t.Logf("attribution sanitized source tree sha256=%s plans=%d", hash, len(artifact.Plans))
	}
	t.Log("catalog attribution only; plan times include instrumentation, inclusive nodes overlap; no policy capacity acceptance")
	return true
}
