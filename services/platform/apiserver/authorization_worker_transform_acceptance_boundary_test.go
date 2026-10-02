package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Diagnostics contain fixed locations only; Cause remains available to errors.As
// but is never interpolated into Error or published/logged as text.
type transformAcceptanceFailure struct {
	Rule, Field, Stage, Phase string
	Cause                     error
}

func (e *transformAcceptanceFailure) Error() string { return "transform acceptance refused" }
func (e *transformAcceptanceFailure) Unwrap() error { return e.Cause }
func transformAllowed(value string, allowed []string) string {
	for _, x := range allowed {
		if value == x {
			return value
		}
	}
	return "none"
}

var transformCaseIDs = []string{"pristine", "config-null", "config-empty", "config-quoted", "config-nonstandard", "owner", "acl", "replacement", "constraint-duplicate", "constraint-null", "saved-missing", "saved-null-definition", "saved-null-acl", "saved-duplicate-definition", "saved-duplicate-acl", "saved-unselected-duplicate", "saved-missing-column", "saved-missing-relation", "literal-missing"}
var transformRuleIDs = []string{"temporal:70.fingerprint:function", "temporal:71.fingerprint:function", "temporal:74.outbox65_fingerprint:function", "temporal:74.owner66_fingerprint:function", "temporal:75.fingerprint:function", "temporal:77.domain67_fingerprint:function", "temporal:78.predecessor73_fingerprint:function", "temporal:78.predecessor76_fingerprint:function", "temporal:78.predecessor76_fingerprint:executor-function", "public:sa_attack_lab:function", "public:sa_export:function", "public:sa_multistep:function", "public:sa_webhook:function"}
var transformFieldIDs = []string{"name", "identity_arguments", "owner", "acl", "definition", "identity", "namespace_name", "security_definer", "volatility", "parallel", "strict", "leakproof", "config_text_or_empty"}
var transformStageIDs = []string{"cardinality", "shape", "missing-field", "type", "value", "line", "aggregate", "mutation", "config", "sql", "frame", "combined", "refused"}
var transformPhaseIDs = []string{"initial", "begin", "configure", "admission", "evidence", "setup", "constraint", "original", "original-aggregate", "candidate", "candidate-aggregate", "roster", "witness", "combined", "raw", "comparison", "rollback", "restored", "post-begin", "post-configure", "post-admission", "post-evidence", "post-rollback", "final-restored", "validation"}

func (e *transformAcceptanceFailure) Diagnostic() map[string]string {
	d := map[string]string{"case": "none", "rule": "none", "field": "none", "stage": "refused", "phase": "none"}
	var inner *transformAcceptanceFailure
	if errors.As(e.Cause, &inner) {
		d = inner.Diagnostic()
	}
	if v := transformAllowed(e.Rule, transformRuleIDs); v != "none" {
		d["rule"] = v
	}
	if v := transformAllowed(e.Field, transformFieldIDs); v != "none" {
		d["field"] = v
	}
	if v := transformAllowed(e.Stage, transformStageIDs); v != "none" {
		d["stage"] = v
	}
	if v := transformAllowed(e.Phase, transformPhaseIDs); v != "none" && d["phase"] == "none" {
		d["phase"] = v
	}
	// errors.As walks joined causes in order. Preserve the earliest PostgreSQL
	// failure, not a later rollback/disposal failure; never print Message/Detail.
	var p *pgconn.PgError
	if errors.As(e.Cause, &p) && len(p.Code) == 5 && strings.IndexFunc(p.Code, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z') }) < 0 {
		d["sqlstate"] = p.Code
		if d["stage"] == "refused" {
			d["stage"] = "sql"
		}
		if p.Position >= 0 && p.Position <= 1048576 {
			d["position"] = strconv.Itoa(int(p.Position))
		}
	}
	return d
}
func transformFailure(rule, field, stage string, cause error) error {
	return &transformAcceptanceFailure{Rule: rule, Field: field, Stage: stage, Cause: cause}
}
func transformAt(rule, phase string, cause error) error {
	if cause == nil {
		return nil
	}
	return &transformAcceptanceFailure{Rule: rule, Phase: phase, Cause: cause}
}
func compareTransformAggregate(rule string, original, candidate *string) error {
	if !reflect.DeepEqual(original, candidate) {
		return transformFailure(rule, "none", "aggregate", nil)
	}
	return nil
}

type transformAcceptanceCase struct {
	ID                            string
	Write                         bool
	SQLState                      string
	Mode                          string
	RuleIDs, Setup                []string
	MustChange, ExpectNonstandard bool
	ProbeSQL, WitnessSQL          string
}
type transformAcceptanceRule struct {
	ID                                                         string
	Cap                                                        int
	Fields                                                     []string
	FieldTypes                                                 map[string]string
	SourceIdentity, SourceSHA256, DefinitionSHA256, SiteSHA256 string
	OriginalSQL, CandidateSQL, RosterSQL, WitnessSQL           string
	OriginalAggregateSQL, CandidateAggregateSQL                string
	OriginalFrame, CandidateFrame                              map[string]string
}
type transformAcceptanceRow struct {
	OID, Identity, Line string
	Fact                json.RawMessage
}

func compareTransformAcceptanceRows(rule transformAcceptanceRule, original, candidate []transformAcceptanceRow, roster map[string]string) (string, error) {
	if rule.Cap <= 0 || rule.Cap > 380 || len(original) == 0 || len(original) != len(candidate) || len(original) > rule.Cap || len(roster) != len(original) {
		return "", transformFailure(rule.ID, "none", "cardinality", nil)
	}
	parsed := func(raw json.RawMessage) (map[string]any, error) {
		var m map[string]any
		if supplementJSON(raw, &m) != nil || len(m) != len(rule.Fields) {
			return nil, transformFailure(rule.ID, "none", "shape", nil)
		}
		for _, f := range rule.Fields {
			v, ok := m[f]
			if !ok {
				return nil, transformFailure(rule.ID, f, "missing-field", nil)
			}
			if v == nil {
				continue
			}
			switch rule.FieldTypes[f] {
			case "boolean":
				if _, ok := v.(bool); !ok {
					return nil, transformFailure(rule.ID, f, "type", nil)
				}
			case "string":
				if _, ok := v.(string); !ok {
					return nil, transformFailure(rule.ID, f, "type", nil)
				}
			default:
				return nil, transformFailure(rule.ID, f, "type", nil)
			}
		}
		return m, nil
	}
	originals := map[string]transformAcceptanceRow{}
	for _, r := range original {
		if r.OID == "" {
			return "", supplementRefusal("transform OID")
		}
		if _, ok := originals[r.OID]; ok {
			return "", supplementRefusal("transform duplicate original")
		}
		if _, e := parsed(r.Fact); e != nil {
			return "", e
		}
		originals[r.OID] = r
	}
	seen := map[string]bool{}
	lines := []string{}
	for _, r := range candidate {
		var key []string
		if supplementJSON([]byte(r.Identity), &key) != nil || len(key) != 2 || key[0] != rule.ID || key[1] == "" || seen[key[1]] {
			return "", supplementRefusal("transform key")
		}
		seen[key[1]] = true
		oid, ok := roster[key[1]]
		if !ok {
			return "", supplementRefusal("transform foreign identity")
		}
		old, ok := originals[oid]
		if !ok {
			return "", supplementRefusal("transform unmatched original")
		}
		want, e := parsed(old.Fact)
		if e != nil {
			return "", e
		}
		got, e := parsed(r.Fact)
		if e != nil {
			return "", e
		}
		for _, f := range rule.Fields {
			if !reflect.DeepEqual(want[f], got[f]) {
				return "", transformFailure(rule.ID, f, "value", nil)
			}
		}
		if old.Line != r.Line {
			return "", transformFailure(rule.ID, "none", "line", nil)
		}
		encoded, _ := json.Marshal(got)
		lines = append(lines, r.Identity+"\x00"+string(encoded)+"\x00"+r.Line)
		delete(originals, oid)
	}
	if len(originals) != 0 {
		return "", supplementRefusal("transform unmatched roster")
	}
	sort.Strings(lines)
	raw, _ := json.Marshal(lines)
	return supplementSHA(raw), nil
}

type transformAcceptanceIO struct {
	Frame     func(context.Context) (orderedSupplementFrame, error)
	Begin     func(context.Context, bool) error
	Configure func(context.Context) error
	Admission func(context.Context) error
	Evidence  func(context.Context) (string, error)
	Exercise  func(context.Context, transformAcceptanceCase) (json.RawMessage, error)
	Validate  func(context.Context, json.RawMessage) error
	Rollback  func(context.Context) error
	Dispose   func(context.Context) error
}

func runTransformAcceptanceCase(ctx context.Context, c transformAcceptanceCase, io transformAcceptanceIO) (result json.RawMessage, err error) {
	if ctx == nil || ctx.Err() != nil || c.ID == "" || io.Frame == nil || io.Begin == nil || io.Configure == nil || io.Admission == nil || io.Evidence == nil || io.Exercise == nil || io.Validate == nil || io.Rollback == nil || io.Dispose == nil {
		return nil, supplementRefusal("transform dependencies")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	phase := "initial"
	active := false
	rollback := func() error {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		active = false
		return io.Rollback(cleanup)
	}
	defer func() {
		if active {
			err = errors.Join(err, rollback())
		}
		if err != nil {
			result = nil
			err = transformAt("none", phase, err)
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			err = errors.Join(err, io.Dispose(cleanup))
		}
	}()
	original, e := io.Frame(ctx)
	if e != nil || (original.Session != "zasp_test" && original.Session != "zasp_e2e") || original.Role != original.Session || original.ReadOnly || original.Postgres == "" || original.ServerVersionNum != "180003" || original.Pgcrypto != "1.4" {
		return nil, errors.Join(supplementRefusal("transform original frame"), e)
	}
	phase = "begin"
	if e = io.Begin(ctx, c.Write); e != nil {
		return nil, e
	}
	active = true
	phase = "configure"
	if e = io.Configure(ctx); e != nil {
		return nil, e
	}
	phase = "admission"
	if e = io.Admission(ctx); e != nil {
		return nil, e
	}
	phase = "evidence"
	before, e := io.Evidence(ctx)
	if e != nil || before == "" {
		return nil, errors.Join(supplementRefusal("transform initial evidence"), e)
	}
	phase = "comparison"
	result, e = io.Exercise(ctx, c)
	if e != nil || ctx.Err() != nil || len(result) == 0 || len(result) > 16*1024*1024 {
		return nil, errors.Join(supplementRefusal("transform comparison"), e)
	}
	if e = rollback(); e != nil {
		return nil, transformAt("none", "rollback", e)
	}
	phase = "restored"
	restored, e := io.Frame(ctx)
	if e != nil || restored != original {
		return nil, errors.Join(supplementRefusal("transform frame restoration"), e)
	}
	firstRestored := restored
	phase = "post-begin"
	if e = io.Begin(ctx, false); e != nil {
		return nil, e
	}
	active = true
	phase = "post-configure"
	if e = io.Configure(ctx); e != nil {
		return nil, e
	}
	phase = "post-admission"
	if e = io.Admission(ctx); e != nil {
		return nil, e
	}
	phase = "post-evidence"
	after, e := io.Evidence(ctx)
	if e != nil || after != before {
		return nil, errors.Join(supplementRefusal("transform evidence restoration"), e)
	}
	phase = "post-rollback"
	if e = rollback(); e != nil {
		return nil, e
	}
	phase = "final-restored"
	restored, e = io.Frame(ctx)
	if e != nil || restored != original || ctx.Err() != nil {
		return nil, errors.Join(supplementRefusal("transform final restoration"), e)
	}
	// No local process, artifact or RPC is executed while holding a transaction.
	// This validation still spends the same, unreset 30-second case budget.
	phase = "validation"
	if e = io.Validate(ctx, result); e != nil || ctx.Err() != nil {
		return nil, errors.Join(supplementRefusal("transform restored validation"), e)
	}
	var evidence map[string]json.RawMessage
	if supplementJSON(result, &evidence) != nil || evidence == nil || evidence["frames"] != nil {
		return nil, supplementRefusal("transform evidence frames")
	}
	frames, e := json.Marshal(map[string]orderedSupplementFrame{"initial": original, "restored": firstRestored, "postAdmissionRestored": restored})
	if e != nil {
		return nil, e
	}
	evidence["frames"] = frames
	result, e = json.Marshal(evidence)
	if e != nil || len(result) > 16*1024*1024 {
		return nil, supplementRefusal("transform evidence bounds")
	}
	return result, nil
}

func checkTransformRawObservations(p transformAcceptancePacket, rows []json.RawMessage, counts map[string]int) error {
	shape := orderedSupplementShape{MaxRows: p.MaxRows, MaxBytes: p.MaxBytes, Fields: map[string]map[string]string{"routine": {}}, CategoryMaxRows: map[string]int{"routine": p.MaxRows}, RuleMaxRows: map[string]int{}}
	expected := map[string]int{}
	for _, raw := range p.RawRules {
		var value map[string]json.RawMessage
		if supplementJSON(raw, &value) != nil {
			return supplementRefusal("transform raw declaration")
		}
		var r orderedSupplementRule
		if supplementJSON(value["id"], &r.ID) != nil || supplementJSON(value["kind"], &r.Kind) != nil || supplementJSON(value["fields"], &r.Fields) != nil {
			return supplementRefusal("transform raw fields")
		}
		for _, rule := range p.Rules {
			if r.ID == "raw-transform:"+rule.ID || strings.HasPrefix(rule.ID, "public:") && r.ID == "raw-transform:"+strings.TrimSuffix(rule.ID, ":function") {
				shape.RuleMaxRows[r.ID] = rule.Cap
				expected[r.ID] = counts[rule.ID]
			}
		}
		if expected[r.ID] <= 0 {
			return supplementRefusal("transform raw comparison coverage")
		}
		for _, f := range r.Fields {
			switch f {
			case "security_definer", "strict", "leakproof":
				shape.Fields["routine"][f] = "boolean"
			case "namespace_name", "name", "identity_arguments", "owner", "acl", "definition", "config_text_or_empty", "volatility", "parallel":
				shape.Fields["routine"][f] = "string"
			default:
				return supplementRefusal("transform raw unsupported field")
			}
		}
		shape.Rules = append(shape.Rules, r)
	}
	if e := checkOrderedSupplementRows(shape, rows); e != nil {
		return e
	}
	actual := map[string]int{}
	for _, raw := range rows {
		var r struct {
			Kind, Identity string
			Fact           json.RawMessage
		}
		if supplementJSON(raw, &r) != nil {
			return supplementRefusal("transform raw row")
		}
		var key []string
		if supplementJSON([]byte(r.Identity), &key) != nil || len(key) != 2 {
			return supplementRefusal("transform raw key")
		}
		actual[key[0]]++
	}
	if !reflect.DeepEqual(expected, actual) {
		return supplementRefusal("transform incomplete raw universe")
	}
	return nil
}

func checkTransformWitnessRoster(rows []json.RawMessage, roster map[string]string) error {
	if len(rows) == 0 || len(rows) != len(roster) {
		return supplementRefusal("transform witness universe")
	}
	seen := map[string]bool{}
	for _, raw := range rows {
		var r struct {
			ObjectOID, Identity, OriginalText          string
			Config, Dimensions, LowerBound, UpperBound json.RawMessage
		}
		if supplementJSON(raw, &r) != nil || r.Identity == "" || r.ObjectOID == "" || roster[r.Identity] != r.ObjectOID || seen[r.Identity] {
			return supplementRefusal("transform witness identity")
		}
		seen[r.Identity] = true
	}
	return nil
}

type transformAcceptanceCaseError struct {
	ID    string
	Cause error
}

func checkTransformExecutionFrame(f orderedSupplementFrame, write bool, searchPath string) error {
	if (searchPath != "pg_catalog" && searchPath != "pg_catalog, public") || (f.Session != "zasp_test" && f.Session != "zasp_e2e") || f.Role != "zasp_discovery_authority" || f.SearchPath != searchPath || f.TimeZone != "UTC" || f.ReadOnly == write || f.Postgres != transformAcceptancePostgres || f.ServerVersionNum != "180003" || f.Pgcrypto != "1.4" {
		return supplementRefusal("transform execution frame")
	}
	return nil
}

func compareTransformCombinedRows(expected, actual []json.RawMessage) error {
	parse := func(rows []json.RawMessage) (map[string]any, error) {
		if len(rows) == 0 || len(rows) > 380 {
			return nil, supplementRefusal("transform combined count")
		}
		out := map[string]any{}
		size := 0
		for _, raw := range rows {
			size += len(raw)
			if size > 16777216 {
				return nil, supplementRefusal("transform combined bytes")
			}
			var r struct {
				Kind, Identity string
				Fact           map[string]any
			}
			if supplementJSON(raw, &r) != nil || r.Kind != "routine" || r.Fact == nil || out[r.Identity] != nil {
				return nil, supplementRefusal("transform combined row")
			}
			var key []string
			if supplementJSON([]byte(r.Identity), &key) != nil || len(key) != 2 || key[0] == "" || key[1] == "" {
				return nil, supplementRefusal("transform combined identity")
			}
			out[r.Identity] = r.Fact
		}
		return out, nil
	}
	want, e := parse(expected)
	if e != nil {
		return e
	}
	got, e := parse(actual)
	if e != nil {
		return transformFailure("none", "none", "combined", e)
	}
	keys := make([]string, 0, len(want))
	for key := range want {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		var id []string
		_ = json.Unmarshal([]byte(key), &id)
		if !reflect.DeepEqual(want[key], got[key]) {
			left, _ := want[key].(map[string]any)
			right, _ := got[key].(map[string]any)
			for _, field := range transformFieldIDs {
				if !reflect.DeepEqual(left[field], right[field]) {
					return transformFailure(id[0], field, "combined", nil)
				}
			}
			return transformFailure(id[0], "none", "combined", nil)
		}
	}
	if len(want) != len(got) {
		return transformFailure("none", "none", "combined", nil)
	}
	return nil
}

func (e *transformAcceptanceCaseError) Error() string { return "transform case refused" }
func (e *transformAcceptanceCaseError) Unwrap() error { return e.Cause }
func (e *transformAcceptanceCaseError) Diagnostic() map[string]string {
	d := (&transformAcceptanceFailure{Cause: e.Cause}).Diagnostic()
	d["case"] = transformAllowed(e.ID, transformCaseIDs)
	return d
}

func runTransformAcceptanceGroup(ctx context.Context, cases []transformAcceptanceCase, io transformAcceptanceIO, paths []string, destination string, encode func([]json.RawMessage) ([]byte, error)) (pub orderedSupplementPublication, err error) {
	if ctx == nil || ctx.Err() != nil || io.Dispose == nil || encode == nil {
		return pub, supplementRefusal("transform group dependencies")
	}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			err = errors.Join(err, io.Dispose(cleanup))
		}
	}()
	ids := transformCaseIDs
	if len(cases) != len(ids) {
		return pub, supplementRefusal("transform incomplete matrix")
	}
	for i, c := range cases {
		if c.ID != ids[i] {
			return pub, supplementRefusal("transform case order")
		}
	}
	results := make([]json.RawMessage, 0, len(cases))
	for _, c := range cases {
		raw, e := runTransformAcceptanceCase(ctx, c, io)
		if e != nil {
			return pub, &transformAcceptanceCaseError{c.ID, e}
		}
		results = append(results, raw)
	}
	payload, e := encode(results)
	if e != nil || ctx.Err() != nil {
		return pub, supplementRefusal("transform group encode")
	}
	return publishPrivateReference(ctx, destination, paths, payload, 16*1024*1024, nil)
}
