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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	registrationReferenceCatalogSHA  = "28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016"
	registrationReferenceMaxRows     = 20000
	registrationReferenceMaxBagRows  = 5000
	registrationReferenceMaxRowBytes = 4 * 1024 * 1024
	registrationReferenceMaxBytes    = 128 * 1024 * 1024
	registrationReferenceDuration    = 90 * time.Second
)

func registrationReferenceSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func registrationReferenceString(s string) *string { return &s }
func registrationReferenceRefuse(reason string) error {
	return fmt.Errorf("original registration reference refused: %s", reason)
}

type registrationReferenceField struct {
	Type   string          `json:"type"`
	Raw    json.RawMessage `json:"raw"`
	Null   bool            `json:"null"`
	Output *string         `json:"output"`
}

// Full typed frame for every F and TF occurrence; native OIDs are not portable
// keys. NULL ACL/config remain distinct from an empty ACL/config.
type registrationReferenceFunctionFrame struct {
	Schema          string    `json:"schema"`
	Name            string    `json:"name"`
	Arguments       string    `json:"arguments"`
	Definition      string    `json:"definition"`
	Owner           string    `json:"owner"`
	ACL             *string   `json:"acl"`
	Language        string    `json:"language"`
	Result          string    `json:"result"`
	Volatility      string    `json:"volatility"`
	Parallel        string    `json:"parallel"`
	SecurityDefiner bool      `json:"security_definer"`
	Strict          bool      `json:"strict"`
	Config          *[]string `json:"config"`
}

type registrationReferenceRow struct {
	Ordinal        int                                 `json:"ordinal"`
	Key            json.RawMessage                     `json:"key"`
	Fields         []registrationReferenceField        `json:"fields"`
	V              *string                             `json:"v"`
	Function       *registrationReferenceFunctionFrame `json:"function,omitempty"`
	SavedSpellings json.RawMessage                     `json:"saved_spellings,omitempty"`
}
type registrationReferenceBag struct {
	Line            int                        `json:"line"`
	SiteSHA256      string                     `json:"site_sha256"`
	StatementSHA256 string                     `json:"statement_sha256"`
	Complete        bool                       `json:"complete"`
	Rows            []registrationReferenceRow `json:"rows"`
	NullArguments   []int                      `json:"null_arguments"`
	NullValues      int                        `json:"null_values"`
	DuplicateValues int                        `json:"duplicate_values"`
	EvidenceSHA256  string                     `json:"byte_bag_sha256"`
}
type registrationReferenceSite struct {
	Line            int      `json:"line"`
	Label           string   `json:"label"`
	Source          string   `json:"source"`
	SourceSHA256    string   `json:"source_sha256"`
	Start           int      `json:"start_byte"`
	End             int      `json:"end_byte"`
	Selector        string   `json:"selector"`
	Expressions     []string `json:"expressions"`
	Types           []string `json:"types"`
	Statement       string   `json:"statement"`
	StatementSHA256 string   `json:"statement_sha256"`
	FunctionFrame   bool     `json:"function_frame"`
}
type registrationReferenceStatementPlan struct {
	CatalogSHA256      string                      `json:"catalog_sha256"`
	Catalog            string                      `json:"catalog"`
	GuardSource        string                      `json:"guard_source"`
	GuardSHA256        string                      `json:"guard_sha256"`
	Fingerprint        string                      `json:"fingerprint"`
	RuntimeFingerprint string                      `json:"runtime_fingerprint"`
	Sites              []registrationReferenceSite `json:"sites"`
}

// Independent ordinal vectors, counted after each literal label. No blanket
// ::text projection is used to obtain native output: concat_ws(”, expr)
// invokes precisely the expression's original type output.
func registrationReferenceTypes(line int) []string {
	var s string
	switch line {
	case 4:
		s = "text,text"
	case 15:
		s = "name,text,text"
	case 5, 16:
		s = "text,text,text,text"
	case 6, 17:
		s = "name,\"char\",text,text,boolean,boolean"
	case 24:
		s = "text,\"char\",text,text,boolean,boolean"
	case 7, 18:
		s = "name,smallint,name,text,boolean,text,text"
	case 8, 19:
		s = "name,name,text,boolean"
	case 20:
		s = "name,text,boolean,boolean,boolean"
	case 9, 21:
		s = "text,name,boolean,\"char\",text,text,text"
	case 26:
		s = "name,boolean,\"char\",text,text,text"
	case 10, 22, 37:
		s = "text,name,\"char\",text"
	case 36:
		s = "name,\"char\",text"
	case 23, 32, 33, 38, 39, 40, 41:
		s = "text,name,\"char\",text,text,text,text"
	case 11, 27:
		s = "text,text,text,text"
	case 12, 35:
		s = "text,text"
	case 25:
		s = "smallint,name,text"
	case 31:
		s = "boolean,text,text"
	case 34:
		s = "text,text,text,text"
	}
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// A deliberately finite parser for the pinned original expression. Quotes,
// escaped quotes and nested calls are handled; an unsupported span refuses.
func registrationReferenceArguments(s string) ([]string, error) {
	var args []string
	start, depth := 0, 0
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				if i+1 < len(s) && s[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, registrationReferenceRefuse("expression framing")
			}
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 || quote != 0 {
		return nil, registrationReferenceRefuse("expression framing")
	}
	args = append(args, strings.TrimSpace(s[start:]))
	return args, nil
}
func registrationReferenceProjectionEnd(s string, start int) (int, error) {
	depth := 0
	quote := byte(0)
	for i := start; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				if i+1 < len(s) && s[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, registrationReferenceRefuse("projection framing")
}

func registrationReferenceFunctionSQL(alias string) string {
	return `(SELECT jsonb_build_object('schema',n.nspname,'name',` + alias + `.proname,'arguments',pg_get_function_identity_arguments(` + alias + `.oid),'definition',pg_get_functiondef(` + alias + `.oid),'owner',` + alias + `.proowner::regrole::text,'acl',` + alias + `.proacl::text,'language',l.lanname,'result',pg_get_function_result(` + alias + `.oid),'volatility',` + alias + `.provolatile,'parallel',` + alias + `.proparallel,'security_definer',` + alias + `.prosecdef,'strict',` + alias + `.proisstrict,'config',` + alias + `.proconfig) FROM pg_namespace n JOIN pg_language l ON l.oid=` + alias + `.prolang WHERE n.oid=` + alias + `.pronamespace)`
}
func registrationReferenceRelationKey(alias string) string {
	return `(SELECT jsonb_build_array(n.nspname,` + alias + `.relname) FROM pg_namespace n WHERE n.oid=` + alias + `.relnamespace)`
}
func registrationReferenceKeySQL(line int) string {
	switch line {
	case 4, 15:
		return `jsonb_build_array('schema',nspname)`
	case 5, 16:
		return `(SELECT jsonb_build_array('function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_namespace n WHERE n.oid=p.pronamespace)`
	case 6, 17, 24, 34, 35:
		return `jsonb_build_array('relation',` + registrationReferenceRelationKey("c") + `)`
	case 7, 18:
		return `jsonb_build_array('column',` + registrationReferenceRelationKey("c") + `,a.attnum,a.attname)`
	case 8, 19:
		return `jsonb_build_array('constraint',` + registrationReferenceRelationKey("c") + `,k.conname)`
	case 20:
		return `jsonb_build_array('index',` + registrationReferenceRelationKey("c") + `,(SELECT ` + registrationReferenceRelationKey("ic") + ` FROM pg_class ic WHERE ic.oid=i.indexrelid))`
	case 9, 21, 26:
		return `jsonb_build_array('policy',(SELECT ` + registrationReferenceRelationKey("pc") + ` FROM pg_class pc WHERE pc.oid=p.polrelid),p.polname)`
	case 10, 22, 23, 32, 33, 36, 37, 38, 39, 40, 41:
		return `jsonb_build_array('trigger',(SELECT ` + registrationReferenceRelationKey("tc") + ` FROM pg_class tc WHERE tc.oid=t.tgrelid),t.tgname,(SELECT jsonb_build_array(n.nspname,fp.proname,pg_get_function_identity_arguments(fp.oid)) FROM pg_proc fp JOIN pg_namespace n ON n.oid=fp.pronamespace WHERE fp.oid=t.tgfoid))`
	case 11, 27:
		return `jsonb_build_array('saved-function',signature)`
	case 12:
		return `jsonb_build_array('saved-view',signature)`
	case 25:
		return `jsonb_build_array('column','public','zasp_runtime_stage_work',a.attnum,a.attname)`
	case 31:
		return `jsonb_build_array('runtime-registration',singleton)`
	}
	panic("unbound original selector key")
}

func registrationReferencePlan(source string) (registrationReferenceStatementPlan, error) {
	p := registrationReferenceStatementPlan{Catalog: source, CatalogSHA256: registrationReferenceSHA([]byte(source))}
	if p.CatalogSHA256 != registrationReferenceCatalogSHA {
		return p, registrationReferenceRefuse("original catalog source hash")
	}
	lines := strings.Split(source, "\n")
	if len(lines) != 45 {
		return p, registrationReferenceRefuse("original source line closure")
	}
	p.GuardSource = lines[1]
	p.GuardSHA256 = registrationReferenceSHA([]byte(p.GuardSource))
	// These substrings are source spans, not candidate SQL lowering. Scalar
	// boundaries are unique in the admitted original source.
	const outerAnchor = "WHERE fingerprint=("
	start := strings.Index(source, outerAnchor)
	if start >= 0 {
		start += len(outerAnchor)
	}
	end := strings.LastIndex(source, "\n ))")
	if start < 0 || end <= start {
		return p, registrationReferenceRefuse("original outer span")
	}
	p.Fingerprint = source[start:end]
	// The source compiler replaces the marker, preserving the enclosing
	// scalar parentheses. Bind that original scalar's exact source span.
	const nestedAnchor = "UNION ALL SELECT 'runtime-catalog|'||("
	nestedStart := strings.Index(source, nestedAnchor)
	if nestedStart < 0 {
		return p, registrationReferenceRefuse("runtime scalar provenance")
	}
	nestedStart += len(nestedAnchor)
	nestedEnd := strings.Index(source[nestedStart:], "\n )\n UNION ALL SELECT concat_ws('|','runtime-registration'")
	if nestedEnd < 0 {
		return p, registrationReferenceRefuse("runtime scalar closing span")
	}
	p.RuntimeFingerprint = source[nestedStart : nestedStart+nestedEnd]
	offset := 0
	for i, line := range lines {
		lineNo := i + 1
		types := registrationReferenceTypes(lineNo)
		if types == nil {
			offset += len(line) + 1
			continue
		}
		trim := strings.TrimSpace(line)
		trim = strings.TrimPrefix(trim, "UNION ALL ")
		if !strings.HasPrefix(trim, "SELECT concat_ws(") {
			return p, registrationReferenceRefuse("original projection site")
		}
		call := strings.Index(trim, "(")
		close, err := registrationReferenceProjectionEnd(trim, call)
		if err != nil {
			return p, err
		}
		args, err := registrationReferenceArguments(trim[call+1 : close])
		if err != nil || len(args) != len(types)+2 || args[0] != "'|'" {
			return p, registrationReferenceRefuse("original ordinal/type roster")
		}
		label := strings.Trim(args[1], "'")
		selector := trim[close+1:]
		if !strings.HasPrefix(selector, " FROM ") {
			return p, registrationReferenceRefuse("original selector span")
		}
		site := registrationReferenceSite{Line: lineNo, Label: label, Source: line, SourceSHA256: registrationReferenceSHA([]byte(line)), Start: offset, End: offset + len(line), Selector: selector, Expressions: args[2:], Types: types, FunctionFrame: lineNo == 5 || lineNo == 16 || lineNo == 23 || lineNo == 32 || lineNo == 33 || lineNo >= 38}
		fields := make([]string, len(site.Expressions))
		for j, a := range site.Expressions {
			fields[j] = `jsonb_build_object('type',pg_typeof(` + a + `)::text,'raw',to_jsonb(` + a + `),'null',(` + a + ` IS NULL),'output',CASE WHEN ` + a + ` IS NULL THEN NULL ELSE concat_ws('',` + a + `) END)`
		}
		projection := `jsonb_build_object('key',` + registrationReferenceKeySQL(lineNo) + `,'fields',jsonb_build_array(` + strings.Join(fields, ",") + `),'v',` + trim[len("SELECT "):close+1]
		if site.FunctionFrame {
			projection += `,'function',` + registrationReferenceFunctionSQL("p")
		}
		if lineNo == 5 || lineNo == 16 {
			table := "zasp_authorization80_worker"
			if lineNo == 16 {
				table = "zasp_authorization80_runtime"
			}
			projection += `,'saved_spellings',(SELECT COALESCE(jsonb_agg(signature ORDER BY signature),'[]'::jsonb) FROM ` + table + `.predecessor_functions WHERE to_regprocedure(signature)=p.oid)`
		}
		projection += `)`
		// The CASE bounds the driver result before its raw JSON is buffered.
		// LIMIT+1 refuses overflow, it never silently truncates a selected bag.
		site.Statement = `SELECT CASE WHEN octet_length(q.row::text)<=` + strconv.Itoa(registrationReferenceMaxRowBytes) + ` THEN q.row ELSE NULL END FROM (SELECT ` + projection + selector + `) q(row) LIMIT ` + strconv.Itoa(registrationReferenceMaxBagRows+1)
		site.StatementSHA256 = registrationReferenceSHA([]byte(site.Statement))
		p.Sites = append(p.Sites, site)
		offset += len(line) + 1
	}
	if len(p.Sites) != 33 {
		return p, registrationReferenceRefuse("complete 33-bag roster")
	}
	return p, nil
}

func registrationReferenceAdmitField(f registrationReferenceField, expected string) error {
	if f.Type != expected || len(f.Raw) == 0 || !json.Valid(f.Raw) || (f.Null != (string(f.Raw) == "null")) || (f.Null != (f.Output == nil)) {
		return registrationReferenceRefuse("typed NULL/native output frame")
	}
	if f.Null {
		return nil
	}
	if f.Output == nil {
		return registrationReferenceRefuse("native output absent")
	}
	switch expected {
	case "boolean":
		var v bool
		if json.Unmarshal(f.Raw, &v) != nil || *f.Output != map[bool]string{true: "t", false: "f"}[v] {
			return registrationReferenceRefuse("bare boolean native output")
		}
	case "text", "name", "\"char\"":
		var v string
		if json.Unmarshal(f.Raw, &v) != nil || *f.Output != v {
			return registrationReferenceRefuse("native string output")
		}
	case "smallint", "int2":
		var v int16
		if json.Unmarshal(f.Raw, &v) != nil || *f.Output != strconv.Itoa(int(v)) {
			return registrationReferenceRefuse("native int2 output")
		}
	default:
		return registrationReferenceRefuse("unbound field type")
	}
	return nil
}
func registrationReferenceConcat(label string, fields []registrationReferenceField) string {
	parts := []string{label}
	for _, f := range fields {
		if !f.Null && f.Output != nil {
			parts = append(parts, *f.Output)
		}
	}
	return strings.Join(parts, "|")
}

func registrationReferenceGuard(count int64, fingerprint, derived *string) bool {
	return count == 1 && fingerprint != nil && derived != nil && *fingerprint == *derived
}
func registrationReferenceAdmitRuntimeRow(raw []byte, checksum string) error {
	var r struct {
		Singleton             bool
		Checksum, Fingerprint string
	}
	if json.Unmarshal(raw, &r) != nil || !r.Singleton || r.Checksum != checksum || len(r.Fingerprint) != 64 {
		return registrationReferenceRefuse("runtime insertion checksum/row provenance")
	}
	if _, err := hex.DecodeString(r.Fingerprint); err != nil {
		return registrationReferenceRefuse("native runtime fingerprint encoding")
	}
	return nil
}
func registrationReferenceAdmitFunction(f registrationReferenceFunctionFrame) error {
	if f.Schema == "" || f.Name == "" || !strings.HasPrefix(f.Definition, "CREATE ") || f.Owner == "" || f.Language == "" || f.Result == "" || !strings.Contains("ivs", f.Volatility) || len(f.Volatility) != 1 || !strings.Contains("urs", f.Parallel) || len(f.Parallel) != 1 {
		return registrationReferenceRefuse("complete F/TF typed frame")
	}
	return nil
}
func registrationReferenceAdmitBags(plan registrationReferenceStatementPlan, bags []registrationReferenceBag) error {
	if len(bags) != 33 || len(plan.Sites) != 33 {
		return registrationReferenceRefuse("partial site coverage")
	}
	totalRows, totalBytes := 0, 0
	for i, b := range bags {
		s := plan.Sites[i]
		if b.Line != s.Line || b.SiteSHA256 != s.SourceSHA256 || !b.Complete || b.Rows == nil {
			return registrationReferenceRefuse("source/order/stream closure")
		}
		for j, r := range b.Rows {
			if r.Ordinal != j+1 || len(r.Key) == 0 || string(r.Key) == "null" || !json.Valid(r.Key) || len(r.Fields) != len(s.Types) || r.V == nil {
				return registrationReferenceRefuse("row/key/ordinal closure")
			}
			for k, f := range r.Fields {
				if err := registrationReferenceAdmitField(f, s.Types[k]); err != nil {
					return err
				}
			}
			if *r.V != registrationReferenceConcat(s.Label, r.Fields) {
				return registrationReferenceRefuse("exact native concat_ws")
			}
			if s.FunctionFrame {
				if r.Function == nil {
					return registrationReferenceRefuse("F/TF join absent")
				}
				if err := registrationReferenceAdmitFunction(*r.Function); err != nil {
					return err
				}
				if (s.Line == 5 || s.Line == 16) && (!json.Valid(r.SavedSpellings) || r.SavedSpellings == nil) {
					return registrationReferenceRefuse("saved resolution spellings absent")
				}
				definitionOrdinal, ownerOrdinal, aclOrdinal := 3, 1, 2
				if s.Line != 5 && s.Line != 16 {
					definitionOrdinal, ownerOrdinal, aclOrdinal = 4, 5, 6
				}
				if r.Fields[definitionOrdinal].Output == nil || *r.Fields[definitionOrdinal].Output != r.Function.Definition || r.Fields[ownerOrdinal].Output == nil || *r.Fields[ownerOrdinal].Output != r.Function.Owner || !reflect.DeepEqual(r.Fields[aclOrdinal].Output, r.Function.ACL) {
					return registrationReferenceRefuse("F/TF selected/joined frame differs")
				}
			}
			raw, _ := json.Marshal(r)
			totalRows++
			totalBytes += len(raw)
			if err := registrationReferenceCheckBudget(j+1, len(raw), totalRows, totalBytes); err != nil {
				return err
			}
		}
	}
	return nil
}
func registrationReferenceCheckBudget(bagRows, rowBytes, totalRows, totalBytes int) error {
	if bagRows > registrationReferenceMaxBagRows || rowBytes > registrationReferenceMaxRowBytes || totalRows > registrationReferenceMaxRows || totalBytes > registrationReferenceMaxBytes {
		return registrationReferenceRefuse("finite row/byte capture limit")
	}
	return nil
}

type registrationReferenceExecutionFrame struct {
	Session          string          `json:"session"`
	Effective        string          `json:"effective"`
	Role             string          `json:"role"`
	Path             string          `json:"path"`
	Schemas          []string        `json:"schemas"`
	RowSecurity      string          `json:"row_security"`
	Isolation        string          `json:"isolation"`
	ReadOnly         string          `json:"read_only"`
	Encoding         string          `json:"encoding"`
	ServerVersion    string          `json:"server_version"`
	AuthorityMember  bool            `json:"authority_member"`
	Superuser        bool            `json:"superuser"`
	BypassRLS        bool            `json:"bypass_rls"`
	RLSClosed        bool            `json:"rls_closed"`
	Contaminated     bool            `json:"contaminated"`
	RoleProperties   json.RawMessage `json:"role_properties"`
	Memberships      json.RawMessage `json:"memberships"`
	Settings         json.RawMessage `json:"settings"`
	StatementTimeout string          `json:"statement_timeout"`
	LockTimeout      string          `json:"lock_timeout"`
}
type registrationReferenceCollation struct {
	Name                    string  `json:"name"`
	Provider                string  `json:"provider"`
	Deterministic           bool    `json:"deterministic"`
	Locale                  *string `json:"locale"`
	Rules                   *string `json:"rules"`
	RecordedVersion         *string `json:"recorded_version"`
	ActualVersion           *string `json:"actual_version"`
	DatabaseProvider        string  `json:"database_provider"`
	DatabaseCollate         string  `json:"database_collate"`
	DatabaseCType           string  `json:"database_ctype"`
	DatabaseLocale          *string `json:"database_locale"`
	DatabaseRecordedVersion *string `json:"database_recorded_version"`
	DatabaseActualVersion   *string `json:"database_actual_version"`
}

func registrationReferenceAdmitExecution(f registrationReferenceExecutionFrame, nested, outer registrationReferenceCollation) error {
	if f.Session != "zasp_test" || f.Effective != "zasp_discovery_authority" || f.Role != "zasp_discovery_authority" || f.Path != "pg_catalog, public" || !reflect.DeepEqual(f.Schemas, []string{"pg_catalog", "public"}) || f.RowSecurity != "on" || f.Isolation != "repeatable read" || f.ReadOnly != "on" || f.Encoding != "UTF8" || f.ServerVersion != "180003" || !f.AuthorityMember || f.Superuser || f.BypassRLS || !f.RLSClosed || f.Contaminated {
		return registrationReferenceRefuse("discovery/session/RLS execution authority")
	}
	if f.StatementTimeout != "10s" || f.LockTimeout != "2s" {
		return registrationReferenceRefuse("independent native statement/lock time limits")
	}
	if !reflect.DeepEqual(nested, outer) || nested.Name == "" || !nested.Deterministic || !reflect.DeepEqual(nested.RecordedVersion, nested.ActualVersion) || !reflect.DeepEqual(nested.DatabaseRecordedVersion, nested.DatabaseActualVersion) || nested.Provider == "" || nested.DatabaseProvider == "" || nested.DatabaseCollate == "" || nested.DatabaseCType == "" {
		return registrationReferenceRefuse("effective expression collation/version ordering closure")
	}
	return nil
}
func registrationReferenceAdmitPublication(complete, restored bool, c disposablePostgresCleanupObservation) error {
	if !complete || !restored || !c.Available || !c.PGCtlStopped || !c.CommandWaitJoined || !c.NormalExit || !c.EndpointChecked || len(c.EndpointSHA256) != 64 || !c.SurvivingResourcesChecked || c.SurvivingResources != 0 {
		return registrationReferenceRefuse("complete/restored/normal joined cleanup publication gate")
	}
	return nil
}
func registrationReferenceCompare(reference, target []registrationReferenceBag) error {
	if len(reference) != len(target) {
		return registrationReferenceRefuse("comparison coverage")
	}
	for i, r := range reference {
		t := target[i]
		if r.Line != t.Line || !reflect.DeepEqual(registrationReferenceComparableRows(r.Rows), registrationReferenceComparableRows(t.Rows)) {
			return registrationReferenceRefuse(fmt.Sprintf("comparison first differing source line %d", r.Line))
		}
	}
	return nil
}
func registrationReferenceComparableRows(rows []registrationReferenceRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		r.Ordinal = 0
		b, _ := json.Marshal(r)
		out[i] = string(b)
	}
	sort.Strings(out)
	return out
}

type registrationReferenceInput struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Kind    string `json:"kind"`
	Package string `json:"package"`
}

func registrationReferenceAdmitInputs(expected, actual []registrationReferenceInput) error {
	if len(expected) == 0 || len(expected) != len(actual) {
		return registrationReferenceRefuse("complete build-consumed input roster")
	}
	e := make(map[string]registrationReferenceInput, len(expected))
	for _, f := range expected {
		if f.Path == "" || len(f.SHA256) != 64 || f.Kind == "" || f.Package == "" {
			return registrationReferenceRefuse("unbound input identity")
		}
		if _, ok := e[f.Path]; ok {
			return registrationReferenceRefuse("duplicate expected input")
		}
		e[f.Path] = f
	}
	seen := map[string]bool{}
	for _, f := range actual {
		if seen[f.Path] || e[f.Path] != f {
			return registrationReferenceRefuse("missing/changed/duplicate transitive input")
		}
		seen[f.Path] = true
	}
	return nil
}

func registrationReferenceMergeInput(old, next registrationReferenceInput) (registrationReferenceInput, error) {
	if old.Path != next.Path || old.SHA256 != next.SHA256 {
		return old, registrationReferenceRefuse("split consumed input bytes")
	}
	merge := func(a, b, separator string) string {
		seen := map[string]bool{}
		for _, v := range append(strings.Split(a, separator), strings.Split(b, separator)...) {
			seen[v] = true
		}
		out := make([]string, 0, len(seen))
		for v := range seen {
			out = append(out, v)
		}
		sort.Strings(out)
		return strings.Join(out, separator)
	}
	old.Kind = merge(old.Kind, next.Kind, "+")
	old.Package = merge(old.Package, next.Package, "|")
	return old, nil
}

// The runtime capture and frozen-build binding below deliberately live in a
// _test.go file. Nothing here is a production helper API or a candidate lowering.

type registrationReferenceAssembly struct {
	Version                 string `json:"version"`
	GoVersion               string `json:"go_version"`
	InputSHA256             string `json:"input_sha256"`
	ExecutableSHA256        string `json:"executable_sha256"`
	BuildInfo               string `json:"build_info"`
	WorkerSource            string `json:"worker_source"`
	WorkerChecksum          string `json:"worker_checksum"`
	WorkerChecksumPreimage  string `json:"worker_checksum_preimage"`
	WorkerSourceSHA256      string `json:"worker_source_sha256"`
	WorkerFingerprint       string `json:"worker_fingerprint"`
	WorkerCatalog           string `json:"worker_catalog"`
	WorkerCatalogSHA256     string `json:"worker_catalog_sha256"`
	RuntimeSource           string `json:"runtime_source"`
	RuntimeChecksum         string `json:"runtime_checksum"`
	RuntimeChecksumPreimage string `json:"runtime_checksum_preimage"`
	RuntimeSourceSHA256     string `json:"runtime_source_sha256"`
	RuntimeFingerprint      string `json:"runtime_fingerprint"`
	StopSuccessor           string `json:"stop_successor"`
	Tokens                  map[string]struct {
		Checksum     string `json:"checksum"`
		Fingerprint  string `json:"fingerprint"`
		SourceSHA256 string `json:"source_sha256"`
	} `json:"tokens"`
}
type registrationReferenceModule struct {
	Path     string                       `json:"path"`
	Version  string                       `json:"version"`
	Sum      string                       `json:"sum"`
	GoModSum string                       `json:"go_mod_sum"`
	Replace  *registrationReferenceModule `json:"replace,omitempty"`
}
type registrationReferenceBuild struct {
	Version string `json:"version"`
	// Root reviews, freezes and supplies the digest of this complete envelope.
	// A self-reported file hash or a worktree label is never build authority.
	Platform                 string                        `json:"platform"`
	GoRoot                   string                        `json:"go_root"`
	GoSHA256                 string                        `json:"go_sha256"`
	GoVersion                string                        `json:"go_version"`
	GOOS                     string                        `json:"goos"`
	GOARCH                   string                        `json:"goarch"`
	CGOEnabled               string                        `json:"cgo_enabled"`
	ModuleCache              string                        `json:"module_cache"`
	BuildCache               string                        `json:"build_cache"`
	CachePolicy              string                        `json:"cache_policy"`
	ControlledPATH           string                        `json:"controlled_path"`
	BuildCommands            [][]string                    `json:"build_commands"`
	ExecutableSHA256         string                        `json:"executable_sha256"`
	AssemblyExecutable       string                        `json:"assembly_executable"`
	AssemblyExecutableSHA256 string                        `json:"assembly_executable_sha256"`
	Inputs                   []registrationReferenceInput  `json:"inputs"`
	Modules                  []registrationReferenceModule `json:"modules"`
	InputSHA256              string                        `json:"input_sha256"`
	PG                       map[string]string             `json:"pg_binary_sha256"`
	PGExtensionFiles         map[string]string             `json:"pg_extension_files"`
	InstallerOrder           []string                      `json:"installer_order"`
	DispatchPins             map[string]string             `json:"dispatch_pins"`
}

var registrationReferenceInstallerOrder = []string{"multistepVersionedExistingTestFixture with sole startDisposablePostgresAs(zasp_test): original canonical61/bootstrap/seeds", "runTemporalDomainFreshFixture: compliance, attack-lab, exports, webhooks, discovery-schedule-replay", "runTemporalExecutorPlanningFixture: CLI up-temporal-domain; queued public62 API request; CLI up-temporal-executor; original executor admission/principal/plan controls", "runTemporalExecutorPolicyFixtureWithHook: seedOrderedApplicationGateway", "seedOrderedTestSource", "installAutomaticSourceFixture: original test-executor fixture then selector75, human-admission76, automatic-sources77", "UpProductionTemporalFindingResponse", "UpProductionAuthorizationTemporalProfile", "UpProductionAuthorizationWorkerProfile: fresh absent namespace, complete original source, separate worker registration INSERT, final guarded check", "registration reference callback; return before downstream product flow"}

// These source pins prove the original dispatch and forwarding, not a live
// tracer claim. The complete transitive roster separately binds its imports,
// embeds, predecessor compilers, upstream token providers and fixture seeds.
var registrationReferenceDispatchPins = map[string]string{
	"migrations/production_authorization_worker_profile.go":          "39929eafe70f2dfda1a1fa4d42b0d6f591badc728e7da0fe5245e5c048a057e0",
	"migrations/production_authorization_worker_runtime.go":          "3f93b8bd2ae8b08e61eaf9ffccb0694d559b93f81b03e03df3d1cbe2faa874ab",
	"migrations/production_authorization_runtime_profile.go":         "2e1505d973f621b97081cef217fa0f7f56f3d501ba77a15228a7b9bfb50a6c70",
	"apiserver/authorization_worker_effect_postgres_test.go":         "4ca7a7b3b468e9b8a8602b486d0d781253b21f97c4b6d495628ef7327226d4b8",
	"apiserver/postgres_integration_test.go":                         "0d908c53cdea021e4c60adc412a04d631fd58c0b0544e7cce723884ea4002a42",
	"apiserver/authorization_worker_ordered_policy_postgres_test.go": "302037d9efd8e55515af71a3b367fb1069b5d9e880be3c3de56cef7420f8892d",
	"apiserver/security_agent_temporal_executor_postgres_test.go":    "ba094a67bb90c1275dd75e1505d9a43e63900e5718c1092058b1f64489e29833",
}

func registrationReferenceReadBound(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, registrationReferenceRefuse("bound evidence file unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, registrationReferenceRefuse("bound evidence file size/type")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, registrationReferenceRefuse("complete bounded evidence read")
	}
	return b, nil
}
func registrationReferenceHashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", registrationReferenceRefuse("input missing")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 512*1024*1024 {
		return "", registrationReferenceRefuse("input file type/bounds")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 512*1024*1024+1))
	if err != nil || n > 512*1024*1024 {
		return "", registrationReferenceRefuse("input hash stream")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func registrationReferenceJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return registrationReferenceRefuse("strict packet JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return registrationReferenceRefuse("packet trailing data")
	}
	return nil
}

func registrationReferenceGoEnvironment(build registrationReferenceBuild) []string {
	// The existing fixture invokes go run for its original CLI. Running from
	// the frozen package and this exact environment binds that nested build too.
	return []string{"PATH=" + build.ControlledPATH, "GOROOT=" + build.GoRoot, "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly", "GOEXPERIMENT=", "GOOS=" + build.GOOS, "GOARCH=" + build.GOARCH, "CGO_ENABLED=" + build.CGOEnabled, "GOMODCACHE=" + build.ModuleCache, "GOCACHE=" + build.BuildCache, "HOME=" + os.Getenv("HOME")}
}

func registrationReferenceEnumerateInputs(ctx context.Context, b registrationReferenceBuild) ([]registrationReferenceInput, []registrationReferenceModule, error) {
	goPath := filepath.Join(b.GoRoot, "bin", "go")
	command := exec.CommandContext(ctx, goPath, "list", "-mod=readonly", "-deps", "-test", "-json", "./apiserver", "./agentsec-migrate", "./migrations")
	command.Dir = b.Platform
	command.Env = registrationReferenceGoEnvironment(b)
	var output bytes.Buffer
	command.Stdout = &registrationReferenceBoundWriter{Buffer: &output, Limit: 64 * 1024 * 1024}
	command.Stderr = io.Discard
	if command.Run() != nil {
		return nil, nil, registrationReferenceRefuse("offline complete Go build input enumeration")
	}
	type pkg struct {
		Dir, ImportPath                                                                                                                                                                 string
		GoFiles, CgoFiles, TestGoFiles, XTestGoFiles, EmbedFiles, TestEmbedFiles, XTestEmbedFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles, SwigFiles, SwigCXXFiles, SysoFiles []string
		Module                                                                                                                                                                          *struct {
			Path, Version, Sum, GoMod, GoModSum string
			Replace                             *struct{ Path, Version, Sum, GoMod, GoModSum string }
		}
		Error      any
		Incomplete bool
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	files := map[string]registrationReferenceInput{}
	modules := map[string]registrationReferenceModule{}
	add := func(path, kind, pkg string) error {
		path = filepath.Clean(path)
		hash, err := registrationReferenceHashFile(path)
		if err != nil {
			return err
		}
		f := registrationReferenceInput{Path: path, SHA256: hash, Kind: kind, Package: pkg}
		if old, ok := files[path]; ok {
			merged, e := registrationReferenceMergeInput(old, f)
			if e != nil {
				return e
			}
			files[path] = merged
			return nil
		}
		files[path] = f
		return nil
	}
	for decoder.More() {
		var p pkg
		if decoder.Decode(&p) != nil || p.Error != nil || p.Incomplete {
			return nil, nil, registrationReferenceRefuse("Go dependency closure incomplete")
		}
		pkgName := strings.Split(p.ImportPath, " [")[0]
		if strings.HasSuffix(pkgName, ".test") {
			continue
		}
		for _, group := range []struct {
			kind  string
			names []string
		}{{"go", append(append([]string{}, p.GoFiles...), p.CgoFiles...)}, {"embed", p.EmbedFiles}, {"native", append(append(append(append(append(append(append(append(append([]string{}, p.CFiles...), p.CXXFiles...), p.MFiles...), p.HFiles...), p.FFiles...), p.SFiles...), p.SwigFiles...), p.SwigCXXFiles...), p.SysoFiles...)}} {
			for _, n := range group.names {
				path := n
				if !filepath.IsAbs(path) {
					path = filepath.Join(p.Dir, n)
				}
				if err := add(path, group.kind, pkgName); err != nil {
					return nil, nil, err
				}
			}
		}
		if p.Module != nil {
			m := registrationReferenceModule{Path: p.Module.Path, Version: p.Module.Version, Sum: p.Module.Sum, GoModSum: p.Module.GoModSum}
			if p.Module.Replace != nil {
				r := p.Module.Replace
				m.Replace = &registrationReferenceModule{Path: r.Path, Version: r.Version, Sum: r.Sum, GoModSum: r.GoModSum}
				if err := add(r.GoMod, "module", r.Path); err != nil {
					return nil, nil, err
				}
			}
			modules[m.Path] = m
			if p.Module.GoMod != "" {
				if err := add(p.Module.GoMod, "module", p.Module.Path); err != nil {
					return nil, nil, err
				}
			}
		}
	}
	for _, n := range []string{"go.mod", "go.sum"} {
		if err := add(filepath.Join(b.Platform, n), "module", "github.com/zasp-ai/zasp-sec/services/platform"); err != nil {
			return nil, nil, err
		}
	}
	toolDir := filepath.Join(b.GoRoot, "pkg", "tool", b.GOOS+"_"+b.GOARCH)
	tools, err := os.ReadDir(toolDir)
	if err != nil {
		return nil, nil, registrationReferenceRefuse("Go compiler tool closure")
	}
	for _, f := range tools {
		if f.Type().IsRegular() {
			if err := add(filepath.Join(toolDir, f.Name()), "tool", "go-toolchain"); err != nil {
				return nil, nil, err
			}
		}
	}
	if err := add(goPath, "tool", "go-toolchain"); err != nil {
		return nil, nil, err
	}
	implicitInputs, err := registrationReferenceToolInputPaths(b.GoRoot)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range implicitInputs {
		if err := add(filepath.Join(b.GoRoot, p), "tool-input", "go-toolchain"); err != nil {
			return nil, nil, err
		}
	}
	inputs := make([]registrationReferenceInput, 0, len(files))
	for _, f := range files {
		inputs = append(inputs, f)
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Path < inputs[j].Path })
	ms := make([]registrationReferenceModule, 0, len(modules))
	for _, m := range modules {
		ms = append(ms, m)
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Path < ms[j].Path })
	return inputs, ms, nil
}

// go list does not list the assembler's implicit pkg/include search inputs or
// the distribution's default configuration/version files. Bind them directly;
// generated go_asm.h/test-main files remain outputs of this admitted compiler.
func registrationReferenceToolInputPaths(goRoot string) ([]string, error) {
	paths := []string{"VERSION", "go.env"}
	entries, err := os.ReadDir(filepath.Join(goRoot, "pkg", "include"))
	if err != nil {
		return nil, registrationReferenceRefuse("implicit assembler include closure")
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return nil, registrationReferenceRefuse("implicit assembler input type")
		}
		paths = append(paths, filepath.Join("pkg", "include", e.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

type registrationReferenceBoundWriter struct {
	Buffer *bytes.Buffer
	Limit  int
}

func (w *registrationReferenceBoundWriter) Write(p []byte) (int, error) {
	if len(p) > w.Limit-w.Buffer.Len() {
		return 0, registrationReferenceRefuse("command output bound")
	}
	return w.Buffer.Write(p)
}

func registrationReferenceBindBuild(ctx context.Context, path, expectedSHA string) (registrationReferenceBuild, error) {
	var b registrationReferenceBuild
	raw, err := registrationReferenceReadBound(path, 16*1024*1024)
	if err != nil {
		return b, err
	}
	if len(expectedSHA) != 64 || registrationReferenceSHA(raw) != expectedSHA {
		return b, registrationReferenceRefuse("root-authorized build envelope digest")
	}
	if err := registrationReferenceJSON(raw, &b); err != nil {
		return b, err
	}
	if b.Version != "original-worker-registration-frozen-build-v1" || b.GoVersion != "go1.25.13" || runtime.Version() != b.GoVersion || runtime.GOOS != b.GOOS || runtime.GOARCH != b.GOARCH || b.CGOEnabled != "0" || !filepath.IsAbs(b.Platform) || !filepath.IsAbs(b.GoRoot) || !filepath.IsAbs(b.ModuleCache) || !filepath.IsAbs(b.BuildCache) || !strings.HasPrefix(b.ControlledPATH, filepath.Join(b.GoRoot, "bin")+":") || !reflect.DeepEqual(b.InstallerOrder, registrationReferenceInstallerOrder) {
		return b, registrationReferenceRefuse("frozen build/runtime/installer order")
	}
	if err := registrationReferenceAdmitPATH(b.GoRoot, b.ControlledPATH, os.Getenv("PATH")); err != nil {
		return b, err
	}
	working, _ := os.Getwd()
	if working != filepath.Join(b.Platform, "apiserver") {
		return b, registrationReferenceRefuse("frozen fixture working directory")
	}
	executable, err := os.Executable()
	if err != nil {
		return b, registrationReferenceRefuse("executed test identity")
	}
	for file, expected := range map[string]string{executable: b.ExecutableSHA256, b.AssemblyExecutable: b.AssemblyExecutableSHA256, filepath.Join(b.GoRoot, "bin", "go"): b.GoSHA256} {
		hash, e := registrationReferenceHashFile(file)
		if e != nil || len(expected) != 64 || hash != expected {
			return b, registrationReferenceRefuse("executed binary/Go identity")
		}
	}
	if len(b.DispatchPins) < len(registrationReferenceDispatchPins) {
		return b, registrationReferenceRefuse("source-bound dispatch pins absent")
	}
	for p, h := range registrationReferenceDispatchPins {
		if b.DispatchPins[p] != h {
			return b, registrationReferenceRefuse("original compiler dispatch changed")
		}
	}
	for p, h := range b.DispatchPins {
		if filepath.IsAbs(p) || strings.Contains(p, "..") {
			return b, registrationReferenceRefuse("dispatch source path")
		}
		got, e := registrationReferenceHashFile(filepath.Join(b.Platform, p))
		if e != nil || got != h {
			return b, registrationReferenceRefuse("dispatch source input differs")
		}
	}
	// A frozen snapshot, not the writable development tree, is mandatory. Root
	// builds its reviewed binaries there, then removes write bits before opt-in.
	for _, f := range b.Inputs {
		if err := registrationReferenceImmutableInput(f.Path, b); err != nil {
			return b, err
		}
	}
	inputs, modules, err := registrationReferenceEnumerateInputs(ctx, b)
	if err != nil {
		return b, err
	}
	if err := registrationReferenceAdmitInputs(b.Inputs, inputs); err != nil {
		return b, err
	}
	if !reflect.DeepEqual(b.Modules, modules) {
		return b, registrationReferenceRefuse("resolved module identity closure")
	}
	if err := registrationReferenceVerifyModules(ctx, b); err != nil {
		return b, err
	}
	if b.CachePolicy != "owned-trusted-go1.25.13" {
		return b, registrationReferenceRefuse("root-admitted owned trusted build cache recipe")
	}
	if err := registrationReferenceAdmitCache(b.BuildCache); err != nil {
		return b, err
	}
	encoded, _ := json.Marshal(inputs)
	if registrationReferenceSHA(encoded) != b.InputSHA256 {
		return b, registrationReferenceRefuse("complete input roster digest")
	}
	for _, name := range []string{"initdb", "postgres", "pg_isready", "pg_ctl"} {
		path, e := exec.LookPath(name)
		if e != nil {
			return b, registrationReferenceRefuse("PG executable unavailable")
		}
		h, e := registrationReferenceHashFile(path)
		if e != nil || b.PG[name] != h {
			return b, registrationReferenceRefuse("root-admitted PG executable identity")
		}
		version := exec.CommandContext(ctx, path, "--version")
		version.Stderr = io.Discard
		out, e := version.Output()
		if e != nil || !strings.Contains(string(out), "18.3") {
			return b, registrationReferenceRefuse("pinned PG18.3 executable version")
		}
	}
	if _, e := registrationReferencePGCryptoVersion(b.PGExtensionFiles); e != nil {
		return b, e
	}
	return b, nil
}

func registrationReferenceAdmitPATH(goRoot, controlled, actual string) error {
	if controlled != actual || !strings.HasPrefix(controlled, filepath.Join(goRoot, "bin")+":") {
		return registrationReferenceRefuse("same admitted Go/PG runtime PATH before and during fixture")
	}
	return nil
}

func registrationReferenceImmutableInput(path string, b registrationReferenceBuild) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 {
		return registrationReferenceRefuse("immutable build input snapshot")
	}
	root := ""
	for _, candidate := range []string{b.Platform, b.GoRoot, b.ModuleCache} {
		if path == candidate || strings.HasPrefix(path, candidate+string(filepath.Separator)) {
			if len(candidate) > len(root) {
				root = candidate
			}
		}
	}
	if root == "" {
		return registrationReferenceRefuse("consumed file outside owned/admitted frozen roots")
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		stat, e := os.Lstat(dir)
		if e != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm()&0222 != 0 {
			return registrationReferenceRefuse("immutable input directory/CLI confinement")
		}
		if dir == root {
			break
		}
		if dir == filepath.Dir(dir) {
			return registrationReferenceRefuse("frozen input root identity")
		}
	}
	return nil
}

func registrationReferenceAdmitCache(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return registrationReferenceRefuse("private owned trusted Go cache directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return registrationReferenceRefuse("owned Go cache UID")
	}
	return nil
}

func registrationReferenceVerifyModules(ctx context.Context, b registrationReferenceBuild) error {
	sumsRaw, err := registrationReferenceReadBound(filepath.Join(b.Platform, "go.sum"), 4*1024*1024)
	if err != nil {
		return err
	}
	sums := map[string]string{}
	for _, line := range strings.Split(string(sumsRaw), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 {
			sums[f[0]+" "+f[1]] = f[2]
		}
	}
	for _, m := range b.Modules {
		if m.Version == "" && m.Replace == nil {
			continue
		}
		effective := m
		if m.Replace != nil {
			effective = *m.Replace
		}
		if effective.Version == "" {
			continue
		}
		if !strings.HasPrefix(effective.Sum, "h1:") || sums[effective.Path+" "+effective.Version] != effective.Sum || effective.GoModSum != "" && sums[effective.Path+" "+effective.Version+"/go.mod"] != effective.GoModSum {
			return registrationReferenceRefuse("module content identity not admitted by frozen go.sum")
		}
	}
	command := exec.CommandContext(ctx, filepath.Join(b.GoRoot, "bin", "go"), "mod", "verify")
	command.Dir = b.Platform
	command.Env = registrationReferenceGoEnvironment(b)
	var out bytes.Buffer
	command.Stdout = &registrationReferenceBoundWriter{Buffer: &out, Limit: 4 * 1024 * 1024}
	command.Stderr = io.Discard
	if command.Run() != nil || strings.TrimSpace(out.String()) != "all modules verified" {
		return registrationReferenceRefuse("offline admitted whole-module bytes verification")
	}
	return nil
}

func registrationReferenceFreshAssembly(ctx context.Context, b registrationReferenceBuild, directory string) (registrationReferenceAssembly, error) {
	var a registrationReferenceAssembly
	destination := filepath.Join(directory, "fresh-original-assembly.json")
	command := exec.CommandContext(ctx, b.AssemblyExecutable, "-test.run=^TestWorkerRegistrationReferenceAssemblyEmitter$", "-test.count=1")
	command.Dir = filepath.Join(b.Platform, "migrations")
	command.Env = append(registrationReferenceGoEnvironment(b), "ZASP_WORKER_REGISTRATION_ASSEMBLY_OUTPUT="+destination, "ZASP_WORKER_REGISTRATION_INPUT_SHA256="+b.InputSHA256)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if command.Run() != nil {
		return a, registrationReferenceRefuse("fresh original compiled assembly emitter")
	}
	raw, err := registrationReferenceReadBound(destination, 16*1024*1024)
	if err != nil {
		return a, err
	}
	if err := registrationReferenceJSON(raw, &a); err != nil {
		return a, err
	}
	if a.Version != "original-worker-registration-assembly-v1" || a.GoVersion != b.GoVersion || a.InputSHA256 != b.InputSHA256 || a.ExecutableSHA256 != b.AssemblyExecutableSHA256 || a.BuildInfo == "" || registrationReferenceSHA([]byte(a.WorkerSource)) != a.WorkerSourceSHA256 || registrationReferenceSHA([]byte(a.RuntimeSource)) != a.RuntimeSourceSHA256 || a.WorkerCatalogSHA256 != registrationReferenceCatalogSHA || registrationReferenceSHA([]byte(a.WorkerCatalog)) != a.WorkerCatalogSHA256 {
		return a, registrationReferenceRefuse("fresh compiler output/build identity")
	}
	for _, n := range []string{"finding78", "test74", "runtime48", "runtime50", "runtime51", "authorization80"} {
		v, ok := a.Tokens[n]
		if !ok || len(v.Checksum) != 64 || len(v.SourceSHA256) != 64 || (n != "authorization80" && len(v.Fingerprint) != 64) {
			return a, registrationReferenceRefuse("upstream runtime/compiler token closure")
		}
	}
	if len(a.WorkerChecksum) != 64 || len(a.RuntimeChecksum) != 64 || a.WorkerChecksum == a.RuntimeChecksum || !strings.Contains(a.WorkerSource, a.StopSuccessor) || strings.Count(a.WorkerSource, "INSERT INTO zasp_authorization80_runtime.registration") != 1 || strings.Contains(a.WorkerSource, "INSERT INTO zasp_authorization80_worker.registration VALUES") {
		return a, registrationReferenceRefuse("original assembly/registration insertion provenance")
	}
	if registrationReferenceSHA([]byte(a.WorkerChecksumPreimage)) != a.WorkerChecksum || registrationReferenceSHA([]byte(a.RuntimeChecksumPreimage)) != a.RuntimeChecksum || strings.ReplaceAll(a.WorkerChecksumPreimage, "-- worker profile checksum", a.WorkerChecksum) != a.WorkerSource || strings.ReplaceAll(a.RuntimeChecksumPreimage, "-- runtime profile checksum", a.RuntimeChecksum) != a.RuntimeSource {
		return a, registrationReferenceRefuse("full original checksum preimage closure")
	}
	p, err := registrationReferencePlan(a.WorkerCatalog)
	if err != nil {
		return a, err
	}
	if p.Fingerprint != a.WorkerFingerprint || p.RuntimeFingerprint != a.RuntimeFingerprint {
		return a, registrationReferenceRefuse("fresh original nested/outer scalar spans")
	}
	return a, nil
}

func registrationReferenceSnapshotControl(ctx context.Context, begin, capture, rollback, restored func() error) (err error) {
	if err = ctx.Err(); err != nil {
		return registrationReferenceRefuse("capture context expired")
	}
	if err = begin(); err != nil {
		return err
	}
	defer func() {
		rollbackErr := rollback()
		restoreErr := restored()
		if rollbackErr != nil || restoreErr != nil {
			err = errors.Join(err, registrationReferenceRefuse("rollback/frame restoration failed"))
		}
	}()
	if err = capture(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return registrationReferenceRefuse("finite capture time limit")
	}
	return nil
}

// A source/compile-only positive control for the admitted owned-cache recipe.
// It builds the actual original CLI but never starts that CLI or a database.
func registrationReferenceCompileOriginalCLI(ctx context.Context, b registrationReferenceBuild, destination string) (string, error) {
	command := exec.CommandContext(ctx, filepath.Join(b.GoRoot, "bin", "go"), "build", "-mod=readonly", "-o", destination, "../agentsec-migrate")
	command.Dir = filepath.Join(b.Platform, "apiserver")
	command.Env = registrationReferenceGoEnvironment(b)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if command.Run() != nil {
		return "", registrationReferenceRefuse("source-only original CLI compile control")
	}
	return registrationReferenceHashFile(destination)
}

// Ordinary unit tests inherit Go's default module cache without an exported
// GOMODCACHE. Resolve it through that test runtime's actual Go binary, with Go
// config/workspace and toolchain switching disabled. Native capture does NOT
// use this fallback: its frozen module-cache path stays explicitly admitted.
func registrationReferenceUnitModuleCache(ctx context.Context, goRoot string) (string, error) {
	command := exec.CommandContext(ctx, filepath.Join(goRoot, "bin", "go"), "env", "GOMODCACHE")
	command.Env = []string{"GOROOT=" + goRoot, "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOPROXY=off", "GOSUMDB=off", "HOME=" + os.Getenv("HOME"), "GOPATH=" + os.Getenv("GOPATH")}
	var out bytes.Buffer
	command.Stdout = &registrationReferenceBoundWriter{Buffer: &out, Limit: 8192}
	command.Stderr = io.Discard
	if command.Run() != nil {
		return "", registrationReferenceRefuse("unit default Go module-cache resolution")
	}
	path := strings.TrimSpace(out.String())
	if !filepath.IsAbs(path) {
		return "", registrationReferenceRefuse("unit resolved module-cache path")
	}
	return path, nil
}

const registrationReferenceSessionSQL = `SELECT jsonb_build_object(
 'session',session_user,'effective',current_user,'role',current_setting('role'),'path',current_setting('search_path'),'schemas',current_schemas(true),'row_security',current_setting('row_security'),'isolation',current_setting('transaction_isolation'),'read_only',current_setting('transaction_read_only'),'encoding',current_setting('server_encoding'),'server_version',current_setting('server_version_num'),
 'statement_timeout',current_setting('statement_timeout'),'lock_timeout',current_setting('lock_timeout'),
 'authority_member',pg_has_role(session_user,'zasp_discovery_authority','MEMBER'),
 'superuser',(SELECT rolsuper FROM pg_roles WHERE rolname='zasp_discovery_authority'),'bypass_rls',(SELECT rolbypassrls FROM pg_roles WHERE rolname='zasp_discovery_authority'),
 'role_properties',(SELECT to_jsonb(r)-'oid' FROM pg_roles r WHERE rolname='zasp_discovery_authority'),
 'memberships',(SELECT COALESCE(jsonb_agg(jsonb_build_object('role',r.rolname,'member',m.rolname,'grantor',g.rolname,'admin',a.admin_option,'inherit',a.inherit_option,'set',a.set_option) ORDER BY r.rolname,m.rolname,g.rolname),'[]'::jsonb) FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor WHERE r.rolname='zasp_discovery_authority' OR m.rolname IN(session_user,'zasp_discovery_authority')),
 'settings',(SELECT COALESCE(jsonb_agg(jsonb_build_object('database',COALESCE(d.datname,''),'role',COALESCE(r.rolname,''),'settings',s.setconfig) ORDER BY COALESCE(d.datname,''),COALESCE(r.rolname,'')),'[]'::jsonb) FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase LEFT JOIN pg_roles r ON r.oid=s.setrole WHERE s.setdatabase IN(0,(SELECT oid FROM pg_database WHERE datname=current_database())) AND s.setrole IN(0,(SELECT oid FROM pg_roles WHERE rolname=session_user),(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority'))),
 'rls_closed',(SELECT count(*)=5 AND bool_and(c.relowner='zasp_discovery_authority'::regrole AND c.relrowsecurity AND c.relforcerowsecurity AND (SELECT count(*)=1 FROM pg_policy p WHERE p.polrelid=c.oid) AND EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='authority' AND p.polpermissive AND p.polcmd='*' AND p.polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(p.polqual,p.polrelid)='true' AND pg_get_expr(p.polwithcheck,p.polrelid)='true')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_authorization80_worker' AND c.relname IN('registration','predecessor_functions','predecessor_views')) OR (n.nspname='zasp_authorization80_runtime' AND c.relname IN('registration','predecessor_functions'))),
 'contaminated',to_regnamespace('zasp_authorization80_ordered_current') IS NOT NULL)`

type registrationReferenceNative struct {
	Nested                   *string           `json:"nested_digest"`
	Outer                    *string           `json:"outer_digest"`
	ParameterNested          *string           `json:"parameter_nested_digest"`
	ParameterOuter           *string           `json:"parameter_outer_digest"`
	WorkerRows               []json.RawMessage `json:"worker_registration_rows"`
	RuntimeRows              []json.RawMessage `json:"runtime_registration_rows"`
	WorkerCount              int64             `json:"worker_count"`
	FingerprintEqual         bool              `json:"fingerprint_equal"`
	Line2Guard               bool              `json:"line2_guard"`
	OriginalGuard            bool              `json:"original_source_guard"`
	InstallerChecksum        bool              `json:"separate_installer_checksum"`
	RuntimeInsertionOffset   int               `json:"runtime_registration_insertion_byte"`
	RuntimeLaterSourceSHA256 string            `json:"post_runtime_insertion_source_sha256"`
	WorkerInsertSourceSHA256 string            `json:"separate_worker_insert_source_sha256"`
	ExtensionFrame           json.RawMessage   `json:"native_digest_extension_frame"`
}
type registrationReferencePacket struct {
	Version                  string                               `json:"version"`
	BuildSHA256              string                               `json:"build_sha256"`
	Build                    registrationReferenceBuild           `json:"build"`
	Assembly                 registrationReferenceAssembly        `json:"assembly"`
	Plan                     registrationReferenceStatementPlan   `json:"plan"`
	Bags                     []registrationReferenceBag           `json:"bags"`
	Execution                registrationReferenceExecutionFrame  `json:"execution"`
	Before                   registrationReferenceExecutionFrame  `json:"before"`
	After                    registrationReferenceExecutionFrame  `json:"after"`
	Restored                 bool                                 `json:"restored"`
	NestedCollation          registrationReferenceCollation       `json:"nested_collation"`
	OuterCollation           registrationReferenceCollation       `json:"outer_collation"`
	ParameterCollation       registrationReferenceCollation       `json:"parameter_collation"`
	ParameterNestedCollation registrationReferenceCollation       `json:"parameter_nested_collation"`
	Native                   registrationReferenceNative          `json:"native"`
	InstalledFunctions       []registrationReferenceFunctionFrame `json:"installed_assembly_crosschecks"`
	Complete                 bool                                 `json:"complete"`
	Cleanup                  json.RawMessage                      `json:"cleanup"`
	StatementHashes          map[string]string                    `json:"control_statement_sha256"`
	ControlStatements        map[string]string                    `json:"control_statements"`
}

func registrationReferenceQueryJSON(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, statement string, target any, args ...any) error {
	var raw []byte
	if err := q.QueryRow(ctx, statement, args...).Scan(&raw); err != nil {
		// Never wrap or format the driver error: its message, detail, hint,
		// object names and internal SQL may contain unbounded private data.
		class, state := "untyped", "none"
		var pgErr *pgconn.PgError
		switch {
		case errors.As(err, &pgErr) && pgErr != nil:
			class = "postgres"
			if len(pgErr.Code) == 5 && strings.IndexFunc(pgErr.Code, func(r rune) bool {
				return !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z')
			}) == -1 {
				state = pgErr.Code
			}
		case errors.Is(err, pgx.ErrNoRows):
			class = "no_rows"
		case errors.Is(err, context.DeadlineExceeded):
			class = "deadline_exceeded"
		case errors.Is(err, context.Canceled):
			class = "canceled"
		}
		return registrationReferenceRefuse(fmt.Sprintf("native catalog query failed: error_class=%s sqlstate=%s statement_sha256=%s", class, state, registrationReferenceSHA([]byte(statement))))
	}
	if len(raw) > registrationReferenceMaxRowBytes {
		return registrationReferenceRefuse("native control row byte limit")
	}
	return registrationReferenceJSON(raw, target)
}

func registrationReferenceCollationSQL(scalar string) string {
	return `WITH effective AS (SELECT to_regcollation(pg_collation_for((` + scalar + `))) AS oid) SELECT jsonb_build_object('name',c.oid::regcollation::text,'provider',c.collprovider,'deterministic',c.collisdeterministic,'locale',c.colllocale,'rules',c.collicurules,'recorded_version',CASE WHEN c.collprovider='d' THEN d.datcollversion ELSE c.collversion END,'actual_version',CASE WHEN c.collprovider='d' THEN pg_database_collation_actual_version(d.oid) ELSE pg_collation_actual_version(c.oid) END,'database_provider',d.datlocprovider,'database_collate',d.datcollate,'database_ctype',d.datctype,'database_locale',d.datlocale,'database_recorded_version',d.datcollversion,'database_actual_version',pg_database_collation_actual_version(d.oid)) FROM effective e JOIN pg_collation c ON c.oid=e.oid JOIN pg_database d ON d.datname=current_database()`
}

// Observe the actual ORDER BY v upstream of convert_to/digest. LIMIT 0 returns
// a typed scalar NULL without computing any bag values; scalar-subquery type
// and collation remain those of the exact original UNION output even when no
// source rows exist. Core pg_collation_for is non-strict, so it observes that
// expression identity rather than requiring a value or a surrogate NULL::text.
func registrationReferenceSortKeyCollationQueries(p registrationReferenceStatementPlan) (string, string, error) {
	const aggregateProjection = `SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM `
	fromSource := func(s string) (string, error) {
		const fromFacts = aggregateProjection + "facts"
		if !strings.HasPrefix(strings.TrimSpace(s), "WITH facts(v) AS(") || !strings.HasSuffix(s, "\n ) "+fromFacts+"\n") {
			return "", registrationReferenceRefuse("original ORDER BY v source span")
		}
		// Preserve every original UNION, cast, predicate and nested scalar byte.
		return registrationReferenceCollationSQL(strings.TrimSuffix(s, fromFacts+"\n") + "SELECT v FROM facts LIMIT 0\n"), nil
	}
	outer, err := fromSource(p.Fingerprint)
	if err != nil {
		return "", "", err
	}
	nested, err := fromSource(p.RuntimeFingerprint)
	if err != nil {
		return "", "", err
	}
	return outer, nested, nil
}

// These independent observations resolve only fixed pg_catalog identities in
// the already admitted PG18.3 snapshot. No caller-supplied SQL identifier is used.
const registrationReferenceBuiltinCollationSQL = `SELECT jsonb_build_object('name',c.oid::regcollation::text,'provider',c.collprovider,'deterministic',c.collisdeterministic,'locale',c.colllocale,'rules',c.collicurules,'recorded_version',CASE WHEN c.collprovider='d' THEN d.datcollversion ELSE c.collversion END,'actual_version',CASE WHEN c.collprovider='d' THEN pg_database_collation_actual_version(d.oid) ELSE pg_collation_actual_version(c.oid) END,'database_provider',d.datlocprovider,'database_collate',d.datcollate,'database_ctype',d.datctype,'database_locale',d.datlocale,'database_recorded_version',d.datcollversion,'database_actual_version',pg_database_collation_actual_version(d.oid)) FROM pg_collation c JOIN pg_database d ON d.datname=current_database() WHERE c.oid=`

const registrationReferenceBuiltinCSQL = registrationReferenceBuiltinCollationSQL + `'pg_catalog."C"'::regcollation`
const registrationReferenceBuiltinDefaultSQL = registrationReferenceBuiltinCollationSQL + `'pg_catalog.default'::regcollation`

// Reproduce the admitted source ordering on our typed replay only. Both queries
// share one projected v expression; the original source is never rewritten.
func registrationReferenceParameterReplayQueries(nested, outer, builtinC, builtinDefault registrationReferenceCollation) (string, string, error) {
	wantC := registrationReferenceCollation{Name: `"C"`, Provider: "c", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	wantDefault := registrationReferenceCollation{Name: `"default"`, Provider: "d", Deterministic: true, DatabaseProvider: "c", DatabaseCollate: "C", DatabaseCType: "C"}
	if !reflect.DeepEqual(builtinC, wantC) || !reflect.DeepEqual(builtinDefault, wantDefault) || !reflect.DeepEqual(nested, outer) {
		return "", "", registrationReferenceRefuse("finite replay builtin/source collation authority")
	}
	var relation string
	switch {
	case reflect.DeepEqual(nested, builtinDefault):
		relation = `unnest($1::text[]) AS facts(v)`
	case reflect.DeepEqual(nested, builtinC):
		relation = `(SELECT v COLLATE pg_catalog."C" AS v FROM unnest($1::text[]) AS input(v)) AS facts`
	default:
		return "", "", registrationReferenceRefuse("source collation outside finite replay authority")
	}
	aggregate := `SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM ` + relation
	witness := registrationReferenceCollationSQL("SELECT v FROM " + relation + " LIMIT 0")
	return aggregate, witness, nil
}
func registrationReferenceAdmitSortKeyCollations(nested, outer, parameterNested, parameterOuter registrationReferenceCollation) error {
	if nested.Name == "" || !nested.Deterministic || !reflect.DeepEqual(nested, outer) || !reflect.DeepEqual(parameterNested, nested) || !reflect.DeepEqual(parameterOuter, outer) {
		return registrationReferenceRefuse("source/parameter expression collation differs")
	}
	return nil
}

type registrationReferenceDigestFrame struct {
	Extension, Version, Schema, Owner, Source, Library string
	Function                                           registrationReferenceFunctionFrame
	Resolved                                           bool
}

func registrationReferenceAdmitDigest(ext registrationReferenceDigestFrame, selectedVersion string) error {
	if selectedVersion != "1.4" || ext.Extension != "pgcrypto" || ext.Version != selectedVersion || ext.Schema != "public" || ext.Owner != "zasp_test" || ext.Source != "pg_digest" || ext.Library != "$libdir/pgcrypto" || !ext.Resolved || ext.Function.Language != "c" || ext.Function.SecurityDefiner || !ext.Function.Strict || ext.Function.Volatility != "i" || ext.Function.Parallel != "s" || ext.Function.Result != "bytea" {
		return registrationReferenceRefuse("native digest call-list/source/library authority")
	}
	return nil
}
func registrationReferencePGCryptoVersion(files map[string]string) (string, error) {
	// Original0002 selects the control default, not a requested/downgraded
	// VERSION. This PG18.3 admission binds the actual1.3 base->1.4 chain.
	names := map[string]string{}
	for path, expected := range files {
		got, err := registrationReferenceHashFile(path)
		name := filepath.Base(path)
		if !filepath.IsAbs(path) || len(expected) != 64 || err != nil || got != expected || names[name] != "" {
			return "", registrationReferenceRefuse("pgcrypto source/library input drift or ambiguous path")
		}
		names[name] = path
	}
	control := names["pgcrypto.control"]
	base := names["pgcrypto--1.3.sql"]
	upgrade := names["pgcrypto--1.3--1.4.sql"]
	if control == "" || base == "" || upgrade == "" || (names["pgcrypto.dylib"] == "" && names["pgcrypto.so"] == "") || filepath.Dir(base) != filepath.Dir(control) || filepath.Dir(upgrade) != filepath.Dir(control) {
		return "", registrationReferenceRefuse("pgcrypto complete original default install chain")
	}
	raw, err := registrationReferenceReadBound(control, 65536)
	if err != nil {
		return "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || (key != "default_version" && key != "module_pathname") {
			continue
		}
		value = strings.TrimSpace(value)
		if values[key] != "" || len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
			return "", registrationReferenceRefuse("pgcrypto selected control framing")
		}
		values[key] = value[1 : len(value)-1]
	}
	if values["default_version"] != "1.4" || values["module_pathname"] != "$libdir/pgcrypto" {
		return "", registrationReferenceRefuse("pgcrypto original selected default/library")
	}
	return values["default_version"], nil
}

func registrationReferenceBagEvidence(b *registrationReferenceBag, s registrationReferenceSite) {
	b.NullArguments = make([]int, len(s.Types))
	values := make([]*string, len(b.Rows))
	seen := map[string]bool{}
	for i, r := range b.Rows {
		values[i] = r.V
		if r.V == nil {
			b.NullValues++
		} else {
			if seen[*r.V] {
				b.DuplicateValues++
			}
			seen[*r.V] = true
		}
		for j, f := range r.Fields {
			if f.Null {
				b.NullArguments[j]++
			}
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i] == nil {
			return values[j] != nil
		}
		if values[j] == nil {
			return false
		}
		return *values[i] < *values[j]
	})
	raw, _ := json.Marshal(values)
	b.EvidenceSHA256 = registrationReferenceSHA(raw)
}

func registrationReferenceReadBag(ctx context.Context, tx pgx.Tx, s registrationReferenceSite, totalRows, totalBytes *int) (registrationReferenceBag, error) {
	b := registrationReferenceBag{Line: s.Line, SiteSHA256: s.SourceSHA256, StatementSHA256: s.StatementSHA256, Rows: []registrationReferenceRow{}}
	rows, err := tx.Query(ctx, s.Statement)
	if err != nil {
		return b, registrationReferenceRefuse("native selector/cast/permission error")
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil || raw == nil {
			return b, registrationReferenceRefuse("selector row overflow/type/error")
		}
		*totalRows++
		*totalBytes += len(raw)
		if err := registrationReferenceCheckBudget(len(b.Rows)+1, len(raw), *totalRows, *totalBytes); err != nil {
			return b, err
		}
		var r registrationReferenceRow
		if err := registrationReferenceJSON(raw, &r); err != nil {
			return b, err
		}
		r.Ordinal = len(b.Rows) + 1
		b.Rows = append(b.Rows, r)
	}
	if rows.Err() != nil || ctx.Err() != nil {
		return b, registrationReferenceRefuse("partial/timeout native row stream")
	}
	b.Complete = true
	registrationReferenceBagEvidence(&b, s)
	return b, nil
}

const registrationReferenceWorkerInsertSQL = `INSERT INTO zasp_authorization80_worker.registration(checksum,fingerprint) VALUES($1,zasp_authorization80_worker.fingerprint())`

func registrationReferenceCapture(ctx context.Context, owner *pgx.Conn, b registrationReferenceBuild, a registrationReferenceAssembly, buildSHA string) (packet registrationReferencePacket, err error) {
	packet = registrationReferencePacket{Version: "original-worker-registration-reference-v1", BuildSHA256: buildSHA, Build: b, Assembly: a, StatementHashes: map[string]string{}, ControlStatements: map[string]string{}}
	plan, err := registrationReferencePlan(a.WorkerCatalog)
	if err != nil {
		return packet, err
	}
	packet.Plan = plan
	selectedVersion, err := registrationReferencePGCryptoVersion(b.PGExtensionFiles)
	if err != nil {
		return packet, err
	}
	if err := registrationReferenceQueryJSON(ctx, owner, registrationReferenceSessionSQL, &packet.Before); err != nil {
		return packet, err
	}
	if packet.Before.Contaminated {
		return packet, registrationReferenceRefuse("dormant evaluator contamination before capture")
	}
	var tx pgx.Tx
	err = registrationReferenceSnapshotControl(ctx, func() error {
		var e error
		tx, e = owner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if e != nil {
			return registrationReferenceRefuse("single read-only repeatable snapshot")
		}
		return nil
	}, func() error {
		const setupSQL = `SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=pg_catalog,public; SET LOCAL row_security=on; SET LOCAL statement_timeout='10000ms'; SET LOCAL lock_timeout='2000ms'`
		packet.ControlStatements["bounded_snapshot_setup"] = setupSQL
		packet.StatementHashes["bounded_snapshot_setup"] = registrationReferenceSHA([]byte(setupSQL))
		if _, e := tx.Exec(ctx, setupSQL); e != nil {
			return registrationReferenceRefuse("bounded authority setup")
		}
		if e := registrationReferenceQueryJSON(ctx, tx, registrationReferenceSessionSQL, &packet.Execution); e != nil {
			return e
		}
		// Only the extension's admitted C digest, not arbitrary installed
		// application code, may participate in the original aggregate.
		extSQL := `SELECT jsonb_build_object('extension',e.extname,'version',e.extversion,'schema',n.nspname,'owner',e.extowner::regrole::text,'function',` + registrationReferenceFunctionSQL("p") + `,'source',p.prosrc,'library',p.probin,'resolved',p.oid='digest(bytea,text)'::regprocedure) FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace JOIN pg_depend d ON d.refobjid=e.oid AND d.refclassid='pg_extension'::regclass AND d.classid='pg_proc'::regclass AND d.deptype='e' JOIN pg_proc p ON p.oid=d.objid WHERE e.extname='pgcrypto' AND p.oid='public.digest(bytea,text)'::regprocedure`
		var ext registrationReferenceDigestFrame
		var extRaw []byte
		if tx.QueryRow(ctx, extSQL).Scan(&extRaw) != nil || len(extRaw) > registrationReferenceMaxRowBytes || json.Unmarshal(extRaw, &ext) != nil || registrationReferenceAdmitDigest(ext, selectedVersion) != nil {
			return registrationReferenceRefuse("native digest call-list/source/library authority")
		}
		packet.Native.ExtensionFrame = extRaw
		packet.StatementHashes["native_digest_call_frame"] = registrationReferenceSHA([]byte(extSQL))
		packet.ControlStatements["native_digest_call_frame"] = extSQL
		for _, cross := range []struct {
			signature, body string
			volatility      string
		}{{"zasp_authorization80_worker.fingerprint()", a.WorkerFingerprint, "s"}, {"zasp_authorization80_worker.catalog_ready()", a.WorkerCatalog, "s"}, {"zasp_authorization80_runtime.fingerprint()", a.RuntimeFingerprint, "s"}} {
			q := `SELECT ` + registrationReferenceFunctionSQL("p") + ` FROM pg_proc p WHERE p.oid=$1::regprocedure AND p.prokind='f' AND p.prosrc=$2 AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile=$3::"char" AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee<>p.proowner OR acl.grantor<>p.proowner)`
			var f registrationReferenceFunctionFrame
			if e := registrationReferenceQueryJSON(ctx, tx, q, &f, cross.signature, cross.body, cross.volatility); e != nil {
				return e
			}
			if e := registrationReferenceAdmitFunction(f); e != nil {
				return e
			}
			packet.InstalledFunctions = append(packet.InstalledFunctions, f)
			packet.StatementHashes["installed_assembly_frame"] = registrationReferenceSHA([]byte(q))
			packet.ControlStatements["installed_assembly_frame"] = q
		}
		outerCollationSQL, nestedCollationSQL, e := registrationReferenceSortKeyCollationQueries(plan)
		if e != nil {
			return e
		}
		if e := registrationReferenceQueryJSON(ctx, tx, outerCollationSQL, &packet.OuterCollation); e != nil {
			return e
		}
		if e := registrationReferenceQueryJSON(ctx, tx, nestedCollationSQL, &packet.NestedCollation); e != nil {
			return e
		}
		if e := registrationReferenceAdmitExecution(packet.Execution, packet.NestedCollation, packet.OuterCollation); e != nil {
			return e
		}
		var builtinC, builtinDefault registrationReferenceCollation
		if e := registrationReferenceQueryJSON(ctx, tx, registrationReferenceBuiltinCSQL, &builtinC); e != nil {
			return e
		}
		if e := registrationReferenceQueryJSON(ctx, tx, registrationReferenceBuiltinDefaultSQL, &builtinDefault); e != nil {
			return e
		}
		parameterAggregateSQL, parameterCollationSQL, e := registrationReferenceParameterReplayQueries(packet.NestedCollation, packet.OuterCollation, builtinC, builtinDefault)
		if e != nil {
			return e
		}
		packet.ControlStatements["builtin_c_collation"] = registrationReferenceBuiltinCSQL
		packet.ControlStatements["builtin_default_collation"] = registrationReferenceBuiltinDefaultSQL
		packet.StatementHashes["builtin_c_collation"] = registrationReferenceSHA([]byte(registrationReferenceBuiltinCSQL))
		packet.StatementHashes["builtin_default_collation"] = registrationReferenceSHA([]byte(registrationReferenceBuiltinDefaultSQL))
		packet.StatementHashes["outer_collation"] = registrationReferenceSHA([]byte(outerCollationSQL))
		packet.StatementHashes["nested_collation"] = registrationReferenceSHA([]byte(nestedCollationSQL))
		packet.StatementHashes["parameter_collation"] = registrationReferenceSHA([]byte(parameterCollationSQL))
		packet.ControlStatements["outer_collation"] = outerCollationSQL
		packet.ControlStatements["nested_collation"] = nestedCollationSQL
		packet.ControlStatements["parameter_collation"] = parameterCollationSQL
		totalRows, totalBytes := 0, 0
		for _, s := range plan.Sites {
			bag, e := registrationReferenceReadBag(ctx, tx, s, &totalRows, &totalBytes)
			if e != nil {
				return e
			}
			packet.Bags = append(packet.Bags, bag)
		}
		if e := registrationReferenceAdmitBags(plan, packet.Bags); e != nil {
			return e
		}
		if tx.QueryRow(ctx, plan.RuntimeFingerprint).Scan(&packet.Native.Nested) != nil || tx.QueryRow(ctx, plan.Fingerprint).Scan(&packet.Native.Outer) != nil {
			return registrationReferenceRefuse("exact original native aggregation error")
		}
		var nestedValues, outerValues []*string
		for _, bag := range packet.Bags {
			for _, r := range bag.Rows {
				if bag.Line >= 15 && bag.Line <= 27 {
					nestedValues = append(nestedValues, r.V)
				} else {
					outerValues = append(outerValues, r.V)
				}
			}
		}
		// Same expression and actual typed arguments as the nested parameter
		// aggregate, including an empty bag. No synthetic sentinel text.
		if e := registrationReferenceQueryJSON(ctx, tx, parameterCollationSQL, &packet.ParameterNestedCollation, nestedValues); e != nil {
			return e
		}
		if e := registrationReferenceAdmitSortKeyCollations(packet.NestedCollation, packet.OuterCollation, packet.ParameterNestedCollation, packet.ParameterNestedCollation); e != nil {
			return e
		}
		if tx.QueryRow(ctx, parameterAggregateSQL, nestedValues).Scan(&packet.Native.ParameterNested) != nil {
			return registrationReferenceRefuse("native nested type-output bridge")
		}
		if packet.Native.ParameterNested != nil {
			outerValues = append(outerValues, registrationReferenceString("runtime-catalog|"+*packet.Native.ParameterNested))
		} else {
			outerValues = append(outerValues, nil)
		}
		if e := registrationReferenceQueryJSON(ctx, tx, parameterCollationSQL, &packet.ParameterCollation, outerValues); e != nil {
			return e
		}
		if e := registrationReferenceAdmitSortKeyCollations(packet.NestedCollation, packet.OuterCollation, packet.ParameterNestedCollation, packet.ParameterCollation); e != nil {
			return e
		}
		if tx.QueryRow(ctx, parameterAggregateSQL, outerValues).Scan(&packet.Native.ParameterOuter) != nil || !reflect.DeepEqual(packet.Native.Nested, packet.Native.ParameterNested) || !reflect.DeepEqual(packet.Native.Outer, packet.Native.ParameterOuter) {
			return registrationReferenceRefuse("native original/type-output aggregate differs")
		}
		for _, v := range []struct {
			table string
			dest  *[]json.RawMessage
		}{{"zasp_authorization80_worker.registration", &packet.Native.WorkerRows}, {"zasp_authorization80_runtime.registration", &packet.Native.RuntimeRows}} {
			rowSQL := `SELECT to_jsonb(r) FROM ` + v.table + ` r LIMIT 3`
			packet.ControlStatements[v.table+"_rows"] = rowSQL
			packet.StatementHashes[v.table+"_rows"] = registrationReferenceSHA([]byte(rowSQL))
			rows, e := tx.Query(ctx, rowSQL)
			if e != nil {
				return registrationReferenceRefuse("registration row provenance query")
			}
			*v.dest = []json.RawMessage{}
			for rows.Next() {
				var raw []byte
				if rows.Scan(&raw) != nil || len(raw) > 4096 {
					rows.Close()
					return registrationReferenceRefuse("registration row bytes")
				}
				*v.dest = append(*v.dest, json.RawMessage(append([]byte(nil), raw...)))
			}
			e = rows.Err()
			rows.Close()
			if e != nil || len(*v.dest) != 1 {
				return registrationReferenceRefuse("exact registration row count")
			}
		}
		if err := registrationReferenceAdmitRuntimeRow(packet.Native.RuntimeRows[0], a.RuntimeChecksum); err != nil {
			return err
		}
		guardSQL := `SELECT (SELECT count(*) FROM zasp_authorization80_worker.registration),EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE fingerprint=$1::text),COALESCE((SELECT count(*)=1 FROM zasp_authorization80_worker.registration) AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE fingerprint=$1::text),false),EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum=$2::text)`
		if tx.QueryRow(ctx, guardSQL, packet.Native.Outer, a.WorkerChecksum).Scan(&packet.Native.WorkerCount, &packet.Native.FingerprintEqual, &packet.Native.Line2Guard, &packet.Native.InstallerChecksum) != nil || tx.QueryRow(ctx, plan.Catalog).Scan(&packet.Native.OriginalGuard) != nil || packet.Native.WorkerCount != 1 || !packet.Native.InstallerChecksum || !packet.Native.Line2Guard || packet.Native.Line2Guard != packet.Native.OriginalGuard {
			return registrationReferenceRefuse("original line2/separate installer checksum")
		}
		var workerRow struct {
			Singleton   bool
			Checksum    string
			Fingerprint *string
		}
		if json.Unmarshal(packet.Native.WorkerRows[0], &workerRow) != nil || !workerRow.Singleton || workerRow.Checksum != a.WorkerChecksum || registrationReferenceGuard(packet.Native.WorkerCount, workerRow.Fingerprint, packet.Native.Outer) != packet.Native.Line2Guard {
			return registrationReferenceRefuse("native derived line2 guard/worker insertion row")
		}
		// Final runtime bag != insertion-time bag is allowed and is recorded,
		// never bootstrapped from the worker digest or forced to an old value.
		packet.Native.RuntimeInsertionOffset = strings.Index(a.WorkerSource, "INSERT INTO zasp_authorization80_runtime.registration")
		end := strings.Index(a.WorkerSource[packet.Native.RuntimeInsertionOffset:], ";")
		if end < 0 {
			return registrationReferenceRefuse("runtime insertion checkpoint")
		}
		packet.Native.RuntimeLaterSourceSHA256 = registrationReferenceSHA([]byte(a.WorkerSource[packet.Native.RuntimeInsertionOffset+end+1:]))
		packet.ControlStatements["source_proved_runtime_registration_insert"] = a.WorkerSource[packet.Native.RuntimeInsertionOffset : packet.Native.RuntimeInsertionOffset+end+1]
		packet.StatementHashes["source_proved_runtime_registration_insert"] = registrationReferenceSHA([]byte(packet.ControlStatements["source_proved_runtime_registration_insert"]))
		packet.Native.WorkerInsertSourceSHA256 = registrationReferenceSHA([]byte(registrationReferenceWorkerInsertSQL))
		packet.StatementHashes["line2"] = registrationReferenceSHA([]byte(guardSQL))
		packet.StatementHashes["original_guard"] = registrationReferenceSHA([]byte(plan.Catalog))
		packet.StatementHashes["original_nested"] = registrationReferenceSHA([]byte(plan.RuntimeFingerprint))
		packet.StatementHashes["original_outer"] = registrationReferenceSHA([]byte(plan.Fingerprint))
		packet.StatementHashes["parameter_aggregate"] = registrationReferenceSHA([]byte(parameterAggregateSQL))
		packet.StatementHashes["session"] = registrationReferenceSHA([]byte(registrationReferenceSessionSQL))
		for name, statement := range map[string]string{"line2": guardSQL, "original_guard": plan.Catalog, "original_nested": plan.RuntimeFingerprint, "original_outer": plan.Fingerprint, "parameter_aggregate": parameterAggregateSQL, "session": registrationReferenceSessionSQL, "source_proved_worker_registration_insert": registrationReferenceWorkerInsertSQL} {
			packet.ControlStatements[name] = statement
			packet.StatementHashes[name] = registrationReferenceSHA([]byte(statement))
		}
		return nil
	}, func() error {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if tx.Rollback(restoreCtx) != nil {
			return registrationReferenceRefuse("snapshot rollback failed")
		}
		return nil
	}, func() error {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := registrationReferenceQueryJSON(restoreCtx, owner, registrationReferenceSessionSQL, &packet.After); e != nil {
			return e
		}
		if !reflect.DeepEqual(packet.Before, packet.After) || packet.After.Contaminated {
			return registrationReferenceRefuse("post-rollback role/path/session/contamination differs")
		}
		packet.Restored = true
		return nil
	})
	if err != nil {
		return packet, err
	}
	packet.Complete = true
	return packet, nil
}

func TestWorkerRegistrationReferenceOriginalPostgres(t *testing.T) {
	destination := os.Getenv("ZASP_WORKER_REGISTRATION_REFERENCE_OUTPUT")
	if destination == "" {
		t.Skip("explicit root-reviewed original-reference capture opt-in required; compilation is not capture acceptance")
	}
	if !filepath.IsAbs(destination) {
		t.Fatal("reference destination must be absolute")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reference destination must not exist")
	}
	for _, name := range []string{"ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_CURRENT_DEVELOPMENT_CAPTURE", "ZASP_ORDERED_CURRENT_NATIVE_CAPTURE"} {
		if os.Getenv(name) != "" {
			t.Fatal("competing catalog/evaluator capture opt-in refused")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	buildPath, buildSHA := os.Getenv("ZASP_WORKER_REGISTRATION_BUILD"), os.Getenv("ZASP_WORKER_REGISTRATION_BUILD_SHA256")
	b, err := registrationReferenceBindBuild(ctx, buildPath, buildSHA)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range registrationReferenceGoEnvironment(b) {
		k, value, ok := strings.Cut(v, "=")
		if ok {
			t.Setenv(k, value)
		}
	}
	a, err := registrationReferenceFreshAssembly(ctx, b, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var packet registrationReferencePacket
	var reached bool
	observation := &disposablePostgresCleanupObservation{}
	// Register publication FIRST: testing cleanup is LIFO. The sole original
	// server stop+Wait and all original fixture cleanup run before publication.
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		if err := registrationReferenceAdmitPublication(reached && packet.Complete, packet.Restored, observation.snapshot()); err != nil {
			t.Error(err)
			return
		}
		postCtx, postCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer postCancel()
		if _, err := registrationReferenceBindBuild(postCtx, buildPath, buildSHA); err != nil {
			t.Error(err)
			return
		}
		c := observation.snapshot()
		packet.Cleanup = json.RawMessage(fmt.Sprintf(`{"available":%t,"pg_ctl_stopped":%t,"wait_joined":%t,"normal_exit":%t,"endpoint_checked":%t,"endpoint_sha256":%q,"surviving_resources_checked":%t,"surviving_resources":%d}`, c.Available, c.PGCtlStopped, c.CommandWaitJoined, c.NormalExit, c.EndpointChecked, c.EndpointSHA256, c.SurvivingResourcesChecked, c.SurvivingResources))
		raw, e := json.Marshal(packet)
		if e != nil || len(raw) > registrationReferenceMaxBytes {
			t.Error("complete reference packet bound")
			return
		}
		f, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Error("exclusive reference publication refused")
			return
		}
		n, writeErr := f.Write(raw)
		syncErr := f.Sync()
		modeErr := f.Chmod(0400)
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || modeErr != nil || closeErr != nil || n != len(raw) {
			t.Error("reference complete immutable publication failed")
			return
		}
		t.Log("complete original33 reference packet published after normal owned cleanup; independent review still required", len(raw), registrationReferenceSHA(raw))
	})
	registerDisposablePostgresCleanupObservation(t, observation)
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, func(t *testing.T, parent context.Context, owner *pgx.Conn) bool {
		reached = true
		captureCtx, stop := context.WithTimeout(context.WithoutCancel(parent), registrationReferenceDuration)
		defer stop()
		var e error
		packet, e = registrationReferenceCapture(captureCtx, owner, b, a, buildSHA)
		if e != nil {
			t.Fatal(e)
		}
		return true
	}, nil)
}

// Source-only utility for root's external frozen-build recipe. Its output is a
// candidate input roster, NEVER a compiled bundle or a reference acceptance.
// Re-run from the finished immutable source/module tree with the actual build
// configuration; root records binary builds and authorizes the final envelope.
func TestWorkerRegistrationReferenceBuildInputInventory(t *testing.T) {
	destination := os.Getenv("ZASP_WORKER_REGISTRATION_INPUT_INVENTORY_OUTPUT")
	if destination == "" {
		t.Skip("explicit source-only input inventory destination required")
	}
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	moduleCache := os.Getenv("GOMODCACHE")
	if !filepath.IsAbs(moduleCache) {
		t.Fatal("explicit prepared module cache path required")
	}
	b := registrationReferenceBuild{Version: "original-worker-registration-frozen-build-v1", Platform: filepath.Dir(working), GoRoot: runtime.GOROOT(), GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CGOEnabled: "0", ModuleCache: moduleCache, BuildCache: os.Getenv("GOCACHE"), ControlledPATH: filepath.Join(runtime.GOROOT(), "bin") + ":" + os.Getenv("PATH"), InstallerOrder: registrationReferenceInstallerOrder, DispatchPins: registrationReferenceDispatchPins}
	if b.BuildCache == "" {
		b.BuildCache = t.TempDir()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	inputs, modules, err := registrationReferenceEnumerateInputs(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	b.Inputs = inputs
	b.Modules = modules
	rawInputs, _ := json.Marshal(inputs)
	b.InputSHA256 = registrationReferenceSHA(rawInputs)
	if err := registrationReferenceVerifyModules(ctx, b); err != nil {
		t.Fatal(err)
	}
	b.GoSHA256, err = registrationReferenceHashFile(filepath.Join(b.GoRoot, "bin", "go"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > 16*1024*1024 {
		t.Fatal("source-only input inventory bound")
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("exclusive input inventory destination")
	}
	n, writeErr := f.Write(raw)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil || n != len(raw) {
		t.Fatal("complete source-only inventory write")
	}
	t.Log("source-only CGO0 complete input roster; binaries and PG NOT accepted", len(inputs), len(modules), b.InputSHA256)
}
