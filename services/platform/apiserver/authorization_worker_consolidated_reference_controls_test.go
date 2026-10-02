package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func consolidatedReferenceTestInput() consolidatedReferenceInput {
	roster, demand := "roster", "demand"
	phase := func(id, path string, rules ...string) consolidatedReferencePhase {
		sql := []byte("SELECT NULL::jsonb WHERE false /* " + id + " */")
		return consolidatedReferencePhase{ID: id, SQLSHA256: supplementSHA(sql), SearchPath: path, TimeZone: "UTC", SQL: sql, RuleIDs: rules}
	}
	return consolidatedReferenceInput{
		Phases: []consolidatedReferencePhase{
			phase("demand", "pg_catalog, public", "demand"),
			phase("keys", "pg_catalog", "roster"),
			phase("original", "pg_catalog, public", "raw", "normalized"),
			phase("resolution", "pg_catalog, public", "resolution"),
			phase("witness", "pg_catalog, public", "witness"),
		},
		Format: "ordered-current-complete-capture-contract-v1", Status: "REFERENCE-CAPTURE-ONLY",
		CompilerArtifactSHA256: supplementCompilerSHA, CompilerChecksum: supplementChecksum,
		CompiledSourceSHA256: supplementCompiledSourceSHA, SourceContractSHA256: supplementSourceContractSHA,
		ClosureSHA256: strings.Repeat("c", 64), Catalog1FileSHA256: supplementCatalogSHA,
		Postgres: "PostgreSQL 18.3 test build", ServerVersionNum: "180003", Pgcrypto: "1.4",
		Variant: "A", SessionUser: "zasp_test", RequiredRole: "zasp_discovery_authority", TimeZone: "UTC",
		SourceFrameVersion: 1, MaxRows: 10000, MaxBytes: 16777216, CaptureReady: true,
		ManifestSHA256: strings.Repeat("a", 64), ContractSHA256: strings.Repeat("b", 64),
		Rules: map[string]consolidatedReferenceRule{
			"demand":     {Kind: "routine-demand", Section: "demand", Phase: "demand", Fields: []string{}, FieldTypes: map[string]string{}, RefusalMaxRows: 10},
			"roster":     {Kind: "routine", Section: "roster", Phase: "keys", Fields: []string{}, FieldTypes: map[string]string{}, RefusalMaxRows: 10, DemandRuleID: &demand},
			"raw":        {Kind: "routine", Section: "rawInputs", Phase: "original", Fields: []string{"definition"}, FieldTypes: map[string]string{"definition": "text"}, RefusalMaxRows: 10, RosterRuleID: &roster},
			"normalized": {Kind: "export", Section: "normalizationObservations", Phase: "original", Fields: []string{"owner", "acl"}, FieldTypes: map[string]string{"owner": "text", "acl": "json?"}, RefusalMaxRows: 10},
			"resolution": {Kind: "resolution", Section: "resolutions", Phase: "resolution", Fields: []string{"literal", "cast", "sourceSite", "demandPath", "resolvedIdentity"}, FieldTypes: map[string]string{"literal": "text", "cast": "text", "sourceSite": "text", "demandPath": "text", "resolvedIdentity": "text"}, RefusalMaxRows: 10},
			"witness":    {Kind: "authority", Section: "witnesses", Phase: "witness", Fields: []string{"member"}, FieldTypes: map[string]string{"member": "boolean"}, RefusalMaxRows: 10},
		},
		ReusedEvidence: []consolidatedReferenceEvidence{{FileSHA256: strings.Repeat("d", 64), RowIdentity: "prior:1", Field: "definition", SiteSHA256: strings.Repeat("e", 64), FrameSHA256: strings.Repeat("f", 64)}},
		SourcePins:     map[string]string{"producer.go": strings.Repeat("1", 64)},
	}
}

func consolidatedReferenceTestRows(phase string) []json.RawMessage {
	rows := map[string][]string{
		"demand":     {`{"ruleId":"demand","identity":null,"handle":"pg_proc:42:0","multiplicity":1,"fact":{}}`},
		"keys":       {`{"ruleId":"roster","identity":"public.f()","handle":"pg_proc:42:0","multiplicity":1,"fact":{}}`},
		"original":   {`{"ruleId":"raw","identity":null,"handle":"pg_proc:42:0","multiplicity":1,"fact":{"definition":"SELECT 1"}}`, `{"ruleId":"normalized","identity":"public.export()","handle":null,"multiplicity":1,"fact":{"owner":"zasp_test","acl":null}}`},
		"resolution": {`{"ruleId":"resolution","identity":"site:0","handle":null,"multiplicity":1,"fact":{"literal":"public.f()","cast":"regprocedure","sourceSite":"site","demandPath":"always","resolvedIdentity":"public.f()"}}`},
		"witness":    {`{"ruleId":"witness","identity":"member:zasp_test","handle":null,"multiplicity":1,"fact":{"member":true}}`},
	}
	result := make([]json.RawMessage, len(rows[phase]))
	for i, row := range rows[phase] {
		result[i] = json.RawMessage(row)
	}
	return result
}

// Test-local hashes exercise the actual emitted packet's consumer compatibility.
// They are not authorized trust pins and cannot open native capture/admission.
func consolidatedReferenceOfflinePacket(t *testing.T, snapshot string) consolidatedReferenceInput {
	t.Helper()
	if snapshot != "ordered-current-complete-capture-packet-A" && snapshot != "ordered-current-complete-capture-packet-A-fix1" && snapshot != "ordered-current-complete-capture-packet-A-fix1-final" {
		t.Fatal("unknown offline packet")
	}
	directory, err := filepath.Abs(filepath.Join("..", "..", "..", consolidatedReferenceP7, snapshot))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(directory, "snapshot-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := os.ReadFile(filepath.Join(directory, "services/platform/migrations/ordered_current/consolidated-capture-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := loadConsolidatedReferencePacket(directory, consolidatedReferencePacketPins{Variant: "A", SessionUser: "zasp_test", ManifestSHA256: supplementSHA(manifest), ContractSHA256: supplementSHA(contract)})
	if err != nil {
		t.Fatal("actual emitted contract compatibility", err)
	}
	if _, err := loadConsolidatedReference(directory); err == nil {
		t.Fatal("test-local hashes opened native trust")
	}
	return input
}

func TestConsolidatedReferenceEmittedPacketCompatibility(t *testing.T) {
	for _, snapshot := range []string{"ordered-current-complete-capture-packet-A", "ordered-current-complete-capture-packet-A-fix1", "ordered-current-complete-capture-packet-A-fix1-final"} {
		t.Run(snapshot, func(t *testing.T) {
			input := consolidatedReferenceOfflinePacket(t, snapshot)
			for _, id := range []string{"public:sa_export:saved-observations", "wrapper:audit-source:snapshot", "wrapper:audit-source:expected", "wrapper:audit-workflow:snapshot"} {
				rule := input.Rules[id]
				if rule.Section != "normalizationObservations" || rule.Phase != "witness" {
					t.Fatal("normalization placement", id)
				}
			}
		})
	}
}

func TestConsolidatedReferenceEmittedSourceMaxima(t *testing.T) {
	input := consolidatedReferenceOfflinePacket(t, "ordered-current-complete-capture-packet-A-fix1-final")
	for _, tc := range []struct {
		id      string
		maximum int
	}{
		{"worker:projected_domain:table", 23}, {"worker-edge:gateway_projected27:8", 1},
		{"worker-edge:gateway_projected27:10", 2}, {"worker-edge:runtime_projected50_binding:7", 2},
	} {
		for _, suffix := range []string{"", ":demand", ":keys"} {
			rule := input.Rules[tc.id+suffix]
			if rule.SourceMaxRows == nil || *rule.SourceMaxRows != tc.maximum || rule.RefusalMaxRows != 10000 {
				t.Fatal("source maximum lost", tc.id+suffix)
			}
		}
		state := newConsolidatedCollection(input)
		for i := 0; i <= tc.maximum; i++ {
			raw, err := json.Marshal(map[string]any{"ruleId": tc.id + ":demand", "identity": nil, "handle": fmt.Sprintf("pg_class:%d:0", i+1), "multiplicity": 1, "fact": map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			err = state.emit(input, input.Phases[0], raw)
			if (err == nil) != (i < tc.maximum) {
				t.Fatalf("source maximum %s row %d: %v", tc.id, i+1, err)
			}
		}
	}
}

func TestConsolidatedReferenceTextArrayRows(t *testing.T) {
	for _, tc := range []struct {
		name, typ, raw string
		valid          bool
	}{
		{"null member", "text[]", `[null]`, false},
		{"nullable array null member", "text[]?", `["first",null]`, false},
		{"whole null required", "text[]", `null`, false},
		{"whole null nullable", "text[]?", `null`, true},
		{"strings round trip", "text[]", `["first","","last"]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := consolidatedReferenceTestInput()
			rule := input.Rules["witness"]
			rule.Fields = []string{"values"}
			rule.FieldTypes = map[string]string{"values": tc.typ}
			input.Rules["witness"] = rule
			state := newConsolidatedCollection(input)
			err := state.emit(input, input.Phases[4], json.RawMessage(`{"ruleId":"witness","identity":"array","handle":null,"multiplicity":1,"fact":{"values":`+tc.raw+`}}`))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid {
				raw, err := json.Marshal(state.sections["witnesses"][0].Fact["values"])
				if err != nil || string(raw) != tc.raw {
					t.Fatalf("array conversion: %s, %v", raw, err)
				}
			}
		})
	}
}

func TestConsolidatedReferenceIllegalSectionPhases(t *testing.T) {
	for _, tc := range []struct{ rule, phase string }{
		{"normalized", "demand"}, {"normalized", "keys"}, {"normalized", "resolution"},
		{"raw", "witness"}, {"witness", "original"}, {"resolution", "witness"},
	} {
		input := consolidatedReferenceTestInput()
		for i := range input.Phases {
			ids := []string{}
			for _, id := range input.Phases[i].RuleIDs {
				if id != tc.rule {
					ids = append(ids, id)
				}
			}
			if input.Phases[i].ID == tc.phase {
				ids = append(ids, tc.rule)
			}
			input.Phases[i].RuleIDs = ids
		}
		rule := input.Rules[tc.rule]
		rule.Phase = tc.phase
		input.Rules[tc.rule] = rule
		if err := validConsolidatedInput(input); err == nil {
			t.Fatalf("accepted illegal %s phase %s", tc.rule, tc.phase)
		}
	}
}

func consolidatedReferenceTestIO(input consolidatedReferenceInput, fault string, cancel context.CancelFunc) (consolidatedReferenceIO, *[]string) {
	calls := []string{}
	active, role := false, false
	path := "\"$user\", public"
	frames, admissions := 0, 0
	io := consolidatedReferenceIO{
		Begin: func(context.Context) error {
			calls = append(calls, "begin")
			if fault == "begin" {
				return errors.New("begin")
			}
			active = true
			return nil
		},
		Exec: func(_ context.Context, statement string) error {
			calls = append(calls, statement)
			if fault == "exec" {
				return errors.New("exec")
			}
			if strings.HasPrefix(statement, "SET LOCAL ROLE") {
				role = true
			}
			if strings.HasPrefix(statement, "SET LOCAL search_path=") {
				path = strings.TrimPrefix(statement, "SET LOCAL search_path=")
			}
			if statement == "RESET ROLE" {
				role = false
			}
			return nil
		},
		Frame: func(context.Context) (orderedSupplementFrame, error) {
			frames++
			f := orderedSupplementFrame{Session: input.SessionUser, Role: input.SessionUser, SearchPath: "\"$user\", public", TimeZone: "America/Los_Angeles", Postgres: input.Postgres, ServerVersionNum: input.ServerVersionNum, Pgcrypto: input.Pgcrypto}
			if active {
				f.SearchPath, f.TimeZone, f.ReadOnly = path, "UTC", true
				if role {
					f.Role = input.RequiredRole
				}
			}
			if fault == "build" {
				f.Postgres = "another build"
			}
			if fault == "owner" {
				f.Session = "somebody_else"
			}
			if fault == "phase-frame" && active && role && path == "pg_catalog, public" {
				f.SearchPath = "public, pg_catalog"
			}
			if fault == "restore" && !active && frames > 2 {
				f.TimeZone = "UTC"
			}
			if fault == "cancel-after-restore" && !active && frames > 2 {
				cancel()
			}
			return f, nil
		},
		Admission: func(context.Context) error {
			admissions++
			calls = append(calls, "admission")
			if fault == "pre-admission" && admissions == 1 || fault == "post-admission" && admissions == 2 {
				return errors.New("admission")
			}
			return nil
		},
		Collect: func(_ context.Context, phase consolidatedReferencePhase, emit func(json.RawMessage) error) error {
			calls = append(calls, "collect:"+phase.ID+":"+string(phase.SQL))
			if phase.ID == "keys" {
				if len(phase.DemandHandles) != 1 || phase.DemandHandles[0] != (consolidatedReferenceHandle{RuleID: "demand", Handle: "pg_proc:42:0"}) {
					return errors.New("bound demand handles")
				}
			} else if phase.DemandHandles != nil {
				return errors.New("unexpected demand handles")
			}
			if fault == "collect" && phase.ID == "original" {
				return errors.New("collect")
			}
			rows := consolidatedReferenceTestRows(phase.ID)
			if fault == "overflow" && phase.ID == "demand" {
				rows[0] = json.RawMessage(`{"ruleId":"demand","identity":null,"handle":"pg_proc:42:0","multiplicity":10001,"fact":{}}`)
			}
			if fault == "ignored-emit" && phase.ID == "demand" {
				bad := json.RawMessage(`{"ruleId":"unknown","identity":"x","handle":null,"multiplicity":1,"fact":{}}`)
				_ = emit(bad)
				_ = emit(rows[0])
				return nil
			}
			for _, row := range rows {
				if err := emit(row); err != nil {
					return err
				}
			}
			return nil
		},
		Rollback: func(ctx context.Context) error {
			calls = append(calls, "rollback")
			active, role, path = false, false, "\"$user\", public"
			deadline, ok := ctx.Deadline()
			if ctx.Err() != nil || !ok || time.Until(deadline) > 3*time.Second {
				return errors.New("unbounded rollback")
			}
			if fault == "rollback" {
				return errors.New("rollback")
			}
			return nil
		},
		Dispose: func(ctx context.Context) error {
			calls = append(calls, "dispose")
			deadline, ok := ctx.Deadline()
			if ctx.Err() != nil || !ok || time.Until(deadline) > 3*time.Second {
				return errors.New("unbounded dispose")
			}
			return nil
		},
	}
	if fault == "cancel" {
		base := io.Collect
		io.Collect = func(ctx context.Context, phase consolidatedReferencePhase, emit func(json.RawMessage) error) error {
			if phase.ID == "witness" {
				cancel()
			}
			return base(ctx, phase, emit)
		}
	}
	return io, &calls
}

func TestConsolidatedReferenceLifecycleAndPublication(t *testing.T) {
	input := consolidatedReferenceTestInput()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	io, calls := consolidatedReferenceTestIO(input, "", cancel)
	output := filepath.Join(t.TempDir(), "reference.json")
	publication, err := captureConsolidatedReference(ctx, input, io, output)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil || publication.FileSHA256 != supplementSHA(raw) || publication.PayloadSHA256 != supplementSHA(raw[:len(raw)-1]) {
		t.Fatal("publication hashes")
	}
	var envelope map[string]json.RawMessage
	if consolidatedDecodeJSON(raw, &envelope) != nil || string(envelope["format"]) != `"ordered-current-complete-reference-v1"` || string(envelope["status"]) != `"REFERENCE-CAPTURE-ONLY"` || string(envelope["installable"]) != "false" || string(envelope["readOnly"]) != "true" || string(envelope["preAdmission"]) != "true" || string(envelope["postAdmission"]) != "true" || string(envelope["rolledBack"]) != "true" || string(envelope["frameRestored"]) != "true" {
		t.Fatal("published envelope separation")
	}
	for _, section := range []string{"rawInputs", "normalizationObservations", "resolutions", "witnesses"} {
		var rows []json.RawMessage
		if consolidatedDecodeJSON(envelope[section], &rows) != nil || len(rows) != 1 {
			t.Fatal("published section", section)
		}
		if section == "rawInputs" {
			var row map[string]json.RawMessage
			if consolidatedDecodeJSON(rows[0], &row) != nil || string(row["identity"]) != `"public.f()"` || row["handle"] != nil {
				t.Fatal("transient join handle escaped publication")
			}
		}
	}
	var counts map[string]json.RawMessage
	if consolidatedDecodeJSON(envelope["counts"], &counts) != nil || string(counts["streamRows"]) != "6" || string(counts["expandedRows"]) != "6" || string(counts["demandRows"]) != "1" || string(counts["rosterRows"]) != "1" {
		t.Fatal("published counts")
	}
	joined := strings.Join(*calls, "|")
	wantOrder := []string{"begin", "statement_timeout='10s'", "lock_timeout='3s'", "pg_advisory_xact_lock_shared", "admission", "SET LOCAL ROLE zasp_discovery_authority", "collect:demand:", "collect:keys:", "collect:original:", "collect:resolution:", "collect:witness:", "RESET ROLE", "admission", "rollback"}
	position := 0
	for _, want := range wantOrder {
		next := strings.Index(joined[position:], want)
		if next < 0 {
			t.Fatalf("callback order missing %q in %s", want, joined)
		}
		position += next + len(want)
	}
	if strings.Contains(joined, "dispose") {
		t.Fatal("successful publication disposed owner")
	}
}

func TestConsolidatedReferenceFailureAndCleanupControls(t *testing.T) {
	for _, fault := range []string{"begin", "build", "owner", "pre-admission", "phase-frame", "collect", "overflow", "ignored-emit", "post-admission", "rollback", "restore", "cancel", "cancel-after-restore", "existing", "collision"} {
		t.Run(fault, func(t *testing.T) {
			input := consolidatedReferenceTestInput()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			io, calls := consolidatedReferenceTestIO(input, fault, cancel)
			output := filepath.Join(t.TempDir(), "reference.json")
			if fault == "existing" {
				if err := os.WriteFile(output, []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "collision" {
				input.Paths = []string{output}
			}
			if _, err := captureConsolidatedReference(ctx, input, io, output); err == nil {
				t.Fatal("failure published")
			}
			if fault == "existing" {
				raw, _ := os.ReadFile(output)
				if string(raw) != "retained" {
					t.Fatal("existing output overwritten")
				}
			} else if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("failed capture left output")
			}
			if !strings.Contains(strings.Join(*calls, "|"), "dispose") {
				t.Fatal("failed capture did not dispose")
			}
		})
	}
}

func TestConsolidatedReferenceInputAndRowRefusals(t *testing.T) {
	for _, mutate := range []func(*consolidatedReferenceInput){
		func(in *consolidatedReferenceInput) { in.Phases = in.Phases[:3] },
		func(in *consolidatedReferenceInput) { in.Phases[1].ID = "demand" },
		func(in *consolidatedReferenceInput) { in.Phases[1].SearchPath = "public, pg_catalog" },
		func(in *consolidatedReferenceInput) { in.MaxRows = 10001 },
		func(in *consolidatedReferenceInput) { in.MaxBytes = 16777217 },
		func(in *consolidatedReferenceInput) { in.Installable = true },
		func(in *consolidatedReferenceInput) { r := in.Rules["raw"]; r.Phase = "keys"; in.Rules["raw"] = r },
		func(in *consolidatedReferenceInput) { in.Phases[0].SQLSHA256 = strings.Repeat("0", 64) },
	} {
		input := consolidatedReferenceTestInput()
		mutate(&input)
		ctx, cancel := context.WithCancel(context.Background())
		io, _ := consolidatedReferenceTestIO(input, "", cancel)
		if _, err := captureConsolidatedReference(ctx, input, io, filepath.Join(t.TempDir(), "out")); err == nil {
			t.Fatal("invalid input accepted")
		}
		cancel()
	}
	input := consolidatedReferenceTestInput()
	delete(input.Rules, "witness")
	input.Phases[4].RuleIDs = []string{}
	if err := validConsolidatedInput(input); err != nil {
		t.Fatal("empty phase refused", err)
	}
	input = consolidatedReferenceTestInput()
	rawRule := input.Rules["raw"]
	sourceMaximum := 100
	rawRule.SourceMaxRows = &sourceMaximum
	input.Rules["raw"] = rawRule
	if err := validConsolidatedInput(input); err != nil {
		t.Fatal("mathematical maximum above refusal maximum rejected", err)
	}
}

func TestConsolidatedReferenceStrictRowsAndJoinClosure(t *testing.T) {
	input := consolidatedReferenceTestInput()
	if err := newConsolidatedCollection(input).finish(input); err != nil {
		t.Fatal("matching empty demand/roster/original sets refused", err)
	}
	demandPhase := input.Phases[0]
	invalid := []json.RawMessage{
		json.RawMessage(`{"ruleId":"demand","identity":null,"handle":"pg_proc:42:0","multiplicity":1,"fact":{},"extra":true}`),
		json.RawMessage(`{"ruleId":"demand","ruleId":"demand","identity":null,"handle":"pg_proc:42:0","multiplicity":1,"fact":{}}`),
		json.RawMessage(`{"ruleId":"demand","identity":"guessed","handle":"pg_proc:42:0","multiplicity":1,"fact":{}}`),
		json.RawMessage(`{"ruleId":"demand","identity":null,"handle":"pg_proc:42:0","multiplicity":0,"fact":{}}`),
		json.RawMessage{'{', '"', 'r', 'u', 'l', 'e', 'I', 'd', '"', ':', '"', 0xff, '"', '}'},
	}
	for _, row := range invalid {
		state := newConsolidatedCollection(input)
		if err := state.emit(input, demandPhase, row); err == nil {
			t.Fatalf("invalid row accepted: %q", row)
		}
	}
	state := newConsolidatedCollection(input)
	if err := state.emit(input, demandPhase, consolidatedReferenceTestRows("demand")[0]); err != nil {
		t.Fatal(err)
	}
	if err := state.finish(input); err == nil {
		t.Fatal("demand without roster accepted")
	}
	state = newConsolidatedCollection(input)
	rows := []struct {
		phase consolidatedReferencePhase
		raw   json.RawMessage
	}{
		{input.Phases[0], json.RawMessage(`{"ruleId":"demand","identity":null,"handle":"pg_proc:42:0","multiplicity":1,"fact":{}}`)},
		{input.Phases[0], json.RawMessage(`{"ruleId":"demand","identity":null,"handle":"pg_proc:43:0","multiplicity":1,"fact":{}}`)},
		{input.Phases[1], json.RawMessage(`{"ruleId":"roster","identity":"public.f()","handle":"pg_proc:42:0","multiplicity":1,"fact":{}}`)},
		{input.Phases[1], json.RawMessage(`{"ruleId":"roster","identity":"public.f()","handle":"pg_proc:43:0","multiplicity":1,"fact":{}}`)},
	}
	for i, row := range rows {
		err := state.emit(input, row.phase, row.raw)
		if i == len(rows)-1 {
			if err == nil {
				t.Fatal("ambiguous canonical roster identity accepted")
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	bagInput := consolidatedReferenceTestInput()
	bagInput.Rules["bag"] = consolidatedReferenceRule{Kind: "membership", Section: "witnesses", Phase: "witness", Fields: []string{"member"}, FieldTypes: map[string]string{"member": "boolean"}, RefusalMaxRows: 10, Bag: true}
	bagState := newConsolidatedCollection(bagInput)
	if err := bagState.emit(bagInput, bagInput.Phases[4], json.RawMessage(`{"ruleId":"bag","identity":"tuple","handle":null,"multiplicity":2,"fact":{"member":true}}`)); err != nil || bagState.expandedRows != 2 || bagState.streamRows != 1 {
		t.Fatal("expanded bag accounting", err)
	}
}

func TestConsolidatedReferenceRawContractDomains(t *testing.T) {
	for _, test := range []struct {
		name, raw, kind string
		nullable        bool
		valid           bool
	}{
		{"boolean", "false", "boolean", false, true},
		{"boolean null", "null", "boolean", false, false},
		{"array", "[]", "array", false, true},
		{"array null", "null", "array", false, false},
		{"object", "{}", "object", false, true},
		{"object null", "null", "object", false, false},
		{"string", `"x"`, "string", false, true},
		{"string null", "null", "string", false, false},
		{"nullable integer", "null", "integer", true, true},
		{"integer null", "null", "integer", false, false},
		{"integer fraction", "1.1", "integer", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := consolidatedRequireJSONType(json.RawMessage(test.raw), test.kind, test.nullable)
			if (err == nil) != test.valid {
				t.Fatal("raw contract domain outcome", err)
			}
		})
	}
	if consolidatedRequireStringArray(json.RawMessage(`["rule",null]`)) == nil {
		t.Fatal("null ruleIds/fields member accepted")
	}
	if consolidatedRequireStringMap(json.RawMessage(`{"field":null}`)) == nil {
		t.Fatal("null manifest file/sourcePins/fieldTypes value accepted")
	}
	for _, shape := range []map[string]json.RawMessage{
		{"format": json.RawMessage("null")},
		{"installable": json.RawMessage("null")},
		{"bag": json.RawMessage("null")},
		{"rowIdentity": json.RawMessage("null")},
	} {
		for key, raw := range shape {
			kind := "string"
			if key == "format" {
				kind = "integer"
			} else if key == "installable" || key == "bag" {
				kind = "boolean"
			}
			if consolidatedRequireMembers(shape, map[string]string{key: kind}) == nil {
				t.Fatal("null shape member accepted", key, raw)
			}
		}
	}
	input := consolidatedReferenceTestInput()
	rule := input.Rules["raw"]
	tooLarge := 9007199254740992
	rule.SourceMaxRows = &tooLarge
	input.Rules["raw"] = rule
	if err := validConsolidatedInput(input); err == nil {
		t.Fatal("unsafe source maximum accepted")
	}
}

func TestConsolidatedReferenceClosedMode(t *testing.T) {
	if enabled, err := consolidatedReferenceMode("", nil); err != nil || enabled {
		t.Fatal("default not inert")
	}
	if enabled, err := consolidatedReferenceMode("1", nil); err != nil || !enabled {
		t.Fatal("explicit mode refused")
	}
	for _, mode := range []string{"true", "2", "capture"} {
		if _, err := consolidatedReferenceMode(mode, nil); err == nil {
			t.Fatal("old mode accepted")
		}
	}
	for _, key := range consolidatedReferenceOverlapControls {
		if _, err := consolidatedReferenceMode("1", map[string]string{key: "1"}); err == nil {
			t.Fatalf("overlap %s accepted", key)
		}
	}
}

func TestConsolidatedReferenceConsumesSharedWireVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", consolidatedReferenceP7, "ordered-current-complete-capture-wire-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil || supplementSHA(raw) != "438c2f9e563ce01d0052c4e8556d1dea93185d9494d2c46f4d25b1616f059a96" {
		t.Fatal("shared wire vectors changed")
	}
	var vectors struct {
		Format                                     string
		Accepted                                   []struct{ Name, Input, Wire string }
		IntegerAccepted, IntegerRejected, Rejected []string
	}
	if consolidatedDecodeJSON(raw, &vectors) != nil || vectors.Format != "ordered-current-wire-vectors-v1" {
		t.Fatal("shared wire vector shape")
	}
	for _, vector := range vectors.Accepted {
		var value any
		if consolidatedDecodeJSON([]byte(vector.Input), &value) != nil {
			t.Fatal("accepted vector decode", vector.Name)
		}
		wire, err := canonicalConsolidatedJSON(value)
		if err != nil || string(wire) != vector.Wire {
			t.Fatalf("accepted vector %q: got %q want %q", vector.Name, wire, vector.Wire)
		}
	}
	for _, token := range vectors.IntegerAccepted {
		if _, ok := consolidatedSafeInteger(json.RawMessage(token)); !ok {
			t.Fatal("accepted integer refused", token)
		}
	}
	for _, token := range vectors.IntegerRejected {
		if _, ok := consolidatedSafeInteger(json.RawMessage(token)); ok {
			t.Fatal("invalid integer accepted", token)
		}
	}
	for _, encoded := range vectors.Rejected {
		var value any
		if consolidatedDecodeJSON([]byte(encoded), &value) == nil {
			if _, err := canonicalConsolidatedJSON(value); err == nil {
				t.Fatal("invalid wire accepted", encoded)
			}
		}
	}
	if wire, err := canonicalConsolidatedJSON([]string{"a", "b"}); err != nil || string(wire) != `["a","b"]` {
		t.Fatal("text array canonicalization")
	}
}
