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
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	orderedMissingReferenceNativePacketDirectory = "/private/tmp/zasp-ordered-missing-reference-native-packet"
	orderedMissingReferenceNativeOutputDirectory = "/private/tmp/zasp-ordered-missing-reference-native-capture"
	orderedMissingReferenceNativePacketSHA256    = "23930c86b7cd4a623a3317be48d30654f62cccf19c1f2c6115fc80902a932287"
	orderedMissingReferenceContractJSONSHA256    = "ae63b0e31dd6ee7d7855d302184acb116e28fb081b2b17facae6c6be4de70d29"
	orderedMissingReferenceContractSHA256        = "262728237a748a512b98e499a9b0335c13cabcf39a372fd3eaf65261e8f1449d"
	orderedMissingReferenceContractModuleSHA256  = "2a304799618b0ca70b18df1f63f04c7bc450aab83b0bfcc19b779aead5b3af90"
)

type orderedMissingReferenceFrame struct {
	Owner      string   `json:"owner"`
	SearchPath []string `json:"searchPath"`
}

type orderedMissingReferenceStageOutput struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type orderedMissingReferenceStageInput struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Parameter int    `json:"parameter"`
}

type orderedMissingReferenceBaselineStage struct {
	ID        string                              `json:"id"`
	Action    string                              `json:"action"`
	Frame     string                              `json:"frame"`
	SQL       string                              `json:"sql"`
	SQLSHA256 string                              `json:"sqlSHA256"`
	Output    *orderedMissingReferenceStageOutput `json:"output,omitempty"`
	Inputs    []orderedMissingReferenceStageInput `json:"inputs,omitempty"`
}

type orderedMissingReferenceBaselineRule struct {
	ID                   string                       `json:"id"`
	Kind                 string                       `json:"kind"`
	ExactRows            int                          `json:"exactRows"`
	Fields               []string                     `json:"fields"`
	FieldTypes           map[string]string            `json:"fieldTypes"`
	ProjectionFrame      orderedMissingReferenceFrame `json:"projectionFrame"`
	CanonicalRosterFrame struct {
		SearchPath string `json:"searchPath"`
		Purpose    string `json:"purpose"`
	} `json:"canonicalRosterFrame"`
	SourceSitesSHA256 string                                 `json:"sourceSitesSHA256"`
	RuleSHA256        string                                 `json:"ruleSHA256"`
	SQLIdentities     []string                               `json:"sqlIdentities"`
	Stages            []orderedMissingReferenceBaselineStage `json:"stages"`
}

type orderedMissingReferenceBaselineWitness struct {
	ID        string `json:"id"`
	RuleID    string `json:"ruleId,omitempty"`
	Frame     string `json:"frame"`
	SQL       string `json:"sql"`
	SQLSHA256 string `json:"sqlSHA256"`
	Expected  string `json:"expected"`
}

type orderedMissingReferenceProbeExpected struct {
	Outcome  string `json:"outcome"`
	SQLState string `json:"sqlState,omitempty"`
}

type orderedMissingReferenceProbeStage struct {
	ID        string                                `json:"id"`
	Action    string                                `json:"action"`
	SQL       string                                `json:"sql,omitempty"`
	SQLSHA256 string                                `json:"sqlSHA256,omitempty"`
	Expected  *orderedMissingReferenceProbeExpected `json:"expected,omitempty"`
}

type orderedMissingReferenceProbe struct {
	ID          string                              `json:"id"`
	Transaction string                              `json:"transaction"`
	Frame       string                              `json:"frame"`
	Stages      []orderedMissingReferenceProbeStage `json:"stages"`
	Cleanup     string                              `json:"cleanup"`
}

type orderedMissingReferenceWitnessFamily struct {
	ID       string                                   `json:"id"`
	Baseline []orderedMissingReferenceBaselineWitness `json:"baseline"`
	Probes   []orderedMissingReferenceProbe           `json:"probes"`
}

type orderedMissingReferenceNativePacket struct {
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
		ContractModuleSHA256   string `json:"contractModuleSHA256"`
		ContractJSONSHA256     string `json:"contractJSONSHA256"`
	} `json:"sourcePins"`
	Limits orderedMissingReferenceLimits `json:"limits"`
	Counts struct {
		Rules           int `json:"rules"`
		Rows            int `json:"rows"`
		SourceSites     int `json:"sourceSites"`
		WitnessFamilies int `json:"witnessFamilies"`
	} `json:"counts"`
	Contract json.RawMessage `json:"contract"`
	Baseline struct {
		Transaction struct {
			Isolation string `json:"isolation"`
			Access    string `json:"access"`
			Snapshot  string `json:"snapshot"`
		} `json:"transaction"`
		Rules []orderedMissingReferenceBaselineRule `json:"rules"`
	} `json:"baseline"`
	WitnessProgram struct {
		Limits struct {
			SQLSeconds     int `json:"sqlSeconds"`
			LockSeconds    int `json:"lockSeconds"`
			CleanupSeconds int `json:"cleanupSeconds"`
		} `json:"limits"`
		Families []orderedMissingReferenceWitnessFamily `json:"families"`
	} `json:"witnessProgram"`
	Output struct {
		Format      string   `json:"format"`
		Status      string   `json:"status"`
		Installable bool     `json:"installable"`
		FileName    string   `json:"fileName"`
		Mode        string   `json:"mode"`
		Publish     string   `json:"publish"`
		Sections    []string `json:"sections"`
	} `json:"output"`
}

type orderedMissingReferenceLimits struct {
	MaxRules       int `json:"maxRules"`
	MaxRows        int `json:"maxRows"`
	MaxBytes       int `json:"maxBytes"`
	OuterSeconds   int `json:"outerSeconds"`
	SQLSeconds     int `json:"sqlSeconds"`
	LockSeconds    int `json:"lockSeconds"`
	CleanupSeconds int `json:"cleanupSeconds"`
}

type orderedMissingReferenceRuleCapture struct {
	RuleID               string            `json:"ruleId"`
	Rows                 []json.RawMessage `json:"rows"`
	CanonicalIdentities  []string          `json:"-"`
	ProjectionRowsSHA256 string            `json:"projectionRowsSHA256"`
	CanonicalKeysSHA256  string            `json:"canonicalKeysSHA256"`
}

type orderedMissingReferenceControl struct {
	ID       string            `json:"id"`
	Family   string            `json:"family"`
	Outcome  string            `json:"outcome"`
	SQLState string            `json:"sqlState,omitempty"`
	Evidence []json.RawMessage `json:"evidence,omitempty"`
}

type orderedMissingReferenceCaptureEnvelope struct {
	Format              string                                       `json:"format"`
	Status              string                                       `json:"status"`
	Installable         bool                                         `json:"installable"`
	Observations        []orderedMissingReferenceRuleCapture         `json:"observations"`
	CanonicalIdentities []orderedMissingReferenceCanonicalIdentities `json:"canonicalIdentities"`
	Controls            []orderedMissingReferenceControl             `json:"controls"`
	Provenance          struct {
		PacketSHA256    string `json:"packetSHA256"`
		ContractSHA256  string `json:"contractSHA256"`
		SourceAuthority string `json:"sourceAuthority"`
	} `json:"provenance"`
}

type orderedMissingReferenceCanonicalIdentities struct {
	RuleID     string   `json:"ruleId"`
	Identities []string `json:"identities"`
}

func TestP7OrderedCurrentMissingReferenceNativeCapture(t *testing.T) {
	run, err := orderedMissingReferenceNativeMode(os.Getenv("ZASP_ORDERED_MISSING_REFERENCE_NATIVE"))
	if err != nil {
		t.Fatal(err)
	}
	if !run {
		t.Skip("explicit missing-reference native capture required")
	}
	packet, err := loadOrderedMissingReferenceNativePacket(orderedMissingReferenceNativePacketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, orderedMissingReferenceCatalogCapture(packet), nil)
}

func orderedMissingReferenceNativeMode(mode string) (bool, error) {
	if mode == "" {
		return false, nil
	}
	if mode != "1" {
		return false, errors.New("invalid explicit missing-reference native capture mode")
	}
	return true, nil
}

func loadOrderedMissingReferenceNativePacket(directory string) (orderedMissingReferenceNativePacket, error) {
	var packet orderedMissingReferenceNativePacket
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return packet, errors.New("missing-reference packet directory must be absolute")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "missing-reference-native-packet.json"))
	if err != nil {
		return packet, err
	}
	return decodeOrderedMissingReferenceNativePacket(raw, orderedMissingReferenceNativePacketSHA256)
}

func decodeOrderedMissingReferenceNativePacket(raw []byte, expectedDigest string) (orderedMissingReferenceNativePacket, error) {
	var packet orderedMissingReferenceNativePacket
	if len(raw) > 16*1024*1024 || orderedMissingReferenceDigestBytes(raw) != expectedDigest {
		return packet, errors.New("missing-reference packet authority digest refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&packet); err != nil {
		return packet, errors.New("missing-reference packet JSON refused")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return packet, errors.New("missing-reference packet trailing JSON refused")
	}
	if err := validateOrderedMissingReferenceNativePacket(packet); err != nil {
		return packet, err
	}
	return packet, nil
}

func validateOrderedMissingReferenceNativePacket(packet orderedMissingReferenceNativePacket) error {
	if packet.Format != "ordered-current-missing-reference-native-v1" || packet.Status != "NATIVE-UNVERIFIED" || packet.Installable || packet.CaptureStatus != "NOT-CAPTURED" || packet.SourceAuthority != "accepted-recovery80-source-2ca-missing-reference-capture-only" {
		return errors.New("missing-reference packet envelope refused")
	}
	if packet.SourcePins.CompilerArtifactSHA256 != "2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c" || packet.SourcePins.CompilerChecksum != "f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214" || packet.SourcePins.CompiledSourceSHA256 != "e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e" || packet.SourcePins.SourceContractSHA256 != "02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb" || packet.SourcePins.CatalogSHA256 != "9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df" || packet.SourcePins.ContractModuleSHA256 != orderedMissingReferenceContractModuleSHA256 || packet.SourcePins.ContractJSONSHA256 != orderedMissingReferenceContractJSONSHA256 || orderedMissingReferenceDigestBytes(packet.Contract) != orderedMissingReferenceContractJSONSHA256 {
		return errors.New("missing-reference packet source authority refused")
	}
	var contract struct {
		Installable    bool   `json:"installable"`
		CaptureStatus  string `json:"captureStatus"`
		MaxRows        int    `json:"maxRows"`
		ContractSHA256 string `json:"contractSHA256"`
	}
	if err := json.Unmarshal(packet.Contract, &contract); err != nil || contract.Installable || contract.CaptureStatus != "NOT-CAPTURED" || contract.MaxRows != 204 || contract.ContractSHA256 != orderedMissingReferenceContractSHA256 {
		return errors.New("missing-reference accepted contract refused")
	}
	if packet.Limits.MaxRules != 12 || packet.Limits.MaxRows != 204 || packet.Limits.MaxBytes != 16777216 || packet.Limits.OuterSeconds != 300 || packet.Limits.SQLSeconds != 10 || packet.Limits.LockSeconds != 3 || packet.Limits.CleanupSeconds != 3 || packet.Counts.Rules != 12 || packet.Counts.Rows != 204 || packet.Counts.SourceSites != 21 || packet.Counts.WitnessFamilies != 7 || packet.Baseline.Transaction.Isolation != "repeatable-read" || packet.Baseline.Transaction.Access != "read-only" || packet.Baseline.Transaction.Snapshot != "single" {
		return errors.New("missing-reference packet bounds refused")
	}
	expected := orderedMissingReferenceExpectedRules()
	if len(packet.Baseline.Rules) != len(expected) {
		return errors.New("missing-reference rule count refused")
	}
	seen := make(map[string]bool, len(expected))
	rows := 0
	order := orderedMissingReferenceExpectedRuleOrder()
	for ruleIndex, rule := range packet.Baseline.Rules {
		if rule.ID != order[ruleIndex] {
			return fmt.Errorf("missing-reference rule order refused: %s", rule.ID)
		}
		want, ok := expected[rule.ID]
		if !ok || seen[rule.ID] || rule.Kind != want.Kind || rule.ExactRows != want.Rows || !reflect.DeepEqual(rule.Fields, want.Fields) || !reflect.DeepEqual(rule.FieldTypes, want.Types) || rule.ProjectionFrame.Owner != want.Owner || !reflect.DeepEqual(rule.ProjectionFrame.SearchPath, []string{"pg_catalog", "public"}) || rule.CanonicalRosterFrame.SearchPath != "pg_catalog" || rule.CanonicalRosterFrame.Purpose != "canonical-key-roster-only" || len(rule.Stages) != 4 || len(rule.SQLIdentities) != 4 {
			return fmt.Errorf("missing-reference rule refused: %s", rule.ID)
		}
		for index, stageID := range []string{"capture-projection", "capture-projection-identities", "capture-canonical-roster-identities", "compare-identity-multisets"} {
			stage := rule.Stages[index]
			if stage.ID != stageID || stage.SQL == "" || orderedMissingReferenceDigestText(stage.SQL) != stage.SQLSHA256 || stage.SQLSHA256 != rule.SQLIdentities[index] {
				return fmt.Errorf("missing-reference stage refused: %s/%s", rule.ID, stage.ID)
			}
		}
		if rule.Stages[0].Action != "query-jsonb-rows" || rule.Stages[0].Output != nil || len(rule.Stages[0].Inputs) != 0 || rule.Stages[1].Action != "execute-fixed-sql-and-bind-one-row" || rule.Stages[1].Output == nil || rule.Stages[1].Output.Name != "projectionIdentities" || rule.Stages[1].Output.Type != "text[]" || len(rule.Stages[1].Inputs) != 0 || rule.Stages[2].Action != "execute-fixed-sql-and-bind-one-row" || rule.Stages[2].Output == nil || rule.Stages[2].Output.Name != "canonicalRosterIdentities" || rule.Stages[2].Output.Type != "text[]" || len(rule.Stages[2].Inputs) != 0 || rule.Stages[3].Action != "execute-fixed-sql-with-bound-arrays" || rule.Stages[3].Output != nil || rule.Stages[0].Frame != "projectionFrame" || rule.Stages[1].Frame != "projectionFrame" || rule.Stages[2].Frame != "canonicalRosterFrame" || rule.Stages[3].Frame != "bound-values-only" || len(rule.Stages[3].Inputs) != 2 || rule.Stages[3].Inputs[0].Name != "projectionIdentities" || rule.Stages[3].Inputs[0].Type != "text[]" || rule.Stages[3].Inputs[0].Parameter != 1 || rule.Stages[3].Inputs[1].Name != "canonicalRosterIdentities" || rule.Stages[3].Inputs[1].Type != "text[]" || rule.Stages[3].Inputs[1].Parameter != 2 {
			return fmt.Errorf("missing-reference frame program refused: %s", rule.ID)
		}
		seen[rule.ID] = true
		rows += rule.ExactRows
	}
	if rows != 204 || len(seen) != 12 {
		return errors.New("missing-reference rule universe refused")
	}
	if packet.WitnessProgram.Limits.SQLSeconds != 10 || packet.WitnessProgram.Limits.LockSeconds != 3 || packet.WitnessProgram.Limits.CleanupSeconds != 3 || len(packet.WitnessProgram.Families) != 7 {
		return errors.New("missing-reference witness limits refused")
	}
	witnesses := orderedMissingReferenceExpectedWitnesses()
	for index, family := range packet.WitnessProgram.Families {
		want := witnesses[index]
		if family.ID != want.ID || len(family.Baseline) != len(want.Baseline) || len(family.Probes) != len(want.Probes) {
			return errors.New("missing-reference witness order refused")
		}
		for baselineIndex, baseline := range family.Baseline {
			expectedBaseline := want.Baseline[baselineIndex]
			if baseline.ID != expectedBaseline.ID || baseline.RuleID != expectedBaseline.RuleID || baseline.Frame != expectedBaseline.Frame || baseline.Expected != expectedBaseline.Outcome || baseline.SQL == "" || orderedMissingReferenceDigestText(baseline.SQL) != baseline.SQLSHA256 {
				return fmt.Errorf("missing-reference witness baseline refused: %s", family.ID)
			}
		}
		for probeIndex, probe := range family.Probes {
			expectedProbe := want.Probes[probeIndex]
			if probe.ID != expectedProbe.ID || probe.Frame != expectedProbe.Frame || probe.Transaction != "separate-read-write-rollback" || probe.Cleanup != "rollback-and-verify-exact-state" || len(probe.Stages) != 5 || probe.Stages[0].ID != "capture-pre-state" || probe.Stages[0].Action != "capture-exact-session-and-selected-object-state" || probe.Stages[1].ID != "mutate" || probe.Stages[1].Action != "execute-fixed-sql" || probe.Stages[2].ID != "probe" || probe.Stages[2].Action != "execute-fixed-query" || probe.Stages[3].ID != "rollback" || probe.Stages[3].Action != "rollback-transaction-bounded" || probe.Stages[4].ID != "verify-restoration" || probe.Stages[4].Action != "compare-exact-pre-state" || probe.Stages[1].SQL == "" || orderedMissingReferenceDigestText(probe.Stages[1].SQL) != probe.Stages[1].SQLSHA256 || probe.Stages[2].SQL == "" || orderedMissingReferenceDigestText(probe.Stages[2].SQL) != probe.Stages[2].SQLSHA256 || probe.Stages[2].Expected == nil || probe.Stages[2].Expected.Outcome != expectedProbe.Outcome || probe.Stages[2].Expected.SQLState != expectedProbe.SQLState {
				return fmt.Errorf("missing-reference witness probe refused: %s/%s", family.ID, probe.ID)
			}
		}
	}
	if packet.Output.Format != "ordered-current-missing-reference-capture-v1" || packet.Output.Status != "NATIVE-OBSERVED-NOT-ACCEPTED" || packet.Output.Installable || packet.Output.FileName != "missing-reference-capture.json" || packet.Output.Mode != "0600" || packet.Output.Publish != "exclusive-after-all-controls" || !reflect.DeepEqual(packet.Output.Sections, []string{"observations", "canonicalIdentities", "controls", "provenance"}) {
		return errors.New("missing-reference output contract refused")
	}
	return nil
}

type orderedMissingReferenceExpectedRule struct {
	Kind   string
	Rows   int
	Owner  string
	Fields []string
	Types  map[string]string
}

func orderedMissingReferenceExpectedRuleOrder() []string {
	return []string{
		"role-profile:current-profile", "role-profile:native-roles", "temporal72:table", "temporal72:function",
		"temporal72:policy", "temporal72:trigger", "temporal72:role", "temporal72:precision-function",
		"inventory-fields:table", "inventory-fields:policy", "inventory-fields:function", "inventory-fields:role",
	}
}

type orderedMissingReferenceExpectedBaseline struct {
	ID      string
	RuleID  string
	Frame   string
	Outcome string
}

type orderedMissingReferenceExpectedProbe struct {
	ID       string
	Frame    string
	Outcome  string
	SQLState string
}

type orderedMissingReferenceExpectedWitness struct {
	ID       string
	Baseline []orderedMissingReferenceExpectedBaseline
	Probes   []orderedMissingReferenceExpectedProbe
}

func orderedMissingReferenceExpectedWitnesses() []orderedMissingReferenceExpectedWitness {
	baseline := func(id, ruleID, frame, outcome string) orderedMissingReferenceExpectedBaseline {
		return orderedMissingReferenceExpectedBaseline{ID: id, RuleID: ruleID, Frame: frame, Outcome: outcome}
	}
	probe := func(id, frame, outcome, sqlState string) orderedMissingReferenceExpectedProbe {
		return orderedMissingReferenceExpectedProbe{ID: id, Frame: frame, Outcome: outcome, SQLState: sqlState}
	}
	return []orderedMissingReferenceExpectedWitness{
		{ID: "role-profile:current-profile:aggregate", Baseline: []orderedMissingReferenceExpectedBaseline{baseline("role-profile:current-profile:aggregate", "", "sourceDiscoveryPublic", "capture-boolean-or-null")}},
		{ID: "role-profile:native-roles:aggregate", Baseline: []orderedMissingReferenceExpectedBaseline{baseline("role-profile:native-roles:aggregate", "", "sourceDiscoveryPublic", "capture-boolean-or-null")}},
		{ID: "role-profile:native-roles:membership", Baseline: []orderedMissingReferenceExpectedBaseline{baseline("role-profile:native-roles:membership", "", "sourceDiscoveryPublic", "capture-boolean-or-null")}, Probes: []orderedMissingReferenceExpectedProbe{probe("native-role-missing-regrole", "sourceDiscoveryPublic", "error", "42704")}},
		{ID: "routine-config-array-shape", Baseline: []orderedMissingReferenceExpectedBaseline{
			baseline("temporal72:function:raw-config-array", "temporal72:function", "sourceDiscoveryPublic", "capture-jsonb-rows"),
			baseline("inventory-fields:function:raw-config-array", "inventory-fields:function", "sourceInventoryPublic", "capture-jsonb-rows"),
		}},
		{ID: "saved-scalar-case-demand", Probes: []orderedMissingReferenceExpectedProbe{
			probe("temporal-lazy-unselected", "sourceDiscoveryPublic", "one-non-null-row", ""),
			probe("temporal-zero-row-null", "sourceDiscoveryPublic", "one-null-row", ""),
			probe("temporal-multiple-row", "sourceDiscoveryPublic", "error", "21000"),
			probe("temporal-missing-regprocedure", "sourceDiscoveryPublic", "error", "42883"),
			probe("precision-lazy-unselected", "sourceDiscoveryPublic", "one-non-null-row", ""),
			probe("precision-zero-row-null", "sourceDiscoveryPublic", "one-null-row", ""),
			probe("precision-multiple-row", "sourceDiscoveryPublic", "error", "21000"),
			probe("precision-missing-regprocedure", "sourceDiscoveryPublic", "error", "42883"),
		}},
		{ID: "managed-role-current-database", Baseline: []orderedMissingReferenceExpectedBaseline{
			baseline("temporal72:role:managed-current-database", "temporal72:role", "sourceDiscoveryPublic", "capture-jsonb-rows"),
			baseline("inventory-fields:role:managed-current-database", "inventory-fields:role", "sourceInventoryPublic", "capture-jsonb-rows"),
		}},
		{ID: "inventory-core-owner-resolution", Probes: []orderedMissingReferenceExpectedProbe{
			probe("inventory-core-shadow-resolution", "sourceInventoryPublic", "one-json-row", ""),
			probe("inventory-core-missing-regclass", "sourceInventoryPublic", "error", "42P01"),
		}},
	}
}

func orderedMissingReferenceExpectedRules() map[string]orderedMissingReferenceExpectedRule {
	rule := func(kind string, rows int, owner string, fields []string, bools ...string) orderedMissingReferenceExpectedRule {
		types := make(map[string]string, len(fields))
		for _, field := range fields {
			types[field] = "string"
		}
		for _, field := range bools {
			types[field] = "boolean"
		}
		return orderedMissingReferenceExpectedRule{Kind: kind, Rows: rows, Owner: owner, Fields: fields, Types: types}
	}
	return map[string]orderedMissingReferenceExpectedRule{
		"role-profile:current-profile":  rule("fixed_runtime_profile", 1, "zasp_discovery_authority", []string{"singleton", "name"}, "singleton"),
		"role-profile:native-roles":     rule("role", 3, "zasp_discovery_authority", []string{"login", "superuser", "create_db", "create_role", "replication", "bypass_rls"}, "login", "superuser", "create_db", "create_role", "replication", "bypass_rls"),
		"temporal72:table":              rule("relation", 18, "zasp_discovery_authority", []string{"name", "owner", "row_security", "forced_row_security", "execution_acl_text"}, "row_security", "forced_row_security"),
		"temporal72:function":           rule("routine", 56, "zasp_discovery_authority", []string{"name", "identity_arguments", "owner", "security_definer", "execution_config_text", "execution_acl_text", "execution_body"}, "security_definer"),
		"temporal72:policy":             rule("policy", 17, "zasp_discovery_authority", []string{"relation_name", "name", "permissive", "command", "execution_roles_text", "using", "check"}, "permissive"),
		"temporal72:trigger":            rule("trigger", 2, "zasp_discovery_authority", []string{"relation_name", "name", "execution_definition", "enabled", "function"}),
		"temporal72:role":               rule("role", 4, "zasp_discovery_authority", []string{"name", "login", "inherit", "superuser", "create_db", "create_role", "replication", "bypass_rls", "execution_v1_managed_here"}, "login", "inherit", "superuser", "create_db", "create_role", "replication", "bypass_rls", "execution_v1_managed_here"),
		"temporal72:precision-function": rule("routine", 51, "zasp_discovery_authority", []string{"namespace_name", "name", "identity_arguments", "owner", "security_definer", "config_text_or_empty", "acl_text_or_empty", "precision_definition"}, "security_definer"),
		"inventory-fields:table":        rule("relation", 9, "zasp_inventory_authority", []string{"name", "owner", "row_security", "forced_row_security", "execution_acl_text"}, "row_security", "forced_row_security"),
		"inventory-fields:policy":       rule("policy", 8, "zasp_inventory_authority", []string{"relation_name", "name", "permissive", "command", "execution_roles_text", "using", "check"}, "permissive"),
		"inventory-fields:function":     rule("routine", 34, "zasp_inventory_authority", []string{"name", "identity_arguments", "inventory_owner", "security_definer", "execution_config_text", "inventory_acl_text", "inventory_body"}, "security_definer"),
		"inventory-fields:role":         rule("role", 1, "zasp_inventory_authority", []string{"name", "login", "inherit", "superuser", "create_db", "create_role", "replication", "bypass_rls", "inventory_v1_managed_here"}, "login", "inherit", "superuser", "create_db", "create_role", "replication", "bypass_rls", "inventory_v1_managed_here"),
	}
}

func orderedMissingReferenceDigestText(value string) string {
	return orderedMissingReferenceDigestBytes([]byte(value))
}
func orderedMissingReferenceDigestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func decodeOrderedMissingReferenceLossless(raw []byte) (any, error) {
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

func validateOrderedMissingReferenceObservation(raw []byte, fields []string, fieldTypes map[string]string) error {
	var value struct {
		Identity string                     `json:"identity"`
		Fields   map[string]json.RawMessage `json:"fields"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.Identity == "" || len(value.Fields) != len(fields) {
		return errors.New("observation shape refused")
	}
	for _, field := range fields {
		rawValue, ok := value.Fields[field]
		if !ok {
			return fmt.Errorf("observation missing field %s", field)
		}
		if bytes.Equal(rawValue, []byte("null")) {
			continue
		}
		decoded, err := decodeOrderedMissingReferenceLossless(rawValue)
		if err != nil {
			return err
		}
		switch fieldTypes[field] {
		case "string":
			if _, ok := decoded.(string); !ok {
				return fmt.Errorf("field %s type", field)
			}
		case "boolean":
			if _, ok := decoded.(bool); !ok {
				return fmt.Errorf("field %s type", field)
			}
		default:
			return fmt.Errorf("field %s unknown type", field)
		}
	}
	return nil
}

func publishOrderedMissingReferenceCapture(ctx context.Context, output string, raw []byte, limit int, observe func(string)) error {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(output) || filepath.Clean(output) != output || limit <= 0 || limit > 16*1024*1024 || len(raw) == 0 || len(raw) > limit {
		return errors.New("capture output path refused")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(output), ".missing-reference-capture-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	defer temporary.Close()
	if err = temporary.Chmod(0o600); err != nil {
		return err
	}
	for start := 0; start < len(raw); start += 64 * 1024 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		end := start + 64*1024
		if end > len(raw) {
			end = len(raw)
		}
		if n, writeErr := temporary.Write(raw[start:end]); writeErr != nil || n != end-start {
			return errors.Join(writeErr, io.ErrShortWrite)
		}
		if start == 0 && observe != nil {
			observe("write")
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := errors.Join(temporary.Sync(), temporary.Close()); err != nil {
		return err
	}
	if observe != nil {
		observe("precommit")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = os.Link(temporaryPath, output); err != nil {
		return fmt.Errorf("exclusive capture publish: %w", err)
	}
	if observe != nil {
		observe("committed")
	}
	return nil
}

type orderedMissingReferenceQueryer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func orderedMissingReferenceSetFrame(ctx context.Context, queryer orderedMissingReferenceQueryer, owner, searchPath string, limits orderedMissingReferenceLimits) error {
	if owner != "zasp_discovery_authority" && owner != "zasp_inventory_authority" {
		return errors.New("source owner refused")
	}
	if searchPath != "pg_catalog, public" && searchPath != "pg_catalog" {
		return errors.New("search path refused")
	}
	opCtx, cancel := context.WithTimeout(ctx, time.Duration(limits.SQLSeconds)*time.Second)
	defer cancel()
	_, err := queryer.Exec(opCtx, `SET LOCAL ROLE `+owner+`; SET LOCAL search_path=`+searchPath+`; SET LOCAL TIME ZONE 'UTC'`)
	return err
}

type orderedMissingReferenceByteBudget struct {
	limit int
	used  int
}

func (budget *orderedMissingReferenceByteBudget) add(raw []byte) error {
	if budget == nil || budget.limit <= 0 || len(raw) > budget.limit-budget.used {
		return errors.New("capture byte bound exceeded")
	}
	budget.used += len(raw)
	return nil
}

func orderedMissingReferenceCollectJSON(ctx context.Context, queryer orderedMissingReferenceQueryer, seconds, capRows int, budget *orderedMissingReferenceByteBudget, sql string) ([]json.RawMessage, error) {
	opCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	rows, err := queryer.Query(opCtx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]json.RawMessage, 0, capRows)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if len(result) >= capRows {
			return nil, errors.New("row bound exceeded")
		}
		if _, err := decodeOrderedMissingReferenceLossless(raw); err != nil {
			return nil, err
		}
		if err := budget.add(raw); err != nil {
			return nil, err
		}
		result = append(result, append(json.RawMessage(nil), raw...))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func orderedMissingReferenceQueryTextArray(ctx context.Context, queryer orderedMissingReferenceQueryer, seconds int, sql string) ([]string, error) {
	opCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	var values []string
	if err := queryer.QueryRow(opCtx, sql).Scan(&values); err != nil {
		return nil, err
	}
	return values, nil
}

func orderedMissingReferenceCompareArrays(ctx context.Context, queryer orderedMissingReferenceQueryer, seconds int, sql string, left, right []string) error {
	opCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	var valid bool
	if err := queryer.QueryRow(opCtx, sql, left, right).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return errors.New("identity multiset refused")
	}
	return nil
}

const orderedMissingReferenceStateSQL = `SELECT pg_catalog.jsonb_build_object('role',current_user,'path',current_setting('search_path'),'zone',current_setting('TimeZone'),'readonly',current_setting('transaction_read_only'),'roles',(SELECT pg_catalog.jsonb_agg(to_jsonb(r) ORDER BY r.rolname) FROM (SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,pg_catalog.shobj_description(oid,'pg_authid') comment FROM pg_catalog.pg_roles WHERE rolname LIKE 'zasp_%') r),'functions',(SELECT pg_catalog.jsonb_agg(to_jsonb(f) ORDER BY f.identity) FROM (SELECT p.oid::regprocedure::text identity,p.proowner::regrole::text owner,p.prosrc,COALESCE(p.proconfig::text,'') config FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN('public','zasp_precision_predecessor')) f),'saved',(SELECT pg_catalog.jsonb_agg(to_jsonb(s) ORDER BY s.signature,s.definition) FROM zasp_temporal72.predecessor_functions s),'core',(SELECT to_jsonb(c) FROM (SELECT oid::regclass::text identity,relowner::regrole::text owner FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('public.zasp_core_payloads')) c))::text`

func orderedMissingReferenceCaptureState(ctx context.Context, owner *pgx.Conn, seconds int) (string, error) {
	opCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	var value string
	err := owner.QueryRow(opCtx, orderedMissingReferenceStateSQL).Scan(&value)
	return value, err
}

func orderedMissingReferenceRollback(parent context.Context, tx pgx.Tx, seconds int) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), time.Duration(seconds)*time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func orderedMissingReferenceRunBaseline(ctx context.Context, owner *pgx.Conn, packet orderedMissingReferenceNativePacket, budget *orderedMissingReferenceByteBudget) (captures []orderedMissingReferenceRuleCapture, controls []orderedMissingReferenceControl, resultErr error) {
	beginCtx, beginCancel := context.WithTimeout(ctx, time.Duration(packet.Limits.SQLSeconds)*time.Second)
	tx, err := owner.BeginTx(beginCtx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	beginCancel()
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if rollbackErr := orderedMissingReferenceRollback(ctx, tx, packet.Limits.CleanupSeconds); rollbackErr != nil {
			resultErr = errors.Join(resultErr, rollbackErr)
		}
	}()
	opCtx, cancel := context.WithTimeout(ctx, time.Duration(packet.Limits.SQLSeconds)*time.Second)
	_, err = tx.Exec(opCtx, fmt.Sprintf("SET LOCAL statement_timeout='%ds'; SET LOCAL lock_timeout='%ds'; SET LOCAL TIME ZONE 'UTC'", packet.Limits.SQLSeconds, packet.Limits.LockSeconds))
	cancel()
	if err != nil {
		return nil, nil, err
	}
	captures = make([]orderedMissingReferenceRuleCapture, 0, 12)
	for _, rule := range packet.Baseline.Rules {
		if err := orderedMissingReferenceSetFrame(ctx, tx, rule.ProjectionFrame.Owner, "pg_catalog, public", packet.Limits); err != nil {
			return nil, nil, err
		}
		rows, err := orderedMissingReferenceCollectJSON(ctx, tx, packet.Limits.SQLSeconds, rule.ExactRows+1, budget, rule.Stages[0].SQL)
		if err != nil {
			return nil, nil, fmt.Errorf("%s projection: %w", rule.ID, err)
		}
		if len(rows) != rule.ExactRows {
			return nil, nil, fmt.Errorf("%s rows=%d want=%d", rule.ID, len(rows), rule.ExactRows)
		}
		identities := make(map[string]bool, rule.ExactRows)
		for _, raw := range rows {
			if err := validateOrderedMissingReferenceObservation(raw, rule.Fields, rule.FieldTypes); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", rule.ID, err)
			}
			var value struct {
				Identity string `json:"identity"`
			}
			_ = json.Unmarshal(raw, &value)
			if identities[value.Identity] {
				return nil, nil, fmt.Errorf("%s duplicate identity", rule.ID)
			}
			identities[value.Identity] = true
		}
		projectionKeys, err := orderedMissingReferenceQueryTextArray(ctx, tx, packet.Limits.SQLSeconds, rule.Stages[1].SQL)
		if err != nil {
			return nil, nil, err
		}
		if err := orderedMissingReferenceSetFrame(ctx, tx, rule.ProjectionFrame.Owner, "pg_catalog", packet.Limits); err != nil {
			return nil, nil, err
		}
		canonical, err := orderedMissingReferenceQueryTextArray(ctx, tx, packet.Limits.SQLSeconds, rule.Stages[2].SQL)
		if err != nil {
			return nil, nil, err
		}
		if err := orderedMissingReferenceCompareArrays(ctx, tx, packet.Limits.SQLSeconds, rule.Stages[3].SQL, projectionKeys, canonical); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", rule.ID, err)
		}
		if len(projectionKeys) != rule.ExactRows || len(canonical) != rule.ExactRows {
			return nil, nil, fmt.Errorf("%s key bounds", rule.ID)
		}
		rowRaw, _ := json.Marshal(rows)
		keyRaw, _ := json.Marshal(canonical)
		captures = append(captures, orderedMissingReferenceRuleCapture{RuleID: rule.ID, Rows: rows, CanonicalIdentities: canonical, ProjectionRowsSHA256: orderedMissingReferenceDigestBytes(rowRaw), CanonicalKeysSHA256: orderedMissingReferenceDigestBytes(keyRaw)})
	}
	controls = make([]orderedMissingReferenceControl, 0)
	for _, family := range packet.WitnessProgram.Families {
		for _, item := range family.Baseline {
			ownerName := "zasp_discovery_authority"
			if item.Frame == "sourceInventoryPublic" {
				ownerName = "zasp_inventory_authority"
			}
			if err := orderedMissingReferenceSetFrame(ctx, tx, ownerName, "pg_catalog, public", packet.Limits); err != nil {
				return nil, nil, err
			}
			control := orderedMissingReferenceControl{ID: item.ID, Family: family.ID, Outcome: item.Expected}
			if item.Expected == "capture-boolean-or-null" {
				op, cancel := context.WithTimeout(ctx, time.Duration(packet.Limits.SQLSeconds)*time.Second)
				var value *bool
				err := tx.QueryRow(op, item.SQL).Scan(&value)
				cancel()
				if err != nil {
					return nil, nil, err
				}
				raw, _ := json.Marshal(value)
				control.Evidence = []json.RawMessage{raw}
			} else {
				values, err := orderedMissingReferenceCollectJSON(ctx, tx, packet.Limits.SQLSeconds, packet.Limits.MaxRows, budget, item.SQL)
				if err != nil {
					return nil, nil, err
				}
				if item.RuleID != "" {
					expectedRule, ok := orderedMissingReferenceExpectedRules()[item.RuleID]
					if !ok || len(values) != expectedRule.Rows {
						return nil, nil, fmt.Errorf("%s witness rows=%d", item.ID, len(values))
					}
				}
				control.Evidence = values
			}
			controls = append(controls, control)
		}
	}
	if err := orderedMissingReferenceRollback(ctx, tx, packet.Limits.CleanupSeconds); err != nil {
		return nil, nil, err
	}
	return captures, controls, nil
}

func orderedMissingReferenceProbeSQLState(control orderedMissingReferenceControl, expected *orderedMissingReferenceProbeExpected, err error) (orderedMissingReferenceControl, error) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		control.SQLState = pgErr.Code
		if expected.Outcome == "error" && pgErr.Code == expected.SQLState {
			return control, nil
		}
	}
	return control, err
}

func orderedMissingReferenceShadowEvidence(raw []byte) ([]json.RawMessage, error) {
	var value struct {
		Resolved   string            `json:"resolved"`
		Temporary  *bool             `json:"temporary"`
		Projection []json.RawMessage `json:"projection"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.Resolved == "" || value.Temporary == nil || !*value.Temporary || len(value.Projection) != 34 {
		return nil, errors.New("probe shadow evidence refused")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("probe shadow evidence refused")
	}
	return value.Projection, nil
}

func validateOrderedMissingReferenceShadowEvidence(raw []byte) error {
	_, err := orderedMissingReferenceShadowEvidence(raw)
	return err
}

func orderedMissingReferenceProbeJSONValue(value any) ([]byte, error) {
	if raw, ok := value.([]byte); ok {
		return append([]byte(nil), raw...), nil
	}
	return json.Marshal(value)
}

func orderedMissingReferenceProbeOutcome(ctx context.Context, queryer orderedMissingReferenceQueryer, seconds int, budget *orderedMissingReferenceByteBudget, stage orderedMissingReferenceProbeStage) (orderedMissingReferenceControl, error) {
	expected := stage.Expected
	control := orderedMissingReferenceControl{Outcome: expected.Outcome}
	op, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	rows, err := queryer.Query(op, stage.SQL)
	if err != nil {
		return orderedMissingReferenceProbeSQLState(control, expected, err)
	}
	defer rows.Close()
	count := 0
	nullValue := false
	jsonObject := false
	for rows.Next() {
		count++
		values, valueErr := rows.Values()
		if valueErr != nil {
			return control, valueErr
		}
		if len(values) != 1 {
			return control, fmt.Errorf("probe columns=%d", len(values))
		}
		nullValue = values[0] == nil
		if raw, marshalErr := orderedMissingReferenceProbeJSONValue(values[0]); marshalErr == nil {
			if err := budget.add(raw); err != nil {
				return control, err
			}
			control.Evidence = append(control.Evidence, raw)
			var object map[string]any
			jsonObject = json.Unmarshal(raw, &object) == nil && object != nil
			if expected.Outcome == "one-json-row" {
				if err := validateOrderedMissingReferenceShadowEvidence(raw); err != nil {
					return control, err
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return orderedMissingReferenceProbeSQLState(control, expected, err)
	}
	if expected.Outcome == "error" {
		return control, errors.New("expected SQLSTATE not raised")
	}
	if count != 1 {
		return control, fmt.Errorf("probe rows=%d", count)
	}
	if expected.Outcome == "one-null-row" && !nullValue {
		return control, errors.New("probe expected NULL")
	}
	if expected.Outcome == "one-non-null-row" && nullValue {
		return control, errors.New("probe unexpected NULL")
	}
	if expected.Outcome == "one-json-row" && (nullValue || !jsonObject) {
		return control, errors.New("probe expected JSON object")
	}
	return control, nil
}

func joinOrderedMissingReferenceProbeCleanup(probeErr, rollbackErr, restorationErr error, mismatch bool) error {
	if mismatch {
		restorationErr = errors.Join(restorationErr, errors.New("probe exact restoration mismatch"))
	}
	return errors.Join(probeErr, rollbackErr, restorationErr)
}

func orderedMissingReferenceRunProbe(ctx context.Context, owner *pgx.Conn, packet orderedMissingReferenceNativePacket, budget *orderedMissingReferenceByteBudget, family string, probe orderedMissingReferenceProbe) (orderedMissingReferenceControl, error) {
	before, err := orderedMissingReferenceCaptureState(ctx, owner, packet.Limits.SQLSeconds)
	if err != nil {
		return orderedMissingReferenceControl{}, err
	}
	beginCtx, beginCancel := context.WithTimeout(ctx, time.Duration(packet.Limits.SQLSeconds)*time.Second)
	tx, err := owner.Begin(beginCtx)
	beginCancel()
	if err != nil {
		return orderedMissingReferenceControl{}, err
	}
	cleanup := func(probeErr error) error {
		rollbackErr := orderedMissingReferenceRollback(ctx, tx, packet.Limits.CleanupSeconds)
		after, stateErr := orderedMissingReferenceCaptureState(context.WithoutCancel(ctx), owner, packet.Limits.CleanupSeconds)
		return joinOrderedMissingReferenceProbeCleanup(probeErr, rollbackErr, stateErr, stateErr == nil && before != after)
	}
	op, cancel := context.WithTimeout(ctx, time.Duration(packet.Limits.SQLSeconds)*time.Second)
	_, err = tx.Exec(op, fmt.Sprintf("SET LOCAL statement_timeout='%ds'; SET LOCAL lock_timeout='%ds'; SET LOCAL TIME ZONE 'UTC'", packet.Limits.SQLSeconds, packet.Limits.LockSeconds))
	cancel()
	if err == nil {
		op, cancel = context.WithTimeout(ctx, time.Duration(packet.Limits.SQLSeconds)*time.Second)
		_, err = tx.Exec(op, probe.Stages[1].SQL)
		cancel()
	}
	if err != nil {
		return orderedMissingReferenceControl{}, cleanup(err)
	}
	role := "zasp_discovery_authority"
	if probe.Frame == "sourceInventoryPublic" {
		role = "zasp_inventory_authority"
	}
	if err = orderedMissingReferenceSetFrame(ctx, tx, role, "pg_catalog, public", packet.Limits); err != nil {
		return orderedMissingReferenceControl{}, cleanup(err)
	}
	control, probeErr := orderedMissingReferenceProbeOutcome(ctx, tx, packet.Limits.SQLSeconds, budget, probe.Stages[2])
	control.ID = probe.ID
	control.Family = family
	return control, cleanup(probeErr)
}

func orderedMissingReferenceValidateCapture(packet orderedMissingReferenceNativePacket, envelope orderedMissingReferenceCaptureEnvelope) error {
	if envelope.Format != packet.Output.Format || envelope.Status != packet.Output.Status || envelope.Installable || len(envelope.Observations) != 12 || len(envelope.CanonicalIdentities) != 12 || len(envelope.Controls) != 18 || envelope.Provenance.PacketSHA256 != orderedMissingReferenceNativePacketSHA256 || envelope.Provenance.ContractSHA256 != orderedMissingReferenceContractSHA256 || envelope.Provenance.SourceAuthority != packet.SourceAuthority {
		return errors.New("capture envelope refused")
	}
	rows := 0
	for index, capture := range envelope.Observations {
		rule := packet.Baseline.Rules[index]
		canonical := envelope.CanonicalIdentities[index]
		if capture.RuleID != rule.ID || canonical.RuleID != rule.ID || len(capture.Rows) != rule.ExactRows || len(canonical.Identities) != rule.ExactRows || !reflect.DeepEqual(capture.CanonicalIdentities, canonical.Identities) {
			return errors.New("captured rule identity refused")
		}
		rows += len(capture.Rows)
		seenIdentities := make(map[string]bool, rule.ExactRows)
		for rowIndex, raw := range capture.Rows {
			if err := validateOrderedMissingReferenceObservation(raw, rule.Fields, rule.FieldTypes); err != nil {
				return err
			}
			var observation struct {
				Identity string `json:"identity"`
			}
			if err := json.Unmarshal(raw, &observation); err != nil || seenIdentities[observation.Identity] || observation.Identity != canonical.Identities[rowIndex] {
				return errors.New("captured observation identity refused")
			}
			seenIdentities[observation.Identity] = true
		}
		rowsRaw, err := json.Marshal(capture.Rows)
		if err != nil || orderedMissingReferenceDigestBytes(rowsRaw) != capture.ProjectionRowsSHA256 {
			return errors.New("capture rows digest refused")
		}
		keysRaw, err := json.Marshal(canonical.Identities)
		if err != nil || orderedMissingReferenceDigestBytes(keysRaw) != capture.CanonicalKeysSHA256 {
			return errors.New("capture identities digest refused")
		}
	}
	if rows != 204 {
		return errors.New("capture row total refused")
	}
	expectedControls := make([]orderedMissingReferenceControl, 0, 18)
	for _, family := range orderedMissingReferenceExpectedWitnesses() {
		for _, baseline := range family.Baseline {
			expectedControls = append(expectedControls, orderedMissingReferenceControl{ID: baseline.ID, Family: family.ID, Outcome: baseline.Outcome})
		}
	}
	for _, family := range orderedMissingReferenceExpectedWitnesses() {
		for _, probe := range family.Probes {
			expectedControls = append(expectedControls, orderedMissingReferenceControl{ID: probe.ID, Family: family.ID, Outcome: probe.Outcome, SQLState: probe.SQLState})
		}
	}
	for index, control := range envelope.Controls {
		expected := expectedControls[index]
		if control.ID != expected.ID || control.Family != expected.Family || control.Outcome != expected.Outcome || control.SQLState != expected.SQLState || (control.Outcome != "error" && len(control.Evidence) == 0) || (control.Outcome == "error" && len(control.Evidence) != 0) {
			return errors.New("capture control refused")
		}
		for _, evidence := range control.Evidence {
			if _, err := decodeOrderedMissingReferenceLossless(evidence); err != nil {
				return errors.New("capture control evidence refused")
			}
		}
	}
	return nil
}

func orderedMissingReferenceCatalogCapture(packet orderedMissingReferenceNativePacket) ordered68CatalogCapture {
	return func(t *testing.T, parent context.Context, owner *pgx.Conn) bool {
		t.Helper()
		ctx, cancel := context.WithTimeout(parent, time.Duration(packet.Limits.OuterSeconds)*time.Second)
		defer cancel()
		before, err := orderedMissingReferenceCaptureState(ctx, owner, packet.Limits.SQLSeconds)
		if err != nil {
			t.Fatal(err)
		}
		budget := &orderedMissingReferenceByteBudget{limit: packet.Limits.MaxBytes}
		captures, controls, err := orderedMissingReferenceRunBaseline(ctx, owner, packet, budget)
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range packet.WitnessProgram.Families {
			for _, probe := range family.Probes {
				control, probeErr := orderedMissingReferenceRunProbe(ctx, owner, packet, budget, family.ID, probe)
				if probeErr != nil {
					t.Fatalf("%s: %v", probe.ID, probeErr)
				}
				controls = append(controls, control)
			}
		}
		after, err := orderedMissingReferenceCaptureState(ctx, owner, packet.Limits.SQLSeconds)
		if err != nil || before != after {
			t.Fatal("missing-reference final exact restoration", err)
		}
		envelope := orderedMissingReferenceCaptureEnvelope{Format: packet.Output.Format, Status: packet.Output.Status, Installable: false, Observations: captures, Controls: controls}
		for _, capture := range captures {
			envelope.CanonicalIdentities = append(envelope.CanonicalIdentities, orderedMissingReferenceCanonicalIdentities{capture.RuleID, capture.CanonicalIdentities})
		}
		envelope.Provenance.PacketSHA256 = orderedMissingReferenceNativePacketSHA256
		envelope.Provenance.ContractSHA256 = orderedMissingReferenceContractSHA256
		envelope.Provenance.SourceAuthority = packet.SourceAuthority
		if err := orderedMissingReferenceValidateCapture(packet, envelope); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, '\n')
		if len(raw) > packet.Limits.MaxBytes {
			t.Fatal("missing-reference final capture byte bound exceeded")
		}
		output := filepath.Join(orderedMissingReferenceNativeOutputDirectory, packet.Output.FileName)
		publishCtx, publishCancel := context.WithTimeout(ctx, time.Duration(packet.Limits.CleanupSeconds)*time.Second)
		defer publishCancel()
		if err := publishOrderedMissingReferenceCapture(publishCtx, output, raw, packet.Limits.MaxBytes, nil); err != nil {
			t.Fatal(err)
		}
		t.Log("missing-reference native capture completed", len(captures), 204, len(controls), orderedMissingReferenceDigestBytes(raw), output)
		return true
	}
}
