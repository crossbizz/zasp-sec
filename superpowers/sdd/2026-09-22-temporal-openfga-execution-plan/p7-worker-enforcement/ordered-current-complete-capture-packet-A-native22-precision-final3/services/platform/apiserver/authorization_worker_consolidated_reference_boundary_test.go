package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const consolidatedReferenceP7 = ".superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/"

var consolidatedReferenceOverlapControls = []string{
	"ZASP_ORDERED_PRIVATE_REFERENCE", "ZASP_ORDERED_PRIVATE_REFERENCE_CAPTURE", "ZASP_ORDERED_PRIVATE_REFERENCE_DIR", "ZASP_ORDERED_PRIVATE_REFERENCE_OUTPUT",
	"ZASP_ORDERED_SUPPLEMENT_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_REFERENCE_DIR", "ZASP_ORDERED_SUPPLEMENT_OUTPUT",
	"ZASP_ORDERED_REMAINING_REFERENCE", "ZASP_ORDERED_REMAINING_REFERENCE_DIR", "ZASP_ORDERED_REMAINING_REFERENCE_OUTPUT",
	"ZASP_ORDERED_TRANSFORM_ACCEPTANCE", "ZASP_ORDERED_TRANSFORM_ACCEPTANCE_DIR", "ZASP_ORDERED_TRANSFORM_ACCEPTANCE_OUTPUT",
	"ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT",
	"ZASP_ORDERED_READINESS_ATTRIBUTION", "ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_READINESS_PLAN_OUTPUT",
	"ZASP_ORDERED_POLICY_CAPACITY", "ZASP_ORDERED_POLICY_PREFIX", "ZASP_P7_ORDERED69_RETIREMENT_ACL", "ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION",
	"ZASP_P7_ORDERED_BODY_CAPTURE", "ZASP_ORDERED62_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", "ZASP_ORDERED_POLICY_TRACE",
}

type consolidatedReferencePhase struct {
	ID, SQLSHA256, SearchPath, TimeZone string
	SQL                                 []byte
	RuleIDs                             []string
	DemandHandles                       []consolidatedReferenceHandle
}

type consolidatedReferenceHandle struct {
	RuleID string `json:"ruleId"`
	Handle string `json:"handle"`
}

type consolidatedReferenceIO struct {
	Begin     func(context.Context) error
	Exec      func(context.Context, string) error
	Frame     func(context.Context) (orderedSupplementFrame, error)
	Admission func(context.Context) error
	Collect   func(context.Context, consolidatedReferencePhase, func(json.RawMessage) error) error
	Rollback  func(context.Context) error
	Dispose   func(context.Context) error
}

type consolidatedReferenceRule struct {
	Kind           string
	Section        string
	Phase          string
	Fields         []string
	FieldTypes     map[string]string
	SourceMaxRows  *int
	RefusalMaxRows int
	Bag            bool
	RosterRuleID   *string
	DemandRuleID   *string
}

type consolidatedReferenceEvidence struct {
	FileSHA256, RowIdentity, Field, SiteSHA256, FrameSHA256 string
}

type consolidatedReferenceInput struct {
	Phases                                                    []consolidatedReferencePhase
	Shape                                                     orderedSupplementShape
	Paths                                                     []string
	ContractSHA256, ManifestSHA256                            string
	Format, Status, CompilerArtifactSHA256, CompilerChecksum  string
	CompiledSourceSHA256, SourceContractSHA256, ClosureSHA256 string
	Catalog1FileSHA256, Postgres, ServerVersionNum, Pgcrypto  string
	Variant, SessionUser, RequiredRole, TimeZone              string
	SourceFrameVersion, MaxRows, MaxBytes                     int
	Installable, CaptureReady                                 bool
	Rules                                                     map[string]consolidatedReferenceRule
	ReusedEvidence                                            []consolidatedReferenceEvidence
	SourcePins                                                map[string]string
}

func consolidatedReferenceRefusal(phase string) error {
	return errors.New("consolidated reference refused: " + phase)
}

func consolidatedExactKeys(object map[string]json.RawMessage, expected ...string) bool {
	if len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func consolidatedRequireJSONType(raw json.RawMessage, kind string, nullable bool) error {
	if bytes.Equal(raw, []byte("null")) {
		if nullable {
			return nil
		}
		return consolidatedReferenceRefusal("null contract member")
	}
	var value any
	if consolidatedDecodeJSON(raw, &value) != nil {
		return consolidatedReferenceRefusal("contract member JSON")
	}
	valid := false
	switch kind {
	case "boolean":
		_, valid = value.(bool)
	case "string":
		_, valid = value.(string)
	case "array":
		_, valid = value.([]any)
	case "object":
		_, valid = value.(map[string]any)
	case "integer":
		_, valid = consolidatedSafeInteger(raw)
	}
	if !valid {
		return consolidatedReferenceRefusal("contract member type")
	}
	return nil
}

func consolidatedRequireMembers(object map[string]json.RawMessage, fields map[string]string) error {
	for key, kind := range fields {
		nullable := strings.HasSuffix(kind, "?")
		if err := consolidatedRequireJSONType(object[key], strings.TrimSuffix(kind, "?"), nullable); err != nil {
			return consolidatedReferenceRefusal("contract member " + key)
		}
	}
	return nil
}

func consolidatedRequireStringArray(raw json.RawMessage) error {
	if err := consolidatedRequireJSONType(raw, "array", false); err != nil {
		return err
	}
	var values []json.RawMessage
	if consolidatedDecodeJSON(raw, &values) != nil {
		return consolidatedReferenceRefusal("string array")
	}
	for _, value := range values {
		if err := consolidatedRequireJSONType(value, "string", false); err != nil {
			return consolidatedReferenceRefusal("string array member")
		}
	}
	return nil
}

func consolidatedRequireStringMap(raw json.RawMessage) error {
	if err := consolidatedRequireJSONType(raw, "object", false); err != nil {
		return err
	}
	var values map[string]json.RawMessage
	if consolidatedDecodeJSON(raw, &values) != nil {
		return consolidatedReferenceRefusal("string map")
	}
	for _, value := range values {
		if err := consolidatedRequireJSONType(value, "string", false); err != nil {
			return consolidatedReferenceRefusal("string map member")
		}
	}
	return nil
}

func loadConsolidatedReference(directory string) (consolidatedReferenceInput, error) {
	return loadConsolidatedReferencePacket(directory, consolidatedReferenceVariantAPins())
}

func loadConsolidatedReferenceVariantB(directory string) (consolidatedReferenceInput, error) {
	return loadConsolidatedReferencePacket(directory, consolidatedReferenceVariantBPins())
}

func loadConsolidatedReferencePacket(directory string, pins consolidatedReferencePacketPins) (consolidatedReferenceInput, error) {
	var result consolidatedReferenceInput
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !validConsolidatedSHA(pins.ManifestSHA256) || !validConsolidatedSHA(pins.ContractSHA256) || (pins.Variant != "A" && pins.Variant != "B") || pins.Variant == "A" && pins.SessionUser != "zasp_test" || pins.Variant == "B" && pins.SessionUser != "zasp_e2e" {
		return result, consolidatedReferenceRefusal("fixed packet pins")
	}
	manifestPath := filepath.Join(directory, "snapshot-manifest.json")
	rawManifest, err := readOrderedSupplementFile(manifestPath, 1024*1024)
	if err != nil || supplementSHA(rawManifest) != pins.ManifestSHA256 {
		return result, consolidatedReferenceRefusal("manifest pin")
	}
	var manifest struct {
		Format int               `json:"format"`
		Source string            `json:"source"`
		Files  map[string]string `json:"files"`
	}
	var manifestObject map[string]json.RawMessage
	if consolidatedDecodeJSON(rawManifest, &manifestObject) != nil || !consolidatedExactKeys(manifestObject, "format", "source", "files") || consolidatedRequireMembers(manifestObject, map[string]string{"format": "integer", "source": "string", "files": "object"}) != nil || consolidatedRequireStringMap(manifestObject["files"]) != nil || consolidatedDecodeJSON(rawManifest, &manifest) != nil || manifest.Format != 1 || manifest.Source == "" || len(manifest.Files) < 7 {
		return result, consolidatedReferenceRefusal("manifest shape")
	}
	files := map[string][]byte{}
	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return bytes.Compare([]byte(names[i]), []byte(names[j])) < 0 })
	for _, name := range names {
		pin := manifest.Files[name]
		if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.HasPrefix(name, "../") || !validConsolidatedSHA(pin) || strings.HasSuffix(name, "authorization_worker_consolidated_reference_pins_test.go") {
			return consolidatedReferenceInput{}, consolidatedReferenceRefusal("manifest member")
		}
		path := filepath.Join(directory, name)
		raw, readErr := readOrderedSupplementFile(path, 32*1024*1024)
		if readErr != nil || supplementSHA(raw) != pin {
			return consolidatedReferenceInput{}, consolidatedReferenceRefusal("member pin")
		}
		files[name] = raw
		result.Paths = append(result.Paths, path)
	}
	result.Paths = append(result.Paths, manifestPath)
	base := "services/platform/migrations/ordered_current/"
	contractName := base + "consolidated-capture-contract.json"
	coverageName := base + "consolidated-capture-coverage.json"
	contractRaw := files[contractName]
	if len(contractRaw) == 0 || supplementSHA(contractRaw) != pins.ContractSHA256 || len(files[coverageName]) == 0 {
		return consolidatedReferenceInput{}, consolidatedReferenceRefusal("contract pin")
	}
	type wirePhase struct {
		ID, SearchPath, TimeZone, SQLSHA256 string
		RuleIDs                             []string `json:"ruleIds"`
	}
	type wireRule struct {
		Kind, Section, Phase string
		Fields               []string
		FieldTypes           map[string]string `json:"fieldTypes"`
		SourceMaxRows        *int              `json:"sourceMaxRows"`
		RefusalMaxRows       int               `json:"refusalMaxRows"`
		Bag                  bool
		RosterRuleID         *string `json:"rosterRuleId"`
		DemandRuleID         *string `json:"demandRuleId"`
	}
	var contract struct {
		Format, Status                                                 string
		Installable, CaptureReady                                      bool
		SourceFrameVersion, MaxRows, MaxBytes                          int
		CompilerArtifactSHA256, CompilerChecksum, CompiledSourceSHA256 string
		SourceContractSHA256, ClosureSHA256, Catalog1FileSHA256        string
		RequiredPostgres, RequiredServerVersionNum, Pgcrypto           string
		Variant, SessionUser, RequiredRole, RequiredTimeZone           string
		Phases                                                         []wirePhase
		Rules                                                          map[string]wireRule
		ReusedEvidence                                                 []consolidatedReferenceEvidence `json:"reusedEvidence"`
		SourcePins                                                     map[string]string               `json:"sourcePins"`
	}
	var contractObject map[string]json.RawMessage
	contractKeys := []string{"format", "status", "installable", "captureReady", "sourceFrameVersion", "compilerArtifactSHA256", "compilerChecksum", "compiledSourceSHA256", "sourceContractSHA256", "closureSHA256", "catalog1FileSHA256", "requiredPostgres", "requiredServerVersionNum", "pgcrypto", "variant", "sessionUser", "requiredRole", "requiredTimeZone", "maxRows", "maxBytes", "phases", "rules", "reusedEvidence", "sourcePins"}
	contractDomains := map[string]string{
		"format": "string", "status": "string", "installable": "boolean", "captureReady": "boolean", "sourceFrameVersion": "integer",
		"compilerArtifactSHA256": "string", "compilerChecksum": "string", "compiledSourceSHA256": "string", "sourceContractSHA256": "string", "closureSHA256": "string", "catalog1FileSHA256": "string",
		"requiredPostgres": "string", "requiredServerVersionNum": "string", "pgcrypto": "string", "variant": "string", "sessionUser": "string", "requiredRole": "string", "requiredTimeZone": "string",
		"maxRows": "integer", "maxBytes": "integer", "phases": "array", "rules": "object", "reusedEvidence": "array", "sourcePins": "object",
	}
	if consolidatedDecodeJSON(contractRaw, &contractObject) != nil || !consolidatedExactKeys(contractObject, contractKeys...) || consolidatedRequireMembers(contractObject, contractDomains) != nil || consolidatedRequireStringMap(contractObject["sourcePins"]) != nil || consolidatedDecodeJSON(contractRaw, &contract) != nil {
		return consolidatedReferenceInput{}, consolidatedReferenceRefusal("contract JSON")
	}
	var rawPhases []map[string]json.RawMessage
	var rawRules map[string]map[string]json.RawMessage
	var rawEvidence []map[string]json.RawMessage
	if consolidatedDecodeJSON(contractObject["phases"], &rawPhases) != nil || consolidatedDecodeJSON(contractObject["rules"], &rawRules) != nil || consolidatedDecodeJSON(contractObject["reusedEvidence"], &rawEvidence) != nil {
		return consolidatedReferenceInput{}, consolidatedReferenceRefusal("contract nested JSON")
	}
	for _, phase := range rawPhases {
		if !consolidatedExactKeys(phase, "id", "searchPath", "timeZone", "sqlSHA256", "ruleIds") || consolidatedRequireMembers(phase, map[string]string{"id": "string", "searchPath": "string", "timeZone": "string", "sqlSHA256": "string", "ruleIds": "array"}) != nil || consolidatedRequireStringArray(phase["ruleIds"]) != nil {
			return consolidatedReferenceInput{}, consolidatedReferenceRefusal("contract phase keys")
		}
	}
	for _, rule := range rawRules {
		if !consolidatedExactKeys(rule, "kind", "section", "phase", "fields", "fieldTypes", "sourceMaxRows", "refusalMaxRows", "bag", "rosterRuleId", "demandRuleId") || consolidatedRequireMembers(rule, map[string]string{"kind": "string", "section": "string", "phase": "string", "fields": "array", "fieldTypes": "object", "sourceMaxRows": "integer?", "refusalMaxRows": "integer", "bag": "boolean", "rosterRuleId": "string?", "demandRuleId": "string?"}) != nil || consolidatedRequireStringArray(rule["fields"]) != nil || consolidatedRequireStringMap(rule["fieldTypes"]) != nil {
			return consolidatedReferenceInput{}, consolidatedReferenceRefusal("contract rule keys")
		}
	}
	for _, evidence := range rawEvidence {
		if !consolidatedExactKeys(evidence, "fileSHA256", "rowIdentity", "field", "siteSHA256", "frameSHA256") || consolidatedRequireMembers(evidence, map[string]string{"fileSHA256": "string", "rowIdentity": "string", "field": "string", "siteSHA256": "string", "frameSHA256": "string"}) != nil {
			return consolidatedReferenceInput{}, consolidatedReferenceRefusal("contract evidence keys")
		}
	}
	result.Format, result.Status, result.Installable, result.CaptureReady = contract.Format, contract.Status, contract.Installable, contract.CaptureReady
	result.SourceFrameVersion, result.MaxRows, result.MaxBytes = contract.SourceFrameVersion, contract.MaxRows, contract.MaxBytes
	result.CompilerArtifactSHA256, result.CompilerChecksum, result.CompiledSourceSHA256 = contract.CompilerArtifactSHA256, contract.CompilerChecksum, contract.CompiledSourceSHA256
	result.SourceContractSHA256, result.ClosureSHA256, result.Catalog1FileSHA256 = contract.SourceContractSHA256, contract.ClosureSHA256, contract.Catalog1FileSHA256
	result.Postgres, result.ServerVersionNum, result.Pgcrypto = contract.RequiredPostgres, contract.RequiredServerVersionNum, contract.Pgcrypto
	result.Variant, result.SessionUser, result.RequiredRole, result.TimeZone = contract.Variant, contract.SessionUser, contract.RequiredRole, contract.RequiredTimeZone
	result.ManifestSHA256, result.ContractSHA256 = pins.ManifestSHA256, pins.ContractSHA256
	result.ReusedEvidence, result.SourcePins = contract.ReusedEvidence, contract.SourcePins
	result.Rules = map[string]consolidatedReferenceRule{}
	for id, rule := range contract.Rules {
		result.Rules[id] = consolidatedReferenceRule{Kind: rule.Kind, Section: rule.Section, Phase: rule.Phase, Fields: rule.Fields, FieldTypes: rule.FieldTypes, SourceMaxRows: rule.SourceMaxRows, RefusalMaxRows: rule.RefusalMaxRows, Bag: rule.Bag, RosterRuleID: rule.RosterRuleID, DemandRuleID: rule.DemandRuleID}
	}
	for _, phase := range contract.Phases {
		queryName := base + "consolidated-capture-" + phase.ID + ".sql"
		query := files[queryName]
		if len(query) == 0 || supplementSHA(query) != phase.SQLSHA256 {
			return consolidatedReferenceInput{}, consolidatedReferenceRefusal("query pin")
		}
		result.Phases = append(result.Phases, consolidatedReferencePhase{ID: phase.ID, SQLSHA256: phase.SQLSHA256, SearchPath: phase.SearchPath, TimeZone: phase.TimeZone, SQL: query, RuleIDs: phase.RuleIDs})
	}
	if result.ClosureSHA256 != supplementSHA(files[coverageName]) || result.Variant != pins.Variant || result.SessionUser != pins.SessionUser || result.CompilerArtifactSHA256 != supplementCompilerSHA || result.CompilerChecksum != supplementChecksum || result.CompiledSourceSHA256 != supplementCompiledSourceSHA || result.SourceContractSHA256 != supplementSourceContractSHA || result.Catalog1FileSHA256 != supplementCatalogSHA {
		return consolidatedReferenceInput{}, consolidatedReferenceRefusal("frozen provenance")
	}
	for path, pin := range result.SourcePins {
		if manifest.Files[path] != pin {
			return consolidatedReferenceInput{}, consolidatedReferenceRefusal("source pin manifest")
		}
	}
	result.Shape = orderedSupplementShape{MaxRows: result.MaxRows, MaxBytes: result.MaxBytes}
	if err := validConsolidatedInput(result); err != nil {
		return consolidatedReferenceInput{}, err
	}
	return result, nil
}

func consolidatedReferenceMode(mode string, controls map[string]string) (bool, error) {
	if mode == "" {
		return false, nil
	}
	if mode != "1" {
		return false, consolidatedReferenceRefusal("mode")
	}
	for _, key := range consolidatedReferenceOverlapControls {
		if controls[key] != "" {
			return false, consolidatedReferenceRefusal("overlap")
		}
	}
	return true, nil
}

type consolidatedReferenceRow struct {
	RuleID       string                     `json:"ruleId"`
	Identity     *string                    `json:"identity"`
	Handle       *string                    `json:"handle"`
	Multiplicity int64                      `json:"multiplicity"`
	Fact         map[string]json.RawMessage `json:"fact"`
}

type consolidatedPublishedRow struct {
	RuleID       string         `json:"ruleId"`
	Identity     string         `json:"identity"`
	Multiplicity int64          `json:"multiplicity"`
	Fact         map[string]any `json:"fact"`
}

type consolidatedPhaseEvidence struct {
	ID, SearchPath, TimeZone, SQLSHA256 string
	RowCount, ExpandedRows, StreamBytes int64
}

type consolidatedCollection struct {
	sections      map[string][]consolidatedPublishedRow
	phaseEvidence []consolidatedPhaseEvidence
	ruleRows      map[string]int64
	roster        map[string]map[string]string
	joins         map[string]map[string]string
	demand        map[string]map[string]bool
	seen          map[string]bool
	streamRows    int64
	expandedRows  int64
	streamBytes   int64
	rosterRows    int64
	demandRows    int64
	sticky        error
}

func validConsolidatedSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func validConsolidatedInput(input consolidatedReferenceInput) error {
	if input.Format != "ordered-current-complete-capture-contract-v1" || input.Status != "REFERENCE-CAPTURE-ONLY" || input.Installable || !input.CaptureReady || input.SourceFrameVersion != 1 || input.RequiredRole != "zasp_discovery_authority" || input.TimeZone != "UTC" || input.ServerVersionNum != "180003" || input.Pgcrypto != "1.4" || input.Postgres == "" || input.MaxRows != 10000 || input.MaxBytes != 16777216 {
		return consolidatedReferenceRefusal("contract")
	}
	if input.Variant != "A" && input.Variant != "B" || input.Variant == "A" && input.SessionUser != "zasp_test" || input.Variant == "B" && input.SessionUser != "zasp_e2e" {
		return consolidatedReferenceRefusal("variant")
	}
	for _, pin := range []string{input.ManifestSHA256, input.ContractSHA256, input.CompilerArtifactSHA256, input.CompilerChecksum, input.CompiledSourceSHA256, input.SourceContractSHA256, input.ClosureSHA256, input.Catalog1FileSHA256} {
		if !validConsolidatedSHA(pin) {
			return consolidatedReferenceRefusal("provenance")
		}
	}
	wantPhases := []struct{ id, path string }{{"demand", "pg_catalog, public"}, {"keys", "pg_catalog"}, {"original", "pg_catalog, public"}, {"resolution", "pg_catalog, public"}, {"witness", "pg_catalog, public"}}
	if len(input.Phases) != len(wantPhases) || len(input.Rules) == 0 {
		return consolidatedReferenceRefusal("phases")
	}
	declared := map[string]bool{}
	for i, phase := range input.Phases {
		if phase.ID != wantPhases[i].id || phase.SearchPath != wantPhases[i].path || phase.TimeZone != "UTC" || len(phase.SQL) == 0 || supplementSHA(phase.SQL) != phase.SQLSHA256 || phase.DemandHandles != nil {
			return consolidatedReferenceRefusal("phase shape")
		}
		for _, id := range phase.RuleIDs {
			if declared[id] {
				return consolidatedReferenceRefusal("phase rule duplicate")
			}
			rule, ok := input.Rules[id]
			if !ok || rule.Phase != phase.ID {
				return consolidatedReferenceRefusal("phase rule")
			}
			declared[id] = true
		}
	}
	if len(declared) != len(input.Rules) {
		return consolidatedReferenceRefusal("undeclared rule")
	}
	sections := map[string]bool{"demand": true, "roster": true, "rawInputs": true, "normalizationObservations": true, "resolutions": true, "witnesses": true}
	types := map[string]bool{"text": true, "boolean": true, "integer": true, "number": true, "json": true, "text[]": true}
	for id, rule := range input.Rules {
		if id == "" || rule.Kind == "" || !sections[rule.Section] || rule.RefusalMaxRows < 0 || rule.RefusalMaxRows > input.MaxRows || len(rule.Fields) != len(rule.FieldTypes) {
			return consolidatedReferenceRefusal("rule")
		}
		phaseForSection := map[string]string{"demand": "demand", "roster": "keys", "rawInputs": "original", "normalizationObservations": "original", "resolutions": "resolution", "witnesses": "witness"}
		if rule.Phase != phaseForSection[rule.Section] && !(rule.Section == "normalizationObservations" && rule.Phase == "witness") {
			return consolidatedReferenceRefusal("section phase")
		}
		if rule.Section == "demand" && (len(rule.Fields) != 0 || rule.RosterRuleID != nil || rule.DemandRuleID != nil || rule.Bag) {
			return consolidatedReferenceRefusal("demand rule")
		}
		if rule.Section == "roster" && (len(rule.Fields) != 0 || rule.RosterRuleID != nil || rule.DemandRuleID == nil || rule.Bag) {
			return consolidatedReferenceRefusal("roster rule")
		}
		if rule.Section != "roster" && rule.DemandRuleID != nil {
			return consolidatedReferenceRefusal("demand consumer")
		}
		seen := map[string]bool{}
		for _, field := range rule.Fields {
			typ := rule.FieldTypes[field]
			base := strings.TrimSuffix(typ, "?")
			if field == "" || seen[field] || !types[base] || strings.Count(typ, "?") > 1 || strings.Contains(typ[:max(0, len(typ)-1)], "?") {
				return consolidatedReferenceRefusal("field")
			}
			seen[field] = true
		}
		if rule.SourceMaxRows != nil && (*rule.SourceMaxRows < 0 || int64(*rule.SourceMaxRows) > 9007199254740991) {
			return consolidatedReferenceRefusal("source maximum")
		}
		if rule.RosterRuleID != nil {
			roster, ok := input.Rules[*rule.RosterRuleID]
			if !ok || roster.Section != "roster" || rule.Phase != "original" {
				return consolidatedReferenceRefusal("roster binding")
			}
		}
	}
	demandConsumers, rosterConsumers := map[string]int{}, map[string]int{}
	for _, rule := range input.Rules {
		if rule.DemandRuleID != nil {
			demand, ok := input.Rules[*rule.DemandRuleID]
			if !ok || demand.Section != "demand" {
				return consolidatedReferenceRefusal("demand binding")
			}
			demandConsumers[*rule.DemandRuleID]++
		}
		if rule.RosterRuleID != nil {
			rosterConsumers[*rule.RosterRuleID]++
		}
	}
	for id, rule := range input.Rules {
		if rule.Section == "demand" && demandConsumers[id] != 1 || rule.Section == "roster" && rosterConsumers[id] != 1 {
			return consolidatedReferenceRefusal("consumer closure")
		}
	}
	for path, pin := range input.SourcePins {
		if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, "../") || !validConsolidatedSHA(pin) {
			return consolidatedReferenceRefusal("source pin")
		}
	}
	if len(input.SourcePins) == 0 {
		return consolidatedReferenceRefusal("source pins")
	}
	for _, item := range input.ReusedEvidence {
		if !validConsolidatedSHA(item.FileSHA256) || !validConsolidatedSHA(item.SiteSHA256) || !validConsolidatedSHA(item.FrameSHA256) || item.RowIdentity == "" || item.Field == "" {
			return consolidatedReferenceRefusal("reused evidence")
		}
	}
	return nil
}

func consolidatedHasLoneSurrogate(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' || i+1 >= len(raw) {
			continue
		}
		if raw[i+1] != 'u' {
			i++
			continue
		}
		if i+5 >= len(raw) {
			return true
		}
		value, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
		if err != nil {
			return true
		}
		if value >= 0xdc00 && value <= 0xdfff {
			return true
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+11 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return true
			}
			low, err := strconv.ParseUint(string(raw[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return true
			}
			i += 11
			continue
		}
		i += 5
	}
	return false
}

func consolidatedDecodeJSON(raw []byte, target any) error {
	if !utf8.Valid(raw) || consolidatedHasLoneSurrogate(raw) {
		return consolidatedReferenceRefusal("unicode")
	}
	if err := supplementJSON(raw, target); err != nil {
		return err
	}
	return nil
}

func consolidatedSafeInteger(raw json.RawMessage) (int64, bool) {
	text := string(raw)
	if text == "" {
		return 0, false
	}
	var number json.Number
	if consolidatedDecodeJSON(raw, &number) != nil {
		return 0, false
	}
	mantissa, exponent := text, 0
	if at := strings.IndexAny(mantissa, "eE"); at >= 0 {
		parsed, err := strconv.Atoi(mantissa[at+1:])
		if err != nil || parsed < -100000 || parsed > 100000 {
			return 0, false
		}
		exponent, mantissa = parsed, mantissa[:at]
	}
	negative := strings.HasPrefix(mantissa, "-")
	mantissa = strings.TrimPrefix(mantissa, "-")
	scale := 0
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		scale = len(mantissa) - dot - 1
		mantissa = mantissa[:dot] + mantissa[dot+1:]
	}
	coefficient := new(big.Int)
	if _, ok := coefficient.SetString(mantissa, 10); !ok {
		return 0, false
	}
	power := exponent - scale
	if power >= 0 {
		coefficient.Mul(coefficient, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(power)), nil))
	} else {
		divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-power)), nil)
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(coefficient, divisor, remainder)
		if remainder.Sign() != 0 {
			return 0, false
		}
		coefficient = quotient
	}
	if negative {
		coefficient.Neg(coefficient)
	}
	limit := big.NewInt(9007199254740991)
	if new(big.Int).Abs(new(big.Int).Set(coefficient)).Cmp(limit) > 0 || !coefficient.IsInt64() {
		return 0, false
	}
	return coefficient.Int64(), true
}

type consolidatedNumber string

func consolidatedFiniteNumber(raw json.RawMessage) (consolidatedNumber, bool) {
	var value json.Number
	if consolidatedDecodeJSON(raw, &value) != nil {
		return "", false
	}
	text := value.String()
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", false
	}
	if f == 0 {
		significand := text
		if at := strings.IndexAny(significand, "eE"); at >= 0 {
			significand = significand[:at]
		}
		for _, r := range significand {
			if r >= '1' && r <= '9' {
				return "", false
			}
		}
	}
	return consolidatedNumber(text), true
}

func consolidatedJSONValue(raw json.RawMessage, typ string) (any, bool) {
	nullable := strings.HasSuffix(typ, "?")
	typ = strings.TrimSuffix(typ, "?")
	if bytes.Equal(raw, []byte("null")) {
		return nil, nullable
	}
	if !utf8.Valid(raw) || consolidatedHasLoneSurrogate(raw) {
		return nil, false
	}
	switch typ {
	case "text":
		var value string
		return value, consolidatedDecodeJSON(raw, &value) == nil
	case "boolean":
		var value bool
		return value, consolidatedDecodeJSON(raw, &value) == nil
	case "integer", "number":
		if typ == "integer" {
			_, ok := consolidatedSafeInteger(raw)
			return consolidatedNumber(string(raw)), ok
		}
		value, ok := consolidatedFiniteNumber(raw)
		return value, ok
	case "text[]":
		if consolidatedRequireStringArray(raw) != nil {
			return nil, false
		}
		var value []string
		return value, consolidatedDecodeJSON(raw, &value) == nil && value != nil
	case "json":
		var value any
		if consolidatedDecodeJSON(raw, &value) != nil {
			return nil, false
		}
		value, ok := consolidatedNumbers(value)
		return value, ok
	default:
		return nil, false
	}
}

func consolidatedNumbers(value any) (any, bool) {
	switch item := value.(type) {
	case json.Number:
		return consolidatedFiniteNumber(json.RawMessage(item.String()))
	case []any:
		result := make([]any, len(item))
		for i, child := range item {
			converted, ok := consolidatedNumbers(child)
			if !ok {
				return nil, false
			}
			result[i] = converted
		}
		return result, true
	case map[string]any:
		result := map[string]any{}
		for key, child := range item {
			converted, ok := consolidatedNumbers(child)
			if !ok {
				return nil, false
			}
			result[key] = converted
		}
		return result, true
	}
	return value, true
}

func newConsolidatedCollection(input consolidatedReferenceInput) *consolidatedCollection {
	result := &consolidatedCollection{
		sections: map[string][]consolidatedPublishedRow{"rawInputs": {}, "normalizationObservations": {}, "resolutions": {}, "witnesses": {}},
		ruleRows: map[string]int64{}, roster: map[string]map[string]string{}, joins: map[string]map[string]string{}, demand: map[string]map[string]bool{}, seen: map[string]bool{},
	}
	for id := range input.Rules {
		result.ruleRows[id] = 0
	}
	return result
}

func (state *consolidatedCollection) emit(input consolidatedReferenceInput, phase consolidatedReferencePhase, raw json.RawMessage) error {
	if state.sticky != nil {
		return state.sticky
	}
	state.streamBytes += int64(len(raw))
	if state.streamBytes > int64(input.MaxBytes) {
		state.sticky = consolidatedReferenceRefusal("stream bytes")
		return state.sticky
	}
	var row consolidatedReferenceRow
	var rowObject map[string]json.RawMessage
	if err := consolidatedDecodeJSON(raw, &rowObject); err != nil || !consolidatedExactKeys(rowObject, "ruleId", "identity", "handle", "multiplicity", "fact") || consolidatedDecodeJSON(raw, &row) != nil || row.RuleID == "" || row.Fact == nil || row.Identity != nil && (*row.Identity == "" || strings.ContainsRune(*row.Identity, 0)) {
		state.sticky = consolidatedReferenceRefusal("row shape")
		return state.sticky
	}
	rule, ok := input.Rules[row.RuleID]
	if !ok || rule.Phase != phase.ID || row.Multiplicity <= 0 || row.Multiplicity > 9007199254740991 || !rule.Bag && row.Multiplicity != 1 || len(row.Fact) != len(rule.Fields) {
		state.sticky = consolidatedReferenceRefusal("row rule")
		return state.sticky
	}
	identityKey := "<null>"
	if row.Identity != nil {
		identityKey = *row.Identity
	}
	key := row.RuleID + "\x00" + identityKey
	if row.Handle != nil {
		key += "\x00" + *row.Handle
	}
	if state.seen[key] {
		state.sticky = consolidatedReferenceRefusal("row duplicate")
		return state.sticky
	}
	state.seen[key] = true
	fact := map[string]any{}
	for _, field := range rule.Fields {
		rawValue, exists := row.Fact[field]
		value, valid := consolidatedJSONValue(rawValue, rule.FieldTypes[field])
		if !exists || !valid {
			state.sticky = consolidatedReferenceRefusal("row field")
			return state.sticky
		}
		fact[field] = value
	}
	state.streamRows++
	state.expandedRows += row.Multiplicity
	state.ruleRows[row.RuleID] += row.Multiplicity
	if state.expandedRows > int64(input.MaxRows) || state.ruleRows[row.RuleID] > int64(rule.RefusalMaxRows) || rule.SourceMaxRows != nil && state.ruleRows[row.RuleID] > int64(*rule.SourceMaxRows) {
		state.sticky = consolidatedReferenceRefusal("row bounds")
		return state.sticky
	}
	if rule.Section == "demand" {
		if row.Identity != nil || row.Handle == nil || *row.Handle == "" || len(row.Fact) != 0 || row.Multiplicity != 1 {
			state.sticky = consolidatedReferenceRefusal("demand row")
			return state.sticky
		}
		if state.demand[row.RuleID] == nil {
			state.demand[row.RuleID] = map[string]bool{}
		}
		if state.demand[row.RuleID][*row.Handle] {
			state.sticky = consolidatedReferenceRefusal("demand handle")
			return state.sticky
		}
		state.demand[row.RuleID][*row.Handle] = true
		state.demandRows++
		return nil
	}
	if rule.Section == "roster" {
		if row.Identity == nil || row.Handle == nil || *row.Handle == "" || len(row.Fact) != 0 || row.Multiplicity != 1 {
			state.sticky = consolidatedReferenceRefusal("roster row")
			return state.sticky
		}
		if state.roster[row.RuleID] == nil {
			state.roster[row.RuleID] = map[string]string{}
		}
		if state.roster[row.RuleID][*row.Handle] != "" {
			state.sticky = consolidatedReferenceRefusal("roster handle")
			return state.sticky
		}
		for _, identity := range state.roster[row.RuleID] {
			if identity == *row.Identity {
				state.sticky = consolidatedReferenceRefusal("roster identity")
				return state.sticky
			}
		}
		state.roster[row.RuleID][*row.Handle] = *row.Identity
		state.rosterRows++
		return nil
	}
	if rule.RosterRuleID != nil {
		if row.Identity != nil || row.Handle == nil || *row.Handle == "" {
			state.sticky = consolidatedReferenceRefusal("join handle")
			return state.sticky
		}
		if state.joins[row.RuleID] == nil {
			state.joins[row.RuleID] = map[string]string{}
		}
		if state.joins[row.RuleID][*row.Handle] != "" {
			state.sticky = consolidatedReferenceRefusal("join duplicate")
			return state.sticky
		}
		canonical := state.roster[*rule.RosterRuleID][*row.Handle]
		if canonical == "" {
			state.sticky = consolidatedReferenceRefusal("unresolved join")
			return state.sticky
		}
		state.joins[row.RuleID][*row.Handle] = canonical
		row.Identity = &canonical
	} else if row.Handle != nil || row.Identity == nil {
		state.sticky = consolidatedReferenceRefusal("unexpected handle")
		return state.sticky
	}
	state.sections[rule.Section] = append(state.sections[rule.Section], consolidatedPublishedRow{RuleID: row.RuleID, Identity: *row.Identity, Multiplicity: row.Multiplicity, Fact: fact})
	return nil
}

func (state *consolidatedCollection) finish(input consolidatedReferenceInput) error {
	if state.sticky != nil {
		return state.sticky
	}
	for id, rule := range input.Rules {
		if rule.Section == "roster" {
			demand, roster := state.demand[*rule.DemandRuleID], state.roster[id]
			if len(demand) != len(roster) {
				return consolidatedReferenceRefusal("demand roster completeness")
			}
			for handle := range demand {
				if roster[handle] == "" {
					return consolidatedReferenceRefusal("demand roster handle")
				}
			}
		}
		if rule.RosterRuleID == nil {
			continue
		}
		roster, joins := state.roster[*rule.RosterRuleID], state.joins[id]
		if len(roster) != len(joins) {
			return consolidatedReferenceRefusal("join completeness")
		}
		for handle, identity := range roster {
			if joins[handle] != identity {
				return consolidatedReferenceRefusal("join identity")
			}
		}
	}
	for section := range state.sections {
		sort.Slice(state.sections[section], func(i, j int) bool {
			left, right := state.sections[section][i], state.sections[section][j]
			if left.RuleID != right.RuleID {
				return bytes.Compare([]byte(left.RuleID), []byte(right.RuleID)) < 0
			}
			return bytes.Compare([]byte(left.Identity), []byte(right.Identity)) < 0
		})
	}
	return nil
}

func consolidatedFrameOK(frame orderedSupplementFrame, input consolidatedReferenceInput, path string, role string) bool {
	return frame.Session == input.SessionUser && frame.Role == role && frame.SearchPath == path && frame.TimeZone == input.TimeZone && frame.ReadOnly && frame.Postgres == input.Postgres && frame.ServerVersionNum == input.ServerVersionNum && frame.Pgcrypto == input.Pgcrypto
}

func captureConsolidatedReference(parent context.Context, input consolidatedReferenceInput, io consolidatedReferenceIO, destination string) (publication orderedSupplementPublication, result error) {
	if parent == nil || parent.Err() != nil || io.Begin == nil || io.Exec == nil || io.Frame == nil || io.Admission == nil || io.Collect == nil || io.Rollback == nil || io.Dispose == nil {
		return publication, consolidatedReferenceRefusal("dependencies")
	}
	if err := validConsolidatedInput(input); err != nil {
		return publication, err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	success := false
	defer func() {
		if success {
			return
		}
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		if err := io.Dispose(cleanup); err != nil {
			result = errors.Join(result, consolidatedReferenceRefusal("dispose"))
		}
	}()
	original, err := io.Frame(ctx)
	if err != nil || original.Session != input.SessionUser || original.Role != input.SessionUser || original.Postgres != input.Postgres || original.ServerVersionNum != input.ServerVersionNum || original.Pgcrypto != input.Pgcrypto {
		return publication, consolidatedReferenceRefusal("initial frame")
	}
	if err := io.Begin(ctx); err != nil {
		return publication, consolidatedReferenceRefusal("begin")
	}
	active := true
	rollbackRestore := func() error {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		if err := io.Rollback(cleanup); err != nil {
			active = false
			return consolidatedReferenceRefusal("rollback")
		}
		active = false
		restored, err := io.Frame(cleanup)
		if err != nil || restored != original {
			return consolidatedReferenceRefusal("restored frame")
		}
		return nil
	}
	defer func() {
		if active {
			result = errors.Join(result, rollbackRestore())
		}
	}()
	configure := `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL search_path=pg_catalog; SET LOCAL TIME ZONE 'UTC'; SELECT pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0))`
	if io.Exec(ctx, configure) != nil || io.Admission(ctx) != nil || io.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`) != nil {
		return publication, consolidatedReferenceRefusal("setup/admission")
	}
	state := newConsolidatedCollection(input)
	for _, phase := range input.Phases {
		if phase.ID == "keys" {
			phase.DemandHandles = []consolidatedReferenceHandle{}
			for ruleID, handles := range state.demand {
				for handle := range handles {
					phase.DemandHandles = append(phase.DemandHandles, consolidatedReferenceHandle{RuleID: ruleID, Handle: handle})
				}
			}
			sort.Slice(phase.DemandHandles, func(i, j int) bool {
				if phase.DemandHandles[i].RuleID != phase.DemandHandles[j].RuleID {
					return bytes.Compare([]byte(phase.DemandHandles[i].RuleID), []byte(phase.DemandHandles[j].RuleID)) < 0
				}
				return bytes.Compare([]byte(phase.DemandHandles[i].Handle), []byte(phase.DemandHandles[j].Handle)) < 0
			})
		}
		if io.Exec(ctx, "SET LOCAL search_path="+phase.SearchPath) != nil {
			return publication, consolidatedReferenceRefusal("phase path")
		}
		frame, err := io.Frame(ctx)
		if err != nil || !consolidatedFrameOK(frame, input, phase.SearchPath, input.RequiredRole) {
			return publication, consolidatedReferenceRefusal("phase frame")
		}
		beforeRows, beforeExpanded, beforeBytes := state.streamRows, state.expandedRows, state.streamBytes
		collectErr := io.Collect(ctx, phase, func(raw json.RawMessage) error { return state.emit(input, phase, raw) })
		state.phaseEvidence = append(state.phaseEvidence, consolidatedPhaseEvidence{ID: phase.ID, SearchPath: phase.SearchPath, TimeZone: phase.TimeZone, SQLSHA256: phase.SQLSHA256, RowCount: state.streamRows - beforeRows, ExpandedRows: state.expandedRows - beforeExpanded, StreamBytes: state.streamBytes - beforeBytes})
		if collectErr != nil || state.sticky != nil || ctx.Err() != nil {
			return publication, consolidatedReferenceRefusal("collect " + phase.ID)
		}
	}
	if err := state.finish(input); err != nil {
		return publication, err
	}
	if io.Exec(ctx, "SET LOCAL search_path=pg_catalog") != nil {
		return publication, consolidatedReferenceRefusal("restore catalog path")
	}
	frame, err := io.Frame(ctx)
	if err != nil || !consolidatedFrameOK(frame, input, "pg_catalog", input.RequiredRole) {
		return publication, consolidatedReferenceRefusal("catalog frame")
	}
	if io.Exec(ctx, "RESET ROLE") != nil {
		return publication, consolidatedReferenceRefusal("reset role")
	}
	frame, err = io.Frame(ctx)
	if err != nil || !consolidatedFrameOK(frame, input, "pg_catalog", input.SessionUser) {
		return publication, consolidatedReferenceRefusal("owner frame")
	}
	if io.Admission(ctx) != nil || ctx.Err() != nil {
		return publication, consolidatedReferenceRefusal("admission after")
	}
	if err := rollbackRestore(); err != nil {
		return publication, err
	}
	envelope := consolidatedEnvelope(input, state)
	payload, err := canonicalConsolidatedJSON(envelope)
	if err != nil || len(payload)+1 > input.MaxBytes {
		return publication, consolidatedReferenceRefusal("envelope bytes")
	}
	publication, err = publishPrivateReference(ctx, destination, input.Paths, payload, input.MaxBytes, nil)
	if err != nil {
		return orderedSupplementPublication{}, err
	}
	success = true
	return publication, nil
}

func consolidatedEnvelope(input consolidatedReferenceInput, state *consolidatedCollection) map[string]any {
	phases := make([]any, 0, len(state.phaseEvidence))
	for _, phase := range state.phaseEvidence {
		phases = append(phases, map[string]any{"id": phase.ID, "searchPath": phase.SearchPath, "timeZone": phase.TimeZone, "sqlSHA256": phase.SQLSHA256, "rowCount": phase.RowCount, "expandedRows": phase.ExpandedRows, "streamBytes": phase.StreamBytes})
	}
	evidence := make([]any, 0, len(input.ReusedEvidence))
	for _, item := range input.ReusedEvidence {
		evidence = append(evidence, map[string]any{"fileSHA256": item.FileSHA256, "rowIdentity": item.RowIdentity, "field": item.Field, "siteSHA256": item.SiteSHA256, "frameSHA256": item.FrameSHA256})
	}
	rows := func(section string) []any {
		result := make([]any, 0, len(state.sections[section]))
		for _, row := range state.sections[section] {
			result = append(result, map[string]any{"ruleId": row.RuleID, "identity": row.Identity, "multiplicity": row.Multiplicity, "fact": row.Fact})
		}
		return result
	}
	ruleRows := map[string]any{}
	for id, count := range state.ruleRows {
		ruleRows[id] = count
	}
	sourcePins := map[string]any{}
	for path, sha := range input.SourcePins {
		sourcePins[path] = sha
	}
	return map[string]any{
		"format": "ordered-current-complete-reference-v1", "status": "REFERENCE-CAPTURE-ONLY", "installable": false, "sourceFrameVersion": input.SourceFrameVersion,
		"packetManifestSHA256": input.ManifestSHA256, "contractSHA256": input.ContractSHA256, "closureSHA256": input.ClosureSHA256,
		"compilerArtifactSHA256": input.CompilerArtifactSHA256, "compilerChecksum": input.CompilerChecksum, "compiledSourceSHA256": input.CompiledSourceSHA256,
		"sourceContractSHA256": input.SourceContractSHA256, "catalog1FileSHA256": input.Catalog1FileSHA256, "sourcePins": sourcePins,
		"variant": input.Variant, "sessionUser": input.SessionUser, "role": input.RequiredRole, "timeZone": input.TimeZone,
		"postgres": input.Postgres, "serverVersionNum": input.ServerVersionNum, "pgcrypto": input.Pgcrypto,
		"readOnly": true, "preAdmission": true, "postAdmission": true, "rolledBack": true, "frameRestored": true,
		"phases": phases, "counts": map[string]any{"streamRows": state.streamRows, "expandedRows": state.expandedRows, "streamBytes": state.streamBytes, "demandRows": state.demandRows, "rosterRows": state.rosterRows, "ruleRows": ruleRows},
		"rawInputs": rows("rawInputs"), "normalizationObservations": rows("normalizationObservations"), "resolutions": rows("resolutions"), "witnesses": rows("witnesses"), "reusedEvidence": evidence,
	}
}

func canonicalConsolidatedJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := appendConsolidatedJSON(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func appendConsolidatedString(out *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return consolidatedReferenceRefusal("canonical unicode")
	}
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\u2028':
			out.WriteString(`\u2028`)
		case '\u2029':
			out.WriteString(`\u2029`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return nil
}

func appendConsolidatedJSON(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		return appendConsolidatedString(out, v)
	case int:
		return appendConsolidatedJSON(out, int64(v))
	case int64:
		if v < -9007199254740991 || v > 9007199254740991 {
			return consolidatedReferenceRefusal("canonical integer")
		}
		out.WriteString(strconv.FormatInt(v, 10))
	case json.Number:
		n, ok := consolidatedFiniteNumber(json.RawMessage(v.String()))
		if !ok {
			return consolidatedReferenceRefusal("canonical number")
		}
		out.WriteString(string(n))
	case consolidatedNumber:
		if _, ok := consolidatedFiniteNumber(json.RawMessage(v)); !ok {
			return consolidatedReferenceRefusal("canonical number")
		}
		out.WriteString(string(v))
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare([]byte(keys[i]), []byte(keys[j])) < 0 })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendConsolidatedString(out, key); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := appendConsolidatedJSON(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendConsolidatedJSON(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case []string:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendConsolidatedString(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]string:
		converted := map[string]any{}
		for key, item := range v {
			converted[key] = item
		}
		return appendConsolidatedJSON(out, converted)
	default:
		return consolidatedReferenceRefusal("canonical type")
	}
	return nil
}
