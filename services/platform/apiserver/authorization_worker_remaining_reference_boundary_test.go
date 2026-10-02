package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

const remainingPacket = "/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-supplement3-qualified-dgdNyg"
const remainingP7 = ".superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/"
const remainingManifestSHA = "23801c8ec87733dd97f4b7273fab3013ae86b927d397527a140c818faf468ef9"
const remainingContractSHA = "1046cd882d3493bbd5186a6fb95aaf711e97070a9b3cec611fefeae108e1be17"
const remainingQuerySHA = "0aea676e6d05d1be6578d673d9bb690c04b63a96168e8fe3d03d8b211ca0aecf"

type remainingReferenceInput struct {
	Shape                                                     orderedSupplementShape
	SQL                                                       []byte
	Paths                                                     []string
	Postgres, ServerVersionNum, Pgcrypto, RawInputDisposition string
	RawInputRuleIDs                                           []string
}

// The literal whole-manifest hash binds all 19 literal path/hash pairs, including
// the eight reviewed emitter modules. Never repin these from the mutable tree.
func loadRemainingReference(directory string) (remainingReferenceInput, error) {
	var result remainingReferenceInput
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return result, supplementRefusal("remaining directory")
	}
	manifestPath := filepath.Join(directory, "snapshot-manifest.json")
	raw, e := readOrderedSupplementFile(manifestPath, 1024*1024)
	if e != nil || supplementSHA(raw) != remainingManifestSHA {
		return result, supplementRefusal("remaining manifest pin")
	}
	var manifest struct {
		Format int
		Source string
		Files  map[string]string
	}
	if supplementJSON(raw, &manifest) != nil || manifest.Format != 1 || len(manifest.Files) != 19 {
		return result, supplementRefusal("remaining manifest shape")
	}
	names := []string{}
	for name := range manifest.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	files := map[string][]byte{}
	for _, name := range names {
		if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.HasPrefix(name, "../") {
			return result, supplementRefusal("remaining path")
		}
		path := filepath.Join(directory, name)
		body, err := readOrderedSupplementFile(path, 32*1024*1024)
		if err != nil || supplementSHA(body) != manifest.Files[name] {
			return result, supplementRefusal("remaining file pin")
		}
		result.Paths = append(result.Paths, path)
		files[name] = body
	}
	result.Paths = append(result.Paths, manifestPath)
	contract := files[remainingP7+"ordered-current-supplementary-query-contract3.json"]
	result.SQL = files[remainingP7+"ordered-current-supplementary-select3.sql"]
	if supplementSHA(contract) != remainingContractSHA || supplementSHA(result.SQL) != remainingQuerySHA {
		return remainingReferenceInput{}, supplementRefusal("remaining query pin")
	}
	var object map[string]json.RawMessage
	if supplementJSON(contract, &object) != nil {
		return remainingReferenceInput{}, supplementRefusal("remaining contract JSON")
	}
	// Decode only capture fields after the independent entire-file pin. Source
	// selectors/obligations are not rewritten, and no target row supplies a limit.
	var c struct {
		Format, Status, SQLSHA256, CompilerChecksum, CompiledSourceSHA256, CompilerArtifactSHA256, Catalog1FileSHA256, SourceContractSHA256 string
		RequiredRole, RequiredTimeZone, RequiredPostgres, RequiredServerVersionNum, PriorReferenceFileSHA256, RawInputDisposition           string
		RequiredSearchPath, RawInputRuleIDs                                                                                                 []string
		Rules                                                                                                                               []orderedSupplementRule
		FieldTypes                                                                                                                          map[string]map[string]string
		CategoryMaxRows, RuleMaxRows                                                                                                        map[string]int
		MaxRows, MaxBytes                                                                                                                   int
	}
	if json.Unmarshal(contract, &c) != nil || c.Format != "ordered-current-supplementary-query-v1" || c.Status != "REFERENCE-CAPTURE-ONLY" || c.SQLSHA256 != remainingQuerySHA || c.CompilerChecksum != supplementChecksum || c.CompiledSourceSHA256 != supplementCompiledSourceSHA || c.CompilerArtifactSHA256 != supplementCompilerSHA || c.Catalog1FileSHA256 != supplementCatalogSHA || c.SourceContractSHA256 != supplementSourceContractSHA || c.RequiredRole != "zasp_discovery_authority" || !reflect.DeepEqual(c.RequiredSearchPath, []string{"pg_catalog"}) || c.RequiredTimeZone != "UTC" || c.RequiredPostgres == "" || c.RequiredServerVersionNum != "180003" || len(c.Rules) != 64 || len(c.RawInputRuleIDs) != 16 || c.MaxRows != 9623 || c.MaxBytes != 16777216 || c.RawInputDisposition == "" {
		return remainingReferenceInput{}, supplementRefusal("remaining contract shape")
	}
	prior := files[remainingP7+"ordered-current-supplementary-reference1.json"]
	var reference struct{ Postgres, ServerVersionNum, Pgcrypto string }
	if supplementSHA(prior) != c.PriorReferenceFileSHA256 || json.Unmarshal(prior, &reference) != nil || reference.Postgres != c.RequiredPostgres || reference.ServerVersionNum != c.RequiredServerVersionNum || reference.Pgcrypto != "1.4" {
		return remainingReferenceInput{}, supplementRefusal("remaining prior frame")
	}
	result.Shape = orderedSupplementShape{Rules: c.Rules, Fields: c.FieldTypes, CategoryMaxRows: c.CategoryMaxRows, RuleMaxRows: c.RuleMaxRows, MaxRows: c.MaxRows, MaxBytes: c.MaxBytes}
	if checkOrderedSupplementRows(result.Shape, []json.RawMessage{}) != nil {
		return remainingReferenceInput{}, supplementRefusal("remaining typed shape")
	}
	result.Postgres = c.RequiredPostgres
	result.ServerVersionNum = c.RequiredServerVersionNum
	result.Pgcrypto = reference.Pgcrypto
	result.RawInputRuleIDs = c.RawInputRuleIDs
	result.RawInputDisposition = c.RawInputDisposition
	return result, nil
}

var remainingOverlapControls = []string{"ZASP_ORDERED_PRIVATE_REFERENCE", "ZASP_ORDERED_PRIVATE_REFERENCE_CAPTURE", "ZASP_ORDERED_PRIVATE_REFERENCE_DIR", "ZASP_ORDERED_PRIVATE_REFERENCE_OUTPUT", "ZASP_ORDERED_SUPPLEMENT_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_REFERENCE_DIR", "ZASP_ORDERED_SUPPLEMENT_OUTPUT", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", "ZASP_ORDERED_READINESS_ATTRIBUTION", "ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_READINESS_PLAN_OUTPUT", "ZASP_ORDERED_POLICY_CAPACITY", "ZASP_ORDERED_POLICY_PREFIX", "ZASP_P7_ORDERED69_RETIREMENT_ACL", "ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION", "ZASP_P7_ORDERED_BODY_CAPTURE", "ZASP_ORDERED62_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", "ZASP_ORDERED_POLICY_TRACE"}

func remainingReferenceMode(mode string, controls map[string]string) (bool, error) {
	if mode == "" {
		return false, nil
	}
	if mode != "1" {
		return false, supplementRefusal("remaining mode")
	}
	for _, name := range remainingOverlapControls {
		if controls[name] != "" {
			return false, supplementRefusal("remaining overlap")
		}
	}
	return true, nil
}

// Composition adds exact release-frame admission and cancellation-aware
// publication; the accepted read-only boundary retains its SQL and ordering.
func captureRemainingReference(ctx context.Context, input remainingReferenceInput, io orderedSupplementIO, destination string) (publication orderedSupplementPublication, err error) {
	if ctx == nil || io.Frame == nil || io.Dispose == nil {
		return publication, supplementRefusal("remaining dependencies")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	defer func() {
		if err != nil {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer done()
			if e := io.Dispose(cleanup); e != nil {
				err = errors.Join(err, supplementRefusal("remaining disposal"))
			}
		}
	}()
	frameRead := io.Frame
	io.Frame = func(c context.Context) (orderedSupplementFrame, error) {
		f, e := frameRead(c)
		if e != nil || f.Postgres != input.Postgres || f.ServerVersionNum != input.ServerVersionNum || f.Pgcrypto != input.Pgcrypto {
			return orderedSupplementFrame{}, supplementRefusal("remaining exact frame")
		}
		return f, nil
	}
	rows, frame, e := runOrderedSupplementBoundary(ctx, "zasp_test", input.Shape, io)
	if e != nil {
		return publication, e
	}
	// Raw routine facts are explicitly intermediate; this file does not authorize
	// a comparison recipe or replace any transformation/live binding obligation.
	envelope := map[string]any{
		"format": "ordered-current-remaining-reference-v1", "status": "REFERENCE-CAPTURE-ONLY", "packetManifestSHA256": remainingManifestSHA, "contractSHA256": remainingContractSHA, "querySHA256": remainingQuerySHA,
		"compilerArtifactSHA256": supplementCompilerSHA, "compilerChecksum": supplementChecksum, "compiledSourceSHA256": supplementCompiledSourceSHA, "catalog1FileSHA256": supplementCatalogSHA, "sourceContractSHA256": supplementSourceContractSHA,
		"variant": "A", "sessionUser": frame.Session, "role": frame.Role, "searchPath": []string{"pg_catalog"}, "timeZone": frame.TimeZone, "postgres": frame.Postgres, "serverVersionNum": frame.ServerVersionNum, "pgcrypto": frame.Pgcrypto,
		"readOnly": true, "rolledBack": true, "frameRestored": true, "rawInputRuleIds": input.RawInputRuleIDs, "rawInputDisposition": input.RawInputDisposition, "rows": rows,
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(envelope) != nil {
		return publication, supplementRefusal("remaining envelope")
	}
	payload := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	// Successful hard-link is the publication commit. Cancellation observed before
	// that link refuses output; subsequent cancellation does not retract it.
	return publishPrivateReference(ctx, destination, input.Paths, payload, input.Shape.MaxBytes, nil)
}
