package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
)

// These are reviewed reference-query inputs, not a deployable evaluator release.
// Callers cannot replace expected hashes through environment or query arguments.
const supplementContractSHA = "b59111a99e3fa275c7f550eaacb4f98e0636e7132326d0dc2e5c0a58be2c9af5"
const supplementQuerySHA = "2b2adb28c2537de544ee7a5e543972ef25e771ac73b28313d78c1d20fedc28cd"
const supplementRulesSHA = "e5066d24979fc3e1bc85d9edd19fe8616766d01a0cc02fbf2edc0eae63b3af87"
const supplementSitesSHA = "422d8f45419b308b1c2e11daa7caa4d4a28adde0d036a1117dd285412afa0351"
const supplementCompilerSHA = "9600d455d8e03d14a3c37983ab1ba8654981befe0d39818eb9197e2d4312a8f4"
const supplementCompiledSourceSHA = "816a024518918d4d1fd5f0fd532323e8d3c4458f8905fbdf9af545693520a17a"
const supplementChecksum = "e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960"
const supplementCatalogSHA = "036c92946205f854600cd0ef0e7ebbd1f8bc672c1a5e23d070ef198959abebec"
const supplementSourceContractSHA = "5fed1f43b6475087e16ba4f1ab1db6d6827f508bf9160b13c05e6ef8f6a975e8"

type orderedSupplementInputs struct{ Contract, SQL, Rules, Sites, Compiler, Catalog, SourceContract []byte }

func readOrderedSupplementFile(path string, limit int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 || limit > 32*1024*1024 {
		return nil, supplementRefusal("input bounds")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, supplementRefusal("input open")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(limit) {
		return nil, supplementRefusal("input file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, supplementRefusal("input read")
	}
	return raw, nil
}

func supplementSHA(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func verifyOrderedSupplementInputs(input orderedSupplementInputs) (orderedSupplementShape, error) {
	var empty orderedSupplementShape
	for _, pin := range []struct {
		raw []byte
		sha string
		max int
	}{
		{input.Contract, supplementContractSHA, 1024 * 1024}, {input.SQL, supplementQuerySHA, 1024 * 1024},
		{input.Rules, supplementRulesSHA, 1024 * 1024}, {input.Sites, supplementSitesSHA, 1024 * 1024},
		{input.Compiler, supplementCompilerSHA, 2 * 1024 * 1024}, {input.Catalog, supplementCatalogSHA, 32 * 1024 * 1024},
		{input.SourceContract, supplementSourceContractSHA, 16 * 1024 * 1024},
	} {
		if len(pin.raw) == 0 || len(pin.raw) > pin.max || supplementSHA(pin.raw) != pin.sha {
			return empty, supplementRefusal("artifact pin")
		}
	}
	var c struct {
		Format      string `json:"format"`
		Status      string `json:"status"`
		Predecessor string `json:"predecessorContractFileSHA256"`
		SQLSHA      string `json:"sqlSHA256"`
		RulesSHA    string `json:"rulesSHA256"`
		SitesSHA    string `json:"sitesSHA256"`
		SourcePins  map[string]struct {
			Source     string `json:"sourceSHA256"`
			Definition string `json:"definitionSHA256"`
			Frame      string `json:"frameSHA256"`
		} `json:"sourcePins"`
		Modules          map[string]string            `json:"modules"`
		Checksum         string                       `json:"compilerChecksum"`
		CompiledSource   string                       `json:"compiledSourceSHA256"`
		CompilerArtifact string                       `json:"compilerArtifactSHA256"`
		Catalog          string                       `json:"catalog1FileSHA256"`
		SourceContract   string                       `json:"sourceContractSHA256"`
		Role             string                       `json:"requiredRole"`
		SearchPath       []string                     `json:"requiredSearchPath"`
		TimeZone         string                       `json:"requiredTimeZone"`
		MaxRows          int                          `json:"maxRows"`
		MaxBytes         int                          `json:"maxBytes"`
		CategoryMaxRows  map[string]int               `json:"categoryMaxRows"`
		RuleMaxRows      map[string]int               `json:"ruleMaxRows"`
		Rules            json.RawMessage              `json:"rules"`
		Sites            json.RawMessage              `json:"sites"`
		Fields           map[string]map[string]string `json:"fieldTypes"`
		Obligations      []json.RawMessage            `json:"unresolvedObligations"`
		Gaps             []json.RawMessage            `json:"referenceGaps"`
	}
	if supplementJSON(input.Contract, &c) != nil || c.Format != "ordered-current-supplementary-query-v1" || c.Status != "REFERENCE-CAPTURE-ONLY" || c.Predecessor != "2f93f8390aa4897b7bd6c273ed524f55cf4e360692158e4af4868ddd9bd5bcae" || c.SQLSHA != supplementQuerySHA || c.RulesSHA != supplementRulesSHA || c.SitesSHA != supplementSitesSHA || c.Checksum != supplementChecksum || c.CompiledSource != supplementCompiledSourceSHA || c.CompilerArtifact != supplementCompilerSHA || c.Catalog != supplementCatalogSHA || c.SourceContract != supplementSourceContractSHA || c.Role != "zasp_discovery_authority" || !reflect.DeepEqual(c.SearchPath, []string{"pg_catalog"}) || c.TimeZone != "UTC" || c.MaxRows != 520 || c.MaxBytes != 16777216 || len(c.SourcePins) == 0 || len(c.Modules) == 0 {
		return empty, supplementRefusal("artifact shape")
	}
	// Hash the canonical files as bytes, not by inventing a second JS canonicalizer.
	// Exact contract SHA binds all inline pins/selectors; equality below binds the
	// inline values to those separately pinned canonical files without rewriting.
	for _, pair := range [][2][]byte{{c.Rules, input.Rules}, {c.Sites, input.Sites}} {
		var a, b any
		if supplementJSON(pair[0], &a) != nil || supplementJSON(pair[1], &b) != nil || !reflect.DeepEqual(a, b) {
			return empty, supplementRefusal("artifact linked values")
		}
	}
	var rules []struct {
		ID         string          `json:"id"`
		Kind       string          `json:"kind"`
		Fields     []string        `json:"fields"`
		Namespaces []string        `json:"namespaces"`
		Identities []string        `json:"identities"`
		Selector   json.RawMessage `json:"selector"`
		Predicate  string          `json:"predicate"`
	}
	if supplementJSON(c.Rules, &rules) != nil || len(rules) != 57 {
		return empty, supplementRefusal("artifact rules")
	}
	shape := orderedSupplementShape{Fields: c.Fields, CategoryMaxRows: c.CategoryMaxRows, RuleMaxRows: c.RuleMaxRows, MaxRows: c.MaxRows, MaxBytes: c.MaxBytes}
	for _, r := range rules {
		shape.Rules = append(shape.Rules, orderedSupplementRule{ID: r.ID, Kind: r.Kind, Fields: r.Fields})
	}
	if checkOrderedSupplementRows(shape, []json.RawMessage{}) != nil {
		return empty, supplementRefusal("artifact row contract")
	}
	return shape, nil
}
