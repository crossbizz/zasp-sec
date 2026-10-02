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
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	orderedDirectFrameAcceptancePacketDirectory = "/private/tmp/zasp-ordered-direct-frame-acceptance-packet"
	orderedDirectFrameCompilerArtifactSHA256    = "2ca5e151e304df622167ab5a313135acd28d8a010bc29638dd0e9c83f968395c"
	orderedDirectFrameCompilerChecksum          = "f53752f15df1875e7c08ab6db39e91f08efdf5cf23bb2d6f86015fb22615a214"
	orderedDirectFrameCompiledSourceSHA256      = "e04af1ed6cdaf40add80196b59214cc64f7f126c1d3f64801352a4bc20923b6e"
	orderedDirectFrameSourceContractSHA256      = "02b13c54ff1a543a4ca3a8f43fd2aa71e0334b04efea90afcf61cccf6a74e5cb"
	orderedDirectFrameCoverageSHA256            = "67e214f69821c113b58078b5fc38e7504e33fb5748d7ad56de1fce01f85ed5c4"
	orderedDirectFrameCatalogSHA256             = "9cda05aa8d51f32b0b86d7997930e768b0b050308db26837093ff4fc6f6f35df"
	orderedDirectFrameSQLSHA256                 = "c6270a6104bee35fd0ce5d23c64ef663d3b3538f8029a0e5debf59584d67f3e1"
	orderedDirectFrameInstallSQLSHA256          = "796afffa52713eb05cae14858c0d884372b0f27b88c484e92304394fa573a0f0"
	orderedDirectFrameAdmissionSQLSHA256        = "802427a97982ab56f894207f5581a9e042e5b84a21c15de7c7113f8ebc802c57"
	orderedDirectFramePacketSHA256              = "c936c721c58de952ccd1d55baa89d3381a841ec82a4e7f62b1aadb26d72af4ab"
	orderedDirectFrameSourceBaselinePath        = "/private/tmp/zasp-direct-frame-source-check.pDCNE6/release.json"
)

type orderedDirectFrameAcceptancePacket struct {
	Format          string `json:"format"`
	Status          string `json:"status"`
	Installable     bool   `json:"installable"`
	SourceAuthority string `json:"sourceAuthority"`
	SourcePins      struct {
		CompilerArtifactSHA256         string `json:"compilerArtifactSHA256"`
		CompilerChecksum               string `json:"compilerChecksum"`
		CompiledSourceSHA256           string `json:"compiledSourceSHA256"`
		SourceContractSHA256           string `json:"sourceContractSHA256"`
		CoverageSHA256                 string `json:"coverageSHA256"`
		CatalogSHA256                  string `json:"catalogSHA256"`
		DirectFrameModuleSHA256        string `json:"directFrameModuleSHA256"`
		DirectReferenceModuleSHA256    string `json:"directReferenceModuleSHA256"`
		CatalogModuleSHA256            string `json:"catalogModuleSHA256"`
		TransformReferenceModuleSHA256 string `json:"transformReferenceModuleSHA256"`
		CaptureSQLModuleSHA256         string `json:"captureSQLModuleSHA256"`
		CaseProgramModuleSHA256        string `json:"caseProgramModuleSHA256"`
	} `json:"sourcePins"`
	Limits struct {
		MaxRows         int `json:"maxRows"`
		MaxBytes        int `json:"maxBytes"`
		ObserverSeconds int `json:"observerSeconds"`
		SQLSeconds      int `json:"sqlSeconds"`
		LockSeconds     int `json:"lockSeconds"`
		CleanupSeconds  int `json:"cleanupSeconds"`
	} `json:"limits"`
	Counts struct {
		DirectRules    int `json:"directRules"`
		TransformRules int `json:"transformRules"`
		TotalRules     int `json:"totalRules"`
		DirectRows     int `json:"directRows"`
		TransformRows  int `json:"transformRows"`
		TotalRows      int `json:"totalRows"`
	} `json:"counts"`
	DirectFrame struct {
		Version         int               `json:"version"`
		Installable     bool              `json:"installable"`
		InstallSQL      string            `json:"installSQL"`
		AdmissionSQL    string            `json:"admissionSQL"`
		SQL             string            `json:"sql"`
		SQLSHA256       string            `json:"sqlSHA256"`
		Rules           []json.RawMessage `json:"rules"`
		Adapters        []json.RawMessage `json:"adapters"`
		RuleFieldMatrix []json.RawMessage `json:"ruleFieldMatrix"`
		DescriptorRules []json.RawMessage `json:"descriptorRules"`
		ExpectedRows    []json.RawMessage `json:"expectedRows"`
		Provenance      json.RawMessage   `json:"provenance"`
	} `json:"directFrame"`
	OriginalUniverse struct {
		Rules   int `json:"rules"`
		Queries []struct {
			ID            string  `json:"id"`
			OriginalSQL   string  `json:"originalSQL"`
			DemandSQL     *string `json:"demandSQL"`
			KeysSQL       *string `json:"keysSQL"`
			OriginalFrame string  `json:"originalFrame"`
			KeyFrame      string  `json:"keyFrame"`
			RowCap        int     `json:"rowCap"`
			ByteCap       int     `json:"byteCap"`
		} `json:"queries"`
		TransformRules []struct {
			ID            string `json:"id"`
			OriginalSQL   string `json:"originalSQL"`
			RosterSQL     string `json:"rosterSQL"`
			OriginalFrame string `json:"originalFrame"`
			KeyFrame      string `json:"keyFrame"`
			RowCap        int    `json:"rowCap"`
			ByteCap       int    `json:"byteCap"`
		} `json:"transformRules"`
		QuerySHA256 string `json:"querySHA256"`
		Comparison  string `json:"comparison"`
	} `json:"originalUniverse"`
	Transform struct {
		Rules             []json.RawMessage `json:"rules"`
		ExpectedRows      []json.RawMessage `json:"expectedRows"`
		Provenance        json.RawMessage   `json:"provenance"`
		CompiledSQL       string            `json:"compiledSQL"`
		CompiledSQLSHA256 string            `json:"compiledSQLSHA256"`
		PacketSHA256      string            `json:"packetSHA256"`
		ManifestSHA256    string            `json:"manifestSHA256"`
	} `json:"transform"`
	TransformCorrespondence struct {
		Rules []struct {
			ID         string   `json:"id"`
			Kind       string   `json:"kind"`
			Fields     []string `json:"fields"`
			FieldTypes struct {
				Captured  map[string]string `json:"captured"`
				Candidate map[string]string `json:"candidate"`
			} `json:"fieldTypes"`
			CaptureFields  []string        `json:"captureFields"`
			Residual       json.RawMessage `json:"residual"`
			SourceSite     json.RawMessage `json:"sourceSite"`
			ExecutionFrame string          `json:"executionFrame"`
			CandidateFrame string          `json:"candidateFrame"`
			ExpectedRows   int             `json:"expectedRows"`
			SQL            struct {
				Original           string `json:"original"`
				Candidate          string `json:"candidate"`
				Roster             string `json:"roster"`
				OriginalAggregate  string `json:"originalAggregate"`
				CandidateAggregate string `json:"candidateAggregate"`
			} `json:"sql"`
		} `json:"rules"`
	} `json:"transformCorrespondence"`
	// CaseProgram is the source-derived successor case contract. It is kept as
	// raw JSON at this boundary so the packet reader can refuse an absent or
	// malformed contract without duplicating the JavaScript program's schema.
	// The program records postcondition obligations; the native callback below
	// executes them against the separately source-bound expected facts.
	CaseProgram json.RawMessage `json:"caseProgram"`
}

type orderedDirectFrameCaseProgram struct {
	PoisonCases        []orderedDirectFramePoisonCase    `json:"poisonCases"`
	PropertyCases      []orderedDirectFramePropertyCase  `json:"propertyCases"`
	SemanticProbes     []orderedDirectFrameSemanticProbe `json:"semanticProbes"`
	SuccessorTransform struct {
		Compiled struct {
			SQL string `json:"sql"`
		} `json:"compiled"`
		Rules []orderedDirectFrameTransformRule `json:"rules"`
		Cases []orderedDirectFrameTransformCase `json:"cases"`
	} `json:"successorTransform"`
}

type orderedDirectFrameTransformRule struct {
	ID                    string            `json:"id"`
	Kind                  string            `json:"kind"`
	Fields                []string          `json:"fields"`
	FieldTypes            map[string]string `json:"fieldTypes"`
	SourceSite            json.RawMessage   `json:"sourceSite"`
	ExecutionFrame        string            `json:"executionFrame"`
	CandidateFrame        string            `json:"candidateFrame"`
	OriginalSQL           string            `json:"originalSQL"`
	CandidateSQL          string            `json:"candidateSQL"`
	RosterSQL             string            `json:"rosterSQL"`
	WitnessSQL            string            `json:"witnessSQL"`
	OriginalAggregateSQL  string            `json:"originalAggregateSQL"`
	CandidateAggregateSQL string            `json:"candidateAggregateSQL"`
}

type orderedDirectFramePoisonCase struct {
	ID       string `json:"id"`
	Mutation struct {
		SQL string `json:"sql"`
	} `json:"mutation"`
	PositiveInvocation struct {
		SQL              string `json:"sql"`
		ExpectedSQLState string `json:"expectedSQLState"`
	} `json:"positiveInvocation"`
	ExpectedAdmission bool                      `json:"expectedAdmission"`
	Stages            []orderedDirectFrameStage `json:"stages"`
	Reachability      struct {
		RuleID                string `json:"ruleId"`
		SelectorWitnessSQL    string `json:"selectorWitnessSQL"`
		MinimumRows           int    `json:"minimumRows"`
		SelectedKeyAuthority  string `json:"selectedKeyAuthority"`
		ExpectedKeyComparison string `json:"expectedKeyComparison"`
	} `json:"reachability"`
	Limits struct {
		CaseSeconds    int `json:"caseSeconds"`
		CleanupSeconds int `json:"cleanupSeconds"`
	} `json:"limits"`
}

type orderedDirectFramePropertyCase struct {
	ID       string `json:"id"`
	Mutation struct {
		SQL string `json:"sql"`
	} `json:"mutation"`
	ExpectedAdmission bool `json:"expectedAdmission"`
	CollectorOutcomes []struct {
		Collector        string `json:"collector"`
		Outcome          string `json:"outcome"`
		ExpectedSQLState string `json:"expectedSQLState"`
		Rows             int    `json:"rows"`
	} `json:"collectorOutcomes"`
	Stages       []orderedDirectFrameStage `json:"stages"`
	Reachability struct {
		RuleID                string `json:"ruleId"`
		SelectorWitnessSQL    string `json:"selectorWitnessSQL"`
		MinimumRows           int    `json:"minimumRows"`
		SelectedKeyAuthority  string `json:"selectedKeyAuthority"`
		ExpectedKeyComparison string `json:"expectedKeyComparison"`
	} `json:"reachability"`
	Limits struct {
		CaseSeconds    int `json:"caseSeconds"`
		CleanupSeconds int `json:"cleanupSeconds"`
	} `json:"limits"`
}

type orderedDirectFrameSemanticProbe struct {
	ID               string   `json:"id"`
	SetupSQL         []string `json:"setupSQL"`
	OriginalSQL      string   `json:"originalSQL"`
	AdapterSQL       string   `json:"adapterSQL"`
	ExpectedOutcome  string   `json:"expectedOutcome"`
	ExpectedSQLState *string  `json:"expectedSQLState"`
	Limits           struct {
		CaseSeconds    int `json:"caseSeconds"`
		CleanupSeconds int `json:"cleanupSeconds"`
	} `json:"limits"`
}

type orderedDirectFrameTransformCase struct {
	ID                string                    `json:"id"`
	RuleIDs           []string                  `json:"ruleIDs"`
	MutationSQL       []string                  `json:"mutationSQL"`
	Mode              string                    `json:"mode"`
	ExpectedOutcome   string                    `json:"expectedOutcome"`
	ExpectedSQLState  *string                   `json:"expectedSQLState"`
	MustChange        bool                      `json:"mustChange"`
	ExpectNonstandard bool                      `json:"expectNonstandard"`
	ProbeSQL          string                    `json:"probeSQL"`
	WitnessSQL        string                    `json:"witnessSQL"`
	Stages            []orderedDirectFrameStage `json:"stages"`
	Limits            struct {
		CaseSeconds    int `json:"caseSeconds"`
		CleanupSeconds int `json:"cleanupSeconds"`
	} `json:"limits"`
}

// orderedDirectFrameStage retains every execution obligation carried by the
// accepted program. Fields omitted by the older property cases are resolved
// against the closed ID schema in decodeOrderedDirectFrameCaseProgram rather
// than silently ignored.
type orderedDirectFrameStage struct {
	ID                   string   `json:"id"`
	Action               string   `json:"action"`
	Frame                string   `json:"frame"`
	ExpectedOutcome      string   `json:"expectedOutcome"`
	ExpectedSQLState     *string  `json:"expectedSQLState"`
	ExpectedAdmission    *bool    `json:"expectedAdmission"`
	ExpectedRows         *int     `json:"expectedRows"`
	ForbiddenSQLState    string   `json:"forbiddenSQLState"`
	MinimumRows          *int     `json:"minimumRows"`
	SelectedKeyAuthority string   `json:"selectedKeyAuthority"`
	Comparison           string   `json:"comparison"`
	RuleIDs              []string `json:"ruleIDs"`
	StatementCount       *int     `json:"statementCount"`
	TimeoutSeconds       int      `json:"timeoutSeconds"`
}

func TestP7OrderedCurrentDirectFrameAcceptance(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_DIRECT_FRAME_ACCEPTANCE") != "1" {
		t.Skip("explicit direct-frame native acceptance required")
	}
	packet, err := loadOrderedDirectFrameAcceptancePacket(orderedDirectFrameAcceptancePacketDirectory)
	if err != nil {
		t.Fatal(err)
	}
	validateOrderedDirectFrameAcceptancePacket(t, packet)
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, orderedDirectFrameCatalogCapture(packet), nil)
}

func loadOrderedDirectFrameAcceptancePacket(directory string) (orderedDirectFrameAcceptancePacket, error) {
	var packet orderedDirectFrameAcceptancePacket
	if filepath.IsAbs(directory) == false || filepath.Clean(directory) != directory {
		return packet, errors.New("direct-frame packet directory must be absolute")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "direct-frame-acceptance.json"))
	if err != nil {
		return packet, err
	}
	return decodeOrderedDirectFrameAcceptancePacket(raw, orderedDirectFramePacketSHA256)
}

func decodeOrderedDirectFrameAcceptancePacket(raw []byte, expectedDigest string) (orderedDirectFrameAcceptancePacket, error) {
	var packet orderedDirectFrameAcceptancePacket
	if len(raw) > 32*1024*1024 || orderedDirectFrameDigestBytes(raw) != expectedDigest {
		return packet, errors.New("direct-frame packet authority digest refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&packet); err != nil {
		return packet, fmt.Errorf("direct-frame packet JSON refused: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return packet, errors.New("direct-frame packet trailing JSON refused")
	}
	return packet, nil
}

func validateOrderedDirectFrameAcceptancePacket(t *testing.T, packet orderedDirectFrameAcceptancePacket) {
	t.Helper()
	if packet.Format != "ordered-current-direct-frame-acceptance-v1" || packet.Status != "NATIVE-UNVERIFIED" || packet.Installable || packet.SourceAuthority != "accepted-recovery80-source-2ca-local-parity-only" {
		t.Fatal("direct-frame packet envelope")
	}
	if packet.SourcePins.CompilerArtifactSHA256 != orderedDirectFrameCompilerArtifactSHA256 || packet.SourcePins.CompilerChecksum != orderedDirectFrameCompilerChecksum || packet.SourcePins.CompiledSourceSHA256 != orderedDirectFrameCompiledSourceSHA256 || packet.SourcePins.SourceContractSHA256 != orderedDirectFrameSourceContractSHA256 || packet.SourcePins.CoverageSHA256 != orderedDirectFrameCoverageSHA256 || packet.SourcePins.CatalogSHA256 != orderedDirectFrameCatalogSHA256 {
		t.Fatal("direct-frame source pins")
	}
	if packet.SourcePins.DirectFrameModuleSHA256 != "4c15aee77f9a6d00d8c63a969487dbe9f2d024db0b0f3814aab76424fc9a533b" || packet.SourcePins.DirectReferenceModuleSHA256 != "21a646eb8724ed2a129a6d2f5edab63feabcb5e8764557eabe19c944a9fa09b8" || packet.SourcePins.CatalogModuleSHA256 != "90a2b21bd268ccaacbec3a0e4684486baebb5ca5c2aff2e42e2a69c15170e820" || packet.SourcePins.TransformReferenceModuleSHA256 != "9fdc86ef3e6df47f3668ec49474b288a34f44d3c0f0a8b995989dfa60b29898a" || packet.SourcePins.CaptureSQLModuleSHA256 != "30909caf252a6dfad8a48b0673f782a1a6f07253613f0b847c142ef1aefce3d2" || packet.SourcePins.CaseProgramModuleSHA256 != "e95a1858b8e04473bc80d0d57b3c1f945728d4b223151563b1f206ef90905b8c" {
		t.Fatal("direct-frame module pins")
	}
	if packet.Limits.MaxRows != 1600 || packet.Limits.MaxBytes != 33554432 || packet.Limits.ObserverSeconds != 30 || packet.Limits.SQLSeconds != 10 || packet.Limits.LockSeconds != 3 || packet.Limits.CleanupSeconds != 3 || packet.Counts.DirectRules != 50 || packet.Counts.TransformRules != 13 || packet.Counts.TotalRules != 63 || packet.Counts.DirectRows != 1220 || packet.Counts.TransformRows != 380 || packet.Counts.TotalRows != 1600 || packet.DirectFrame.Version != 1 || packet.DirectFrame.Installable || len(packet.DirectFrame.Rules) != 50 || len(packet.DirectFrame.RuleFieldMatrix) != 50 || len(packet.DirectFrame.DescriptorRules) != 50 || len(packet.DirectFrame.ExpectedRows) != 1220 || len(packet.Transform.Rules) != 13 || len(packet.Transform.ExpectedRows) != 380 || len(packet.DirectFrame.Adapters) != 18 {
		t.Fatal("direct-frame packet counts")
	}
	if digestText(packet.DirectFrame.SQL) != orderedDirectFrameSQLSHA256 || packet.DirectFrame.SQLSHA256 != orderedDirectFrameSQLSHA256 || digestText(packet.DirectFrame.InstallSQL) != orderedDirectFrameInstallSQLSHA256 || digestText(packet.DirectFrame.AdmissionSQL) != orderedDirectFrameAdmissionSQLSHA256 {
		t.Fatal("direct-frame packet SQL pins")
	}
	if packet.Transform.CompiledSQLSHA256 == "" || digestText(packet.Transform.CompiledSQL) != packet.Transform.CompiledSQLSHA256 || len(packet.Transform.ExpectedRows) != 380 {
		t.Fatal("direct-frame transform authority")
	}
	if len(packet.DirectFrame.Provenance) == 0 || len(packet.Transform.Provenance) == 0 {
		t.Fatal("direct-frame provenance closure")
	}
	if len(packet.TransformCorrespondence.Rules) != 13 {
		t.Fatal("direct-frame transform correspondence count")
	}
	seenCorrespondence := make(map[string]bool, 13)
	for _, rule := range packet.TransformCorrespondence.Rules {
		if rule.ID == "" || rule.Kind != "routine" || len(rule.Fields) == 0 || len(rule.FieldTypes.Captured) != len(rule.Fields) || len(rule.FieldTypes.Candidate) != len(rule.Fields) || len(rule.CaptureFields) < len(rule.Fields) || len(rule.Residual) == 0 || len(rule.SourceSite) == 0 || rule.ExecutionFrame != "sourceDiscoveryPublic" || rule.CandidateFrame != "canonicalCollector" || rule.ExpectedRows <= 0 || seenCorrespondence[rule.ID] {
			t.Fatal("direct-frame transform correspondence rule")
		}
		for _, field := range rule.Fields {
			if rule.FieldTypes.Captured[field] == "" || rule.FieldTypes.Candidate[field] == "" {
				t.Fatal("direct-frame transform correspondence field types")
			}
		}
		for _, sqlDigest := range []string{rule.SQL.Original, rule.SQL.Candidate, rule.SQL.Roster, rule.SQL.OriginalAggregate, rule.SQL.CandidateAggregate} {
			if len(sqlDigest) != 64 {
				t.Fatal("direct-frame transform correspondence SQL")
			}
		}
		seenCorrespondence[rule.ID] = true
	}
	if packet.OriginalUniverse.Rules != 50 || len(packet.OriginalUniverse.Queries) != 50 || len(packet.OriginalUniverse.TransformRules) != 13 || packet.OriginalUniverse.Comparison != "exact-unnormalized-source-and-roster-multiset-before-and-after-each-case" || packet.OriginalUniverse.QuerySHA256 == "" {
		t.Fatal("direct-frame original universe closure")
	}
	seenUniverse := make(map[string]bool, len(packet.OriginalUniverse.Queries))
	for _, query := range packet.OriginalUniverse.Queries {
		if query.ID == "" || query.OriginalSQL == "" || query.DemandSQL == nil || query.KeysSQL == nil || *query.DemandSQL == "" || *query.KeysSQL == "" || query.OriginalFrame != "sourceDiscoveryPublic" || query.KeyFrame != "pg_catalog" || query.RowCap <= 0 || query.ByteCap <= 0 || query.RowCap > packet.Limits.MaxRows || query.ByteCap > packet.Limits.MaxBytes || seenUniverse[query.ID] {
			t.Fatal("direct-frame original universe query")
		}
		seenUniverse[query.ID] = true
	}
	for _, query := range packet.OriginalUniverse.TransformRules {
		if query.ID == "" || query.OriginalSQL == "" || query.RosterSQL == "" || query.OriginalFrame != "sourceDiscoveryPublic" || query.KeyFrame != "canonicalCollector" || query.RowCap <= 0 || query.ByteCap <= 0 || query.RowCap > packet.Limits.MaxRows || query.ByteCap > packet.Limits.MaxBytes {
			t.Fatal("direct-frame original universe transform query")
		}
	}
	validateOrderedDirectFrameCaseProgram(t, packet.CaseProgram)
}

func validateOrderedDirectFrameCaseProgram(t *testing.T, raw json.RawMessage) {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("direct-frame case program missing")
	}
	var program struct {
		Format             string `json:"format"`
		Status             string `json:"status"`
		Installable        bool   `json:"installable"`
		RequiredAcceptance struct {
			Rules          int `json:"rules"`
			Rows           int `json:"rows"`
			DirectRules    int `json:"directRules"`
			DirectRows     int `json:"directRows"`
			TransformRules int `json:"transformRules"`
			TransformRows  int `json:"transformRows"`
		} `json:"requiredAcceptance"`
		BlockingDependencies []struct {
			ID       string `json:"id"`
			Required string `json:"required"`
		} `json:"blockingDependencies"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&program); err != nil {
		t.Fatalf("direct-frame case program schema: %v", err)
	}
	if program.Format != "ordered-current-direct-frame-cases-v1" || program.Status != "NATIVE-UNVERIFIED" || program.Installable || program.RequiredAcceptance.Rules != 63 || program.RequiredAcceptance.Rows != 1600 || program.RequiredAcceptance.DirectRules != 50 || program.RequiredAcceptance.DirectRows != 1220 || program.RequiredAcceptance.TransformRules != 13 || program.RequiredAcceptance.TransformRows != 380 {
		t.Fatal("direct-frame case program authority")
	}
	seen := make(map[string]bool, len(program.BlockingDependencies))
	for _, dependency := range program.BlockingDependencies {
		if dependency.ID == "" || dependency.Required == "" || seen[dependency.ID] {
			t.Fatal("direct-frame case program dependency contract")
		}
		seen[dependency.ID] = true
	}
	for _, required := range []string{"independent-expected-rows", "original-universe-query", "successor-installation-proof", "native-execution"} {
		if !seen[required] {
			t.Fatalf("direct-frame case program missing blocking dependency %s", required)
		}
	}
}

func decodeOrderedDirectFrameCaseProgram(raw json.RawMessage) (orderedDirectFrameCaseProgram, error) {
	var program orderedDirectFrameCaseProgram
	if err := json.Unmarshal(raw, &program); err != nil {
		return program, fmt.Errorf("case program decode: %w", err)
	}
	if len(program.PoisonCases) != 18 || len(program.PropertyCases) != 6 || len(program.SemanticProbes) != 22 || len(program.SuccessorTransform.Rules) != 13 || program.SuccessorTransform.Compiled.SQL == "" || len(program.SuccessorTransform.Cases) != 19 {
		return program, fmt.Errorf("case program counts poison=%d property=%d probes=%d transform=%d", len(program.PoisonCases), len(program.PropertyCases), len(program.SemanticProbes), len(program.SuccessorTransform.Cases))
	}
	poisonStages := []string{"capture-pre-state", "mutate", "positive-invocation", "rollback-positive-invocation", "admission-probe", "selector-reachability-probe", "direct-gated-collector", "transform-gated-collector", "assert-noninvocation", "rollback-case", "verify-restoration"}
	for _, item := range program.PoisonCases {
		if len(item.Stages) != len(poisonStages) {
			return program, fmt.Errorf("poison case %s stage count", item.ID)
		}
		for index, stage := range item.Stages {
			if stage.ID != poisonStages[index] {
				return program, fmt.Errorf("poison case %s stage %d=%s", item.ID, index, stage.ID)
			}
		}
	}
	for _, item := range program.PropertyCases {
		propertyStages := []string{"capture-pre-state", "mutate", "admission-probe", "selector-reachability-probe", "direct-gated-collector", "transform-gated-collector", "rollback-case", "verify-restoration"}
		if item.ID == "adapter-acl" || item.ID == "adapter-exact-arity" {
			propertyStages = []string{"capture-pre-state", "mutate", "admission-probe", "selector-reachability-probe", "begin-direct-savepoint", "direct-gated-collector", "rollback-direct-savepoint", "transform-gated-collector", "rollback-case", "verify-restoration"}
		}
		if len(item.Stages) != len(propertyStages) {
			return program, fmt.Errorf("property case %s stage count", item.ID)
		}
		for index, stage := range item.Stages {
			if stage.ID != propertyStages[index] {
				return program, fmt.Errorf("property case %s stage %d=%s", item.ID, index, stage.ID)
			}
		}
	}
	for _, item := range program.SuccessorTransform.Cases {
		mustChange := map[string]bool{
			"owner": true, "acl": true, "replacement": true,
			"saved-missing": true, "saved-null-definition": true, "saved-null-acl": true,
		}
		if item.MustChange != mustChange[item.ID] {
			return program, fmt.Errorf("transform case %s must-change contract", item.ID)
		}
		if err := validateOrderedDirectFrameTransformCaseStages(item, program.SuccessorTransform.Rules); err != nil {
			return program, err
		}
	}
	return program, nil
}

func validateOrderedDirectFrameTransformCaseStages(item orderedDirectFrameTransformCase, rules []orderedDirectFrameTransformRule) error {
	allRuleIDs := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.ID == "" {
			return fmt.Errorf("transform case %s empty rule", item.ID)
		}
		allRuleIDs = append(allRuleIDs, rule.ID)
	}
	ruleIDs := item.RuleIDs
	if len(ruleIDs) == 0 {
		ruleIDs = allRuleIDs
	}
	expected := []string{"capture-pre-state", "apply-mutations"}
	if item.WitnessSQL != "" {
		expected = append(expected, "run-config-witness", "validate-config-witness")
	}
	if item.ProbeSQL != "" {
		expected = append(expected, "begin-probe-error-savepoint", "run-expected-error-probe", "rollback-probe-error-savepoint")
	}
	expected = append(expected, "run-roster-probes")
	if item.ExpectedSQLState != nil && item.ProbeSQL == "" {
		expected = append(expected, "begin-original-error-savepoint", "run-original-aggregates", "rollback-original-error-savepoint", "begin-candidate-error-savepoint", "run-candidate-aggregates", "rollback-candidate-error-savepoint", "compare-error-sqlstates")
	} else {
		expected = append(expected, "run-original-aggregates", "run-candidate-aggregates", "compare-exact-aggregates")
	}
	expected = append(expected, "rollback-case", "verify-restoration")
	if len(item.Stages) != len(expected) {
		return fmt.Errorf("transform case %s stage count", item.ID)
	}
	actions := map[string]string{
		"capture-pre-state": "capture-exact-case-object-and-session-state", "apply-mutations": "execute-fixed-mutationSQL", "run-config-witness": "execute-fixed-witnessSQL", "validate-config-witness": "validate-fixed-config-shape-and-text", "begin-probe-error-savepoint": "begin-savepoint", "run-expected-error-probe": "execute-fixed-probeSQL", "rollback-probe-error-savepoint": "rollback-savepoint", "run-roster-probes": "execute-fixed-rule-rosterSQL", "begin-original-error-savepoint": "begin-savepoint", "run-original-aggregates": "execute-fixed-rule-originalAggregateSQL", "rollback-original-error-savepoint": "rollback-savepoint", "begin-candidate-error-savepoint": "begin-savepoint", "run-candidate-aggregates": "execute-fixed-rule-candidateAggregateSQL", "rollback-candidate-error-savepoint": "rollback-savepoint", "compare-error-sqlstates": "compare-exact-original-candidate-sqlstate", "compare-exact-aggregates": "compare-exact-unnormalized-original-candidate-and-roster", "rollback-case": "rollback-case-transaction", "verify-restoration": "compare-exact-object-session-and-roster-pre-state",
	}
	frames := map[string]string{
		"capture-pre-state": "mutation", "apply-mutations": "mutation", "run-config-witness": "sourceDiscoveryPublic", "validate-config-witness": "sourceDiscoveryPublic", "begin-probe-error-savepoint": "mutation", "run-expected-error-probe": "mutation", "rollback-probe-error-savepoint": "mutation", "run-roster-probes": "canonicalCollector", "begin-original-error-savepoint": "sourceDiscoveryPublic", "run-original-aggregates": "sourceDiscoveryPublic", "rollback-original-error-savepoint": "sourceDiscoveryPublic", "begin-candidate-error-savepoint": "canonicalCollector", "run-candidate-aggregates": "canonicalCollector", "rollback-candidate-error-savepoint": "canonicalCollector", "compare-error-sqlstates": "mutation", "compare-exact-aggregates": "mutation", "rollback-case": "mutation", "verify-restoration": "mutation",
	}
	for index, stage := range item.Stages {
		if stage.ID != expected[index] || stage.Action != actions[stage.ID] || stage.Frame != frames[stage.ID] || stage.ExpectedOutcome == "" || stage.TimeoutSeconds != 10 && stage.TimeoutSeconds != 3 {
			return fmt.Errorf("transform case %s stage %d schema", item.ID, index)
		}
		if stage.TimeoutSeconds == 3 && stage.ID != "rollback-probe-error-savepoint" && stage.ID != "rollback-original-error-savepoint" && stage.ID != "rollback-candidate-error-savepoint" && stage.ID != "rollback-case" && stage.ID != "verify-restoration" {
			return fmt.Errorf("transform case %s stage %s timeout", item.ID, stage.ID)
		}
		switch stage.ID {
		case "apply-mutations":
			if stage.StatementCount == nil || *stage.StatementCount != len(item.MutationSQL) {
				return fmt.Errorf("transform case %s mutation statement count", item.ID)
			}
		case "run-roster-probes", "run-original-aggregates", "run-candidate-aggregates", "compare-error-sqlstates", "compare-exact-aggregates":
			if !reflect.DeepEqual(stage.RuleIDs, ruleIDs) {
				return fmt.Errorf("transform case %s stage %s rule selection", item.ID, stage.ID)
			}
		}
	}
	return nil
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func orderedDirectFrameDigestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func orderedDirectFrameCatalogCapture(packet orderedDirectFrameAcceptancePacket) ordered68CatalogCapture {
	return func(t *testing.T, ctx context.Context, owner *pgx.Conn) bool {
		t.Helper()
		assertOrderedDirectFrameWorkerRelease(t, ctx, owner)
		if err := runOrderedDirectFramePristine(t, ctx, owner, packet); err != nil {
			t.Fatal(err)
		}
		program, err := decodeOrderedDirectFrameCaseProgram(packet.CaseProgram)
		if err != nil {
			t.Fatal(err)
		}
		if err := runOrderedDirectFrameProgramCases(t, ctx, owner, packet, program); err != nil {
			t.Fatal(err)
		}
		t.Log("direct-frame pristine and bounded mutation comparisons passed; direct=1220 transform=380 total=1600")
		return true
	}
}

type orderedDirectFrameQueryer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type orderedDirectFrameState struct {
	Role       string
	SearchPath string
	TimeZone   string
	ReadOnly   string
	Objects    string
}

const orderedDirectFrameStateSQL = `
SELECT current_user,
       current_setting('search_path'),
       current_setting('TimeZone'),
       current_setting('transaction_read_only'),
       COALESCE((SELECT jsonb_agg(to_jsonb(objects) ORDER BY objects.identity)::text
                 FROM (SELECT p.oid::regprocedure::text AS identity,
                              p.proowner::regrole::text AS owner,
                              COALESCE(p.proacl::text,'') AS acl,
                              COALESCE(p.proconfig::text,'') AS config,
                              p.prosrc AS body,
                              p.proargtypes::text AS argument_types
                         FROM pg_catalog.pg_proc p
                         JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                        WHERE n.nspname='zasp_authorization80_ordered_current'
                        ORDER BY identity) objects), '[]')`

func captureOrderedDirectFrameState(ctx context.Context, queryer orderedDirectFrameQueryer) (orderedDirectFrameState, error) {
	var state orderedDirectFrameState
	err := queryer.QueryRow(ctx, orderedDirectFrameStateSQL).Scan(&state.Role, &state.SearchPath, &state.TimeZone, &state.ReadOnly, &state.Objects)
	return state, err
}

func captureOrderedDirectFrameOriginalUniverse(ctx context.Context, queryer orderedDirectFrameQueryer, packet orderedDirectFrameAcceptancePacket) ([][]byte, error) {
	if packet.OriginalUniverse.Rules != 50 || len(packet.OriginalUniverse.Queries) != 50 {
		return nil, errors.New("original universe query bounds")
	}
	rowsByRule := make([][]byte, 0, packet.OriginalUniverse.Rules*3+13*2)
	for _, query := range packet.OriginalUniverse.Queries {
		if err := setOrderedDirectFrameQueryFrame(ctx, queryer, "pg_catalog, public"); err != nil {
			return nil, fmt.Errorf("original universe %s source frame: %w", query.ID, err)
		}
		original, err := collectOrderedDirectFrameQueryRowsBounded(ctx, queryer, query.RowCap, query.ByteCap, query.OriginalSQL)
		if err != nil {
			return nil, fmt.Errorf("original universe %s original: %w", query.ID, err)
		}
		tagged, err := tagOrderedDirectFrameUniverseRows(query.ID, "original", original)
		if err != nil {
			return nil, err
		}
		rowsByRule = append(rowsByRule, tagged...)
		demand, err := collectOrderedDirectFrameQueryRowsBounded(ctx, queryer, query.RowCap, query.ByteCap, *query.DemandSQL)
		if err != nil {
			return nil, fmt.Errorf("original universe %s demand: %w", query.ID, err)
		}
		tagged, err = tagOrderedDirectFrameUniverseRows(query.ID, "demand", demand)
		if err != nil {
			return nil, err
		}
		rowsByRule = append(rowsByRule, tagged...)
		demandJSON, err := json.Marshal(rawRowsAsJSON(demand))
		if err != nil {
			return nil, fmt.Errorf("original universe %s demand encode: %w", query.ID, err)
		}
		if err := setOrderedDirectFrameQueryFrame(ctx, queryer, "pg_catalog"); err != nil {
			return nil, fmt.Errorf("original universe %s key frame: %w", query.ID, err)
		}
		keys, err := collectOrderedDirectFrameQueryRowsBounded(ctx, queryer, query.RowCap, query.ByteCap, *query.KeysSQL, string(demandJSON))
		if err != nil {
			return nil, fmt.Errorf("original universe %s keys: %w", query.ID, err)
		}
		if err := assertOrderedDirectFrameHandleLinkage(query.ID, demand, keys, original); err != nil {
			return nil, err
		}
		tagged, err = tagOrderedDirectFrameUniverseRows(query.ID, "keys", keys)
		if err != nil {
			return nil, err
		}
		rowsByRule = append(rowsByRule, tagged...)
	}
	for _, query := range packet.OriginalUniverse.TransformRules {
		if err := setOrderedDirectFrameQueryFrame(ctx, queryer, "pg_catalog, public"); err != nil {
			return nil, fmt.Errorf("original universe %s transform source frame: %w", query.ID, err)
		}
		original, err := collectOrderedDirectFrameTransformRowsBounded(ctx, queryer, query.RowCap, query.ByteCap, query.OriginalSQL, 3)
		if err != nil {
			return nil, fmt.Errorf("original universe %s transform original: %w", query.ID, err)
		}
		tagged, err := tagOrderedDirectFrameUniverseRows(query.ID, "transform-original", original)
		if err != nil {
			return nil, err
		}
		rowsByRule = append(rowsByRule, tagged...)
		if err := setOrderedDirectFrameQueryFrame(ctx, queryer, "pg_catalog"); err != nil {
			return nil, fmt.Errorf("original universe %s transform roster frame: %w", query.ID, err)
		}
		roster, err := collectOrderedDirectFrameTransformRowsBounded(ctx, queryer, query.RowCap, query.ByteCap, query.RosterSQL, 2)
		if err != nil {
			return nil, fmt.Errorf("original universe %s transform roster: %w", query.ID, err)
		}
		if err := assertOrderedDirectFrameTransformLinkage(query.ID, original, roster); err != nil {
			return nil, err
		}
		tagged, err = tagOrderedDirectFrameUniverseRows(query.ID, "transform-roster", roster)
		if err != nil {
			return nil, err
		}
		rowsByRule = append(rowsByRule, tagged...)
	}
	return rowsByRule, nil
}

func assertOrderedDirectFrameHandleLinkage(id string, demand, keys, original [][]byte) error {
	type linkedRow struct {
		Handle *string         `json:"handle"`
		Fact   json.RawMessage `json:"fact"`
	}
	read := func(phase string, rows [][]byte, requireFact bool) (map[string]int, error) {
		counts := make(map[string]int, len(rows))
		for _, raw := range rows {
			var row linkedRow
			if err := json.Unmarshal(raw, &row); err != nil || row.Handle == nil || *row.Handle == "" {
				return nil, fmt.Errorf("original universe %s %s handle linkage", id, phase)
			}
			if requireFact && (len(row.Fact) == 0 || string(row.Fact) == "null") {
				return nil, fmt.Errorf("original universe %s %s fact linkage", id, phase)
			}
			counts[*row.Handle]++
		}
		return counts, nil
	}
	demandHandles, err := read("demand", demand, false)
	if err != nil {
		return err
	}
	keyHandles, err := read("keys", keys, false)
	if err != nil {
		return err
	}
	originalHandles, err := read("original", original, true)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(demandHandles, keyHandles) || !reflect.DeepEqual(demandHandles, originalHandles) {
		return fmt.Errorf("original universe %s demand/key/fact handle linkage mismatch", id)
	}
	return nil
}

func setOrderedDirectFrameQueryFrame(ctx context.Context, queryer orderedDirectFrameQueryer, searchPath string) error {
	_, err := queryer.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=`+searchPath+`; SET LOCAL TIME ZONE 'UTC'`)
	return err
}

func collectOrderedDirectFrameQueryRowsBounded(ctx context.Context, queryer orderedDirectFrameQueryer, maxRows, maxBytes int, sql string, args ...any) ([][]byte, error) {
	rows, err := queryer.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([][]byte, 0)
	bytesRead := 0
	for rows.Next() {
		if maxRows > 0 && len(values) >= maxRows {
			return nil, errors.New("bounded query row limit exceeded")
		}
		var value []byte
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		bytesRead += len(value)
		if maxBytes > 0 && bytesRead > maxBytes {
			return nil, errors.New("bounded query byte limit exceeded")
		}
		values = append(values, append([]byte(nil), value...))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func collectOrderedDirectFrameTransformRowsBounded(ctx context.Context, queryer orderedDirectFrameQueryer, maxRows, maxBytes int, sql string, columns int) ([][]byte, error) {
	rows, err := queryer.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([][]byte, 0)
	bytesRead := 0
	for rows.Next() {
		if maxRows > 0 && len(values) >= maxRows {
			return nil, errors.New("bounded transform query row limit exceeded")
		}
		var encoded []byte
		switch columns {
		case 3:
			var objectOID, line string
			var fact json.RawMessage
			if err := rows.Scan(&objectOID, &fact, &line); err != nil {
				return nil, err
			}
			encoded, err = encodeOrderedDirectFrameTransformOriginalRow(objectOID, fact, line)
		case 2:
			var objectOID, identity string
			if err := rows.Scan(&objectOID, &identity); err != nil {
				return nil, err
			}
			encoded, err = encodeOrderedDirectFrameTransformRosterRow(objectOID, identity)
		default:
			return nil, fmt.Errorf("transform query columns got=%d want=2-or-3", columns)
		}
		if err != nil {
			return nil, err
		}
		bytesRead += len(encoded)
		if maxBytes > 0 && bytesRead > maxBytes {
			return nil, errors.New("bounded transform query byte limit exceeded")
		}
		values = append(values, encoded)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

// The transform rows are deliberately scanned into their PostgreSQL wire
// destinations. In particular fact stays json.RawMessage: decoding JSONB into
// any would round adjacent integers through float64 before comparison.
func encodeOrderedDirectFrameTransformOriginalRow(objectOID string, fact json.RawMessage, line string) ([]byte, error) {
	if objectOID == "" || line == "" || !json.Valid(fact) {
		return nil, errors.New("transform original typed row")
	}
	return json.Marshal([]any{objectOID, fact, line})
}

func encodeOrderedDirectFrameTransformRosterRow(objectOID, identity string) ([]byte, error) {
	if objectOID == "" || identity == "" {
		return nil, errors.New("transform roster typed row")
	}
	return json.Marshal([]string{objectOID, identity})
}

func assertOrderedDirectFrameTransformLinkage(id string, original, roster [][]byte) error {
	originalIDs := make(map[string]bool, len(original))
	for _, raw := range original {
		var row []json.RawMessage
		if err := json.Unmarshal(raw, &row); err != nil || len(row) != 3 {
			return fmt.Errorf("original universe %s transform original row shape", id)
		}
		var objectID string
		if err := json.Unmarshal(row[0], &objectID); err != nil || objectID == "" || originalIDs[objectID] {
			return fmt.Errorf("original universe %s transform original object linkage", id)
		}
		originalIDs[objectID] = true
	}
	rosterIDs := make(map[string]string, len(roster))
	for _, raw := range roster {
		var row []json.RawMessage
		if err := json.Unmarshal(raw, &row); err != nil || len(row) != 2 {
			return fmt.Errorf("original universe %s transform roster row shape", id)
		}
		var objectID, identity string
		if err := json.Unmarshal(row[0], &objectID); err != nil || objectID == "" {
			return fmt.Errorf("original universe %s transform roster identity linkage", id)
		}
		if err := json.Unmarshal(row[1], &identity); err != nil || identity == "" || rosterIDs[objectID] != "" {
			return fmt.Errorf("original universe %s transform roster identity linkage", id)
		}
		rosterIDs[objectID] = identity
	}
	if !reflect.DeepEqual(originalIDs, boolKeysFromStringMap(rosterIDs)) {
		return fmt.Errorf("original universe %s transform object_oid roster linkage mismatch", id)
	}
	return nil
}

func boolKeysFromStringMap(values map[string]string) map[string]bool {
	result := make(map[string]bool, len(values))
	for key := range values {
		result[key] = true
	}
	return result
}

func rawRowsAsJSON(rows [][]byte) []json.RawMessage {
	values := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		values = append(values, json.RawMessage(row))
	}
	return values
}

func tagOrderedDirectFrameUniverseRows(id, phase string, rows [][]byte) ([][]byte, error) {
	tagged := make([][]byte, 0, len(rows))
	for _, row := range rows {
		value, err := json.Marshal(struct {
			ID    string          `json:"id"`
			Phase string          `json:"phase"`
			Row   json.RawMessage `json:"row"`
		}{ID: id, Phase: phase, Row: json.RawMessage(row)})
		if err != nil {
			return nil, fmt.Errorf("tag %s/%s: %w", id, phase, err)
		}
		tagged = append(tagged, value)
	}
	return tagged, nil
}

func captureOrderedDirectFrameOriginalUniverseSnapshot(ctx context.Context, owner *pgx.Conn, packet orderedDirectFrameAcceptancePacket) ([][]byte, error) {
	tx, err := owner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(packet.Limits.CleanupSeconds)*time.Second)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return rollbackErr
		}
		return nil
	}
	if _, err = tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=pg_catalog, public; SET LOCAL TIME ZONE 'UTC'`); err != nil {
		_ = cleanup()
		return nil, err
	}
	values, err := captureOrderedDirectFrameOriginalUniverse(ctx, tx, packet)
	if rollbackErr := cleanup(); err == nil && rollbackErr != nil {
		err = rollbackErr
	}
	return values, err
}

func equalOrderedDirectFrameJSONMultiset(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	used := make([]bool, len(right))
	for _, candidate := range left {
		found := false
		for index, value := range right {
			if !used[index] && jsonEqual(candidate, value) {
				used[index] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func beginOrderedDirectFrameCase(ctx context.Context, owner *pgx.Conn, packet orderedDirectFrameAcceptancePacket) (pgx.Tx, orderedDirectFrameState, error) {
	before, err := captureOrderedDirectFrameState(ctx, owner)
	if err != nil {
		return nil, orderedDirectFrameState{}, fmt.Errorf("capture pre-case state: %w", err)
	}
	tx, err := owner.Begin(ctx)
	if err != nil {
		return nil, orderedDirectFrameState{}, err
	}
	rollback := func() error {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Duration(packet.Limits.CleanupSeconds)*time.Second)
		defer cleanupCancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return rollbackErr
		}
		return nil
	}
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL ROLE zasp_test; SET LOCAL search_path=pg_catalog, public; SET LOCAL TIME ZONE 'UTC'`); err != nil {
		_ = rollback()
		return nil, orderedDirectFrameState{}, fmt.Errorf("source frame: %w", err)
	}
	if _, err = tx.Exec(ctx, packet.DirectFrame.InstallSQL); err != nil {
		_ = rollback()
		return nil, orderedDirectFrameState{}, fmt.Errorf("adapter installation: %w", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=pg_catalog`); err != nil {
		_ = rollback()
		return nil, orderedDirectFrameState{}, fmt.Errorf("canonical collector frame: %w", err)
	}
	return tx, before, nil
}

// captureOrderedDirectFrameInstalledUniverse runs the source-frame snapshot
// after the adapter DDL has been installed, while the case transaction is
// still open. The adapter namespace is intentionally outside the selected
// source universe; this proves installation did not alter the original
// demand/key/fact or transform roster inputs before admission/mutation.
func captureOrderedDirectFrameInstalledUniverse(ctx context.Context, tx pgx.Tx, packet orderedDirectFrameAcceptancePacket) ([][]byte, error) {
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=pg_catalog, public; SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return nil, err
	}
	values, err := captureOrderedDirectFrameOriginalUniverse(ctx, tx, packet)
	if _, restoreErr := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=pg_catalog`); err == nil && restoreErr != nil {
		err = restoreErr
	}
	return values, err
}

func finishOrderedDirectFrameCase(ctx context.Context, owner *pgx.Conn, tx pgx.Tx, before orderedDirectFrameState, packet orderedDirectFrameAcceptancePacket) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(packet.Limits.CleanupSeconds)*time.Second)
	defer cancel()
	if err := rollbackOrderedDirectFrameCase(tx, packet); err != nil {
		return fmt.Errorf("bounded rollback: %w", err)
	}
	after, err := captureOrderedDirectFrameState(cleanupCtx, owner)
	if err != nil {
		return fmt.Errorf("capture post-case state: %w", err)
	}
	if !reflect.DeepEqual(before, after) {
		return fmt.Errorf("exact restoration mismatch: before=%+v after=%+v", before, after)
	}
	return nil
}

func rollbackOrderedDirectFrameCase(tx pgx.Tx, packet orderedDirectFrameAcceptancePacket) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(packet.Limits.CleanupSeconds)*time.Second)
	defer cancel()
	if err := tx.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func runOrderedDirectFramePristine(t *testing.T, parent context.Context, owner *pgx.Conn, packet orderedDirectFrameAcceptancePacket) error {
	ctx, cancel := context.WithTimeout(parent, time.Duration(packet.Limits.ObserverSeconds)*time.Second)
	defer cancel()
	beforeUniverse, err := captureOrderedDirectFrameOriginalUniverseSnapshot(ctx, owner, packet)
	if err != nil {
		return err
	}
	tx, before, err := beginOrderedDirectFrameCase(ctx, owner, packet)
	if err != nil {
		return fmt.Errorf("pristine setup: %w", err)
	}
	installedUniverse, err := captureOrderedDirectFrameInstalledUniverse(ctx, tx, packet)
	if err != nil {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return fmt.Errorf("pristine original universe after installation: %w", err)
	}
	if !equalOrderedDirectFrameJSONMultiset(beforeUniverse, installedUniverse) {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return errors.New("pristine original universe changed after installation")
	}
	var admitted bool
	if err = tx.QueryRow(ctx, packet.DirectFrame.AdmissionSQL).Scan(&admitted); err != nil || !admitted {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return fmt.Errorf("pristine direct admission: admitted=%t err=%v", admitted, err)
	}
	if err = compareOrderedDirectFrameRows(ctx, tx, packet.DirectFrame.SQL, packet.DirectFrame.ExpectedRows, packet.Limits.MaxBytes); err != nil {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return fmt.Errorf("pristine direct collector: %w", err)
	}
	if err = compareOrderedDirectFrameTransformRows(ctx, tx, packet.Transform.CompiledSQL, packet.Transform.ExpectedRows, packet.Limits.MaxBytes); err != nil {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return fmt.Errorf("pristine transform collector: %w", err)
	}
	if err = finishOrderedDirectFrameCase(ctx, owner, tx, before, packet); err != nil {
		return err
	}
	afterUniverse, err := captureOrderedDirectFrameOriginalUniverseSnapshot(ctx, owner, packet)
	if err != nil {
		return fmt.Errorf("pristine original universe after snapshot: %w", err)
	}
	if !equalOrderedDirectFrameJSONMultiset(beforeUniverse, afterUniverse) {
		return errors.New("pristine original universe changed")
	}
	t.Log("direct-frame pristine comparison passed: direct=1220 transform=380")
	return nil
}

type orderedDirectFrameQueryOutcome struct {
	Rows [][]byte
	Code string
}

func orderedDirectFrameErrorCode(err error, fallback string) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return fallback
}

func queryOrderedDirectFrameOutcome(ctx context.Context, tx orderedDirectFrameQueryer, sql string) orderedDirectFrameQueryOutcome {
	rows, err := tx.Query(ctx, sql)
	if err != nil {
		return orderedDirectFrameQueryOutcome{Code: orderedDirectFrameErrorCode(err, "client-error")}
	}
	defer rows.Close()
	out := orderedDirectFrameQueryOutcome{}
	for rows.Next() {
		values, valueErr := rows.Values()
		if valueErr != nil {
			out.Code = orderedDirectFrameErrorCode(valueErr, "row-error")
			return out
		}
		for index, value := range values {
			if raw, ok := value.([]byte); ok {
				var decoded any
				if json.Unmarshal(raw, &decoded) == nil {
					values[index] = json.RawMessage(raw)
				}
			}
		}
		encoded, encodeErr := json.Marshal(values)
		if encodeErr != nil {
			out.Code = "encode-error"
			return out
		}
		out.Rows = append(out.Rows, encoded)
	}
	if err := rows.Err(); err != nil {
		out.Code = orderedDirectFrameErrorCode(err, "row-error")
	}
	return out
}

func queryOrderedDirectFrameOutcomeInSavepoint(ctx context.Context, tx pgx.Tx, name, sql string) (orderedDirectFrameQueryOutcome, error) {
	if _, err := tx.Exec(ctx, "SAVEPOINT "+name); err != nil {
		return orderedDirectFrameQueryOutcome{}, err
	}
	outcome := queryOrderedDirectFrameOutcome(ctx, tx, sql)
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+name); err != nil {
		return outcome, err
	}
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT "+name); err != nil {
		return outcome, err
	}
	return outcome, nil
}

func setOrderedDirectFrameRole(ctx context.Context, tx pgx.Tx, role, searchPath string) error {
	_, err := tx.Exec(ctx, `SET LOCAL ROLE `+role+`; SET LOCAL search_path=`+searchPath+`; SET LOCAL TIME ZONE 'UTC'`)
	return err
}

func assertOrderedDirectFrameOutcomeEqual(left, right orderedDirectFrameQueryOutcome, expectedCode *string) error {
	if expectedCode != nil {
		if left.Code != *expectedCode || right.Code != *expectedCode {
			return fmt.Errorf("expected SQLSTATE %s, original=%s adapter=%s", *expectedCode, left.Code, right.Code)
		}
		return nil
	}
	if left.Code != right.Code || left.Code != "" {
		return fmt.Errorf("probe error mismatch original=%s adapter=%s", left.Code, right.Code)
	}
	if len(left.Rows) != len(right.Rows) {
		return fmt.Errorf("probe row count mismatch original=%d adapter=%d", len(left.Rows), len(right.Rows))
	}
	for index := range left.Rows {
		if !jsonEqual(left.Rows[index], right.Rows[index]) {
			return fmt.Errorf("probe value mismatch at row %d: %s", index, orderedDirectFrameMismatchSummary(left.Rows[index], right.Rows[index]))
		}
	}
	return nil
}

func orderedDirectFrameMismatchSummary(left, right []byte) string {
	offset := 0
	for offset < len(left) && offset < len(right) && left[offset] == right[offset] {
		offset++
	}
	start := offset - 96
	if start < 0 {
		start = 0
	}
	leftEnd, rightEnd := start+256, start+256
	if leftEnd > len(left) {
		leftEnd = len(left)
	}
	if rightEnd > len(right) {
		rightEnd = len(right)
	}
	return fmt.Sprintf("offset=%d left_sha256=%s right_sha256=%s left=%q right=%q", offset, orderedDirectFrameDigestBytes(left), orderedDirectFrameDigestBytes(right), left[start:leftEnd], right[start:rightEnd])
}

func runOrderedDirectFrameGatedCollectorZero(ctx context.Context, tx pgx.Tx, sql string) error {
	rows, err := tx.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	bytesRead := 0
	for rows.Next() {
		count++
		values, valueErr := rows.Values()
		if valueErr != nil {
			return valueErr
		}
		encoded, encodeErr := json.Marshal(values)
		if encodeErr != nil {
			return encodeErr
		}
		bytesRead += len(encoded)
		if count > 1600 || bytesRead > 33554432 {
			return errors.New("gated collector bounds exceeded")
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("gated collector returned %d rows", count)
	}
	return nil
}

func runOrderedDirectFrameGatedCollectorOutcome(ctx context.Context, tx pgx.Tx, sql, expectedSQLState string) error {
	if expectedSQLState == "" {
		return runOrderedDirectFrameGatedCollectorZero(ctx, tx, sql)
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT ordered_direct_frame_gated_collector"); err != nil {
		return err
	}
	outcome := queryOrderedDirectFrameOutcome(ctx, tx, sql)
	if outcome.Code != expectedSQLState {
		return fmt.Errorf("gated collector SQLSTATE=%s want=%s", outcome.Code, expectedSQLState)
	}
	if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT ordered_direct_frame_gated_collector"); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "RELEASE SAVEPOINT ordered_direct_frame_gated_collector")
	return err
}

func assertOrderedDirectFrameReachability(ctx context.Context, tx pgx.Tx, packet orderedDirectFrameAcceptancePacket, ruleID, witnessSQL string, minimumRows int) error {
	want := make(map[string]bool)
	for _, raw := range packet.DirectFrame.ExpectedRows {
		var row struct {
			Identity string `json:"identity"`
			Source   struct {
				RuleID string `json:"ruleId"`
			} `json:"source"`
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		if row.Source.RuleID == ruleID {
			want[row.Identity] = true
		}
	}
	if len(want) < minimumRows {
		return fmt.Errorf("expected canonical key set too small: %d", len(want))
	}
	rows, err := tx.Query(ctx, witnessSQL)
	if err != nil {
		return err
	}
	defer rows.Close()
	got := make(map[string]bool)
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			return err
		}
		got[identity] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("canonical key count got=%d want=%d", len(got), len(want))
	}
	for identity := range want {
		if !got[identity] {
			return fmt.Errorf("canonical key missing %s", identity)
		}
	}
	for identity := range got {
		if !want[identity] {
			return fmt.Errorf("canonical key unexpected %s", identity)
		}
	}
	return nil
}

func runOrderedDirectFrameProgramCase(t *testing.T, parent context.Context, owner *pgx.Conn, packet orderedDirectFrameAcceptancePacket, caseID string, mutationSQL []string, positiveSQL string, positiveCode string, expectedAdmission bool, directCollectorExpectedSQLState, reachabilityRuleID, reachabilitySQL string, reachabilityMinimum int, probe *orderedDirectFrameSemanticProbe) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	beforeUniverse, err := captureOrderedDirectFrameOriginalUniverseSnapshot(ctx, owner, packet)
	if err != nil {
		return err
	}
	tx, before, err := beginOrderedDirectFrameCase(ctx, owner, packet)
	if err != nil {
		return err
	}
	installedUniverse, err := captureOrderedDirectFrameInstalledUniverse(ctx, tx, packet)
	if err != nil {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return fmt.Errorf("%s original universe after installation: %w", caseID, err)
	}
	if !equalOrderedDirectFrameJSONMultiset(beforeUniverse, installedUniverse) {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return fmt.Errorf("%s original universe changed after installation", caseID)
	}
	finished := false
	defer func() {
		if !finished {
			if rollbackErr := rollbackOrderedDirectFrameCase(tx, packet); rollbackErr != nil {
				t.Errorf("%s bounded failure cleanup: %v", caseID, rollbackErr)
			}
		}
	}()
	if err := setOrderedDirectFrameRole(ctx, tx, "zasp_test", "pg_catalog, public"); err != nil {
		return fmt.Errorf("%s mutation frame: %w", caseID, err)
	}
	for _, statement := range mutationSQL {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("%s mutation: %w", caseID, err)
		}
	}
	if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog, public"); err != nil {
		return fmt.Errorf("%s source frame: %w", caseID, err)
	}
	if positiveSQL != "" {
		if _, err := tx.Exec(ctx, "SAVEPOINT ordered_direct_frame_positive"); err != nil {
			return err
		}
		positive := queryOrderedDirectFrameOutcome(ctx, tx, positiveSQL)
		if positive.Code != positiveCode {
			return fmt.Errorf("%s positive invocation SQLSTATE=%s want=%s", caseID, positive.Code, positiveCode)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT ordered_direct_frame_positive"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT ordered_direct_frame_positive"); err != nil {
			return err
		}
	}
	if probe != nil {
		if err := setOrderedDirectFrameRole(ctx, tx, "zasp_test", "pg_catalog, public"); err != nil {
			return fmt.Errorf("%s setup frame: %w", caseID, err)
		}
		for _, statement := range probe.SetupSQL {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return fmt.Errorf("%s setup: %w", caseID, err)
			}
		}
		if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog, public"); err != nil {
			return fmt.Errorf("%s probe source frame: %w", caseID, err)
		}
		original, err := queryOrderedDirectFrameOutcomeInSavepoint(ctx, tx, "ordered_direct_frame_original_probe", probe.OriginalSQL)
		if err != nil {
			return fmt.Errorf("%s original probe: %w", caseID, err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL search_path=pg_catalog`); err != nil {
			return err
		}
		adapter, err := queryOrderedDirectFrameOutcomeInSavepoint(ctx, tx, "ordered_direct_frame_adapter_probe", probe.AdapterSQL)
		if err != nil {
			return fmt.Errorf("%s adapter probe: %w", caseID, err)
		}
		if err := assertOrderedDirectFrameOutcomeEqual(original, adapter, probe.ExpectedSQLState); err != nil {
			return fmt.Errorf("%s semantic probe: %w", caseID, err)
		}
	}
	if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog"); err != nil {
		return fmt.Errorf("%s canonical collector frame: %w", caseID, err)
	}
	var admitted bool
	if err := tx.QueryRow(ctx, packet.DirectFrame.AdmissionSQL).Scan(&admitted); err != nil {
		return fmt.Errorf("%s admission: %w", caseID, err)
	}
	if admitted != expectedAdmission {
		return fmt.Errorf("%s admission=%t want=%t", caseID, admitted, expectedAdmission)
	}
	if reachabilitySQL != "" {
		if err := assertOrderedDirectFrameReachability(ctx, tx, packet, reachabilityRuleID, reachabilitySQL, reachabilityMinimum); err != nil {
			return fmt.Errorf("%s reachability: %w", caseID, err)
		}
	}
	if !admitted {
		if err := runOrderedDirectFrameGatedCollectorOutcome(ctx, tx, packet.DirectFrame.SQL, directCollectorExpectedSQLState); err != nil {
			return fmt.Errorf("%s direct gated collector: %w", caseID, err)
		}
		if err := runOrderedDirectFrameGatedCollectorZero(ctx, tx, packet.Transform.CompiledSQL); err != nil {
			return fmt.Errorf("%s transform gated collector: %w", caseID, err)
		}
	}
	if err := finishOrderedDirectFrameCase(ctx, owner, tx, before, packet); err != nil {
		return err
	}
	afterUniverse, err := captureOrderedDirectFrameOriginalUniverseSnapshot(ctx, owner, packet)
	if err != nil {
		return err
	}
	if !equalOrderedDirectFrameJSONMultiset(beforeUniverse, afterUniverse) {
		return fmt.Errorf("%s original universe changed", caseID)
	}
	finished = true
	t.Logf("direct-frame program case %s passed", caseID)
	return nil
}

func runOrderedDirectFrameProgramCases(t *testing.T, parent context.Context, owner *pgx.Conn, packet orderedDirectFrameAcceptancePacket, program orderedDirectFrameCaseProgram) error {
	for _, item := range program.PoisonCases {
		if err := runOrderedDirectFrameProgramCase(t, parent, owner, packet, item.ID, []string{item.Mutation.SQL}, item.PositiveInvocation.SQL, item.PositiveInvocation.ExpectedSQLState, item.ExpectedAdmission, "", item.Reachability.RuleID, item.Reachability.SelectorWitnessSQL, item.Reachability.MinimumRows, nil); err != nil {
			return err
		}
	}
	for _, item := range program.PropertyCases {
		directExpectedSQLState := ""
		for _, outcome := range item.CollectorOutcomes {
			if outcome.Collector == "direct" && outcome.Outcome == "error" {
				directExpectedSQLState = outcome.ExpectedSQLState
			}
		}
		if err := runOrderedDirectFrameProgramCase(t, parent, owner, packet, item.ID, []string{item.Mutation.SQL}, "", "", item.ExpectedAdmission, directExpectedSQLState, item.Reachability.RuleID, item.Reachability.SelectorWitnessSQL, item.Reachability.MinimumRows, nil); err != nil {
			return err
		}
	}
	for _, item := range program.SemanticProbes {
		if err := runOrderedDirectFrameProgramCase(t, parent, owner, packet, item.ID, nil, "", "", true, "", "", "", 0, &item); err != nil {
			return err
		}
	}
	for _, item := range program.SuccessorTransform.Cases {
		if err := runOrderedDirectFrameTransformCase(t, parent, owner, packet, item, program.SuccessorTransform.Rules); err != nil {
			return err
		}
	}
	return nil
}

func orderedDirectFrameAggregateExpectedSQLState(item orderedDirectFrameTransformCase) *string {
	if item.ExpectedOutcome == "error" && item.ProbeSQL == "" {
		return item.ExpectedSQLState
	}
	return nil
}

func orderedDirectFrameRequiresTransformLinkage(item orderedDirectFrameTransformCase) bool {
	return orderedDirectFrameAggregateExpectedSQLState(item) == nil
}

func runOrderedDirectFrameTransformCase(t *testing.T, parent context.Context, owner *pgx.Conn, packet orderedDirectFrameAcceptancePacket, item orderedDirectFrameTransformCase, rules []orderedDirectFrameTransformRule) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	beforeUniverse, err := captureOrderedDirectFrameOriginalUniverseSnapshot(ctx, owner, packet)
	if err != nil {
		return err
	}
	tx, before, err := beginOrderedDirectFrameCase(ctx, owner, packet)
	if err != nil {
		return err
	}
	installedUniverse, err := captureOrderedDirectFrameInstalledUniverse(ctx, tx, packet)
	if err != nil {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return fmt.Errorf("transform:%s original universe after installation: %w", item.ID, err)
	}
	if !equalOrderedDirectFrameJSONMultiset(beforeUniverse, installedUniverse) {
		_ = rollbackOrderedDirectFrameCase(tx, packet)
		return fmt.Errorf("transform:%s original universe changed after installation", item.ID)
	}
	finished := false
	defer func() {
		if !finished {
			if rollbackErr := rollbackOrderedDirectFrameCase(tx, packet); rollbackErr != nil {
				t.Errorf("transform:%s bounded failure cleanup: %v", item.ID, rollbackErr)
			}
		}
	}()
	byID := make(map[string]orderedDirectFrameTransformRule, len(rules))
	for _, rule := range rules {
		byID[rule.ID] = rule
	}
	preMutation := make(map[string]orderedDirectFrameQueryOutcome)
	if item.MustChange {
		for _, ruleID := range item.RuleIDs {
			rule, ok := byID[ruleID]
			if !ok {
				return fmt.Errorf("transform:%s must-change unknown rule %s", item.ID, ruleID)
			}
			if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog, public"); err != nil {
				return err
			}
			outcome, outcomeErr := queryOrderedDirectFrameOutcomeInSavepoint(ctx, tx, "ordered_direct_frame_pre_mutation", rule.OriginalAggregateSQL)
			if outcomeErr != nil || outcome.Code != "" {
				return fmt.Errorf("transform:%s must-change pre-state %s: %v/%s", item.ID, ruleID, outcomeErr, outcome.Code)
			}
			preMutation[ruleID] = outcome
		}
	}
	if err := setOrderedDirectFrameRole(ctx, tx, "zasp_test", "pg_catalog, public"); err != nil {
		return fmt.Errorf("transform:%s mutation frame: %w", item.ID, err)
	}
	for _, statement := range item.MutationSQL {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("transform:%s mutation: %w", item.ID, err)
		}
	}
	if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog, public"); err != nil {
		return fmt.Errorf("transform:%s source frame: %w", item.ID, err)
	}
	if item.WitnessSQL != "" {
		witness, err := queryOrderedDirectFrameOutcomeInSavepoint(ctx, tx, "ordered_direct_frame_transform_witness", item.WitnessSQL)
		if err != nil {
			return fmt.Errorf("transform:%s witness: %w", item.ID, err)
		}
		if witness.Code != "" {
			return fmt.Errorf("transform:%s witness SQLSTATE=%s", item.ID, witness.Code)
		}
		if item.Mode == "config" {
			if err := validateOrderedDirectFrameConfigWitness(item.ID, witness, item.ExpectNonstandard); err != nil {
				return fmt.Errorf("transform:%s config witness: %w", item.ID, err)
			}
		}
	}
	if item.ProbeSQL != "" {
		probe, probeErr := queryOrderedDirectFrameOutcomeInSavepoint(ctx, tx, "ordered_direct_frame_transform_probe", item.ProbeSQL)
		if probeErr != nil {
			return fmt.Errorf("transform:%s probe: %w", item.ID, probeErr)
		}
		if item.ExpectedSQLState != nil && probe.Code != *item.ExpectedSQLState {
			return fmt.Errorf("transform:%s probe SQLSTATE=%s want=%s", item.ID, probe.Code, *item.ExpectedSQLState)
		}
	}
	capsByID, err := orderedDirectFrameTransformRuleCaps(packet)
	if err != nil {
		return err
	}
	ruleIDs := item.RuleIDs
	if len(ruleIDs) == 0 {
		ruleIDs = make([]string, 0, len(rules))
		for _, rule := range rules {
			ruleIDs = append(ruleIDs, rule.ID)
		}
	}
	for _, ruleID := range ruleIDs {
		rule, ok := byID[ruleID]
		if !ok {
			return fmt.Errorf("transform:%s unknown rule %s", item.ID, ruleID)
		}
		cap, ok := capsByID[ruleID]
		if !ok {
			return fmt.Errorf("transform:%s missing fixed cap %s", item.ID, ruleID)
		}
		if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog"); err != nil {
			return err
		}
		roster, rosterErr := collectOrderedDirectFrameTransformRowsBounded(ctx, tx, cap.RowCap, cap.ByteCap, rule.RosterSQL, 2)
		if rosterErr != nil {
			return fmt.Errorf("transform:%s roster %s: %w", item.ID, ruleID, rosterErr)
		}
		if orderedDirectFrameRequiresTransformLinkage(item) {
			if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog, public"); err != nil {
				return err
			}
			originalRows, originalRowsErr := collectOrderedDirectFrameTransformRowsBounded(ctx, tx, cap.RowCap, cap.ByteCap, rule.OriginalSQL, 3)
			if originalRowsErr != nil {
				return fmt.Errorf("transform:%s original linkage %s: %w", item.ID, ruleID, originalRowsErr)
			}
			if err := assertOrderedDirectFrameTransformLinkage(ruleID, originalRows, roster); err != nil {
				return fmt.Errorf("transform:%s roster linkage %s: %w", item.ID, ruleID, err)
			}
		}
		if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog, public"); err != nil {
			return err
		}
		original, originalErr := queryOrderedDirectFrameOutcomeInSavepoint(ctx, tx, "ordered_direct_frame_transform_original", rule.OriginalAggregateSQL)
		if originalErr != nil {
			return fmt.Errorf("transform:%s original %s: %w", item.ID, ruleID, originalErr)
		}
		if err := setOrderedDirectFrameRole(ctx, tx, "zasp_discovery_authority", "pg_catalog"); err != nil {
			return err
		}
		candidate, candidateErr := queryOrderedDirectFrameOutcomeInSavepoint(ctx, tx, "ordered_direct_frame_transform_candidate", rule.CandidateAggregateSQL)
		if candidateErr != nil {
			return fmt.Errorf("transform:%s candidate %s: %w", item.ID, ruleID, candidateErr)
		}
		if aggregateSQLState := orderedDirectFrameAggregateExpectedSQLState(item); aggregateSQLState != nil {
			if original.Code != *aggregateSQLState || candidate.Code != *aggregateSQLState {
				return fmt.Errorf("transform:%s aggregate SQLSTATE original=%s candidate=%s", item.ID, original.Code, candidate.Code)
			}
		} else if err := assertOrderedDirectFrameOutcomeEqual(original, candidate, nil); err != nil {
			return fmt.Errorf("transform:%s aggregate %s: %w", item.ID, ruleID, err)
		}
		if before, required := preMutation[ruleID]; required {
			if assertOrderedDirectFrameOutcomeEqual(before, original, nil) == nil {
				return fmt.Errorf("transform:%s must-change rule %s remained unchanged", item.ID, ruleID)
			}
		}
	}
	if err := finishOrderedDirectFrameCase(ctx, owner, tx, before, packet); err != nil {
		return err
	}
	afterUniverse, err := captureOrderedDirectFrameOriginalUniverseSnapshot(ctx, owner, packet)
	if err != nil {
		return err
	}
	if !equalOrderedDirectFrameJSONMultiset(beforeUniverse, afterUniverse) {
		return fmt.Errorf("transform:%s original universe changed", item.ID)
	}
	finished = true
	t.Logf("direct-frame transform case %s passed", item.ID)
	return nil
}

type orderedDirectFrameTransformRuleCap struct {
	RowCap  int
	ByteCap int
}

func orderedDirectFrameTransformRuleCaps(packet orderedDirectFrameAcceptancePacket) (map[string]orderedDirectFrameTransformRuleCap, error) {
	if len(packet.OriginalUniverse.TransformRules) != 13 {
		return nil, errors.New("transform fixed cap count")
	}
	caps := make(map[string]orderedDirectFrameTransformRuleCap, 13)
	for _, rule := range packet.OriginalUniverse.TransformRules {
		if rule.ID == "" || rule.RowCap <= 0 || rule.ByteCap <= 0 || rule.RowCap > packet.Limits.MaxRows || rule.ByteCap > packet.Limits.MaxBytes {
			return nil, errors.New("transform fixed cap shape")
		}
		if _, exists := caps[rule.ID]; exists {
			return nil, errors.New("transform fixed cap duplicate")
		}
		caps[rule.ID] = orderedDirectFrameTransformRuleCap{RowCap: rule.RowCap, ByteCap: rule.ByteCap}
	}
	return caps, nil
}

func validateOrderedDirectFrameConfigWitness(caseID string, outcome orderedDirectFrameQueryOutcome, expectNonstandard bool) error {
	if len(outcome.Rows) == 0 || len(outcome.Rows) > 176 {
		return errors.New("config witness row bounds")
	}
	seenObjects := make(map[string]bool, len(outcome.Rows))
	seenIdentities := make(map[string]bool, len(outcome.Rows))
	for _, raw := range outcome.Rows {
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil || len(values) != 1 {
			return errors.New("config witness row envelope")
		}
		var witness map[string]json.RawMessage
		if err := json.Unmarshal(values[0], &witness); err != nil {
			return errors.New("config witness object")
		}
		for _, key := range []string{"config", "dimensions", "identity", "lowerBound", "objectOID", "originalText", "upperBound"} {
			if _, ok := witness[key]; !ok {
				return fmt.Errorf("config witness missing %s", key)
			}
		}
		var objectID, identity, originalText string
		if json.Unmarshal(witness["objectOID"], &objectID) != nil || objectID == "" || seenObjects[objectID] || json.Unmarshal(witness["identity"], &identity) != nil || identity == "" || seenIdentities[identity] || json.Unmarshal(witness["originalText"], &originalText) != nil {
			return errors.New("config witness identity shape")
		}
		seenObjects[objectID], seenIdentities[identity] = true, true
		if expectNonstandard {
			var dimensions, lower, upper int
			var config []string
			if len(outcome.Rows) != 1 || json.Unmarshal(witness["config"], &config) != nil || len(config) != 1 || json.Unmarshal(witness["dimensions"], &dimensions) != nil || json.Unmarshal(witness["lowerBound"], &lower) != nil || json.Unmarshal(witness["upperBound"], &upper) != nil || dimensions != 1 || lower != 0 || upper != 0 || !strings.HasPrefix(originalText, "[0:0]=") {
				return errors.New("nonstandard config witness mismatch")
			}
			continue
		}
		if len(outcome.Rows) != 1 {
			return errors.New("config witness exact row count")
		}
		switch caseID {
		case "config-null":
			if string(witness["config"]) != "null" || string(witness["dimensions"]) != "null" || string(witness["lowerBound"]) != "null" || string(witness["upperBound"]) != "null" || originalText != "" {
				return errors.New("null config witness mismatch")
			}
		case "config-empty":
			var config []string
			if json.Unmarshal(witness["config"], &config) != nil || len(config) != 0 || string(witness["dimensions"]) != "null" || string(witness["lowerBound"]) != "null" || string(witness["upperBound"]) != "null" || originalText != "{}" {
				return errors.New("empty config witness mismatch")
			}
		case "config-quoted":
			var config []*string
			var dimensions, lower, upper int
			if json.Unmarshal(witness["config"], &config) != nil || len(config) != 6 || config[0] == nil || *config[0] != "search_path=pg_catalog, public" || config[1] == nil || *config[1] != "" || config[2] == nil || *config[2] != "NULL" || config[3] != nil || config[4] == nil || *config[4] != `x=a"b` || config[5] == nil || *config[5] != `x=a\b` || json.Unmarshal(witness["dimensions"], &dimensions) != nil || json.Unmarshal(witness["lowerBound"], &lower) != nil || json.Unmarshal(witness["upperBound"], &upper) != nil || dimensions != 1 || lower != 1 || upper != 6 || originalText != `{"search_path=pg_catalog, public","","NULL",NULL,"x=a\"b","x=a\\b"}` {
				return errors.New("quoted config witness mismatch")
			}
		default:
			return fmt.Errorf("unexpected ordinary config case %s", caseID)
		}
	}
	return nil
}

func compareOrderedDirectFrameRows(ctx context.Context, tx pgx.Tx, sql string, expected []json.RawMessage, maxBytes int) error {
	if len(expected) != 1220 || strings.TrimSpace(sql) == "" {
		return errors.New("direct-frame expected bounds")
	}
	want := make(map[string]json.RawMessage, len(expected))
	for _, raw := range expected {
		var row struct {
			Kind     string          `json:"kind"`
			Identity string          `json:"identity"`
			Fact     json.RawMessage `json:"fact"`
		}
		if json.Unmarshal(raw, &row) != nil || row.Kind == "" || row.Identity == "" || len(row.Fact) == 0 {
			return errors.New("direct-frame expected row")
		}
		key := row.Kind + "\x00" + row.Identity
		if _, exists := want[key]; exists {
			return fmt.Errorf("direct-frame duplicate expected key %s", key)
		}
		want[key] = row.Fact
	}
	rows, err := tx.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := make(map[string]bool, len(want))
	bytesRead := 0
	for rows.Next() {
		var kind, identity string
		var fact json.RawMessage
		if err := rows.Scan(&kind, &identity, &fact); err != nil {
			return err
		}
		bytesRead += len(kind) + len(identity) + len(fact)
		if maxBytes > 0 && bytesRead > maxBytes {
			return errors.New("direct-frame collector byte limit exceeded")
		}
		key := kind + "\x00" + identity
		wantFact, exists := want[key]
		if !exists || seen[key] || !jsonEqual(wantFact, fact) {
			return fmt.Errorf("direct-frame unexpected row %s", key)
		}
		seen[key] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(seen) != len(want) {
		return fmt.Errorf("direct-frame row count got=%d want=%d", len(seen), len(want))
	}
	return nil
}

func compareOrderedDirectFrameTransformRows(ctx context.Context, tx pgx.Tx, sql string, expected []json.RawMessage, maxBytes int) error {
	if len(expected) != 380 || sql == "" {
		return errors.New("transform expected bounds")
	}
	want := make(map[string]json.RawMessage, len(expected))
	for _, raw := range expected {
		var row struct {
			Kind     string          `json:"kind"`
			Identity string          `json:"identity"`
			Fact     json.RawMessage `json:"fact"`
		}
		if json.Unmarshal(raw, &row) != nil || row.Kind == "" || row.Identity == "" || len(row.Fact) == 0 {
			return errors.New("transform expected row")
		}
		key := row.Kind + "\x00" + row.Identity
		if _, exists := want[key]; exists {
			return fmt.Errorf("transform duplicate expected key %s", key)
		}
		want[key] = row.Fact
	}
	rows, err := tx.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := make(map[string]bool, len(want))
	bytesRead := 0
	for rows.Next() {
		var kind, identity string
		var fact json.RawMessage
		if err := rows.Scan(&kind, &identity, &fact); err != nil {
			return err
		}
		bytesRead += len(kind) + len(identity) + len(fact)
		if maxBytes > 0 && bytesRead > maxBytes {
			return errors.New("transform collector byte limit exceeded")
		}
		key := kind + "\x00" + identity
		if seen[key] || !jsonEqual(want[key], fact) {
			return fmt.Errorf("transform unexpected row %s", key)
		}
		seen[key] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(seen) != len(want) {
		return fmt.Errorf("transform row count got=%d want=%d", len(seen), len(want))
	}
	return nil
}

func jsonEqual(left, right []byte) bool {
	decode := func(value []byte) (any, error) {
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.UseNumber()
		var result any
		if err := decoder.Decode(&result); err != nil {
			return nil, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return nil, errors.New("trailing JSON")
		}
		return result, nil
	}
	l, leftErr := decode(left)
	r, rightErr := decode(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return reflect.DeepEqual(l, r)
}

func assertOrderedDirectFrameWorkerRelease(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	release, err := os.ReadFile(orderedDirectFrameSourceBaselinePath)
	if err != nil || orderedDirectFrameDigestBytes(release) != orderedDirectFrameCompilerArtifactSHA256 {
		t.Fatalf("accepted 2ca source baseline required: %v", err)
	}
	var releaseEnvelope struct {
		Checksum     string `json:"checksum"`
		SourceSHA256 string `json:"source_sha256"`
	}
	if err := json.Unmarshal(release, &releaseEnvelope); err != nil || releaseEnvelope.Checksum != orderedDirectFrameCompilerChecksum || releaseEnvelope.SourceSHA256 != orderedDirectFrameCompiledSourceSHA256 {
		t.Fatalf("accepted 2ca source baseline envelope refused: %v", err)
	}
	var checksum string
	if err := owner.QueryRow(ctx, `SELECT checksum FROM zasp_authorization80_worker.registration WHERE singleton`).Scan(&checksum); err != nil || checksum != orderedDirectFrameCompilerChecksum {
		t.Fatalf("accepted 2ca worker release required: %v", err)
	}
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatalf("accepted worker catalog not ready: %v", err)
	}
}
