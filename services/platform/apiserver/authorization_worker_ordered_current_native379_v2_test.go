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
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	orderedCurrentNative379V2ModuleFile     = "development-module.sql"
	orderedCurrentNative379V2CollectorFile  = "development-collector.sql"
	orderedCurrentNative379V2MaxResultBytes = 4 * 1024 * 1024
)

type orderedCurrentNative379V2Rule struct {
	ID            string `json:"id"`
	ExpectedFacts int    `json:"expectedFacts"`
}

type orderedCurrentNative379V2Fact struct {
	Kind     string          `json:"kind"`
	Identity string          `json:"identity"`
	Fact     json.RawMessage `json:"fact"`
}

type orderedCurrentNative379V2CatalogDiagnosticEntry struct {
	Class           string `json:"class"`
	Kind            string `json:"kind"`
	Identity        string `json:"identity"`
	ExpectedSHA256  string `json:"expectedSHA256,omitempty"`
	LiveSHA256      string `json:"liveSHA256,omitempty"`
	ExpectedPreview string `json:"expectedPreview,omitempty"`
	LivePreview     string `json:"livePreview,omitempty"`
}

type orderedCurrentNative379V2CatalogDiagnosticCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type orderedCurrentNative379V2CatalogDiagnosticClassCount struct {
	Class string `json:"class"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type orderedCurrentNative379V2CatalogDiagnosticRelocationCount struct {
	Kind       string `json:"kind"`
	Rule       string `json:"rule"`
	FactSHA256 string `json:"factSHA256"`
	Count      int    `json:"count"`
}

type orderedCurrentNative379V2CatalogDiagnosticRelocation struct {
	Kind           string `json:"kind"`
	Rule           string `json:"rule"`
	FactSHA256     string `json:"factSHA256"`
	BeforeIdentity string `json:"beforeIdentity"`
	AfterIdentity  string `json:"afterIdentity"`
}

type orderedCurrentNative379V2CatalogDiagnosticChangedFieldCount struct {
	Kind  string `json:"kind"`
	Rule  string `json:"rule"`
	Field string `json:"field"`
	Count int    `json:"count"`
}

type orderedCurrentNative379V2CatalogDiagnosticChangedFieldSample struct {
	Kind            string `json:"kind"`
	Rule            string `json:"rule"`
	Field           string `json:"field"`
	ExpectedSHA256  string `json:"expectedSHA256"`
	LiveSHA256      string `json:"liveSHA256"`
	ExpectedPreview string `json:"expectedPreview"`
	LivePreview     string `json:"livePreview"`
}

type orderedCurrentNative379V2CatalogDiagnostic struct {
	Expected              int                                                            `json:"expected"`
	Live                  int                                                            `json:"live"`
	Missing               int                                                            `json:"missing"`
	Extra                 int                                                            `json:"extra"`
	Changed               int                                                            `json:"changed"`
	Duplicates            int                                                            `json:"duplicates"`
	Overflow              bool                                                           `json:"overflow"`
	CountOverflow         bool                                                           `json:"countOverflow,omitempty"`
	Error                 string                                                         `json:"error,omitempty"`
	ClassCounts           []orderedCurrentNative379V2CatalogDiagnosticCount              `json:"classCounts,omitempty"`
	KindCounts            []orderedCurrentNative379V2CatalogDiagnosticCount              `json:"kindCounts,omitempty"`
	RuleCounts            []orderedCurrentNative379V2CatalogDiagnosticCount              `json:"ruleCounts,omitempty"`
	KindClassCounts       []orderedCurrentNative379V2CatalogDiagnosticClassCount         `json:"kindClassCounts,omitempty"`
	RuleClassCounts       []orderedCurrentNative379V2CatalogDiagnosticClassCount         `json:"ruleClassCounts,omitempty"`
	RelocationCounts      []orderedCurrentNative379V2CatalogDiagnosticRelocationCount    `json:"relocationCounts,omitempty"`
	Relocations           []orderedCurrentNative379V2CatalogDiagnosticRelocation         `json:"relocations,omitempty"`
	RelocationAmbiguities int                                                            `json:"relocationAmbiguities,omitempty"`
	ChangedFieldCounts    []orderedCurrentNative379V2CatalogDiagnosticChangedFieldCount  `json:"changedFieldCounts,omitempty"`
	ChangedFieldSamples   []orderedCurrentNative379V2CatalogDiagnosticChangedFieldSample `json:"changedFieldSamples,omitempty"`
	Entries               []orderedCurrentNative379V2CatalogDiagnosticEntry              `json:"entries"`
}

type orderedCurrentNative379V2StepExpectation struct {
	Outcome  string          `json:"outcome"`
	SQLState *string         `json:"sqlState"`
	Rows     json.RawMessage `json:"rows"`
	Value    json.RawMessage `json:"value"`
	Key      string          `json:"key"`
}

type orderedCurrentNative379V2ProgramStep struct {
	ID        string                                   `json:"id"`
	Role      string                                   `json:"role"`
	SQL       string                                   `json:"sql"`
	SQLSHA256 string                                   `json:"sqlSHA256"`
	Expected  orderedCurrentNative379V2StepExpectation `json:"expected"`
}

type orderedCurrentNative379V2Control struct {
	ID             string          `json:"id"`
	Phase          string          `json:"phase"`
	Category       string          `json:"category"`
	Mutation       json.RawMessage `json:"mutation"`
	MutationSHA256 string          `json:"mutationSHA256"`
	Program        struct {
		Format            string `json:"format"`
		Transaction       string `json:"transaction"`
		Connection        string `json:"connection"`
		ErrorContinuation string `json:"errorContinuation"`
		RoleSemantics     string `json:"roleSemantics"`
		EvaluationFrame   struct {
			ID              string `json:"id"`
			Isolation       string `json:"isolation"`
			Access          string `json:"access"`
			Visibility      string `json:"visibility"`
			CommitForbidden bool   `json:"commitForbidden"`
		} `json:"evaluationFrame"`
		Steps []orderedCurrentNative379V2ProgramStep `json:"steps"`
	} `json:"program"`
	Restoration struct {
		BeforeNextProbe                bool   `json:"beforeNextProbe"`
		TimeoutIsDenial                bool   `json:"timeoutIsDenial"`
		SnapshotSQL                    string `json:"snapshotSQL"`
		RestoreSQL                     string `json:"restoreSQL"`
		AssertionSQL                   string `json:"assertionSQL"`
		ProtocolTransactionStatusAfter string `json:"protocolTransactionStatusAfter"`
		ExpectedTransactionStatus      string `json:"expectedTransactionStatus"`
	} `json:"restoration"`
}

// The typed view drives execution. Raw preserves every authenticated source,
// transition/provenance/coverage field; none becomes runtime authority by decoding.
type orderedCurrentNative379V2Packet struct {
	Raw                 json.RawMessage `json:"-"`
	admittedRawSHA      string
	CaptureAuthority    bool            `json:"captureAuthority"`
	SourceFactDelta     json.RawMessage `json:"sourceFactDelta"`
	ReferenceProvenance json.RawMessage `json:"referenceProvenance"`
	PendingGates        []string        `json:"pendingGates"`
	BuildRuntime        json.RawMessage `json:"buildRuntime"`
	Coverage            json.RawMessage `json:"coverage"`
	NextGates           json.RawMessage `json:"nextGates"`
	ResultAuthority     string          `json:"resultAuthority"`
	Format              string          `json:"format"`
	Status              string          `json:"status"`
	Installable         bool            `json:"installable"`
	NativeVerified      bool            `json:"nativeVerified"`
	Authority           struct {
		Generated                 map[string]string `json:"generated"`
		GoPacketAnchorPolicy      json.RawMessage   `json:"goPacketAnchorPolicy"`
		SourceInventorySHA256     string            `json:"sourceInventorySHA256"`
		GeneratedIdentitiesSHA256 string            `json:"generatedIdentitiesSHA256"`
		SourceFactDeltaSHA256     string            `json:"sourceFactDeltaSHA256"`
	} `json:"authority"`
	Identity struct {
		ServerVersionNum int    `json:"serverVersionNum"`
		Postgres         string `json:"postgres"`
		Pgcrypto         string `json:"pgcrypto"`
	} `json:"identity"`
	Rules           []orderedCurrentNative379V2Rule `json:"rules"`
	ExpectedFacts   []orderedCurrentNative379V2Fact `json:"expectedFacts"`
	SourceInventory struct {
		Sites        []json.RawMessage `json:"sites"`
		Unclassified int               `json:"unclassified"`
	} `json:"sourceInventory"`
	Phases []struct {
		ID         string   `json:"id"`
		ControlIDs []string `json:"controlIds"`
		Limits     struct {
			MaxRows         int `json:"maxRows"`
			MaxBytes        int `json:"maxBytes"`
			MaxMilliseconds int `json:"maxMilliseconds"`
		} `json:"limits"`
	} `json:"phases"`
	Controls []orderedCurrentNative379V2Control `json:"controls"`
	Limits   struct {
		MaxRows             int `json:"maxRows"`
		MaxBytes            int `json:"maxBytes"`
		MaxMilliseconds     int `json:"maxMilliseconds"`
		MaxPacketBytes      int `json:"maxPacketBytes"`
		SQLMilliseconds     int `json:"sqlMilliseconds"`
		LockMilliseconds    int `json:"lockMilliseconds"`
		CleanupMilliseconds int `json:"cleanupMilliseconds"`
	} `json:"limits"`
	Entry struct {
		Manifest            string `json:"manifest"`
		ManifestLiteral     string `json:"manifestLiteral"`
		PrivateRoutineFacts []struct {
			Identity string `json:"identity"`
		} `json:"privateRoutineFacts"`
		IndependentAdmission struct {
			SQL string `json:"sql"`
		} `json:"independentAdmission"`
	} `json:"entry"`
	WireSHA256 string `json:"-"`
}

func (packet orderedCurrentNative379V2Packet) clone() orderedCurrentNative379V2Packet {
	raw, _ := json.Marshal(packet)
	var copy orderedCurrentNative379V2Packet
	_ = json.Unmarshal(raw, &copy)
	copy.WireSHA256 = packet.WireSHA256
	copy.admittedRawSHA = packet.admittedRawSHA
	copy.Raw = append(json.RawMessage(nil), packet.Raw...)
	return copy
}

type orderedCurrentNative379V2Stage struct {
	ID           string `json:"id"`
	Phase        string `json:"phase"`
	Milliseconds int64  `json:"milliseconds"`
}

type orderedCurrentNative379V2Operation struct {
	ID       string `json:"id"`
	SQLState string `json:"sqlState"`
}

type orderedCurrentNative379V2ControlStepResult struct {
	ID                        string                       `json:"id"`
	Outcome                   string                       `json:"outcome"`
	SQLState                  string                       `json:"sqlState"`
	DeclaredRole              string                       `json:"declaredRole"`
	RoleAssertion             *native379V2AssertionReceipt `json:"roleAssertion,omitempty"`
	RecoveryPredecessorSHA256 string                       `json:"recoveryPredecessorSHA256,omitempty"`
	RecoverySQLState          string                       `json:"recoverySQLState,omitempty"`
	CarriedAssertionSHA256    string                       `json:"carriedAssertionSHA256,omitempty"`
	BoundSessionUser          string                       `json:"boundSessionUser"`
	BoundBackendPID           int32                        `json:"boundBackendPID"`
	RoleObservation           string                       `json:"roleObservation"`
	Observation               json.RawMessage              `json:"observation"`
	ObservedSHA256            string                       `json:"observedSHA256"`
	Matched                   bool                         `json:"matched"`
	TimedOut                  bool                         `json:"timedOut"`
}

type orderedCurrentNative379V2AdmittedPacket struct {
	packet   orderedCurrentNative379V2Packet
	rawSHA   string
	rawBytes int
}

type orderedCurrentNative379V2ControlResult struct {
	ID             string                                       `json:"id"`
	Phase          string                                       `json:"phase"`
	MutationSHA256 string                                       `json:"mutationSHA256"`
	Milliseconds   int64                                        `json:"milliseconds"`
	Steps          []orderedCurrentNative379V2ControlStepResult `json:"steps"`
	Restored       bool                                         `json:"restored"`
}

var orderedCurrentNative379V2PristineOperationPlan = []string{
	"preflight-identity", "dormant-module-install", "installed-inventory",
	"expected-stream-query", "expected-stream-complete", "frame-before",
	"pristine-begin", "pristine-frame", "private-admission", "catalog",
	"require", "pristine-rollback", "frame-after",
}

type orderedCurrentNative379V2OperationRecorder struct {
	operations []orderedCurrentNative379V2Operation
	invalid    bool
}

func (recorder *orderedCurrentNative379V2OperationRecorder) observe(id string, err error) error {
	if recorder == nil || len(recorder.operations) >= len(orderedCurrentNative379V2PristineOperationPlan) || id != orderedCurrentNative379V2PristineOperationPlan[len(recorder.operations)] {
		if recorder != nil {
			recorder.invalid = true
		}
		return errors.New("native379 operation order refused")
	}
	code := "00000"
	if err != nil {
		var postgres *pgconn.PgError
		if errors.As(err, &postgres) {
			code = postgres.Code
		} else {
			code = "NON_SQL_ERROR"
			recorder.invalid = true
		}
	}
	recorder.operations = append(recorder.operations, orderedCurrentNative379V2Operation{ID: id, SQLState: code})
	return err
}

func (recorder *orderedCurrentNative379V2OperationRecorder) finish() ([]orderedCurrentNative379V2Operation, error) {
	if recorder == nil || recorder.invalid || len(recorder.operations) != len(orderedCurrentNative379V2PristineOperationPlan) {
		return nil, errors.New("native379 operation evidence incomplete")
	}
	for index, operation := range recorder.operations {
		if operation.ID != orderedCurrentNative379V2PristineOperationPlan[index] || operation.SQLState != "00000" {
			return nil, errors.New("native379 pristine operation outcome refused")
		}
	}
	return append([]orderedCurrentNative379V2Operation(nil), recorder.operations...), nil
}

func validateOrderedCurrentNative379V2Operations(operations []orderedCurrentNative379V2Operation) error {
	if operations == nil || len(operations) != len(orderedCurrentNative379V2PristineOperationPlan) {
		return errors.New("native379 observed operation evidence absent or incomplete")
	}
	for index, operation := range operations {
		if operation.ID != orderedCurrentNative379V2PristineOperationPlan[index] || operation.SQLState != "00000" {
			return errors.New("native379 observed operation order or SQLSTATE refused")
		}
	}
	return nil
}

type orderedCurrentNative379V2Observation struct {
	Budget         native379V2BudgetEvidence `json:"budget"`
	Available      bool                      `json:"available"`
	EndpointSHA256 string                    `json:"endpointSHA256"`
	Hashes         map[string]string         `json:"hashes"`
	Server         struct {
		VersionNum int    `json:"versionNum"`
		Postgres   string `json:"postgres"`
		Pgcrypto   string `json:"pgcrypto"`
	} `json:"server"`
	Objects struct {
		SchemaOwner      string   `json:"schemaOwner"`
		Tables           []string `json:"tables"`
		Routines         []string `json:"routines"`
		UnexpectedGrants int      `json:"unexpectedGrants"`
	} `json:"objects"`
	Counts struct {
		Rules        int `json:"rules"`
		Facts        int `json:"facts"`
		RoleSites    int `json:"roleSites"`
		Registration int `json:"registration"`
		ExpectedRows int `json:"expectedRows"`
		EqualFacts   int `json:"equalFacts"`
	} `json:"counts"`
	Operations  []orderedCurrentNative379V2Operation     `json:"operations"`
	Controls    []orderedCurrentNative379V2ControlResult `json:"controls"`
	Restoration struct {
		TransactionRolledBack bool `json:"transactionRolledBack"`
		FrameRestored         bool `json:"frameRestored"`
	} `json:"restoration"`
}

func (observation orderedCurrentNative379V2Observation) clone() orderedCurrentNative379V2Observation {
	raw, _ := json.Marshal(observation)
	var copy orderedCurrentNative379V2Observation
	_ = json.Unmarshal(raw, &copy)
	return copy
}

type orderedCurrentNative379V2Result struct {
	Budget              native379V2BudgetEvidence        `json:"budget"`
	NativeVerified      bool                             `json:"nativeVerified"`
	BuildEnvelopeSHA256 string                           `json:"buildEnvelopeSHA256"`
	PendingGates        []string                         `json:"pendingGates"`
	Format              string                           `json:"format"`
	Status              string                           `json:"status"`
	Installable         bool                             `json:"installable"`
	Truncated           bool                             `json:"truncated"`
	PacketSHA256        string                           `json:"packetSHA256"`
	Stages              []orderedCurrentNative379V2Stage `json:"stages"`
	Hashes              map[string]string                `json:"hashes"`
	EndpointSHA256      string                           `json:"endpointSHA256"`
	Server              struct {
		VersionNum int    `json:"versionNum"`
		Postgres   string `json:"postgres"`
		Pgcrypto   string `json:"pgcrypto"`
	} `json:"server"`
	Objects struct {
		SchemaOwner      string   `json:"schemaOwner"`
		Tables           []string `json:"tables"`
		Routines         []string `json:"routines"`
		UnexpectedGrants int      `json:"unexpectedGrants"`
	} `json:"objects"`
	Counts struct {
		Rules        int `json:"rules"`
		Facts        int `json:"facts"`
		RoleSites    int `json:"roleSites"`
		Registration int `json:"registration"`
		ExpectedRows int `json:"expectedRows"`
		EqualFacts   int `json:"equalFacts"`
		Tables       int `json:"tables"`
		Routines     int `json:"routines"`
	} `json:"counts"`
	Operations  []orderedCurrentNative379V2Operation     `json:"operations"`
	Controls    []orderedCurrentNative379V2ControlResult `json:"controls"`
	Restoration struct {
		TransactionRolledBack bool `json:"transactionRolledBack"`
		FrameRestored         bool `json:"frameRestored"`
	} `json:"restoration"`
	Cleanup struct {
		PGCtlStopped              bool   `json:"pgCtlStopped"`
		EndpointChecked           bool   `json:"endpointChecked"`
		EndpointSHA256            string `json:"endpointSHA256"`
		Joined                    bool   `json:"joined"`
		NormalExit                bool   `json:"normalExit"`
		SurvivingResourcesChecked bool   `json:"survivingResourcesChecked"`
		SurvivingResources        int    `json:"survivingResources"`
	} `json:"cleanup"`
}

func (result orderedCurrentNative379V2Result) clone() orderedCurrentNative379V2Result {
	raw, _ := json.Marshal(result)
	var copy orderedCurrentNative379V2Result
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func orderedCurrentNative379V2ExpectedRoutines(packet orderedCurrentNative379V2Packet) ([]string, error) {
	if len(packet.Entry.PrivateRoutineFacts) != 8 {
		return nil, errors.New("native379 pinned routine inventory cardinality refused")
	}
	routines := make([]string, 0, 8)
	seen := make(map[string]bool, 8)
	for _, fact := range packet.Entry.PrivateRoutineFacts {
		var identity []string
		if json.Unmarshal([]byte(fact.Identity), &identity) != nil || len(identity) != 2 || identity[0] != "private-routines" || identity[1] == "" || seen[identity[1]] {
			return nil, errors.New("native379 pinned routine inventory refused")
		}
		seen[identity[1]] = true
		routines = append(routines, identity[1])
	}
	sort.Strings(routines)
	return routines, nil
}

func orderedCurrentNative379V2TestStages(packet orderedCurrentNative379V2Packet) []orderedCurrentNative379V2Stage {
	return []orderedCurrentNative379V2Stage{
		{ID: "packet-input", Phase: "preflight", Milliseconds: 1},
		{ID: "fixed-source-inputs", Phase: "preflight", Milliseconds: 1},
		{ID: "owned-production-source", Phase: "pristine-truth", Milliseconds: 1},
		{ID: "dormant-install-pristine", Phase: "pristine-truth", Milliseconds: 1},
		{ID: "drift-probes", Phase: "drift", Milliseconds: 1},
		{ID: "forged-entry-probes", Phase: "forged-entry", Milliseconds: 1},
		{ID: "semantic-probes", Phase: "null-error-lazy-demand", Milliseconds: 1},
		{ID: "frame-restoration-probes", Phase: "frame-restoration", Milliseconds: 1},
		{ID: "fixture-cleanup-join", Phase: "cleanup-result", Milliseconds: 1},
		{ID: "result-admission", Phase: "cleanup-result", Milliseconds: 1},
	}
}

func orderedCurrentNative379V2SHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func orderedCurrentNative379V2CanonicalSHA256(raw json.RawMessage) (string, error) {
	canonical, err := orderedCurrentNative379V2CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	return orderedCurrentNative379V2SHA256(canonical), nil
}

func orderedCurrentNative379V2CanonicalJSON(raw json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("native379 noncanonical JSON refused")
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, errors.New("native379 canonical JSON encoding refused")
	}
	return native379V2JSONStringSeparators(bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'})), nil
}

func orderedCurrentNative379V2CanonicalJSONFromValue(value any) (json.RawMessage, error) {
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, errors.New("native379 observation encoding refused")
	}
	normalized, err := orderedCurrentNative379V2CanonicalJSON(canonical.Bytes())
	return json.RawMessage(normalized), err
}

func orderedCurrentNative379V2DiagnosticFact(raw json.RawMessage) ([]byte, string) {
	canonical, err := orderedCurrentNative379V2CanonicalJSON(raw)
	if err != nil {
		canonical = append([]byte(nil), raw...)
	}
	previewRunes := []rune(string(canonical))
	if len(previewRunes) > 256 {
		previewRunes = previewRunes[:256]
	}
	return canonical, string(previewRunes)
}

func orderedCurrentNative379V2DiagnosticField(raw json.RawMessage) (string, string) {
	canonical, _ := orderedCurrentNative379V2DiagnosticFact(raw)
	previewRunes := []rune(string(canonical))
	if len(previewRunes) > 128 {
		previewRunes = previewRunes[:128]
	}
	return orderedCurrentNative379V2SHA256(canonical), string(previewRunes)
}

func orderedCurrentNative379V2DiagnosticRule(identity string) string {
	var parts []string
	decoder := json.NewDecoder(strings.NewReader(identity))
	if decoder.Decode(&parts) == nil && decoder.Decode(new(any)) == io.EOF && len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "<unclassified>"
}

func orderedCurrentNative379V2DiagnosticCounts(values map[string]int, limit int) ([]orderedCurrentNative379V2CatalogDiagnosticCount, bool) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if values[keys[left]] != values[keys[right]] {
			return values[keys[left]] > values[keys[right]]
		}
		return keys[left] < keys[right]
	})
	overflow := len(keys) > limit
	if overflow {
		keys = keys[:limit]
	}
	counts := make([]orderedCurrentNative379V2CatalogDiagnosticCount, 0, len(keys))
	for _, key := range keys {
		counts = append(counts, orderedCurrentNative379V2CatalogDiagnosticCount{Name: key, Count: values[key]})
	}
	return counts, overflow
}

func orderedCurrentNative379V2DiagnosticClassCounts(values map[string]int, limit int) ([]orderedCurrentNative379V2CatalogDiagnosticClassCount, bool) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if values[keys[left]] != values[keys[right]] {
			return values[keys[left]] > values[keys[right]]
		}
		leftParts := strings.SplitN(keys[left], "\x00", 2)
		rightParts := strings.SplitN(keys[right], "\x00", 2)
		if leftParts[0] != rightParts[0] {
			return leftParts[0] < rightParts[0]
		}
		return leftParts[1] < rightParts[1]
	})
	overflow := len(keys) > limit
	if overflow {
		keys = keys[:limit]
	}
	counts := make([]orderedCurrentNative379V2CatalogDiagnosticClassCount, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 2)
		counts = append(counts, orderedCurrentNative379V2CatalogDiagnosticClassCount{Class: parts[0], Name: parts[1], Count: values[key]})
	}
	return counts, overflow
}

func orderedCurrentNative379V2DiagnosticChangedFieldCounts(values map[string]int, limit int) ([]orderedCurrentNative379V2CatalogDiagnosticChangedFieldCount, bool) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if values[keys[left]] != values[keys[right]] {
			return values[keys[left]] > values[keys[right]]
		}
		return keys[left] < keys[right]
	})
	overflow := len(keys) > limit
	if overflow {
		keys = keys[:limit]
	}
	counts := make([]orderedCurrentNative379V2CatalogDiagnosticChangedFieldCount, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 3)
		counts = append(counts, orderedCurrentNative379V2CatalogDiagnosticChangedFieldCount{Kind: parts[0], Rule: parts[1], Field: parts[2], Count: values[key]})
	}
	return counts, overflow
}

func orderedCurrentNative379V2DiagnosticTopLevelFields(expected, live json.RawMessage) []string {
	var expectedFields, liveFields map[string]json.RawMessage
	if json.Unmarshal(expected, &expectedFields) != nil || json.Unmarshal(live, &liveFields) != nil || expectedFields == nil || liveFields == nil {
		return []string{"<fact>"}
	}
	keys := make(map[string]bool, len(expectedFields)+len(liveFields))
	for key := range expectedFields {
		keys[key] = true
	}
	for key := range liveFields {
		keys[key] = true
	}
	fields := make([]string, 0, len(keys))
	for key := range keys {
		left, leftOK := expectedFields[key]
		right, rightOK := liveFields[key]
		if !leftOK || !rightOK {
			fields = append(fields, key)
			continue
		}
		leftCanonical, leftErr := orderedCurrentNative379V2CanonicalJSON(left)
		rightCanonical, rightErr := orderedCurrentNative379V2CanonicalJSON(right)
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftCanonical, rightCanonical) {
			fields = append(fields, key)
		}
	}
	sort.Strings(fields)
	return fields
}

func orderedCurrentNative379V2BuildCatalogDiagnostic(expected, live []orderedCurrentNative379V2Fact, maxEntries, maxRows, maxBytes int) orderedCurrentNative379V2CatalogDiagnostic {
	diagnostic := orderedCurrentNative379V2CatalogDiagnostic{Entries: make([]orderedCurrentNative379V2CatalogDiagnosticEntry, 0)}
	classCounts := make(map[string]int)
	kindCounts := make(map[string]int)
	ruleCounts := make(map[string]int)
	kindClassCounts := make(map[string]int)
	ruleClassCounts := make(map[string]int)
	changedFieldCounts := make(map[string]int)
	changedFieldSamples := make(map[string]orderedCurrentNative379V2CatalogDiagnosticChangedFieldSample)
	record := func(class string, fact orderedCurrentNative379V2Fact) {
		classCounts[class]++
		kindCounts[fact.Kind]++
		rule := orderedCurrentNative379V2DiagnosticRule(fact.Identity)
		ruleCounts[rule]++
		kindClassCounts[class+"\x00"+fact.Kind]++
		ruleClassCounts[class+"\x00"+rule]++
	}
	expectedByKey := make(map[string]orderedCurrentNative379V2Fact, len(expected))
	for _, fact := range expected {
		if fact.Kind == "build" && fact.Identity == "provenance" {
			continue
		}
		diagnostic.Expected++
		expectedByKey[fact.Kind+"\x00"+fact.Identity] = fact
	}
	liveByKey := make(map[string]orderedCurrentNative379V2Fact, len(live))
	bytesSeen := 0
	entries := make([]orderedCurrentNative379V2CatalogDiagnosticEntry, 0)
	for _, fact := range live {
		diagnostic.Live++
		bytesSeen += len(fact.Kind) + len(fact.Identity) + len(fact.Fact)
		key := fact.Kind + "\x00" + fact.Identity
		if prior, exists := liveByKey[key]; exists {
			diagnostic.Duplicates++
			record("duplicate", fact)
			priorCanonical, priorPreview := orderedCurrentNative379V2DiagnosticFact(prior.Fact)
			liveCanonical, livePreview := orderedCurrentNative379V2DiagnosticFact(fact.Fact)
			entries = append(entries, orderedCurrentNative379V2CatalogDiagnosticEntry{Class: "duplicate", Kind: fact.Kind, Identity: fact.Identity, ExpectedSHA256: orderedCurrentNative379V2SHA256(priorCanonical), LiveSHA256: orderedCurrentNative379V2SHA256(liveCanonical), ExpectedPreview: priorPreview, LivePreview: livePreview})
			continue
		}
		liveByKey[key] = fact
	}
	diagnostic.Overflow = maxEntries < 0 || maxRows <= 0 || maxBytes <= 0 || len(live) > maxRows || bytesSeen > maxBytes
	for key, want := range expectedByKey {
		got, exists := liveByKey[key]
		if !exists {
			diagnostic.Missing++
			record("missing", want)
			canonical, preview := orderedCurrentNative379V2DiagnosticFact(want.Fact)
			entries = append(entries, orderedCurrentNative379V2CatalogDiagnosticEntry{Class: "missing", Kind: want.Kind, Identity: want.Identity, ExpectedSHA256: orderedCurrentNative379V2SHA256(canonical), ExpectedPreview: preview})
			continue
		}
		wantCanonical, wantPreview := orderedCurrentNative379V2DiagnosticFact(want.Fact)
		gotCanonical, gotPreview := orderedCurrentNative379V2DiagnosticFact(got.Fact)
		if !bytes.Equal(wantCanonical, gotCanonical) {
			diagnostic.Changed++
			record("changed", want)
			var expectedFields, liveFields map[string]json.RawMessage
			_ = json.Unmarshal(want.Fact, &expectedFields)
			_ = json.Unmarshal(got.Fact, &liveFields)
			for _, field := range orderedCurrentNative379V2DiagnosticTopLevelFields(want.Fact, got.Fact) {
				changedFieldCounts[want.Kind+"\x00"+orderedCurrentNative379V2DiagnosticRule(want.Identity)+"\x00"+field]++
				if _, exists := changedFieldSamples[want.Kind+"\x00"+orderedCurrentNative379V2DiagnosticRule(want.Identity)+"\x00"+field]; !exists {
					expectedValue, expectedOK := expectedFields[field]
					liveValue, liveOK := liveFields[field]
					if !expectedOK {
						expectedValue = json.RawMessage(`null`)
					}
					if !liveOK {
						liveValue = json.RawMessage(`null`)
					}
					expectedSHA, expectedPreview := orderedCurrentNative379V2DiagnosticField(expectedValue)
					liveSHA, livePreview := orderedCurrentNative379V2DiagnosticField(liveValue)
					changedFieldSamples[want.Kind+"\x00"+orderedCurrentNative379V2DiagnosticRule(want.Identity)+"\x00"+field] = orderedCurrentNative379V2CatalogDiagnosticChangedFieldSample{Kind: want.Kind, Rule: orderedCurrentNative379V2DiagnosticRule(want.Identity), Field: field, ExpectedSHA256: expectedSHA, LiveSHA256: liveSHA, ExpectedPreview: expectedPreview, LivePreview: livePreview}
				}
			}
			entries = append(entries, orderedCurrentNative379V2CatalogDiagnosticEntry{Class: "changed", Kind: want.Kind, Identity: want.Identity, ExpectedSHA256: orderedCurrentNative379V2SHA256(wantCanonical), LiveSHA256: orderedCurrentNative379V2SHA256(gotCanonical), ExpectedPreview: wantPreview, LivePreview: gotPreview})
		}
	}
	for key, got := range liveByKey {
		if _, exists := expectedByKey[key]; exists {
			continue
		}
		diagnostic.Extra++
		record("extra", got)
		canonical, preview := orderedCurrentNative379V2DiagnosticFact(got.Fact)
		entries = append(entries, orderedCurrentNative379V2CatalogDiagnosticEntry{Class: "extra", Kind: got.Kind, Identity: got.Identity, LiveSHA256: orderedCurrentNative379V2SHA256(canonical), LivePreview: preview})
	}
	// A relocation is a missing/extra pair with the same kind, rule and exact
	// fact bytes. Emit a representative only for one-to-one buckets; ambiguous
	// buckets remain counted but are never silently paired.
	type relocationBucket struct {
		missing []orderedCurrentNative379V2Fact
		extra   []orderedCurrentNative379V2Fact
	}
	relocationBuckets := make(map[string]*relocationBucket)
	for key, want := range expectedByKey {
		if _, exists := liveByKey[key]; exists {
			continue
		}
		factCanonical, _ := orderedCurrentNative379V2DiagnosticFact(want.Fact)
		factSHA := orderedCurrentNative379V2SHA256(factCanonical)
		relocationKey := want.Kind + "\x00" + orderedCurrentNative379V2DiagnosticRule(want.Identity) + "\x00" + factSHA
		bucket := relocationBuckets[relocationKey]
		if bucket == nil {
			bucket = &relocationBucket{}
			relocationBuckets[relocationKey] = bucket
		}
		bucket.missing = append(bucket.missing, want)
	}
	for key, got := range liveByKey {
		if _, exists := expectedByKey[key]; exists {
			continue
		}
		factCanonical, _ := orderedCurrentNative379V2DiagnosticFact(got.Fact)
		factSHA := orderedCurrentNative379V2SHA256(factCanonical)
		parts := strings.SplitN(got.Kind+"\x00"+orderedCurrentNative379V2DiagnosticRule(got.Identity)+"\x00"+factSHA, "\x00", 3)
		relocationKey := strings.Join(parts, "\x00")
		bucket := relocationBuckets[relocationKey]
		if bucket == nil {
			bucket = &relocationBucket{}
			relocationBuckets[relocationKey] = bucket
		}
		bucket.extra = append(bucket.extra, got)
	}
	relocationKeys := make([]string, 0, len(relocationBuckets))
	for key, bucket := range relocationBuckets {
		if len(bucket.missing) == 0 || len(bucket.extra) == 0 {
			continue
		}
		relocationKeys = append(relocationKeys, key)
	}
	sort.Strings(relocationKeys)
	for _, key := range relocationKeys {
		parts := strings.SplitN(key, "\x00", 3)
		bucket := relocationBuckets[key]
		diagnostic.RelocationCounts = append(diagnostic.RelocationCounts, orderedCurrentNative379V2CatalogDiagnosticRelocationCount{Kind: parts[0], Rule: parts[1], FactSHA256: parts[2], Count: len(bucket.missing) + len(bucket.extra)})
		if len(bucket.missing) == 1 && len(bucket.extra) == 1 {
			diagnostic.Relocations = append(diagnostic.Relocations, orderedCurrentNative379V2CatalogDiagnosticRelocation{Kind: parts[0], Rule: parts[1], FactSHA256: parts[2], BeforeIdentity: bucket.missing[0].Identity, AfterIdentity: bucket.extra[0].Identity})
		} else {
			diagnostic.RelocationAmbiguities++
		}
	}
	if len(diagnostic.RelocationCounts) > 1 {
		sort.Slice(diagnostic.RelocationCounts, func(left, right int) bool {
			if diagnostic.RelocationCounts[left].Count != diagnostic.RelocationCounts[right].Count {
				return diagnostic.RelocationCounts[left].Count > diagnostic.RelocationCounts[right].Count
			}
			return diagnostic.RelocationCounts[left].Kind+"\x00"+diagnostic.RelocationCounts[left].Rule+"\x00"+diagnostic.RelocationCounts[left].FactSHA256 < diagnostic.RelocationCounts[right].Kind+"\x00"+diagnostic.RelocationCounts[right].Rule+"\x00"+diagnostic.RelocationCounts[right].FactSHA256
		})
	}
	if len(diagnostic.Relocations) > 1 {
		sort.Slice(diagnostic.Relocations, func(left, right int) bool {
			return diagnostic.Relocations[left].Kind+"\x00"+diagnostic.Relocations[left].Rule+"\x00"+diagnostic.Relocations[left].BeforeIdentity < diagnostic.Relocations[right].Kind+"\x00"+diagnostic.Relocations[right].Rule+"\x00"+diagnostic.Relocations[right].BeforeIdentity
		})
	}
	if len(diagnostic.RelocationCounts) > 32 {
		diagnostic.RelocationCounts = diagnostic.RelocationCounts[:32]
		diagnostic.CountOverflow = true
	}
	if len(diagnostic.Relocations) > 16 {
		diagnostic.Relocations = diagnostic.Relocations[:16]
		diagnostic.CountOverflow = true
	}
	classOrder := map[string]int{"duplicate": 0, "changed": 1, "extra": 2, "missing": 3}
	sort.Slice(entries, func(left, right int) bool {
		if classOrder[entries[left].Class] != classOrder[entries[right].Class] {
			return classOrder[entries[left].Class] < classOrder[entries[right].Class]
		}
		if entries[left].Kind != entries[right].Kind {
			return entries[left].Kind < entries[right].Kind
		}
		return entries[left].Identity < entries[right].Identity
	})
	if maxEntries < len(entries) {
		diagnostic.Overflow = true
		if maxEntries < 0 {
			maxEntries = 0
		}
		classSet := make(map[string]bool)
		for _, entry := range entries {
			classSet[entry.Class] = true
		}
		if maxEntries >= len(classSet) {
			balanced := make([]orderedCurrentNative379V2CatalogDiagnosticEntry, 0, maxEntries)
			selected := make(map[string]bool)
			groups := make(map[string]map[string]bool)
			for _, class := range []string{"changed", "missing", "extra", "duplicate"} {
				for _, entry := range entries {
					if entry.Class == class {
						key := class + "\x00" + entry.Kind + "\x00" + entry.Identity
						balanced = append(balanced, entry)
						selected[key] = true
						if groups[class] == nil {
							groups[class] = make(map[string]bool)
						}
						groups[class][entry.Kind+"\x00"+orderedCurrentNative379V2DiagnosticRule(entry.Identity)] = true
						break
					}
				}
			}
			for len(balanced) < maxEntries {
				progress := false
				for _, class := range []string{"changed", "missing", "extra", "duplicate"} {
					if len(balanced) == maxEntries {
						break
					}
					for _, entry := range entries {
						if entry.Class != class {
							continue
						}
						key := entry.Class + "\x00" + entry.Kind + "\x00" + entry.Identity
						group := entry.Kind + "\x00" + orderedCurrentNative379V2DiagnosticRule(entry.Identity)
						if selected[key] || groups[class][group] {
							continue
						}
						balanced = append(balanced, entry)
						selected[key] = true
						groups[class][group] = true
						progress = true
						break
					}
				}
				if len(balanced) == maxEntries || !progress {
					break
				}
			}
			for len(balanced) < maxEntries {
				progress := false
				for _, entry := range entries {
					if len(balanced) == maxEntries {
						break
					}
					key := entry.Class + "\x00" + entry.Kind + "\x00" + entry.Identity
					if !selected[key] {
						balanced = append(balanced, entry)
						selected[key] = true
						progress = true
					}
				}
				if !progress {
					break
				}
			}
			sort.Slice(balanced, func(left, right int) bool {
				if classOrder[balanced[left].Class] != classOrder[balanced[right].Class] {
					return classOrder[balanced[left].Class] < classOrder[balanced[right].Class]
				}
				if balanced[left].Kind != balanced[right].Kind {
					return balanced[left].Kind < balanced[right].Kind
				}
				return balanced[left].Identity < balanced[right].Identity
			})
			entries = balanced
		} else {
			entries = entries[:maxEntries]
		}
	}
	diagnostic.ClassCounts, _ = orderedCurrentNative379V2DiagnosticCounts(classCounts, 8)
	var kindOverflow, ruleOverflow bool
	diagnostic.KindCounts, kindOverflow = orderedCurrentNative379V2DiagnosticCounts(kindCounts, 64)
	diagnostic.RuleCounts, ruleOverflow = orderedCurrentNative379V2DiagnosticCounts(ruleCounts, 64)
	var kindClassOverflow, ruleClassOverflow bool
	diagnostic.KindClassCounts, kindClassOverflow = orderedCurrentNative379V2DiagnosticClassCounts(kindClassCounts, 64)
	diagnostic.RuleClassCounts, ruleClassOverflow = orderedCurrentNative379V2DiagnosticClassCounts(ruleClassCounts, 64)
	var fieldOverflow bool
	diagnostic.ChangedFieldCounts, fieldOverflow = orderedCurrentNative379V2DiagnosticChangedFieldCounts(changedFieldCounts, 64)
	fieldSampleKeys := make([]string, 0, len(changedFieldSamples))
	for key := range changedFieldSamples {
		fieldSampleKeys = append(fieldSampleKeys, key)
	}
	sort.Strings(fieldSampleKeys)
	if len(fieldSampleKeys) > 32 {
		fieldSampleKeys = fieldSampleKeys[:32]
		diagnostic.CountOverflow = true
	}
	diagnostic.ChangedFieldSamples = make([]orderedCurrentNative379V2CatalogDiagnosticChangedFieldSample, 0, len(fieldSampleKeys))
	for _, key := range fieldSampleKeys {
		diagnostic.ChangedFieldSamples = append(diagnostic.ChangedFieldSamples, changedFieldSamples[key])
	}
	diagnostic.CountOverflow = diagnostic.CountOverflow || kindOverflow || ruleOverflow || kindClassOverflow || ruleClassOverflow || fieldOverflow
	diagnostic.Entries = entries
	return diagnostic
}

func orderedCurrentNative379V2CollectCatalogDiagnostic(ctx context.Context, tx pgx.Tx, packet orderedCurrentNative379V2Packet, collector []byte) orderedCurrentNative379V2CatalogDiagnostic {
	const maxEntries = 20
	collectorSQL := strings.TrimSpace(string(collector))
	collectorSQL = strings.TrimSuffix(collectorSQL, ";")
	if collectorSQL == "" || orderedCurrentNative379V2SHA256(collector) != orderedCurrentNative379V2CollectorSHA256 {
		return orderedCurrentNative379V2CatalogDiagnostic{Overflow: true, Error: "collector source admission refused", Entries: []orderedCurrentNative379V2CatalogDiagnosticEntry{}}
	}
	maxRows, maxBytes := packet.Limits.MaxRows, packet.Limits.MaxBytes
	query := "SELECT kind,identity,fact::text FROM (" + collectorSQL + ") native379_live ORDER BY kind COLLATE \"C\",identity COLLATE \"C\""
	rows, err := tx.Query(ctx, query)
	if err != nil {
		message := "collector query refused"
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			message = fmt.Sprintf("collector query refused: sqlstate=%s", pgErr.Code)
		}
		return orderedCurrentNative379V2CatalogDiagnostic{Overflow: true, Error: message, Entries: []orderedCurrentNative379V2CatalogDiagnosticEntry{}}
	}
	defer rows.Close()
	live := make([]orderedCurrentNative379V2Fact, 0, maxRows+1)
	bytesSeen := 0
	for rows.Next() {
		var fact orderedCurrentNative379V2Fact
		var raw string
		if err := rows.Scan(&fact.Kind, &fact.Identity, &raw); err != nil {
			return orderedCurrentNative379V2CatalogDiagnostic{Overflow: true, Error: "collector row refused", Entries: []orderedCurrentNative379V2CatalogDiagnosticEntry{}}
		}
		fact.Fact = json.RawMessage(raw)
		if err := native379V2Charge(ctx, 1, fact); err != nil {
			return orderedCurrentNative379V2CatalogDiagnostic{Overflow: true, Error: "collector runtime budget refused", Entries: []orderedCurrentNative379V2CatalogDiagnosticEntry{}}
		}
		live = append(live, fact)
		bytesSeen += len(fact.Kind) + len(fact.Identity) + len(fact.Fact)
		if len(live) > maxRows || bytesSeen > maxBytes {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return orderedCurrentNative379V2CatalogDiagnostic{Overflow: true, Error: "collector stream refused", Entries: []orderedCurrentNative379V2CatalogDiagnosticEntry{}}
	}
	return orderedCurrentNative379V2BuildCatalogDiagnostic(packet.ExpectedFacts, live, maxEntries, maxRows, maxBytes)
}

func orderedCurrentNative379V2CatalogFailure(diagnostic orderedCurrentNative379V2CatalogDiagnostic) error {
	raw, err := json.Marshal(diagnostic)
	if err != nil || len(raw) > 32768 {
		raw = []byte(`{"overflow":true,"error":"diagnostic encoding refused","entries":[]}`)
	}
	return fmt.Errorf("native379 pristine catalog equality refused: diagnostic=%s", raw)
}

func validateOrderedCurrentNative379V2PacketControls(packet orderedCurrentNative379V2Packet) error {
	if len(packet.Controls) != 589 {
		return errors.New("native379 control cardinality refused")
	}
	byID := make(map[string]orderedCurrentNative379V2Control, len(packet.Controls))
	for _, control := range packet.Controls {
		mutationSHA, err := orderedCurrentNative379V2CanonicalSHA256(control.Mutation)
		transactionStatus := control.Restoration.ProtocolTransactionStatusAfter
		if transactionStatus == "" {
			transactionStatus = control.Restoration.ExpectedTransactionStatus
		}
		if err != nil || control.ID == "" || control.Phase == "" || control.Category == "" || control.MutationSHA256 != mutationSHA || byID[control.ID].ID != "" || control.Program.Format != "native379-sql-program-v1" || len(control.Program.Steps) < 3 {
			return fmt.Errorf("native379 control envelope refused: %s", control.ID)
		}
		if !control.Restoration.BeforeNextProbe || control.Restoration.TimeoutIsDenial || control.Restoration.SnapshotSQL == "" || !strings.HasPrefix(control.Restoration.RestoreSQL, "ROLLBACK") || control.Restoration.AssertionSQL == "" || transactionStatus != "I" {
			return fmt.Errorf("native379 control restoration refused: %s", control.ID)
		}
		legacyEnvelope := control.Program.Transaction == "owned-read-write-rollback" && control.Program.Connection == "same-owned-session" && control.Program.EvaluationFrame.ID == ""
		frame := control.Program.EvaluationFrame
		entryEnvelope := control.Program.Transaction == "" && control.Program.Connection == "single-owned-session" && control.Program.ErrorContinuation != "" && control.Program.RoleSemantics != "" && frame.CommitForbidden && frame.Isolation == "repeatable read" && frame.Visibility == "same-connection-uncommitted-mutation" && ((frame.ID == "protected-evaluation" && frame.Access == "read-only") || (frame.ID == "mutation-envelope" && frame.Access == "read-write"))
		if !legacyEnvelope && !entryEnvelope {
			return fmt.Errorf("native379 control transaction envelope refused: %s", control.ID)
		}
		seenStep := make(map[string]bool, len(control.Program.Steps))
		probe, restore := false, false
		allowedRoles := map[string]bool{"zasp_test": true, "fixture-owner": true, "zasp_discovery_authority": true, "zasp_security_agent_worker": true}
		allowedOutcomes := map[string]bool{"command-success": true, "command-complete": true, "capture": true, "equal-captured": true, "rows": true, "one-row": true, "one-json-row": true, "error": true}
		for _, step := range control.Program.Steps {
			if step.ID == "" || !allowedRoles[step.Role] || step.SQL == "" || !allowedOutcomes[step.Expected.Outcome] || step.SQLSHA256 != orderedCurrentNative379V2SHA256([]byte(step.SQL)) || seenStep[step.ID] {
				return errors.New("native379 control step refused")
			}
			if step.Expected.Outcome == "error" && (step.Expected.SQLState == nil || len(*step.Expected.SQLState) != 5) {
				return errors.New("native379 error SQLSTATE refused")
			}
			if step.Expected.Outcome == "rows" && len(step.Expected.Rows) == 0 || (step.Expected.Outcome == "one-row" || step.Expected.Outcome == "one-json-row") && len(step.Expected.Value) == 0 || (step.Expected.Outcome == "capture" || step.Expected.Outcome == "equal-captured") && step.Expected.Key == "" {
				return errors.New("native379 step expectation grammar refused")
			}
			seenStep[step.ID] = true
			probe = probe || step.ID == "probe"
			restore = restore || step.ID == "restore"
		}
		if !probe || !restore {
			return errors.New("native379 control probe or rollback refused")
		}
		byID[control.ID] = control
	}
	used := make(map[string]bool, len(packet.Controls))
	for _, phase := range packet.Phases {
		for _, id := range phase.ControlIDs {
			control, ok := byID[id]
			if !ok || used[id] || control.Phase != phase.ID {
				return errors.New("native379 phase control ordering refused")
			}
			used[id] = true
		}
	}
	if len(used) != len(packet.Controls) {
		return errors.New("native379 missing phase control refused")
	}
	return nil
}

func cloneOrderedCurrentNative379V2ControlResults(value []orderedCurrentNative379V2ControlResult) []orderedCurrentNative379V2ControlResult {
	raw, _ := json.Marshal(value)
	var copy []orderedCurrentNative379V2ControlResult
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func validateOrderedCurrentNative379V2ControlResults(packet orderedCurrentNative379V2Packet, results []orderedCurrentNative379V2ControlResult) error {
	if native379V2TetherPacket(packet) != nil || validateOrderedCurrentNative379V2PacketControls(packet) != nil || len(results) != len(packet.Controls) {
		return errors.New("native379 control results incomplete")
	}
	byID := make(map[string]orderedCurrentNative379V2Control, len(packet.Controls))
	phaseLimit := make(map[string]int64, len(packet.Phases))
	for _, control := range packet.Controls {
		byID[control.ID] = control
	}
	for _, phase := range packet.Phases {
		phaseLimit[phase.ID] = int64(phase.Limits.MaxMilliseconds)
	}
	evidenceBudget := native379V2NewBudget(packet)
	pristineCtx, pristineCancel, budgetErr := evidenceBudget.phase(context.Background(), "pristine-truth")
	if budgetErr != nil {
		return budgetErr
	}
	defer pristineCancel()
	for _, fact := range packet.ExpectedFacts {
		if err := native379V2Charge(pristineCtx, 1, map[string]any{"kind": fact.Kind, "identity": fact.Identity, "fact": fact.Fact}); err != nil {
			return err
		}
	}
	index := 0
	phaseDuration := make(map[string]int64, len(packet.Phases))
	boundSessionUser := ""
	var boundBackendPID int32
	for _, phase := range packet.Phases {
		evidenceCtx, cancel, e := evidenceBudget.phase(context.Background(), phase.ID)
		if e != nil {
			return e
		}
		defer cancel()
		for _, id := range phase.ControlIDs {
			if index >= len(results) {
				return errors.New("native379 truncated control results refused")
			}
			control, result := byID[id], results[index]
			if result.ID != id || result.Phase != phase.ID || result.MutationSHA256 != control.MutationSHA256 || !result.Restored || result.Milliseconds < 0 || len(result.Steps) != len(control.Program.Steps) {
				return errors.New("native379 control result identity or restoration refused")
			}
			if result.Milliseconds > phaseLimit[phase.ID]-phaseDuration[phase.ID] {
				return errors.New("native379 v2 control phase time overflow")
			}
			phaseDuration[phase.ID] += result.Milliseconds
			captures := map[string]any{}
			var poisonReceiptSHA string
			var assertionElapsed int64
			for stepIndex, step := range control.Program.Steps {
				got := result.Steps[stepIndex]
				wantState := "00000"
				if step.Expected.SQLState != nil {
					wantState = *step.Expected.SQLState
				}
				canonical, canonicalErr := orderedCurrentNative379V2CanonicalJSON(got.Observation)
				var observedValue any
				decoder := json.NewDecoder(bytes.NewReader(got.Observation))
				decoder.UseNumber()
				if decoder.Decode(&observedValue) != nil {
					return errors.New("native379 v2 observation preimage refused")
				}
				if rows, ok := observedValue.([]any); ok {
					for _, row := range rows {
						if err := native379V2Charge(evidenceCtx, 1, row); err != nil {
							return err
						}
					}
				} else {
					if err := native379V2Charge(evidenceCtx, 0, observedValue); err != nil {
						return err
					}
				}
				wantRoleObservation, wantAssertedRole, placementErr := native379V2RolePlacement(control, stepIndex)
				if placementErr != nil {
					return placementErr
				}
				wantAssertedRole = orderedCurrentNative379V2ExpectedAssertedRole(wantAssertedRole, got.BoundSessionUser)
				if wantRoleObservation == "after-recovery" {
					if stepIndex == 0 {
						return errors.New("native379 v2 recovery predecessor absent")
					}
					predecessor, state, err := native379V2RecoveryEvidence(control, stepIndex, result.Steps[stepIndex-1])
					if err != nil {
						return err
					}
					if got.RecoveryPredecessorSHA256 != predecessor || got.RecoverySQLState != state {
						return errors.New("native379 v2 recovery assertion link refused")
					}
				} else if got.RecoveryPredecessorSHA256 != "" || got.RecoverySQLState != "" {
					return errors.New("native379 v2 unexpected recovery evidence")
				}

				binding := native379V2SessionBinding{ControlID: control.ID, User: got.BoundSessionUser, PID: got.BoundBackendPID}
				if wantRoleObservation == "before-poison" {
					if got.RoleAssertion != nil || got.CarriedAssertionSHA256 == "" || got.CarriedAssertionSHA256 != poisonReceiptSHA || stepIndex == 0 || result.Steps[stepIndex-1].SQLState != "22012" {
						return errors.New("native379 v2 carried before-poison assertion refused")
					}
				} else {
					if got.RoleAssertion == nil || got.CarriedAssertionSHA256 != "" {
						return errors.New("native379 v2 required role assertion omitted")
					}
					if err := native379V2ValidateAssertionReceipt(*got.RoleAssertion, binding, step, wantRoleObservation, wantAssertedRole); err != nil {
						return err
					}
					if err := native379V2Charge(evidenceCtx, 0, *got.RoleAssertion); err != nil {
						return err
					}
					if got.RoleAssertion.ElapsedNanoseconds > (result.Milliseconds+1)*int64(time.Millisecond)-assertionElapsed {
						return errors.New("native379 v2 assertion elapsed aggregate overflow")
					}
					assertionElapsed += got.RoleAssertion.ElapsedNanoseconds
					if control.ID == "restore:transaction" && step.ID == "mutate" {
						poisonReceiptSHA = native379V2AssertionReceiptSHA(*got.RoleAssertion)
					}
				}
				if boundSessionUser == "" {
					boundSessionUser = got.BoundSessionUser
				}
				if boundBackendPID == 0 {
					boundBackendPID = got.BoundBackendPID
				}
				if got.BoundBackendPID <= 0 || got.BoundBackendPID != boundBackendPID || !native379V2ObservedStepMatches(step, got, captures) {
					return errors.New("native379 v2 independently checked observed outcome refused")
				}
				if got.ID != step.ID || got.Outcome != step.Expected.Outcome || got.SQLState != wantState || got.DeclaredRole != step.Role || got.BoundSessionUser == "" || got.BoundSessionUser != boundSessionUser || got.RoleObservation != wantRoleObservation || canonicalErr != nil || !bytes.Equal(canonical, got.Observation) || len(got.ObservedSHA256) != 64 || got.ObservedSHA256 != strings.ToLower(got.ObservedSHA256) || got.ObservedSHA256 != orderedCurrentNative379V2SHA256(canonical) || !got.Matched || got.TimedOut {
					return errors.New("native379 control step evidence refused")
				}
			}
			if assertionElapsed > (result.Milliseconds+1)*int64(time.Millisecond) {
				return errors.New("native379 v2 assertion time exceeds control observation")
			}
			index++
		}
	}
	for phase, duration := range phaseDuration {
		if duration > phaseLimit[phase] {
			return errors.New("native379 control phase duration overflow")
		}
	}
	return nil
}

// Raw is the authority; every public execution/result boundary checks that the
// entire typed projection still equals its authenticated immutable wire.
func native379V2TetherPacket(packet orderedCurrentNative379V2Packet) error {
	if len(packet.Raw) == 0 || !native379V2ValidSHA(packet.admittedRawSHA) || packet.WireSHA256 != packet.admittedRawSHA || orderedCurrentNative379V2SHA256(packet.Raw) != packet.admittedRawSHA {
		return errors.New("native379 v2 raw identity changed")
	}
	var fresh orderedCurrentNative379V2Packet
	if err := json.Unmarshal(packet.Raw, &fresh); err != nil {
		return errors.New("native379 v2 raw projection refused")
	}
	fresh.WireSHA256 = packet.WireSHA256
	actual, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(fresh)
	if err != nil || !bytes.Equal(actual, expected) {
		return errors.New("native379 v2 typed projection changed")
	}
	return nil
}
func validateOrderedCurrentNative379V2PacketStructure(packet orderedCurrentNative379V2Packet) error {
	if err := native379V2TetherPacket(packet); err != nil {
		return err
	}
	if len(packet.Rules) != 379 {
		return errors.New("native379 v2 full rule cardinality required")
	}
	if err := native379V2PacketMetadata(packet); err != nil {
		return err
	}
	if len(packet.WireSHA256) != 64 || packet.Format != "ordered-current-native379-packet-v2" || packet.Status != "NATIVE-PARITY-PENDING" || packet.Installable || packet.NativeVerified || packet.CaptureAuthority {
		return errors.New("native379 packet envelope or wire pin refused")
	}
	if packet.Identity.ServerVersionNum != 180003 || packet.Identity.Postgres == "" || packet.Identity.Pgcrypto != "1.4" {
		return errors.New("native379 PostgreSQL identity refused")
	}
	if !native379V2ValidSHA(packet.Authority.Generated[orderedCurrentNative379V2ModuleFile]) || !native379V2ValidSHA(packet.Authority.Generated["development-manifest.json"]) || !native379V2ValidSHA(packet.Authority.Generated[orderedCurrentNative379V2CollectorFile]) {
		return errors.New("native379 generated source pins refused")
	}
	if len(packet.Rules) != 379 || len(packet.ExpectedFacts) != 10052 || len(packet.SourceInventory.Sites) != 565 || packet.SourceInventory.Unclassified != 0 {
		return errors.New("native379 inventory cardinality refused")
	}
	seen := make(map[string]bool, len(packet.Rules))
	total := 1 // reserved build/provenance row is not owned by a descriptor
	for _, rule := range packet.Rules {
		if rule.ID == "" || rule.ExpectedFacts < 0 || seen[rule.ID] {
			return errors.New("native379 rule identity refused")
		}
		seen[rule.ID] = true
		total += rule.ExpectedFacts
	}
	if total != 10052 || len(packet.Entry.Manifest) != 64 || packet.Entry.ManifestLiteral != "'"+packet.Entry.Manifest+"'" || packet.Entry.IndependentAdmission.SQL == "" {
		return errors.New("native379 expected truth or entry authority refused")
	}
	if _, err := orderedCurrentNative379V2ExpectedRoutines(packet); err != nil {
		return err
	}
	if packet.Limits.MaxPacketBytes <= 0 || packet.Limits.MaxPacketBytes > 33554432 || packet.Limits.MaxRows < 10052 || packet.Limits.MaxBytes <= 0 || packet.Limits.MaxMilliseconds <= 0 || packet.Limits.SQLMilliseconds <= 0 || packet.Limits.LockMilliseconds <= 0 || packet.Limits.CleanupMilliseconds <= 0 {
		return errors.New("native379 bounds refused")
	}
	wantPhases := []string{"preflight", "pristine-truth", "drift", "forged-entry", "null-error-lazy-demand", "frame-restoration", "cleanup-result"}
	if len(packet.Phases) != len(wantPhases) {
		return errors.New("native379 phase set refused")
	}
	for index, phase := range packet.Phases {
		if phase.ID != wantPhases[index] || phase.Limits.MaxRows <= 0 || phase.Limits.MaxBytes <= 0 || phase.Limits.MaxMilliseconds <= 0 || phase.Limits.MaxRows > packet.Limits.MaxRows || phase.Limits.MaxBytes > packet.Limits.MaxBytes || phase.Limits.MaxMilliseconds > packet.Limits.MaxMilliseconds {
			return errors.New("native379 phase order or bound refused")
		}
	}
	if err := validateOrderedCurrentNative379V2PacketControls(packet); err != nil {
		return err
	}
	return nil
}

func validateOrderedCurrentNative379V2Result(packet orderedCurrentNative379V2Packet, result orderedCurrentNative379V2Result) error {
	if err := validateOrderedCurrentNative379V2PacketStructure(packet); err != nil {
		return err
	}
	if result.NativeVerified || !native379V2ValidSHA(result.BuildEnvelopeSHA256) || !reflect.DeepEqual(result.PendingGates, packet.PendingGates) || result.Format != "ordered-current-native379-result-v2" || result.Status != "LOCAL-NATIVE-COMPONENT-EVIDENCE" || result.Installable || result.Truncated || result.PacketSHA256 != packet.WireSHA256 {
		return errors.New("native379 result envelope refused")
	}
	wantStages := []string{"packet-input", "fixed-source-inputs", "owned-production-source", "dormant-install-pristine", "drift-probes", "forged-entry-probes", "semantic-probes", "frame-restoration-probes", "fixture-cleanup-join", "result-admission"}
	wantPhase := map[string]string{"packet-input": "preflight", "fixed-source-inputs": "preflight", "owned-production-source": "pristine-truth", "dormant-install-pristine": "pristine-truth", "drift-probes": "drift", "forged-entry-probes": "forged-entry", "semantic-probes": "null-error-lazy-demand", "frame-restoration-probes": "frame-restoration", "fixture-cleanup-join": "cleanup-result", "result-admission": "cleanup-result"}
	phaseLimits := make(map[string]int, len(packet.Phases))
	for _, phase := range packet.Phases {
		phaseLimits[phase.ID] = phase.Limits.MaxMilliseconds
	}
	if len(result.Stages) != len(wantStages) {
		return errors.New("native379 result stages refused")
	}
	var total int64
	phaseTotals := map[string]int64{}
	for index, stage := range result.Stages {
		if stage.ID != wantStages[index] || stage.Phase != wantPhase[stage.ID] || stage.Milliseconds < 0 || stage.Milliseconds > int64(phaseLimits[stage.Phase]) {
			return errors.New("native379 result stage order refused")
		}
		total += stage.Milliseconds
		phaseTotals[stage.Phase] += stage.Milliseconds
	}
	for phase, millis := range phaseTotals {
		if millis > int64(phaseLimits[phase]) {
			return errors.New("native379 v2 combined phase duration overflow")
		}
	}
	if total > int64(packet.Limits.MaxMilliseconds) {
		return errors.New("native379 result duration overflow")
	}
	if err := validateOrderedCurrentNative379V2ControlResults(packet, result.Controls); err != nil {
		return err
	}
	if err := native379V2ValidateBudgetEvidence(packet, result.Controls, result.Budget); err != nil {
		return err
	}
	var fixedIdentity []json.RawMessage
	_ = json.Unmarshal(result.Budget.Fixed["preinstall"], &fixedIdentity)
	var fixedPort int
	_ = json.Unmarshal(fixedIdentity[4], &fixedPort)
	if result.EndpointSHA256 != disposablePostgresEndpointSHA256(net.JoinHostPort("127.0.0.1", strconv.Itoa(fixedPort))) {
		return errors.New("native379 v2 endpoint budget preimage differs")
	}
	wantRoutines, _ := orderedCurrentNative379V2ExpectedRoutines(packet)
	if !reflect.DeepEqual(result.Hashes, map[string]string{"packet": packet.WireSHA256, "module": orderedCurrentNative379V2ModuleSHA256, "manifest": orderedCurrentNative379V2ManifestSHA256}) || result.EndpointSHA256 == "" || result.Server.VersionNum != packet.Identity.ServerVersionNum || result.Server.Postgres != packet.Identity.Postgres || result.Server.Pgcrypto != packet.Identity.Pgcrypto || result.Objects.SchemaOwner != "zasp_discovery_authority" || !reflect.DeepEqual(result.Objects.Tables, []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}) || !reflect.DeepEqual(result.Objects.Routines, wantRoutines) || result.Objects.UnexpectedGrants != 0 || result.Counts.Rules != 379 || result.Counts.Facts != 10052 || result.Counts.RoleSites != 565 || result.Counts.Registration != 1 || result.Counts.ExpectedRows != 10052 || result.Counts.EqualFacts != 10052 || result.Counts.Tables != 2 || result.Counts.Routines != 8 || validateOrderedCurrentNative379V2Operations(result.Operations) != nil || !result.Restoration.TransactionRolledBack || !result.Restoration.FrameRestored || !result.Cleanup.PGCtlStopped || !result.Cleanup.EndpointChecked || result.Cleanup.EndpointSHA256 != result.EndpointSHA256 || !result.Cleanup.Joined || !result.Cleanup.NormalExit || !result.Cleanup.SurvivingResourcesChecked || result.Cleanup.SurvivingResources != 0 {
		return errors.New("native379 result evidence refused")
	}
	return nil
}

func buildOrderedCurrentNative379V2Result(packet orderedCurrentNative379V2Packet, observation *orderedCurrentNative379V2Observation, cleanup *disposablePostgresCleanupObservation, stages []orderedCurrentNative379V2Stage) (orderedCurrentNative379V2Result, error) {
	var result orderedCurrentNative379V2Result
	if observation == nil || cleanup == nil {
		return result, errors.New("native379 observed evidence absent")
	}
	if err := validateOrderedCurrentNative379V2PacketStructure(packet); err != nil {
		return result, err
	}
	wantRoutines, err := orderedCurrentNative379V2ExpectedRoutines(packet)
	if err != nil {
		return result, err
	}
	wantHashes := map[string]string{"packet": packet.WireSHA256, "module": orderedCurrentNative379V2ModuleSHA256, "manifest": orderedCurrentNative379V2ManifestSHA256}
	if !observation.Available || observation.EndpointSHA256 == "" || !reflect.DeepEqual(observation.Hashes, wantHashes) || observation.Server.VersionNum != packet.Identity.ServerVersionNum || observation.Server.Postgres != packet.Identity.Postgres || observation.Server.Pgcrypto != packet.Identity.Pgcrypto {
		return result, errors.New("native379 observed hashes or server identity refused")
	}
	if observation.Objects.SchemaOwner != "zasp_discovery_authority" || !reflect.DeepEqual(observation.Objects.Tables, []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}) || !reflect.DeepEqual(observation.Objects.Routines, wantRoutines) || observation.Objects.UnexpectedGrants != 0 {
		return result, errors.New("native379 observed object inventory or grants refused")
	}
	if observation.Counts.Rules != len(packet.Rules) || observation.Counts.Facts != len(packet.ExpectedFacts) || observation.Counts.RoleSites != len(packet.SourceInventory.Sites) || observation.Counts.Registration != 1 || observation.Counts.ExpectedRows != len(packet.ExpectedFacts) || observation.Counts.EqualFacts != len(packet.ExpectedFacts) || validateOrderedCurrentNative379V2Operations(observation.Operations) != nil || validateOrderedCurrentNative379V2ControlResults(packet, observation.Controls) != nil || !observation.Restoration.TransactionRolledBack || !observation.Restoration.FrameRestored {
		return result, errors.New("native379 observed counts, SQLSTATEs, or restoration refused")
	}
	clean := cleanup.snapshot()
	if !clean.Available || !clean.PGCtlStopped || !clean.CommandWaitJoined || !clean.NormalExit || !clean.EndpointChecked || clean.EndpointSHA256 == "" || clean.EndpointSHA256 != observation.EndpointSHA256 || !clean.SurvivingResourcesChecked || clean.SurvivingResources != 0 {
		return result, errors.New("native379 structured cleanup evidence refused")
	}
	result.Format, result.Status, result.PacketSHA256 = "ordered-current-native379-result-v2", "LOCAL-NATIVE-COMPONENT-EVIDENCE", packet.WireSHA256
	result.BuildEnvelopeSHA256 = os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD_SHA256")
	result.PendingGates = append([]string(nil), packet.PendingGates...)
	result.Stages = append([]orderedCurrentNative379V2Stage(nil), stages...)
	result.Budget = observation.clone().Budget
	result.Hashes = maps.Clone(observation.Hashes)
	result.EndpointSHA256 = observation.EndpointSHA256
	result.Server.VersionNum, result.Server.Postgres, result.Server.Pgcrypto = observation.Server.VersionNum, observation.Server.Postgres, observation.Server.Pgcrypto
	result.Objects.SchemaOwner = observation.Objects.SchemaOwner
	result.Objects.Tables = append([]string(nil), observation.Objects.Tables...)
	result.Objects.Routines = append([]string(nil), observation.Objects.Routines...)
	result.Objects.UnexpectedGrants = observation.Objects.UnexpectedGrants
	result.Counts.Rules, result.Counts.Facts, result.Counts.RoleSites = observation.Counts.Rules, observation.Counts.Facts, observation.Counts.RoleSites
	result.Counts.Registration, result.Counts.ExpectedRows, result.Counts.EqualFacts = observation.Counts.Registration, observation.Counts.ExpectedRows, observation.Counts.EqualFacts
	result.Counts.Tables, result.Counts.Routines = len(observation.Objects.Tables), len(observation.Objects.Routines)
	result.Operations = append([]orderedCurrentNative379V2Operation(nil), observation.Operations...)
	result.Controls = cloneOrderedCurrentNative379V2ControlResults(observation.Controls)
	result.Restoration.TransactionRolledBack, result.Restoration.FrameRestored = observation.Restoration.TransactionRolledBack, observation.Restoration.FrameRestored
	result.Cleanup.PGCtlStopped, result.Cleanup.EndpointChecked, result.Cleanup.EndpointSHA256 = clean.PGCtlStopped, clean.EndpointChecked, clean.EndpointSHA256
	result.Cleanup.Joined, result.Cleanup.NormalExit = clean.CommandWaitJoined, clean.NormalExit
	result.Cleanup.SurvivingResourcesChecked, result.Cleanup.SurvivingResources = clean.SurvivingResourcesChecked, clean.SurvivingResources
	if err := validateOrderedCurrentNative379V2Result(packet, result); err != nil {
		return orderedCurrentNative379V2Result{}, err
	}
	return result, nil
}

func publishOrderedCurrentNative379V2Result(destination string, result orderedCurrentNative379V2Result, maxBytes int) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || maxBytes <= 0 || maxBytes > orderedCurrentNative379V2MaxResultBytes {
		return errors.New("native379 result destination or bound refused")
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw)+1 > maxBytes {
		return errors.New("native379 result encoding or byte bound refused")
	}
	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, ".native379-result-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(append(raw, '\n'))
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(name, destination); err != nil {
		return err
	}
	published, readErr := os.ReadFile(destination)
	info, statErr := os.Lstat(destination)
	if readErr != nil || statErr != nil || info.Mode().Perm() != 0o600 || !bytes.Equal(published, append(raw, '\n')) {
		return errors.New("native379 published result verification refused")
	}
	dir, err := os.Open(directory)
	if err == nil {
		err = dir.Sync()
		_ = dir.Close()
	}
	return err
}

type orderedCurrentNative379V2LimitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (writer *orderedCurrentNative379V2LimitedBuffer) Write(value []byte) (int, error) {
	if len(value) > writer.limit-writer.buffer.Len() {
		return 0, errors.New("native379 subprocess output overflow")
	}
	return writer.buffer.Write(value)
}

func orderedCurrentNative379V2Root() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func loadOrderedCurrentNative379V2Packet(ctx context.Context) (orderedCurrentNative379V2AdmittedPacket, error) {
	raw, err := generateOrderedCurrentNative379V2PacketRaw(ctx)
	if err != nil {
		return orderedCurrentNative379V2AdmittedPacket{}, err
	}
	return admitOrderedCurrentNative379V2PacketRaw(raw)
}

func validateOrderedCurrentNative379V2Admission(admission orderedCurrentNative379V2AdmittedPacket) error {
	if admission.rawSHA != orderedCurrentNative379V2PacketSHA256 || admission.rawBytes != len(admission.packet.Raw) || admission.rawBytes <= 0 || admission.rawBytes > 33554432 || orderedCurrentNative379V2SHA256(admission.packet.Raw) != admission.rawSHA || admission.packet.WireSHA256 != admission.rawSHA {
		return errors.New("native379 raw admission token refused")
	}
	if err := validateOrderedCurrentNative379V2PacketStructure(admission.packet); err != nil {
		return err
	}
	if err := native379V2RequireFeasibleRows(admission.packet); err != nil {
		return err
	}
	_, err := native379V2AdmitReviewedRaw(admission.packet.Raw, orderedCurrentNative379V2PacketSHA256)
	return err
}

// These variables make the subprocess boundary replaceable by narrow offline
// tests without adding a production API or weakening the opt-in native path.
var (
	native379V2ExecLookPath       = exec.LookPath
	native379V2ExecCommandContext = exec.CommandContext
)

func orderedCurrentNative379V2Duration(start time.Time) int64 {
	value := time.Since(start).Milliseconds()
	if value < 0 {
		return 0
	}
	return value
}

func orderedCurrentNative379V2File(path, expected string, max int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > int64(max) {
		return nil, errors.New("native379 fixed source file refused")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expected {
		return nil, errors.New("native379 fixed source hash refused")
	}
	return raw, nil
}

const orderedCurrentNative379V2PreinstallIdentitySQL = `SELECT current_setting('server_version_num')::integer,version(),COALESCE((SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),''),host(inet_server_addr()),inet_server_port(),(SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname='zasp_authorization80_ordered_current'),(SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_authorization80_ordered_current')`

func orderedCurrentNative379V2Preinstall(ctx context.Context, owner *pgx.Conn, packet orderedCurrentNative379V2Packet, observation *orderedCurrentNative379V2Observation, recorder *orderedCurrentNative379V2OperationRecorder) error {
	if observation == nil || recorder == nil {
		return errors.New("native379 observation target absent")
	}
	var server int
	var postgres, pgcrypto, address string
	var port int
	var namespace, outputRows int
	err := owner.QueryRow(ctx, orderedCurrentNative379V2PreinstallIdentitySQL).Scan(&server, &postgres, &pgcrypto, &address, &port, &namespace, &outputRows)
	if err == nil {
		err = native379V2ChargeFixed(ctx, "preinstall", []any{server, postgres, pgcrypto, address, port, namespace, outputRows})
	}
	recorderErr := recorder.observe("preflight-identity", err)
	if recorderErr != nil || server != packet.Identity.ServerVersionNum || postgres != packet.Identity.Postgres || pgcrypto != packet.Identity.Pgcrypto || address != "127.0.0.1" || port <= 0 {
		return fmt.Errorf("native379 server or pgcrypto identity refused: query=%v server=%d want_server=%d postgres=%q want_postgres=%q pgcrypto=%q want_pgcrypto=%q address=%q port=%d", recorderErr, server, packet.Identity.ServerVersionNum, postgres, packet.Identity.Postgres, pgcrypto, packet.Identity.Pgcrypto, address, port)
	}
	if namespace != 0 || outputRows != 0 {
		return errors.New("native379 nonempty or partial target refused")
	}
	observation.Server.VersionNum, observation.Server.Postgres, observation.Server.Pgcrypto = server, postgres, pgcrypto
	observation.EndpointSHA256 = disposablePostgresEndpointSHA256(net.JoinHostPort(address, strconv.Itoa(port)))
	return nil
}

func orderedCurrentNative379V2NormalizeValue(value any) any {
	if raw, ok := value.([]byte); ok {
		var decoded any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&decoded) == nil && decoder.Decode(&struct{}{}) == io.EOF {
			return decoded
		}
		return string(raw)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if decoder.Decode(&normalized) == nil && decoder.Decode(&struct{}{}) == io.EOF {
		return normalized
	}
	return value
}

// One owned budget spans pristine streams and every control. Rows are charged
// before retention, including role/session queries, with exact canonical bytes.
type native379V2PhysicalRowRefusal struct {
	Phase                 string
	RequiredRows, MaxRows int
}

func (refusal *native379V2PhysicalRowRefusal) Error() string {
	return fmt.Sprintf("native379 v2 physical row feasibility refused: phase=%s required=%d max=%d", refusal.Phase, refusal.RequiredRows, refusal.MaxRows)
}
func native379V2PhysicalRowCosts(packet orderedCurrentNative379V2Packet) (map[string]int, error) {
	required := map[string]int{"pristine-truth": len(packet.ExpectedFacts) + 6}
	for _, control := range packet.Controls {
		required[control.Phase]++ // SessionIdentity is a real one-row query.
		for _, step := range control.Program.Steps {
			// Every role placement uses the exact zero-row assertion; no tuple is charged.
			switch step.Expected.Outcome {
			case "capture", "equal-captured", "one-row", "one-json-row":
				required[control.Phase]++
			case "rows":
				var rows []json.RawMessage
				if json.Unmarshal(step.Expected.Rows, &rows) != nil {
					return nil, errors.New("native379 v2 physical output row grammar refused")
				}
				required[control.Phase] += len(rows)
			case "command-success", "command-complete", "error":
			default:
				return nil, errors.New("native379 v2 physical row outcome refused")
			}
		}
	}
	return required, nil
}
func native379V2RequireFeasibleRows(packet orderedCurrentNative379V2Packet) error {
	required, err := native379V2PhysicalRowCosts(packet)
	if err != nil {
		return err
	}
	total := 0
	admitted := map[string]bool{}
	for _, phase := range packet.Phases {
		rows := required[phase.ID]
		admitted[phase.ID] = true
		total += rows
		if rows > phase.Limits.MaxRows {
			return &native379V2PhysicalRowRefusal{Phase: phase.ID, RequiredRows: rows, MaxRows: phase.Limits.MaxRows}
		}
	}
	for phase, rows := range required {
		if rows > 0 && !admitted[phase] {
			return errors.New("native379 v2 unknown physical row phase")
		}
	}
	if total > packet.Limits.MaxRows {
		return &native379V2PhysicalRowRefusal{Phase: "total", RequiredRows: total, MaxRows: packet.Limits.MaxRows}
	}
	return nil
}

type native379V2BudgetCharge struct {
	Phase string          `json:"phase"`
	Rows  int             `json:"rows"`
	Value json.RawMessage `json:"value"`
}
type native379V2BudgetTotals struct {
	Rows  int `json:"rows"`
	Bytes int `json:"bytes"`
}
type native379V2BudgetEvidence struct {
	Fixed   map[string]json.RawMessage         `json:"fixed"`
	Charges []native379V2BudgetCharge          `json:"charges"`
	Total   native379V2BudgetTotals            `json:"total"`
	Phases  map[string]native379V2BudgetTotals `json:"phases"`
}

func (budget *native379V2Budget) evidence() native379V2BudgetEvidence {
	result := native379V2BudgetEvidence{Fixed: maps.Clone(budget.fixed), Charges: append([]native379V2BudgetCharge(nil), budget.charges...), Total: native379V2BudgetTotals{Rows: budget.rows, Bytes: budget.bytes}, Phases: map[string]native379V2BudgetTotals{}}
	for id, rows := range budget.phaseRows {
		result.Phases[id] = native379V2BudgetTotals{Rows: rows, Bytes: budget.phaseBytes[id]}
	}
	return result
}
func native379V2ValidateBudgetEvidence(packet orderedCurrentNative379V2Packet, controls []orderedCurrentNative379V2ControlResult, evidence native379V2BudgetEvidence) error {
	budget := native379V2NewBudget(packet)
	counts := map[string]int{}
	for _, charge := range evidence.Charges {
		if charge.Rows < 0 || charge.Rows > 1 {
			return errors.New("native379 v2 budget charge cardinality refused")
		}
		canonical, err := orderedCurrentNative379V2CanonicalJSON(charge.Value)
		if err != nil || !bytes.Equal(canonical, charge.Value) {
			return errors.New("native379 v2 budget preimage refused")
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(charge.Value))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return errors.New("native379 v2 budget value refused")
		}
		ctx, cancel, err := budget.phase(context.Background(), charge.Phase)
		if err != nil {
			return err
		}
		err = native379V2Charge(ctx, charge.Rows, value)
		cancel()
		if err != nil {
			return err
		}
		counts[charge.Phase+"\x00"+strconv.Itoa(charge.Rows)+"\x00"+string(canonical)]++
	}
	actual := budget.evidence()
	if !reflect.DeepEqual(actual.Total, evidence.Total) || !reflect.DeepEqual(actual.Phases, evidence.Phases) {
		return errors.New("native379 v2 runtime budget summaries differ")
	}
	require := func(phase string, rows int, value any) error {
		encoded, err := orderedCurrentNative379V2CanonicalJSONFromValue(value)
		if err != nil {
			return err
		}
		key := phase + "\x00" + strconv.Itoa(rows) + "\x00" + string(encoded)
		if counts[key] <= 0 {
			return errors.New("native379 v2 budget observation omitted")
		}
		counts[key]--
		return nil
	}
	fixedKeys := []string{"preinstall", "inventory", "frame-before", "frame-after", "admission", "catalog"}
	if len(evidence.Fixed) != len(fixedKeys) {
		return errors.New("native379 v2 fixed budget provenance incomplete")
	}
	for _, id := range fixedKeys {
		raw, ok := evidence.Fixed[id]
		if !ok {
			return errors.New("native379 v2 fixed budget observation omitted")
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return errors.New("native379 v2 fixed budget value refused")
		}
		if err := require("pristine-truth", 1, value); err != nil {
			return err
		}
	}
	var identity []json.RawMessage
	if json.Unmarshal(evidence.Fixed["preinstall"], &identity) != nil || len(identity) != 7 {
		return errors.New("native379 v2 fixed server identity shape")
	}
	expectedIdentity := []any{packet.Identity.ServerVersionNum, packet.Identity.Postgres, packet.Identity.Pgcrypto, "127.0.0.1"}
	for i, want := range expectedIdentity {
		encoded, _ := orderedCurrentNative379V2CanonicalJSONFromValue(want)
		if !bytes.Equal(encoded, identity[i]) {
			return errors.New("native379 v2 fixed identity mismatch")
		}
	}
	var port int
	if json.Unmarshal(identity[4], &port) != nil || port <= 0 || port > 65535 || string(identity[5]) != "0" || string(identity[6]) != "0" {
		return errors.New("native379 v2 preinstall bounds refused")
	}
	routines, err := orderedCurrentNative379V2ExpectedRoutines(packet)
	if err != nil {
		return err
	}
	inventory, _ := orderedCurrentNative379V2CanonicalJSONFromValue([]any{"zasp_discovery_authority", []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}, routines, 1, len(packet.ExpectedFacts), 0})
	if !bytes.Equal(inventory, evidence.Fixed["inventory"]) || string(evidence.Fixed["admission"]) != "true" || string(evidence.Fixed["catalog"]) != "true" || !bytes.Equal(evidence.Fixed["frame-before"], evidence.Fixed["frame-after"]) {
		return errors.New("native379 v2 fixed inventory/frame/admission refused")
	}
	var frame []string
	if json.Unmarshal(evidence.Fixed["frame-before"], &frame) != nil || len(frame) != 6 || len(controls) == 0 || len(controls[0].Steps) == 0 || frame[0] != controls[0].Steps[0].BoundSessionUser || frame[1] != frame[0] {
		return errors.New("native379 v2 fixed frame shape refused")
	}

	for _, fact := range packet.ExpectedFacts {
		if err := require("pristine-truth", 1, map[string]any{"kind": fact.Kind, "identity": fact.Identity, "fact": fact.Fact}); err != nil {
			return err
		}
	}
	for _, control := range controls {
		if len(control.Steps) == 0 {
			return errors.New("native379 v2 budget control omitted")
		}
		first := control.Steps[0]
		if err := require(control.Phase, 1, map[string]any{"session_user": first.BoundSessionUser, "backend_pid": first.BoundBackendPID}); err != nil {
			return err
		}
		for _, step := range control.Steps {
			if step.RoleObservation != "before-poison" {
				if step.RoleAssertion == nil {
					return errors.New("native379 v2 budget assertion omitted")
				}
				if err := require(control.Phase, 0, *step.RoleAssertion); err != nil {
					return err
				}
			}
			var value any
			decoder := json.NewDecoder(bytes.NewReader(step.Observation))
			decoder.UseNumber()
			if decoder.Decode(&value) != nil {
				return errors.New("native379 v2 budget step preimage refused")
			}
			if rows, ok := value.([]any); ok {
				for _, row := range rows {
					if err := require(control.Phase, 1, row); err != nil {
						return err
					}
				}
			} else {
				if err := require(control.Phase, 0, value); err != nil {
					return err
				}
			}
		}
	}
	for _, count := range counts {
		if count != 0 {
			return errors.New("native379 v2 unbound budget charge")
		}
	}
	return nil
}

type native379V2BudgetKey struct{}
type native379V2PhaseKey struct{}
type native379V2PristineDeadlineKey struct{}
type native379V2Budget struct {
	fixed                 map[string]json.RawMessage
	packet                orderedCurrentNative379V2Packet
	charges               []native379V2BudgetCharge
	rows, bytes           int
	phaseRows, phaseBytes map[string]int
	deadlines             map[string]time.Time
}

func native379V2NewBudget(packet orderedCurrentNative379V2Packet) *native379V2Budget {
	return &native379V2Budget{fixed: map[string]json.RawMessage{}, packet: packet, phaseRows: map[string]int{}, phaseBytes: map[string]int{}, deadlines: map[string]time.Time{}}
}
func (budget *native379V2Budget) phase(ctx context.Context, id string) (context.Context, context.CancelFunc, error) {
	for _, phase := range budget.packet.Phases {
		if phase.ID == id {
			deadline, exists := budget.deadlines[id]
			if !exists {
				deadline = time.Now().Add(time.Duration(phase.Limits.MaxMilliseconds) * time.Millisecond)
				budget.deadlines[id] = deadline
			}
			ctx = context.WithValue(ctx, native379V2BudgetKey{}, budget)
			ctx = context.WithValue(ctx, native379V2PhaseKey{}, id)
			child, cancel := context.WithDeadline(ctx, deadline)
			return child, cancel, nil
		}
	}
	return nil, nil, errors.New("native379 v2 unknown budget phase")
}
func native379V2ChargeFixed(ctx context.Context, id string, value any) error {
	if err := native379V2Charge(ctx, 1, value); err != nil {
		return err
	}
	budget := ctx.Value(native379V2BudgetKey{}).(*native379V2Budget)
	if _, exists := budget.fixed[id]; exists {
		return errors.New("native379 v2 duplicate fixed observation")
	}
	encoded, err := orderedCurrentNative379V2CanonicalJSONFromValue(value)
	if err != nil {
		return err
	}
	budget.fixed[id] = encoded
	return nil
}
func native379V2Charge(ctx context.Context, rows int, value any) error {
	budget, ok := ctx.Value(native379V2BudgetKey{}).(*native379V2Budget)
	if !ok {
		return errors.New("native379 v2 runtime budget absent")
	}
	id, _ := ctx.Value(native379V2PhaseKey{}).(string)
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := orderedCurrentNative379V2CanonicalJSONFromValue(value)
	if err != nil {
		return err
	}
	for _, phase := range budget.packet.Phases {
		if phase.ID == id {
			if rows < 0 || budget.rows+rows > budget.packet.Limits.MaxRows || budget.bytes+len(encoded) > budget.packet.Limits.MaxBytes || budget.phaseRows[id]+rows > phase.Limits.MaxRows || budget.phaseBytes[id]+len(encoded) > phase.Limits.MaxBytes {
				return errors.New("native379 v2 runtime row/byte budget exceeded")
			}
			budget.rows += rows
			budget.bytes += len(encoded)
			budget.phaseRows[id] += rows
			budget.phaseBytes[id] += len(encoded)
			budget.charges = append(budget.charges, native379V2BudgetCharge{Phase: id, Rows: rows, Value: append(json.RawMessage(nil), encoded...)})
			return nil
		}
	}
	return errors.New("native379 v2 runtime phase absent")
}

type native379V2RowStream interface {
	FieldDescriptions() []pgconn.FieldDescription
	Values() ([]any, error)
	Next() bool
	Err() error
	Close()
}

func orderedCurrentNative379V2QueryRows(ctx context.Context, owner *pgx.Conn, sql string) ([]map[string]any, error) {
	rows, err := owner.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	return native379V2ReadRows(ctx, rows)
}
func native379V2ReadRows(ctx context.Context, rows native379V2RowStream) ([]map[string]any, error) {
	defer rows.Close()
	fields := rows.FieldDescriptions()
	result := make([]map[string]any, 0)
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, err
		}
		row := make(map[string]any, len(values))
		for index, value := range values {
			row[string(fields[index].Name)] = orderedCurrentNative379V2NormalizeValue(value)
		}
		if err := native379V2Charge(ctx, 1, row); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func orderedCurrentNative379V2MatchValue(expected, actual any, sessionUser string, backendPID int32) bool {
	if object, ok := expected.(map[string]any); ok {
		if binding, exists := object["binding"]; exists && len(object) == 1 {
			switch binding {
			case "owned-session-user":
				return actual == sessionUser
			case "owned-backend-pid":
				switch value := actual.(type) {
				case int32:
					return value == backendPID
				case int64:
					return value == int64(backendPID)
				case json.Number:
					parsed, err := value.Int64()
					return err == nil && parsed == int64(backendPID)
				}
			}
			return false
		}
		got, ok := actual.(map[string]any)
		if !ok || len(got) != len(object) {
			return false
		}
		for key, value := range object {
			if !orderedCurrentNative379V2MatchValue(value, got[key], sessionUser, backendPID) {
				return false
			}
		}
		return true
	}
	if values, ok := expected.([]any); ok {
		got, ok := actual.([]any)
		if !ok || len(got) != len(values) {
			return false
		}
		for index := range values {
			if !orderedCurrentNative379V2MatchValue(values[index], got[index], sessionUser, backendPID) {
				return false
			}
		}
		return true
	}
	left, _ := json.Marshal(expected)
	right, _ := json.Marshal(actual)
	return orderedCurrentNative379V2JSONEqual(left, right)
}

func orderedCurrentNative379V2DecodeExpected(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return nil, errors.New("native379 expected value absent")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("native379 expected value malformed")
	}
	return value, nil
}

func orderedCurrentNative379V2StepState(err error) string {
	if err == nil {
		return "00000"
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		return postgres.Code
	}
	return "NON_SQL_ERROR"
}

// Exact independently reviewed qualified390-byte server predicate. No source
// control SQL is changed; this replaces only the separate role-observation query.
const native379V2AssertionSQL = `WITH assertion AS (SELECT ((current_user::pg_catalog.text OPERATOR(pg_catalog.=) $1::pg_catalog.text) AND (session_user::pg_catalog.text OPERATOR(pg_catalog.=) $2::pg_catalog.text) AND (pg_catalog.pg_backend_pid() OPERATOR(pg_catalog.=) $3::pg_catalog.int4)) AS ok) SELECT 1 OPERATOR(pg_catalog./) CASE WHEN ok IS TRUE THEN 1 ELSE 0 END AS role_assertion FROM assertion WHERE ok IS NOT TRUE`

type native379V2SessionBinding struct {
	ControlID, User string
	PID             int32
}

const native379V2IdentitySQL = "SELECT session_user,pg_catalog.pg_backend_pid() AS backend_pid"

type native379V2AssertionReceipt struct {
	Kind                string `json:"kind"`
	SQLSHA256           string `json:"sql_sha256"`
	ParameterSHA256     string `json:"parameter_sha256"`
	AssertedRole        string `json:"asserted_role"`
	BoundSessionUser    string `json:"bound_session_user"`
	BoundBackendPID     int32  `json:"bound_backend_pid"`
	Placement           string `json:"placement"`
	SQLState            string `json:"sqlstate"`
	RowCount            int    `json:"row_count"`
	CommandTag          string `json:"command_tag"`
	TimedOut            bool   `json:"timed_out"`
	ControlID           string `json:"controlId"`
	StepID              string `json:"stepId"`
	SourceStepSQLSHA256 string `json:"sourceStepSQLSHA256"`
	PlacementSHA256     string `json:"placementSHA256"`
	BootstrapSHA256     string `json:"bootstrapSHA256"`
	ElapsedNanoseconds  int64  `json:"elapsedNanoseconds"`
}

func native379V2BootstrapSHA(binding native379V2SessionBinding) string {
	raw, _ := orderedCurrentNative379V2CanonicalJSONFromValue(map[string]any{"controlId": binding.ControlID, "identitySQLSHA256": orderedCurrentNative379V2SHA256([]byte(native379V2IdentitySQL)), "session_user": binding.User, "backend_pid": binding.PID})
	return orderedCurrentNative379V2SHA256(raw)
}
func native379V2AssertionReceiptFor(binding native379V2SessionBinding, step orderedCurrentNative379V2ProgramStep, placement, role string, elapsed int64) native379V2AssertionReceipt {
	// Parameter hash is the exact reviewed adapter's UTF8 json.Marshal array.
	parameters, _ := json.Marshal([]any{role, binding.User, binding.PID})
	receipt := native379V2AssertionReceipt{Kind: "server-role-session-assertion-v1", SQLSHA256: orderedCurrentNative379V2SHA256([]byte(native379V2AssertionSQL)), ParameterSHA256: orderedCurrentNative379V2SHA256(parameters), AssertedRole: role, BoundSessionUser: binding.User, BoundBackendPID: binding.PID, Placement: placement, SQLState: "00000", RowCount: 0, CommandTag: "SELECT 0", ControlID: binding.ControlID, StepID: step.ID, SourceStepSQLSHA256: step.SQLSHA256, BootstrapSHA256: native379V2BootstrapSHA(binding), ElapsedNanoseconds: elapsed}
	position, _ := orderedCurrentNative379V2CanonicalJSONFromValue(map[string]any{"controlId": binding.ControlID, "stepId": step.ID, "sourceStepSQLSHA256": step.SQLSHA256, "placement": placement, "SQLSHA256": receipt.SQLSHA256, "parameterSHA256": receipt.ParameterSHA256, "bootstrapSHA256": receipt.BootstrapSHA256})
	receipt.PlacementSHA256 = orderedCurrentNative379V2SHA256(position)
	return receipt
}
func native379V2ValidateAssertionReceipt(receipt native379V2AssertionReceipt, binding native379V2SessionBinding, step orderedCurrentNative379V2ProgramStep, placement, role string) error {
	if binding.ControlID == "" || binding.User == "" || binding.PID <= 0 || role == "" || receipt.ElapsedNanoseconds < 0 || receipt.ElapsedNanoseconds > int64(10000)*int64(time.Millisecond) || (placement != "before" && placement != "after-recovery") {
		return errors.New("native379 v2 assertion authority refused")
	}
	expected := native379V2AssertionReceiptFor(binding, step, placement, role, receipt.ElapsedNanoseconds)
	if !reflect.DeepEqual(expected, receipt) {
		return errors.New("native379 v2 server assertion receipt refused")
	}
	return nil
}
func native379V2AssertionReceiptSHA(receipt native379V2AssertionReceipt) string {
	raw, _ := orderedCurrentNative379V2CanonicalJSONFromValue(receipt)
	return orderedCurrentNative379V2SHA256(raw)
}

type native379V2AssertionStream interface {
	Next() bool
	Close()
	Err() error
	CommandTag() pgconn.CommandTag
}

func native379V2AssertionCompletion(ctx context.Context, rows native379V2AssertionStream) error {
	defer rows.Close()
	if rows.Next() {
		return &native379V2AssertionFailure{Class: "nonzero-assertion-stream", SQLState: "NON_SQL_ERROR"}
	}
	rows.Close()
	if rows.Err() != nil {
		return native379V2AssertionError(ctx, rows.Err())
	}
	if ctx.Err() != nil {
		return native379V2AssertionError(ctx, ctx.Err())
	}
	if rows.CommandTag().String() != "SELECT 0" {
		return &native379V2AssertionFailure{Class: "assertion-completion-refused", SQLState: "NON_SQL_ERROR"}
	}
	return nil
}

type native379V2AssertionFailure struct {
	Class, SQLState string
	TimedOut        bool
}

func (failure *native379V2AssertionFailure) Error() string {
	return fmt.Sprintf("native379 v2 assertion refused: class=%s sqlstate=%s timed_out=%t", failure.Class, failure.SQLState, failure.TimedOut)
}
func native379V2AssertionError(ctx context.Context, err error) error {
	state := orderedCurrentNative379V2StepState(err)
	timeout := errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || state == "57014"
	class := "server-assertion-error"
	if state == "22012" {
		class = "server-assertion-mismatch"
	}
	if timeout {
		class = "server-assertion-timeout"
	}
	return &native379V2AssertionFailure{Class: class, SQLState: state, TimedOut: timeout}
}

type orderedCurrentNative379V2ExecutionSession interface {
	SessionIdentity(context.Context) (string, int32, error)
	AssertRole(context.Context, native379V2SessionBinding, orderedCurrentNative379V2ProgramStep, string, string) (native379V2AssertionReceipt, error)
	ExecStep(context.Context, string) error
	QueryStep(context.Context, string) ([]map[string]any, error)
	TxStatus() byte
	CleanupRollback(context.Context) error
}

type orderedCurrentNative379V2PGXSession struct{ owner *pgx.Conn }

func (session *orderedCurrentNative379V2PGXSession) SessionIdentity(ctx context.Context) (string, int32, error) {
	rows, err := orderedCurrentNative379V2QueryRows(ctx, session.owner, native379V2IdentitySQL)
	if err != nil || len(rows) != 1 {
		return "", 0, errors.New("native379 owned identity budget/query refused")
	}
	user, ok := rows[0]["session_user"].(string)
	pid, pok := rows[0]["backend_pid"].(int32)
	if !ok || !pok || user != session.owner.Config().User || pid != int32(session.owner.PgConn().PID()) {
		return "", 0, errors.New("native379 owned identity shape refused")
	}
	return user, pid, nil
}
func (session *orderedCurrentNative379V2PGXSession) AssertRole(ctx context.Context, binding native379V2SessionBinding, step orderedCurrentNative379V2ProgramStep, placement, role string) (native379V2AssertionReceipt, error) {
	if binding.User != session.owner.Config().User || binding.PID != int32(session.owner.PgConn().PID()) {
		return native379V2AssertionReceipt{}, &native379V2AssertionFailure{Class: "owned-session-binding-refused", SQLState: "NON_SQL_ERROR"}
	}
	started := time.Now()
	rows, err := session.owner.Query(ctx, native379V2AssertionSQL, role, binding.User, binding.PID)
	if err != nil {
		return native379V2AssertionReceipt{}, native379V2AssertionError(ctx, err)
	}
	if err := native379V2AssertionCompletion(ctx, rows); err != nil {
		return native379V2AssertionReceipt{}, err
	}

	receipt := native379V2AssertionReceiptFor(binding, step, placement, role, time.Since(started).Nanoseconds())
	if err := native379V2Charge(ctx, 0, receipt); err != nil {
		return native379V2AssertionReceipt{}, err
	}
	return receipt, nil
}
func (session *orderedCurrentNative379V2PGXSession) ExecStep(ctx context.Context, sql string) error {
	_, err := session.owner.Exec(ctx, sql)
	if err == nil {
		err = native379V2Charge(ctx, 0, map[string]any{"sqlState": "00000"})
	}
	return err
}

func (session *orderedCurrentNative379V2PGXSession) QueryStep(ctx context.Context, sql string) ([]map[string]any, error) {
	return orderedCurrentNative379V2QueryRows(ctx, session.owner, sql)
}

func (session *orderedCurrentNative379V2PGXSession) TxStatus() byte {
	return session.owner.PgConn().TxStatus()
}

func (session *orderedCurrentNative379V2PGXSession) CleanupRollback(ctx context.Context) error {
	_, err := session.owner.Exec(ctx, "ROLLBACK")
	return err
}

func orderedCurrentNative379V2ExpectedAssertedRole(declared, sessionUser string) string {
	if declared == "fixture-owner" || declared == "zasp_test" {
		return sessionUser
	}
	return declared
}

func orderedCurrentNative379V2ExecuteControl(ctx context.Context, owner *pgx.Conn, packet orderedCurrentNative379V2Packet, control orderedCurrentNative379V2Control) (result orderedCurrentNative379V2ControlResult, failure error) {
	if err := native379V2TetherPacket(packet); err != nil {
		return result, err
	}
	if err := native379V2RequireFeasibleRows(packet); err != nil {
		return result, err
	}
	return orderedCurrentNative379V2ExecuteControlSession(ctx, &orderedCurrentNative379V2PGXSession{owner: owner}, packet, control)
}

func orderedCurrentNative379V2ExecuteControlSession(ctx context.Context, session orderedCurrentNative379V2ExecutionSession, packet orderedCurrentNative379V2Packet, control orderedCurrentNative379V2Control) (orderedCurrentNative379V2ControlResult, error) {
	if err := native379V2TetherPacket(packet); err != nil {
		return orderedCurrentNative379V2ControlResult{}, err
	}
	found := false
	for _, owned := range packet.Controls {
		if owned.ID == control.ID {
			found = reflect.DeepEqual(owned, control)
			break
		}
	}
	if !found {
		return orderedCurrentNative379V2ControlResult{}, errors.New("native379 v2 detached control refused")
	}
	return native379V2ExecuteOwnedControlSession(ctx, session, packet, control)
}

const native379V2FullRestoreSQL = "ROLLBACK; RESET ROLE; SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE; SET SESSION search_path TO pg_catalog; SET SESSION TimeZone TO 'UTC'; SET ROLE zasp_discovery_authority;"

func native379V2RecoverySource(control orderedCurrentNative379V2Control, index int) (bool, string, error) {
	step := control.Program.Steps[index]
	if step.ID != "recover-probe" && step.ID != "restore" {
		return false, "", nil
	}
	if index == 0 || control.Program.Steps[index-1].Expected.Outcome != "error" {
		return false, "", nil
	}
	previous := control.Program.Steps[index-1]
	if previous.Expected.SQLState == nil || len(*previous.Expected.SQLState) != 5 {
		return false, "", errors.New("native379 v2 recovery source error state absent")
	}
	if step.Expected.Outcome != "command-success" && step.Expected.Outcome != "command-complete" {
		return false, "", errors.New("native379 v2 recovery source command refused")
	}
	switch step.ID {
	case "recover-probe":
		if step.SQL != "ROLLBACK TO SAVEPOINT native379_probe" {
			return false, "", errors.New("native379 v2 savepoint recovery bytes refused")
		}
	case "restore":
		if step.SQL != native379V2FullRestoreSQL {
			return false, "", errors.New("native379 v2 full recovery bytes refused")
		}
	}
	return true, *previous.Expected.SQLState, nil
}
func native379V2RecoveryEvidence(control orderedCurrentNative379V2Control, index int, previous orderedCurrentNative379V2ControlStepResult) (string, string, error) {
	recovery, state, err := native379V2RecoverySource(control, index)
	if err != nil || !recovery {
		return "", "", errors.New("native379 v2 undeclared recovery refused")
	}
	if !previous.Matched || previous.TimedOut || previous.ID != control.Program.Steps[index-1].ID || previous.Outcome != "error" || previous.SQLState != state {
		return "", "", errors.New("native379 v2 actual recovery predecessor error refused")
	}
	if previous.RoleAssertion != nil {
		return native379V2AssertionReceiptSHA(*previous.RoleAssertion), state, nil
	}
	if control.ID == "restore:transaction" && previous.ID == "probe" && state == "25P02" && native379V2ValidSHA(previous.CarriedAssertionSHA256) {
		return previous.CarriedAssertionSHA256, state, nil
	}
	return "", "", errors.New("native379 v2 recovery predecessor assertion absent")
}
func native379V2RolePlacement(control orderedCurrentNative379V2Control, index int) (string, string, error) {
	step := control.Program.Steps[index]
	if control.ID == "restore:transaction" && step.ID == "probe" {
		return "before-poison", step.Role, nil
	}
	recovery, _, err := native379V2RecoverySource(control, index)
	if err != nil {
		return "", "", err
	}
	if recovery {
		role := step.Role
		if step.ID == "restore" {
			role = "zasp_discovery_authority"
		}
		return "after-recovery", role, nil
	}
	return "before", step.Role, nil
}
func native379V2ExecuteOwnedControlSession(ctx context.Context, session orderedCurrentNative379V2ExecutionSession, packet orderedCurrentNative379V2Packet, control orderedCurrentNative379V2Control) (result orderedCurrentNative379V2ControlResult, failure error) {
	result.ID, result.Phase, result.MutationSHA256 = control.ID, control.Phase, control.MutationSHA256
	started := time.Now()
	defer func() {
		result.Milliseconds = time.Since(started).Milliseconds()
		if failure != nil && session.TxStatus() != 'I' {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(packet.Limits.CleanupMilliseconds)*time.Millisecond)
			defer cancel()
			_ = session.CleanupRollback(cleanup)
		}
	}()
	var sessionUser string
	var backendPID int32
	var err error
	if sessionUser, backendPID, err = session.SessionIdentity(ctx); err != nil {
		return result, errors.New("native379 owned session identity refused")
	}
	captures := make(map[string]any)
	binding := native379V2SessionBinding{ControlID: control.ID, User: sessionUser, PID: backendPID}
	var poisonReceipt native379V2AssertionReceipt
	for stepIndex, step := range control.Program.Steps {
		stepCtx, cancel := context.WithTimeout(ctx, time.Duration(packet.Limits.SQLMilliseconds)*time.Millisecond)
		roleObservation := "before"
		var roleReceipt *native379V2AssertionReceipt
		var carriedSHA, recoverySHA, recoveryState string
		poisonProbe := control.ID == "restore:transaction" && stepIndex > 0 && step.ID == "probe" && control.Program.Steps[stepIndex-1].ID == "mutate" && control.Program.Steps[stepIndex-1].Expected.Outcome == "error" && control.Program.Steps[stepIndex-1].Expected.SQLState != nil && *control.Program.Steps[stepIndex-1].Expected.SQLState == "22012" && len(result.Steps) == stepIndex && result.Steps[stepIndex-1].Matched && result.Steps[stepIndex-1].SQLState == "22012" && step.Expected.Outcome == "error" && step.Expected.SQLState != nil && *step.Expected.SQLState == "25P02"
		sourceRecovery, _, recoveryErr := native379V2RecoverySource(control, stepIndex)
		if recoveryErr != nil {
			cancel()
			return result, recoveryErr
		}
		if sourceRecovery {
			if len(result.Steps) != stepIndex || session.TxStatus() != 'E' {
				cancel()
				return result, errors.New("native379 v2 recovery requires owned aborted transaction")
			}
			recoverySHA, recoveryState, recoveryErr = native379V2RecoveryEvidence(control, stepIndex, result.Steps[stepIndex-1])
			if recoveryErr != nil {
				cancel()
				return result, recoveryErr
			}
		}
		if poisonProbe {
			roleObservation = "before-poison"
			carriedSHA = native379V2AssertionReceiptSHA(poisonReceipt)
		} else if !sourceRecovery {
			wantRole := orderedCurrentNative379V2ExpectedAssertedRole(step.Role, sessionUser)
			receipt, roleErr := session.AssertRole(stepCtx, binding, step, "before", wantRole)
			if roleErr != nil {
				cancel()
				return result, roleErr
			}
			if roleErr = native379V2ValidateAssertionReceipt(receipt, binding, step, "before", wantRole); roleErr != nil {
				cancel()
				return result, roleErr
			}
			roleReceipt = &receipt
		}
		var observed any
		err = nil
		switch step.Expected.Outcome {
		case "command-success", "command-complete":
			err = session.ExecStep(stepCtx, step.SQL)
			observed = map[string]any{"sqlState": orderedCurrentNative379V2StepState(err)}
		case "error":
			_, err = session.QueryStep(stepCtx, step.SQL)
			observed = map[string]any{"sqlState": orderedCurrentNative379V2StepState(err)}
		case "capture", "equal-captured", "rows", "one-row", "one-json-row":
			var rows []map[string]any
			rows, err = session.QueryStep(stepCtx, step.SQL)
			observed = rows
		default:
			cancel()
			return result, errors.New("native379 unknown step outcome refused")
		}
		if sourceRecovery {
			roleObservation = "after-recovery"
			if err == nil {
				wantRole := orderedCurrentNative379V2ExpectedAssertedRole(step.Role, sessionUser)
				if step.ID == "restore" {
					wantRole = "zasp_discovery_authority"
				}
				receipt, roleErr := session.AssertRole(stepCtx, binding, step, "after-recovery", wantRole)
				if roleErr != nil {
					cancel()
					return result, roleErr
				}
				if roleErr = native379V2ValidateAssertionReceipt(receipt, binding, step, "after-recovery", wantRole); roleErr != nil {
					cancel()
					return result, roleErr
				}
				roleReceipt = &receipt
			}
		}
		if step.Expected.Outcome == "error" && err != nil && orderedCurrentNative379V2StepState(err) != "NON_SQL_ERROR" {
			if _, ok := stepCtx.Value(native379V2BudgetKey{}).(*native379V2Budget); ok {
				if budgetErr := native379V2Charge(stepCtx, 0, map[string]any{"sqlState": orderedCurrentNative379V2StepState(err)}); budgetErr != nil {
					cancel()
					return result, budgetErr
				}
			}
		}
		timedOut := errors.Is(stepCtx.Err(), context.DeadlineExceeded)
		cancel()
		state := orderedCurrentNative379V2StepState(err)
		matched := !timedOut
		wantState := "00000"
		if step.Expected.SQLState != nil {
			wantState = *step.Expected.SQLState
		}
		matched = matched && state == wantState
		if step.Expected.Outcome != "error" {
			matched = matched && err == nil
		} else {
			matched = matched && err != nil && state != "NON_SQL_ERROR"
		}
		if matched {
			switch step.Expected.Outcome {
			case "capture":
				rows := observed.([]map[string]any)
				matched = len(rows) == 1 && len(rows[0]) == 1
				if matched {
					for _, value := range rows[0] {
						captures[step.Expected.Key] = value
					}
				}
			case "equal-captured":
				rows := observed.([]map[string]any)
				matched = len(rows) == 1 && len(rows[0]) == 1
				if matched {
					for _, value := range rows[0] {
						matched = orderedCurrentNative379V2MatchValue(captures[step.Expected.Key], value, sessionUser, backendPID)
					}
				}
			case "rows":
				want, decodeErr := orderedCurrentNative379V2DecodeExpected(step.Expected.Rows)
				matched = decodeErr == nil && orderedCurrentNative379V2MatchValue(want, observed, sessionUser, backendPID)
			case "one-row", "one-json-row":
				want, decodeErr := orderedCurrentNative379V2DecodeExpected(step.Expected.Value)
				rows := observed.([]map[string]any)
				matched = decodeErr == nil && len(rows) == 1 && len(rows[0]) == 1
				if matched {
					for _, value := range rows[0] {
						matched = orderedCurrentNative379V2MatchValue(want, value, sessionUser, backendPID)
					}
				}
			}
		}
		observedRaw, encodeErr := orderedCurrentNative379V2CanonicalJSONFromValue(observed)
		if encodeErr != nil {
			return result, encodeErr
		}
		result.Steps = append(result.Steps, orderedCurrentNative379V2ControlStepResult{ID: step.ID, Outcome: step.Expected.Outcome, SQLState: state, DeclaredRole: step.Role, RoleAssertion: roleReceipt, CarriedAssertionSHA256: carriedSHA, RecoveryPredecessorSHA256: recoverySHA, RecoverySQLState: recoveryState, BoundSessionUser: sessionUser, BoundBackendPID: backendPID, RoleObservation: roleObservation, Observation: observedRaw, ObservedSHA256: orderedCurrentNative379V2SHA256(observedRaw), Matched: matched, TimedOut: timedOut})
		if !matched {
			return result, fmt.Errorf("native379 control %s step %s refused", control.ID, step.ID)
		}
		if control.ID == "restore:transaction" && step.ID == "mutate" && state == "22012" {
			if roleReceipt == nil {
				return result, errors.New("native379 v2 before-poison assertion absent")
			}
			poisonReceipt = *roleReceipt
		}
	}
	if session.TxStatus() != 'I' {
		return result, errors.New("native379 control transaction not restored")
	}
	result.Restored = true
	return result, nil
}

func orderedCurrentNative379V2ExecuteControls(ctx context.Context, owner *pgx.Conn, admission orderedCurrentNative379V2AdmittedPacket) ([]orderedCurrentNative379V2ControlResult, error) {
	if err := validateOrderedCurrentNative379V2Admission(admission); err != nil {
		return nil, err
	}
	packet := admission.packet.clone()
	byID := make(map[string]orderedCurrentNative379V2Control, len(packet.Controls))
	for _, control := range packet.Controls {
		byID[control.ID] = control
	}
	budget, ok := ctx.Value(native379V2BudgetKey{}).(*native379V2Budget)
	if !ok {
		budget = native379V2NewBudget(packet)
	}
	results := make([]orderedCurrentNative379V2ControlResult, 0, len(packet.Controls))
	for _, phase := range packet.Phases {
		phaseCtx, cancel, err := budget.phase(ctx, phase.ID)
		if err != nil {
			return nil, err
		}
		for _, id := range phase.ControlIDs {
			result, err := native379V2ExecuteOwnedControlSession(phaseCtx, &orderedCurrentNative379V2PGXSession{owner: owner}, packet, byID[id])
			if err != nil {
				cancel()
				return nil, err
			}
			results = append(results, result)
		}
		cancel()
	}
	if err := validateOrderedCurrentNative379V2ControlResults(packet, results); err != nil {
		return nil, err
	}
	return results, nil
}

func orderedCurrentNative379V2InstallAndCompare(ctx context.Context, owner *pgx.Conn, admission orderedCurrentNative379V2AdmittedPacket, module, manifest, collector []byte) (orderedCurrentNative379V2Observation, error) {
	var observation orderedCurrentNative379V2Observation
	if err := validateOrderedCurrentNative379V2Admission(admission); err != nil {
		return observation, err
	}
	packet := admission.packet.clone()
	budget := native379V2NewBudget(packet)
	if deadline, ok := ctx.Value(native379V2PristineDeadlineKey{}).(time.Time); ok {
		budget.deadlines["pristine-truth"] = deadline
	}
	rootCtx := context.WithValue(ctx, native379V2BudgetKey{}, budget)
	ctx, cancelPhase, phaseErr := budget.phase(rootCtx, "pristine-truth")
	if phaseErr != nil {
		return observation, phaseErr
	}
	defer cancelPhase()
	if orderedCurrentNative379V2SHA256(collector) != orderedCurrentNative379V2CollectorSHA256 || packet.Authority.Generated[orderedCurrentNative379V2CollectorFile] != orderedCurrentNative379V2CollectorSHA256 {
		return observation, errors.New("native379 fixed collector source refused")
	}
	digest := func(raw []byte) string {
		value := sha256.Sum256(raw)
		return hex.EncodeToString(value[:])
	}
	observation.Hashes = map[string]string{"packet": packet.WireSHA256, "module": digest(module), "manifest": digest(manifest)}
	observation.Counts.Rules, observation.Counts.Facts, observation.Counts.RoleSites = len(packet.Rules), len(packet.ExpectedFacts), len(packet.SourceInventory.Sites)
	recorder := &orderedCurrentNative379V2OperationRecorder{}
	if err := orderedCurrentNative379V2Preinstall(ctx, owner, packet, &observation, recorder); err != nil {
		return orderedCurrentNative379V2Observation{}, err
	}
	_, err := owner.Exec(ctx, string(module))
	if recorder.observe("dormant-module-install", err) != nil {
		return orderedCurrentNative379V2Observation{}, native379V2SafeQueryFailure(err, string(module))
	}
	var registration, expected, grants int
	err = owner.QueryRow(ctx, `
SELECT
 (SELECT n.nspowner::regrole::text FROM pg_catalog.pg_namespace n WHERE n.nspname='zasp_authorization80_ordered_current'),
 (SELECT array_agg(pg_catalog.format('%I.%I',n.nspname,c.relname) ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C") FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_authorization80_ordered_current' AND c.relkind='r'),
 (SELECT array_agg(p.oid::regprocedure::text ORDER BY p.oid::regprocedure::text COLLATE "C") FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_authorization80_ordered_current'),
 (SELECT count(*) FROM zasp_authorization80_ordered_current.registration),
 (SELECT count(*) FROM zasp_authorization80_ordered_current.expected),
 (SELECT count(*) FROM (
   SELECT n.nspowner owner,n.nspacl acl FROM pg_catalog.pg_namespace n WHERE n.nspname='zasp_authorization80_ordered_current'
   UNION ALL SELECT c.relowner,c.relacl FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_authorization80_ordered_current' AND c.relkind='r'
   UNION ALL SELECT p.proowner,p.proacl FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_authorization80_ordered_current'
  ) objects CROSS JOIN LATERAL pg_catalog.aclexplode(objects.acl) acl WHERE acl.grantee=0 OR acl.grantee<>objects.owner)`).Scan(&observation.Objects.SchemaOwner, &observation.Objects.Tables, &observation.Objects.Routines, &registration, &expected, &grants)
	if err == nil {
		err = native379V2ChargeFixed(ctx, "inventory", []any{observation.Objects.SchemaOwner, observation.Objects.Tables, observation.Objects.Routines, registration, expected, grants})
	}
	observedInventoryErr := recorder.observe("installed-inventory", err)
	observation.Objects.UnexpectedGrants = grants
	observation.Counts.Registration, observation.Counts.ExpectedRows = registration, expected
	wantRoutines, routineErr := orderedCurrentNative379V2ExpectedRoutines(packet)
	if observedInventoryErr != nil || routineErr != nil || observation.Objects.SchemaOwner != "zasp_discovery_authority" || !reflect.DeepEqual(observation.Objects.Tables, []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}) || !reflect.DeepEqual(observation.Objects.Routines, wantRoutines) || registration != 1 || expected != len(packet.ExpectedFacts) || grants != 0 {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 partial install, object inventory, cardinality, or grant boundary refused")
	}
	expectedByKey := make(map[string]orderedCurrentNative379V2Fact, len(packet.ExpectedFacts))
	for _, fact := range packet.ExpectedFacts {
		key := fact.Kind + "\x00" + fact.Identity
		if fact.Kind == "" || fact.Identity == "" || expectedByKey[key].Kind != "" {
			return orderedCurrentNative379V2Observation{}, errors.New("native379 expected fact key refused")
		}
		expectedByKey[key] = fact
	}
	rows, err := owner.Query(ctx, `SELECT kind,identity,fact::text FROM zasp_authorization80_ordered_current.expected ORDER BY kind COLLATE "C",identity COLLATE "C"`)
	if recorder.observe("expected-stream-query", err) != nil {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 expected table read refused")
	}
	defer rows.Close()
	seen := make(map[string]bool, len(expectedByKey))
	for rows.Next() {
		var kind, identity, raw string
		if err := rows.Scan(&kind, &identity, &raw); err != nil {
			return orderedCurrentNative379V2Observation{}, errors.New("native379 expected row scan refused")
		}
		key := kind + "\x00" + identity
		want, ok := expectedByKey[key]
		if !ok || seen[key] || !orderedCurrentNative379V2JSONEqual([]byte(raw), want.Fact) {
			return orderedCurrentNative379V2Observation{}, errors.New("native379 complete key-set or value equality refused")
		}
		if err := native379V2Charge(ctx, 1, map[string]any{"kind": kind, "identity": identity, "fact": json.RawMessage(raw)}); err != nil {
			return observation, err
		}
		seen[key] = true
		observation.Counts.EqualFacts++
	}
	streamErr := rows.Err()
	if recorder.observe("expected-stream-complete", streamErr) != nil || len(seen) != len(expectedByKey) {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 incomplete expected row stream refused")
	}
	const frameSQL = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),current_setting('transaction_read_only'),current_setting('transaction_isolation')`
	var frameBefore [6]string
	err = owner.QueryRow(ctx, frameSQL).Scan(&frameBefore[0], &frameBefore[1], &frameBefore[2], &frameBefore[3], &frameBefore[4], &frameBefore[5])
	if err == nil {
		err = native379V2ChargeFixed(ctx, "frame-before", frameBefore)
	}
	if recorder.observe("frame-before", err) != nil {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 pre-frame refused")
	}
	tx, err := owner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if recorder.observe("pristine-begin", err) != nil {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 pristine transaction refused")
	}
	active := true
	defer func() {
		if active {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(packet.Limits.CleanupMilliseconds)*time.Millisecond)
			defer cancel()
			_ = tx.Rollback(cleanup)
		}
	}()
	_, err = tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout=%d; SET LOCAL lock_timeout=%d; SET LOCAL search_path=pg_catalog; SET LOCAL TimeZone='UTC'; SET LOCAL ROLE zasp_discovery_authority", packet.Limits.SQLMilliseconds, packet.Limits.LockMilliseconds))
	if recorder.observe("pristine-frame", err) != nil {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 pristine frame refused")
	}
	var admitted, catalog bool
	err = tx.QueryRow(ctx, packet.Entry.IndependentAdmission.SQL).Scan(&admitted)
	if err == nil {
		err = native379V2ChargeFixed(ctx, "admission", admitted)
	}
	if recorder.observe("private-admission", err) != nil || !admitted {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 evaluator/entry admission refused")
	}
	err = tx.QueryRow(ctx, `SELECT zasp_authorization80_ordered_current.catalog($1)`, packet.Entry.Manifest).Scan(&catalog)
	if err == nil {
		err = native379V2ChargeFixed(ctx, "catalog", catalog)
	}
	if observedErr := recorder.observe("catalog", err); observedErr != nil {
		return orderedCurrentNative379V2Observation{}, native379V2SafeQueryFailure(err, `SELECT zasp_authorization80_ordered_current.catalog($1)`)
	}
	if !catalog {
		diagnostic := orderedCurrentNative379V2CollectCatalogDiagnostic(ctx, tx, packet, collector)
		return orderedCurrentNative379V2Observation{}, orderedCurrentNative379V2CatalogFailure(diagnostic)
	}
	_, err = tx.Exec(ctx, `SELECT zasp_authorization80_ordered_current.require($1)`, packet.Entry.Manifest)
	if recorder.observe("require", err) != nil {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 pristine entry refused")
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(packet.Limits.CleanupMilliseconds)*time.Millisecond)
	err = tx.Rollback(cleanup)
	rollbackObservedErr := recorder.observe("pristine-rollback", err)
	cancel()
	active = false
	if rollbackObservedErr != nil {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 pristine rollback refused")
	}
	observation.Restoration.TransactionRolledBack = true
	var frameAfter [6]string
	err = owner.QueryRow(ctx, frameSQL).Scan(&frameAfter[0], &frameAfter[1], &frameAfter[2], &frameAfter[3], &frameAfter[4], &frameAfter[5])
	if err == nil {
		err = native379V2ChargeFixed(ctx, "frame-after", frameAfter)
	}
	if recorder.observe("frame-after", err) != nil || frameAfter != frameBefore {
		return orderedCurrentNative379V2Observation{}, errors.New("native379 pristine frame restoration refused")
	}
	observation.Restoration.FrameRestored = true
	operations, err := recorder.finish()
	if err != nil {
		return orderedCurrentNative379V2Observation{}, err
	}
	observation.Operations = operations
	observation.Controls, err = orderedCurrentNative379V2ExecuteControls(rootCtx, owner, admission)
	if err != nil {
		return orderedCurrentNative379V2Observation{}, err
	}
	observation.Budget = budget.evidence()
	observation.Available = true
	return observation, nil
}

func orderedCurrentNative379V2JSONEqual(left, right []byte) bool {
	var a, b any
	decode := func(raw []byte, output *any) bool {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(output) != nil {
			return false
		}
		return decoder.Decode(&struct{}{}) == io.EOF
	}
	return decode(left, &a) && decode(right, &b) && reflect.DeepEqual(a, b)
}

// TestP7OrderedCurrentIntegrityNativeV2 is deliberately opt-in. Task 2 compiles
// this owned fixture but does not execute it; root alone schedules the bounded
// PostgreSQL run after independent packet and fixture review.
func TestP7OrderedCurrentIntegrityNativeV2(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_V2") == "" {
		t.Skip("explicit ordered-current native379 run required")
	}
	if os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_V2") != "1" {
		t.Fatal("ordered-current native379 mode refused")
	}
	for _, name := range []string{"ZASP_ORDERED_CURRENT_NATIVE379", "ZASP_WORKER_REGISTRATION_REFERENCE", "ZASP_ORDERED_CONSOLIDATED_REFERENCE", "ZASP_ORDERED_PRIVATE_SUCCESSOR_CAPTURE", "ZASP_ORDERED_MISSING_REFERENCE_NATIVE", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_CAPTURE"} {
		if os.Getenv(name) != "" {
			t.Fatalf("ordered-current native379 overlaps %s", name)
		}
	}
	destination := os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_V2_OUTPUT")
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		t.Fatal("ordered-current native379 output must be a new absolute path")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("ordered-current native379 output already exists")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 750000*time.Millisecond)
	defer cancel()
	packetStart := time.Now()
	admission, err := loadOrderedCurrentNative379V2Packet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet := admission.packet
	if err := native379V2RequireFeasibleRows(packet); err != nil {
		t.Fatal(err)
	}
	initialBuildDigest := os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD_SHA256")
	inputsStart := time.Now()
	envelope, boundGo, err := native379V2BindEnvelope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, assignment := range registrationReferenceGoEnvironment(boundGo) {
		key, value, ok := strings.Cut(assignment, "=")
		if ok {
			t.Setenv(key, value)
		}
	}
	module, err := orderedCurrentNative379V2File(envelope.ModulePath, orderedCurrentNative379V2ModuleSHA256, packet.Limits.MaxPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := orderedCurrentNative379V2File(envelope.ManifestPath, orderedCurrentNative379V2ManifestSHA256, packet.Limits.MaxPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := orderedCurrentNative379V2File(envelope.CollectorPath, orderedCurrentNative379V2CollectorSHA256, packet.Limits.MaxPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	stages := orderedCurrentNative379V2TestStages(packet)
	for index := range stages {
		stages[index].Milliseconds = 0
	}
	stages[0].Milliseconds = orderedCurrentNative379V2Duration(packetStart)
	stages[1].Milliseconds = orderedCurrentNative379V2Duration(inputsStart)
	var fixtureStart, moduleStart, cleanupStart time.Time
	var observation *orderedCurrentNative379V2Observation
	cleanupObservation := &disposablePostgresCleanupObservation{}
	t.Run("owned-postgresql-18.3", func(t *testing.T) {
		registerDisposablePostgresCleanupObservation(t, cleanupObservation)
		fixtureStart = time.Now()
		t.Cleanup(func() {
			if !cleanupStart.IsZero() {
				stages[8].Milliseconds = orderedCurrentNative379V2Duration(cleanupStart)
			}
		})
		runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, func(t *testing.T, fixture context.Context, owner *pgx.Conn) bool {
			stages[2].Milliseconds = orderedCurrentNative379V2Duration(fixtureStart)
			moduleStart = time.Now()
			// Only pristine consumes preparation time. Subsequent phases retain
			// their complete original deadlines under the global fixture cap.
			boundedFixture := context.WithValue(fixture, native379V2PristineDeadlineKey{}, fixtureStart.Add(180000*time.Millisecond))
			globalDeadline, _ := ctx.Deadline()
			boundedFixture, cancelFixture := context.WithDeadline(boundedFixture, globalDeadline)
			defer cancelFixture()
			observed, err := orderedCurrentNative379V2InstallAndCompare(boundedFixture, owner, admission, module, manifest, collector)
			if err != nil {
				t.Fatal(err)
			}
			stages[3].Milliseconds = orderedCurrentNative379V2Duration(moduleStart)
			observation = &observed
			cleanupStart = time.Now()
			return true
		}, nil)
	})
	if observation == nil || t.Failed() || ctx.Err() != nil {
		t.Fatal("ordered-current native379 owned fixture did not complete cleanly")
	}
	if time.Since(started) > time.Duration(packet.Limits.MaxMilliseconds)*time.Millisecond {
		t.Fatal("ordered-current native379 total duration overflow")
	}
	stageByPhase := map[string]int{"preflight": 1, "cleanup-result": 8, "drift": 4, "forged-entry": 5, "null-error-lazy-demand": 6, "frame-restoration": 7}
	for _, control := range observation.Controls {
		if index, ok := stageByPhase[control.Phase]; ok {
			stages[3].Milliseconds -= control.Milliseconds
			stages[index].Milliseconds += control.Milliseconds
		}
	}
	admissionStart := time.Now()
	result, err := buildOrderedCurrentNative379V2Result(packet, observation, cleanupObservation, stages)
	if err != nil {
		t.Fatal(err)
	}
	stages[9].Milliseconds = orderedCurrentNative379V2Duration(admissionStart)
	result, err = buildOrderedCurrentNative379V2Result(packet, observation, cleanupObservation, stages)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD_SHA256") != initialBuildDigest {
		t.Fatal("native379 v2 root build authority changed during fixture")
	}
	if _, _, err := native379V2BindEnvelope(ctx); err != nil {
		t.Fatal(err)
	}
	if err := publishOrderedCurrentNative379V2Result(destination, result, orderedCurrentNative379V2MaxResultBytes); err != nil {
		t.Fatal(err)
	}
}

// Raw parsing rejects ambiguity independently of the outer SHA trust anchor.
func native379V2StrictJSON(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 33554432 || !utf8.Valid(raw) {
		return nil, errors.New("native379 v2 raw size/UTF8 refused")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 128 {
			return nil, errors.New("native379 v2 JSON depth refused")
		}
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return token, nil
		}
		switch delim {
		case '{':
			object := map[string]any{}
			for d.More() {
				keyToken, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("native379 v2 key refused")
				}
				if _, exists := object[key]; exists {
					return nil, errors.New("native379 v2 duplicate key refused")
				}
				value, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				object[key] = value
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, errors.New("native379 v2 object refused")
			}
			return object, nil
		case '[':
			array := []any{}
			for d.More() {
				value, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				array = append(array, value)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, errors.New("native379 v2 array refused")
			}
			return array, nil
		}
		return nil, errors.New("native379 v2 delimiter refused")
	}
	value, err := read(0)
	if err != nil {
		return nil, errors.New("native379 v2 strict JSON refused")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("native379 v2 trailing bytes refused")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("native379 v2 object root required")
	}
	return object, nil
}
func native379V2ValidSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
func native379V2SafeQueryFailure(err error, sql string) error {
	class, state := "driver", ""
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		class = "postgres"
		if len(pgerr.Code) == 5 {
			valid := true
			for _, c := range pgerr.Code {
				if c < '0' || c > '9' && c < 'A' || c > 'Z' {
					valid = false
				}
			}
			if valid {
				state = pgerr.Code
			}
		}
	}
	return fmt.Errorf("native379 v2 query refused: error_class=%s sqlstate=%s statement_sha256=%s", class, state, orderedCurrentNative379V2SHA256([]byte(sql)))
}

// Only this wrapper supplies compiled root-reviewed anchors. The pure parser
// accepts explicit test-local authority for offline behavioral controls only.
func admitOrderedCurrentNative379V2PacketRaw(raw []byte) (orderedCurrentNative379V2AdmittedPacket, error) {
	if !native379V2ValidSHA(orderedCurrentNative379V2PacketSHA256) {
		return orderedCurrentNative379V2AdmittedPacket{}, errors.New("native379 v2 independent raw packet review required")
	}
	return native379V2AdmitReviewedRaw(raw, orderedCurrentNative379V2PacketSHA256)
}
func native379V2AdmitReviewedRaw(raw []byte, expectedSHA string) (orderedCurrentNative379V2AdmittedPacket, error) {
	var zero orderedCurrentNative379V2AdmittedPacket
	object, err := native379V2StrictJSON(raw)
	if err != nil {
		return zero, err
	}
	keys := []string{"authority", "buildRuntime", "captureAuthority", "controls", "coverage", "entry", "expectedFacts", "format", "identity", "installable", "limits", "nativeVerified", "nextGates", "pendingGates", "phases", "referenceProvenance", "resultAuthority", "rules", "sourceFactDelta", "sourceInventory", "status"}
	if len(object) != len(keys) {
		return zero, errors.New("native379 v2 unknown/missing root field refused")
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return zero, errors.New("native379 v2 missing field refused")
		}
	}
	canonical, err := orderedCurrentNative379V2CanonicalJSONFromValue(object)
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) {
		return zero, errors.New("native379 v2 noncanonical wire refused")
	}
	wireSHA := orderedCurrentNative379V2SHA256(raw)
	if !native379V2ValidSHA(expectedSHA) || wireSHA != expectedSHA {
		return zero, errors.New("native379 v2 reviewed wire identity refused")
	}
	var packet orderedCurrentNative379V2Packet
	if json.Unmarshal(raw, &packet) != nil {
		return zero, errors.New("native379 v2 typed view refused")
	}
	packet.Raw = append(json.RawMessage(nil), raw...)
	packet.WireSHA256 = wireSHA
	packet.admittedRawSHA = wireSHA
	if err := validateOrderedCurrentNative379V2PacketStructure(packet); err != nil {
		return zero, err
	}
	return orderedCurrentNative379V2AdmittedPacket{packet: packet, rawSHA: wireSHA, rawBytes: len(raw)}, nil
}

type native379V2BuildEnvelope struct {
	Version                   string                       `json:"version"`
	GoBuildPath               string                       `json:"go_build_path"`
	GoBuildSHA256             string                       `json:"go_build_sha256"`
	PacketSHA256              string                       `json:"packet_sha256"`
	SourceInventorySHA256     string                       `json:"source_inventory_sha256"`
	GeneratedIdentitiesSHA256 string                       `json:"generated_identities_sha256"`
	SourceFactDeltaSHA256     string                       `json:"source_fact_delta_sha256"`
	NodeExecutable            string                       `json:"node_executable"`
	NodeSHA256                string                       `json:"node_sha256"`
	ModulePath                string                       `json:"module_path"`
	ManifestPath              string                       `json:"manifest_path"`
	CollectorPath             string                       `json:"collector_path"`
	Inputs                    []registrationReferenceInput `json:"node_generated_inputs"`
}

func native379V2BindEnvelope(ctx context.Context) (native379V2BuildEnvelope, registrationReferenceBuild, error) {
	var e native379V2BuildEnvelope
	var b registrationReferenceBuild
	// Empty compiled anchors fail before any Go/PG/version subprocess executes.
	if err := native379V2ValidateAnchorSet([]string{orderedCurrentNative379V2PacketSHA256, orderedCurrentNative379V2ModuleSHA256, orderedCurrentNative379V2ManifestSHA256, orderedCurrentNative379V2CollectorSHA256, orderedCurrentNative379V2SourceInventorySHA256, orderedCurrentNative379V2GeneratedIdentitiesSHA256, orderedCurrentNative379V2SourceFactDeltaSHA256}); err != nil {
		return e, b, err
	}
	path, pin := os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD"), os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD_SHA256")
	raw, err := registrationReferenceReadBound(path, 16*1024*1024)
	if err != nil || !native379V2ValidSHA(pin) || orderedCurrentNative379V2SHA256(raw) != pin {
		return e, b, errors.New("native379 v2 external envelope digest refused")
	}
	if registrationReferenceJSON(raw, &e) != nil || e.Version != "ordered-current-native379-frozen-build-v2" || e.PacketSHA256 != orderedCurrentNative379V2PacketSHA256 || e.SourceInventorySHA256 != orderedCurrentNative379V2SourceInventorySHA256 || e.GeneratedIdentitiesSHA256 != orderedCurrentNative379V2GeneratedIdentitiesSHA256 || e.SourceFactDeltaSHA256 != orderedCurrentNative379V2SourceFactDeltaSHA256 || e.NodeSHA256 != "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068" || len(e.Inputs) == 0 {
		return e, b, errors.New("native379 v2 closed envelope identity refused")
	}
	b, err = native379V2BindGo(ctx, e.GoBuildPath, e.GoBuildSHA256)
	if err != nil {
		return e, b, err
	}
	seen := map[string]bool{}
	for _, input := range e.Inputs {
		if seen[input.Path] || registrationReferenceImmutableInput(input.Path, b) != nil {
			return e, b, errors.New("native379 v2 immutable source topology refused")
		}
		seen[input.Path] = true
		hash, err := registrationReferenceHashFile(input.Path)
		if err != nil || hash != input.SHA256 {
			return e, b, errors.New("native379 v2 consumed source hash refused")
		}
	}
	for path, pin := range map[string]string{e.NodeExecutable: e.NodeSHA256, e.ModulePath: orderedCurrentNative379V2ModuleSHA256, e.ManifestPath: orderedCurrentNative379V2ManifestSHA256, e.CollectorPath: orderedCurrentNative379V2CollectorSHA256} {
		if !seen[path] {
			return e, b, errors.New("native379 v2 missing node/output roster member")
		}
		hash, err := registrationReferenceHashFile(path)
		if err != nil || hash != pin {
			return e, b, errors.New("native379 v2 node/output identity refused")
		}
	}

	// Reconstruct the entire Node consumed roster from its compiled reviewed
	// manifest. An admitted envelope must never bind only a convenient subset.
	sourceManifestPath := filepath.Join(b.Platform, "migrations/tools/ordered-current-native379-packet-v2-artifacts/source-inputs.json")
	sourceRaw, sourceErr := registrationReferenceReadBound(sourceManifestPath, 1024*1024)
	if sourceErr != nil || orderedCurrentNative379V2SHA256(sourceRaw) != e.SourceInventorySHA256 {
		return e, b, errors.New("native379 v2 exact source manifest refused")
	}
	var source struct {
		Format string            `json:"format"`
		Files  map[string]string `json:"files"`
	}
	if json.Unmarshal(sourceRaw, &source) != nil || source.Format != "ordered-current-native379-source-inputs-v2" || len(source.Files) == 0 {
		return e, b, errors.New("native379 v2 complete source manifest shape refused")
	}
	expectedNode := map[string]bool{}
	root := filepath.Clean(filepath.Join(b.Platform, "..", ".."))
	for relative, pin := range source.Files {
		if filepath.ToSlash(filepath.Clean(relative)) != relative || filepath.IsAbs(relative) || strings.Contains(relative, "\\") || !strings.HasPrefix(relative, "services/platform/") || strings.Contains(relative, "/../") || !native379V2ValidSHA(pin) {
			return e, b, errors.New("native379 v2 source manifest topology refused")
		}
		inputPath := filepath.Join(root, filepath.FromSlash(relative))
		expectedNode[inputPath] = true
		if !seen[inputPath] {
			return e, b, errors.New("native379 v2 incomplete Node consumed source roster")
		}
		hash, err := registrationReferenceHashFile(inputPath)
		if err != nil || hash != pin {
			return e, b, errors.New("native379 v2 Node source member binding refused")
		}
	}
	for _, path := range []string{e.NodeExecutable, e.ModulePath, e.ManifestPath, e.CollectorPath, sourceManifestPath, filepath.Join(b.Platform, "migrations/tools/ordered-current-native379-packet-v2.mjs"), filepath.Join(b.Platform, "migrations/tools/ordered-current-native379-source-schema-v2.mjs"), filepath.Join(b.Platform, "migrations/tools/ordered-current-native379-packet-v2-artifacts/generated-identities.json"), filepath.Join(b.Platform, "migrations/tools/ordered-current-native379-packet-v2-artifacts/source-fact-delta.json")} {
		expectedNode[path] = true
	}
	if len(expectedNode) != len(seen) {
		return e, b, errors.New("native379 v2 extra/missing Node consumed member refused")
	}
	for path := range expectedNode {
		if !seen[path] {
			return e, b, errors.New("native379 v2 required compiler/artifact member missing")
		}
	}
	for path, pin := range map[string]string{filepath.Join(b.Platform, "migrations/tools/ordered-current-native379-packet-v2-artifacts/generated-identities.json"): e.GeneratedIdentitiesSHA256, filepath.Join(b.Platform, "migrations/tools/ordered-current-native379-packet-v2-artifacts/source-fact-delta.json"): e.SourceFactDeltaSHA256} {
		hash, err := registrationReferenceHashFile(path)
		if err != nil || hash != pin {
			return e, b, errors.New("native379 v2 source identity/transition artifact refused")
		}
	}
	if _, excluded := source.Files["services/platform/apiserver/authorization_worker_ordered_current_native379_v2_pins_test.go"]; excluded {
		return e, b, errors.New("native379 v2 cyclic companion source refused")
	}
	implementationPath := filepath.Join(b.Platform, "apiserver/authorization_worker_ordered_current_native379_v2_test.go")
	if !expectedNode[implementationPath] {
		return e, b, errors.New("native379 v2 actual native fixture omitted from Node source")
	}

	companion := filepath.Join(b.Platform, "apiserver", "authorization_worker_ordered_current_native379_v2_pins_test.go")
	bound := false
	for _, input := range b.Inputs {
		if input.Path == companion {
			bound = true
		}
	}
	if !bound {
		return e, b, errors.New("native379 v2 Go trust-anchor source not bound")
	}
	return e, b, nil
}
func generateOrderedCurrentNative379V2PacketRaw(ctx context.Context) ([]byte, error) {
	e, b, err := native379V2BindEnvelope(ctx)
	if err != nil {
		return nil, err
	}
	root := filepath.Clean(filepath.Join(b.Platform, "..", ".."))
	module := filepath.Join(b.Platform, "migrations", "tools", "ordered-current-native379-packet-v2.mjs")
	found := false
	for _, input := range e.Inputs {
		if input.Path == module {
			found = true
		}
	}
	if !found {
		return nil, errors.New("native379 v2 packet compiler not hash-bound")
	}
	stdout := &orderedCurrentNative379V2LimitedBuffer{limit: 33554432}
	command := exec.CommandContext(ctx, e.NodeExecutable, module, "--json")
	command.Dir = root
	command.Env = []string{"PATH=" + b.ControlledPATH, "TZ=UTC", "LANG=C", "LC_ALL=C"}
	command.Stdout = stdout
	command.Stderr = io.Discard
	if command.Run() != nil {
		return nil, errors.New("native379 v2 source packet regeneration refused")
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}

func TestNative379V2RawJSONRefusesAmbiguousWire(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"a":1,"a":2}`), []byte(`{"a":{"b":1,"b":2}}`), []byte(`{"a":1} {}`), {'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'}} {
		if _, err := native379V2StrictJSON(raw); err == nil {
			t.Fatal("ambiguous raw admitted")
		}
	}
	if _, err := native379V2StrictJSON([]byte(`{"a":[null,true,12,{"b":"ok"}]}`)); err != nil {
		t.Fatal(err)
	}
}
func TestNative379V2UnreviewedAnchorsRefuseBeforeSubprocess(t *testing.T) {
	if native379V2ValidateAnchorSet(make([]string, 7)) == nil {
		t.Fatal("explicit empty test-local pinset admitted")
	}
	previous := native379V2BindGo
	defer func() { native379V2BindGo = previous }()
	called := false
	native379V2BindGo = func(context.Context, string, string) (registrationReferenceBuild, error) {
		called = true
		return registrationReferenceBuild{}, errors.New("unexpected tool boundary")
	}
	t.Setenv("ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD", filepath.Join(t.TempDir(), "missing-envelope.json"))
	t.Setenv("ZASP_ORDERED_CURRENT_NATIVE379_V2_BUILD_SHA256", strings.Repeat("0", 64))
	if _, _, err := native379V2BindEnvelope(context.Background()); err == nil || called {
		t.Fatal("empty pins or invalid envelope reached subprocess boundary")
	}
}
func TestNative379V2RawBoundaryRefusesUnknownNoncanonicalAndForgedStatuses(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"unknown":true}`), []byte(` {"format":"ordered-current-native379-packet-v2"}`), []byte(`{"installable":true}`), []byte(`{"nativeVerified":true}`), []byte(`{"captureAuthority":true}`)} {
		if _, err := native379V2AdmitReviewedRaw(raw, orderedCurrentNative379V2SHA256(raw)); err == nil {
			t.Fatal("unreviewed schema/status admitted")
		}
	}
}

// Semantic metadata stays separate from historical reference facts and never
// turns component parity into installed/production/capacity authorization.
func native379V2PacketMetadata(packet orderedCurrentNative379V2Packet) error {
	expectedGates := []string{"independently-reviewed-Go-source-module-test-binary-envelope", "full-native379-owned-fixture-and-reviewed-result", "varied-login-OID-and-production-PostgreSQL-portability", "connected-installed-worker-acceptance", "unchanged-limit-capacity", "deployment-and-provider-acceptance"}
	if !reflect.DeepEqual(packet.PendingGates, expectedGates) || packet.ResultAuthority != "none; packet and bounds validation do not accept native results" || len(packet.Raw) == 0 || len(packet.ReferenceProvenance) == 0 {
		return errors.New("native379 v2 pending/provenance authority refused")
	}
	var runtime struct{ Version, Platform, Arch, ExecutableSHA256, ExecutablePolicy string }
	if json.Unmarshal(packet.BuildRuntime, &runtime) != nil || runtime.Version != "v22.23.1" || runtime.Platform != "linux" || runtime.Arch != "x64" || runtime.ExecutableSHA256 != "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068" || runtime.ExecutablePolicy != "resolved-process-executable-regular-file-exact-sha256" {
		return errors.New("native379 v2 build runtime refused")
	}
	var policy struct {
		Implementation      string   `json:"implementation"`
		ExcludedSourcePaths []string `json:"excludedSourcePaths"`
		CompanionBinding    string   `json:"companionBinding"`
	}
	if json.Unmarshal(packet.Authority.GoPacketAnchorPolicy, &policy) != nil || policy.Implementation != "services/platform/apiserver/authorization_worker_ordered_current_native379_v2_test.go" || !reflect.DeepEqual(policy.ExcludedSourcePaths, []string{"services/platform/apiserver/authorization_worker_ordered_current_native379_v2_pins_test.go"}) || policy.CompanionBinding != "independently-reviewed-full-consumed-Go-source-module-test-binary-envelope" {
		return errors.New("native379 v2 explicit hash-cycle policy refused")
	}
	if packet.Identity.ServerVersionNum != 180003 || !strings.Contains(packet.Identity.Postgres, "PostgreSQL 18.3 (Debian ") || !strings.Contains(packet.Identity.Postgres, "x86_64-pc-linux-gnu") || packet.Identity.Pgcrypto != "1.4" {
		return errors.New("native379 v2 actual native identity refused")
	}
	var delta struct {
		Format     string `json:"format"`
		Historical struct {
			ExpectedFacts int `json:"expectedFacts"`
		} `json:"historicalV1"`
		Current struct{ ExpectedFacts, PrivateRoutines, Rules, RoleSites int } `json:"currentSource"`
		PerRule []struct {
			RuleID     string `json:"ruleId"`
			Historical int    `json:"historicalV1ExpectedFacts"`
			Current    int    `json:"currentSourceExpectedFacts"`
			Delta      int    `json:"delta"`
		} `json:"perRule"`
	}
	if json.Unmarshal(packet.SourceFactDelta, &delta) != nil || delta.Format != "ordered-current-native379-source-fact-delta-v2" || delta.Historical.ExpectedFacts != 10053 || delta.Current.ExpectedFacts != 10052 || delta.Current.PrivateRoutines != 8 || delta.Current.Rules != 379 || delta.Current.RoleSites != 565 || len(delta.PerRule) != 379 {
		return errors.New("native379 v2 source transition cardinality refused")
	}
	oldTotal, currentTotal := 1, 1
	for i, row := range delta.PerRule {
		if row.RuleID != packet.Rules[i].ID || row.Current != packet.Rules[i].ExpectedFacts || row.Current-row.Historical != row.Delta {
			return errors.New("native379 v2 per-rule source transition refused")
		}
		oldTotal += row.Historical
		currentTotal += row.Current
	}
	if oldTotal != 10053 || currentTotal != 10052 {
		return errors.New("native379 v2 source fact accounting refused")
	}
	if !native379V2ValidSHA(packet.Authority.SourceInventorySHA256) || !native379V2ValidSHA(packet.Authority.GeneratedIdentitiesSHA256) || !native379V2ValidSHA(packet.Authority.SourceFactDeltaSHA256) {
		return errors.New("native379 v2 source metadata binding refused")
	}
	factCounts := map[string]int{}
	seen := map[string]bool{}
	build := 0
	for _, fact := range packet.ExpectedFacts {
		key := fact.Kind + "\x00" + fact.Identity
		if fact.Kind == "" || fact.Identity == "" || seen[key] {
			return errors.New("native379 v2 duplicate/empty expected fact refused")
		}
		seen[key] = true
		if fact.Kind == "build" {
			build++
			if !orderedCurrentNative379V2JSONEqual(fact.Fact, packet.ReferenceProvenance) {
				return errors.New("native379 v2 historical provenance row differs")
			}
			continue
		}
		var identity []json.RawMessage
		if json.Unmarshal([]byte(fact.Identity), &identity) != nil || len(identity) < 1 {
			return errors.New("native379 v2 fact identity refused")
		}
		var ruleID string
		if json.Unmarshal(identity[0], &ruleID) != nil {
			return errors.New("native379 v2 fact rule refused")
		}
		factCounts[ruleID]++
	}
	if build != 1 {
		return errors.New("native379 v2 build row cardinality refused")
	}
	for _, rule := range packet.Rules {
		if factCounts[rule.ID] != rule.ExpectedFacts {
			return errors.New("native379 v2 complete per-rule expected set refused")
		}
		delete(factCounts, rule.ID)
	}
	if len(factCounts) != 0 {
		return errors.New("native379 v2 unknown expected rule refused")
	}
	limits := packet.Limits
	if limits.MaxRows != 38240 || limits.MaxBytes != 85983232 || limits.MaxMilliseconds != 750000 || limits.MaxPacketBytes != 33554432 || limits.SQLMilliseconds != 10000 || limits.LockMilliseconds != 3000 || limits.CleanupMilliseconds != 3000 {
		return errors.New("native379 v2 unchanged finite caps refused")
	}
	return nil
}

func TestNative379V2PacketWireAndEveryRecordedControl(t *testing.T) {
	// Offline source compilation only: never installs SQL or starts PostgreSQL.
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("exact source compiler Node unavailable")
	}
	hash, err := registrationReferenceHashFile(node)
	if err != nil || hash != "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068" {
		t.Fatal("exact source compiler Node identity refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	module := filepath.Join(orderedCurrentNative379V2Root(), "services/platform/migrations/tools/ordered-current-native379-packet-v2.mjs")
	cmd := exec.CommandContext(ctx, node, module, "--json")
	cmd.Env = []string{"PATH=" + filepath.Dir(node), "LANG=C", "LC_ALL=C", "TZ=UTC"}
	stdout := &orderedCurrentNative379V2LimitedBuffer{limit: 33554432}
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		t.Fatal("closed source packet regeneration refused")
	}
	raw := stdout.buffer.Bytes()
	admitted, err := native379V2AdmitReviewedRaw(raw, orderedCurrentNative379V2SHA256(raw))
	if err != nil {
		t.Fatal(err)
	}
	packet := admitted.packet
	if len(packet.Rules) != 379 || len(packet.Controls) != 589 || len(packet.ExpectedFacts) != 10052 || len(packet.Raw) != len(raw) || !bytes.Equal(packet.Raw, raw) {
		t.Fatal("complete raw/typed source view differs")
	}

	for _, kind := range []string{"raw", "raw-and-wire", "sql-and-sha", "entry", "phase", "limits", "expected-fact", "expected-outcome"} {
		changed := packet.clone()
		switch kind {
		case "raw":
			changed.Raw[0] = 'X'
		case "raw-and-wire":
			changed.Raw[0] = 'X'
			changed.WireSHA256 = orderedCurrentNative379V2SHA256(changed.Raw)
		case "sql-and-sha":
			changed.Controls[0].Program.Steps[0].SQL = "SELECT 123"
			changed.Controls[0].Program.Steps[0].SQLSHA256 = orderedCurrentNative379V2SHA256([]byte("SELECT 123"))
		case "entry":
			changed.Entry.IndependentAdmission.SQL = "SELECT true"
		case "phase":
			changed.Phases[0].Limits.MaxRows++
		case "limits":
			changed.Limits.MaxMilliseconds++
		case "expected-fact":
			changed.ExpectedFacts[0].Fact = json.RawMessage(`{}`)
		case "expected-outcome":
			changed.Controls[0].Program.Steps[0].Expected.Outcome = "rows"
		}
		if native379V2TetherPacket(changed) == nil || validateOrderedCurrentNative379V2PacketStructure(changed) == nil || validateOrderedCurrentNative379V2ControlResults(changed, nil) == nil {
			t.Fatal("raw/typed mutation admitted", kind)
		}
	}

	results := orderedCurrentNative379V2TestControlResults(packet)
	evidence := native379V2TestAssertionBudgetEvidence(t, packet, results)
	if err := native379V2ValidateBudgetEvidence(packet, results, evidence); err != nil {
		t.Fatal(err)
	}
	t.Logf("complete authenticated-packet source-model ledger: rows=%d bytes=%d forged_rows=%d forged_bytes=%d (mock snapshots/session, not native observations)", evidence.Total.Rows, evidence.Total.Bytes, evidence.Phases["forged-entry"].Rows, evidence.Phases["forged-entry"].Bytes)
	changedEvidence := evidence
	changedEvidence.Total.Bytes--
	if native379V2ValidateBudgetEvidence(packet, results, changedEvidence) == nil {
		t.Fatal("forged receipt ledger totals admitted")
	}
	// Omit a real expected assertion and honestly recompute all totals. Completeness
	// must still refuse; a recomputed summary is not an observation proof.
	changedEvidence = native379V2OmitAssertionCharge(t, packet, evidence)
	if native379V2ValidateBudgetEvidence(packet, results, changedEvidence) == nil {
		t.Fatal("omitted assertion charge with consistent totals admitted")
	}

	t.Run("zero-row-assertions-preserve-complete-physical-feasibility", func(t *testing.T) {
		required, err := native379V2PhysicalRowCosts(packet)
		if err != nil {
			t.Fatal(err)
		}
		if required["forged-entry"] != 1923 {
			t.Fatal("complete program row cost differs", required)
		}
		if err := native379V2RequireFeasibleRows(packet); err != nil {
			t.Fatal(err)
		}
	})

	if err := validateOrderedCurrentNative379V2ControlResults(packet, results); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"partial", "sqlstate", "role", "assertion-omitted", "assertion-misplaced", "assertion-parameters", "assertion-cross-session", "assertion-source", "assertion-cross-user", "assertion-time", "assertion-borrowed-placement", "carried-before-poison", "poison-prior-error", "recovery-omitted", "control-time-overflow", "observation", "self-consistent-forged-observation", "backend", "timeout", "restore"} {
		changed := cloneOrderedCurrentNative379V2ControlResults(results)
		switch kind {
		case "partial":
			changed = changed[:len(changed)-1]
		case "sqlstate":
			changed[0].Steps[0].SQLState = "42501"
		case "role":
			changed[0].Steps[0].RoleAssertion.AssertedRole = "forged"
		case "assertion-omitted":
			changed[0].Steps[0].RoleAssertion = nil
		case "assertion-misplaced":
			changed[0].Steps[0].RoleAssertion.Placement = "after-recovery"
		case "assertion-parameters":
			changed[0].Steps[0].RoleAssertion.ParameterSHA256 = strings.Repeat("0", 64)
		case "assertion-cross-session":
			changed[0].Steps[0].RoleAssertion.BoundBackendPID++
		case "assertion-source":
			changed[0].Steps[0].RoleAssertion.SourceStepSQLSHA256 = strings.Repeat("0", 64)
		case "assertion-cross-user":
			changed[0].Steps[0].RoleAssertion.BoundSessionUser = "borrowed-user"
		case "assertion-time":
			changed[0].Steps[0].RoleAssertion.ElapsedNanoseconds = int64(time.Second)
		case "assertion-borrowed-placement":
			changed[0].Steps[1].RoleAssertion = changed[0].Steps[0].RoleAssertion
		case "poison-prior-error":
			for ci := range changed {
				if changed[ci].ID == "restore:transaction" {
					for si := range changed[ci].Steps {
						if changed[ci].Steps[si].ID == "mutate" {
							changed[ci].Steps[si].SQLState = "42501"
						}
					}
				}
			}
		case "recovery-omitted":
			for ci := range changed {
				for si := range changed[ci].Steps {
					if changed[ci].Steps[si].RoleObservation == "after-recovery" {
						changed[ci].Steps[si].RoleAssertion = nil
					}
				}
			}
		case "carried-before-poison":
			for ci := range changed {
				for si := range changed[ci].Steps {
					if changed[ci].Steps[si].RoleObservation == "before-poison" {
						changed[ci].Steps[si].CarriedAssertionSHA256 = strings.Repeat("0", 64)
					}
				}
			}
		case "control-time-overflow":
			changed[0].Milliseconds = int64(^uint64(0) >> 1)
		case "observation":
			changed[0].Steps[0].Observation = json.RawMessage(`{}`)
		case "self-consistent-forged-observation":
			changed[0].Steps[0].Observation = json.RawMessage(`{"sqlState":"42501"}`)
			changed[0].Steps[0].ObservedSHA256 = orderedCurrentNative379V2SHA256(changed[0].Steps[0].Observation)
		case "backend":
			changed[0].Steps[0].BoundBackendPID = 0
		case "timeout":
			changed[0].Steps[0].TimedOut = true
		case "restore":
			changed[0].Restored = false
		}
		if err := validateOrderedCurrentNative379V2ControlResults(packet, changed); err == nil {
			t.Fatal("forged/partial recorded control evidence admitted", kind)
		}
	}
	var poison orderedCurrentNative379V2Control
	for _, control := range packet.Controls {
		if control.ID == "restore:transaction" {
			poison = control
			break
		}
	}
	if poison.ID == "" {
		t.Fatal("complete source packet lacks transaction poison control")
	}
	var detached orderedCurrentNative379V2Control
	detachedRaw, _ := json.Marshal(poison)
	_ = json.Unmarshal(detachedRaw, &detached)
	detached.Program.Steps[0].SQL = "SELECT 123"
	refused := &orderedCurrentNative379V2PoisonScript{}
	if _, err := orderedCurrentNative379V2ExecuteControlSession(ctx, refused, packet, detached); err == nil || len(refused.calls) != 0 {
		t.Fatal("detached executable control reached session")
	}
	script := &orderedCurrentNative379V2PoisonScript{control: poison, txStatus: 'I', currentRole: "zasp_test", sessionUser: "zasp_test", backendPID: 37980}
	scriptCtx, stopScript := context.WithTimeout(context.Background(), time.Duration(packet.Limits.SQLMilliseconds)*time.Millisecond)
	defer stopScript()
	result, err := orderedCurrentNative379V2ExecuteControlSession(scriptCtx, script, packet, poison)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := "assert:mutate,query:mutate,query:probe,exec:restore,assert-after:restore,assert:assert-restored,query:assert-restored"
	if !strings.Contains(strings.Join(script.calls, ","), wantOrder) || !result.Restored || script.index != len(poison.Program.Steps) {
		t.Fatal("closed poison recovery did not restore/join declared steps")
	}
	t.Run("all-declared-error-recovery-families", func(t *testing.T) {
		covered := map[string]bool{}
		for _, control := range packet.Controls {
			for index := range control.Program.Steps {
				recovery, state, err := native379V2RecoverySource(control, index)
				if err != nil {
					t.Fatal(err)
				}
				if !recovery || covered[state] {
					continue
				}
				script := &orderedCurrentNative379V2PoisonScript{control: control, txStatus: 'I', currentRole: "zasp_test", sessionUser: "zasp_test", backendPID: 37980}
				result, err := orderedCurrentNative379V2ExecuteControlSession(context.Background(), script, packet, control)
				if err != nil {
					t.Fatalf("scripted recovery state=%s control=%s: %v", state, control.ID, err)
				}
				recovered := result.Steps[index]
				if !result.Restored || recovered.RoleAssertion == nil || recovered.RoleObservation != "after-recovery" || recovered.RecoverySQLState != state || recovered.RecoveryPredecessorSHA256 == "" {
					t.Fatal("fresh recovery guard/link absent", state)
				}
				covered[state] = true
			}
		}
		for _, state := range []string{"42883", "42501", "25P02", "21000", "ZX001", "22023"} {
			if !covered[state] {
				t.Fatal("declared recovery family omitted", state)
			}
		}
	})

	copy := packet.clone()
	copy.Raw[0] = 'X'
	copy.ExpectedFacts[0].Fact[0] = 'X'
	copy.Authority.Generated[orderedCurrentNative379V2ModuleFile] = "changed"
	if packet.Raw[0] == 'X' || packet.ExpectedFacts[0].Fact[0] == 'X' || packet.Authority.Generated[orderedCurrentNative379V2ModuleFile] == "changed" {
		t.Fatal("authenticated raw/typed packet clone aliases source authority")
	}
	// Recompute only test-local authority: semantic flags still must refuse.
	object, err := native379V2StrictJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"installable", "nativeVerified", "captureAuthority"} {
		object[flag] = true
		changed, err := orderedCurrentNative379V2CanonicalJSONFromValue(object)
		if err != nil {
			t.Fatal(err)
		}
		changed = append(changed, '\n')
		if _, err := native379V2AdmitReviewedRaw(changed, orderedCurrentNative379V2SHA256(changed)); err == nil {
			t.Fatal("promoted source packet admitted", flag)
		}
		object[flag] = false
	}
}

// Offline scripted controls; these construct no native evidence.
func orderedCurrentNative379V2TestControlResults(packet orderedCurrentNative379V2Packet) []orderedCurrentNative379V2ControlResult {
	results := make([]orderedCurrentNative379V2ControlResult, 0, len(packet.Controls))
	for _, phase := range packet.Phases {
		for _, id := range phase.ControlIDs {
			var control orderedCurrentNative379V2Control
			for _, candidate := range packet.Controls {
				if candidate.ID == id {
					control = candidate
					break
				}
			}
			result := orderedCurrentNative379V2ControlResult{ID: control.ID, Phase: control.Phase, MutationSHA256: control.MutationSHA256, Milliseconds: 1, Restored: true}
			for _, step := range control.Program.Steps {
				sqlState := "00000"
				if step.Expected.SQLState != nil {
					sqlState = *step.Expected.SQLState
				}

				observation := json.RawMessage(`{"sqlState":"` + sqlState + `"}`)
				switch step.Expected.Outcome {
				case "capture", "equal-captured":
					observation, _ = orderedCurrentNative379V2CanonicalJSONFromValue([]any{map[string]any{"snapshot": "mock-" + step.Expected.Key}})
				case "rows":
					value, _ := orderedCurrentNative379V2DecodeExpected(step.Expected.Rows)
					observation, _ = orderedCurrentNative379V2CanonicalJSONFromValue(native379V2TestResolveBindings(value))
				case "one-row", "one-json-row":
					value, _ := orderedCurrentNative379V2DecodeExpected(step.Expected.Value)
					observation, _ = orderedCurrentNative379V2CanonicalJSONFromValue([]any{map[string]any{"value": native379V2TestResolveBindings(value)}})
				}

				stepIndex := len(result.Steps)
				roleObservation, role, placementErr := native379V2RolePlacement(control, stepIndex)
				if placementErr != nil {
					panic(placementErr)
				}
				role = orderedCurrentNative379V2ExpectedAssertedRole(role, "zasp_test")
				var recoverySHA, recoveryState string
				if roleObservation == "after-recovery" {
					var err error
					recoverySHA, recoveryState, err = native379V2RecoveryEvidence(control, stepIndex, result.Steps[stepIndex-1])
					if err != nil {
						panic(err)
					}
				}

				var assertion *native379V2AssertionReceipt
				var carried string
				if roleObservation == "before-poison" {
					carried = native379V2AssertionReceiptSHA(*result.Steps[len(result.Steps)-1].RoleAssertion)
				} else {
					receipt := native379V2AssertionReceiptFor(native379V2SessionBinding{ControlID: control.ID, User: "zasp_test", PID: 37980}, step, roleObservation, role, 0)
					assertion = &receipt
				}
				result.Steps = append(result.Steps, orderedCurrentNative379V2ControlStepResult{ID: step.ID, Outcome: step.Expected.Outcome, SQLState: sqlState, DeclaredRole: step.Role, RoleAssertion: assertion, CarriedAssertionSHA256: carried, RecoveryPredecessorSHA256: recoverySHA, RecoverySQLState: recoveryState, BoundSessionUser: "zasp_test", BoundBackendPID: 37980, RoleObservation: roleObservation, Observation: observation, ObservedSHA256: orderedCurrentNative379V2SHA256(observation), Matched: true})
			}
			results = append(results, result)
		}
	}
	return results
}

type orderedCurrentNative379V2PoisonScript struct {
	control                   orderedCurrentNative379V2Control
	index                     int
	txStatus                  byte
	currentRole               string
	sessionUser               string
	backendPID                int32
	recoveryObservationNeeded bool
	calls                     []string
}

func (script *orderedCurrentNative379V2PoisonScript) SessionIdentity(context.Context) (string, int32, error) {
	script.calls = append(script.calls, "identity")
	return script.sessionUser, script.backendPID, nil
}

func (script *orderedCurrentNative379V2PoisonScript) AssertRole(ctx context.Context, binding native379V2SessionBinding, step orderedCurrentNative379V2ProgramStep, placement, role string) (native379V2AssertionReceipt, error) {
	if script.txStatus == 'E' {
		script.calls = append(script.calls, "assert-refused:"+step.ID)
		return native379V2AssertionReceipt{}, &pgconn.PgError{Code: "25P02"}
	}
	label := "assert:" + step.ID
	if script.recoveryObservationNeeded {
		label = "assert-after:" + step.ID
		script.recoveryObservationNeeded = false
	}
	script.calls = append(script.calls, label)
	if role != script.currentRole || binding.User != script.sessionUser || binding.PID != script.backendPID {
		return native379V2AssertionReceipt{}, &pgconn.PgError{Code: "22012"}
	}
	return native379V2AssertionReceiptFor(binding, step, placement, role, 0), nil
}
func (script *orderedCurrentNative379V2PoisonScript) ExecStep(_ context.Context, sql string) error {
	step := script.control.Program.Steps[script.index]
	if step.SQL != sql {
		return errors.New("script received unexpected SQL")
	}
	script.calls = append(script.calls, "exec:"+step.ID)
	script.index++
	if step.ID == "setup-session" && strings.HasPrefix(sql, "RESET ROLE;") {
		script.txStatus = 'I'
		script.currentRole = script.sessionUser
	}
	if step.ID == "begin" && sql == "BEGIN" {
		script.txStatus = 'T'
	}
	if step.ID == "source-frame" && strings.HasPrefix(sql, "SET LOCAL ROLE zasp_discovery_authority;") {
		script.currentRole = "zasp_discovery_authority"
	}
	if step.ID == "setup" {
		script.txStatus = 'T'
		script.currentRole = "zasp_discovery_authority"
	}
	if step.ID == "recover-probe" {
		if script.txStatus != 'E' {
			return errors.New("script savepoint recovery outside aborted transaction")
		}
		script.txStatus = 'T'
		script.recoveryObservationNeeded = true
	}
	if step.ID == "restore" {
		if script.txStatus != 'E' && script.txStatus != 'T' {
			return errors.New("script restore was not reached from aborted transaction")
		}
		script.txStatus = 'I'
		if sql == native379V2FullRestoreSQL {
			script.currentRole = "zasp_discovery_authority"
		} else if sql == "ROLLBACK" {
			script.currentRole = script.sessionUser
		} else {
			return errors.New("script unknown restoration bytes")
		}
		script.recoveryObservationNeeded = true
	}
	return nil
}

func (script *orderedCurrentNative379V2PoisonScript) QueryStep(_ context.Context, sql string) ([]map[string]any, error) {
	step := script.control.Program.Steps[script.index]
	if step.SQL != sql {
		return nil, errors.New("script received unexpected SQL")
	}
	script.calls = append(script.calls, "query:"+step.ID)
	script.index++
	if step.Expected.Outcome == "error" {
		script.txStatus = 'E'
		return nil, &pgconn.PgError{Code: *step.Expected.SQLState}
	}
	var resolve func(any) any
	resolve = func(value any) any {
		if object, ok := value.(map[string]any); ok {
			if binding, exists := object["binding"]; exists && len(object) == 1 {
				if binding == "owned-session-user" {
					return script.sessionUser
				}
				return script.backendPID
			}
			copy := make(map[string]any, len(object))
			for key, nested := range object {
				copy[key] = resolve(nested)
			}
			return copy
		}
		if array, ok := value.([]any); ok {
			copy := make([]any, len(array))
			for index, nested := range array {
				copy[index] = resolve(nested)
			}
			return copy
		}
		return value
	}
	switch step.Expected.Outcome {
	case "capture", "equal-captured":
		return []map[string]any{{"snapshot": "mock-" + step.Expected.Key}}, nil
	case "one-row", "one-json-row":
		value, err := orderedCurrentNative379V2DecodeExpected(step.Expected.Value)
		if err != nil {
			return nil, err
		}
		return []map[string]any{{"value": resolve(value)}}, nil
	case "rows":
		value, err := orderedCurrentNative379V2DecodeExpected(step.Expected.Rows)
		if err != nil {
			return nil, err
		}
		array := resolve(value).([]any)
		rows := make([]map[string]any, len(array))
		for index, row := range array {
			rows[index] = row.(map[string]any)
		}
		return rows, nil
	default:
		return nil, errors.New("script query outcome refused")
	}
}

func (script *orderedCurrentNative379V2PoisonScript) TxStatus() byte { return script.txStatus }

func (script *orderedCurrentNative379V2PoisonScript) CleanupRollback(context.Context) error {
	script.txStatus = 'I'
	return nil
}

// JSON.stringify preserves literal U+2028/U+2029. Go escapes those runes even
// with EscapeHTML disabled. Decode ONLY the encoder's actual string escapes;
// an escaped backslash followed by literal u2028/u2029 must remain unchanged.
func native379V2JSONStringSeparators(encoded []byte) []byte {
	out := make([]byte, 0, len(encoded))
	inString := false
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		if c == '"' {
			inString = !inString
			out = append(out, c)
			continue
		}
		if inString && c == '\\' && i+1 < len(encoded) {
			if i+6 <= len(encoded) && (string(encoded[i:i+6]) == `\u2028` || string(encoded[i:i+6]) == `\u2029`) {
				last := byte(0xa8)
				if encoded[i+5] == '9' {
					last = 0xa9
				}
				out = append(out, 0xe2, 0x80, last)
				i += 5
				continue
			}
			out = append(out, c, encoded[i+1])
			i++
			continue
		}
		out = append(out, c)
	}
	return out
}
func TestNative379V2CanonicalWirePreservesJSStringBoundaries(t *testing.T) {
	t.Run("struct-map-receipt-canonical-equivalence", func(t *testing.T) {
		value := struct {
			Z string `json:"z"`
			A string `json:"a"`
		}{Z: "<>&\u2028\u2029", A: "receipt"}
		structured, err := orderedCurrentNative379V2CanonicalJSONFromValue(value)
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := orderedCurrentNative379V2CanonicalJSONFromValue(map[string]any{"a": value.A, "z": value.Z})
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := orderedCurrentNative379V2CanonicalJSON(structured)
		if err != nil || !bytes.Equal(structured, mapped) || !bytes.Equal(structured, normalized) {
			t.Fatal("struct receipt canonical order differs from map/raw replay")
		}
	})

	source := map[string]any{"text": "<>&\u2028\u2029", "literal": `\u2028 \u2029`, "quotes": `"\`, "primitives": []any{nil, true, json.Number("12")}}
	raw, err := orderedCurrentNative379V2CanonicalJSONFromValue(source)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"literal":"\\u2028 \\u2029","primitives":[null,true,12],"quotes":"\"\\","text":"<>&` + "\u2028\u2029" + `"}`)
	if !bytes.Equal(raw, want) {
		t.Fatal("JS string primitive/separator/literal-backslash boundary drift")
	}
	canonical, err := orderedCurrentNative379V2CanonicalJSON(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		t.Fatal("canonical JS wire did not round-trip")
	}
}

// Test-only dependency boundary. Native callers never provide a pinset/binder.
var native379V2BindGo = registrationReferenceBindBuild

func native379V2ValidateAnchorSet(pins []string) error {
	if len(pins) != 7 {
		return errors.New("native379 v2 complete anchor set required")
	}
	for _, pin := range pins {
		if !native379V2ValidSHA(pin) {
			return errors.New("native379 v2 empty/invalid compiled anchor refused")
		}
	}
	return nil
}
func native379V2ObservedStepMatches(step orderedCurrentNative379V2ProgramStep, got orderedCurrentNative379V2ControlStepResult, captures map[string]any) bool {
	observed, err := orderedCurrentNative379V2DecodeExpected(got.Observation)
	if err != nil {
		return false
	}
	switch step.Expected.Outcome {
	case "command-success", "command-complete", "error":
		object, ok := observed.(map[string]any)
		return ok && len(object) == 1 && object["sqlState"] == got.SQLState
	case "capture", "equal-captured", "one-row", "one-json-row":
		rows, ok := observed.([]any)
		if !ok || len(rows) != 1 {
			return false
		}
		row, ok := rows[0].(map[string]any)
		if !ok || len(row) != 1 {
			return false
		}
		var value any
		for _, v := range row {
			value = v
		}
		if step.Expected.Outcome == "capture" {
			captures[step.Expected.Key] = value
			return true
		}
		if step.Expected.Outcome == "equal-captured" {
			prior, exists := captures[step.Expected.Key]
			return exists && orderedCurrentNative379V2MatchValue(prior, value, got.BoundSessionUser, got.BoundBackendPID)
		}
		expected, err := orderedCurrentNative379V2DecodeExpected(step.Expected.Value)
		return err == nil && orderedCurrentNative379V2MatchValue(expected, value, got.BoundSessionUser, got.BoundBackendPID)
	case "rows":
		expected, err := orderedCurrentNative379V2DecodeExpected(step.Expected.Rows)
		return err == nil && orderedCurrentNative379V2MatchValue(expected, observed, got.BoundSessionUser, got.BoundBackendPID)
	}
	return false
}
func native379V2TestResolveBindings(value any) any {
	switch v := value.(type) {
	case map[string]any:
		if binding, ok := v["binding"]; ok && len(v) == 1 {
			if binding == "owned-session-user" {
				return "zasp_test"
			}
			return int32(37980)
		}
		copy := map[string]any{}
		for k, x := range v {
			copy[k] = native379V2TestResolveBindings(x)
		}
		return copy
	case []any:
		copy := make([]any, len(v))
		for i, x := range v {
			copy[i] = native379V2TestResolveBindings(x)
		}
		return copy
	}
	return value
}

// Synthetic small limits test the same counter, without reducing actual packet
// cardinalities or changing any declared capture limit.
func TestNative379V2RuntimeBudgetRefusesBeforeRetention(t *testing.T) {
	var packet orderedCurrentNative379V2Packet
	packet.Limits.MaxRows = 3
	packet.Limits.MaxBytes = 1000
	packet.Phases = append(packet.Phases, struct {
		ID         string   `json:"id"`
		ControlIDs []string `json:"controlIds"`
		Limits     struct {
			MaxRows         int `json:"maxRows"`
			MaxBytes        int `json:"maxBytes"`
			MaxMilliseconds int `json:"maxMilliseconds"`
		} `json:"limits"`
	}{ID: "test"})
	packet.Phases[0].Limits.MaxRows = 2
	packet.Phases[0].Limits.MaxBytes = 1000
	packet.Phases[0].Limits.MaxMilliseconds = 10000
	budget := native379V2NewBudget(packet)
	ctx, cancel, err := budget.phase(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if native379V2Charge(ctx, 1, map[string]any{"a": 1}) != nil || native379V2Charge(ctx, 1, map[string]any{"a": 2}) != nil {
		t.Fatal("bounded rows refused")
	}
	rows, bytesSeen := budget.rows, budget.bytes
	if native379V2Charge(ctx, 1, map[string]any{"a": 3}) == nil || budget.rows != rows || budget.bytes != bytesSeen {
		t.Fatal("overflow was retained")
	}
	budget.packet.Phases[0].Limits.MaxBytes = bytesSeen
	if native379V2Charge(ctx, 0, map[string]any{"large": strings.Repeat("x", 100)}) == nil || budget.bytes != bytesSeen {
		t.Fatal("bytes overflow retained")
	}
	expired, cancelExpired := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancelExpired()
	if native379V2Charge(expired, 0, nil) == nil || budget.bytes != bytesSeen {
		t.Fatal("expired phase charged")
	}
	budget.deadlines["test"] = time.Now().Add(-time.Second)
	again, cancelAgain, err := budget.phase(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer cancelAgain()
	if again.Err() != context.DeadlineExceeded {
		t.Fatal("reentry reset phase deadline")
	}
	// A phase's cancellation/expiry is local. Starting drift from the
	// global fixture context must retain its own full cap, not pristine's cap.
	packet.Phases = append(packet.Phases, packet.Phases[0])
	packet.Phases[1].ID = "drift"
	independent := native379V2NewBudget(packet)
	global, stopGlobal := context.WithCancel(context.Background())
	defer stopGlobal()
	pristine, stopPristine, e := independent.phase(global, "test")
	if e != nil {
		t.Fatal(e)
	}
	stopPristine()
	if pristine.Err() != context.Canceled {
		t.Fatal("phase cancellation absent")
	}
	independent.deadlines["test"] = time.Now().Add(-time.Second)
	expiredPhase, stopExpired, e := independent.phase(global, "test")
	if e != nil {
		t.Fatal(e)
	}
	defer stopExpired()
	drift, stopDrift, e := independent.phase(global, "drift")
	if e != nil {
		t.Fatal(e)
	}
	defer stopDrift()
	if expiredPhase.Err() != context.DeadlineExceeded || global.Err() != nil || drift.Err() != nil || native379V2Charge(drift, 1, map[string]any{"v": 1}) != nil {
		t.Fatal("pristine cancellation/expiry leaked into drift")
	}
}

type native379V2FakeRows struct {
	reads  int
	closed bool
}

func (rows *native379V2FakeRows) FieldDescriptions() []pgconn.FieldDescription {
	return []pgconn.FieldDescription{{Name: "v"}}
}
func (rows *native379V2FakeRows) Values() ([]any, error) { return []any{rows.reads}, nil }
func (rows *native379V2FakeRows) Next() bool             { rows.reads++; return rows.reads <= 10 }
func (rows *native379V2FakeRows) Err() error             { return nil }
func (rows *native379V2FakeRows) Close()                 { rows.closed = true }
func TestNative379V2RowStreamClosesAtBudget(t *testing.T) {
	var packet orderedCurrentNative379V2Packet
	packet.Limits.MaxRows = 2
	packet.Limits.MaxBytes = 1000
	packet.Phases = append(packet.Phases, struct {
		ID         string   `json:"id"`
		ControlIDs []string `json:"controlIds"`
		Limits     struct {
			MaxRows         int `json:"maxRows"`
			MaxBytes        int `json:"maxBytes"`
			MaxMilliseconds int `json:"maxMilliseconds"`
		} `json:"limits"`
	}{ID: "test"})
	packet.Phases[0].Limits.MaxRows = 2
	packet.Phases[0].Limits.MaxBytes = 1000
	packet.Phases[0].Limits.MaxMilliseconds = 1000
	budget := native379V2NewBudget(packet)
	ctx, cancel, err := budget.phase(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	stream := &native379V2FakeRows{}
	if result, err := native379V2ReadRows(ctx, stream); err == nil || result != nil || !stream.closed || stream.reads != 3 || budget.rows != 2 || len(budget.charges) != 2 {
		t.Fatal("overflow stream retained/unclosed/unbounded")
	}
}

func TestNative379V2AssertionReceiptClosedBindings(t *testing.T) {
	step := orderedCurrentNative379V2ProgramStep{ID: "probe", Role: "fixture-owner", SQL: "SELECT 1"}
	step.SQLSHA256 = orderedCurrentNative379V2SHA256([]byte(step.SQL))
	binding := native379V2SessionBinding{ControlID: "test-control", User: "owned-user", PID: 37980}
	receipt := native379V2AssertionReceiptFor(binding, step, "before", binding.User, 0)
	if err := native379V2ValidateAssertionReceipt(receipt, binding, step, "before", binding.User); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"sql", "params", "placement", "control", "step", "source", "session", "pid", "rows", "tag", "timeout", "status", "negative-time", "huge-time"} {
		changed := receipt
		switch kind {
		case "sql":
			changed.SQLSHA256 = strings.Repeat("0", 64)
		case "params":
			changed.ParameterSHA256 = strings.Repeat("0", 64)
		case "placement":
			changed.Placement = "after-recovery"
		case "control":
			changed.ControlID = "other"
		case "step":
			changed.StepID = "other"
		case "source":
			changed.SourceStepSQLSHA256 = strings.Repeat("0", 64)
		case "session":
			changed.BoundSessionUser = "borrowed"
		case "pid":
			changed.BoundBackendPID++
		case "rows":
			changed.RowCount = 1
		case "tag":
			changed.CommandTag = "SELECT 1"
		case "timeout":
			changed.TimedOut = true
		case "status":
			changed.SQLState = "22012"
		case "negative-time":
			changed.ElapsedNanoseconds = -1
		case "huge-time":
			changed.ElapsedNanoseconds = int64(^uint64(0) >> 1)
		}
		if native379V2ValidateAssertionReceipt(changed, binding, step, "before", binding.User) == nil {
			t.Fatal("forged assertion admitted", kind)
		}
	}
}

func native379V2TestAssertionBudgetEvidence(t *testing.T, packet orderedCurrentNative379V2Packet, controls []orderedCurrentNative379V2ControlResult) native379V2BudgetEvidence {
	t.Helper()
	budget := native379V2NewBudget(packet)
	charge := func(phase string, rows int, value any) {
		ctx, cancel, err := budget.phase(context.Background(), phase)
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()
		if err := native379V2Charge(ctx, rows, value); err != nil {
			t.Fatalf("mock budget refused phase=%s rows=%d bytes=%d: %v", phase, budget.phaseRows[phase], budget.phaseBytes[phase], err)
		}
	}
	fixedCtx, cancel, err := budget.phase(context.Background(), "pristine-truth")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	routines, err := orderedCurrentNative379V2ExpectedRoutines(packet)
	if err != nil {
		t.Fatal(err)
	}
	for id, value := range map[string]any{"preinstall": []any{packet.Identity.ServerVersionNum, packet.Identity.Postgres, packet.Identity.Pgcrypto, "127.0.0.1", 5432, 0, 0}, "inventory": []any{"zasp_discovery_authority", []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}, routines, 1, len(packet.ExpectedFacts), 0}, "frame-before": []string{"zasp_test", "zasp_test", "pg_catalog", "UTC", "off", "read committed"}, "frame-after": []string{"zasp_test", "zasp_test", "pg_catalog", "UTC", "off", "read committed"}, "admission": true, "catalog": true} {
		if err := native379V2ChargeFixed(fixedCtx, id, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, fact := range packet.ExpectedFacts {
		charge("pristine-truth", 1, map[string]any{"kind": fact.Kind, "identity": fact.Identity, "fact": fact.Fact})
	}
	for _, control := range controls {
		first := control.Steps[0]
		charge(control.Phase, 1, map[string]any{"session_user": first.BoundSessionUser, "backend_pid": first.BoundBackendPID})
		for _, step := range control.Steps {
			if step.RoleAssertion != nil {
				charge(control.Phase, 0, *step.RoleAssertion)
			}
			var value any
			decoder := json.NewDecoder(bytes.NewReader(step.Observation))
			decoder.UseNumber()
			if decoder.Decode(&value) != nil {
				t.Fatal("step decode")
			}
			if rows, ok := value.([]any); ok {
				for _, row := range rows {
					charge(control.Phase, 1, row)
				}
			} else {
				charge(control.Phase, 0, value)
			}
		}
	}
	return budget.evidence()
}
func native379V2OmitAssertionCharge(t *testing.T, packet orderedCurrentNative379V2Packet, evidence native379V2BudgetEvidence) native379V2BudgetEvidence {
	t.Helper()
	budget := native379V2NewBudget(packet)
	removed := false
	for _, charge := range evidence.Charges {
		if !removed && bytes.Contains(charge.Value, []byte(`"kind":"server-role-session-assertion-v1"`)) {
			removed = true
			continue
		}
		ctx, cancel, err := budget.phase(context.Background(), charge.Phase)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(charge.Value))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			t.Fatal("charge decode")
		}
		err = native379V2Charge(ctx, charge.Rows, value)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	if !removed {
		t.Fatal("mock ledger lacks assertion")
	}
	result := budget.evidence()
	result.Fixed = maps.Clone(evidence.Fixed)
	return result
}

type native379V2FakeAssertionStream struct {
	hasRow, closed bool
	state          error
	tag            string
}

func (stream *native379V2FakeAssertionStream) Next() bool { return stream.hasRow }
func (stream *native379V2FakeAssertionStream) Close()     { stream.closed = true }
func (stream *native379V2FakeAssertionStream) Err() error { return stream.state }
func (stream *native379V2FakeAssertionStream) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag(stream.tag)
}
func TestNative379V2AssertionCompletionAndDistinctRefusals(t *testing.T) {
	for _, test := range []struct {
		name                 string
		stream               native379V2FakeAssertionStream
		cancel               bool
		wantClass, wantState string
		wantTimeout          bool
	}{
		{name: "zero", stream: native379V2FakeAssertionStream{tag: "SELECT 0"}},
		{name: "row", stream: native379V2FakeAssertionStream{hasRow: true, tag: "SELECT 1"}, wantClass: "nonzero-assertion-stream", wantState: "NON_SQL_ERROR"},
		{name: "tag", stream: native379V2FakeAssertionStream{tag: "SELECT 1"}, wantClass: "assertion-completion-refused", wantState: "NON_SQL_ERROR"},
		{name: "mismatch", stream: native379V2FakeAssertionStream{state: &pgconn.PgError{Code: "22012"}}, wantClass: "server-assertion-mismatch", wantState: "22012"},
		{name: "timeout", stream: native379V2FakeAssertionStream{state: &pgconn.PgError{Code: "57014"}}, wantClass: "server-assertion-timeout", wantState: "57014", wantTimeout: true},
		{name: "poison", stream: native379V2FakeAssertionStream{state: &pgconn.PgError{Code: "25P02"}}, wantClass: "server-assertion-error", wantState: "25P02"},
		{name: "cancel", stream: native379V2FakeAssertionStream{tag: "SELECT 0"}, cancel: true, wantClass: "server-assertion-error", wantState: "NON_SQL_ERROR"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancel {
				cancel()
			}
			err := native379V2AssertionCompletion(ctx, &test.stream)
			if !test.stream.closed {
				t.Fatal("assertion stream not closed")
			}
			if test.wantClass == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var refusal *native379V2AssertionFailure
			if !errors.As(err, &refusal) || refusal.Class != test.wantClass || refusal.SQLState != test.wantState || refusal.TimedOut != test.wantTimeout {
				t.Fatal("assertion refusal class differs", err)
			}
		})
	}
}
