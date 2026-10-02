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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	orderedCurrentNative379PacketSHA256    = "bdcd82bea5c4a34ade7f298a2ca5c7b586cd73fca36d0e4bb27b167bf3906773"
	orderedCurrentNative379ModuleFile      = "development-module.sql"
	orderedCurrentNative379ModuleSHA256    = "921fe1a2c6fc30e4d66c9ad0b2455376b5bb1afc001ee40bcef35665cfa02208"
	orderedCurrentNative379ManifestSHA256  = "f78003bb5827232f7f603da7490d1fd840818e5c62c18c3b3f85588fcda6b4cd"
	orderedCurrentNative379CollectorFile   = "development-collector.sql"
	orderedCurrentNative379CollectorSHA256 = "a8bb102e8e55abf270c425a8e685715f84569982d37819315846bbd4a0651f80"
	orderedCurrentNative379MaxResultBytes  = 4 * 1024 * 1024
)

type orderedCurrentNative379Rule struct {
	ID            string `json:"id"`
	ExpectedFacts int    `json:"expectedFacts"`
}

type orderedCurrentNative379Fact struct {
	Kind     string          `json:"kind"`
	Identity string          `json:"identity"`
	Fact     json.RawMessage `json:"fact"`
}

type orderedCurrentNative379CatalogDiagnosticEntry struct {
	Class           string `json:"class"`
	Kind            string `json:"kind"`
	Identity        string `json:"identity"`
	ExpectedSHA256  string `json:"expectedSHA256,omitempty"`
	LiveSHA256      string `json:"liveSHA256,omitempty"`
	ExpectedPreview string `json:"expectedPreview,omitempty"`
	LivePreview     string `json:"livePreview,omitempty"`
}

type orderedCurrentNative379CatalogDiagnosticCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type orderedCurrentNative379CatalogDiagnosticClassCount struct {
	Class string `json:"class"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type orderedCurrentNative379CatalogDiagnosticRelocationCount struct {
	Kind       string `json:"kind"`
	Rule       string `json:"rule"`
	FactSHA256 string `json:"factSHA256"`
	Count      int    `json:"count"`
}

type orderedCurrentNative379CatalogDiagnosticRelocation struct {
	Kind           string `json:"kind"`
	Rule           string `json:"rule"`
	FactSHA256     string `json:"factSHA256"`
	BeforeIdentity string `json:"beforeIdentity"`
	AfterIdentity  string `json:"afterIdentity"`
}

type orderedCurrentNative379CatalogDiagnosticChangedFieldCount struct {
	Kind  string `json:"kind"`
	Rule  string `json:"rule"`
	Field string `json:"field"`
	Count int    `json:"count"`
}

type orderedCurrentNative379CatalogDiagnosticChangedFieldSample struct {
	Kind            string `json:"kind"`
	Rule            string `json:"rule"`
	Field           string `json:"field"`
	ExpectedSHA256  string `json:"expectedSHA256"`
	LiveSHA256      string `json:"liveSHA256"`
	ExpectedPreview string `json:"expectedPreview"`
	LivePreview     string `json:"livePreview"`
}

type orderedCurrentNative379CatalogDiagnostic struct {
	Expected              int                                                          `json:"expected"`
	Live                  int                                                          `json:"live"`
	Missing               int                                                          `json:"missing"`
	Extra                 int                                                          `json:"extra"`
	Changed               int                                                          `json:"changed"`
	Duplicates            int                                                          `json:"duplicates"`
	Overflow              bool                                                         `json:"overflow"`
	CountOverflow         bool                                                         `json:"countOverflow,omitempty"`
	Error                 string                                                       `json:"error,omitempty"`
	ClassCounts           []orderedCurrentNative379CatalogDiagnosticCount              `json:"classCounts,omitempty"`
	KindCounts            []orderedCurrentNative379CatalogDiagnosticCount              `json:"kindCounts,omitempty"`
	RuleCounts            []orderedCurrentNative379CatalogDiagnosticCount              `json:"ruleCounts,omitempty"`
	KindClassCounts       []orderedCurrentNative379CatalogDiagnosticClassCount         `json:"kindClassCounts,omitempty"`
	RuleClassCounts       []orderedCurrentNative379CatalogDiagnosticClassCount         `json:"ruleClassCounts,omitempty"`
	RelocationCounts      []orderedCurrentNative379CatalogDiagnosticRelocationCount    `json:"relocationCounts,omitempty"`
	Relocations           []orderedCurrentNative379CatalogDiagnosticRelocation         `json:"relocations,omitempty"`
	RelocationAmbiguities int                                                          `json:"relocationAmbiguities,omitempty"`
	ChangedFieldCounts    []orderedCurrentNative379CatalogDiagnosticChangedFieldCount  `json:"changedFieldCounts,omitempty"`
	ChangedFieldSamples   []orderedCurrentNative379CatalogDiagnosticChangedFieldSample `json:"changedFieldSamples,omitempty"`
	Entries               []orderedCurrentNative379CatalogDiagnosticEntry              `json:"entries"`
}

type orderedCurrentNative379StepExpectation struct {
	Outcome  string          `json:"outcome"`
	SQLState *string         `json:"sqlState"`
	Rows     json.RawMessage `json:"rows"`
	Value    json.RawMessage `json:"value"`
	Key      string          `json:"key"`
}

type orderedCurrentNative379ProgramStep struct {
	ID        string                                 `json:"id"`
	Role      string                                 `json:"role"`
	SQL       string                                 `json:"sql"`
	SQLSHA256 string                                 `json:"sqlSHA256"`
	Expected  orderedCurrentNative379StepExpectation `json:"expected"`
}

type orderedCurrentNative379Control struct {
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
		Steps []orderedCurrentNative379ProgramStep `json:"steps"`
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

type orderedCurrentNative379Packet struct {
	Format         string `json:"format"`
	Status         string `json:"status"`
	Installable    bool   `json:"installable"`
	NativeVerified bool   `json:"nativeVerified"`
	Authority      struct {
		Generated map[string]string `json:"generated"`
	} `json:"authority"`
	Identity struct {
		ServerVersionNum int    `json:"serverVersionNum"`
		Postgres         string `json:"postgres"`
		Pgcrypto         string `json:"pgcrypto"`
	} `json:"identity"`
	Rules           []orderedCurrentNative379Rule `json:"rules"`
	ExpectedFacts   []orderedCurrentNative379Fact `json:"expectedFacts"`
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
	Controls []orderedCurrentNative379Control `json:"controls"`
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

func (packet orderedCurrentNative379Packet) clone() orderedCurrentNative379Packet {
	raw, _ := json.Marshal(packet)
	var copy orderedCurrentNative379Packet
	_ = json.Unmarshal(raw, &copy)
	copy.WireSHA256 = packet.WireSHA256
	return copy
}

type orderedCurrentNative379Stage struct {
	ID           string `json:"id"`
	Phase        string `json:"phase"`
	Milliseconds int64  `json:"milliseconds"`
}

type orderedCurrentNative379Operation struct {
	ID       string `json:"id"`
	SQLState string `json:"sqlState"`
}

type orderedCurrentNative379ControlStepResult struct {
	ID                  string          `json:"id"`
	Outcome             string          `json:"outcome"`
	SQLState            string          `json:"sqlState"`
	DeclaredRole        string          `json:"declaredRole"`
	ObservedRole        string          `json:"observedRole"`
	ObservedSessionUser string          `json:"observedSessionUser"`
	RoleObservation     string          `json:"roleObservation"`
	Observation         json.RawMessage `json:"observation"`
	ObservedSHA256      string          `json:"observedSHA256"`
	Matched             bool            `json:"matched"`
	TimedOut            bool            `json:"timedOut"`
}

type orderedCurrentNative379AdmittedPacket struct {
	packet   orderedCurrentNative379Packet
	rawSHA   string
	rawBytes int
}

type orderedCurrentNative379ControlResult struct {
	ID             string                                     `json:"id"`
	Phase          string                                     `json:"phase"`
	MutationSHA256 string                                     `json:"mutationSHA256"`
	Milliseconds   int64                                      `json:"milliseconds"`
	Steps          []orderedCurrentNative379ControlStepResult `json:"steps"`
	Restored       bool                                       `json:"restored"`
}

var orderedCurrentNative379PristineOperationPlan = []string{
	"preflight-identity", "dormant-module-install", "installed-inventory",
	"expected-stream-query", "expected-stream-complete", "frame-before",
	"pristine-begin", "pristine-frame", "private-admission", "catalog",
	"require", "pristine-rollback", "frame-after",
}

type orderedCurrentNative379OperationRecorder struct {
	operations []orderedCurrentNative379Operation
	invalid    bool
}

func (recorder *orderedCurrentNative379OperationRecorder) observe(id string, err error) error {
	if recorder == nil || len(recorder.operations) >= len(orderedCurrentNative379PristineOperationPlan) || id != orderedCurrentNative379PristineOperationPlan[len(recorder.operations)] {
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
	recorder.operations = append(recorder.operations, orderedCurrentNative379Operation{ID: id, SQLState: code})
	return err
}

func (recorder *orderedCurrentNative379OperationRecorder) finish() ([]orderedCurrentNative379Operation, error) {
	if recorder == nil || recorder.invalid || len(recorder.operations) != len(orderedCurrentNative379PristineOperationPlan) {
		return nil, errors.New("native379 operation evidence incomplete")
	}
	for index, operation := range recorder.operations {
		if operation.ID != orderedCurrentNative379PristineOperationPlan[index] || operation.SQLState != "00000" {
			return nil, errors.New("native379 pristine operation outcome refused")
		}
	}
	return append([]orderedCurrentNative379Operation(nil), recorder.operations...), nil
}

func validateOrderedCurrentNative379Operations(operations []orderedCurrentNative379Operation) error {
	if operations == nil || len(operations) != len(orderedCurrentNative379PristineOperationPlan) {
		return errors.New("native379 observed operation evidence absent or incomplete")
	}
	for index, operation := range operations {
		if operation.ID != orderedCurrentNative379PristineOperationPlan[index] || operation.SQLState != "00000" {
			return errors.New("native379 observed operation order or SQLSTATE refused")
		}
	}
	return nil
}

type orderedCurrentNative379Observation struct {
	Available      bool              `json:"available"`
	EndpointSHA256 string            `json:"endpointSHA256"`
	Hashes         map[string]string `json:"hashes"`
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
	Operations  []orderedCurrentNative379Operation     `json:"operations"`
	Controls    []orderedCurrentNative379ControlResult `json:"controls"`
	Restoration struct {
		TransactionRolledBack bool `json:"transactionRolledBack"`
		FrameRestored         bool `json:"frameRestored"`
	} `json:"restoration"`
}

func (observation orderedCurrentNative379Observation) clone() orderedCurrentNative379Observation {
	raw, _ := json.Marshal(observation)
	var copy orderedCurrentNative379Observation
	_ = json.Unmarshal(raw, &copy)
	return copy
}

type orderedCurrentNative379Result struct {
	Format         string                         `json:"format"`
	Status         string                         `json:"status"`
	Installable    bool                           `json:"installable"`
	Truncated      bool                           `json:"truncated"`
	PacketSHA256   string                         `json:"packetSHA256"`
	Stages         []orderedCurrentNative379Stage `json:"stages"`
	Hashes         map[string]string              `json:"hashes"`
	EndpointSHA256 string                         `json:"endpointSHA256"`
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
		Tables       int `json:"tables"`
		Routines     int `json:"routines"`
	} `json:"counts"`
	Operations  []orderedCurrentNative379Operation     `json:"operations"`
	Controls    []orderedCurrentNative379ControlResult `json:"controls"`
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

func (result orderedCurrentNative379Result) clone() orderedCurrentNative379Result {
	raw, _ := json.Marshal(result)
	var copy orderedCurrentNative379Result
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func orderedCurrentNative379TestPacket() orderedCurrentNative379Packet {
	var packet orderedCurrentNative379Packet
	packet.Format = "ordered-current-native379-packet-v1"
	packet.Status = "NATIVE-PARITY-PENDING"
	packet.Identity.ServerVersionNum = 180003
	packet.Identity.Postgres = "PostgreSQL 18.3 test"
	packet.Identity.Pgcrypto = "1.4"
	packet.WireSHA256 = orderedCurrentNative379PacketSHA256
	packet.Authority.Generated = map[string]string{
		orderedCurrentNative379ModuleFile:    orderedCurrentNative379ModuleSHA256,
		"development-manifest.json":          orderedCurrentNative379ManifestSHA256,
		orderedCurrentNative379CollectorFile: orderedCurrentNative379CollectorSHA256,
	}
	packet.Entry.Manifest = strings.Repeat("a", 64)
	packet.Entry.ManifestLiteral = "'" + packet.Entry.Manifest + "'"
	packet.Entry.IndependentAdmission.SQL = "SELECT true"
	for _, signature := range []string{
		"zasp_authorization80_ordered_current.canonical(jsonb)",
		"zasp_authorization80_ordered_current.normalize_rows(jsonb,text)",
		"zasp_authorization80_ordered_current.catalog(text)",
		"zasp_authorization80_ordered_current.require(text)",
		"zasp_authorization80_ordered_current.function_definition_public(oid)",
		"zasp_authorization80_ordered_current.function_identity_arguments_public(oid)",
		"zasp_authorization80_ordered_current.function_identity_public(oid)",
	} {
		packet.Entry.PrivateRoutineFacts = append(packet.Entry.PrivateRoutineFacts, struct {
			Identity string `json:"identity"`
		}{Identity: `["private-routines","` + signature + `"]`})
	}
	packet.Limits.MaxRows = 38240
	packet.Limits.MaxBytes = 85983232
	packet.Limits.MaxMilliseconds = 750000
	packet.Limits.MaxPacketBytes = 33554432
	packet.Limits.SQLMilliseconds = 10000
	packet.Limits.LockMilliseconds = 3000
	packet.Limits.CleanupMilliseconds = 3000
	for _, id := range []string{"preflight", "pristine-truth", "drift", "forged-entry", "null-error-lazy-demand", "frame-restoration", "cleanup-result"} {
		var phase struct {
			ID         string   `json:"id"`
			ControlIDs []string `json:"controlIds"`
			Limits     struct {
				MaxRows         int `json:"maxRows"`
				MaxBytes        int `json:"maxBytes"`
				MaxMilliseconds int `json:"maxMilliseconds"`
			} `json:"limits"`
		}
		phase.ID = id
		phase.Limits.MaxRows, phase.Limits.MaxBytes, phase.Limits.MaxMilliseconds = 12000, 1024*1024, 60000
		packet.Phases = append(packet.Phases, phase)
	}
	for phaseIndex, count := range []int{0, 0, 124, 388, 68, 9, 0} {
		for index := 0; index < count; index++ {
			id := fmt.Sprintf("test-control-%d-%03d", phaseIndex, index)
			control := orderedCurrentNative379Control{ID: id, Phase: packet.Phases[phaseIndex].ID, Category: "test", Mutation: json.RawMessage(`{}`), MutationSHA256: orderedCurrentNative379SHA256([]byte(`{}`))}
			control.Program.Format = "native379-sql-program-v1"
			control.Program.Transaction, control.Program.Connection = "owned-read-write-rollback", "same-owned-session"
			for _, stepID := range []string{"setup", "snapshot", "mutate", "probe", "restore", "assert-restored", "finish"} {
				sql := "SELECT '" + stepID + "'"
				control.Program.Steps = append(control.Program.Steps, orderedCurrentNative379ProgramStep{ID: stepID, Role: "zasp_test", SQL: sql, SQLSHA256: orderedCurrentNative379SHA256([]byte(sql)), Expected: orderedCurrentNative379StepExpectation{Outcome: "command-success"}})
			}
			control.Restoration.BeforeNextProbe = true
			control.Restoration.SnapshotSQL, control.Restoration.RestoreSQL, control.Restoration.AssertionSQL = "SELECT 'before'", "ROLLBACK", "SELECT 'after'"
			control.Restoration.ProtocolTransactionStatusAfter = "I"
			packet.Controls = append(packet.Controls, control)
			packet.Phases[phaseIndex].ControlIDs = append(packet.Phases[phaseIndex].ControlIDs, id)
		}
	}
	for index := 0; index < 379; index++ {
		facts := 27
		if index < 146 {
			facts = 26
		}
		if index < 1 {
			facts = 27
		}
		packet.Rules = append(packet.Rules, orderedCurrentNative379Rule{ID: fmt.Sprintf("test-rule-%03d", index), ExpectedFacts: facts})
	}
	for index := 0; index < 10089; index++ {
		packet.ExpectedFacts = append(packet.ExpectedFacts, orderedCurrentNative379Fact{Kind: "test", Identity: fmt.Sprintf("fact-%05d", index), Fact: json.RawMessage(`{}`)})
	}
	packet.SourceInventory.Sites = make([]json.RawMessage, 565)
	for index := range packet.SourceInventory.Sites {
		packet.SourceInventory.Sites[index] = json.RawMessage(`{}`)
	}
	return packet
}

func orderedCurrentNative379TestResult(packet orderedCurrentNative379Packet) orderedCurrentNative379Result {
	observation := orderedCurrentNative379TestObservation(packet)
	cleanup := orderedCurrentNative379TestCleanupObservation()
	result, err := buildOrderedCurrentNative379Result(packet, &observation, &cleanup, orderedCurrentNative379TestStages(packet))
	if err != nil {
		panic(err)
	}
	return result
}

func orderedCurrentNative379ExpectedRoutines(packet orderedCurrentNative379Packet) ([]string, error) {
	if len(packet.Entry.PrivateRoutineFacts) != 7 {
		return nil, errors.New("native379 pinned routine inventory cardinality refused")
	}
	routines := make([]string, 0, 7)
	seen := make(map[string]bool, 7)
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

func orderedCurrentNative379TestObservation(packet orderedCurrentNative379Packet) orderedCurrentNative379Observation {
	var observation orderedCurrentNative379Observation
	observation.Available = true
	observation.EndpointSHA256 = disposablePostgresEndpointSHA256("127.0.0.1:5432")
	observation.Hashes = map[string]string{"packet": packet.WireSHA256, "module": orderedCurrentNative379ModuleSHA256, "manifest": orderedCurrentNative379ManifestSHA256}
	observation.Server.VersionNum, observation.Server.Postgres, observation.Server.Pgcrypto = packet.Identity.ServerVersionNum, packet.Identity.Postgres, packet.Identity.Pgcrypto
	observation.Objects.SchemaOwner = "zasp_discovery_authority"
	observation.Objects.Tables = []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}
	observation.Objects.Routines, _ = orderedCurrentNative379ExpectedRoutines(packet)
	observation.Counts.Rules, observation.Counts.Facts, observation.Counts.RoleSites = len(packet.Rules), len(packet.ExpectedFacts), len(packet.SourceInventory.Sites)
	observation.Counts.Registration, observation.Counts.ExpectedRows, observation.Counts.EqualFacts = 1, len(packet.ExpectedFacts), len(packet.ExpectedFacts)
	for _, id := range orderedCurrentNative379PristineOperationPlan {
		observation.Operations = append(observation.Operations, orderedCurrentNative379Operation{ID: id, SQLState: "00000"})
	}
	observation.Restoration.TransactionRolledBack, observation.Restoration.FrameRestored = true, true
	observation.Controls = orderedCurrentNative379TestControlResults(packet)
	return observation
}

func orderedCurrentNative379TestCleanupObservation() disposablePostgresCleanupObservation {
	return disposablePostgresCleanupObservation{Available: true, PGCtlStopped: true, CommandWaitJoined: true, NormalExit: true, EndpointChecked: true, EndpointSHA256: disposablePostgresEndpointSHA256("127.0.0.1:5432"), SurvivingResourcesChecked: true}
}

func orderedCurrentNative379TestStages(packet orderedCurrentNative379Packet) []orderedCurrentNative379Stage {
	return []orderedCurrentNative379Stage{
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

func orderedCurrentNative379SHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func orderedCurrentNative379CanonicalSHA256(raw json.RawMessage) (string, error) {
	canonical, err := orderedCurrentNative379CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	return orderedCurrentNative379SHA256(canonical), nil
}

func orderedCurrentNative379CanonicalJSON(raw json.RawMessage) ([]byte, error) {
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
	return bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'}), nil
}

func orderedCurrentNative379CanonicalJSONFromValue(value any) (json.RawMessage, error) {
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, errors.New("native379 observation encoding refused")
	}
	return json.RawMessage(bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'})), nil
}

func orderedCurrentNative379DiagnosticFact(raw json.RawMessage) ([]byte, string) {
	canonical, err := orderedCurrentNative379CanonicalJSON(raw)
	if err != nil {
		canonical = append([]byte(nil), raw...)
	}
	previewRunes := []rune(string(canonical))
	if len(previewRunes) > 256 {
		previewRunes = previewRunes[:256]
	}
	return canonical, string(previewRunes)
}

func orderedCurrentNative379DiagnosticField(raw json.RawMessage) (string, string) {
	canonical, _ := orderedCurrentNative379DiagnosticFact(raw)
	previewRunes := []rune(string(canonical))
	if len(previewRunes) > 128 {
		previewRunes = previewRunes[:128]
	}
	return orderedCurrentNative379SHA256(canonical), string(previewRunes)
}

func orderedCurrentNative379DiagnosticRule(identity string) string {
	var parts []string
	decoder := json.NewDecoder(strings.NewReader(identity))
	if decoder.Decode(&parts) == nil && decoder.Decode(new(any)) == io.EOF && len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "<unclassified>"
}

func orderedCurrentNative379DiagnosticCounts(values map[string]int, limit int) ([]orderedCurrentNative379CatalogDiagnosticCount, bool) {
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
	counts := make([]orderedCurrentNative379CatalogDiagnosticCount, 0, len(keys))
	for _, key := range keys {
		counts = append(counts, orderedCurrentNative379CatalogDiagnosticCount{Name: key, Count: values[key]})
	}
	return counts, overflow
}

func orderedCurrentNative379DiagnosticClassCounts(values map[string]int, limit int) ([]orderedCurrentNative379CatalogDiagnosticClassCount, bool) {
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
	counts := make([]orderedCurrentNative379CatalogDiagnosticClassCount, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 2)
		counts = append(counts, orderedCurrentNative379CatalogDiagnosticClassCount{Class: parts[0], Name: parts[1], Count: values[key]})
	}
	return counts, overflow
}

func orderedCurrentNative379DiagnosticChangedFieldCounts(values map[string]int, limit int) ([]orderedCurrentNative379CatalogDiagnosticChangedFieldCount, bool) {
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
	counts := make([]orderedCurrentNative379CatalogDiagnosticChangedFieldCount, 0, len(keys))
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 3)
		counts = append(counts, orderedCurrentNative379CatalogDiagnosticChangedFieldCount{Kind: parts[0], Rule: parts[1], Field: parts[2], Count: values[key]})
	}
	return counts, overflow
}

func orderedCurrentNative379DiagnosticTopLevelFields(expected, live json.RawMessage) []string {
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
		leftCanonical, leftErr := orderedCurrentNative379CanonicalJSON(left)
		rightCanonical, rightErr := orderedCurrentNative379CanonicalJSON(right)
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftCanonical, rightCanonical) {
			fields = append(fields, key)
		}
	}
	sort.Strings(fields)
	return fields
}

func orderedCurrentNative379BuildCatalogDiagnostic(expected, live []orderedCurrentNative379Fact, maxEntries, maxRows, maxBytes int) orderedCurrentNative379CatalogDiagnostic {
	diagnostic := orderedCurrentNative379CatalogDiagnostic{Entries: make([]orderedCurrentNative379CatalogDiagnosticEntry, 0)}
	classCounts := make(map[string]int)
	kindCounts := make(map[string]int)
	ruleCounts := make(map[string]int)
	kindClassCounts := make(map[string]int)
	ruleClassCounts := make(map[string]int)
	changedFieldCounts := make(map[string]int)
	changedFieldSamples := make(map[string]orderedCurrentNative379CatalogDiagnosticChangedFieldSample)
	record := func(class string, fact orderedCurrentNative379Fact) {
		classCounts[class]++
		kindCounts[fact.Kind]++
		rule := orderedCurrentNative379DiagnosticRule(fact.Identity)
		ruleCounts[rule]++
		kindClassCounts[class+"\x00"+fact.Kind]++
		ruleClassCounts[class+"\x00"+rule]++
	}
	expectedByKey := make(map[string]orderedCurrentNative379Fact, len(expected))
	for _, fact := range expected {
		if fact.Kind == "build" && fact.Identity == "provenance" {
			continue
		}
		diagnostic.Expected++
		expectedByKey[fact.Kind+"\x00"+fact.Identity] = fact
	}
	liveByKey := make(map[string]orderedCurrentNative379Fact, len(live))
	bytesSeen := 0
	entries := make([]orderedCurrentNative379CatalogDiagnosticEntry, 0)
	for _, fact := range live {
		diagnostic.Live++
		bytesSeen += len(fact.Kind) + len(fact.Identity) + len(fact.Fact)
		key := fact.Kind + "\x00" + fact.Identity
		if prior, exists := liveByKey[key]; exists {
			diagnostic.Duplicates++
			record("duplicate", fact)
			priorCanonical, priorPreview := orderedCurrentNative379DiagnosticFact(prior.Fact)
			liveCanonical, livePreview := orderedCurrentNative379DiagnosticFact(fact.Fact)
			entries = append(entries, orderedCurrentNative379CatalogDiagnosticEntry{Class: "duplicate", Kind: fact.Kind, Identity: fact.Identity, ExpectedSHA256: orderedCurrentNative379SHA256(priorCanonical), LiveSHA256: orderedCurrentNative379SHA256(liveCanonical), ExpectedPreview: priorPreview, LivePreview: livePreview})
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
			canonical, preview := orderedCurrentNative379DiagnosticFact(want.Fact)
			entries = append(entries, orderedCurrentNative379CatalogDiagnosticEntry{Class: "missing", Kind: want.Kind, Identity: want.Identity, ExpectedSHA256: orderedCurrentNative379SHA256(canonical), ExpectedPreview: preview})
			continue
		}
		wantCanonical, wantPreview := orderedCurrentNative379DiagnosticFact(want.Fact)
		gotCanonical, gotPreview := orderedCurrentNative379DiagnosticFact(got.Fact)
		if !bytes.Equal(wantCanonical, gotCanonical) {
			diagnostic.Changed++
			record("changed", want)
			var expectedFields, liveFields map[string]json.RawMessage
			_ = json.Unmarshal(want.Fact, &expectedFields)
			_ = json.Unmarshal(got.Fact, &liveFields)
			for _, field := range orderedCurrentNative379DiagnosticTopLevelFields(want.Fact, got.Fact) {
				changedFieldCounts[want.Kind+"\x00"+orderedCurrentNative379DiagnosticRule(want.Identity)+"\x00"+field]++
				if _, exists := changedFieldSamples[want.Kind+"\x00"+orderedCurrentNative379DiagnosticRule(want.Identity)+"\x00"+field]; !exists {
					expectedValue, expectedOK := expectedFields[field]
					liveValue, liveOK := liveFields[field]
					if !expectedOK {
						expectedValue = json.RawMessage(`null`)
					}
					if !liveOK {
						liveValue = json.RawMessage(`null`)
					}
					expectedSHA, expectedPreview := orderedCurrentNative379DiagnosticField(expectedValue)
					liveSHA, livePreview := orderedCurrentNative379DiagnosticField(liveValue)
					changedFieldSamples[want.Kind+"\x00"+orderedCurrentNative379DiagnosticRule(want.Identity)+"\x00"+field] = orderedCurrentNative379CatalogDiagnosticChangedFieldSample{Kind: want.Kind, Rule: orderedCurrentNative379DiagnosticRule(want.Identity), Field: field, ExpectedSHA256: expectedSHA, LiveSHA256: liveSHA, ExpectedPreview: expectedPreview, LivePreview: livePreview}
				}
			}
			entries = append(entries, orderedCurrentNative379CatalogDiagnosticEntry{Class: "changed", Kind: want.Kind, Identity: want.Identity, ExpectedSHA256: orderedCurrentNative379SHA256(wantCanonical), LiveSHA256: orderedCurrentNative379SHA256(gotCanonical), ExpectedPreview: wantPreview, LivePreview: gotPreview})
		}
	}
	for key, got := range liveByKey {
		if _, exists := expectedByKey[key]; exists {
			continue
		}
		diagnostic.Extra++
		record("extra", got)
		canonical, preview := orderedCurrentNative379DiagnosticFact(got.Fact)
		entries = append(entries, orderedCurrentNative379CatalogDiagnosticEntry{Class: "extra", Kind: got.Kind, Identity: got.Identity, LiveSHA256: orderedCurrentNative379SHA256(canonical), LivePreview: preview})
	}
	// A relocation is a missing/extra pair with the same kind, rule and exact
	// fact bytes. Emit a representative only for one-to-one buckets; ambiguous
	// buckets remain counted but are never silently paired.
	type relocationBucket struct {
		missing []orderedCurrentNative379Fact
		extra   []orderedCurrentNative379Fact
	}
	relocationBuckets := make(map[string]*relocationBucket)
	for key, want := range expectedByKey {
		if _, exists := liveByKey[key]; exists {
			continue
		}
		factCanonical, _ := orderedCurrentNative379DiagnosticFact(want.Fact)
		factSHA := orderedCurrentNative379SHA256(factCanonical)
		relocationKey := want.Kind + "\x00" + orderedCurrentNative379DiagnosticRule(want.Identity) + "\x00" + factSHA
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
		factCanonical, _ := orderedCurrentNative379DiagnosticFact(got.Fact)
		factSHA := orderedCurrentNative379SHA256(factCanonical)
		parts := strings.SplitN(got.Kind+"\x00"+orderedCurrentNative379DiagnosticRule(got.Identity)+"\x00"+factSHA, "\x00", 3)
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
		diagnostic.RelocationCounts = append(diagnostic.RelocationCounts, orderedCurrentNative379CatalogDiagnosticRelocationCount{Kind: parts[0], Rule: parts[1], FactSHA256: parts[2], Count: len(bucket.missing) + len(bucket.extra)})
		if len(bucket.missing) == 1 && len(bucket.extra) == 1 {
			diagnostic.Relocations = append(diagnostic.Relocations, orderedCurrentNative379CatalogDiagnosticRelocation{Kind: parts[0], Rule: parts[1], FactSHA256: parts[2], BeforeIdentity: bucket.missing[0].Identity, AfterIdentity: bucket.extra[0].Identity})
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
			balanced := make([]orderedCurrentNative379CatalogDiagnosticEntry, 0, maxEntries)
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
						groups[class][entry.Kind+"\x00"+orderedCurrentNative379DiagnosticRule(entry.Identity)] = true
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
						group := entry.Kind + "\x00" + orderedCurrentNative379DiagnosticRule(entry.Identity)
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
	diagnostic.ClassCounts, _ = orderedCurrentNative379DiagnosticCounts(classCounts, 8)
	var kindOverflow, ruleOverflow bool
	diagnostic.KindCounts, kindOverflow = orderedCurrentNative379DiagnosticCounts(kindCounts, 64)
	diagnostic.RuleCounts, ruleOverflow = orderedCurrentNative379DiagnosticCounts(ruleCounts, 64)
	var kindClassOverflow, ruleClassOverflow bool
	diagnostic.KindClassCounts, kindClassOverflow = orderedCurrentNative379DiagnosticClassCounts(kindClassCounts, 64)
	diagnostic.RuleClassCounts, ruleClassOverflow = orderedCurrentNative379DiagnosticClassCounts(ruleClassCounts, 64)
	var fieldOverflow bool
	diagnostic.ChangedFieldCounts, fieldOverflow = orderedCurrentNative379DiagnosticChangedFieldCounts(changedFieldCounts, 64)
	fieldSampleKeys := make([]string, 0, len(changedFieldSamples))
	for key := range changedFieldSamples {
		fieldSampleKeys = append(fieldSampleKeys, key)
	}
	sort.Strings(fieldSampleKeys)
	if len(fieldSampleKeys) > 32 {
		fieldSampleKeys = fieldSampleKeys[:32]
		diagnostic.CountOverflow = true
	}
	diagnostic.ChangedFieldSamples = make([]orderedCurrentNative379CatalogDiagnosticChangedFieldSample, 0, len(fieldSampleKeys))
	for _, key := range fieldSampleKeys {
		diagnostic.ChangedFieldSamples = append(diagnostic.ChangedFieldSamples, changedFieldSamples[key])
	}
	diagnostic.CountOverflow = diagnostic.CountOverflow || kindOverflow || ruleOverflow || kindClassOverflow || ruleClassOverflow || fieldOverflow
	diagnostic.Entries = entries
	return diagnostic
}

func orderedCurrentNative379CollectCatalogDiagnostic(ctx context.Context, tx pgx.Tx, packet orderedCurrentNative379Packet, collector []byte) orderedCurrentNative379CatalogDiagnostic {
	const maxEntries = 20
	collectorSQL := strings.TrimSpace(string(collector))
	collectorSQL = strings.TrimSuffix(collectorSQL, ";")
	if collectorSQL == "" || orderedCurrentNative379SHA256(collector) != orderedCurrentNative379CollectorSHA256 {
		return orderedCurrentNative379CatalogDiagnostic{Overflow: true, Error: "collector source admission refused", Entries: []orderedCurrentNative379CatalogDiagnosticEntry{}}
	}
	maxRows, maxBytes := packet.Limits.MaxRows, packet.Limits.MaxBytes
	query := "SELECT kind,identity,fact::text FROM (" + collectorSQL + ") native379_live ORDER BY kind COLLATE \"C\",identity COLLATE \"C\""
	rows, err := tx.Query(ctx, query)
	if err != nil {
		message := "collector query refused"
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			message = fmt.Sprintf("collector query refused: sqlstate=%s message=%s", pgErr.Code, pgErr.Message)
		}
		return orderedCurrentNative379CatalogDiagnostic{Overflow: true, Error: message, Entries: []orderedCurrentNative379CatalogDiagnosticEntry{}}
	}
	defer rows.Close()
	live := make([]orderedCurrentNative379Fact, 0, maxRows+1)
	bytesSeen := 0
	for rows.Next() {
		var fact orderedCurrentNative379Fact
		var raw string
		if err := rows.Scan(&fact.Kind, &fact.Identity, &raw); err != nil {
			return orderedCurrentNative379CatalogDiagnostic{Overflow: true, Error: "collector row refused", Entries: []orderedCurrentNative379CatalogDiagnosticEntry{}}
		}
		fact.Fact = json.RawMessage(raw)
		live = append(live, fact)
		bytesSeen += len(fact.Kind) + len(fact.Identity) + len(fact.Fact)
		if len(live) > maxRows || bytesSeen > maxBytes {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return orderedCurrentNative379CatalogDiagnostic{Overflow: true, Error: "collector stream refused", Entries: []orderedCurrentNative379CatalogDiagnosticEntry{}}
	}
	return orderedCurrentNative379BuildCatalogDiagnostic(packet.ExpectedFacts, live, maxEntries, maxRows, maxBytes)
}

func orderedCurrentNative379CatalogFailure(diagnostic orderedCurrentNative379CatalogDiagnostic) error {
	raw, err := json.Marshal(diagnostic)
	if err != nil || len(raw) > 32768 {
		raw = []byte(`{"overflow":true,"error":"diagnostic encoding refused","entries":[]}`)
	}
	return fmt.Errorf("native379 pristine catalog equality refused: diagnostic=%s", raw)
}

func validateOrderedCurrentNative379PacketControls(packet orderedCurrentNative379Packet) error {
	if len(packet.Controls) != 589 {
		return errors.New("native379 control cardinality refused")
	}
	byID := make(map[string]orderedCurrentNative379Control, len(packet.Controls))
	for _, control := range packet.Controls {
		mutationSHA, err := orderedCurrentNative379CanonicalSHA256(control.Mutation)
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
			if step.ID == "" || !allowedRoles[step.Role] || step.SQL == "" || !allowedOutcomes[step.Expected.Outcome] || step.SQLSHA256 != orderedCurrentNative379SHA256([]byte(step.SQL)) || seenStep[step.ID] {
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

func orderedCurrentNative379TestControlResults(packet orderedCurrentNative379Packet) []orderedCurrentNative379ControlResult {
	results := make([]orderedCurrentNative379ControlResult, 0, len(packet.Controls))
	for _, phase := range packet.Phases {
		for _, id := range phase.ControlIDs {
			var control orderedCurrentNative379Control
			for _, candidate := range packet.Controls {
				if candidate.ID == id {
					control = candidate
					break
				}
			}
			result := orderedCurrentNative379ControlResult{ID: control.ID, Phase: control.Phase, MutationSHA256: control.MutationSHA256, Milliseconds: 1, Restored: true}
			for _, step := range control.Program.Steps {
				sqlState := "00000"
				if step.Expected.SQLState != nil {
					sqlState = *step.Expected.SQLState
				}
				observation := json.RawMessage(`{"sqlState":"` + sqlState + `"}`)
				role := step.Role
				if role == "fixture-owner" {
					role = "zasp_test"
				}
				roleObservation := "before"
				if step.ID == "recover-probe" {
					roleObservation = "after-recovery"
				}
				if control.ID == "restore:transaction" && step.ID == "probe" {
					roleObservation = "before-poison"
				}
				if control.ID == "restore:transaction" && step.ID == "restore" {
					role, roleObservation = "zasp_discovery_authority", "after-recovery"
				}
				result.Steps = append(result.Steps, orderedCurrentNative379ControlStepResult{ID: step.ID, Outcome: step.Expected.Outcome, SQLState: sqlState, DeclaredRole: step.Role, ObservedRole: role, ObservedSessionUser: "zasp_test", RoleObservation: roleObservation, Observation: observation, ObservedSHA256: orderedCurrentNative379SHA256(observation), Matched: true})
			}
			results = append(results, result)
		}
	}
	return results
}

func cloneOrderedCurrentNative379ControlResults(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
	raw, _ := json.Marshal(value)
	var copy []orderedCurrentNative379ControlResult
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func validateOrderedCurrentNative379ControlResults(packet orderedCurrentNative379Packet, results []orderedCurrentNative379ControlResult) error {
	if validateOrderedCurrentNative379PacketControls(packet) != nil || len(results) != len(packet.Controls) {
		return errors.New("native379 control results incomplete")
	}
	byID := make(map[string]orderedCurrentNative379Control, len(packet.Controls))
	phaseLimit := make(map[string]int64, len(packet.Phases))
	for _, control := range packet.Controls {
		byID[control.ID] = control
	}
	for _, phase := range packet.Phases {
		phaseLimit[phase.ID] = int64(phase.Limits.MaxMilliseconds)
	}
	index := 0
	phaseDuration := make(map[string]int64, len(packet.Phases))
	observedSessionUser := ""
	for _, phase := range packet.Phases {
		for _, id := range phase.ControlIDs {
			if index >= len(results) {
				return errors.New("native379 truncated control results refused")
			}
			control, result := byID[id], results[index]
			if result.ID != id || result.Phase != phase.ID || result.MutationSHA256 != control.MutationSHA256 || !result.Restored || result.Milliseconds < 0 || len(result.Steps) != len(control.Program.Steps) {
				return errors.New("native379 control result identity or restoration refused")
			}
			phaseDuration[phase.ID] += result.Milliseconds
			for stepIndex, step := range control.Program.Steps {
				got := result.Steps[stepIndex]
				wantState := "00000"
				if step.Expected.SQLState != nil {
					wantState = *step.Expected.SQLState
				}
				canonical, canonicalErr := orderedCurrentNative379CanonicalJSON(got.Observation)
				wantRoleObservation := "before"
				if step.ID == "recover-probe" {
					wantRoleObservation = "after-recovery"
				}
				if control.ID == "restore:transaction" && step.ID == "probe" {
					wantRoleObservation = "before-poison"
				}
				if control.ID == "restore:transaction" && step.ID == "restore" {
					wantRoleObservation = "after-recovery"
				}
				wantObservedRole := step.Role
				if step.Role == "fixture-owner" || step.Role == "zasp_test" {
					wantObservedRole = got.ObservedSessionUser
				}
				if control.ID == "restore:transaction" && step.ID == "restore" {
					wantObservedRole = "zasp_discovery_authority"
				}
				if observedSessionUser == "" {
					observedSessionUser = got.ObservedSessionUser
				}
				if got.ID != step.ID || got.Outcome != step.Expected.Outcome || got.SQLState != wantState || got.DeclaredRole != step.Role || got.ObservedSessionUser == "" || got.ObservedSessionUser != observedSessionUser || got.ObservedRole != wantObservedRole || got.RoleObservation != wantRoleObservation || canonicalErr != nil || !bytes.Equal(canonical, got.Observation) || len(got.ObservedSHA256) != 64 || got.ObservedSHA256 != strings.ToLower(got.ObservedSHA256) || got.ObservedSHA256 != orderedCurrentNative379SHA256(canonical) || !got.Matched || got.TimedOut {
					return errors.New("native379 control step evidence refused")
				}
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

func validateOrderedCurrentNative379PacketStructure(packet orderedCurrentNative379Packet) error {
	if packet.WireSHA256 != orderedCurrentNative379PacketSHA256 || packet.Format != "ordered-current-native379-packet-v1" || packet.Status != "NATIVE-PARITY-PENDING" || packet.Installable || packet.NativeVerified {
		return errors.New("native379 packet envelope or wire pin refused")
	}
	if packet.Identity.ServerVersionNum != 180003 || packet.Identity.Postgres == "" || packet.Identity.Pgcrypto != "1.4" {
		return errors.New("native379 PostgreSQL identity refused")
	}
	if packet.Authority.Generated[orderedCurrentNative379ModuleFile] != orderedCurrentNative379ModuleSHA256 || packet.Authority.Generated["development-manifest.json"] != orderedCurrentNative379ManifestSHA256 || packet.Authority.Generated[orderedCurrentNative379CollectorFile] != orderedCurrentNative379CollectorSHA256 {
		return errors.New("native379 generated source pins refused")
	}
	if len(packet.Rules) != 379 || len(packet.ExpectedFacts) != 10089 || len(packet.SourceInventory.Sites) != 565 || packet.SourceInventory.Unclassified != 0 {
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
	if total != 10089 || len(packet.Entry.Manifest) != 64 || packet.Entry.ManifestLiteral != "'"+packet.Entry.Manifest+"'" || packet.Entry.IndependentAdmission.SQL == "" {
		return errors.New("native379 expected truth or entry authority refused")
	}
	if _, err := orderedCurrentNative379ExpectedRoutines(packet); err != nil {
		return err
	}
	if packet.Limits.MaxPacketBytes <= 0 || packet.Limits.MaxPacketBytes > 33554432 || packet.Limits.MaxRows < 10089 || packet.Limits.MaxBytes <= 0 || packet.Limits.MaxMilliseconds <= 0 || packet.Limits.SQLMilliseconds <= 0 || packet.Limits.LockMilliseconds <= 0 || packet.Limits.CleanupMilliseconds <= 0 {
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
	if err := validateOrderedCurrentNative379PacketControls(packet); err != nil {
		return err
	}
	return nil
}

func validateOrderedCurrentNative379Result(packet orderedCurrentNative379Packet, result orderedCurrentNative379Result) error {
	if err := validateOrderedCurrentNative379PacketStructure(packet); err != nil {
		return err
	}
	if result.Format != "ordered-current-native379-result-v1" || result.Status != "LOCAL-NATIVE-COMPONENT-EVIDENCE" || result.Installable || result.Truncated || result.PacketSHA256 != packet.WireSHA256 {
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
	for index, stage := range result.Stages {
		if stage.ID != wantStages[index] || stage.Phase != wantPhase[stage.ID] || stage.Milliseconds < 0 || stage.Milliseconds > int64(phaseLimits[stage.Phase]) {
			return errors.New("native379 result stage order refused")
		}
		total += stage.Milliseconds
	}
	if total > int64(packet.Limits.MaxMilliseconds) {
		return errors.New("native379 result duration overflow")
	}
	if err := validateOrderedCurrentNative379ControlResults(packet, result.Controls); err != nil {
		return err
	}
	wantRoutines, _ := orderedCurrentNative379ExpectedRoutines(packet)
	if !reflect.DeepEqual(result.Hashes, map[string]string{"packet": packet.WireSHA256, "module": orderedCurrentNative379ModuleSHA256, "manifest": orderedCurrentNative379ManifestSHA256}) || result.EndpointSHA256 == "" || result.Server.VersionNum != packet.Identity.ServerVersionNum || result.Server.Postgres != packet.Identity.Postgres || result.Server.Pgcrypto != packet.Identity.Pgcrypto || result.Objects.SchemaOwner != "zasp_discovery_authority" || !reflect.DeepEqual(result.Objects.Tables, []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}) || !reflect.DeepEqual(result.Objects.Routines, wantRoutines) || result.Objects.UnexpectedGrants != 0 || result.Counts.Rules != 379 || result.Counts.Facts != 10089 || result.Counts.RoleSites != 565 || result.Counts.Registration != 1 || result.Counts.ExpectedRows != 10089 || result.Counts.EqualFacts != 10089 || result.Counts.Tables != 2 || result.Counts.Routines != 7 || validateOrderedCurrentNative379Operations(result.Operations) != nil || !result.Restoration.TransactionRolledBack || !result.Restoration.FrameRestored || !result.Cleanup.PGCtlStopped || !result.Cleanup.EndpointChecked || result.Cleanup.EndpointSHA256 != result.EndpointSHA256 || !result.Cleanup.Joined || !result.Cleanup.NormalExit || !result.Cleanup.SurvivingResourcesChecked || result.Cleanup.SurvivingResources != 0 {
		return errors.New("native379 result evidence refused")
	}
	return nil
}

func buildOrderedCurrentNative379Result(packet orderedCurrentNative379Packet, observation *orderedCurrentNative379Observation, cleanup *disposablePostgresCleanupObservation, stages []orderedCurrentNative379Stage) (orderedCurrentNative379Result, error) {
	var result orderedCurrentNative379Result
	if observation == nil || cleanup == nil {
		return result, errors.New("native379 observed evidence absent")
	}
	if err := validateOrderedCurrentNative379PacketStructure(packet); err != nil {
		return result, err
	}
	wantRoutines, err := orderedCurrentNative379ExpectedRoutines(packet)
	if err != nil {
		return result, err
	}
	wantHashes := map[string]string{"packet": packet.WireSHA256, "module": orderedCurrentNative379ModuleSHA256, "manifest": orderedCurrentNative379ManifestSHA256}
	if !observation.Available || observation.EndpointSHA256 == "" || !reflect.DeepEqual(observation.Hashes, wantHashes) || observation.Server.VersionNum != packet.Identity.ServerVersionNum || observation.Server.Postgres != packet.Identity.Postgres || observation.Server.Pgcrypto != packet.Identity.Pgcrypto {
		return result, errors.New("native379 observed hashes or server identity refused")
	}
	if observation.Objects.SchemaOwner != "zasp_discovery_authority" || !reflect.DeepEqual(observation.Objects.Tables, []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}) || !reflect.DeepEqual(observation.Objects.Routines, wantRoutines) || observation.Objects.UnexpectedGrants != 0 {
		return result, errors.New("native379 observed object inventory or grants refused")
	}
	if observation.Counts.Rules != len(packet.Rules) || observation.Counts.Facts != len(packet.ExpectedFacts) || observation.Counts.RoleSites != len(packet.SourceInventory.Sites) || observation.Counts.Registration != 1 || observation.Counts.ExpectedRows != len(packet.ExpectedFacts) || observation.Counts.EqualFacts != len(packet.ExpectedFacts) || validateOrderedCurrentNative379Operations(observation.Operations) != nil || validateOrderedCurrentNative379ControlResults(packet, observation.Controls) != nil || !observation.Restoration.TransactionRolledBack || !observation.Restoration.FrameRestored {
		return result, errors.New("native379 observed counts, SQLSTATEs, or restoration refused")
	}
	clean := cleanup.snapshot()
	if !clean.Available || !clean.PGCtlStopped || !clean.CommandWaitJoined || !clean.NormalExit || !clean.EndpointChecked || clean.EndpointSHA256 == "" || clean.EndpointSHA256 != observation.EndpointSHA256 || !clean.SurvivingResourcesChecked || clean.SurvivingResources != 0 {
		return result, errors.New("native379 structured cleanup evidence refused")
	}
	result.Format, result.Status, result.PacketSHA256 = "ordered-current-native379-result-v1", "LOCAL-NATIVE-COMPONENT-EVIDENCE", packet.WireSHA256
	result.Stages = append([]orderedCurrentNative379Stage(nil), stages...)
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
	result.Operations = append([]orderedCurrentNative379Operation(nil), observation.Operations...)
	result.Controls = cloneOrderedCurrentNative379ControlResults(observation.Controls)
	result.Restoration.TransactionRolledBack, result.Restoration.FrameRestored = observation.Restoration.TransactionRolledBack, observation.Restoration.FrameRestored
	result.Cleanup.PGCtlStopped, result.Cleanup.EndpointChecked, result.Cleanup.EndpointSHA256 = clean.PGCtlStopped, clean.EndpointChecked, clean.EndpointSHA256
	result.Cleanup.Joined, result.Cleanup.NormalExit = clean.CommandWaitJoined, clean.NormalExit
	result.Cleanup.SurvivingResourcesChecked, result.Cleanup.SurvivingResources = clean.SurvivingResourcesChecked, clean.SurvivingResources
	if err := validateOrderedCurrentNative379Result(packet, result); err != nil {
		return orderedCurrentNative379Result{}, err
	}
	return result, nil
}

func publishOrderedCurrentNative379Result(destination string, result orderedCurrentNative379Result, maxBytes int) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || maxBytes <= 0 || maxBytes > orderedCurrentNative379MaxResultBytes {
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

type orderedCurrentNative379LimitedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (writer *orderedCurrentNative379LimitedBuffer) Write(value []byte) (int, error) {
	if len(value) > writer.limit-writer.buffer.Len() {
		return 0, errors.New("native379 subprocess output overflow")
	}
	return writer.buffer.Write(value)
}

func orderedCurrentNative379Root() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func generateOrderedCurrentNative379PacketRaw(ctx context.Context) ([]byte, error) {
	root := orderedCurrentNative379Root()
	module := filepath.Join(root, "services", "platform", "migrations", "tools", "ordered-current-native379-packet-v1.mjs")
	node, pathErr := execLookPath("node")
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		approved := filepath.Join(home, ".nvm", "versions", "node", "v22.23.1", "bin", "node")
		if info, statErr := os.Lstat(approved); statErr == nil && info.Mode().IsRegular() {
			node, pathErr = approved, nil
		}
	}
	if pathErr != nil {
		return nil, errors.New("native379 exact Node unavailable")
	}
	stdout := &orderedCurrentNative379LimitedBuffer{limit: 33554432}
	stderr := &orderedCurrentNative379LimitedBuffer{limit: 1024 * 1024}
	command := execCommandContext(ctx, node, module, "--json")
	command.Dir = root
	command.Env = []string{"PATH=" + filepath.Dir(node), "TZ=UTC", "LANG=C"}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("native379 packet generation refused: %w: %s", err, stderr.buffer.String())
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}

func admitOrderedCurrentNative379PacketRaw(raw []byte) (orderedCurrentNative379AdmittedPacket, error) {
	var admission orderedCurrentNative379AdmittedPacket
	if len(raw) == 0 || len(raw) > 33554432 {
		return admission, errors.New("native379 packet byte bound refused")
	}
	digest := sha256.Sum256(raw)
	wireSHA := hex.EncodeToString(digest[:])
	if wireSHA != orderedCurrentNative379PacketSHA256 {
		return admission, errors.New("native379 packet wire pin refused")
	}
	var packet orderedCurrentNative379Packet
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&packet); err != nil {
		return admission, errors.New("native379 packet decode refused")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return admission, errors.New("native379 packet trailing bytes refused")
	}
	packet.WireSHA256 = wireSHA
	if err := validateOrderedCurrentNative379PacketStructure(packet); err != nil {
		return admission, err
	}
	return orderedCurrentNative379AdmittedPacket{packet: packet, rawSHA: wireSHA, rawBytes: len(raw)}, nil
}

func loadOrderedCurrentNative379Packet(ctx context.Context) (orderedCurrentNative379AdmittedPacket, error) {
	raw, err := generateOrderedCurrentNative379PacketRaw(ctx)
	if err != nil {
		return orderedCurrentNative379AdmittedPacket{}, err
	}
	return admitOrderedCurrentNative379PacketRaw(raw)
}

func validateOrderedCurrentNative379Admission(admission orderedCurrentNative379AdmittedPacket) error {
	if admission.rawSHA != orderedCurrentNative379PacketSHA256 || admission.rawBytes <= 0 || admission.rawBytes > 33554432 || admission.packet.WireSHA256 != admission.rawSHA {
		return errors.New("native379 raw admission token refused")
	}
	return validateOrderedCurrentNative379PacketStructure(admission.packet)
}

// These variables make the subprocess boundary replaceable by narrow offline
// tests without adding a production API or weakening the opt-in native path.
var (
	execLookPath       = exec.LookPath
	execCommandContext = exec.CommandContext
)

func orderedCurrentNative379Duration(start time.Time) int64 {
	value := time.Since(start).Milliseconds()
	if value < 0 {
		return 0
	}
	return value
}

func orderedCurrentNative379File(path, expected string, max int) ([]byte, error) {
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

const orderedCurrentNative379PreinstallIdentitySQL = `SELECT current_setting('server_version_num')::integer,version(),COALESCE((SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pgcrypto'),''),host(inet_server_addr()),inet_server_port(),(SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname='zasp_authorization80_ordered_current'),(SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_authorization80_ordered_current')`

func orderedCurrentNative379Preinstall(ctx context.Context, owner *pgx.Conn, packet orderedCurrentNative379Packet, observation *orderedCurrentNative379Observation, recorder *orderedCurrentNative379OperationRecorder) error {
	if observation == nil || recorder == nil {
		return errors.New("native379 observation target absent")
	}
	var server int
	var postgres, pgcrypto, address string
	var port int
	var namespace, outputRows int
	err := owner.QueryRow(ctx, orderedCurrentNative379PreinstallIdentitySQL).Scan(&server, &postgres, &pgcrypto, &address, &port, &namespace, &outputRows)
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

func orderedCurrentNative379NormalizeValue(value any) any {
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

func orderedCurrentNative379QueryRows(ctx context.Context, owner *pgx.Conn, sql string) ([]map[string]any, error) {
	rows, err := owner.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
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
			row[string(fields[index].Name)] = orderedCurrentNative379NormalizeValue(value)
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func orderedCurrentNative379MatchValue(expected, actual any, sessionUser string, backendPID int32) bool {
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
			if !orderedCurrentNative379MatchValue(value, got[key], sessionUser, backendPID) {
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
			if !orderedCurrentNative379MatchValue(values[index], got[index], sessionUser, backendPID) {
				return false
			}
		}
		return true
	}
	left, _ := json.Marshal(expected)
	right, _ := json.Marshal(actual)
	return orderedCurrentNative379JSONEqual(left, right)
}

func orderedCurrentNative379DecodeExpected(raw json.RawMessage) (any, error) {
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

func orderedCurrentNative379StepState(err error) string {
	if err == nil {
		return "00000"
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		return postgres.Code
	}
	return "NON_SQL_ERROR"
}

const orderedCurrentNative379RoleObservationSQL = "SELECT current_user,session_user"

type orderedCurrentNative379ExecutionSession interface {
	SessionIdentity(context.Context) (string, int32, error)
	ObserveRole(context.Context) (string, string, error)
	ExecStep(context.Context, string) error
	QueryStep(context.Context, string) ([]map[string]any, error)
	TxStatus() byte
	CleanupRollback(context.Context) error
}

type orderedCurrentNative379PGXSession struct{ owner *pgx.Conn }

func (session *orderedCurrentNative379PGXSession) SessionIdentity(ctx context.Context) (string, int32, error) {
	var user string
	var pid int32
	err := session.owner.QueryRow(ctx, "SELECT session_user,pg_catalog.pg_backend_pid()").Scan(&user, &pid)
	return user, pid, err
}

func (session *orderedCurrentNative379PGXSession) ObserveRole(ctx context.Context) (string, string, error) {
	var currentUser, sessionUser string
	if err := session.owner.QueryRow(ctx, orderedCurrentNative379RoleObservationSQL).Scan(&currentUser, &sessionUser); err != nil {
		return "", "", errors.New("native379 fixed role observation refused")
	}
	return currentUser, sessionUser, nil
}

func (session *orderedCurrentNative379PGXSession) ExecStep(ctx context.Context, sql string) error {
	_, err := session.owner.Exec(ctx, sql)
	return err
}

func (session *orderedCurrentNative379PGXSession) QueryStep(ctx context.Context, sql string) ([]map[string]any, error) {
	return orderedCurrentNative379QueryRows(ctx, session.owner, sql)
}

func (session *orderedCurrentNative379PGXSession) TxStatus() byte {
	return session.owner.PgConn().TxStatus()
}

func (session *orderedCurrentNative379PGXSession) CleanupRollback(ctx context.Context) error {
	_, err := session.owner.Exec(ctx, "ROLLBACK")
	return err
}

func orderedCurrentNative379ExpectedObservedRole(declared, sessionUser string) string {
	if declared == "fixture-owner" || declared == "zasp_test" {
		return sessionUser
	}
	return declared
}

func orderedCurrentNative379ExecuteControl(ctx context.Context, owner *pgx.Conn, packet orderedCurrentNative379Packet, control orderedCurrentNative379Control) (result orderedCurrentNative379ControlResult, failure error) {
	return orderedCurrentNative379ExecuteControlSession(ctx, &orderedCurrentNative379PGXSession{owner: owner}, packet, control)
}

func orderedCurrentNative379ExecuteControlSession(ctx context.Context, session orderedCurrentNative379ExecutionSession, packet orderedCurrentNative379Packet, control orderedCurrentNative379Control) (result orderedCurrentNative379ControlResult, failure error) {
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
	var poisonRole, poisonSessionUser string
	for stepIndex, step := range control.Program.Steps {
		stepCtx, cancel := context.WithTimeout(ctx, time.Duration(packet.Limits.SQLMilliseconds)*time.Millisecond)
		roleObservation := "before"
		var observedRole, observedSessionUser string
		poisonProbe := control.ID == "restore:transaction" && stepIndex > 0 && step.ID == "probe" && control.Program.Steps[stepIndex-1].ID == "mutate" && control.Program.Steps[stepIndex-1].Expected.Outcome == "error" && control.Program.Steps[stepIndex-1].Expected.SQLState != nil && *control.Program.Steps[stepIndex-1].Expected.SQLState == "22012" && len(result.Steps) == stepIndex && result.Steps[stepIndex-1].Matched && result.Steps[stepIndex-1].SQLState == "22012" && step.Expected.Outcome == "error" && step.Expected.SQLState != nil && *step.Expected.SQLState == "25P02"
		poisonRestore := control.ID == "restore:transaction" && stepIndex > 1 && step.ID == "restore" && control.Program.Steps[stepIndex-1].ID == "probe" && control.Program.Steps[stepIndex-1].Expected.Outcome == "error" && control.Program.Steps[stepIndex-1].Expected.SQLState != nil && *control.Program.Steps[stepIndex-1].Expected.SQLState == "25P02" && len(result.Steps) == stepIndex && result.Steps[stepIndex-1].Matched && result.Steps[stepIndex-1].SQLState == "25P02" && step.Expected.Outcome == "command-complete" && strings.HasPrefix(step.SQL, "ROLLBACK;")
		if poisonProbe {
			observedRole, observedSessionUser, roleObservation = poisonRole, poisonSessionUser, "before-poison"
		} else if step.ID != "recover-probe" && !poisonRestore {
			var roleErr error
			observedRole, observedSessionUser, roleErr = session.ObserveRole(stepCtx)
			wantRole := orderedCurrentNative379ExpectedObservedRole(step.Role, observedSessionUser)
			if roleErr != nil || observedSessionUser == "" || observedRole != wantRole {
				cancel()
				return result, errors.New("native379 declared role transition refused")
			}
		}
		var observed any
		err = nil
		switch step.Expected.Outcome {
		case "command-success", "command-complete":
			err = session.ExecStep(stepCtx, step.SQL)
			observed = map[string]any{"sqlState": orderedCurrentNative379StepState(err)}
		case "error":
			_, err = session.QueryStep(stepCtx, step.SQL)
			observed = map[string]any{"sqlState": orderedCurrentNative379StepState(err)}
		case "capture", "equal-captured", "rows", "one-row", "one-json-row":
			var rows []map[string]any
			rows, err = session.QueryStep(stepCtx, step.SQL)
			observed = rows
		default:
			cancel()
			return result, errors.New("native379 unknown step outcome refused")
		}
		if step.ID == "recover-probe" || poisonRestore {
			roleObservation = "after-recovery"
			if err == nil {
				observedRole, observedSessionUser, err = session.ObserveRole(stepCtx)
				wantRole := orderedCurrentNative379ExpectedObservedRole(step.Role, observedSessionUser)
				if poisonRestore {
					wantRole = "zasp_discovery_authority"
				}
				if err == nil && (observedSessionUser == "" || observedRole != wantRole) {
					err = errors.New("native379 recovered role transition refused")
				}
			}
		}
		timedOut := errors.Is(stepCtx.Err(), context.DeadlineExceeded)
		cancel()
		state := orderedCurrentNative379StepState(err)
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
						matched = orderedCurrentNative379MatchValue(captures[step.Expected.Key], value, sessionUser, backendPID)
					}
				}
			case "rows":
				want, decodeErr := orderedCurrentNative379DecodeExpected(step.Expected.Rows)
				matched = decodeErr == nil && orderedCurrentNative379MatchValue(want, observed, sessionUser, backendPID)
			case "one-row", "one-json-row":
				want, decodeErr := orderedCurrentNative379DecodeExpected(step.Expected.Value)
				rows := observed.([]map[string]any)
				matched = decodeErr == nil && len(rows) == 1 && len(rows[0]) == 1
				if matched {
					for _, value := range rows[0] {
						matched = orderedCurrentNative379MatchValue(want, value, sessionUser, backendPID)
					}
				}
			}
		}
		observedRaw, encodeErr := orderedCurrentNative379CanonicalJSONFromValue(observed)
		if encodeErr != nil {
			return result, encodeErr
		}
		result.Steps = append(result.Steps, orderedCurrentNative379ControlStepResult{ID: step.ID, Outcome: step.Expected.Outcome, SQLState: state, DeclaredRole: step.Role, ObservedRole: observedRole, ObservedSessionUser: observedSessionUser, RoleObservation: roleObservation, Observation: observedRaw, ObservedSHA256: orderedCurrentNative379SHA256(observedRaw), Matched: matched, TimedOut: timedOut})
		if !matched {
			return result, fmt.Errorf("native379 control %s step %s refused", control.ID, step.ID)
		}
		if control.ID == "restore:transaction" && step.ID == "mutate" && state == "22012" {
			poisonRole, poisonSessionUser = observedRole, observedSessionUser
		}
	}
	if session.TxStatus() != 'I' {
		return result, errors.New("native379 control transaction not restored")
	}
	result.Restored = true
	return result, nil
}

func orderedCurrentNative379ExecuteControls(ctx context.Context, owner *pgx.Conn, admission orderedCurrentNative379AdmittedPacket) ([]orderedCurrentNative379ControlResult, error) {
	if err := validateOrderedCurrentNative379Admission(admission); err != nil {
		return nil, err
	}
	packet := admission.packet
	byID := make(map[string]orderedCurrentNative379Control, len(packet.Controls))
	for _, control := range packet.Controls {
		byID[control.ID] = control
	}
	results := make([]orderedCurrentNative379ControlResult, 0, len(packet.Controls))
	for _, phase := range packet.Phases {
		for _, id := range phase.ControlIDs {
			result, err := orderedCurrentNative379ExecuteControl(ctx, owner, packet, byID[id])
			if err != nil {
				return nil, err
			}
			results = append(results, result)
		}
	}
	if err := validateOrderedCurrentNative379ControlResults(packet, results); err != nil {
		return nil, err
	}
	return results, nil
}

func orderedCurrentNative379InstallAndCompare(ctx context.Context, owner *pgx.Conn, admission orderedCurrentNative379AdmittedPacket, module, manifest, collector []byte) (orderedCurrentNative379Observation, error) {
	var observation orderedCurrentNative379Observation
	if err := validateOrderedCurrentNative379Admission(admission); err != nil {
		return observation, err
	}
	packet := admission.packet
	if orderedCurrentNative379SHA256(collector) != orderedCurrentNative379CollectorSHA256 || packet.Authority.Generated[orderedCurrentNative379CollectorFile] != orderedCurrentNative379CollectorSHA256 {
		return observation, errors.New("native379 fixed collector source refused")
	}
	digest := func(raw []byte) string {
		value := sha256.Sum256(raw)
		return hex.EncodeToString(value[:])
	}
	observation.Hashes = map[string]string{"packet": packet.WireSHA256, "module": digest(module), "manifest": digest(manifest)}
	observation.Counts.Rules, observation.Counts.Facts, observation.Counts.RoleSites = len(packet.Rules), len(packet.ExpectedFacts), len(packet.SourceInventory.Sites)
	recorder := &orderedCurrentNative379OperationRecorder{}
	if err := orderedCurrentNative379Preinstall(ctx, owner, packet, &observation, recorder); err != nil {
		return orderedCurrentNative379Observation{}, err
	}
	_, err := owner.Exec(ctx, string(module))
	if recorder.observe("dormant-module-install", err) != nil {
		return orderedCurrentNative379Observation{}, fmt.Errorf("native379 dormant module installation refused: %w", err)
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
	observedInventoryErr := recorder.observe("installed-inventory", err)
	observation.Objects.UnexpectedGrants = grants
	observation.Counts.Registration, observation.Counts.ExpectedRows = registration, expected
	wantRoutines, routineErr := orderedCurrentNative379ExpectedRoutines(packet)
	if observedInventoryErr != nil || routineErr != nil || observation.Objects.SchemaOwner != "zasp_discovery_authority" || !reflect.DeepEqual(observation.Objects.Tables, []string{"zasp_authorization80_ordered_current.expected", "zasp_authorization80_ordered_current.registration"}) || !reflect.DeepEqual(observation.Objects.Routines, wantRoutines) || registration != 1 || expected != len(packet.ExpectedFacts) || grants != 0 {
		return orderedCurrentNative379Observation{}, errors.New("native379 partial install, object inventory, cardinality, or grant boundary refused")
	}
	expectedByKey := make(map[string]orderedCurrentNative379Fact, len(packet.ExpectedFacts))
	for _, fact := range packet.ExpectedFacts {
		key := fact.Kind + "\x00" + fact.Identity
		if fact.Kind == "" || fact.Identity == "" || expectedByKey[key].Kind != "" {
			return orderedCurrentNative379Observation{}, errors.New("native379 expected fact key refused")
		}
		expectedByKey[key] = fact
	}
	rows, err := owner.Query(ctx, `SELECT kind,identity,fact::text FROM zasp_authorization80_ordered_current.expected ORDER BY kind COLLATE "C",identity COLLATE "C"`)
	if recorder.observe("expected-stream-query", err) != nil {
		return orderedCurrentNative379Observation{}, errors.New("native379 expected table read refused")
	}
	defer rows.Close()
	seen := make(map[string]bool, len(expectedByKey))
	for rows.Next() {
		var kind, identity, raw string
		if err := rows.Scan(&kind, &identity, &raw); err != nil {
			return orderedCurrentNative379Observation{}, errors.New("native379 expected row scan refused")
		}
		key := kind + "\x00" + identity
		want, ok := expectedByKey[key]
		if !ok || seen[key] || !orderedCurrentNative379JSONEqual([]byte(raw), want.Fact) {
			return orderedCurrentNative379Observation{}, errors.New("native379 complete key-set or value equality refused")
		}
		seen[key] = true
		observation.Counts.EqualFacts++
	}
	streamErr := rows.Err()
	if recorder.observe("expected-stream-complete", streamErr) != nil || len(seen) != len(expectedByKey) {
		return orderedCurrentNative379Observation{}, errors.New("native379 incomplete expected row stream refused")
	}
	const frameSQL = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),current_setting('transaction_read_only'),current_setting('transaction_isolation')`
	var frameBefore [6]string
	err = owner.QueryRow(ctx, frameSQL).Scan(&frameBefore[0], &frameBefore[1], &frameBefore[2], &frameBefore[3], &frameBefore[4], &frameBefore[5])
	if recorder.observe("frame-before", err) != nil {
		return orderedCurrentNative379Observation{}, errors.New("native379 pre-frame refused")
	}
	tx, err := owner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if recorder.observe("pristine-begin", err) != nil {
		return orderedCurrentNative379Observation{}, errors.New("native379 pristine transaction refused")
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
		return orderedCurrentNative379Observation{}, errors.New("native379 pristine frame refused")
	}
	var admitted, catalog bool
	err = tx.QueryRow(ctx, packet.Entry.IndependentAdmission.SQL).Scan(&admitted)
	if recorder.observe("private-admission", err) != nil || !admitted {
		return orderedCurrentNative379Observation{}, errors.New("native379 evaluator/entry admission refused")
	}
	err = tx.QueryRow(ctx, `SELECT zasp_authorization80_ordered_current.catalog($1)`, packet.Entry.Manifest).Scan(&catalog)
	if observedErr := recorder.observe("catalog", err); observedErr != nil {
		message := "native379 pristine catalog query refused"
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			message = fmt.Sprintf("native379 pristine catalog query refused: sqlstate=%s message=%s detail=%s where=%s routine=%s", pgErr.Code, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Routine)
		}
		return orderedCurrentNative379Observation{}, errors.New(message)
	}
	if !catalog {
		diagnostic := orderedCurrentNative379CollectCatalogDiagnostic(ctx, tx, packet, collector)
		return orderedCurrentNative379Observation{}, orderedCurrentNative379CatalogFailure(diagnostic)
	}
	_, err = tx.Exec(ctx, `SELECT zasp_authorization80_ordered_current.require($1)`, packet.Entry.Manifest)
	if recorder.observe("require", err) != nil {
		return orderedCurrentNative379Observation{}, errors.New("native379 pristine entry refused")
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(packet.Limits.CleanupMilliseconds)*time.Millisecond)
	err = tx.Rollback(cleanup)
	rollbackObservedErr := recorder.observe("pristine-rollback", err)
	cancel()
	active = false
	if rollbackObservedErr != nil {
		return orderedCurrentNative379Observation{}, errors.New("native379 pristine rollback refused")
	}
	observation.Restoration.TransactionRolledBack = true
	var frameAfter [6]string
	err = owner.QueryRow(ctx, frameSQL).Scan(&frameAfter[0], &frameAfter[1], &frameAfter[2], &frameAfter[3], &frameAfter[4], &frameAfter[5])
	if recorder.observe("frame-after", err) != nil || frameAfter != frameBefore {
		return orderedCurrentNative379Observation{}, errors.New("native379 pristine frame restoration refused")
	}
	observation.Restoration.FrameRestored = true
	operations, err := recorder.finish()
	if err != nil {
		return orderedCurrentNative379Observation{}, err
	}
	observation.Operations = operations
	observation.Controls, err = orderedCurrentNative379ExecuteControls(ctx, owner, admission)
	if err != nil {
		return orderedCurrentNative379Observation{}, err
	}
	observation.Available = true
	return observation, nil
}

func orderedCurrentNative379JSONEqual(left, right []byte) bool {
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

// TestP7OrderedCurrentIntegrityNative is deliberately opt-in. Task 2 compiles
// this owned fixture but does not execute it; root alone schedules the bounded
// PostgreSQL run after independent packet and fixture review.
func TestP7OrderedCurrentIntegrityNative(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379") == "" {
		t.Skip("explicit ordered-current native379 run required")
	}
	if os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379") != "1" {
		t.Fatal("ordered-current native379 mode refused")
	}
	for _, name := range []string{"ZASP_ORDERED_PRIVATE_SUCCESSOR_CAPTURE", "ZASP_ORDERED_MISSING_REFERENCE_NATIVE", "ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_SUPPLEMENT_CAPTURE"} {
		if os.Getenv(name) != "" {
			t.Fatalf("ordered-current native379 overlaps %s", name)
		}
	}
	destination := os.Getenv("ZASP_ORDERED_CURRENT_NATIVE379_OUTPUT")
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		t.Fatal("ordered-current native379 output must be a new absolute path")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("ordered-current native379 output already exists")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 13*time.Minute)
	defer cancel()
	packetStart := time.Now()
	admission, err := loadOrderedCurrentNative379Packet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet := admission.packet
	inputsStart := time.Now()
	root := orderedCurrentNative379Root()
	module, err := orderedCurrentNative379File(filepath.Join(root, "services", "platform", "migrations", "ordered_current", orderedCurrentNative379ModuleFile), orderedCurrentNative379ModuleSHA256, packet.Limits.MaxPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := orderedCurrentNative379File(filepath.Join(root, "services", "platform", "migrations", "ordered_current", "development-manifest.json"), orderedCurrentNative379ManifestSHA256, packet.Limits.MaxPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := orderedCurrentNative379File(filepath.Join(root, "services", "platform", "migrations", "ordered_current", orderedCurrentNative379CollectorFile), orderedCurrentNative379CollectorSHA256, packet.Limits.MaxPacketBytes)
	if err != nil {
		t.Fatal(err)
	}
	stages := orderedCurrentNative379TestStages(packet)
	for index := range stages {
		stages[index].Milliseconds = 0
	}
	stages[0].Milliseconds = orderedCurrentNative379Duration(packetStart)
	stages[1].Milliseconds = orderedCurrentNative379Duration(inputsStart)
	var fixtureStart, moduleStart, cleanupStart time.Time
	var observation *orderedCurrentNative379Observation
	cleanupObservation := &disposablePostgresCleanupObservation{}
	t.Run("owned-postgresql-18.3", func(t *testing.T) {
		registerDisposablePostgresCleanupObservation(t, cleanupObservation)
		fixtureStart = time.Now()
		t.Cleanup(func() {
			if !cleanupStart.IsZero() {
				stages[8].Milliseconds = orderedCurrentNative379Duration(cleanupStart)
			}
		})
		runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, func(t *testing.T, fixture context.Context, owner *pgx.Conn) bool {
			stages[2].Milliseconds = orderedCurrentNative379Duration(fixtureStart)
			moduleStart = time.Now()
			observed, err := orderedCurrentNative379InstallAndCompare(fixture, owner, admission, module, manifest, collector)
			if err != nil {
				t.Fatal(err)
			}
			stages[3].Milliseconds = orderedCurrentNative379Duration(moduleStart)
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
	stageByPhase := map[string]int{"drift": 4, "forged-entry": 5, "null-error-lazy-demand": 6, "frame-restoration": 7}
	for _, control := range observation.Controls {
		if index, ok := stageByPhase[control.Phase]; ok {
			stages[index].Milliseconds += control.Milliseconds
		}
	}
	admissionStart := time.Now()
	result, err := buildOrderedCurrentNative379Result(packet, observation, cleanupObservation, stages)
	if err != nil {
		t.Fatal(err)
	}
	stages[9].Milliseconds = orderedCurrentNative379Duration(admissionStart)
	result, err = buildOrderedCurrentNative379Result(packet, observation, cleanupObservation, stages)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishOrderedCurrentNative379Result(destination, result, orderedCurrentNative379MaxResultBytes); err != nil {
		t.Fatal(err)
	}
}

// Break caught: accepting a packet whose immutable wire digest, server
// identity, rule count, fact count, or generated source pins drifted.
func TestOrderedCurrentNative379TrackedPacketAdmitsComponentOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admission, err := loadOrderedCurrentNative379Packet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packet := admission.packet
	if packet.Installable || packet.NativeVerified || len(packet.Controls) != 589 {
		t.Fatal("tracked packet status or executable control set drifted")
	}
}

// Break caught: accepting a packet whose immutable wire digest, server
// identity, rule count, fact count, or generated source pins drifted.
func TestOrderedCurrentNative379PacketBoundaryRefusesDrift(t *testing.T) {
	valid := orderedCurrentNative379TestPacket()
	if err := validateOrderedCurrentNative379PacketStructure(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*orderedCurrentNative379Packet){
		"wrong packet pin": func(value *orderedCurrentNative379Packet) { value.WireSHA256 = "f" + value.WireSHA256[1:] },
		"wrong server":     func(value *orderedCurrentNative379Packet) { value.Identity.ServerVersionNum-- },
		"missing rule":     func(value *orderedCurrentNative379Packet) { value.Rules = value.Rules[:len(value.Rules)-1] },
		"missing fact": func(value *orderedCurrentNative379Packet) {
			value.ExpectedFacts = value.ExpectedFacts[:len(value.ExpectedFacts)-1]
		},
		"wrong module source": func(value *orderedCurrentNative379Packet) {
			value.Authority.Generated[orderedCurrentNative379ModuleFile] = "0" + value.Authority.Generated[orderedCurrentNative379ModuleFile][1:]
		},
		"wrong collector source": func(value *orderedCurrentNative379Packet) {
			value.Authority.Generated[orderedCurrentNative379CollectorFile] = "0" + value.Authority.Generated[orderedCurrentNative379CollectorFile][1:]
		},
		"arbitrary transaction envelope": func(value *orderedCurrentNative379Packet) { value.Controls[0].Program.Transaction = "caller-selected" },
		"arbitrary step role": func(value *orderedCurrentNative379Packet) {
			value.Controls[0].Program.Steps[0].Role = "caller-selected"
		},
		"arbitrary step outcome": func(value *orderedCurrentNative379Packet) {
			value.Controls[0].Program.Steps[0].Expected.Outcome = "caller-selected"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid.clone()
			mutate(&candidate)
			if err := validateOrderedCurrentNative379PacketStructure(candidate); err == nil {
				t.Fatal("drift admitted")
			}
		})
	}
}

// Break caught: publishing partial, reordered, oversized, or non-owner-only
// native evidence and thereby mistaking it for complete pristine evidence.
func TestOrderedCurrentNative379ResultBoundaryAndExclusivePublication(t *testing.T) {
	packet := orderedCurrentNative379TestPacket()
	result := orderedCurrentNative379TestResult(packet)
	if err := validateOrderedCurrentNative379Result(packet, result); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*orderedCurrentNative379Result){
		"missing stage": func(value *orderedCurrentNative379Result) { value.Stages = value.Stages[:len(value.Stages)-1] },
		"wrong facts":   func(value *orderedCurrentNative379Result) { value.Counts.Facts-- },
		"not cleaned":   func(value *orderedCurrentNative379Result) { value.Cleanup.Joined = false },
		"truncated":     func(value *orderedCurrentNative379Result) { value.Truncated = true },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := result.clone()
			mutate(&candidate)
			if err := validateOrderedCurrentNative379Result(packet, candidate); err == nil {
				t.Fatal("incomplete result admitted")
			}
		})
	}
	destination := filepath.Join(t.TempDir(), "result.json")
	if err := publishOrderedCurrentNative379Result(destination, result, orderedCurrentNative379MaxResultBytes); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("result mode = (%v, %v)", info, err)
	}
	if err := publishOrderedCurrentNative379Result(destination, result, orderedCurrentNative379MaxResultBytes); err == nil {
		t.Fatal("pre-existing output overwritten")
	}
}

// Break caught: a result assembled from expected constants or default booleans
// instead of an actual database and owned-lifecycle observation.
func TestOrderedCurrentNative379ObservedResultRequiresCompleteEvidence(t *testing.T) {
	packet := orderedCurrentNative379TestPacket()
	observation := orderedCurrentNative379TestObservation(packet)
	cleanup := orderedCurrentNative379TestCleanupObservation()
	stages := orderedCurrentNative379TestStages(packet)
	result, err := buildOrderedCurrentNative379Result(packet, &observation, &cleanup, stages)
	if err != nil || validateOrderedCurrentNative379Result(packet, result) != nil {
		t.Fatal("complete observation refused", err)
	}
	if _, err := buildOrderedCurrentNative379Result(packet, nil, &cleanup, stages); err == nil {
		t.Fatal("absent database observation admitted")
	}
	if _, err := buildOrderedCurrentNative379Result(packet, &observation, nil, stages); err == nil {
		t.Fatal("absent cleanup observation admitted")
	}
	for name, mutate := range map[string]func(*orderedCurrentNative379Observation){
		"unavailable observation": func(value *orderedCurrentNative379Observation) { value.Available = false },
		"default hashes":          func(value *orderedCurrentNative379Observation) { value.Hashes = nil },
		"missing routine":         func(value *orderedCurrentNative379Observation) { value.Objects.Routines = value.Objects.Routines[1:] },
		"extra routine": func(value *orderedCurrentNative379Observation) {
			value.Objects.Routines = append(value.Objects.Routines, "zasp_authorization80_ordered_current.extra()")
		},
		"missing table":             func(value *orderedCurrentNative379Observation) { value.Objects.Tables = value.Objects.Tables[1:] },
		"missing equality":          func(value *orderedCurrentNative379Observation) { value.Counts.EqualFacts-- },
		"absent operation recorder": func(value *orderedCurrentNative379Observation) { value.Operations = nil },
		"initialized unused recorder": func(value *orderedCurrentNative379Observation) {
			value.Operations = []orderedCurrentNative379Operation{}
		},
		"reordered operation codes": func(value *orderedCurrentNative379Observation) {
			value.Operations[0], value.Operations[1] = value.Operations[1], value.Operations[0]
		},
		"forged operation code": func(value *orderedCurrentNative379Observation) { value.Operations[0].SQLState = "42501" },
		"forged rollback":       func(value *orderedCurrentNative379Observation) { value.Restoration.TransactionRolledBack = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := observation.clone()
			mutate(&candidate)
			if _, err := buildOrderedCurrentNative379Result(packet, &candidate, &cleanup, stages); err == nil {
				t.Fatal("forged/default observation admitted")
			}
		})
	}
	badCleanup := cleanup
	badCleanup.Available = false
	if _, err := buildOrderedCurrentNative379Result(packet, &observation, &badCleanup, stages); err == nil {
		t.Fatal("unavailable cleanup evidence admitted")
	}
	noEndpoint := cleanup
	noEndpoint.EndpointChecked = false
	if _, err := buildOrderedCurrentNative379Result(packet, &observation, &noEndpoint, stages); err == nil {
		t.Fatal("cleanup without endpoint dial admitted")
	}
	forgedEndpoint := cleanup
	forgedEndpoint.EndpointSHA256 = strings.Repeat("f", 64)
	if _, err := buildOrderedCurrentNative379Result(packet, &observation, &forgedEndpoint, stages); err == nil {
		t.Fatal("stale or forged endpoint provenance admitted")
	}
	overflow := append([]orderedCurrentNative379Stage(nil), stages...)
	overflow[0].Milliseconds = int64(packet.Phases[0].Limits.MaxMilliseconds) + 1
	if _, err := buildOrderedCurrentNative379Result(packet, &observation, &cleanup, overflow); err == nil {
		t.Fatal("per-phase duration overflow admitted")
	}
}

func TestOrderedCurrentNative379OperationRecorderPreservesExactOutcomeCodes(t *testing.T) {
	success := &orderedCurrentNative379OperationRecorder{}
	if err := success.observe(orderedCurrentNative379PristineOperationPlan[0], nil); err != nil || len(success.operations) != 1 || success.operations[0].SQLState != "00000" {
		t.Fatal("successful SQL operation code not observed", success.operations, err)
	}
	postgresFailure := &orderedCurrentNative379OperationRecorder{}
	pgErr := &pgconn.PgError{Code: "42501"}
	if err := postgresFailure.observe(orderedCurrentNative379PristineOperationPlan[0], pgErr); !errors.Is(err, pgErr) || postgresFailure.operations[0].SQLState != "42501" {
		t.Fatal("PostgreSQL error code not preserved", postgresFailure.operations, err)
	}
	nonSQL := &orderedCurrentNative379OperationRecorder{}
	plain := errors.New("transport failure")
	if err := nonSQL.observe(orderedCurrentNative379PristineOperationPlan[0], plain); !errors.Is(err, plain) || nonSQL.operations[0].SQLState != "NON_SQL_ERROR" {
		t.Fatal("non-SQL refusal sentinel not preserved", nonSQL.operations, err)
	}
	if _, err := nonSQL.finish(); err == nil {
		t.Fatal("non-SQL sentinel entered accepted operation evidence")
	}
	missing := &orderedCurrentNative379OperationRecorder{}
	if err := missing.observe(orderedCurrentNative379PristineOperationPlan[0], nil); err != nil {
		t.Fatal(err)
	}
	if _, err := missing.finish(); err == nil {
		t.Fatal("partial operation sequence entered accepted evidence")
	}
	duplicate := &orderedCurrentNative379OperationRecorder{}
	if err := duplicate.observe(orderedCurrentNative379PristineOperationPlan[0], nil); err != nil {
		t.Fatal(err)
	}
	if err := duplicate.observe(orderedCurrentNative379PristineOperationPlan[0], nil); err == nil {
		t.Fatal("duplicate operation identity admitted")
	}
	if _, err := duplicate.finish(); err == nil {
		t.Fatal("duplicate operation sequence entered accepted evidence")
	}
}

// Break caught: accepting native evidence when a declared probe was truncated,
// reordered, duplicated, forged, timed out, or admitted over its packet cap.
func TestOrderedCurrentNative379ControlResultAdmissionRefusesPartialOrForgedEvidence(t *testing.T) {
	packet := orderedCurrentNative379TestPacket()
	results := orderedCurrentNative379TestControlResults(packet)
	if err := validateOrderedCurrentNative379ControlResults(packet, results); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult{
		"truncated": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			return value[:len(value)-1]
		},
		"reordered": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0], value[1] = value[1], value[0]
			return value
		},
		"duplicate": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			return append(value, value[0])
		},
		"forged mutation": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0].MutationSHA256 = strings.Repeat("f", 64)
			return value
		},
		"forged outcome": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0].Steps[0].Matched = false
			return value
		},
		"missing control step": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0].Steps = value[0].Steps[:len(value[0].Steps)-1]
			return value
		},
		"reordered control step": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0].Steps[0], value[0].Steps[1] = value[0].Steps[1], value[0].Steps[0]
			return value
		},
		"duplicate control step": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0].Steps[1] = value[0].Steps[0]
			return value
		},
		"forged observation digest": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0].Steps[0].ObservedSHA256 = "forged"
			return value
		},
		"timeout as denial": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0].Steps[0].TimedOut = true
			return value
		},
		"over cap": func(value []orderedCurrentNative379ControlResult) []orderedCurrentNative379ControlResult {
			value[0].Milliseconds = int64(packet.Phases[2].Limits.MaxMilliseconds) + 1
			return value
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneOrderedCurrentNative379ControlResults(results)
			candidate = mutate(candidate)
			if err := validateOrderedCurrentNative379ControlResults(packet, candidate); err == nil {
				t.Fatal("partial or forged control evidence admitted")
			}
		})
	}
}

// Break caught: trusting a decoded struct or claimed digest instead of the
// exact Node22-produced packet bytes.
func TestOrderedCurrentNative379RawPacketAdmissionBindsExactBytesAndPrograms(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := generateOrderedCurrentNative379PacketRaw(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := admitOrderedCurrentNative379PacketRaw(raw)
	if err != nil || len(admission.packet.Controls) != 589 {
		t.Fatal("exact packet bytes refused", err)
	}
	forgedAdmission := admission
	forgedAdmission.rawSHA = strings.Repeat("0", 64)
	if err := validateOrderedCurrentNative379Admission(forgedAdmission); err == nil {
		t.Fatal("forged wire admission token admitted")
	}
	altered := append([]byte(nil), raw...)
	altered[len(altered)/2] ^= 1
	if _, err := admitOrderedCurrentNative379PacketRaw(altered); err == nil {
		t.Fatal("altered raw packet admitted")
	}
	decoded := admission.packet.clone()
	decoded.Controls[0].Program.Steps[0].SQL += " "
	forged, _ := json.Marshal(decoded)
	if _, err := admitOrderedCurrentNative379PacketRaw(append(forged, '\n')); err == nil {
		t.Fatal("altered program with claimed structure admitted")
	}
	results := orderedCurrentNative379TestControlResults(admission.packet)
	if err := validateOrderedCurrentNative379ControlResults(admission.packet, results); err != nil {
		t.Fatal("actual 589-control result shape refused", err)
	}
	forgedResults := cloneOrderedCurrentNative379ControlResults(results)
	forgedResults[0].Steps[0].Observation = json.RawMessage(`{"sqlState":"forged"}`)
	if err := validateOrderedCurrentNative379ControlResults(admission.packet, forgedResults); err == nil {
		t.Fatal("forged actual-packet result admitted")
	}
}

// Break caught: accepting a digest without its canonical observation preimage
// or accepting a role observation that does not match the declared step role.
func TestOrderedCurrentNative379StepEvidenceBindsRoleAndObservationPreimage(t *testing.T) {
	packet := orderedCurrentNative379TestPacket()
	results := orderedCurrentNative379TestControlResults(packet)
	if err := validateOrderedCurrentNative379ControlResults(packet, results); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*orderedCurrentNative379ControlStepResult){
		"wrong declared role":      func(value *orderedCurrentNative379ControlStepResult) { value.DeclaredRole = "zasp_discovery_authority" },
		"wrong observed role":      func(value *orderedCurrentNative379ControlStepResult) { value.ObservedRole = "zasp_discovery_authority" },
		"missing session user":     func(value *orderedCurrentNative379ControlStepResult) { value.ObservedSessionUser = "" },
		"missing role observation": func(value *orderedCurrentNative379ControlStepResult) { value.RoleObservation = "" },
		"forged digest":            func(value *orderedCurrentNative379ControlStepResult) { value.ObservedSHA256 = strings.Repeat("f", 64) },
		"uppercase digest": func(value *orderedCurrentNative379ControlStepResult) {
			value.ObservedSHA256 = strings.ToUpper(value.ObservedSHA256)
		},
		"missing preimage": func(value *orderedCurrentNative379ControlStepResult) { value.Observation = nil },
		"altered preimage": func(value *orderedCurrentNative379ControlStepResult) {
			value.Observation = json.RawMessage(`{"sqlState":"forged"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneOrderedCurrentNative379ControlResults(results)
			mutate(&candidate[0].Steps[0])
			if err := validateOrderedCurrentNative379ControlResults(packet, candidate); err == nil {
				t.Fatal("forged role or observation evidence admitted")
			}
		})
	}
}

type orderedCurrentNative379PoisonScript struct {
	control                   orderedCurrentNative379Control
	index                     int
	txStatus                  byte
	currentRole               string
	sessionUser               string
	backendPID                int32
	recoveryObservationNeeded bool
	calls                     []string
}

func (script *orderedCurrentNative379PoisonScript) SessionIdentity(context.Context) (string, int32, error) {
	script.calls = append(script.calls, "identity")
	return script.sessionUser, script.backendPID, nil
}

func (script *orderedCurrentNative379PoisonScript) ObserveRole(context.Context) (string, string, error) {
	if script.txStatus == 'E' {
		script.calls = append(script.calls, "observe-refused:"+script.control.Program.Steps[script.index].ID)
		return "", "", &pgconn.PgError{Code: "25P02"}
	}
	label := "observe:" + script.control.Program.Steps[script.index].ID
	if script.recoveryObservationNeeded {
		label = "observe-after:restore"
		script.recoveryObservationNeeded = false
	}
	script.calls = append(script.calls, label)
	return script.currentRole, script.sessionUser, nil
}

func (script *orderedCurrentNative379PoisonScript) ExecStep(_ context.Context, sql string) error {
	step := script.control.Program.Steps[script.index]
	if step.SQL != sql {
		return errors.New("script received unexpected SQL")
	}
	script.calls = append(script.calls, "exec:"+step.ID)
	script.index++
	if step.ID == "setup" {
		script.txStatus = 'T'
		script.currentRole = "zasp_discovery_authority"
	}
	if step.ID == "restore" {
		if script.txStatus != 'E' {
			return errors.New("script restore was not reached from aborted transaction")
		}
		script.txStatus = 'I'
		script.currentRole = "zasp_discovery_authority"
		script.recoveryObservationNeeded = true
	}
	return nil
}

func (script *orderedCurrentNative379PoisonScript) QueryStep(_ context.Context, sql string) ([]map[string]any, error) {
	step := script.control.Program.Steps[script.index]
	if step.SQL != sql {
		return nil, errors.New("script received unexpected SQL")
	}
	script.calls = append(script.calls, "query:"+step.ID)
	script.index++
	if step.Expected.Outcome == "error" {
		if step.ID == "mutate" {
			script.txStatus = 'E'
		}
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
	case "one-row", "one-json-row":
		value, err := orderedCurrentNative379DecodeExpected(step.Expected.Value)
		if err != nil {
			return nil, err
		}
		return []map[string]any{{"value": resolve(value)}}, nil
	case "rows":
		value, err := orderedCurrentNative379DecodeExpected(step.Expected.Rows)
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

func (script *orderedCurrentNative379PoisonScript) TxStatus() byte { return script.txStatus }

func (script *orderedCurrentNative379PoisonScript) CleanupRollback(context.Context) error {
	script.txStatus = 'I'
	return nil
}

// Break caught: querying current_user in an aborted transaction before the
// declared 25P02 probe prevents the fixed rollback from ever running.
func TestOrderedCurrentNative379TransactionPoisonUsesClosedRecoveryOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admission, err := loadOrderedCurrentNative379Packet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var control orderedCurrentNative379Control
	for _, candidate := range admission.packet.Controls {
		if candidate.ID == "restore:transaction" {
			control = candidate
			break
		}
	}
	script := &orderedCurrentNative379PoisonScript{control: control, txStatus: 'I', currentRole: "zasp_test", sessionUser: "zasp_test", backendPID: 37980}
	result, err := orderedCurrentNative379ExecuteControlSession(ctx, script, admission.packet, control)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"observe:mutate", "query:mutate", "query:probe", "exec:restore", "observe-after:restore", "observe:assert-restored", "query:assert-restored"}
	joined := strings.Join(script.calls, ",")
	if !strings.Contains(joined, strings.Join(want, ",")) {
		t.Fatalf("closed poison recovery order absent: %v", script.calls)
	}
	if script.index != len(control.Program.Steps) || !result.Restored {
		t.Fatal("transaction poison program did not finish and restore")
	}
	var probe, restore orderedCurrentNative379ControlStepResult
	for _, step := range result.Steps {
		if step.ID == "probe" {
			probe = step
		}
		if step.ID == "restore" {
			restore = step
		}
	}
	if probe.ID != "probe" || probe.SQLState != "25P02" || probe.RoleObservation != "before-poison" || restore.ID != "restore" || restore.ObservedRole != "zasp_discovery_authority" || restore.ObservedSessionUser != "zasp_test" || restore.RoleObservation != "after-recovery" {
		t.Fatal("poison recovery evidence did not bind exact pre-poison and post-rollback roles", probe, restore)
	}
}

// Break caught: a false pristine catalog result reports no bounded, exact-key
// explanation of whether live collector truth is missing, extra, or changed.
func TestOrderedCurrentNative379CatalogDiagnosticClassifiesBoundedSemanticDiff(t *testing.T) {
	expected := []orderedCurrentNative379Fact{
		{Kind: "build", Identity: "provenance", Fact: json.RawMessage(`{"ignored":true}`)},
		{Kind: "routine", Identity: "a()", Fact: json.RawMessage(`{"value":1}`)},
		{Kind: "routine", Identity: "b()", Fact: json.RawMessage(`{"value":2}`)},
		{Kind: "view", Identity: "c", Fact: json.RawMessage(`{"value":3}`)},
	}
	live := []orderedCurrentNative379Fact{
		{Kind: "routine", Identity: "a()", Fact: json.RawMessage(`{ "value" : 1 }`)},
		{Kind: "routine", Identity: "b()", Fact: json.RawMessage(`{"value":20}`)},
		{Kind: "table", Identity: "d", Fact: json.RawMessage(`{"value":4}`)},
	}
	diagnostic := orderedCurrentNative379BuildCatalogDiagnostic(expected, live, 8, 20, 4096)
	if diagnostic.Expected != 3 || diagnostic.Live != 3 || diagnostic.Missing != 1 || diagnostic.Extra != 1 || diagnostic.Changed != 1 || diagnostic.Duplicates != 0 || diagnostic.Overflow {
		t.Fatal("semantic diagnostic counts drifted", diagnostic)
	}
	if len(diagnostic.Entries) != 3 || diagnostic.Entries[0].Class != "changed" || diagnostic.Entries[0].Kind != "routine" || diagnostic.Entries[0].Identity != "b()" || diagnostic.Entries[0].ExpectedSHA256 == diagnostic.Entries[0].LiveSHA256 || diagnostic.Entries[1].Class != "extra" || diagnostic.Entries[1].Identity != "d" || diagnostic.Entries[2].Class != "missing" || diagnostic.Entries[2].Identity != "c" {
		t.Fatal("semantic diagnostic entries drifted", diagnostic.Entries)
	}
}

// Break caught: duplicate collector keys or row/byte/entry overflows become
// unbounded diagnostics or conceal ambiguity.
func TestOrderedCurrentNative379CatalogDiagnosticRefusesDuplicateAndBoundsOutput(t *testing.T) {
	expected := []orderedCurrentNative379Fact{{Kind: "routine", Identity: "a()", Fact: json.RawMessage(`{"value":1}`)}}
	live := []orderedCurrentNative379Fact{
		{Kind: "routine", Identity: "a()", Fact: json.RawMessage(`{"value":1}`)},
		{Kind: "routine", Identity: "a()", Fact: json.RawMessage(`{"value":2}`)},
		{Kind: "table", Identity: "very-long-extra-key", Fact: json.RawMessage(`{"value":"0123456789"}`)},
	}
	diagnostic := orderedCurrentNative379BuildCatalogDiagnostic(expected, live, 1, 2, 32)
	if diagnostic.Duplicates != 1 || !diagnostic.Overflow || len(diagnostic.Entries) != 1 || diagnostic.Entries[0].Class != "duplicate" || diagnostic.Entries[0].Identity != "a()" {
		t.Fatal("duplicate/overflow diagnostic boundary drifted", diagnostic)
	}
	encoded, err := json.Marshal(diagnostic)
	if err != nil || len(encoded) > 2048 {
		t.Fatal("bounded diagnostic encoding drifted", len(encoded), err)
	}
}

// Break caught: a large semantic diff must retain bounded class/kind/rule
// counts and one independently visible sample for each mismatch class rather
// than allowing changed entries to crowd out missing and extra evidence.
func TestOrderedCurrentNative379CatalogDiagnosticPreservesBalancedMismatchEvidence(t *testing.T) {
	expected := make([]orderedCurrentNative379Fact, 0, 40)
	live := make([]orderedCurrentNative379Fact, 0, 40)
	for index := 0; index < 30; index++ {
		identity := fmt.Sprintf(`["rule:%d","item:%d"]`, index%3, index)
		expected = append(expected, orderedCurrentNative379Fact{Kind: "routine", Identity: identity, Fact: json.RawMessage(fmt.Sprintf(`{"value":%d}`, index))})
		live = append(live, orderedCurrentNative379Fact{Kind: "routine", Identity: identity, Fact: json.RawMessage(fmt.Sprintf(`{"value":%d}`, index+100))})
	}
	for index := 0; index < 4; index++ {
		expected = append(expected, orderedCurrentNative379Fact{Kind: "column", Identity: fmt.Sprintf(`["rule:missing","item:%d"]`, index), Fact: json.RawMessage(`{"value":1}`)})
		live = append(live, orderedCurrentNative379Fact{Kind: "trigger", Identity: fmt.Sprintf(`["rule:extra","item:%d"]`, index), Fact: json.RawMessage(`{"value":2}`)})
	}
	diagnostic := orderedCurrentNative379BuildCatalogDiagnostic(expected, live, 20, 100, 1<<20)
	encoded, err := json.Marshal(diagnostic)
	if err != nil || len(encoded) > 32768 {
		t.Fatal("bounded semantic diagnostic encoding drifted", len(encoded), err)
	}
	var view map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &view); err != nil {
		t.Fatal("semantic diagnostic JSON refused", err)
	}
	for _, key := range []string{"classCounts", "kindCounts", "ruleCounts"} {
		if len(view[key]) == 0 {
			t.Fatal("semantic diagnostic dimension missing", key)
		}
	}
	classes := make(map[string]bool)
	for _, entry := range diagnostic.Entries {
		classes[entry.Class] = true
	}
	for _, class := range []string{"changed", "missing", "extra"} {
		if !classes[class] {
			t.Fatal("balanced semantic diagnostic sample missing", class, diagnostic.Entries)
		}
	}
}

// Break caught: bounded entries must expose multiple mismatch kinds and rules;
// one changed-kind sample cannot classify the large native run-9 families.
func TestOrderedCurrentNative379CatalogDiagnosticSamplesMultipleKindsAndRules(t *testing.T) {
	expected := make([]orderedCurrentNative379Fact, 0, 36)
	live := make([]orderedCurrentNative379Fact, 0, 36)
	for index := 0; index < 18; index++ {
		identity := fmt.Sprintf(`["rule:%d","item:%d"]`, index%6, index)
		kind := []string{"column_name", "constraint", "foreign_key_trigger", "trigger", "routine", "policy"}[index%6]
		expected = append(expected, orderedCurrentNative379Fact{Kind: kind, Identity: identity, Fact: json.RawMessage(fmt.Sprintf(`{"value":%d}`, index))})
		live = append(live, orderedCurrentNative379Fact{Kind: kind, Identity: identity, Fact: json.RawMessage(fmt.Sprintf(`{"value":%d}`, index+100))})
	}
	for index := 0; index < 6; index++ {
		expected = append(expected, orderedCurrentNative379Fact{Kind: []string{"column_name", "constraint", "foreign_key_trigger"}[index%3], Identity: fmt.Sprintf(`["missing-rule:%d","item:%d"]`, index%3, index), Fact: json.RawMessage(`{"value":1}`)})
		live = append(live, orderedCurrentNative379Fact{Kind: []string{"trigger", "routine", "policy"}[index%3], Identity: fmt.Sprintf(`["extra-rule:%d","item:%d"]`, index%3, index), Fact: json.RawMessage(`{"value":2}`)})
	}
	diagnostic := orderedCurrentNative379BuildCatalogDiagnostic(expected, live, 12, 100, 1<<20)
	encoded, err := json.Marshal(diagnostic)
	if err != nil || len(encoded) > 32768 {
		t.Fatal("multi-dimension diagnostic encoding drifted", len(encoded), err)
	}
	if len(diagnostic.KindClassCounts) == 0 || len(diagnostic.RuleClassCounts) == 0 {
		t.Fatal("class-by-kind/rule counts missing", diagnostic)
	}
	kinds := make(map[string]bool)
	rules := make(map[string]bool)
	for _, entry := range diagnostic.Entries {
		kinds[entry.Kind] = true
		rules[orderedCurrentNative379DiagnosticRule(entry.Identity)] = true
	}
	if len(kinds) < 3 || len(rules) < 3 {
		t.Fatal("bounded samples did not preserve multiple kinds/rules", diagnostic.Entries)
	}
}

// Break caught: symmetric missing/extra rows with the same source-bound fact
// must be explained as a relocation only when the (kind, rule, fact) match is
// one-to-one; ambiguous matches must remain explicitly unresolved.
func TestOrderedCurrentNative379CatalogDiagnosticReportsBoundedRelocations(t *testing.T) {
	expected := []orderedCurrentNative379Fact{
		{Kind: "policy", Identity: `["rule:policy","old"]`, Fact: json.RawMessage(`{"name":"authority","using":"true"}`)},
		{Kind: "policy", Identity: `["rule:ambiguous","old-a"]`, Fact: json.RawMessage(`{"name":"same"}`)},
		{Kind: "policy", Identity: `["rule:ambiguous","old-b"]`, Fact: json.RawMessage(`{"name":"same"}`)},
	}
	live := []orderedCurrentNative379Fact{
		{Kind: "policy", Identity: `["rule:policy","new"]`, Fact: json.RawMessage(`{"name":"authority","using":"true"}`)},
		{Kind: "policy", Identity: `["rule:ambiguous","new-a"]`, Fact: json.RawMessage(`{"name":"same"}`)},
		{Kind: "policy", Identity: `["rule:ambiguous","new-b"]`, Fact: json.RawMessage(`{"name":"same"}`)},
	}
	diagnostic := orderedCurrentNative379BuildCatalogDiagnostic(expected, live, 20, 100, 1<<20)
	if len(diagnostic.RelocationCounts) != 2 || diagnostic.RelocationCounts[0].Count != 4 || diagnostic.RelocationCounts[1].Count != 2 {
		t.Fatal("relocation counts drifted", diagnostic.RelocationCounts)
	}
	if len(diagnostic.Relocations) != 1 || diagnostic.Relocations[0].BeforeIdentity != `["rule:policy","old"]` || diagnostic.Relocations[0].AfterIdentity != `["rule:policy","new"]` {
		t.Fatal("unique relocation sample drifted", diagnostic.Relocations)
	}
	if diagnostic.RelocationAmbiguities != 1 {
		t.Fatal("ambiguous relocation was not refused", diagnostic.RelocationAmbiguities)
	}
}

// Break caught: changed rows need bounded top-level field counts, not only
// opaque fact hashes, so qualification and FK predicate drift are classifiable
// without changing equality or admission.
func TestOrderedCurrentNative379CatalogDiagnosticReportsChangedFieldCounts(t *testing.T) {
	expected := []orderedCurrentNative379Fact{{Kind: "constraint", Identity: `["rule:constraint","same"]`, Fact: json.RawMessage(`{"definition":"CHECK (f())","validated":true,"name":"same"}`)}}
	live := []orderedCurrentNative379Fact{{Kind: "constraint", Identity: `["rule:constraint","same"]`, Fact: json.RawMessage(`{"definition":"CHECK (public.f())","validated":true,"name":"same"}`)}}
	diagnostic := orderedCurrentNative379BuildCatalogDiagnostic(expected, live, 20, 100, 1<<20)
	if len(diagnostic.ChangedFieldCounts) != 1 || diagnostic.ChangedFieldCounts[0].Kind != "constraint" || diagnostic.ChangedFieldCounts[0].Rule != "rule:constraint" || diagnostic.ChangedFieldCounts[0].Field != "definition" || diagnostic.ChangedFieldCounts[0].Count != 1 {
		t.Fatal("changed field counts drifted", diagnostic.ChangedFieldCounts)
	}
}

// Break caught: changed-field counts without deterministic value samples cannot
// distinguish qualification-only drift from an unrelated semantic change.
func TestOrderedCurrentNative379CatalogDiagnosticReportsBoundedChangedFieldSamples(t *testing.T) {
	expected := []orderedCurrentNative379Fact{{Kind: "foreign_key_trigger", Identity: `["rule:fk","same"]`, Fact: json.RawMessage(`{"relation":"zasp_source","referenced_relation":"zasp_target"}`)}}
	live := []orderedCurrentNative379Fact{{Kind: "foreign_key_trigger", Identity: `["rule:fk","same"]`, Fact: json.RawMessage(`{"relation":"public.zasp_source","referenced_relation":"public.zasp_target"}`)}}
	diagnostic := orderedCurrentNative379BuildCatalogDiagnostic(expected, live, 20, 100, 1<<20)
	if len(diagnostic.ChangedFieldSamples) != 2 || diagnostic.ChangedFieldSamples[0].Kind != "foreign_key_trigger" || diagnostic.ChangedFieldSamples[0].Field != "referenced_relation" || diagnostic.ChangedFieldSamples[0].ExpectedSHA256 == diagnostic.ChangedFieldSamples[0].LiveSHA256 || diagnostic.ChangedFieldSamples[0].ExpectedPreview == diagnostic.ChangedFieldSamples[0].LivePreview {
		t.Fatal("changed field samples drifted", diagnostic.ChangedFieldSamples)
	}
	encoded, err := json.Marshal(diagnostic)
	if err != nil || len(encoded) > 32768 {
		t.Fatal("changed field sample diagnostic exceeded bound", len(encoded), err)
	}
}

// Break caught: inet_server_addr()::text includes a CIDR suffix and produces
// a non-dialable endpoint string for the owned fixture cleanup proof.
func TestOrderedCurrentNative379EndpointIdentityUsesCanonicalHost(t *testing.T) {
	if !strings.Contains(orderedCurrentNative379PreinstallIdentitySQL, "host(inet_server_addr())") || strings.Contains(orderedCurrentNative379PreinstallIdentitySQL, "inet_server_addr()::text") {
		t.Fatal("native379 endpoint identity SQL is not host-canonical")
	}
}
