package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

func TestSecurityAgentRelease61TickPreflightsEveryDependencyBeforeRead(t *testing.T) {
	runtime, database, journalDatabase, store, providerCalls := release61PreflightFixture(t)
	if err := runtime.preflight(); err != nil || database.calls.Load() != 0 || journalDatabase.calls.Load() != 0 || store.calls.Load() != 0 || providerCalls.Load() != 0 {
		t.Fatalf("valid local preflight failed or performed I/O: err=%v", err)
	}
	for name, mutate := range map[string]func(*securityAgentRelease61Runtime){
		"journal":         func(r *securityAgentRelease61Runtime) { r.journal = nil },
		"invalid journal": func(r *securityAgentRelease61Runtime) { r.journal = &redteamadapter.PostgresInvocationJournal{} },
		"base release61 journal": func(r *securityAgentRelease61Runtime) {
			r.journal, _ = redteamadapter.NewPostgresInvocationJournal(journalDatabase, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
		},
		"stale journal checksum": func(r *securityAgentRelease61Runtime) {
			r.journal, _ = redteamadapter.NewPostgresInvocationJournal(journalDatabase, strings.Repeat("0", 64), migrations.SecurityAgentMultistepRegisteredFingerprint())
		},
		"stale journal fingerprint": func(r *securityAgentRelease61Runtime) {
			r.journal, _ = redteamadapter.NewPostgresInvocationJournal(journalDatabase, migrations.ProductionSecurityAgentMultistep().Checksum(), strings.Repeat("0", 64))
		},
		"planning database":        func(r *securityAgentRelease61Runtime) { r.planning.Database = nil },
		"planning store":           func(r *securityAgentRelease61Runtime) { r.planning.Store = nil },
		"planner":                  func(r *securityAgentRelease61Runtime) { r.planning.Planner = nil },
		"closed planner":           func(r *securityAgentRelease61Runtime) { r.planning.Planner.closed = true },
		"planner model":            func(r *securityAgentRelease61Runtime) { r.planning.Planner.model = "openai/gpt-4o-mini" },
		"test runner":              func(r *securityAgentRelease61Runtime) { r.testRunner = nil },
		"test runner store":        func(r *securityAgentRelease61Runtime) { r.testRunner.config.Artifacts = nil },
		"test runner image absent": func(r *securityAgentRelease61Runtime) { r.testRunner.config.RunnerImage = "" },
		"test runner image mutable": func(r *securityAgentRelease61Runtime) {
			r.testRunner.config.RunnerImage = "registry.example/zasp-red-team:latest"
		},
		"organization":    func(r *securityAgentRelease61Runtime) { r.planning.Selection.OrganizationID = "bad" },
		"workspace":       func(r *securityAgentRelease61Runtime) { r.planning.Selection.WorkspaceID = "bad" },
		"environment":     func(r *securityAgentRelease61Runtime) { r.planning.Selection.EnvironmentID = "bad" },
		"account profile": func(r *securityAgentRelease61Runtime) { r.planning.Selection.AccountProfile = "" },
		"credential reference": func(r *securityAgentRelease61Runtime) {
			r.planning.Selection.CredentialReference = "secret_ref_planner/global"
		},
		"policy id malformed":  func(r *securityAgentRelease61Runtime) { r.planning.Selection.PolicyID = "bad" },
		"policy id mismatch":   func(r *securityAgentRelease61Runtime) { r.planning.Selection.PolicyID = r.planning.Selection.AccountID },
		"policy version":       func(r *securityAgentRelease61Runtime) { r.planning.Selection.PolicyVersion = 0 },
		"policy digest":        func(r *securityAgentRelease61Runtime) { r.planning.Selection.PolicyDigest = "bad" },
		"account id malformed": func(r *securityAgentRelease61Runtime) { r.planning.Selection.AccountID = "bad" },
		"account id mismatch":  func(r *securityAgentRelease61Runtime) { r.planning.Selection.AccountID = r.planning.Selection.PolicyID },
		"account version":      func(r *securityAgentRelease61Runtime) { r.planning.Selection.AccountVersion = 0 },
		"deployment worker":    func(r *securityAgentRelease61Runtime) { r.deploymentWorkerID = "" },
		"deployment lease":     func(r *securityAgentRelease61Runtime) { r.deploymentLeaseToken = "short" },
		"planning worker":      func(r *securityAgentRelease61Runtime) { r.planning.WorkerID = "" },
		"planning lease":       func(r *securityAgentRelease61Runtime) { r.planning.LeaseToken = "short" },
		"signing key id":       func(r *securityAgentRelease61Runtime) { r.keyID = "" },
		"signing private key":  func(r *securityAgentRelease61Runtime) { r.privateKey = nil },
		"mismatched signing key": func(r *securityAgentRelease61Runtime) {
			r.privateKey = ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", ed25519.SeedSize)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *runtime
			candidate.planning = runtime.planning
			if runtime.planning.Planner != nil {
				original := runtime.planning.Planner
				original.mu.RLock()
				candidate.planning.Planner = &productionSecurityAgentPlanner{endpoint: original.endpoint, model: original.model, token: append([]byte(nil), original.token...), maximumTokens: original.maximumTokens, policyVersion: original.policyVersion, client: original.client, closed: original.closed}
				original.mu.RUnlock()
			}
			if runtime.testRunner != nil {
				copyRunner := *runtime.testRunner
				candidate.testRunner = &copyRunner
			}
			mutate(&candidate)
			database.calls.Store(0)
			journalDatabase.calls.Store(0)
			store.calls.Store(0)
			providerCalls.Store(0)
			if transition, err := candidate.Tick(context.Background()); err == nil || transition != "" {
				t.Fatalf("invalid runtime advanced: transition=%q err=%v", transition, err)
			}
			if database.calls.Load() != 0 || journalDatabase.calls.Load() != 0 || store.calls.Load() != 0 || providerCalls.Load() != 0 {
				t.Fatalf("preflight failure performed I/O: composition=%d journal=%d store=%d provider=%d", database.calls.Load(), journalDatabase.calls.Load(), store.calls.Load(), providerCalls.Load())
			}
		})
	}
}

func release61PreflightFixture(t *testing.T) (*securityAgentRelease61Runtime, *release61PreflightDatabase, *release61PreflightDatabase, *release61PreflightStore, *atomic.Int32) {
	t.Helper()
	database := &release61PreflightDatabase{}
	journalDatabase := &release61PreflightDatabase{}
	store := &release61PreflightStore{}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"release61-component": private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	composition, err := apiserver.NewSecurityAgentRelease61Composition(context.Background(), apiserver.SecurityAgentRelease61CompositionConfig{Worker: database, Action: database, Deployment: database, TestWorker: database, Store: store, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	baseJournal, err := redteamadapter.NewPostgresInvocationJournal(journalDatabase, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	journal, err := baseJournal.Release61(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	providerCalls := &atomic.Int32{}
	planner := orderedRequestBindingPlanner(t, release61PreflightTransport{calls: providerCalls})
	root := t.TempDir()
	token := filepath.Join(root, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 64)), 0o400); err != nil {
		t.Fatal(err)
	}
	ca := writeRedTeamTestCA(t, root)
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "registry.example/zasp-red-team@sha256:" + strings.Repeat("a", 64), Artifacts: store, Command: redTeamCommandFunc(func(context.Context, string, []string, []string, string) error { return nil }), NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.platform.svc.cluster.local/v1/evaluate", TargetTokenFile: token, TargetCAFile: ca, TempRoot: root, Timeout: time.Minute, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &securityAgentRelease61Runtime{
		composition: composition,
		planning: orderedPlanningConfig{Database: database, Store: store, Planner: planner, Selection: securityAgentMultistepPricingBinding{
			AccountProfile: "local-controlled-account", CredentialReference: "secret_ref_planner/pid_71000001-0000-4000-8000-000000000001/pid_71000002-0000-4000-8000-000000000002/pid_71000003-0000-4000-8000-000000000003/credential", PolicyID: "pid_62c591fd-f6e0-4793-8aa2-16aa29135f31", PolicyVersion: 1,
			PolicyDigest: "sha256:" + strings.Repeat("c", 64), AccountID: "pid_56b04655-ade6-465b-8ddd-d53b93412312", AccountVersion: 1,
		}, RunID: "pid_78000001-0000-4000-8000-000000000001", WorkerID: "release61-worker", LeaseToken: strings.Repeat("a", 32)},
		deploymentWorkerID: "release61-delivery", deploymentLeaseToken: strings.Repeat("b", 32), keyID: "release61-component", privateKey: private,
		testRunner: runner, journal: journal,
	}
	runtime.planning.Selection.OrganizationID = "pid_71000001-0000-4000-8000-000000000001"
	runtime.planning.Selection.WorkspaceID = "pid_71000002-0000-4000-8000-000000000002"
	runtime.planning.Selection.EnvironmentID = "pid_71000003-0000-4000-8000-000000000003"
	database.calls.Store(0)
	journalDatabase.calls.Store(0)
	return runtime, database, journalDatabase, store, providerCalls
}

type release61PreflightDatabase struct{ calls atomic.Int32 }

func (d *release61PreflightDatabase) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	d.calls.Add(1)
	if strings.Contains(statement, "orchestration_ready") || strings.Contains(statement, "client_ready") || strings.Contains(statement, "test_adapter_ready") || strings.Contains(statement, "principal_ready") {
		return json.RawMessage("true"), nil
	}
	return nil, errWorkerExecution
}
func (*release61PreflightDatabase) SchemaVersion(context.Context) (string, error) { return "", nil }
func (*release61PreflightDatabase) Exec(context.Context, string, ...any) error    { return nil }

type release61PreflightStore struct{ calls atomic.Int32 }

func (s *release61PreflightStore) Put(context.Context, artifactstore.PutRequest) (artifactstore.Artifact, error) {
	s.calls.Add(1)
	return artifactstore.Artifact{}, errWorkerExecution
}
func (s *release61PreflightStore) Get(context.Context, artifactstore.Locator) (artifactstore.Artifact, error) {
	s.calls.Add(1)
	return artifactstore.Artifact{}, errWorkerExecution
}
func (s *release61PreflightStore) Delete(context.Context, artifactstore.Locator) error {
	s.calls.Add(1)
	return errWorkerExecution
}
func (s *release61PreflightStore) ObjectReference(artifactstore.Locator) (string, error) {
	s.calls.Add(1)
	return "", errWorkerExecution
}

type release61PreflightTransport struct{ calls *atomic.Int32 }

func (t release61PreflightTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, errWorkerExecution
}
