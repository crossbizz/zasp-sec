package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type dispatchReadbackStore struct {
	*artifactstore.Store
	gets    int
	corrupt bool
}

func (s *dispatchReadbackStore) Get(ctx context.Context, l artifactstore.Locator) (artifactstore.Artifact, error) {
	s.gets++
	a, e := s.Store.Get(ctx, l)
	if s.corrupt && len(a.Body) > 0 {
		a.Body[0] = '!'
	}
	return a, e
}

type dispatchReadbackDatabase struct {
	JSONDatabase
	t                         *testing.T
	before, after             json.RawMessage
	store                     *dispatchReadbackStore
	composed, execute, legacy int
	finalErr                  error
}

func (d *dispatchReadbackDatabase) QueryJSON(_ context.Context, sql string, args ...any) (json.RawMessage, error) {
	if strings.Contains(sql, "ready(") {
		return json.RawMessage(`true`), nil
	}
	d.legacy++
	var q temporalEffectRequest
	_ = json.Unmarshal(args[0].(json.RawMessage), &q)
	if q.Operation == "read" {
		return d.before, nil
	}
	return d.after, nil
}
func (d *dispatchReadbackDatabase) DispatchOrderedTestLinked(ctx context.Context, raw json.RawMessage, verify func(json.RawMessage) error) (json.RawMessage, error) {
	d.composed++
	var q temporalEffectRequest
	if json.Unmarshal(raw, &q) != nil || q.Operation != "dispatch" {
		d.t.Fatal("wrong composed request")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second {
		d.t.Fatal("dispatch budget lost")
	}
	if err := verify(d.before); err != nil {
		return nil, err
	}
	if d.store.gets != 1 {
		d.t.Fatal("dispatch preceded real artifact read", d.store.gets)
	}
	d.execute++
	return d.after, d.finalErr
}

func dispatchReadbackFixture(t *testing.T, action string) (*securityAgentMultistepAdmissionRepository, *dispatchReadbackDatabase, *dispatchReadbackStore, json.RawMessage) {
	t.Helper()
	o := "pid_89000001-0000-4000-8000-000000000001"
	w := "pid_89000002-0000-4000-8000-000000000001"
	e := "pid_89000003-0000-4000-8000-000000000001"
	r := "pid_89000004-0000-4000-8000-000000000001"
	org, _ := domain.ParseProductID(o)
	workspace, _ := domain.ParseProductID(w)
	environment, _ := domain.ParseProductID(e)
	scope, _ := domain.NewScope(org, workspace, environment)
	index := "1"
	if action != "" {
		index = "0"
	}
	step, _ := CanonicalDiscoveryID(scope, "security_agent_step", r+"\x1f"+index)
	childAction := action
	if childAction == "" {
		childAction = "run_test"
	}
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", r+"\x1f"+step+"\x1f"+childAction)
	q := temporalEffectRequest{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, RunID: r, StepID: step, Generation: 1, Operation: "dispatch", Payload: json.RawMessage(`{}`)}
	raw, _ := json.Marshal(q)
	digest := strings.Repeat("a", 64)
	target := "pid_89000011-0000-4000-8000-000000000001"
	definition := "pid_89000012-0000-4000-8000-000000000001"
	input := orderedTestInput{SchemaVersion: "red-team-runner-input-v2", OrganizationID: o, WorkspaceID: w, EnvironmentID: e, RunID: child, DefinitionID: definition, DefinitionVersion: 1, TargetID: target, TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, InputDigest: digest, RunnerImageDigest: "sha256:" + digest}
	body, _ := json.Marshal(input)
	store, err := artifactstore.New(&orderedTestArtifactDriver{objects: make(map[artifactstore.DriverLocator]artifactstore.DriverObject)}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", r+"\x1f"+step)
	ref, _ := domain.ParseEvidenceRef(id)
	a, err := store.Put(context.Background(), artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/json", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	object, _ := store.ObjectReference(a.Locator)
	manifest := RedTeamArtifactReference{Reference: object, VersionID: a.VersionID, SHA256: hex.EncodeToString(a.SHA256[:]), SizeBytes: a.Size}
	endpoint := "https://target.example/evaluate"
	endpointHash := sha256.Sum256([]byte(endpoint))
	resolution, _ := json.Marshal(map[string]any{"binding": map[string]any{"target_id": target, "target_kind": "agent_endpoint", "endpoint": endpoint, "credential_reference": "ref:red-team/fixture_credential", "version": 1}, "comparison": map[string]any{"schema_version": "red-team-target-comparison-v1", "organization_id": o, "workspace_id": w, "environment_id": e, "test_definition_id": definition, "test_definition_version": 1, "target_id": target, "target_kind": "agent_endpoint", "categories": input.Categories, "safety_digest": digest, "endpoint_digest": hex.EncodeToString(endpointHash[:]), "configuration_digest": digest, "credential_binding_id": target, "credential_binding_version": 1, "credential_binding_digest": digest}, "provenance": map[string]any{"integration_id": target, "snapshot_id": target, "evidence_id": target, "source": "fixture", "generation": 1}})
	bodyText := string(body)
	state := temporalLinkedState{EffectKey: temporalEffectIdentity(q), Generation: 1, TestRunID: child, InputDigest: digest, DefinitionID: definition, DefinitionVersion: 1, TargetID: target, TargetKind: "agent_endpoint", Categories: input.Categories, TargetResolution: resolution, InputManifest: &manifest, InputBody: &bodyText}
	before, _ := json.Marshal(state)
	state.SendPermit = true
	after, _ := json.Marshal(state)
	counted := &dispatchReadbackStore{Store: store}
	db := &dispatchReadbackDatabase{t: t, before: before, after: after, store: counted}
	return &securityAgentMultistepAdmissionRepository{database: db}, db, counted, raw
}

func TestTemporalDispatchUsesOneComposedDecisionWithRealReadback(t *testing.T) {
	repo, db, store, q := dispatchReadbackFixture(t, "")
	got, err := repo.TemporalLinked(context.Background(), q, store)
	if err != nil || len(got) == 0 || db.composed != 1 || db.legacy != 0 || db.execute != 1 || store.gets != 2 {
		t.Fatalf("composed=%d legacy=%d execute=%d gets=%d err=%v", db.composed, db.legacy, db.execute, store.gets, err)
	}
}
func TestTemporalDispatchReadbackRefusesBeforeExecution(t *testing.T) {
	for _, mutation := range []string{"scope", "body", "hash", "version", "missing", "permit", "artifact"} {
		t.Run(mutation, func(t *testing.T) {
			repo, db, store, q := dispatchReadbackFixture(t, "")
			var state temporalLinkedState
			_ = json.Unmarshal(db.before, &state)
			switch mutation {
			case "scope":
				state.TestRunID = state.TargetID
			case "body":
				s := "{}"
				state.InputBody = &s
			case "hash":
				state.InputManifest.SHA256 = strings.Repeat("b", 64)
			case "version":
				state.InputManifest.VersionID = "foreign"
			case "missing":
				state.InputManifest = nil
				state.InputBody = nil
			case "permit":
				state.SendPermit = true
			case "artifact":
				store.corrupt = true
			}
			db.before, _ = json.Marshal(state)
			if _, err := repo.TemporalLinked(context.Background(), q, store); err == nil || db.execute != 0 {
				t.Fatalf("invalid readback reached dispatch: %d %v", db.execute, err)
			}
		})
	}
}
func TestTemporalDispatchFinalRefusalAndMismatch(t *testing.T) {
	for _, mode := range []string{"authority-error", "changed", "comparison"} {
		t.Run(mode, func(t *testing.T) {
			repo, db, store, q := dispatchReadbackFixture(t, "")
			if mode == "authority-error" {
				db.finalErr = ErrRepositoryConflict
			} else {
				var state temporalLinkedState
				_ = json.Unmarshal(db.after, &state)
				if mode == "comparison" {
					var resolution map[string]any
					_ = json.Unmarshal(state.TargetResolution, &resolution)
					resolution["provenance"].(map[string]any)["generation"] = 2
					state.TargetResolution, _ = json.Marshal(resolution)
				} else {
					state.DefinitionVersion = 2
				}
				db.after, _ = json.Marshal(state)
			}
			if _, err := repo.TemporalLinked(context.Background(), q, store); err == nil || db.execute != 1 {
				t.Fatal("final refusal lost", err, db.execute)
			}
		})
	}
}
func TestSingleTestDispatchKeepsHistoricalReadback(t *testing.T) {
	repo, db, store, q := dispatchReadbackFixture(t, "run_test")
	if _, err := repo.SingleTestLinked(context.Background(), q, store, "run_test"); err != nil || db.composed != 0 || db.legacy != 2 || store.gets != 2 {
		t.Fatal(err, db.composed, db.legacy, store.gets)
	}
}

type legacyDispatchDatabase struct {
	JSONDatabase
	inner *dispatchReadbackDatabase
}

func (d *legacyDispatchDatabase) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	return d.inner.QueryJSON(ctx, sql, args...)
}
func TestLegacyOrderedDispatchKeepsHistoricalReadback(t *testing.T) {
	repo, db, store, q := dispatchReadbackFixture(t, "")
	repo.database = &legacyDispatchDatabase{inner: db}
	if _, err := repo.TemporalLinked(context.Background(), q, store); err != nil || db.composed != 0 || db.legacy != 2 || store.gets != 2 {
		t.Fatal(err, db.composed, db.legacy, store.gets)
	}
}
