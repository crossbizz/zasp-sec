package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// Component-only runner command. It crosses the real68 repository, file
// artifact store and adapter TLS journal, but does not execute live Promptfoo.
func TestTemporalOwnedRunner(t *testing.T) {
	dsn := os.Getenv("ZASP_TEMPORAL_JOURNAL_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned68 database")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	for _, f := range cfg.Fallbacks {
		if net.ParseIP(f.Host) == nil || !net.ParseIP(f.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	cfg = cfg.Copy()
	cfg.User = "temporal_executor_test_login"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	mode := os.Getenv("ZASP_TEMPORAL_RUNNER_MODE")
	base := &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: conn}, t: t}
	ids := make([]domain.ProductID, 3)
	for i, k := range []string{"ZASP_ORDERED_ORG", "ZASP_ORDERED_WORKSPACE", "ZASP_ORDERED_ENVIRONMENT"} {
		ids[i], err = domain.ParseProductID(os.Getenv(k))
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	parent, step := os.Getenv("ZASP_TEMPORAL_PARENT"), os.Getenv("ZASP_TEMPORAL_STEP")
	db := &temporalRunnerFaultDatabase{release61WorkerPG: base, owner: owner, run: parent, mode: mode}
	version, err := strconv.ParseInt(os.Getenv("ZASP_TEMPORAL_DEFINITION_VERSION"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	driver := &temporalRunnerArtifactDriver{release61ArtifactDriver: release61ArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}, mode: mode}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	token := filepath.Join(root, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 64)), 0400); err != nil {
		t.Fatal(err)
	}
	calls := 0
	command := redTeamCommandFunc(func(ctx context.Context, executable string, args, env []string, dir string) error {
		calls++
		if mode == "command_error" {
			return errWorkerExecution
		}
		var key string
		for _, v := range env {
			if strings.HasPrefix(v, "ZASP_RED_TEAM_RUN_LEASE=") {
				t.Error("fabricated lease")
			}
			if strings.HasPrefix(v, "ZASP_RED_TEAM_EFFECT_KEY=") {
				key = strings.TrimPrefix(v, "ZASP_RED_TEAM_EFFECT_KEY=")
			}
		}
		if !redteamadapter.ValidEffectKey(key) || executable != "/usr/local/bin/node" || len(args) != 4 || !containsWorkerString(env, "ZASP_RED_TEAM_TARGET_ENDPOINT=https://agentsec-red-team-adapter.platform.svc.cluster.local/v1/effects/evaluate") {
			return errWorkerExecution
		}
		body, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		var input redTeamRunnerInput
		if decodeStrictWorkerJSON(body, &input) != nil {
			return errWorkerExecution
		}
		observations := map[string]redteamadapter.LinkedObservationResponse{}
		for _, category := range input.Categories {
			child := exec.CommandContext(ctx, "go", "test", "./redteamadapter", "-run", "^TestTemporalOwnedHTTPS$", "-count=1", "-v")
			child.Dir = ".."
			child.WaitDelay = 5 * time.Second
			child.Env = append(os.Environ(), "ZASP_TEMPORAL_JOURNAL_MODE=success", "ZASP_ORDERED_TEST_RUN="+input.RunID, "ZASP_TEMPORAL_EFFECT_KEY="+key, "ZASP_TEMPORAL_CATEGORY="+category, "ZASP_TEMPORAL_TARGET="+input.TargetID, "ZASP_TEMPORAL_KIND="+input.TargetKind)
			output, err := child.CombinedOutput()
			t.Log(string(output))
			if err != nil || !strings.Contains(string(output), "provider_calls=1 credential_reads=1") || strings.Contains(string(output), "--- SKIP:") {
				return errWorkerExecution
			}
			var raw []byte
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('schema_version','red-team-linked-observation-v1','run_id',test_run_id,'category',category,'target_comparison',target_resolution->'comparison','credential_version_digest',encode(credential_version_digest,'hex'),'observation',jsonb_build_object('http_status',http_status,'response_digest',encode(response_digest,'hex'),'protected',protected)) FROM zasp_temporal68.invocations WHERE effect_key=$1 AND category=$2 AND state='completed'`, key, category).Scan(&raw); err != nil {
				t.Log("controlled command journal read", err)
				return err
			}
			var observed redteamadapter.LinkedObservationResponse
			if json.Unmarshal(raw, &observed) != nil {
				return errWorkerExecution
			}
			observations[category] = observed
		}
		return temporalControlledRunnerOutput(input, observations, dir, args[3])
	})
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "registry.example/zasp-red-team@sha256:" + strings.Repeat("a", 64), Artifacts: store, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.platform.svc.cluster.local/v1/evaluate", TargetTokenFile: token, TargetCAFile: writeRedTeamTestCA(t, root), TempRoot: root, Timeout: 60 * time.Second, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := any(runner).(interface {
		RunTemporalTest(context.Context, apiserver.JSONDatabase, domain.Scope, string, string, int64) (string, error)
	})
	if !ok {
		t.Fatal("reusable68 runner operation missing")
	}
	state, err := actual.RunTemporalTest(ctx, db, scope, parent, step, version)
	if strings.HasPrefix(mode, "wire_") {
		if err == nil || !db.fired || calls != 0 || driver.puts != 0 {
			t.Fatal("malformed runner status reached IO", state, err, calls, driver.puts)
		}
		return
	}
	if mode == "lost_dispatch" || mode == "lost_settle" || mode == "input_get" {
		wantCalls := 0
		if mode == "lost_settle" {
			wantCalls = 1
		}
		if err == nil || calls != wantCalls {
			t.Fatal("runner acknowledgement/readback fault missed", state, err, calls)
		}
		state, err = actual.RunTemporalTest(ctx, db, scope, parent, step, version)
	}
	if mode != "" && mode != "lost_settle" && mode != "input_get" {
		wantCalls := 0
		if mode == "command_error" || mode == "output_get" {
			wantCalls = 1
		}
		if err != nil || state != "stopped" || calls != wantCalls {
			t.Fatal("runner fault did not stop honestly", mode, state, err, calls)
		}
		before := driver.puts
		state, err = actual.RunTemporalTest(ctx, db, scope, parent, step, version)
		if err != nil || state != "stopped" || calls != wantCalls || driver.puts != before {
			t.Fatal("stopped runner resent or rewrote", state, err, calls)
		}
		var valid bool
		childState, reason := "failed", "test_outcome_unknown"
		if mode == "reserved_lost" || mode == "input_lost" {
			childState, reason = "cancelled", "test_cancelled_before_dispatch"
		}
		if err := owner.QueryRow(ctx, `SELECT c.state=$2 AND c.attempt=0 AND c.lease_token IS NULL AND c.lease_expires_at IS NULL AND s.response->>'reason'=$3 AND NOT EXISTS(SELECT 1 FROM zasp_red_team_attempts a WHERE a.run_id=c.run_id) AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements x WHERE x.run_id=l.run_id) FROM zasp_security_agent_test_links l JOIN zasp_red_team_runs c ON c.run_id=l.test_run_id JOIN zasp_temporal68.test_stops s ON s.run_id=l.run_id AND s.step_id=l.step_id WHERE l.run_id=$1`, parent, childState, reason).Scan(&valid); err != nil || !valid {
			t.Fatal("fabricated runner settlement", valid, err)
		}
		t.Log("actual68 runner fault joined", mode, "command_calls", calls)
		return
	}
	if err != nil || state != "settled" {
		t.Fatal("actual68 runner did not settle", state, err)
	}
	if calls != 1 || driver.puts < 2 || mode != "input_get" && driver.puts != 2 {
		t.Fatal("input/output IO or command count", calls, driver.puts)
	}
	before := driver.puts
	state, err = actual.RunTemporalTest(ctx, db, scope, parent, step, version)
	if err != nil || state != "settled" || calls != 1 || driver.puts != before {
		t.Fatal("terminal runner resend/artifact rewrite", state, err, calls, driver.puts)
	}
	var valid bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_red_team_runs r JOIN zasp_security_agent_test_links l ON l.test_run_id=r.run_id WHERE l.run_id=$1 AND l.step_id=$2 AND r.state='complete' AND r.attempt=1 AND r.lease_token IS NULL AND r.lease_expires_at IS NULL AND EXISTS(SELECT 1 FROM zasp_red_team_attempts a WHERE a.run_id=r.run_id AND a.attempt=1)`, parent, step).Scan(&valid); err != nil || !valid {
		t.Fatal("lease-free runner settlement", valid, err)
	}
	t.Log("real68 runner: two artifact writes with readback, one command, durable journal TLS per category; terminal replay did not resend")
}

type temporalRunnerFaultDatabase struct {
	*release61WorkerPG
	owner     *pgx.Conn
	run, mode string
	fired     bool
}

func (d *temporalRunnerFaultDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second {
		d.t.Error("runner SQL call lacks finite bound")
	}
	raw, err := d.release61WorkerPG.QueryJSON(ctx, q, args...)
	if err != nil || d.fired || len(args) == 0 {
		return raw, err
	}
	var request struct {
		Operation string `json:"operation"`
	}
	if body, ok := args[0].([]byte); ok {
		json.Unmarshal(body, &request)
	}
	if body, ok := args[0].(json.RawMessage); ok {
		json.Unmarshal(body, &request)
	}
	status := strings.Contains(q, ".status(")
	if d.mode == "reserved_lost" && status || d.mode == "input_lost" && request.Operation == "input" {
		d.fired = true
		_, err = d.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, d.run)
	}
	if d.mode == "lost_dispatch" && request.Operation == "dispatch" || d.mode == "lost_settle" && strings.Contains(q, ".test_settle(") {
		d.fired = true
		return nil, errWorkerExecution
	}
	if strings.HasPrefix(d.mode, "wire_") && status {
		d.fired = true
		if d.mode == "wire_duplicate_run" {
			raw = append([]byte(`{"run_id":"foreign",`), raw[1:]...)
		}
		if d.mode == "wire_missing_effects" {
			var fields map[string]json.RawMessage
			json.Unmarshal(raw, &fields)
			delete(fields, "effects")
			raw, err = json.Marshal(fields)
		}
	}
	return raw, err
}

type temporalRunnerArtifactDriver struct {
	release61ArtifactDriver
	mode  string
	fired bool
}

func (d *temporalRunnerArtifactDriver) Get(ctx context.Context, v artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	result, err := d.release61ArtifactDriver.Get(ctx, v)
	if err == nil && !d.fired && (d.mode == "input_get" && d.puts == 1 || d.mode == "output_get" && d.puts == 2) {
		d.fired = true
		return artifactstore.DriverObject{}, artifactstore.ErrGet
	}
	return result, err
}

func temporalControlledRunnerOutput(input redTeamRunnerInput, observations map[string]redteamadapter.LinkedObservationResponse, dir, out string) error {
	native := redTeamNativeArtifact{SchemaVersion: "red-team-native-artifact-v2", RedactionPolicy: "red-team-artifact-redaction-v2", RunID: input.RunID, InputDigest: input.InputDigest, EvaluationIdentity: expectedRedTeamEvaluationIdentity(input), NativeOutput: &redTeamNativeOutput{}}
	native.NativeOutput.Metadata.PromptfooVersion = "0.121.19"
	native.NativeOutput.Results.Version = 3
	summary := redTeamRunnerOutput{SchemaVersion: "red-team-evidence-v2", Engine: "promptfoo", EngineVersion: "0.121.19", RunID: input.RunID, InputDigest: input.InputDigest, Objective: "Evaluate curated categories: " + strings.Join(input.Categories, ", "), Verdict: "pass"}
	passed := 0
	for _, category := range input.Categories {
		observation, ok := observations[category]
		if !ok || observation.Observation.Protected == nil {
			return errWorkerExecution
		}
		protected := *observation.Observation.Protected
		record := redTeamNativeResult{Success: &protected}
		record.Provider.Label = "zasp-red-team-adapter"
		record.Vars.Category = category
		record.Vars.Prompt = redTeamCuratedPrompt(category)
		record.TestCase.Metadata.Category = category
		record.TestCase.Assert = []redTeamNativeAssertion{{Type: "javascript", Value: redTeamLinkedAssertion}}
		record.Response.Output = "[REDACTED]"
		status := observation.Observation.HTTPStatus
		record.Response.Metadata.HTTP.Status = &status
		record.Response.LinkedObservation = &observation
		record.GradingResult.Pass = &protected
		record.GradingResult.Reason = "[REDACTED]"
		native.NativeOutput.Results.Results = append(native.NativeOutput.Results.Results, record)
		suffix := "unsafe behavior observed"
		if protected {
			passed++
			suffix = "protected"
		} else {
			summary.Verdict = "fail"
		}
		summary.Evidence = append(summary.Evidence, category+": "+suffix)
	}
	summary.Behavior = fmt.Sprintf("%d of %d curated security checks passed; %d exposed unsafe behavior.", passed, len(input.Categories), len(input.Categories)-passed)
	nativeBody, _ := json.Marshal(native)
	summaryBody, _ := json.Marshal(summary)
	if writeRedTeamFile(filepath.Join(dir, "artifact.json"), nativeBody) != nil || writeRedTeamFile(out, summaryBody) != nil {
		return errWorkerExecution
	}
	return nil
}
