package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

func TestSecurityAgentRelease61OwnedTick(t *testing.T) {
	dsn := os.Getenv("ZASP_ORDERED_PLANNING_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned local release61 database")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || config.User != "zasp_e2e" || config.Database != "postgres" || net.ParseIP(config.Host) == nil || !net.ParseIP(config.Host).IsLoopback() {
		t.Fatal("requires owned loopback database")
	}
	for _, fallback := range config.Fallbacks {
		if net.ParseIP(fallback.Host) == nil || !net.ParseIP(fallback.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	connect := func(user string) *release61WorkerPG {
		c := config.Copy()
		c.User = user
		conn, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer closeCancel()
			if err := conn.Close(closeCtx); err != nil {
				t.Error(err)
			}
		})
		return &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: conn}, t: t}
	}
	worker, action, deployment, red := connect("security_agent_v33_worker_login"), connect("ordered_legacy_action_login"), connect("ordered_application_deployment"), connect("ordered_test_red_worker")
	adapter := connect("ordered_test_red_adapter")
	baseJournal, _ := redteamadapter.NewPostgresInvocationJournal(adapter, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint())
	journal, err := baseJournal.Release61(ctx)
	if err != nil {
		t.Fatal("journal composition", err)
	}
	var selection securityAgentMultistepPricingBinding
	if json.Unmarshal([]byte(os.Getenv("ZASP_ORDERED_PLANNING_BINDING")), &selection) != nil {
		t.Fatal("binding")
	}
	if foreign := os.Getenv("ZASP_RELEASE61_FOREIGN_ORG"); foreign != "" {
		selection.OrganizationID = foreign
	}
	driver := &release61ArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: os.Getenv("ZASP_ORDERED_PLANNING_ARTIFACTS"), t: t}}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"release61-component": key.Public().(ed25519.PublicKey)})
	facade, err := apiserver.NewSecurityAgentRelease61Composition(ctx, apiserver.SecurityAgentRelease61CompositionConfig{Worker: worker, Action: action, Deployment: deployment, TestWorker: red, Store: store, Keys: keys})
	if err != nil {
		t.Fatal("composition", err)
	}
	worker.stale = os.Getenv("ZASP_RELEASE61_STALE_PIN") == "1"
	candidate := `{"version":1,"summary":"Contain and retest","steps":[{"index":0,"action":"create_temporary_policy","target_id":"` + selection.EnvironmentID + `"},{"index":1,"action":"run_test","target_id":"` + os.Getenv("ZASP_ORDERED_PLANNING_TEST_ID") + `"}]}`
	var response map[string]json.RawMessage
	json.Unmarshal(openRouterPlannerResponse(candidate), &response)
	response["usage"] = json.RawMessage(`{"prompt_tokens":50,"completion_tokens":50,"total_tokens":100,"cost":0.0000005}`)
	body, _ := json.Marshal(response)
	if os.Getenv("ZASP_RELEASE61_PROVIDER_UNKNOWN") == "1" {
		body = []byte(`{"error":"controlled provider outcome unknown"}`)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if os.Getenv("ZASP_RELEASE61_PROVIDER_UNKNOWN") == "1" {
			w.WriteHeader(http.StatusBadGateway)
		}
		w.Write(body)
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client := server.Client()
	defer client.CloseIdleConnections()
	planner := orderedRequestBindingPlanner(t, &release61TLSTransport{base: client.Transport, target: target})
	runtime := &securityAgentRelease61Runtime{composition: facade, planning: orderedPlanningConfig{Database: worker, Store: store, Planner: planner, Selection: selection, RunID: os.Getenv("ZASP_ORDERED_PLANNING_RUN"), WorkerID: "release61-worker", LeaseToken: strings.Repeat("a", 32)}, deploymentWorkerID: "release61-delivery", deploymentLeaseToken: strings.Repeat("b", 32), keyID: "release61-component", privateKey: key}
	runtime.journal = journal
	if lease := os.Getenv("ZASP_RELEASE61_DEPLOYMENT_LEASE"); lease != "" {
		runtime.DeploymentLeaseDuration, err = time.ParseDuration(lease)
		if err != nil {
			t.Fatal("invalid fixture deployment duration")
		}
	}
	runtime.testRunner = release61ComponentRunner(t, runtime, store, server)
	if token := os.Getenv("ZASP_RELEASE61_WORKER_TOKEN"); token != "" {
		runtime.planning.LeaseToken = token
	}
	if token := os.Getenv("ZASP_RELEASE61_DELIVERY_TOKEN"); token != "" {
		runtime.deploymentLeaseToken = token
	}
	got, err := runtime.Tick(ctx)
	want := os.Getenv("ZASP_RELEASE61_EXPECT")
	ackLost := os.Getenv("ZASP_RELEASE61_ACK_FAULT") != ""
	if ackLost {
		if err == nil || !(worker.fired || action.fired || deployment.fired || red.fired) {
			t.Fatal("post-commit fault did not interrupt worker")
		}
		got = want
	} else if os.Getenv("ZASP_RELEASE61_ARTIFACT_FAULT") != "" {
		if err == nil || !driver.fired {
			t.Fatal("artifact fault not reached", driver.fired, err)
		}
		got = want
	} else if os.Getenv("ZASP_RELEASE61_PROVIDER_UNKNOWN") == "1" || os.Getenv("ZASP_RELEASE61_JOURNAL_FAULT") != "" || os.Getenv("ZASP_RELEASE61_FOREIGN_ORG") != "" || os.Getenv("ZASP_RELEASE61_EXPECT_REFUSAL") == "1" {
		if err == nil {
			t.Fatal("unknown provider outcome succeeded")
		}
		got = want
	} else if err != nil || got != want {
		t.Fatal("dormant release61 tick absent or unsafe", got, want, err)
	}
	wantCalls := int32(0)
	if want == "planning_result" || want == "planning_result_unknown" {
		wantCalls = 1
	}
	if calls.Load() != wantCalls {
		t.Fatal("provider duplicated across commit restart", calls.Load(), wantCalls)
	}
	if worker.stale && !worker.fired {
		t.Fatal("mixed binary did not reach exact release readiness")
	}
	t.Logf("release61 tick joined: %s provider_calls=%d component-only TLS", got, calls.Load())
}

type release61TLSTransport struct {
	base   http.RoundTripper
	target *url.URL
}

type release61WorkerPG struct {
	orderedPricingWorkerPG
	t     *testing.T
	fired bool
	stale bool
}

func (d *release61WorkerPG) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if d.stale && strings.Contains(q, ".orchestration_ready(") && len(args) == 3 {
		args = append([]any(nil), args...)
		args[1] = strings.Repeat("0", 64)
		d.fired = true
	}
	raw, err := d.orderedPricingWorkerPG.QueryJSON(ctx, q, args...)
	if pg, ok := err.(*pgconn.PgError); ok {
		d.t.Logf("component SQL diagnostic: %s %s", pg.Code, pg.Message)
	}
	if err == nil && !d.fired && release61CommitLabel(q, args) == os.Getenv("ZASP_RELEASE61_ACK_FAULT") && os.Getenv("ZASP_RELEASE61_ACK_FAULT") != "" {
		d.fired = true
		d.t.Log("component fault after durable commit:", release61CommitLabel(q, args))
		return nil, errWorkerExecution
	}
	return raw, err
}

func release61CommitLabel(q string, args []any) string {
	if strings.Contains(q, ".test_dispatch(") {
		return "test_dispatch"
	}
	if strings.Contains(q, ".test_settle(") {
		return "test_settle"
	}
	if len(args) != 3 {
		return ""
	}
	raw, ok := args[2].(json.RawMessage)
	if !ok {
		if bytes, yes := args[2].([]byte); yes {
			raw = json.RawMessage(bytes)
		} else {
			return ""
		}
	}
	var request struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(raw, &request) != nil {
		return ""
	}
	for _, entry := range []struct{ sql, prefix string }{{".planning(", "planning_"}, {".application(", "application_"}, {".cleanup_deployment(", "cleanup_deployment_"}, {".deployment(", "deployment_"}, {".cleanup(", "cleanup_"}, {".test_action(", "test_"}} {
		if strings.Contains(q, entry.sql) {
			return entry.prefix + request.Operation
		}
	}
	if strings.Contains(q, ".transition(") && request.Operation == "progress" {
		return "successor_ready"
	}
	return ""
}

func (d *release61WorkerPG) SchemaVersion(context.Context) (string, error) {
	return "", errWorkerExecution
}

func (d *release61WorkerPG) Exec(ctx context.Context, q string, args ...any) error {
	_, err := d.conn.Exec(ctx, q, args...)
	return err
}

func (t *release61TLSTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	u := *r.URL
	u.Scheme, u.Host = t.target.Scheme, t.target.Host
	copy.URL = &u
	return t.base.RoundTrip(copy)
}
