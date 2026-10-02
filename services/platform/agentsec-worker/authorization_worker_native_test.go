package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

type workerNativeCountingChecker struct {
	delegate authorization.Checker
	calls    int
}

type workerNativeFGATransport struct {
	base        http.RoundTripper
	unavailable atomic.Bool
}

func (t *workerNativeFGATransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.unavailable.Load() && strings.HasSuffix(r.URL.Path, "/check") {
		return nil, errors.New("owned check transport unavailable")
	}
	return t.base.RoundTrip(r)
}

func TestWorkerAuthorizationRuntimeKeyConfiguration(t *testing.T) {
	cfg := validSecurityAgentRuntimeConfig()
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "owned", TaskQueue: "owned-agent", DiscoveryTaskQueue: "owned-discovery", FGAURL: "http://127.0.0.1:8088", StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: "/fixture/token", Timeout: time.Second}
	cfg.WorkerAuthorizationKeyFile = "/fixture/forward"
	cfg.CompensationAuthorizationKeyFile = "/fixture/compensation"
	if !validWorkerRuntimeConfig(cfg) {
		t.Fatal("complete worker key configuration rejected")
	}
	for _, change := range []func(*workerRuntimeConfig){func(c *workerRuntimeConfig) { c.WorkerAuthorizationKeyFile = "" }, func(c *workerRuntimeConfig) { c.CompensationAuthorizationKeyFile = "" }, func(c *workerRuntimeConfig) { c.WorkerAuthorizationKeyFile = c.CompensationAuthorizationKeyFile }, func(c *workerRuntimeConfig) { c.WorkerAuthorizationKeyFile = "relative" }, func(c *workerRuntimeConfig) { c.RuntimeServices = runtimeservices.Config{} }} {
		changed := cfg
		change(&changed)
		if validWorkerRuntimeConfig(changed) {
			t.Fatal("partial worker key configuration accepted")
		}
	}
}

func (c *workerNativeCountingChecker) Check(ctx context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
	c.calls++
	return c.delegate.Check(ctx, q)
}

// Spawned only by the owning PostgreSQL/FGA fixture. This consumes the actual
// Activity product and the same pool/key binder used by runtime composition.
func TestP7FindingProductMachineNative(t *testing.T) {
	runWorkerProductMachineNative(t, false)
}

func TestP7Test74ProductMachineNative(t *testing.T) {
	runWorkerProductMachineNative(t, true)
}

func runWorkerProductMachineNative(t *testing.T, test74 bool) {
	t.Helper()
	dsn := os.Getenv("ZASP_P7_WORKER_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned parent fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var config runtimeservices.Config
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_WORKER_FGA_CONFIG")), &config) != nil || config.FGAURL != "http://127.0.0.1:8088" {
		t.Fatal("owned FGA configuration required")
	}
	var request struct {
		OrganizationID string `json:"organization_id"`
		WorkspaceID    string `json:"workspace_id"`
		EnvironmentID  string `json:"environment_id"`
		RunID          string `json:"run_id"`
		Version        int64  `json:"definition_version"`
		Digest         string `json:"input_digest"`
	}
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_WORKER_REQUEST")), &request) != nil {
		t.Fatal("owned request required")
	}
	start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID, RunID: request.RunID}, DefinitionVersion: request.Version, InputDigest: request.Digest}
	var pools []*pgxpool.Pool
	var databases []apiserver.JSONDatabase
	principals := []string{"finding78_executor", "finding78_compensation"}
	if test74 {
		principals = []string{"worker_test_executor", "worker_test_compensation"}
	}
	for _, principal := range principals {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil || net.ParseIP(cfg.ConnConfig.Host) == nil || !net.ParseIP(cfg.ConnConfig.Host).IsLoopback() {
			t.Fatal("owned loopback database required")
		}
		cfg.ConnConfig.User = principal
		cfg.MaxConns = 2
		if strings.HasSuffix(os.Getenv("ZASP_P7_WORKER_PHASE"), "-timezone") {
			cfg.ConnConfig.Tracer = plannerTimezoneTracer(t, cfg.ConnConfig.Tracer)
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal("fixture pool")
		}
		defer pool.Close()
		pools = append(pools, pool)
		db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
		if err != nil {
			t.Fatal(err)
		}
		databases = append(databases, db)
	}
	data, err := exec.CommandContext(ctx, "docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		t.Fatal("owned FGA service unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		t.Fatal("owned FGA configuration unavailable")
	}
	token := ""
	for _, entry := range containers[0].Config.Env {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		t.Fatal("owned FGA credential unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	fgaTransport := &workerNativeFGATransport{base: transport}
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: config.FGAURL, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: fgaTransport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal("official SDK unavailable")
	}
	checker, err := authorization.NewOpenFGA(client, config)
	if err != nil {
		t.Fatal(err)
	}
	observed := &workerNativeCountingChecker{delegate: checker}
	dir := t.TempDir()
	write := func(name string, seed byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, bytes.Repeat([]byte{seed}, 32), 0o400); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg := workerRuntimeConfig{RuntimeServices: config, WorkerAuthorizationKeyFile: write("forward", 42), CompensationAuthorizationKeyFile: write("compensation", 73)}
	phase := os.Getenv("ZASP_P7_WORKER_PHASE")
	if phase == "replay" {
		cfg.CompensationAuthorizationKeyFile = write("rotated-compensation", 74)
	}
	product := &temporalSecurityAgentProduct{executor: databases[0], compensation: databases[1]}
	if workerProductionProfileReady(ctx, pools[0]) == nil {
		t.Fatal("partial worker profile accepted for production runtime")
	}
	for _, invalid := range []workerRuntimeConfig{{RuntimeServices: config}, {RuntimeServices: config, WorkerAuthorizationKeyFile: cfg.WorkerAuthorizationKeyFile, CompensationAuthorizationKeyFile: cfg.WorkerAuthorizationKeyFile}, {RuntimeServices: config, WorkerAuthorizationKeyFile: write("wrong-forward", 99), CompensationAuthorizationKeyFile: cfg.CompensationAuthorizationKeyFile}} {
		if err := bindTemporalWorkerAuthorization(ctx, invalid, observed, product, pools); err == nil {
			t.Fatal("installed worker profile accepted missing/mismatched keys")
		}
	}
	if err := bindTemporalWorkerAuthorization(ctx, cfg, observed, product, pools); err != nil {
		t.Fatal("actual product authority binder", err)
	}
	if strings.HasPrefix(phase, "planning") || test74 {
		writer, err := authorization.NewOpenFGATupleWriter(client, config)
		if err != nil {
			t.Fatal(err)
		}
		if test74 {
			assertWorkerTest74ProductPlanning(t, ctx, dsn, config, writer, product, start, strings.TrimPrefix(phase, "test74-"), fgaTransport)
		} else {
			assertWorkerFindingProductPlanning(t, ctx, dsn, config, writer, product, start, phase, fgaTransport)
		}
		return
	}
	if err := product.FindingResponseProduct().Apply(ctx, start); err != nil {
		t.Fatal("actual product finding apply/replay", err)
	}
	if phase == "apply" && observed.calls != 6 || phase == "replay" && observed.calls != 0 {
		t.Fatal("product used wrong fresh/replay authority path", observed.calls)
	}
	if phase == "replay" {
		if err := product.FindingResponseProduct().Cleanup(ctx, orchestration.CleanupRequest{Start: start, Reason: "terminal"}); err != nil {
			t.Fatal("actual product captured cleanup", err)
		}
		if observed.calls != 0 {
			t.Fatal("captured cleanup requested forward authority")
		}
	}
	if err := product.Apply(ctx, start); err == nil {
		t.Fatal("unimplemented worker family used legacy forward path")
	}
}
