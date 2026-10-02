package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/exportfixture"
)

// The shared provider fixture omits the typed export arguments and selects an
// evidence digest as the target. The production parser must receive a bounded
// export candidate for the actual parent and its retained manual selection.
func TestSecurityAgentExportBrowserPlannerSelection(t *testing.T) {
	p, calls, closePlanner, err := newExportBrowserPlanner()
	if err != nil {
		t.Fatal(err)
	}
	defer closePlanner()
	c := testSecurityAgentPlannerContext()
	c.AllowedActions = []string{"create_evidence_export"}
	c.AllowedTargets = []string{c.RunID}
	c.ManualTrigger = &apiserver.SecurityAgentManualTrigger{Kind: "manual", IntentDigest: "sha256:" + strings.Repeat("a", 64), Version: 1}
	c.Evidence = []securityAgentPlannerEvidence{{ID: strings.Repeat("a", 64), Kind: "manual", Version: 1, Summary: "Original manual intent"}}
	c.ExportSelection = []apiserver.SecurityAgentExportSelection{{Kind: "manual", ID: strings.Repeat("a", 64), Version: 1, AssociationDigest: "sha256:" + strings.Repeat("b", 64)}}
	result := p.Plan(context.Background(), c)
	if result.Failure != "" || len(result.Candidate.Steps) != 1 || result.Candidate.Steps[0].TargetID != "pid_70000004-0000-4000-8000-000000000004" || len(result.Candidate.Steps[0].EvidenceIDs) != 1 || result.Candidate.Steps[0].EvidenceIDs[0] != c.ExportSelection[0] || calls() != 1 {
		t.Fatalf("public manual export candidate rejected or changed: result=%+v calls=%d", result, calls())
	}
	if result.Usage == nil || result.Usage.TotalTokens != 160 || result.Usage.CostNanoCredits != 100 {
		t.Fatalf("missing bounded accounting: %+v", result.Usage)
	}
}

func TestSecurityAgentExportBrowserEnvironment(t *testing.T) {
	now := time.Now().UTC()
	valid := map[string]string{"WORKER": "true", "PG_PORT": "15432", "WORKER_PORT": "18081", "DSN": "postgres://zasp_e2e_security_agent_worker@127.0.0.1:15432/postgres?sslmode=disable", "DEADLINE": now.Add(time.Minute).Format(time.RFC3339Nano), "OBJECT": "/private/tmp/zasp-production-e2e-owned/export-store"}
	for _, tc := range []struct{ name, key, value string }{
		{"valid", "", ""}, {"opt in", "WORKER", "false"}, {"external database", "DSN", "postgres://zasp_e2e_security_agent_worker@external.test:15432/postgres?sslmode=disable"}, {"owner database", "DSN", "postgres://zasp_e2e@127.0.0.1:15432/postgres?sslmode=disable"}, {"password", "DSN", "postgres" + "://zasp_e2e_security_agent_worker:secret@127.0.0.1:15432/postgres?sslmode=disable"}, {"port mismatch", "PG_PORT", "15433"}, {"privileged port", "WORKER_PORT", "80"}, {"same port", "WORKER_PORT", "15432"}, {"port alias", "WORKER_PORT", "018081"}, {"expired", "DEADLINE", now.Add(-time.Second).Format(time.RFC3339Nano)}, {"unbounded", "DEADLINE", now.Add(31 * time.Minute).Format(time.RFC3339Nano)}, {"relative path", "OBJECT", "export-store"}, {"unowned root", "OBJECT", "/private/tmp/shared/export-store"}, {"unclean", "OBJECT", "/private/tmp/zasp-production-e2e-owned/../export-store"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := make(map[string]string)
			for k, v := range valid {
				env[k] = v
			}
			if tc.key != "" {
				env[tc.key] = tc.value
			}
			_, err := parseExportBrowserWorkerEnvironment(func(k string) string { return env[strings.TrimPrefix(k, "ZASP_SA_EXPORT_BROWSER_")] }, now)
			if (err == nil) != (tc.name == "valid") {
				t.Fatalf("environment acceptance=%v", err)
			}
		})
	}
}
func TestSecurityAgentExportBrowserPhaseRouting(t *testing.T) {
	var invoked []string
	op := func(name string) func(context.Context) error {
		return func(ctx context.Context) error {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("unbounded operation")
			}
			invoked = append(invoked, name)
			return nil
		}
	}
	ready := map[string]func(context.Context) error{"agentsec-security-agent:8081": op("agent ready"), "agentsec-security-agent-action:8081": op("action ready"), "zasp-compliance-export-worker:8081": op("writer ready"), "zasp-compliance-cleanup-worker:8081": op("cleanup ready")}
	phases := map[string]func(context.Context) error{"/plan": op("plan"), "/dispatch": op("dispatch"), "/capture": op("capture"), "/settle": op("settle"), "/cleanup": op("cleanup")}
	h := exportBrowserControlHandler(context.Background(), "127.0.0.1:18081", ready, phases)
	for host := range ready {
		r := httptest.NewRequest("GET", "http://"+host+"/readyz", nil)
		r.RemoteAddr = "127.0.0.1:30001"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("readiness %s status=%d", host, w.Code)
		}
		if w.Header().Get("Content-Type") != "application/json; charset=utf-8" || w.Body.String() != "{\"status\":\"ready\"}\n" {
			t.Fatalf("API workflow readiness rejects response: %v %q", w.Header(), w.Body.String())
		}
	}
	for path := range phases {
		r := httptest.NewRequest("POST", "http://127.0.0.1:18081"+path, nil)
		r.RemoteAddr = "127.0.0.1:30001"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("phase %s status=%d", path, w.Code)
		}
	}
	if len(invoked) != 9 {
		t.Fatalf("actual callbacks=%v", invoked)
	}
	for _, target := range []string{"http://unknown.invalid/readyz", "http://127.0.0.1:18081/plan?run=foreign", "http://127.0.0.1:18081/unknown"} {
		r := httptest.NewRequest("POST", target, nil)
		r.RemoteAddr = "127.0.0.1:30001"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatalf("foreign control accepted: %s", target)
		}
	}
	if len(invoked) != 9 {
		t.Fatal("refused request invoked product operation")
	}
}

type exportBrowserWorkerEnvironment struct {
	dsn, pgPort, port, object string
	deadline                  time.Time
}

func parseExportBrowserWorkerEnvironment(get func(string) string, now time.Time) (exportBrowserWorkerEnvironment, error) {
	bad := func() (exportBrowserWorkerEnvironment, error) {
		return exportBrowserWorkerEnvironment{}, fmt.Errorf("owned export worker environment rejected")
	}
	if get("ZASP_SA_EXPORT_BROWSER_WORKER") != "true" {
		return bad()
	}
	prefix := "ZASP_SA_EXPORT_BROWSER_"
	c := exportBrowserWorkerEnvironment{dsn: get(prefix + "DSN"), pgPort: get(prefix + "PG_PORT"), port: get(prefix + "WORKER_PORT"), object: get(prefix + "OBJECT")}
	for _, port := range []string{c.pgPort, c.port} {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1024 || n > 65535 || strconv.Itoa(n) != port {
			return bad()
		}
	}
	if c.port == c.pgPort {
		return bad()
	}
	u, err := url.Parse(c.dsn)
	if err != nil || u.Scheme != "postgres" || u.Host != "127.0.0.1:"+c.pgPort || u.User == nil || u.User.String() != "zasp_e2e_security_agent_worker" || u.Path != "/postgres" || u.RawPath != "" || u.RawQuery != "sslmode=disable" || u.Fragment != "" || u.Opaque != "" {
		return bad()
	}
	c.deadline, err = time.Parse(time.RFC3339Nano, get(prefix+"DEADLINE"))
	if err != nil || !c.deadline.After(now.Add(time.Second)) || c.deadline.After(now.Add(30*time.Minute)) {
		return bad()
	}
	if !filepath.IsAbs(c.object) || filepath.Clean(c.object) != c.object || filepath.Base(c.object) != "export-store" || !strings.HasPrefix(filepath.Base(filepath.Dir(c.object)), "zasp-production-e2e-") || filepath.Base(filepath.Dir(c.object)) == "zasp-production-e2e-" {
		return bad()
	}
	return c, nil
}
func exportBrowserControlHandler(ctx context.Context, host string, checks, phases map[string]func(context.Context) error) http.Handler {
	gate := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(remote) == nil || !net.ParseIP(remote).IsLoopback() || r.URL.RawQuery != "" || r.ContentLength != 0 || r.TransferEncoding != nil {
			http.Error(w, "control refused", 400)
			return
		}
		var operation func(context.Context) error
		if r.Method == "GET" && r.URL.Path == "/readyz" {
			operation = checks[r.Host]
			if r.Host == host {
				operation = func(c context.Context) error {
					for _, key := range []string{"agentsec-security-agent:8081", "agentsec-security-agent-action:8081", "zasp-compliance-export-worker:8081", "zasp-compliance-cleanup-worker:8081"} {
						check := checks[key]
						if check == nil {
							return errRuntimeUnavailable
						}
						if err := check(c); err != nil {
							return err
						}
					}
					return nil
				}
			}
		} else if r.Method == "POST" && r.Host == host {
			operation = phases[r.URL.Path]
		}
		if operation == nil {
			http.NotFound(w, r)
			return
		}
		work, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		case <-work.Done():
			http.Error(w, "control unavailable", 503)
			return
		}
		if ctx.Err() != nil || work.Err() != nil || operation(work) != nil || work.Err() != nil {
			http.Error(w, "control unavailable", 503)
			return
		}
		if r.URL.Path == "/readyz" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = io.WriteString(w, "{\"status\":\"ready\"}\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "phase": r.URL.Path})
	})
}

func TestSecurityAgentExportBrowserPlannerRuntime(t *testing.T) {
	now := time.Now().UTC()
	claim := securityAgentTestClaim("pid_70000004-0000-4000-8000-000000000004", false, now)
	claim.TriggerID = strings.Repeat("a", 64)
	claim.ManualTrigger = &apiserver.SecurityAgentManualTrigger{Kind: "manual", IntentDigest: "sha256:" + claim.TriggerID, Version: 1}
	selection := `[{"source_kind":"manual","source_id":"` + strings.Repeat("a", 64) + `","source_version":1,"association_digest":"sha256:` + strings.Repeat("b", 64) + `"}]`
	a := &exportPlannerRuntimeAuthority{securityAgentWorkerAuthorityStub: &securityAgentWorkerAuthorityStub{claims: []apiserver.SecurityAgentRunClaim{claim}}, selection: json.RawMessage(selection)}
	planner, calls, closePlanner, err := newExportBrowserPlanner()
	if err != nil {
		t.Fatal(err)
	}
	defer closePlanner()
	ids := 0
	p, err := newSecurityAgentProcessor(securityAgentProcessorConfig{Authority: a, Planner: &budgetFixturePlanner{planner}, WorkerID: "export-browser-test", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 20 * time.Second, Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "export-browser-test-lease", nil }, NewProductID: func() (string, error) { ids++; return fmt.Sprintf("pid_78000010-0000-4000-8000-%012d", ids), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.RunOnce(context.Background()); err != nil {
		t.Fatalf("actual processor rejected export: %v", err)
	}
	var submission apiserver.SecurityAgentPlannerSubmission
	if json.Unmarshal(a.submitted, &submission) != nil || submission.TargetID != claim.RunID || submission.Action != "create_evidence_export" || len(submission.EvidenceIDs) != 1 || submission.EvidenceIDs[0].ID != claim.TriggerID || len(a.prepared) != 1 || len(a.executed) != 0 || len(a.failedPlanner) != 0 || calls() != 1 {
		t.Fatalf("runtime export admission changed: %s calls=%d", a.submitted, calls())
	}
}

func TestSecurityAgentExportBrowserControlRefusals(t *testing.T) {
	for _, scenario := range []string{"health failure", "aggregate", "unknown health", "remote", "body", "phase failure", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			op := func(work context.Context) error {
				calls++
				if scenario == "health failure" || scenario == "phase failure" {
					return fmt.Errorf("private database detail")
				}
				return nil
			}
			checks := map[string]func(context.Context) error{}
			for _, host := range []string{"agentsec-security-agent:8081", "agentsec-security-agent-action:8081", "zasp-compliance-export-worker:8081", "zasp-compliance-cleanup-worker:8081"} {
				checks[host] = op
			}
			h := exportBrowserControlHandler(ctx, "127.0.0.1:18081", checks, map[string]func(context.Context) error{"/plan": op})
			method, target, remote, body := "POST", "http://127.0.0.1:18081/plan", "127.0.0.1:30001", ""
			want, wantCalls := 503, 1
			switch scenario {
			case "health failure":
				method, target = "GET", "http://agentsec-security-agent:8081/readyz"
			case "aggregate":
				method, target, want, wantCalls = "GET", "http://127.0.0.1:18081/readyz", 200, 4
			case "unknown health":
				method, target, want, wantCalls = "GET", "http://unknown.invalid/readyz", 404, 0
			case "remote":
				remote, want, wantCalls = "192.0.2.1:30001", 400, 0
			case "body":
				body, want, wantCalls = "{}", 400, 0
			case "cancelled":
				cancel()
				wantCalls = 0
			}
			r := httptest.NewRequest(method, target, strings.NewReader(body))
			r.RemoteAddr = remote
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || calls != wantCalls || strings.Contains(w.Body.String(), "private database") {
				t.Fatalf("refusal status=%d calls=%d body=%q", w.Code, calls, w.Body.String())
			}
		})
	}
}

// This transport replaces only the provider boundary. Production request
// preparation, response parsing, validation and budget settlement stay active.
type exportBrowserPlannerTransport struct{ calls atomic.Int64 }

func (p *exportBrowserPlannerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Context().Err() != nil {
		return nil, r.Context().Err()
	}
	if _, ok := r.Context().Deadline(); !ok {
		return nil, fmt.Errorf("planner deadline required")
	}
	if r.Method != "POST" || r.URL.String() != "https://openrouter.ai/api/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer sk-or-v1-export-browser-test-token" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-Zasp-Data-Policy") != "security-agent-planner-v1" {
		return nil, fmt.Errorf("planner request rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	if err != nil || len(raw) > 64*1024 {
		return nil, fmt.Errorf("planner input bounds")
	}
	var req securityAgentOpenRouterRequest
	if json.Unmarshal(raw, &req) != nil || len(req.Messages) != 2 || req.Messages[1].Role != "user" || req.Model != "openai/gpt-5-mini" || req.MaximumTokens != 512 || req.Provider.DataCollection != "deny" || !req.Provider.RequireParameters {
		return nil, fmt.Errorf("planner wire rejected")
	}
	var c struct {
		Scope          map[string]string                        `json:"scope"`
		AllowedActions []string                                 `json:"allowed_actions"`
		AllowedTargets []string                                 `json:"allowed_targets"`
		MaximumSteps   int                                      `json:"maximum_steps"`
		Selection      []apiserver.SecurityAgentExportSelection `json:"export_selection"`
	}
	if json.Unmarshal([]byte(req.Messages[1].Content), &c) != nil || c.MaximumSteps != 1 || !slices.Equal(c.AllowedActions, []string{"create_evidence_export"}) || !validSecurityAgentPlannerProductID(c.Scope["run_id"]) || !slices.Equal(c.AllowedTargets, []string{c.Scope["run_id"]}) || !validSecurityAgentPlannerExportSelection(c.Selection) {
		return nil, fmt.Errorf("export planner context rejected")
	}
	candidate, err := json.Marshal(securityAgentPlannerCandidate{Version: 1, Summary: "Export selected original run evidence", Steps: []securityAgentPlannerStep{{Index: 0, Action: "create_evidence_export", TargetID: c.Scope["run_id"], EvidenceIDs: slices.Clone(c.Selection)}}})
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if err = json.Unmarshal(openRouterPlannerResponse(string(candidate)), &envelope); err != nil {
		return nil, err
	}
	envelope["usage"] = json.RawMessage(`{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"cost":0.0000001}`)
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	p.calls.Add(1)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
}
func newExportBrowserPlanner() (*productionSecurityAgentPlanner, func() int, func(), error) {
	transport := &exportBrowserPlannerTransport{}
	planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-export-browser-test-token"), Timeout: 5 * time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport})
	if err != nil {
		return nil, nil, nil, err
	}
	return planner, func() int { return int(transport.calls.Load()) }, func() { _ = planner.Close() }, nil
}

// Only the owning browser harness launches this entry. SQL authority and all
// four runtime compositions are real; identity/model/object providers are local.
func TestSecurityAgentExportBrowserWorkerProcess(t *testing.T) {
	if os.Getenv("ZASP_SA_EXPORT_BROWSER_WORKER") == "" {
		t.Skip("owned export browser parent launches child")
	}
	c, err := parseExportBrowserWorkerEnvironment(os.Getenv, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(ctx, c.deadline)
	defer cancel()
	storeConfig := exportfixture.Config{Directory: c.object, Bucket: "zasp-compliance-exports", Owner: "123456789012", KMSKey: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20}
	var store *exportfixture.Store
	if _, err = os.Lstat(c.object); errors.Is(err, os.ErrNotExist) {
		store, err = exportfixture.Create(storeConfig)
	} else if err == nil {
		store, err = exportfixture.Open(storeConfig)
	}
	if err != nil {
		t.Fatal("owned object store unavailable")
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error("object store close failed")
		}
	}()
	database := func(login string) apiserver.JSONDatabase {
		u, _ := url.Parse(c.dsn)
		u.User = url.User(login)
		return combinedE2ERecoveryDatabase(t, ctx, u.String())
	}
	planner, _, closePlanner, err := newExportBrowserPlanner()
	if err != nil {
		t.Fatal(err)
	}
	defer closePlanner()
	agentConfig := validSecurityAgentRuntimeConfig()
	agentConfig.PostgresDSN = c.dsn
	agentConfig.BatchSize = 1
	agent, err := composeSecurityAgentWorkerRuntime(agentConfig, database("zasp_e2e_security_agent_worker"), &budgetFixturePlanner{planner})
	if err != nil {
		t.Fatal("agent composition unavailable")
	}
	defer agent.Close()
	actionConfig := validSecurityAgentActionRuntimeConfig()
	u, _ := url.Parse(c.dsn)
	u.User = url.User("zasp_e2e_security_agent_action")
	actionConfig.PostgresDSN = u.String()
	actionConfig.BatchSize = 1
	action, err := composeSecurityAgentActionWorkerRuntime(actionConfig, database("zasp_e2e_security_agent_action"), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x58}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal("action composition unavailable")
	}
	defer action.Close()
	compliance := func(cleanup bool) workerRuntimeDependencies {
		env := complianceRuntimeEnvironment()
		role, login := "compliance-export-worker", "compliance_executor"
		if cleanup {
			role, login = "compliance-export-cleanup", "compliance_cleanup"
			env["ZASP_WORKER_MODE"] = "compliance-export-cleanup"
			env["ZASP_DATABASE_AUTHORITY"] = "zasp_compliance_cleanup"
			env["ZASP_WORKER_ID"] = "export-browser-cleanup"
		}
		env["ZASP_BATCH_SIZE"] = "1"
		env["ZASP_POSTGRES_DSN"] = "postgres://" + login + "@postgres.internal/zasp?sslmode=verify-full"
		env["ZASP_COMPLIANCE_EXPORT_ROLE_ARN"] = "arn:aws:iam::123456789012:role/" + role
		env["ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"] = storeConfig.KMSKey
		cfg, err := loadWorkerRuntimeConfig(mapLookup(env))
		if err != nil {
			t.Fatal("compliance config unavailable")
		}
		provider := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{}, HTTPClient: &http.Client{Timeout: 5 * time.Second, Transport: store.Transport(exportfixture.Options{}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
		clients := &complianceExportProductionClients{transport: &http.Transport{}, identity: &runtimeIdentityStub{account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/" + role + "/zasp-" + string(cfg.Mode)}, credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture", SessionToken: "fixture", CanExpire: true, Expires: time.Now().Add(time.Hour)}, nil
		})}
		if cleanup {
			clients.reader = provider
			clients.cleanup = provider
		} else {
			clients.writer = provider
		}
		runtime, err := composeComplianceExportWorkerRuntime(ctx, cfg, database(login), clients)
		if err != nil {
			t.Fatal("compliance composition unavailable")
		}
		return runtime
	}
	writer := compliance(false)
	defer writer.Close()
	cleanup := compliance(true)
	defer cleanup.Close()
	checks := map[string]func(context.Context) error{"agentsec-security-agent:8081": agent.Ready, "agentsec-security-agent-action:8081": action.Ready, "zasp-compliance-export-worker:8081": writer.Ready, "zasp-compliance-cleanup-worker:8081": cleanup.Ready}
	phases := map[string]func(context.Context) error{"/plan": agent.Processor.RunOnce, "/dispatch": agent.Processor.RunOnce, "/capture": writer.Processor.RunOnce, "/settle": agent.Processor.RunOnce, "/cleanup": cleanup.Processor.RunOnce}
	host := "127.0.0.1:" + c.port
	listener, err := net.Listen("tcp4", host)
	if err != nil {
		t.Fatal("owned worker listener unavailable")
	}
	server := &http.Server{Handler: exportBrowserControlHandler(ctx, host, checks, phases), ReadHeaderTimeout: time.Second, ReadTimeout: 12 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Error("worker listener stopped unexpectedly")
		}
		return
	}
	shutdown, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
		t.Error("worker shutdown timeout")
	}
	if err := <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Error("worker listener join failed")
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Error("worker parent deadline exceeded")
	}
	t.Log("owned export browser worker joined; controlled providers, persisted object store retained")
}
