package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/multisteppricing"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func orderedRequestBindingPlanner(t *testing.T, transport http.RoundTripper) *productionSecurityAgentPlanner {
	t.Helper()
	planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = planner.Close() })
	return planner
}

func orderedBindingResponseTransport() *securityAgentPlannerTransport {
	return &securityAgentPlannerTransport{responseStatus: http.StatusOK, responseBody: openRouterPlannerResponse(orderedCandidateJSON)}
}

func orderedPreparedPlanFixture(ctx context.Context, planner *productionSecurityAgentPlanner, value securityAgentOrderedPlannerContext) (*securityAgentOrderedPreparedPlan, error) {
	if ctx == nil || ctx.Err() != nil || planner == nil || !validSecurityAgentOrderedContext(securityAgentOrderedContext{Context: value, Autonomy: "supervised", BudgetMaximumSteps: 2, DefinitionVersion: 3, Attempt: 1}) {
		return nil, errWorkerExecution
	}
	planner.mu.RLock()
	defer planner.mu.RUnlock()
	if planner.closed || planner.client == nil {
		return nil, errWorkerExecution
	}
	body, err := json.Marshal(map[string]any{
		"model": planner.model, "max_tokens": planner.maximumTokens,
		"messages":        []map[string]string{{"role": "system", "content": "Return only the ordered release61 plan."}, {"role": "user", "content": "Use only the trusted targets."}},
		"provider":        map[string]any{"data_collection": "deny", "require_parameters": true},
		"response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "security_response_plan", "strict": true, "schema": map[string]any{"type": "object"}}},
	})
	if err != nil {
		return nil, errWorkerExecution
	}
	return &securityAgentOrderedPreparedPlan{planner: planner, preparationContext: ctx, contextValue: cloneSecurityAgentOrderedPlannerContext(value), body: string(body), client: planner.client, identity: securityAgentOrderedRequestIdentity{BodyDigest: orderedPlanningDigest(body), Model: planner.model, Endpoint: planner.endpoint, PolicyVersion: planner.policyVersion, MaximumTokens: planner.maximumTokens}}, nil
}

// Dropping raw bytes, bypassing retained credentials, or allowing a second send
// must fail against the actual production HTTP request boundary.
func TestSecurityAgentMultistepPlanningRawTransport(t *testing.T) {
	for _, mode := range []string{"exact", "credential", "cancel", "consumed", "oversize", "invalid_utf8"} {
		t.Run(mode, func(t *testing.T) {
			transport := orderedBindingResponseTransport()
			planner := orderedRequestBindingPlanner(t, transport)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prepared, err := orderedPreparedPlanFixture(ctx, planner, orderedContextFixture().Context)
			if err != nil {
				t.Fatal(err)
			}
			credential, ok := orderedPreparedCredential(prepared)
			if !ok {
				t.Fatal("credential binding")
			}
			want := bytes.Clone(transport.responseBody)
			switch mode {
			case "credential":
				credential = "sha256:" + strings.Repeat("0", 64)
			case "cancel":
				cancel()
			case "consumed":
				prepared.consumed.Store(true)
			case "oversize":
				transport.responseBody = []byte(strings.Repeat("x", 65537))
			case "invalid_utf8":
				transport.responseBody = []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
			}
			raw, err := sendSecurityAgentOrdered(ctx, prepared, credential)
			if mode == "exact" {
				if err != nil || !bytes.Equal(raw, want) {
					t.Fatal("lost raw response", err)
				}
			} else if err == nil || len(raw) != 0 {
				t.Fatal("unsafe provider dispatch result", mode, err)
			}
			if again, err := sendSecurityAgentOrdered(ctx, prepared, credential); err == nil || len(again) != 0 {
				t.Fatal("provider uncertainty resent")
			}
			wantCalls := 0
			if mode == "exact" || mode == "oversize" || mode == "invalid_utf8" {
				wantCalls = 1
			}
			if transport.calls != wantCalls {
				t.Fatal("unexpected outbound calls", transport.calls)
			}
			if err != nil && !errors.Is(err, errWorkerExecution) {
				t.Fatal("unredacted boundary error", err)
			}
		})
	}
}

// Passing an unbounded caller through to QueryJSON permits an indefinite
// database lock wait before even obtaining a planning lease.
func TestSecurityAgentMultistepPlanningSQLDeadline(t *testing.T) {
	for _, mode := range []string{"background", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			db := &orderedPlanningBlockingDB{entered: make(chan context.Context, 1), release: make(chan struct{})}
			store, err := artifactstore.New(&orderedFileArtifactDriver{directory: t.TempDir(), t: t}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 524288})
			if err != nil {
				t.Fatal(err)
			}
			planner := orderedRequestBindingPlanner(t, orderedBindingResponseTransport())
			done := make(chan error, 1)
			go func() {
				_, err := runSecurityAgentOrderedPlanning(parent, orderedPlanningConfig{Database: db, Store: store, Planner: planner, RunID: testSecurityAgentPlannerContext().RunID})
				done <- err
			}()
			defer close(db.release)
			var queryContext context.Context
			select {
			case queryContext = <-db.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not enter SQL boundary")
			}
			deadline, bounded := queryContext.Deadline()
			if !bounded || deadline.After(time.Now().Add(30*time.Second)) {
				t.Error("private planning SQL has no finite 30-second bound")
			}
			if mode == "cancel" {
				cancel()
			} else {
				db.release <- struct{}{}
			}
			select {
			case err := <-done:
				if err == nil {
					t.Error("SQL failure was accepted")
				}
			case <-time.After(5 * time.Second):
				cancel()
				t.Fatal("SQL cancellation did not join worker")
			}
			if queryContext.Err() == nil {
				t.Error("SQL child context retained after return")
			}
			if mode == "background" && parent.Err() != nil {
				t.Error("SQL call canceled caller")
			}
		})
	}
}

type orderedPlanningBlockingDB struct {
	entered chan context.Context
	release chan struct{}
}

func TestSecurityAgentMultistepPlanningSQLDeadlineClamp(t *testing.T) {
	for _, mode := range []string{"cap", "lease", "caller", "expired"} {
		t.Run(mode, func(t *testing.T) {
			parent := context.Background()
			now := time.Now()
			lease := now.Add(time.Hour)
			latest := now.Add(30*time.Second + time.Second)
			switch mode {
			case "lease":
				lease = now.Add(time.Second)
				latest = lease
			case "caller":
				var cancel context.CancelFunc
				latest = now.Add(time.Second)
				parent, cancel = context.WithDeadline(parent, latest)
				defer cancel()
			case "expired":
				lease = now.Add(-time.Second)
				latest = lease
			}
			db := &orderedPlanningBlockingDB{entered: make(chan context.Context, 1), release: make(chan struct{})}
			bounded := &orderedPlanningSQLDatabase{Database: db, authorityDeadline: lease}
			done := make(chan struct{})
			go func() { bounded.QueryJSON(parent, "controlled SQL"); close(done) }()
			queryContext := <-db.entered
			deadline, ok := queryContext.Deadline()
			if !ok || deadline.After(latest) {
				t.Error("SQL deadline exceeded earlier authority")
			}
			close(db.release)
			<-done
			if queryContext.Err() == nil {
				t.Error("SQL context not released")
			}
			if mode == "expired" && queryContext.Err() != context.DeadlineExceeded {
				t.Error("expired authority not propagated")
			}
		})
	}
}

func TestSecurityAgentMultistepPlanningEarliestAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, earliest := range []string{"lease", "budget", "pricing", "caller"} {
		t.Run(earliest, func(t *testing.T) {
			job := orderedPlanningJob{LeaseExpiresAt: now.Add(time.Hour), BudgetDeadlineAt: now.Add(time.Hour), PricingBound: &multisteppricing.Bound{Policy: multisteppricing.Policy{ExpiresAt: now.Add(time.Hour).Format(multisteppricing.TimeFormat)}}}
			want := now.Add(time.Minute)
			ctx := context.Background()
			switch earliest {
			case "lease":
				job.LeaseExpiresAt = want
			case "budget":
				job.BudgetDeadlineAt = want
			case "pricing":
				job.PricingBound.Policy.ExpiresAt = want.Format(multisteppricing.TimeFormat)
			case "caller":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, want)
				defer cancel()
			}
			if got := orderedPlanningDeadline(ctx, job); !got.Equal(want) {
				t.Fatal("earliest authority omitted", earliest, got, want)
			}
		})
	}
}

func (d *orderedPlanningBlockingDB) QueryJSON(ctx context.Context, _ string, _ ...any) (json.RawMessage, error) {
	d.entered <- ctx
	select {
	case <-ctx.Done():
	case <-d.release:
	}
	return nil, errWorkerExecution
}

func TestSecurityAgentMultistepPlanningOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_ORDERED_PLANNING_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned local planning database")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || config.User != "zasp_e2e" || config.Database != "postgres" || net.ParseIP(config.Host) == nil || !net.ParseIP(config.Host).IsLoopback() {
		t.Fatal("requires owned loopback database")
	}
	for _, f := range config.Fallbacks {
		if net.ParseIP(f.Host) == nil || !net.ParseIP(f.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	var selection securityAgentMultistepPricingBinding
	if json.Unmarshal([]byte(os.Getenv("ZASP_ORDERED_PLANNING_BINDING")), &selection) != nil {
		t.Fatal("binding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	config.User = "security_agent_v33_worker_login"
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	transport := orderedBindingResponseTransport()
	if os.Getenv("ZASP_ORDERED_PLANNING_FAULT") == "provider_lost" {
		transport.err = errors.New("controlled post-send lost acknowledgement")
	}
	candidate := `{"version":1,"summary":"Contain and retest","steps":[{"index":0,"action":"create_temporary_policy","target_id":"` + selection.EnvironmentID + `"},{"index":1,"action":"run_test","target_id":"` + os.Getenv("ZASP_ORDERED_PLANNING_TEST_ID") + `"}]}`
	transport.responseBody = openRouterPlannerResponse(candidate)
	var response map[string]json.RawMessage
	json.Unmarshal(transport.responseBody, &response)
	response["usage"] = json.RawMessage(`{"prompt_tokens":50,"completion_tokens":50,"total_tokens":100,"cost":0.0000005}`)
	transport.responseBody, _ = json.Marshal(response)
	if os.Getenv("ZASP_ORDERED_PLANNING_FAULT") == "invalid_utf8" {
		transport.responseBody = bytes.Replace(transport.responseBody, []byte("Contain and retest"), []byte{'x', 0xff, 'y'}, 1)
	}
	witnessRequest, _ := json.Marshal(map[string]any{"organization_id": selection.OrganizationID, "workspace_id": selection.WorkspaceID, "environment_id": selection.EnvironmentID, "run_id": os.Getenv("ZASP_ORDERED_PLANNING_RUN"), "worker_id": "ordered-planner", "lease_token": "ordered-planner-lease-0001", "operation": "claim", "payload": map[string]any{}})
	db := &orderedPlanningFaultDB{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: conn}, fault: os.Getenv("ZASP_ORDERED_PLANNING_FAULT"), cancel: cancel, t: t}
	var outbound http.RoundTripper = &orderedProviderWitness{base: transport, db: &orderedPricingWorkerPG{conn: conn}, request: witnessRequest}
	if strings.HasPrefix(db.fault, "budget_") || strings.HasPrefix(db.fault, "pricing_") {
		// Do not let the normal SQL witness mask a runtime post-ack send:
		// this controlled external transport must observe any attempted call.
		outbound = &orderedDeadlineTransport{base: transport, db: db, t: t}
	}
	planner := orderedRequestBindingPlanner(t, outbound)
	if strings.HasSuffix(db.fault, "_cancel") {
		// Controlled transport test removes the independent one-second fixture
		// timeout so it cannot mask a missing earlier authority cancellation.
		planner.client.Timeout = 80 * time.Second
	}
	driver := &orderedFileArtifactDriver{directory: os.Getenv("ZASP_ORDERED_PLANNING_ARTIFACTS"), t: t, fault: os.Getenv("ZASP_ORDERED_PLANNING_FAULT"), authorityDeadline: &db.authorityDeadline}
	if !filepath.IsAbs(driver.directory) {
		t.Fatal("artifact directory")
	}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 524288})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runSecurityAgentOrderedPlanning(ctx, orderedPlanningConfig{Database: db, Store: store, Planner: planner, Selection: selection, RunID: os.Getenv("ZASP_ORDERED_PLANNING_RUN"), WorkerID: "ordered-planner", LeaseToken: "ordered-planner-lease-0001"})
	if db.fault != "" && !strings.HasSuffix(db.fault, "_timely") {
		if err == nil {
			t.Fatal("fault did not stop worker")
		}
	} else if err != nil || !bytes.Contains(receipt, []byte(`"admitted"`)) {
		t.Fatal("actual private planning worker", err, string(receipt), "last operation", db.lastOperation, "response fields", db.lastFields)
	}
	t.Logf("owned planning worker joined: provider_calls=%d", transport.calls)
}

type orderedPlanningFaultDB struct {
	orderedPricingWorkerPG
	fault             string
	lastOperation     string
	lastFields        int
	authorityDeadline time.Time
	cancel            context.CancelFunc
	t                 *testing.T
}

type orderedDeadlineTransport struct {
	base *securityAgentPlannerTransport
	db   *orderedPlanningFaultDB
	t    *testing.T
}

func (p *orderedDeadlineTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	deadline, ok := request.Context().Deadline()
	if !ok || p.db.authorityDeadline.IsZero() || deadline.After(p.db.authorityDeadline) {
		p.t.Error("provider context exceeded earliest budget/pricing authority")
		return nil, errWorkerExecution
	}
	if strings.HasSuffix(p.db.fault, "_cancel") {
		p.base.calls++
		<-request.Context().Done()
		if time.Now().After(p.db.authorityDeadline.Add(time.Second)) {
			p.t.Error("provider cancellation exceeded authority")
		}
		return nil, request.Context().Err()
	}
	return p.base.RoundTrip(request)
}

// A separate transaction at the outbound boundary observes the committed
// started journal and exact retained body before the controlled provider sees it.
type orderedProviderWitness struct {
	base    *securityAgentPlannerTransport
	db      *orderedPricingWorkerPG
	request json.RawMessage
}

func (p *orderedProviderWitness) RoundTrip(request *http.Request) (*http.Response, error) {
	raw, err := p.db.QueryJSON(request.Context(), `SELECT zasp_sa_multistep_prior.planning($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), p.request)
	var job orderedPlanningJob
	if err != nil || json.Unmarshal(raw, &job) != nil || job.State != "started" || job.InputVersion == "" || job.InputSize <= 0 || job.RequestDigest != orderedPlanningDigest([]byte(job.RequestBody)) || job.PricingBound == nil || request.GetBody == nil {
		return nil, errWorkerExecution
	}
	copy, err := request.GetBody()
	if err != nil {
		return nil, errWorkerExecution
	}
	body, err := io.ReadAll(copy)
	copy.Close()
	if err != nil || string(body) != job.RequestBody {
		return nil, errWorkerExecution
	}
	var prepared securityAgentOpenRouterRequest
	if json.Unmarshal(body, &prepared) != nil || len(prepared.Messages) != 2 || prepared.Messages[0].Role != "system" || prepared.Messages[0].Content != securityAgentPlannerSystemPolicy || prepared.Messages[1].Role != "user" {
		return nil, errWorkerExecution
	}
	var visible map[string]json.RawMessage
	if json.Unmarshal([]byte(prepared.Messages[1].Content), &visible) != nil || len(visible) != 10 || visible["credential"] != nil || visible["definition"] != nil {
		return nil, errWorkerExecution
	}
	var actions []string
	if json.Unmarshal(visible["allowed_actions"], &actions) != nil || len(actions) != 2 || actions[0] != "create_temporary_policy" || actions[1] != "run_test" {
		return nil, errWorkerExecution
	}
	return p.base.RoundTrip(request)
}

func (d *orderedPlanningFaultDB) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if d.fault == "cancel_lookup" && strings.Contains(q, "pricing_ready(") {
		d.cancel()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			d.t.Error("pricing constructor SQL outlived private caller cancellation")
		}
		return nil, errWorkerExecution
	}
	if deadline, ok := ctx.Deadline(); !ok || deadline.After(time.Now().Add(30*time.Second)) {
		return nil, errors.New("private planning SQL boundary has no finite deadline")
	}
	if deadline, _ := ctx.Deadline(); !d.authorityDeadline.IsZero() && deadline.After(d.authorityDeadline) {
		return nil, errors.New("private planning SQL exceeded earliest observed authority")
	}
	raw, err := d.orderedPricingWorkerPG.QueryJSON(ctx, q, args...)
	if err == nil && strings.Contains(q, "prior.planning(") && len(args) == 3 {
		var request struct {
			Operation string `json:"operation"`
		}
		body, _ := json.Marshal(args[2])
		if value, ok := args[2].(json.RawMessage); ok {
			body = value
		}
		json.Unmarshal(body, &request)
		d.lastOperation = request.Operation
		fields, _ := securityAgentOrderedJSONObject(raw)
		d.lastFields = len(fields)
		var window struct {
			BudgetDeadline time.Time               `json:"budget_deadline_at"`
			Lease          time.Time               `json:"lease_expires_at"`
			Pricing        *multisteppricing.Bound `json:"pricing_bound"`
		}
		if json.Unmarshal(raw, &window) == nil && !window.BudgetDeadline.IsZero() {
			d.authorityDeadline = window.BudgetDeadline
			if window.Lease.Before(d.authorityDeadline) {
				d.authorityDeadline = window.Lease
			}
			if window.Pricing != nil {
				expiry, parseErr := time.Parse(time.RFC3339Nano, window.Pricing.Policy.ExpiresAt)
				if parseErr == nil && expiry.Before(d.authorityDeadline) {
					d.authorityDeadline = expiry
				}
			}
		}
		if (d.fault == "pricing_ack" || d.fault == "pricing_runway_ack" || d.fault == "budget_ack") && request.Operation == "start" {
			var job orderedPlanningJob
			if json.Unmarshal(raw, &job) != nil || job.PricingBound == nil {
				return nil, errWorkerExecution
			}
			expires, err := time.Parse(time.RFC3339Nano, job.PricingBound.Policy.ExpiresAt)
			if err != nil {
				return nil, errWorkerExecution
			}
			if d.fault == "budget_ack" {
				expires = window.BudgetDeadline
			}
			if d.fault == "pricing_runway_ack" {
				expires = expires.Add(-20 * time.Second)
			}
			// Deliberately delay a committed acknowledgement until authority
			// expires or remaining runway is insufficient for external I/O.
			timer := time.NewTimer(time.Until(expires.Add(20 * time.Millisecond)))
			defer timer.Stop()
			<-timer.C
		}
		if d.fault == "wire_size" && request.Operation == "claim" {
			fields["input_size"] = json.RawMessage("1")
			raw, _ = json.Marshal(fields)
		}
		if d.fault == "wire_claim_pricing" && request.Operation == "claim" {
			fields["pricing_bound"] = json.RawMessage(`{"policy":{"expires_at":"not-a-time"}}`)
			raw, _ = json.Marshal(fields)
		}
		if strings.HasPrefix(d.fault, "wire_budget_") && request.Operation == "claim" {
			switch d.fault {
			case "wire_budget_missing":
				delete(fields, "budget_deadline_at")
			case "wire_budget_null":
				fields["budget_started_at"] = json.RawMessage("null")
			case "wire_budget_malformed":
				fields["budget_deadline_at"] = json.RawMessage(`"not-a-time"`)
			case "wire_budget_inconsistent":
				fields["budget_deadline_at"], _ = json.Marshal(window.BudgetDeadline.Add(time.Second))
			}
			raw, _ = json.Marshal(fields)
		}
		if d.fault == "wire_pricing" && request.Operation == "prepare" {
			var bound map[string]json.RawMessage
			json.Unmarshal(fields["pricing_bound"], &bound)
			var policy map[string]json.RawMessage
			json.Unmarshal(bound["policy"], &policy)
			policy["expires_at"] = json.RawMessage(`"not-a-time"`)
			bound["policy"], _ = json.Marshal(policy)
			fields["pricing_bound"], _ = json.Marshal(bound)
			raw, _ = json.Marshal(fields)
		}
		if request.Operation == d.fault {
			return nil, errWorkerExecution
		}
	}
	return raw, err
}

// Controlled durable create-only object service. The real typed artifact store
// validates scope, version, bytes, digest and size above this external boundary.
type orderedFileArtifactDriver struct {
	directory         string
	t                 *testing.T
	fault             string
	puts              int
	authorityDeadline *time.Time
}

func (d *orderedFileArtifactDriver) Put(ctx context.Context, v artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	if d.authorityDeadline != nil && !d.authorityDeadline.IsZero() {
		if deadline, ok := ctx.Deadline(); !ok || deadline.After(*d.authorityDeadline) {
			d.t.Error("artifact write exceeded earliest authority")
			return artifactstore.DriverObject{}, errWorkerExecution
		}
	}
	d.puts++
	if ctx.Err() != nil {
		return artifactstore.DriverObject{}, ctx.Err()
	}
	v.VersionID = "component-version-1"
	path := filepath.Join(d.directory, v.Reference.ArtifactID().String()+".json")
	raw, _ := json.Marshal(struct {
		Object artifactstore.DriverObject
		Scope  [3]string
	}{v, [3]string{v.Scope.OrganizationID().String(), v.Scope.WorkspaceID().String(), v.Scope.EnvironmentID().String()}})
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		prior, err := d.Get(ctx, v.DriverLocator)
		if err != nil || !bytes.Equal(prior.Body, v.Body) || prior.SHA256 != v.SHA256 {
			return artifactstore.DriverObject{}, errWorkerExecution
		}
		return prior, nil
	}
	if err != nil {
		return artifactstore.DriverObject{}, err
	}
	_, err = f.Write(raw)
	closeErr := f.Close()
	if err != nil {
		return artifactstore.DriverObject{}, err
	}
	if closeErr != nil {
		return artifactstore.DriverObject{}, closeErr
	}
	if d.fault == "input_put" && d.puts == 1 || d.fault == "output_put" && d.puts == 2 {
		return artifactstore.DriverObject{}, artifactstore.ErrPut
	}
	return v, nil
}
func (d *orderedFileArtifactDriver) Get(ctx context.Context, v artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	if d.authorityDeadline != nil && !d.authorityDeadline.IsZero() {
		if deadline, ok := ctx.Deadline(); !ok || deadline.After(*d.authorityDeadline) {
			d.t.Error("artifact read exceeded earliest authority")
			return artifactstore.DriverObject{}, errWorkerExecution
		}
	}
	if ctx.Err() != nil {
		return artifactstore.DriverObject{}, ctx.Err()
	}
	raw, err := os.ReadFile(filepath.Join(d.directory, v.Reference.ArtifactID().String()+".json"))
	if err != nil {
		return artifactstore.DriverObject{}, err
	}
	var stored struct {
		Object artifactstore.DriverObject
		Scope  [3]string
	}
	decodeErr := json.Unmarshal(raw, &stored)
	result := stored.Object
	if stored.Scope == ([3]string{v.Scope.OrganizationID().String(), v.Scope.WorkspaceID().String(), v.Scope.EnvironmentID().String()}) {
		result.Scope = v.Scope
	}
	if decodeErr != nil || result.DriverLocator != v || sha256.Sum256(result.Body) != result.SHA256 {
		d.t.Logf("controlled artifact discovery: decode_error=%t scope_match=%t version_match=%t digest_match=%t", decodeErr != nil, result.Scope == v.Scope, result.VersionID == v.VersionID, sha256.Sum256(result.Body) == result.SHA256)
		return artifactstore.DriverObject{}, errWorkerExecution
	}
	return result, nil
}
func (d *orderedFileArtifactDriver) Delete(context.Context, artifactstore.DriverLocator) error {
	return artifactstore.ErrDelete
}
