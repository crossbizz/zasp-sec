package redteamadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

type p7AdapterChecker struct {
	delegate   authorization.Checker
	calls      atomic.Int32
	diagnostic *testing.T
	after      func(int32)
}

func (c *p7AdapterChecker) Check(ctx context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
	count := c.calls.Add(1)
	started := time.Now()
	d, err := c.delegate.Check(ctx, q)
	if err == nil && d.Allowed && c.after != nil {
		c.after(count)
	}
	if c.diagnostic != nil {
		c.diagnostic.Log("FGA elapsed", time.Since(started), "error", p7DiagnosticError(err))
	}
	return d, err
}

type p7HeldJournal struct {
	InvocationJournal
	request     JournalRequest
	observation InvocationObservation
	attempt     int
	completions int
	afterStart  func(context.Context) error
}

func (j *p7HeldJournal) Start(ctx context.Context, q JournalRequest) (InvocationReceipt, error) {
	r, err := j.InvocationJournal.Start(ctx, q)
	if err == nil && j.afterStart != nil {
		err = j.afterStart(ctx)
	}
	return r, err
}

type p7CountedResolver struct {
	TargetResolver
	calls *atomic.Int32
}

func (r p7CountedResolver) ResolveTarget(ctx context.Context, q TargetResolution) (TargetBinding, error) {
	r.calls.Add(1)
	return r.TargetResolver.ResolveTarget(ctx, q)
}

func (j *p7HeldJournal) Complete(ctx context.Context, q JournalRequest, attempt int, o InvocationObservation) error {
	j.request, j.observation, j.attempt = q, o, attempt
	j.completions++
	return j.InvocationJournal.Complete(ctx, q, attempt, o)
}

// The parent owns native admission, planning, input and dispatch. This child
// consumes the real HTTP handler, journal, official FGA client and TLS target.
func TestP7WorkerTest74JournalHTTPNative(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_ADAPTER_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned worker74 adapter fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	for _, fallback := range cfg.Fallbacks {
		if net.ParseIP(fallback.Host) == nil || !net.ParseIP(fallback.Host).IsLoopback() {
			t.Fatal("foreign database fallback")
		}
	}
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("owned database")
	}
	defer owner.Close(ctx)
	var q struct {
		OrganizationID string          `json:"organization_id"`
		WorkspaceID    string          `json:"workspace_id"`
		EnvironmentID  string          `json:"environment_id"`
		ParentRunID    string          `json:"parent_run_id"`
		StepID         string          `json:"step_id"`
		OriginalInput  json.RawMessage `json:"original_input"`
		TestRunID      string          `json:"test_run_id"`
		EffectKey      string          `json:"effect_key"`
		Category       string          `json:"category"`
		TargetID       string          `json:"target_id"`
		TargetKind     string          `json:"target_kind"`
	}
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_ADAPTER_REQUEST")), &q) != nil || !ValidEffectKey(q.EffectKey) || curatedInputs[q.Category] == "" {
		t.Fatal("owned request")
	}
	var config runtimeservices.Config
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_ADAPTER_FGA_CONFIG")), &config) != nil || config.FGAURL != "http://127.0.0.1:8088" {
		t.Fatal("owned FGA configuration")
	}
	data, err := exec.CommandContext(ctx, "docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		t.Fatal("owned FGA unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		t.Fatal("owned FGA configuration")
	}
	token := ""
	for _, entry := range containers[0].Config.Env {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		t.Fatal("owned FGA credential")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: config.FGAURL, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal("official FGA client")
	}
	checker, err := authorization.NewOpenFGA(client, config)
	if err != nil {
		t.Fatal("official checker")
	}
	observed := &p7AdapterChecker{delegate: checker}
	diagnostic := os.Getenv("ZASP_P7_ADAPTER_DIAGNOSTIC") == "1"
	recovery := os.Getenv("ZASP_P7_ADAPTER_COMPLETED_RETRY") == "1"
	if diagnostic {
		observed.diagnostic = t
	}
	poolFor := func(login string) *pgxpool.Pool {
		pc, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal("owned pool configuration")
		}
		pc.ConnConfig.User = login
		if diagnostic {
			pc.ConnConfig.Tracer = p7AdapterQueryTrace{t}
		}
		pc.MaxConns = 2
		p, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal("owned pool")
		}
		t.Cleanup(p.Close)
		return p
	}
	load := func(name string, purpose authorization.WorkerPurpose, seed byte) *authorization.WorkerKey {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, bytes.Repeat([]byte{seed}, 32), 0400); err != nil {
			t.Fatal(err)
		}
		key, err := authorization.LoadWorkerKeyFile(purpose, path)
		if err != nil {
			t.Fatal("pinned fixture key")
		}
		return key
	}
	forward, err := authorization.NewWorkerAdapter(poolFor("ordered_test_red_adapter"), observed, config.StoreID, config.ModelID, load("forward", authorization.WorkerForward, 41))
	if err != nil || forward.Ready(ctx) != nil {
		t.Fatal("registered adapter key")
	}
	compensation, err := authorization.NewWorkerExecutor(poolFor("worker_test_compensation"), nil, "", "", load("compensation", authorization.CapturedCompensation, 73))
	if err != nil || compensation.Ready(ctx) != nil {
		t.Fatal("registered compensation key")
	}
	adapterConfig := cfg.Copy()
	adapterConfig.User = "ordered_test_red_adapter"
	adapter, err := pgx.ConnectConfig(ctx, adapterConfig)
	if err != nil {
		t.Fatal("registered adapter")
	}
	defer adapter.Close(ctx)
	wrongRoles, err := NewWorkerSingleTestPostgresJournal(ownedJournalDatabase{adapter}, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint(), compensation, forward)
	if err != nil || wrongRoles.Ready(ctx) == nil {
		t.Fatal("swapped registered worker purposes accepted")
	}
	journal, err := NewWorkerSingleTestPostgresJournal(ownedJournalDatabase{adapter}, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint(), forward, compensation)
	if err != nil || journal.Ready(ctx) != nil {
		t.Fatal("native journal readiness")
	}
	nativeRequest, _ := json.Marshal(map[string]any{"organization_id": q.OrganizationID, "workspace_id": q.WorkspaceID, "environment_id": q.EnvironmentID, "run_id": q.TestRunID, "effect_key": q.EffectKey, "operation": "resolve", "payload": map[string]any{"category": q.Category, "target_id": q.TargetID, "target_kind": q.TargetKind}, "checksum": migrations.ProductionTemporalTestExecutor().Checksum(), "fingerprint": migrations.TemporalTestExecutorFingerprint()})
	if diagnostic {
		bounded, release := context.WithTimeout(ctx, 10*time.Second)
		defer release()
		started := time.Now()
		decision, err := forward.Authorize(bounded, "test74.adapter.resolve", nativeRequest)
		t.Log("Authorize elapsed", time.Since(started), "error", p7DiagnosticError(err), "context", p7DiagnosticError(bounded.Err()), "checks", observed.calls.Load())
		if err == nil {
			started = time.Now()
			_, err = forward.Execute(bounded, decision)
			t.Log("Execute elapsed", time.Since(started), "error", p7DiagnosticError(err), "context", p7DiagnosticError(bounded.Err()))
		}
		t.Fatal("bounded resolve diagnostic complete; no target IO attempted")
	}
	var outbox string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
		t.Fatal("registered projector")
	}
	projection, err := authorization.NewPostgresProjectionRepository(poolFor(outbox))
	if err != nil {
		t.Fatal("actual projection repository")
	}
	writer, err := authorization.NewOpenFGATupleWriter(client, config)
	if err != nil {
		t.Fatal("actual tuple writer")
	}
	for _, at := range []int32{1, 8} {
		if recovery {
			break
		}
		observed.calls.Store(0)
		observed.after = func(n int32) {
			if n == at {
				if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=(SELECT grantor_id FROM zasp_authorization80_worker.test_associations WHERE run_id=$2)`, q.OrganizationID, q.ParentRunID); err != nil {
					t.Fatal("owned mid-Check revoke")
				}
			}
		}
		bounded, release := context.WithTimeout(ctx, 10*time.Second)
		_, err := forward.Authorize(bounded, "test74.adapter.resolve", nativeRequest)
		release()
		observed.after = nil
		if !errors.Is(err, authorization.ErrConflict) || observed.calls.Load() != 8 {
			t.Fatal("mid-Check native revision change did not refuse complete set", at, p7DiagnosticError(err), observed.calls.Load())
		}
		var empty bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.invocations WHERE test_run_id=$1)`, q.TestRunID).Scan(&empty); err != nil || !empty {
			t.Fatal("mid-Check refusal created invocation")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=(SELECT grantor_id FROM zasp_authorization80_worker.test_associations WHERE run_id=$2)`, q.OrganizationID, q.ParentRunID); err != nil {
			t.Fatal("restore owned grantor")
		}
		if _, err := authorization.Reconcile(ctx, projection, writer, q.OrganizationID, config.StoreID, config.ModelID); err != nil {
			t.Fatal("normal projection after owned grantor restoration")
		}
	}
	observed.calls.Store(0)
	var originalInput struct {
		InputDigest string `json:"input_digest"`
	}
	if json.Unmarshal(q.OriginalInput, &originalInput) != nil {
		t.Fatal("original input digest")
	}
	promptBytes, _ := json.Marshal(curatedInputs[q.Category])
	wireBody := `{"schema_version":"red-team-target-v1","run_id":"` + q.TestRunID + `","target_id":"` + q.TargetID + `","target_kind":"` + q.TargetKind + `","category":"` + q.Category + `","input":` + string(promptBytes) + `}`
	wireDigest := sha256.Sum256([]byte(wireBody))
	receiptRequest, _ := json.Marshal(map[string]any{"organization_id": q.OrganizationID, "workspace_id": q.WorkspaceID, "environment_id": q.EnvironmentID, "parent_run_id": q.ParentRunID, "test_run_id": q.TestRunID, "step_id": q.StepID, "effect_key": q.EffectKey, "generation": 1, "category": q.Category, "input_digest": originalInput.InputDigest, "request_digest": hex.EncodeToString(wireDigest[:])})
	if recovery {
		if _, err := compensation.Authorize(ctx, "test74.adapter.receipt", receiptRequest); !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("absent journal receipt did not refuse", p7DiagnosticError(err))
		}
	}
	var sends atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		body, readErr := io.ReadAll(r.Body)
		digest := sha256.Sum256(body)
		var committed bool
		err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_temporal74.invocations WHERE test_run_id=$1 AND category=$2 AND effect_key=$3 AND request_digest=$4 AND state='started'`, q.TestRunID, q.Category, q.EffectKey, digest[:]).Scan(&committed)
		if readErr != nil || err != nil || !committed {
			t.Error("target send preceded exact durable native start")
			w.WriteHeader(500)
			return
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=(SELECT grantor_id FROM zasp_authorization80_worker.test_associations WHERE run_id=$2)`, q.OrganizationID, q.ParentRunID); err != nil {
			t.Error("owned revocation")
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output":"controlled target refused"}`)
	}))
	defer server.Close()
	credential := &credentialResolverStub{secret: []byte("0123456789abcdef0123456789abcdef"), destroyed: &atomic.Bool{}}
	invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, server)}, credential, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	held := &p7HeldJournal{InvocationJournal: journal}
	if recovery {
		held.afterStart = func(callCtx context.Context) error {
			if _, err := compensation.Authorize(callCtx, "test74.adapter.receipt", receiptRequest); !errors.Is(err, authorization.ErrDenied) {
				t.Error("started journal receipt did not refuse", p7DiagnosticError(err))
				return ErrAdapter
			}
			return nil
		}
	}
	var resolverCalls atomic.Int32
	handler, err := NewWorkerEffectJournaledHandler(Config{WorkerToken: []byte(strings.Repeat("a", 64)), MaximumRequestBytes: 4096}, p7CountedResolver{journal, &resolverCalls}, invoker, held, journal)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"target_id": q.TargetID, "target_kind": q.TargetKind, "category": q.Category, "input": curatedInputs[q.Category]})
	request := httptest.NewRequest("POST", "/v1/effects/evaluate", bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	request.Header.Set("Content-Type", "application/json")
	for k, v := range map[string]string{"X-Zasp-Organization-ID": q.OrganizationID, "X-Zasp-Workspace-ID": q.WorkspaceID, "X-Zasp-Environment-ID": q.EnvironmentID, "X-Zasp-Run-ID": q.TestRunID, "X-Zasp-Effect-Key": q.EffectKey} {
		request.Header.Set(k, v)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 || sends.Load() != 1 || credential.calls != 1 || held.completions != 1 || observed.calls.Load() != 16 || resolverCalls.Load() != 1 {
		t.Fatal("actual worker HTTP/current authority/captured Complete", response.Code, sends.Load(), credential.calls, held.completions, observed.calls.Load())
	}
	beforeChecks := observed.calls.Load()
	for i := 0; i < 2; i++ {
		if err := journal.Complete(ctx, held.request, held.attempt, held.observation); err != nil {
			t.Fatal("held Complete retry after revoke")
		}
	}
	if sends.Load() != 1 || credential.calls != 1 || observed.calls.Load() != beforeChecks || !credential.destroyed.Load() {
		t.Fatal("captured completion retried forward IO")
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(state='completed' AND attempt=1 AND http_status=200 AND protected) FROM zasp_temporal74.invocations WHERE test_run_id=$1`, q.TestRunID).Scan(&exact); err != nil || !exact {
		t.Fatal("native HTTP completion cardinality")
	}
	if recovery {
		var bodySafe bool
		if err := owner.QueryRow(ctx, `SELECT strpos(pg_get_functiondef('zasp_authorization80_worker.test74_receipt_read(jsonb)'::regprocedure),'INSERT INTO')=0 AND strpos(pg_get_functiondef('zasp_authorization80_worker.test74_receipt_read(jsonb)'::regprocedure),'UPDATE zasp_temporal74.invocations')=0 AND NOT has_function_privilege('zasp_temporal_compensation','zasp_authorization80_worker.test74_receipt_read(jsonb)','EXECUTE') AND NOT has_function_privilege('zasp_red_team_adapter','zasp_authorization80_worker.test74_receipt(jsonb)','EXECUTE')`).Scan(&bodySafe); err != nil || !bodySafe {
			t.Fatal("installed receipt reader mutation/ACL contract")
		}
		var originalJournal json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY category) FROM zasp_temporal74.invocations j WHERE test_run_id=$1`, q.TestRunID).Scan(&originalJournal); err != nil {
			t.Fatal("original completed journal")
		}
		var original struct {
			Schema      string   `json:"schema_version"`
			RunID       string   `json:"run_id"`
			TargetID    string   `json:"target_id"`
			TargetKind  string   `json:"target_kind"`
			InputDigest string   `json:"input_digest"`
			Categories  []string `json:"categories"`
		}
		if json.Unmarshal(q.OriginalInput, &original) != nil || original.Schema != "red-team-runner-input-v2" || original.RunID != q.TestRunID || original.TargetID != q.TargetID || original.TargetKind != q.TargetKind || len(original.Categories) != 1 || original.Categories[0] != q.Category {
			t.Fatal("original captured input association")
		}
		prompt, _ := json.Marshal(curatedInputs[q.Category])
		wire := `{"schema_version":"red-team-target-v1","run_id":"` + original.RunID + `","target_id":"` + original.TargetID + `","target_kind":"` + original.TargetKind + `","category":"` + q.Category + `","input":` + string(prompt) + `}`
		requestDigest := sha256.Sum256([]byte(wire))
		retryBody, _ := json.Marshal(map[string]any{"organization_id": q.OrganizationID, "workspace_id": q.WorkspaceID, "environment_id": q.EnvironmentID, "parent_run_id": q.ParentRunID, "test_run_id": q.TestRunID, "step_id": q.StepID, "effect_key": q.EffectKey, "generation": 1, "category": q.Category, "input_digest": original.InputDigest, "request_digest": hex.EncodeToString(requestDigest[:])})
		var expectedRaw json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',j.organization_id,'workspace_id',j.workspace_id,'environment_id',j.environment_id,'parent_run_id',x.run_id,'test_run_id',j.test_run_id,'step_id',x.step_id,'effect_key',j.effect_key,'category',j.category,'attempt',j.attempt,'state',j.state,'request_digest',encode(j.request_digest,'hex'),'response_digest',encode(j.response_digest,'hex'),'http_status',j.http_status,'protected',j.protected,'credential_version_digest',encode(j.credential_version_digest,'hex'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'input_digest',encode(j.input_digest,'hex'),'generation',1,'captured_resolution_digest',encode(digest(convert_to(j.target_resolution::text,'UTF8'),'sha256'),'hex')) FROM zasp_temporal74.invocations j JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,test_run_id) WHERE j.test_run_id=$1 AND j.category=$2`, q.TestRunID, q.Category).Scan(&expectedRaw); err != nil {
			t.Fatal("exact native completed reference")
		}
		freshJournal, err := NewWorkerSingleTestPostgresJournal(ownedJournalDatabase{adapter}, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint(), forward, compensation)
		if err != nil || freshJournal.Ready(ctx) != nil {
			t.Fatal("fresh captured retry clients")
		}
		fresh, err := NewWorkerEffectJournaledHandler(Config{WorkerToken: []byte(strings.Repeat("a", 64)), MaximumRequestBytes: 4096}, p7CountedResolver{freshJournal, &resolverCalls}, invoker, freshJournal, freshJournal)
		if err != nil {
			t.Fatal("fresh retry handler")
		}
		var expected map[string]any
		_ = json.Unmarshal(expectedRaw, &expected)
		for i := 0; i < 2; i++ {
			retry := httptest.NewRequest("POST", "/v1/effects/completed-receipt", bytes.NewReader(retryBody)).WithContext(ctx)
			retry.Header = request.Header.Clone()
			response := httptest.NewRecorder()
			fresh.ServeHTTP(response, retry)
			if response.Code != 200 {
				var diagnosticRaw json.RawMessage
				diagnosticErr := poolFor("worker_test_compensation").QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_receipt_source('receipt',$1::jsonb)`, retryBody).Scan(&diagnosticRaw)
				t.Log("receipt source refusal class", p7DiagnosticError(diagnosticErr))
				t.Fatal("fresh revoked completed receipt unavailable", response.Code, "sends", sends.Load(), "credentials", credential.calls, "checks", observed.calls.Load())
			}
			fields, err := exactJournalObject(response.Body.Bytes(), "organization_id workspace_id environment_id parent_run_id test_run_id step_id effect_key category attempt state request_digest response_digest http_status protected credential_version_digest completed_at input_digest generation captured_resolution_digest")
			var got map[string]any
			if err != nil || len(fields) != 19 || json.Unmarshal(response.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, expected) {
				t.Fatal("captured retry receipt changed or disclosed extra fields")
			}
			if sends.Load() != 1 || credential.calls != 1 || observed.calls.Load() != beforeChecks || resolverCalls.Load() != 1 {
				t.Fatal("captured retry attempted forward IO")
			}
		}
		for _, mode := range []string{"auth", "header", "duplicate", "extra", "null"} {
			badBody := bytes.Clone(retryBody)
			switch mode {
			case "duplicate":
				badBody = append([]byte(`{"generation":1,`), retryBody[1:]...)
			case "extra":
				badBody = append([]byte(`{"context":{},`), retryBody[1:]...)
			case "null":
				badBody = bytes.Replace(badBody, []byte(`"generation":1`), []byte(`"generation":null`), 1)
			}
			r := httptest.NewRequest("POST", "/v1/effects/completed-receipt", bytes.NewReader(badBody)).WithContext(ctx)
			r.Header = request.Header.Clone()
			if mode == "auth" {
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 64))
			}
			if mode == "header" {
				r.Header.Set("X-Zasp-Effect-Key", strings.Repeat("0", 64))
			}
			res := httptest.NewRecorder()
			fresh.ServeHTTP(res, r)
			want := http.StatusBadRequest
			if mode == "auth" {
				want = http.StatusForbidden
			}
			if res.Code != want {
				t.Fatal("malformed receipt route accepted", mode, res.Code)
			}
			if sends.Load() != 1 || credential.calls != 1 || observed.calls.Load() != beforeChecks || resolverCalls.Load() != 1 {
				t.Fatal("refused receipt route attempted forward IO", mode)
			}
		}
		var unchanged bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND jsonb_agg(to_jsonb(j) ORDER BY category)=$2::jsonb FROM zasp_temporal74.invocations j WHERE test_run_id=$1`, q.TestRunID, originalJournal).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("receipt retries changed completed journal")
		}
	}
	t.Log("actual handler/native journal:1 exact committed-start TLS send,1 credential read, revoke before response, captured completion and2 held retries; no full runtime or recovered receipt claim")
}
