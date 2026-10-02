package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/exportfixture"
)

type publicExportWorkerDatabase struct {
	*apiserver.PostgresJSONDatabase
	directory, phase string
	queries          []string
	mu               sync.Mutex
	retried          bool
}

func (d *publicExportWorkerDatabase) querySnapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.queries...)
}

func (d *publicExportWorkerDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	name := strings.TrimSuffix(strings.Split(strings.TrimPrefix(query, "SELECT public."), "(")[0], " ")
	// LoadPrepared uses the same SQL function with an empty payload. It is not
	// a fresh Prepare mutation and must remain available during recovery.
	payload, _ := func() (json.RawMessage, bool) {
		if len(args) == 10 {
			v, ok := args[7].(json.RawMessage)
			return v, ok
		}
		return nil, false
	}()
	loadPrepared := query == compliancePrepareSQL && string(payload) == "{}"
	if loadPrepared {
		name = "zasp_compliance_export_load_prepared"
	}
	d.mu.Lock()
	d.queries = append(d.queries, name)
	d.mu.Unlock()
	if d.phase == "E-resume" && (query == complianceCaptureSQL || query == compliancePrepareSQL && !loadPrepared) {
		return nil, fmt.Errorf("prepared resume entered capture/render/prepare path")
	}
	raw, err := d.PostgresJSONDatabase.QueryJSON(ctx, query, args...)
	if err != nil {
		return raw, err
	}
	if query == complianceRetrySQL {
		d.retried = true
	}
	if query == complianceClaimSQL && string(raw) != "null" {
		data, _ := json.Marshal(map[string]any{"args": args, "result": json.RawMessage(raw)})
		if err := os.WriteFile(filepath.Join(d.directory, d.phase+"-claim.json"), data, 0600); err != nil {
			return nil, err
		}
	}
	if d.phase == "G" && strings.Contains(query, "zasp_sa_export_settlement_claim(") && string(raw) != "[]" {
		data, _ := json.Marshal(map[string]any{"args": args, "result": json.RawMessage(raw)})
		if err := os.WriteFile(filepath.Join(d.directory, "G-claim.json"), data, 0600); err != nil {
			return nil, err
		}
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := os.Stat(filepath.Join(d.directory, "G-release")); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
			}
		}
	}
	stop := d.phase == "B" && strings.Contains(query, "zasp_sa_export_accept_planner(") ||
		d.phase == "D" && strings.Contains(query, "zasp_sa_export_execute_run(") ||
		d.phase == "F" && strings.Contains(query, "zasp_sa_export_settlement_claim(") && string(raw) != "[]" ||
		d.phase == "G" && strings.Contains(query, "zasp_sa_export_settle(")
	if stop {
		data, _ := json.Marshal(map[string]any{"args": args, "result": json.RawMessage(raw), "queries": d.querySnapshot()})
		if err := os.WriteFile(filepath.Join(d.directory, "checkpoint.json"), data, 0600); err != nil {
			return nil, err
		}
		fmt.Fprintln(os.Stdout, "PUBLIC_EXPORT_CHECKPOINT "+d.phase)
		os.Exit(86)
	}
	return raw, nil
}

type publicExportPlannerTransport struct {
	directory string
	inner     exportBrowserPlannerTransport
}

func TestSecurityAgentExportPublicRestartPlannerSelection(t *testing.T) {
	p, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-export-browser-test-token"), Timeout: 5 * time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: &publicExportPlannerTransport{directory: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c := testSecurityAgentPlannerContext()
	c.AllowedActions, c.AllowedTargets = []string{"create_evidence_export"}, []string{c.RunID}
	c.ManualTrigger = &apiserver.SecurityAgentManualTrigger{Kind: "manual", IntentDigest: "sha256:" + strings.Repeat("a", 64), Version: 1}
	c.Evidence = []securityAgentPlannerEvidence{{ID: strings.Repeat("a", 64), Kind: "manual", Version: 1, Summary: "Original manual intent"}}
	manual := apiserver.SecurityAgentExportSelection{Kind: "manual", ID: strings.Repeat("a", 64), Version: 1, AssociationDigest: "sha256:" + strings.Repeat("b", 64)}
	c.ExportSelection = []apiserver.SecurityAgentExportSelection{manual, {Kind: "run_audit", ID: "pid_71000001-0000-4000-8000-000000000001", Version: 1, AssociationDigest: "sha256:" + strings.Repeat("c", 64)}}
	result := p.Plan(context.Background(), c)
	if result.Failure != "" || len(result.Candidate.Steps) != 1 || len(result.Candidate.Steps[0].EvidenceIDs) != 1 || result.Candidate.Steps[0].EvidenceIDs[0] != manual {
		t.Fatalf("provider must select only original manual tuple: %+v", result)
	}
}

func (p *publicExportPlannerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f, err := os.OpenFile(filepath.Join(p.directory, "planner-calls.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fprintf(f, "{\"pid\":%d}\n", os.Getpid())
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	// The existing controlled provider validates the actual production request
	// and derives candidate tuples from its trusted context. Select just the
	// original manual tuple from that response, leaving accounting unchanged.
	response, err := p.inner.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, fmt.Errorf("provider response bounds")
	}
	var envelope map[string]json.RawMessage
	var choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		Finish string `json:"finish_reason"`
		Index  int    `json:"index"`
	}
	if json.Unmarshal(raw, &envelope) != nil || json.Unmarshal(envelope["choices"], &choices) != nil || len(choices) != 1 {
		return nil, fmt.Errorf("provider choices")
	}
	var candidate securityAgentPlannerCandidate
	if json.Unmarshal([]byte(choices[0].Message.Content), &candidate) != nil || len(candidate.Steps) != 1 {
		return nil, fmt.Errorf("provider candidate")
	}
	var selected []apiserver.SecurityAgentExportSelection
	for _, tuple := range candidate.Steps[0].EvidenceIDs {
		if tuple.Kind == "manual" {
			selected = append(selected, tuple)
		}
	}
	if len(selected) != 1 {
		return nil, fmt.Errorf("original manual tuple required")
	}
	candidate.Steps[0].EvidenceIDs = selected
	content, _ := json.Marshal(candidate)
	choices[0].Message.Content = string(content)
	envelope["choices"], _ = json.Marshal(choices)
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

// Each entry owns fresh pools, repositories and runtime composition. No parent
// SQL advances product state. Checkpoints observe real autocommitted calls.
func TestSecurityAgentExportPublicWorkerProcess(t *testing.T) {
	directory := os.Getenv("ZASP_PUBLIC_EXPORT_DIRECTORY")
	if directory == "" {
		t.Skip("owned public restart parent only")
	}
	phase := os.Getenv("ZASP_PUBLIC_EXPORT_PHASE")
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !strings.HasPrefix(filepath.Base(directory), "zasp-public-export-restart-") || !strings.Contains("|B|B-wait|D|D-pending|E-interrupt|E-resume|F|F-held|G|G-done|", "|"+phase+"|") {
		t.Fatal("owned worker phase refused")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(os.Getenv("ZASP_PUBLIC_EXPORT_WORKER_DSN"))
	if err != nil || cfg.ConnConfig.Host != "127.0.0.1" || cfg.ConnConfig.Database != "postgres" || cfg.ConnConfig.Password != "" {
		t.Fatal("owned worker database refused")
	}
	login := "security_agent_v33_worker_login"
	if strings.HasPrefix(phase, "E-") {
		login = "compliance_executor"
	}
	if cfg.ConnConfig.User != login {
		t.Fatal("registered worker login refused")
	}
	cfg.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("worker database unavailable")
	}
	defer pool.Close()
	native, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	db := &publicExportWorkerDatabase{PostgresJSONDatabase: native, directory: directory, phase: phase}
	if !strings.HasPrefix(phase, "E-") {
		planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-export-browser-test-token"), Timeout: 5 * time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: &publicExportPlannerTransport{directory: directory}})
		if err != nil {
			t.Fatal(err)
		}
		config := validSecurityAgentRuntimeConfig()
		config.BatchSize, config.LeaseDuration = 1, 30*time.Second
		config.WorkerID = fmt.Sprintf("public-export-%s-%d", strings.ToLower(phase), os.Getpid())
		runtime, err := composeSecurityAgentWorkerRuntime(config, db, &budgetFixturePlanner{planner})
		if err != nil {
			t.Fatal("agent composition", err)
		}
		defer runtime.Close()
		if err := runtime.Processor.RunOnce(ctx); err != nil {
			t.Fatal("actual agent RunOnce", err)
		}
	} else {
		store, err := exportfixture.Open(exportfixture.Config{Directory: filepath.Join(directory, "export-store"), Bucket: "zasp-compliance-exports", Owner: "123456789012", KMSKey: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20})
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		options := exportfixture.Options{}
		if phase == "E-interrupt" {
			options.After = func(call context.Context, r exportfixture.Request) *exportfixture.Fault {
				if r.Method != "PUT" || r.Status != 200 {
					return nil
				}
				if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
					return &exportfixture.Fault{Err: err}
				}
				<-call.Done()
				return &exportfixture.Fault{Err: call.Err()}
			}
		}
		provider := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{}, HTTPClient: &http.Client{Timeout: 5 * time.Second, Transport: store.Transport(options)}})
		env := complianceRuntimeEnvironment()
		env["ZASP_BATCH_SIZE"] = "1"
		env["ZASP_WORKER_ID"] = fmt.Sprintf("public-export-%s-%d", strings.ToLower(phase), os.Getpid())
		env["ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"] = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
		config, err := loadWorkerRuntimeConfig(mapLookup(env))
		if err != nil {
			t.Fatal(err)
		}
		clients := &complianceExportProductionClients{transport: &http.Transport{}, writer: provider, identity: &runtimeIdentityStub{account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/compliance-export-worker/zasp-" + string(config.Mode)}, credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture", SessionToken: "fixture", CanExpire: true, Expires: time.Now().Add(time.Hour)}, nil
		})}
		runtime, err := composeComplianceExportWorkerRuntime(ctx, config, db, clients)
		if err != nil {
			t.Fatal("export composition", err)
		}
		defer runtime.Close()
		err = runtime.Processor.RunOnce(ctx)
		if phase == "E-interrupt" {
			if ctx.Err() != context.Canceled || !db.retried {
				t.Fatal("SIGTERM did not record bounded uncertainty", err)
			}
		} else if err != nil {
			t.Fatal("actual export RunOnce", err)
		}
	}
	trace, _ := json.Marshal(db.querySnapshot())
	if err := os.WriteFile(filepath.Join(directory, phase+"-queries.json"), trace, 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "PUBLIC_EXPORT_JOINED "+phase)
}
