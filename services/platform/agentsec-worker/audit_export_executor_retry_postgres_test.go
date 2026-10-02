//go:build darwin || linux

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
)

// The parent checks persisted state and ACK effects even if a mutated executor
// falsely returns success. This child reports observations, not replacement state.
func TestAuditExportExecutorRetryProcessWorkerPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned executor retry fixture")
	}
	phase := os.Getenv("ZASP_AUDIT_EXPORT_EXECUTOR_RETRY_PHASE")
	if err := auditExportExecutorRetryInputs(dsn, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_MODE"), os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_ADDRESS"), phase, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_FAULT"), os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_OUTCOME")); err != nil {
		t.Fatal(err)
	}
	scope, ok := recoveryScope(os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_ORG"), os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_WORKSPACE"), os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_ENVIRONMENT"))
	exportID := os.Getenv("ZASP_AUDIT_EXPORT_WORKER_TEST_EXPORT")
	if !ok || !validRecoveryProductID(exportID) {
		t.Fatal("invalid retry scope/export")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database := &auditExportExecutorRetryDatabase{base: combinedE2ERecoveryDatabase(t, ctx, dsn), lose: phase == "retry-response-loss"}
	if phase == "direct-retry-zero" {
		authority, err := newPostgresAuditExportAuthority(database, auditExportWorkerPolicyFixture())
		if err != nil {
			t.Fatal(err)
		}
		token, err := newAuditExportProductionToken()
		if err != nil {
			t.Fatal(err)
		}
		lease, err := authority.Claim(ctx, scope, exportID, "audit-export-retry-zero", token, 180)
		if err != nil || lease == nil || !lease.ExpiresAt.After(time.Now()) {
			t.Fatal("live direct Retry0 claim", err)
		}
		terminal, err := authority.Retry(ctx, *lease, 0)
		if err != nil || !terminal {
			t.Fatal("actual Go Retry0", err)
		}
	} else {
		ca := auditExportProcessPrivateFile(t, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_CA"), 16384)
		tokenPath := os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_TOKEN")
		_ = auditExportProcessPrivateFile(t, tokenPath, 4096)
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			t.Fatal("invalid retry CA")
		}
		values := auditExportProductionEnvironment("audit-export")
		values["ZASP_POSTGRES_DSN"], values["ZASP_BATCH_SIZE"] = dsn, "1"
		config, err := loadWorkerRuntimeConfig(mapLookup(values))
		if err != nil {
			t.Fatal(err)
		}
		clients, err := newAuditExportProductionClients(config)
		if err != nil {
			t.Fatal(err)
		}
		defer clients.transport.CloseIdleConnections()
		clients.credentials.(*auditExportCredentialCache).provider.(*outboxWebIdentityProvider).tokenFile = tokenPath
		clients.transport.TLSClientConfig.RootCAs, clients.transport.TLSClientConfig.ServerName = roots, "example.com"
		clients.transport.DialContext = func(ctx context.Context, network, destination string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(destination)
			if err != nil || port != "443" || (host != "sts.us-east-1.amazonaws.com" && host != "sqs.us-east-1.amazonaws.com" && host != auditExportWorkerPolicyFixture().Bucket+".s3.us-east-1.amazonaws.com") {
				return nil, errors.New("unexpected retry provider destination")
			}
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, os.Getenv("ZASP_AUDIT_EXPORT_PROCESS_ADDRESS"))
		}
		observer := &auditExportExecutorRetrySDK{API: clients.artifacts[auditExportWorkerPolicyFixture().PolicyID]}
		clients.artifacts[auditExportWorkerPolicyFixture().PolicyID] = observer
		runtime, err := composeAuditExportWorkerRuntime(ctx, config, database, clients)
		if err != nil {
			t.Fatal("actual retry runtime", err)
		}
		runErr := runtime.Processor.RunOnce(ctx)
		if err := runtime.Close(); err != nil {
			t.Fatal("retry runtime cleanup", err)
		}
		database.report.RunError = runErr != nil
		database.report.Put500, database.report.Head500 = observer.put500, observer.head500
	}
	if ctx.Err() != nil {
		t.Fatal("retry child deadline", ctx.Err())
	}
	database.report.PID = os.Getpid()
	body, err := json.Marshal(database.report)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("registered executor retry result: %s", body)
}

func auditExportExecutorRetryInputs(dsn, mode, address, phase, fault, outcome string) error {
	if mode != "audit-export" || fault != "" || outcome != "" {
		return errors.New("invalid retry mode/fault")
	}
	switch phase {
	case "sdk-error", "retry-response-loss", "terminal-failure", "recovery", "terminal-duplicate", "early-nonterminal", "direct-retry-zero":
	default:
		return errors.New("invalid retry phase")
	}
	return auditExportProcessInputs(dsn, mode, address)
}

type auditExportExecutorRetryReport struct {
	PID, Put500, Head500, Claims, NullClaims, Captures, Retries, Losses, Finishes int
	RunError                                                                      bool
	Terminal                                                                      string
	RetryBody                                                                     json.RawMessage
	Worker, TokenDigest, PolicyID, PolicyDigest, CaptureID                        string
	Generation                                                                    int64
	Attempt, Seconds                                                              int
}

type auditExportExecutorRetryDatabase struct {
	base   recoveryJSONDatabase
	mu     sync.Mutex
	lose   bool
	report auditExportExecutorRetryReport
}

// Delegate first. Even the selected response loss follows a committed real call.
func (d *auditExportExecutorRetryDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	body, err := d.base.QueryJSON(ctx, query, args...)
	if err != nil {
		return body, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch query {
	case auditExportWorkerClaimSQL:
		if string(body) == "null" {
			d.report.NullClaims++
		} else {
			d.report.Claims++
		}
	case auditExportWorkerCaptureSQL:
		d.report.Captures++
	case auditExportWorkerFinishSQL:
		d.report.Finishes++
	case auditExportWorkerTerminalSQL:
		var terminal struct {
			State string `json:"state"`
		}
		if json.Unmarshal(body, &terminal) == nil {
			d.report.Terminal = terminal.State
		}
	case auditExportWorkerRetrySQL:
		d.report.Retries++
		d.report.RetryBody = append(json.RawMessage(nil), body...)
		d.report.CaptureID, _ = args[4].(string)
		d.report.Generation, _ = args[5].(int64)
		d.report.Attempt, _ = args[6].(int)
		d.report.Worker, _ = args[7].(string)
		token, _ := args[8].(string)
		digest := sha256.Sum256([]byte(token))
		d.report.TokenDigest = hex.EncodeToString(digest[:])
		d.report.PolicyID, _ = args[9].(string)
		policyDigest, _ := args[10].([]byte)
		d.report.PolicyDigest = hex.EncodeToString(policyDigest)
		d.report.Seconds, _ = args[13].(int)
		if d.lose {
			d.lose = false
			d.report.Losses++
			return nil, errors.New("owned loss after committed executor Retry")
		}
	}
	return body, nil
}

type auditExportExecutorRetrySDK struct {
	s3driver.API
	put500, head500 int
}

func auditExportExecutorRetryReceived500(ctx context.Context, err error, code string) bool {
	var response *smithyhttp.ResponseError
	var api smithy.APIError
	return ctx.Err() == nil && errors.As(err, &response) && response.Response != nil && response.Response.Response != nil && response.HTTPStatusCode() == 500 && errors.As(err, &api) && api.ErrorCode() == code
}

func (s *auditExportExecutorRetrySDK) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	out, err := s.API.PutObject(ctx, in, opts...)
	if auditExportExecutorRetryReceived500(ctx, err, "InternalError") {
		s.put500++
	}
	return out, err
}

func (s *auditExportExecutorRetrySDK) HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	out, err := s.API.HeadObject(ctx, in, opts...)
	// HEAD has no XML response body. The SDK uses HTTP status text as its code.
	if auditExportExecutorRetryReceived500(ctx, err, "InternalServerError") {
		s.head500++
	}
	return out, err
}

func TestAuditExportExecutorRetryInputsRefuseBroadenedAuthority(t *testing.T) {
	dsn := "postgres://audit_export_worker_fixture@127.0.0.1:15432/zasp?sslmode=disable"
	for _, phase := range []string{"sdk-error", "retry-response-loss", "terminal-failure", "recovery", "terminal-duplicate", "early-nonterminal", "direct-retry-zero"} {
		if auditExportExecutorRetryInputs(dsn, "audit-export", "127.0.0.1:14443", phase, "", "") != nil {
			t.Fatal("closed phase refused", phase)
		}
	}
	for _, input := range [][6]string{
		{dsn, "audit-export-outbox", "127.0.0.1:14443", "sdk-error", "", ""},
		{dsn, "audit-export", "127.0.0.1:14443", "arbitrary", "", ""},
		{dsn, "audit-export", "127.0.0.1:14443", "sdk-error", "finish-outbox-response", ""},
		{dsn, "audit-export", "127.0.0.1:14443", "sdk-error", "", "error"},
		{"postgres://audit_export_outbox_fixture@127.0.0.1:15432/zasp?sslmode=disable", "audit-export", "127.0.0.1:14443", "sdk-error", "", ""},
		{"postgres://postgres@127.0.0.1:15432/zasp?sslmode=disable", "audit-export", "127.0.0.1:14443", "direct-retry-zero", "", ""},
	} {
		if auditExportExecutorRetryInputs(input[0], input[1], input[2], input[3], input[4], input[5]) == nil {
			t.Fatal("broadened retry authority admitted")
		}
	}
}
