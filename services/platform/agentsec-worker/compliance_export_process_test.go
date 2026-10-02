package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

// A persistent controlled HTTP service behind the real AWS SDK. The parent
// gives two independent worker processes this same object file. No AWS calls.
type complianceProcessObject struct {
	Body    []byte
	Headers http.Header
	Key     string
}
type complianceProcessHTTP struct {
	t           *testing.T
	path, phase string
	puts        int
}

func (h *complianceProcessHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, ok := r.Context().Deadline(); !ok {
		return nil, errors.New("unbounded provider call")
	}
	if r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || !strings.Contains(r.URL.Path, "/exports/") {
		return nil, errors.New("provider scope/pin absent")
	}
	saved, err := os.ReadFile(h.path)
	var object complianceProcessObject
	exists := err == nil && json.Unmarshal(saved, &object) == nil
	if exists && object.Key != r.URL.Path {
		return nil, errors.New("foreign key")
	}
	response := func(status int, headers http.Header, body []byte) *http.Response {
		return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(bytes.NewReader(body)), Request: r}
	}
	failure := func(code string) *http.Response {
		return response(500, http.Header{}, []byte("<Error><Code>"+code+"</Code></Error>"))
	}
	switch r.Method {
	case "PUT":
		h.puts++
		if r.Header.Get("If-None-Match") != "*" || r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111" {
			return nil, errors.New("conditional/KMS pins absent")
		}
		if !exists {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			headers := http.Header{"Content-Type": []string{"application/json"}, "Content-Length": []string{strconv.Itoa(len(body))}, "X-Amz-Version-Id": []string{"compliance-process-v1"}, "X-Amz-Checksum-Sha256": []string{r.Header.Get("X-Amz-Checksum-Sha256")}, "X-Amz-Server-Side-Encryption": []string{"aws:kms"}, "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id": []string{r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id")}}
			for key, values := range r.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") {
					headers[key] = values
				}
			}
			object = complianceProcessObject{Body: body, Headers: headers, Key: r.URL.Path}
			encoded, _ := json.Marshal(object)
			if os.WriteFile(h.path, encoded, 0600) != nil {
				return nil, errors.New("fixture storage failed")
			}
		}
		if h.phase == "interrupt" {
			if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				return nil, err
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		if h.phase == "revoked" || h.phase == "lease_lost" {
			if os.WriteFile(h.path+".entered", []byte("upload"), 0600) != nil {
				return nil, errors.New("fixture signal failed")
			}
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				if _, err := os.Stat(h.path + ".release"); err == nil {
					break
				}
				select {
				case <-r.Context().Done():
					return nil, r.Context().Err()
				case <-ticker.C:
				}
			}
		}
		if h.phase == "unknown" {
			return failure("InternalError"), nil
		}
		if exists {
			return response(412, http.Header{}, []byte(`<Error><Code>PreconditionFailed</Code></Error>`)), nil
		}
		return response(200, object.Headers.Clone(), nil), nil
	case "HEAD":
		if h.phase == "unknown" {
			return failure("InternalError"), nil
		}
		if !exists {
			return response(404, http.Header{}, nil), nil
		}
		if version := r.URL.Query().Get("versionId"); version != "" && version != "compliance-process-v1" {
			return response(404, http.Header{}, nil), nil
		}
		return response(200, object.Headers.Clone(), nil), nil
	case "GET":
		if r.URL.Query().Get("versionId") != "compliance-process-v1" {
			return nil, errors.New("version pin absent")
		}
		if !exists {
			return response(404, http.Header{}, []byte(`<Error><Code>NoSuchVersion</Code></Error>`)), nil
		}
		return response(200, object.Headers.Clone(), object.Body), nil
	case "DELETE":
		if r.URL.Query().Get("versionId") != "compliance-process-v1" {
			return nil, errors.New("versionless delete")
		}
		if h.phase == "cleanup_denied" {
			return response(403, http.Header{}, []byte(`<Error><Code>AccessDenied</Code></Error>`)), nil
		}
		if exists {
			if err := os.Remove(h.path); err != nil {
				return nil, err
			}
		}
		return response(204, http.Header{"X-Amz-Version-Id": []string{"compliance-process-v1"}}, nil), nil
	}
	return nil, errors.New("unexpected provider operation")
}

type complianceProcessDB struct {
	database recoveryJSONDatabase
	stop     context.CancelFunc
	phase    string
}

func (d *complianceProcessDB) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	raw, err := d.database.QueryJSON(ctx, q, args...)
	terminal := q == complianceFinishSQL || q == complianceCleanupSQL
	if q == complianceRetrySQL {
		var p struct {
			Outcome string `json:"outcome"`
		}
		_ = json.Unmarshal(args[7].(json.RawMessage), &p)
		terminal = p.Outcome != "heartbeat"
	}
	if terminal && (err == nil || d.phase == "lease_lost") {
		d.stop()
	}
	return raw, err
}

func TestComplianceRuntimeProcess(t *testing.T) {
	dsn := os.Getenv("ZASP_COMPLIANCE_RUNTIME_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL parent launches child")
	}
	phase := os.Getenv("ZASP_COMPLIANCE_RUNTIME_PHASE")
	path := os.Getenv("ZASP_COMPLIANCE_RUNTIME_OBJECT")
	if path == "" || !strings.HasPrefix(path, "/tmp/") {
		t.Fatal("owned fixture path missing")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, 12*time.Second)
	defer deadline()
	env := complianceRuntimeEnvironment()
	cleanup := phase == "reconcile" || strings.HasPrefix(phase, "cleanup")
	user := "compliance_executor"
	if cleanup {
		user = "compliance_cleanup"
		env["ZASP_WORKER_MODE"] = "compliance-export-cleanup"
		env["ZASP_DATABASE_AUTHORITY"] = "zasp_compliance_cleanup"
		env["ZASP_COMPLIANCE_EXPORT_ROLE_ARN"] = "arn:aws:iam::123456789012:role/compliance-export-cleanup"
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = user
	cfg.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	env["ZASP_POSTGRES_DSN"] = "postgres://" + user + "@postgres.internal/zasp?sslmode=verify-full"
	env["ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"] = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	config, err := loadWorkerRuntimeConfig(mapLookup(env))
	if err != nil {
		t.Fatal(err)
	}
	transport := &complianceProcessHTTP{t: t, path: path, phase: phase}
	provider := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
	role := "compliance-export-worker"
	if cleanup {
		role = "compliance-export-cleanup"
	}
	clients := &complianceExportProductionClients{transport: &http.Transport{}, identity: &runtimeIdentityStub{account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/" + role + "/zasp-" + string(config.Mode)}, credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture", SessionToken: "fixture", CanExpire: true, Expires: time.Now().Add(time.Hour)}, nil
	})}
	if cleanup {
		clients.reader = provider
		clients.cleanup = provider
	} else {
		clients.writer = provider
	}
	dependencies, err := composeComplianceExportWorkerRuntime(ctx, config, &complianceProcessDB{database: db, stop: cancel, phase: phase}, clients)
	if err != nil {
		t.Fatal(err)
	}
	if err := serveWorkerRuntime(ctx, io.Discard, "test", config, dependencies, func(_, _ string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatal("process did not stop after terminal SQL")
	}
	if cleanup && transport.puts != 0 {
		t.Fatal("maintenance/reconciler issued PUT")
	}
	if !cleanup && transport.puts != 1 {
		t.Fatalf("SDK attempts=%d", transport.puts)
	}
	t.Logf("joined %s polling worker; provider PUT=%d; transport is controlled HTTP, not live AWS", phase, transport.puts)
}
