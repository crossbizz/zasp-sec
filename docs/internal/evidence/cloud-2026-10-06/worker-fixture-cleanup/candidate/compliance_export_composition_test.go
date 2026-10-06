package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type complianceCanceledProcessor struct{ entered, joined chan struct{} }

func (p complianceCanceledProcessor) RunOnce(ctx context.Context) error {
	close(p.entered)
	<-ctx.Done()
	close(p.joined)
	return ctx.Err()
}

type complianceFailedListener struct{ entered chan struct{} }

func (l complianceFailedListener) Accept() (net.Conn, error) {
	<-l.entered
	return nil, errors.New("owned listener failure")
}
func (complianceFailedListener) Close() error   { return nil }
func (complianceFailedListener) Addr() net.Addr { return &net.TCPAddr{} }
func TestComplianceRuntimeListenerFailureJoinsPolling(t *testing.T) {
	config, _, _, _ := complianceRuntimeFixture(t)
	config.ShutdownTimeout = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := complianceCanceledProcessor{make(chan struct{}), make(chan struct{})}
	defer func() {
		cancel()
		select {
		case <-p.joined:
		case <-time.After(time.Second):
			t.Error("test borrower did not join")
		}
	}()
	err := serveWorkerRuntime(ctx, io.Discard, "test", config, workerRuntimeDependencies{Processor: p, Ready: func(context.Context) error { return nil }, Close: func() error { return nil }}, func(string, string) (net.Listener, error) { return complianceFailedListener{p.entered}, nil })
	if err == nil {
		t.Fatal("listener failure accepted")
	}
	select {
	case <-p.joined:
	default:
		t.Fatal("listener failure left polling goroutine alive")
	}
}

type complianceRuntimeDB struct {
	mu                                    sync.Mutex
	lease                                 complianceExportLease
	snapshot, prepared                    json.RawMessage
	finished                              bool
	retry                                 string
	heartbeat, claims, captures, prepares int
	leaseLost, revoked                    bool
	captureFailure                        bool
}

func (d *complianceRuntimeDB) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	l := d.lease
	switch q {
	case complianceCandidatesSQL:
		if d.finished || d.retry != "" {
			return json.RawMessage(`{"items":[]}`), nil
		}
		return json.Marshal(map[string]any{"items": []any{map[string]string{"organization_id": l.Scope.OrganizationID().String(), "workspace_id": l.Scope.WorkspaceID().String(), "environment_id": l.Scope.EnvironmentID().String(), "export_id": l.ExportID}}})
	case complianceClaimSQL:
		d.claims++
		d.lease.WorkerID = args[4].(string)
		d.lease.Token = args[5].(string)
		return json.Marshal(map[string]any{"organization_id": l.Scope.OrganizationID().String(), "workspace_id": l.Scope.WorkspaceID().String(), "environment_id": l.Scope.EnvironmentID().String(), "export_id": l.ExportID, "generation": l.Generation, "attempt": l.Attempt, "lease_expires_at": l.ExpiresAt, "lane": "execute", "captured": false, "prepared": false, "reference": nil, "version": nil, "size": nil, "sha256": nil})
	case complianceCaptureSQL:
		d.captures++
		if d.captureFailure {
			return nil, errors.New("owned pre-upload capture failure")
		}
		h := sha256.Sum256(d.snapshot)
		return json.Marshal(map[string]any{"snapshot": d.snapshot, "mapping_revision": "product-evidence-v1", "sha256": hex.EncodeToString(h[:])})
	case compliancePrepareSQL:
		d.prepares++
		d.prepared = append([]byte(nil), args[7].(json.RawMessage)...)
		return d.prepared, nil
	case complianceFinishSQL:
		if d.revoked || d.leaseLost {
			return nil, errors.New("current source authority rejected")
		}
		d.finished = true
		return json.RawMessage(`{}`), nil
	case complianceRetrySQL:
		var p struct {
			Outcome string `json:"outcome"`
		}
		_ = json.Unmarshal(args[7].(json.RawMessage), &p)
		if p.Outcome == "heartbeat" {
			d.heartbeat++
			if d.leaseLost {
				return nil, errors.New("lease lost")
			}
			d.lease.ExpiresAt = time.Now().Add(time.Minute)
			return json.Marshal(map[string]any{"renewed": true, "generation": l.Generation, "attempt": l.Attempt, "lease_expires_at": d.lease.ExpiresAt})
		}
		d.retry = p.Outcome
		return json.RawMessage(`{}`), nil
	}
	return nil, errors.New("unexpected SQL")
}

type complianceRuntimeS3 struct {
	discoveryS3APIStub
	before func(context.Context)
	puts   int
}

func (s *complianceRuntimeS3) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.puts++
	if s.before != nil {
		s.before(ctx)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	s.body = body
	return s.discoveryS3APIStub.PutObject(ctx, in, opts...)
}
func complianceRuntimeFixture(t *testing.T) (workerRuntimeConfig, *complianceRuntimeDB, *complianceRuntimeS3, *complianceExportProductionClients) {
	t.Helper()
	env := complianceRuntimeEnvironment()
	env["ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"] = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	config, err := loadWorkerRuntimeConfig(mapLookup(env))
	if err != nil {
		t.Fatal(err)
	}
	l := complianceRuntimeLease(t)
	db := &complianceRuntimeDB{lease: l, snapshot: complianceSnapshotFixture(t, l)}
	api := &complianceRuntimeS3{}
	clients := &complianceExportProductionClients{writer: api, transport: &http.Transport{}, identity: &runtimeIdentityStub{account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/compliance-export-worker/zasp-compliance-export"}, credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture", SessionToken: "fixture", CanExpire: true, Expires: time.Now().Add(time.Hour)}, nil
	})}
	return config, db, api, clients
}

func TestComplianceRuntimeComposedLifecycle(t *testing.T) {
	for _, mode := range []string{"complete", "cancel", "lease_loss", "revoked", "close", "capture_failure"} {
		t.Run(mode, func(t *testing.T) {
			config, db, api, clients := complianceRuntimeFixture(t)
			db.captureFailure = mode == "capture_failure"
			deps, err := composeComplianceExportWorkerRuntime(context.Background(), config, db, clients)
			if err != nil {
				t.Fatal(err)
			}
			defer deps.Close()
			runtime := deps.Processor.(*complianceExportRuntime)
			runtime.processor.heartbeat = 5 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			api.before = func(c context.Context) {
				close(entered)
				switch mode {
				case "cancel", "close":
					<-c.Done()
				case "lease_loss":
					db.mu.Lock()
					db.leaseLost = true
					db.mu.Unlock()
					<-c.Done()
				case "revoked":
					db.mu.Lock()
					db.revoked = true
					db.mu.Unlock()
				case "complete":
					time.Sleep(15 * time.Millisecond)
				}
			}
			done := make(chan struct{})
			var runErr error
			go func() { runErr = deps.Processor.RunOnce(ctx); close(done) }()
			failBeforeUpload := func(reason string) {
				db.mu.Lock()
				defer db.mu.Unlock()
				t.Fatalf("%s: claims=%d captures=%d prepares=%d heartbeats=%d retry=%q", reason, db.claims, db.captures, db.prepares, db.heartbeat, db.retry)
			}
			select {
			case <-entered:
			case <-done:
				// Both channels may be closed after a successful upload. Observe
				// upload entry before classifying an early worker return.
				select {
				case <-entered:
				default:
					if mode != "capture_failure" {
						failBeforeUpload("worker returned before upload")
					}
				}
			case <-time.After(time.Second):
				failBeforeUpload("upload not reached within unchanged one-second test bound")
			}
			if mode == "capture_failure" {
				select {
				case <-done:
				default:
					t.Fatal("capture failure reached upload before joining")
				}
				db.mu.Lock()
				defer db.mu.Unlock()
				if runErr == nil || db.finished || db.claims != 1 || db.captures != 1 || db.prepares != 0 || api.puts != 0 || db.retry != "source_failed" {
					t.Fatal("pre-upload failure crossed a prepare/upload/finish boundary")
				}
				return
			}
			if mode == "cancel" {
				cancel()
			}
			if mode == "close" {
				if err := deps.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
				err = runErr
			case <-time.After(2 * time.Second):
				t.Fatal("worker/heartbeat did not join")
			}
			db.mu.Lock()
			defer db.mu.Unlock()
			if (err == nil) != (mode == "complete") || db.finished != (mode == "complete") {
				t.Fatalf("mode=%s finished=%v err=%v", mode, db.finished, err)
			}
			if db.captures != 1 || db.prepares != 1 || api.puts != 1 {
				t.Fatalf("wrong render/upload lifecycle %+v puts=%d", db, api.puts)
			}
			if mode == "complete" && (db.heartbeat == 0 || !strings.Contains(string(api.body), "definition_only")) {
				t.Fatal("missing heartbeat or real formatter")
			}
			if mode != "complete" && mode != "lease_loss" && db.retry != "unknown" {
				t.Fatalf("uncertain upload released capacity: %s", db.retry)
			}
		})
	}
}
