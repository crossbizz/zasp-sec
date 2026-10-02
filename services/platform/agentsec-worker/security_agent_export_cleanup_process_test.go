package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/exportfixture"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func cleanupProcessFault(phase string, r exportfixture.Request) *exportfixture.Fault {
	if phase == "denied" {
		return &exportfixture.Fault{StatusCode: 403, Code: "AccessDenied"}
	}
	if phase == "generic404" {
		return &exportfixture.Fault{StatusCode: 404, Code: "NotFound"}
	}
	return nil
}

type cleanupProcessDatabase struct {
	*apiserver.PostgresJSONDatabase
	mu                             sync.Mutex
	Claims, Retries, Confirmations int
	Queries                        []string
}

func (d *cleanupProcessDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	raw, err := d.PostgresJSONDatabase.QueryJSON(ctx, q, args...)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Queries = append(d.Queries, strings.Split(strings.TrimPrefix(q, "SELECT public."), "(")[0])
	if err == nil {
		if q == complianceClaimSQL && string(raw) != "null" {
			d.Claims++
		}
		if q == complianceCleanupSQL {
			d.Confirmations++
		}
		if q == complianceRetrySQL && len(args) > 7 && string(args[7].(json.RawMessage)) != `{"outcome":"heartbeat"}` {
			d.Retries++
		}
	}
	return raw, err
}

// A fresh process owns the production cleanup runtime and registered login.
// Only SDK faults and the post-DELETE process exit are controlled.
func TestSecurityAgentExportCleanupWorkerProcess(t *testing.T) {
	directory := os.Getenv("ZASP_CLEANUP_DIRECTORY")
	if directory == "" {
		t.Skip("owned cleanup parent only")
	}
	phase := os.Getenv("ZASP_CLEANUP_PHASE")
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !strings.HasPrefix(filepath.Base(directory), "zasp-public-export-restart-") || !strings.Contains("|publish|blocked|delete-loss|held|denied|generic404|absent|done|", "|"+phase+"|") {
		t.Fatal("owned cleanup phase refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(os.Getenv("ZASP_CLEANUP_DSN"))
	if err != nil || cfg.ConnConfig.Host != "127.0.0.1" || cfg.ConnConfig.Database != "postgres" || cfg.ConnConfig.Password != "" {
		t.Fatal("owned registered database required")
	}
	cleanup := phase != "publish"
	login := "compliance_executor"
	if cleanup {
		login = "compliance_cleanup"
	}
	if cfg.ConnConfig.User != login {
		t.Fatal("registered cleanup login required")
	}
	cfg.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	native, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	db := &cleanupProcessDatabase{PostgresJSONDatabase: native}
	store, err := exportfixture.Open(exportfixture.Config{Directory: filepath.Join(directory, "export-store"), Bucket: "zasp-compliance-exports", Owner: "123456789012", KMSKey: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	options := exportfixture.Options{}
	if cleanup {
		options.Before = func(_ context.Context, r exportfixture.Request) *exportfixture.Fault {
			if r.Method != "GET" && r.Method != "DELETE" {
				return &exportfixture.Fault{Err: fmt.Errorf("cleanup issued forbidden %s", r.Method)}
			}
			return cleanupProcessFault(phase, r)
		}
	}
	if phase == "delete-loss" {
		options.After = func(_ context.Context, r exportfixture.Request) *exportfixture.Fault {
			if r.Method == "DELETE" && r.Status == 204 {
				data, _ := json.Marshal(r)
				if err := os.WriteFile(filepath.Join(directory, "cleanup-delete-checkpoint.json"), data, 0600); err != nil {
					return &exportfixture.Fault{Err: err}
				}
				fmt.Fprintln(os.Stdout, "PUBLIC_EXPORT_CHECKPOINT delete-loss")
				os.Exit(86)
			}
			return nil
		}
	}
	provider := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{}, HTTPClient: &http.Client{Timeout: 5 * time.Second, Transport: store.Transport(options)}})
	env := complianceRuntimeEnvironment()
	env["ZASP_BATCH_SIZE"] = "1"
	env["ZASP_WORKER_ID"] = fmt.Sprintf("cleanup-proof-%s-%d", phase, os.Getpid())
	role := "compliance-export-worker"
	if cleanup {
		role = "compliance-export-cleanup"
		env["ZASP_WORKER_MODE"] = "compliance-export-cleanup"
		env["ZASP_DATABASE_AUTHORITY"] = "zasp_compliance_cleanup"
		env["ZASP_COMPLIANCE_EXPORT_ROLE_ARN"] = "arn:aws:iam::123456789012:role/" + role
	}
	env["ZASP_COMPLIANCE_EXPORT_KMS_KEY_ARN"] = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
	config, err := loadWorkerRuntimeConfig(mapLookup(env))
	if err != nil {
		t.Fatal(err)
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
	runtime, err := composeComplianceExportWorkerRuntime(ctx, config, db, clients)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	err = runtime.Processor.RunOnce(ctx)
	if phase == "denied" || phase == "generic404" {
		if err == nil || db.Retries != 1 || db.Confirmations != 0 {
			t.Fatal("uncertain cleanup failed to retain retry duty", err)
		}
	} else if err != nil {
		t.Fatal("actual cleanup RunOnce", err)
	}
	db.mu.Lock()
	trace, _ := json.Marshal(map[string]any{"claims": db.Claims, "retries": db.Retries, "confirmations": db.Confirmations, "queries": db.Queries})
	db.mu.Unlock()
	if err := os.WriteFile(filepath.Join(directory, "cleanup-"+phase+".json"), trace, 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "PUBLIC_EXPORT_JOINED "+phase)
}

// If generic HTTP404 is mistaken for typed missing-version authority, cleanup
// would release durable accounting before absence is established.
func TestSecurityAgentExportCleanupResponseTaxonomy(t *testing.T) {
	for _, phase := range []string{"denied", "generic404", "absent"} {
		t.Run(phase, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			store, err := exportfixture.Create(exportfixture.Config{Directory: filepath.Join(directory, "store"), Bucket: "zasp-compliance-exports", Owner: "123456789012", KMSKey: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			sdk := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{}, HTTPClient: &http.Client{Transport: store.Transport(exportfixture.Options{Before: func(_ context.Context, r exportfixture.Request) *exportfixture.Fault {
				return cleanupProcessFault(phase, r)
			}})}})
			cleaner, err := s3driver.NewExportCleanup(sdk, s3driver.Config{Bucket: "zasp-compliance-exports", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20})
			if err != nil {
				t.Fatal(err)
			}
			lease := complianceRuntimeLease(t)
			ref, _ := domain.ParseEvidenceRef(lease.ExportID)
			key, _ := bucketlayout.ExportKey(lease.Scope, ref.ArtifactID())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = cleaner.DeleteExact(ctx, artifactstore.DriverLocator{Scope: lease.Scope, Reference: ref, Key: key, VersionID: "stored-v1"})
			if (err == nil) != (phase == "absent") {
				t.Fatalf("%s classified as confirmed absence: %v", phase, err)
			}
		})
	}
}
