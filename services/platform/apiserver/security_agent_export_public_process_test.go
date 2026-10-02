package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/internal/exportfixture"
)

// Private parent/child envelopes are deleted after all children join. They
// contain local session/grant tokens and must never be copied into evidence.
type publicExportAPIRequest struct {
	DSN, Directory, Organization, Workspace, Environment, Actor string
	Method, Path, Body, Version, Key, Correlation, Checkpoint   string
}
type publicExportAPIResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

type publicExportWriteObserver struct {
	http.ResponseWriter
	HeaderWrites, BodyWrites, BodyBytes int
}

func (w *publicExportWriteObserver) WriteHeader(status int) {
	w.HeaderWrites++
	w.ResponseWriter.WriteHeader(status)
}
func (w *publicExportWriteObserver) Write(body []byte) (int, error) {
	w.BodyWrites++
	w.BodyBytes += len(body)
	return w.ResponseWriter.Write(body)
}
func (w *publicExportWriteObserver) beforeConsume() error {
	if w.HeaderWrites != 0 || w.BodyWrites != 0 || w.BodyBytes != 0 {
		return fmt.Errorf("HTTP output preceded committed grant consumption")
	}
	return nil
}

func TestSecurityAgentExportPublicConsumeWriteBoundary(t *testing.T) {
	for _, mode := range []string{"none", "header", "body"} {
		t.Run(mode, func(t *testing.T) {
			w := &publicExportWriteObserver{ResponseWriter: httptest.NewRecorder()}
			if mode == "header" {
				w.WriteHeader(http.StatusOK)
			}
			if mode == "body" {
				_, _ = w.Write([]byte("must not escape"))
			}
			if err := w.beforeConsume(); (err == nil) != (mode == "none") {
				t.Fatalf("consume checkpoint accepted pre-commit %s output: %v", mode, err)
			}
		})
	}
}

type publicExportAPIDatabase struct {
	*PostgresJSONDatabase
	directory, checkpoint string
	writes                *publicExportWriteObserver
}

func (d *publicExportAPIDatabase) SecurityAgentExportsWorkflowAvailable(ctx context.Context) (bool, error) {
	ready, err := d.SecurityAgentExportDefinitionsAvailable(ctx)
	if err != nil || !ready {
		return false, err
	}
	return d.SecurityAgentExportsAvailable(ctx) // Only external worker health is controlled.
}

func (d *publicExportAPIDatabase) QueryJSON(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	raw, err := d.PostgresJSONDatabase.QueryJSON(ctx, query, args...)
	if err != nil {
		return raw, err
	}
	stop := d.checkpoint == "A" && query == postgresSecurityAgentManualRunSQL ||
		d.checkpoint == "C" && strings.Contains(query, "decide_approval(") ||
		d.checkpoint == "H-consume" && strings.Contains(query, "zasp_sa_export_grant(") && len(args) > 10 && args[10] == "consume"
	if stop {
		if d.checkpoint == "H-consume" {
			if d.writes == nil {
				return nil, fmt.Errorf("consume write observer absent")
			}
			observed, _ := json.Marshal(map[string]int{"header_writes": d.writes.HeaderWrites, "body_writes": d.writes.BodyWrites, "body_bytes": d.writes.BodyBytes})
			if err := os.WriteFile(filepath.Join(d.directory, "H-consume-writes.json"), observed, 0600); err != nil {
				return nil, err
			}
			if err := d.writes.beforeConsume(); err != nil {
				return nil, err
			}
		}
		// QueryJSON has scanned the real autocommitted result. The production
		// repository never receives it; this is an injected post-commit exit.
		if err := os.WriteFile(filepath.Join(d.directory, "checkpoint.json"), raw, 0600); err != nil {
			return nil, err
		}
		fmt.Fprintln(os.Stdout, "PUBLIC_EXPORT_CHECKPOINT "+d.checkpoint)
		os.Exit(86)
	}
	return raw, nil
}

func publicExportSession(actor string) string { return "public-export-restart-session-" + actor }

func TestSecurityAgentExportPublicAPIProcess(t *testing.T) {
	name := os.Getenv("ZASP_PUBLIC_EXPORT_API_REQUEST")
	if name == "" {
		t.Skip("owned public restart parent only")
	}
	var in publicExportAPIRequest
	raw, err := os.ReadFile(name)
	if err != nil || json.Unmarshal(raw, &in) != nil || !filepath.IsAbs(in.Directory) || filepath.Clean(in.Directory) != in.Directory || !strings.HasPrefix(filepath.Base(in.Directory), "zasp-public-export-restart-") || filepath.Dir(name) != in.Directory {
		t.Fatal("invalid owned API request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(in.DSN)
	if err != nil || config.Host != "127.0.0.1" || config.User != "security_agent_v33_api_login" || config.Database != "postgres" || config.Password != "" {
		t.Fatal("owned API database refused")
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("owned API database unavailable")
	}
	defer conn.Close(context.Background())
	native, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: conn})
	if err != nil {
		t.Fatal(err)
	}
	db := &publicExportAPIDatabase{PostgresJSONDatabase: native, directory: in.Directory, checkpoint: in.Checkpoint}
	repo, err := NewSecurityAgentPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	parse := func(value string) domain.ProductID {
		id, err := domain.ParseProductID(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	identity.Scope, err = domain.NewScope(parse(in.Organization), parse(in.Workspace), parse(in.Environment))
	if err != nil {
		t.Fatal(err)
	}
	identity.PrincipalID = parse(in.Actor)
	identity.Permissions = []string{"view", "manage_workflows", "manage_identity", "view_audit"}
	now := time.Now().UTC().Truncate(time.Microsecond)
	identity.FreshAuthenticated, identity.FreshAuthExpiresAt = true, now.Add(4*time.Minute)
	definitions, err := newWorkflowHTTPHandler(repo, securityAgentTestSigningKey, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	public, err := NewSecurityAgentPublicHTTPHandler(repo, definitions, SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return now }, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	store, err := exportfixture.Open(exportfixture.Config{Directory: filepath.Join(in.Directory, "export-store"), Bucket: "zasp-compliance-exports", Owner: "123456789012", KMSKey: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", MaximumBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	provider := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://controlled.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, Retryer: aws.NopRetryer{}, HTTPClient: &http.Client{Timeout: 5 * time.Second, Transport: store.Transport(exportfixture.Options{ReadOnly: true})}})
	exports, err := NewSecurityAgentExportProductionHandler(ctx, db, ComplianceHandlerConfiguration{Bucket: "zasp-compliance-exports", ExpectedBucketOwner: "123456789012", KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111", ProviderTimeout: 5 * time.Second, Client: provider})
	if err != nil || exports == nil {
		t.Fatal("mounted export retrieval unavailable", err)
	}
	router, err := NewCompositionWithSecurityAgentExports(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: public, Connector: handlerResponse("connector")}, nil, nil, exports)
	if err != nil {
		t.Fatal(err)
	}
	r := workflowRequest(t, identity, in.Correlation, "", nil, in.Method, in.Path, in.Body)
	r = r.WithContext(context.WithValue(r.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
	r = r.WithContext(func() context.Context {
		deadline, _ := ctx.Deadline()
		bounded, done := context.WithDeadline(r.Context(), deadline)
		t.Cleanup(done)
		return bounded
	}())
	r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: publicExportSession(in.Actor)})
	r.Header.Set("Origin", "https://app.zasp.test")
	r.Header.Set("X-CSRF-Token", identity.CSRFToken)
	r.Header.Set(expectedScopeHeader, in.Organization+"/"+in.Workspace+"/"+in.Environment)
	r.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	if in.Version != "" {
		r.Header.Set("If-Match", in.Version)
	}
	if in.Key != "" {
		r.Header.Set("Idempotency-Key", in.Key)
	}
	w := httptest.NewRecorder()
	db.writes = &publicExportWriteObserver{ResponseWriter: w}
	router.ServeHTTP(db.writes, r)
	response, err := json.Marshal(publicExportAPIResponse{w.Code, w.Header(), w.Body.Bytes()})
	if err != nil || os.WriteFile(filepath.Join(in.Directory, "response.json"), response, 0600) != nil {
		t.Fatal("response persistence failed")
	}
	fmt.Fprintf(os.Stdout, "PUBLIC_EXPORT_RESPONSE %d\n", w.Code)
}
