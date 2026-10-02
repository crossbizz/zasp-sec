package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func auditExportProductionConfigFixture(t *testing.T) (AuditExportHandlerConfiguration, *auditExportPolicyNoIO) {
	t.Helper()
	policy, _ := auditExportPolicyFixture(t)
	transport := &auditExportPolicyNoIO{}
	client := s3.New(s3.Options{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
	return AuditExportHandlerConfiguration{Storage: []AuditExportStorageConfiguration{{Policy: policy, Client: client}}, CursorSigningKey: []byte(strings.Repeat("k", 32)), ProviderTimeout: time.Second}, transport
}

type auditExportFactoryDatabase struct {
	*discoveryCallDatabase
	schemas  int
	deadline time.Time
	onSchema context.CancelFunc
}

func (database *auditExportFactoryDatabase) SchemaVersion(ctx context.Context) (string, error) {
	database.schemas++
	database.deadline, _ = ctx.Deadline()
	if database.onSchema != nil {
		database.onSchema()
	}
	return database.discoveryCallDatabase.SchemaVersion(ctx)
}

func TestAuditExportProductionFactoryCancellationDuringSchema(t *testing.T) {
	_, database, _, _ := auditExportRepositoryFixture(t)
	database.queries = nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	wrapper := &auditExportFactoryDatabase{discoveryCallDatabase: database, onSchema: cancel}
	config, transport := auditExportProductionConfigFixture(t)
	handler, err := NewAuditExportProductionHandler(ctx, wrapper, config)
	if handler != nil || !errors.Is(err, ErrRepositoryConfiguration) || wrapper.schemas != 1 || !wrapper.deadline.Equal(deadline) || len(database.queries) != 0 || transport.calls != 0 {
		t.Fatal("factory ignored caller deadline/cancellation or continued after schema response", err)
	}
}

func TestAuditExportProductionFactoryUsesDurableRepository(t *testing.T) {
	_, database, identity, input := auditExportRepositoryFixture(t)
	config, transport := auditExportProductionConfigFixture(t)
	handler, err := NewAuditExportProductionHandler(context.Background(), database, config)
	if err != nil {
		t.Fatal("valid production composition rejected", err)
	}
	request := workflowRequest(t, identity, testCorrelationID, "createAuditExport", nil, http.MethodPost, "/api/v1/audit-exports", "{}")
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", input.IdempotencyKey)
	request.Header.Set("X-CSRF-Token", identity.CSRFToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || database.query != postgresAuditExportCreateSQL || len(database.args) != 13 || transport.calls != 0 {
		t.Fatalf("durable create composition failed: %d %s", response.Code, response.Body.String())
	}
	var descriptor AuditExportDescriptor
	if json.Unmarshal(response.Body.Bytes(), &descriptor) != nil || descriptor.ID != input.ExportID || descriptor.Status != "queued" {
		t.Fatal("persisted replay identity lost")
	}
	// A warmed factory cannot bypass a later database capability failure.
	database.responses[postgresAuditExportReadySQL] = json.RawMessage(`false`)
	request = workflowRequest(t, identity, testCorrelationID, "getAuditExport", map[string]string{"id": input.ExportID}, http.MethodGet, "/api/v1/audit-exports/"+input.ExportID, "")
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || database.query != postgresAuditExportReadySQL || transport.calls != 0 {
		t.Fatal("factory cached authority or reached provider")
	}
}

func TestAuditExportProductionReadinessIsLive(t *testing.T) {
	_, database, _, _ := auditExportRepositoryFixture(t)
	config, transport := auditExportProductionConfigFixture(t)
	handler, err := NewAuditExportProductionHandler(context.Background(), database, config)
	if err != nil {
		t.Fatal(err)
	}
	database.queries = nil
	if err := handler.Ready(context.Background()); err != nil || len(database.queries) != 1 || database.query != postgresAuditExportReadySQL {
		t.Fatal("live readiness unavailable", err)
	}
	database.responses[postgresAuditExportReadySQL] = json.RawMessage(`false`)
	if err := handler.Ready(context.Background()); err == nil {
		t.Fatal("warmed handler cached readiness")
	}
	if transport.calls != 0 {
		t.Fatal("readiness reached provider")
	}
}

func TestAuditExportProductionFactoryRejectsInvalidDependencies(t *testing.T) {
	for _, kind := range []string{"nil context", "canceled", "nil database", "typed nil database", "key", "empty storage", "policy", "client", "timeout", "readiness"} {
		t.Run(kind, func(t *testing.T) {
			_, database, _, _ := auditExportRepositoryFixture(t)
			database.queries = nil
			wrapper := &auditExportFactoryDatabase{discoveryCallDatabase: database}
			config, transport := auditExportProductionConfigFixture(t)
			ctx := context.Background()
			var db JSONDatabase = wrapper
			switch kind {
			case "nil context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil database":
				db = nil
			case "typed nil database":
				db = (*auditExportFactoryDatabase)(nil)
			case "key":
				config.CursorSigningKey = nil
			case "empty storage":
				config.Storage = nil
			case "policy":
				config.Storage[0].Policy.Bucket = "invalid/"
			case "client":
				config.Storage[0].Client = nil
			case "timeout":
				config.ProviderTimeout = 0
			case "readiness":
				database.responses[postgresAuditExportReadySQL] = json.RawMessage(`false`)
			}
			if handler, err := NewAuditExportProductionHandler(ctx, db, config); handler != nil || !errors.Is(err, ErrRepositoryConfiguration) || transport.calls != 0 {
				t.Fatal("invalid production configuration accepted", err)
			}
			if kind != "readiness" && (wrapper.schemas != 0 || len(database.queries) != 0) {
				t.Fatal("invalid construction reached database")
			}
		})
	}
}
