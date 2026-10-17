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
)

type systemHealthIntegrationDatabase struct {
	refused     bool
	schemaReads int
	queries     int
}

func (d *systemHealthIntegrationDatabase) SchemaVersion(context.Context) (string, error) {
	d.schemaReads++
	if d.refused {
		return "", errors.New("private database failure")
	}
	return CoreSchemaVersion, nil
}
func (d *systemHealthIntegrationDatabase) QueryJSON(_ context.Context, q string, _ ...any) (json.RawMessage, error) {
	d.queries++
	switch q {
	case postgresWorkflowReceiptCleanupSQL:
		return json.RawMessage(`{"deleted":0}`), nil
	case postgresRevealGrantCleanupSQL:
		return json.RawMessage(`{"cleaned":0}`), nil
	default:
		return nil, errors.New("unexpected readiness query")
	}
}
func (*systemHealthIntegrationDatabase) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected write")
}

type systemHealthIntegrationProvider struct {
	liveCalls, localCalls int
	refused               bool
}

func (*systemHealthIntegrationProvider) Complete(context.Context, string, string) (SessionGrant, error) {
	return SessionGrant{}, errors.New("unexpected callback")
}
func (p *systemHealthIntegrationProvider) Ready(context.Context) error { p.localCalls++; return nil }
func (p *systemHealthIntegrationProvider) VerifyIdentityProvider(context.Context) error {
	p.liveCalls++
	if p.refused {
		return errors.New("private identity failure")
	}
	return nil
}

func TestSystemHealthProbeIntegrationRequiredStatesMatchActualComponents(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                       string
		dbRefused, identityRefused bool
	}{{"healthy", false, false}, {"required database failed", true, false}, {"required identity failed", false, true}, {"both required failed", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			db := &systemHealthIntegrationDatabase{refused: test.dbRefused}
			provider := &systemHealthIntegrationProvider{refused: test.identityRefused}
			handler := &identityHTTPHandler{version: "1.5.0", administration: &PostgresRepository{database: db, schema: CoreSchemaVersion}, provider: provider, now: func() time.Time { return now }}
			status := systemHealthIntegrationRequest(t, handler, context.Background(), "getSystemStatus", "/api/v1/system/status", true)
			components := systemHealthIntegrationRequest(t, handler, context.Background(), "listSystemComponents", "/api/v1/system/components", true)
			var summary struct {
				Healthy  bool      `json:"security_plane_healthy"`
				Optional bool      `json:"optional_degraded"`
				FreshAt  time.Time `json:"fresh_at"`
			}
			var page struct {
				Items []struct {
					ID       string    `json:"id"`
					Required bool      `json:"required"`
					State    string    `json:"state"`
					FreshAt  time.Time `json:"fresh_at"`
				} `json:"items"`
			}
			if status.Code != http.StatusOK || components.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &summary) != nil || json.Unmarshal(components.Body.Bytes(), &page) != nil || len(page.Items) != 2 {
				t.Fatal("actual health response failed")
			}
			observedHealthy := true
			seen := map[string]bool{}
			for _, c := range page.Items {
				if seen[c.ID] || !c.Required || c.FreshAt != now {
					t.Fatal("actual observed component identity/requiredness/freshness changed")
				}
				seen[c.ID] = true
				switch c.ID {
				case "postgresql":
					if (c.State == "healthy") == test.dbRefused {
						t.Fatal("database observation changed")
					}
				case "identity-provider":
					if (c.State == "healthy") == test.identityRefused {
						t.Fatal("live identity observation changed")
					}
				default:
					t.Fatal("unobserved component invented")
				}
				if c.Required && c.State != "healthy" {
					observedHealthy = false
				}
			}
			if summary.Healthy != observedHealthy || summary.Optional || summary.FreshAt != now {
				t.Fatal("required observations were misclassified as optional or inconsistent with components")
			}
			if db.schemaReads != 2 || provider.liveCalls != 2 || provider.localCalls != 0 {
				t.Fatal("actual health probes duplicated, omitted or replaced by local readiness")
			}
			if strings.Contains(status.Body.String()+components.Body.String(), "private ") {
				t.Fatal("raw provider failure escaped")
			}
		})
	}
}

func TestSystemHealthProbeIntegrationRejectsInvalidAggregateAndMissingIdentity(t *testing.T) {
	now := time.Date(2026, 10, 17, 14, 0, 0, 0, time.UTC)
	for _, mode := range []string{"invalid version", "canceled", "missing identity", "unexpected query"} {
		t.Run(mode, func(t *testing.T) {
			db := &systemHealthIntegrationDatabase{}
			provider := &systemHealthIntegrationProvider{}
			handler := &identityHTTPHandler{version: "1.5.0", administration: &PostgresRepository{database: db, schema: CoreSchemaVersion}, provider: provider, now: func() time.Time { return now }}
			ctx := context.Background()
			target := "/api/v1/system/status"
			switch mode {
			case "invalid version":
				handler.version = ""
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unexpected query":
				target += "?invented=1"
			}
			response := systemHealthIntegrationRequest(t, handler, ctx, "getSystemStatus", target, mode != "missing identity")
			if response.Code == http.StatusOK || strings.Contains(response.Body.String(), `"security_plane_healthy"`) || strings.Contains(response.Body.String(), "private ") {
				t.Fatal("invalid or unauthorized health context emitted aggregate")
			}
			if (mode == "missing identity" || mode == "unexpected query") && (db.schemaReads != 0 || provider.liveCalls != 0) {
				t.Fatal("inadmissible request reached probes")
			}
		})
	}
}

func systemHealthIntegrationRequest(t *testing.T, handler *identityHTTPHandler, ctx context.Context, operation, path string, identity bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	if identity {
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, fixtureRequestIdentity(t)))
	}
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
