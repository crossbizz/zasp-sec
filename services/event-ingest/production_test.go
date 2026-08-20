package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestLoadProductionIngestConfigRequiresExactAuthority(t *testing.T) {
	values := validProductionIngestEnvironment()
	config, err := loadProductionIngestConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if config.DatabaseURL != values["ZASP_DATABASE_URL"] || config.Region != "us-west-2" || config.RoleARN != values["ZASP_EVENT_INGEST_ROLE_ARN"] || config.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" || config.Bucket != "zasp-runtime-prod" || config.ExpectedBucketOwner != "123456789012" || config.KMSKeyARN != values["ZASP_RUNTIME_RAW_KMS_KEY_ARN"] || config.MaximumBytes != 64<<20 || config.OperationTimeout != 10*time.Second || config.ShutdownTimeout != 20*time.Second {
		t.Fatalf("config=%#v", config)
	}
	for _, key := range []string{"ZASP_DATABASE_URL", "ZASP_AWS_REGION", "ZASP_EVENT_INGEST_ROLE_ARN", "ZASP_EVENT_INGEST_WEB_IDENTITY_TOKEN_FILE", "ZASP_RUNTIME_RAW_BUCKET", "ZASP_RUNTIME_RAW_BUCKET_OWNER", "ZASP_RUNTIME_RAW_KMS_KEY_ARN", "ZASP_EVENT_INGEST_MAX_BYTES", "ZASP_EVENT_INGEST_OPERATION_TIMEOUT", "ZASP_EVENT_INGEST_SHUTDOWN_TIMEOUT"} {
		t.Run(key, func(t *testing.T) {
			candidate := validProductionIngestEnvironment()
			candidate[key] = ""
			if _, err := loadProductionIngestConfig(func(name string) string { return candidate[name] }); !errors.Is(err, errRuntimeUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	for _, databaseURL := range []string{
		"postgres://zasp_runtime_ingest@postgres.internal/zasp",
		"postgres://zasp_runtime_ingest@postgres.internal/zasp?sslmode=disable",
		"postgres://zasp_runtime_ingest@postgres.internal/zasp?sslmode=require",
		"postgres://zasp_runtime_ingest@postgres.internal/zasp?sslmode=verify-full&application_name=event-ingest",
		"postgres://zasp_runtime_ingest@postgres.internal/zasp?sslmode=verify-full&sslmode=verify-full",
	} {
		t.Run(databaseURL, func(t *testing.T) {
			candidate := validProductionIngestEnvironment()
			candidate["ZASP_DATABASE_URL"] = databaseURL
			if _, err := loadProductionIngestConfig(func(name string) string { return candidate[name] }); !errors.Is(err, errRuntimeUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProductionIngestRuntimeGatesRequestsOnCombinedReadiness(t *testing.T) {
	readyErr := error(nil)
	called := 0
	handler := readinessGatedIngestHandler{ready: func(context.Context) error { return readyErr }, next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called++ })}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://ingest/internal/v1/runtime/events", nil)
	response := &recordingResponse{}
	handler.ServeHTTP(response, request)
	if called != 1 || response.status != 0 {
		t.Fatalf("ready called=%d status=%d", called, response.status)
	}
	readyErr = errors.New("database-secret")
	response = &recordingResponse{}
	handler.ServeHTTP(response, request)
	if called != 1 || response.status != http.StatusServiceUnavailable || response.header.Get("Cache-Control") != "no-store" || response.body == "" || response.body == "database-secret" {
		t.Fatalf("drift called=%d status=%d headers=%v body=%q", called, response.status, response.header, response.body)
	}
}

func TestProductionIngestRouterMountsOnlyPrivateV15Routes(t *testing.T) {
	repository := &productionIngestRepositoryStub{}
	handler, err := newProductionIngestRouter(repository, productionRawArtifactStub{}, 64<<20, func() time.Time { return time.Unix(1_800_000_000, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		want int
	}{
		{path: sensor.PrivateHeartbeatPath, want: http.StatusBadRequest},
		{path: "/internal/v1/runtime/events", want: http.StatusBadRequest},
		{path: "/", want: http.StatusNotFound},
		{path: "/healthz", want: http.StatusNotFound},
		{path: "/api/v1/sensors", want: http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, test.path, nil)
		handler.ServeHTTP(response, request)
		if response.Code != test.want || response.Header().Get("Cache-Control") != "no-store" && test.want != http.StatusNotFound {
			t.Fatalf("%s status=%d headers=%v body=%q", test.path, response.Code, response.Header(), response.Body.String())
		}
	}
}

type productionIngestRepositoryStub struct{}

func (*productionIngestRepositoryStub) Ready(context.Context) error { return nil }
func (*productionIngestRepositoryStub) Authenticate(context.Context, *sensor.TokenCredential) (runtimeevent.IngestAuthority, error) {
	return runtimeevent.IngestAuthority{}, runtimeevent.ErrProductionIngestDenied
}
func (*productionIngestRepositoryStub) Reserve(context.Context, *sensor.TokenCredential, runtimeevent.IngestReserveRequest) (runtimeevent.IngestReservation, error) {
	return runtimeevent.IngestReservation{}, runtimeevent.ErrProductionIngest
}
func (*productionIngestRepositoryStub) Finalize(context.Context, *sensor.TokenCredential, runtimeevent.IngestFinalizeRequest) (runtimeevent.IngestResult, error) {
	return runtimeevent.IngestResult{}, runtimeevent.ErrProductionIngest
}
func (*productionIngestRepositoryStub) RecordAuthenticatedHeartbeat(context.Context, *sensor.TokenCredential, sensor.PrivateHeartbeat) error {
	return sensor.ErrForbidden
}

type productionRawArtifactStub struct{}

func (productionRawArtifactStub) Put(context.Context, runtimeevent.RawArtifactPut) (runtimeevent.RawArtifact, error) {
	return runtimeevent.RawArtifact{}, runtimeevent.ErrProductionIngest
}

type recordingResponse struct {
	header http.Header
	status int
	body   string
}

func (response *recordingResponse) Header() http.Header {
	if response.header == nil {
		response.header = http.Header{}
	}
	return response.header
}
func (response *recordingResponse) WriteHeader(status int) { response.status = status }
func (response *recordingResponse) Write(value []byte) (int, error) {
	response.body += string(value)
	return len(value), nil
}

func validProductionIngestEnvironment() map[string]string {
	return map[string]string{
		"ZASP_DATABASE_URL":                         "postgres://zasp_runtime_ingest@postgres.internal/zasp?sslmode=verify-full",
		"ZASP_AWS_REGION":                           "us-west-2",
		"ZASP_EVENT_INGEST_ROLE_ARN":                "arn:aws:iam::123456789012:role/zasp-event-ingest",
		"ZASP_EVENT_INGEST_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"ZASP_RUNTIME_RAW_BUCKET":                   "zasp-runtime-prod",
		"ZASP_RUNTIME_RAW_BUCKET_OWNER":             "123456789012",
		"ZASP_RUNTIME_RAW_KMS_KEY_ARN":              "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
		"ZASP_EVENT_INGEST_MAX_BYTES":               "67108864",
		"ZASP_EVENT_INGEST_OPERATION_TIMEOUT":       "10s",
		"ZASP_EVENT_INGEST_SHUTDOWN_TIMEOUT":        "20s",
	}
}
