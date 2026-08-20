package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestLoadProductionControlConfigRequiresExactV15Authority(t *testing.T) {
	values := map[string]string{
		"ZASP_DATABASE_URL":                      "postgresql://gateway_control@database.internal:5432/zasp?sslmode=verify-full",
		"ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES":    "16384",
		"ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT": "3s",
		"ZASP_GATEWAY_CONTROL_READINESS_TTL":     "30s",
		"ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT":  "10s",
	}
	config, err := loadProductionControlConfig(func(key string) string { return values[key] })
	if err != nil || config.DatabaseURL != values["ZASP_DATABASE_URL"] || config.MaximumBodyBytes != 16*1024 || config.ReadinessTTL != 30*time.Second {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	for key, replacement := range map[string]string{
		"ZASP_DATABASE_URL":                      "postgresql://gateway_control@database.internal:5432/zasp?sslmode=disable",
		"ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES":    "999999",
		"ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT": "20ms",
		"ZASP_GATEWAY_CONTROL_READINESS_TTL":     "500ms",
		"ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT":  "0s",
	} {
		prior := values[key]
		values[key] = replacement
		if candidate, err := loadProductionControlConfig(func(name string) string { return values[name] }); err == nil || candidate.DatabaseURL != "" {
			t.Fatalf("key=%s candidate=%#v err=%v", key, candidate, err)
		}
		values[key] = prior
	}
}

func TestBuildProductionControlDependenciesCachesOnlySuccessfulReadinessAndClosesOnce(t *testing.T) {
	config := validProductionControlConfigFixture()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repository := &controlRepositoryStub{}
	closeCalls := 0
	var capturedURL string
	var capturedTimeout time.Duration
	dependencies, err := buildProductionControlDependenciesWithFactory(context.Background(), config, func(_ context.Context, databaseURL string, timeout time.Duration) (gatewaycontrol.Repository, func() error, error) {
		capturedURL, capturedTimeout = databaseURL, timeout
		return repository, func() error { closeCalls++; return nil }, nil
	}, func() time.Time { return now })
	if err != nil || dependencies.Handler == nil || dependencies.Ready == nil || dependencies.Close == nil || capturedURL != config.DatabaseURL || capturedTimeout != config.OperationTimeout {
		t.Fatalf("dependencies=%#v url=%q timeout=%s err=%v", dependencies, capturedURL, capturedTimeout, err)
	}
	for range 100 {
		if err := dependencies.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(http.MethodGet, gatewaycontrol.AuthorityPath, nil)
	response := httptest.NewRecorder()
	dependencies.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || repository.readyCalls != 1 {
		t.Fatalf("status=%d ready_calls=%d", response.Code, repository.readyCalls)
	}
	now = now.Add(31 * time.Second)
	repository.readyErr = errors.New("v15 drift")
	if err := dependencies.Ready(context.Background()); err == nil || repository.readyCalls != 2 {
		t.Fatalf("ready_calls=%d err=%v", repository.readyCalls, err)
	}
	if dependencies.Close() != nil || dependencies.Close() != nil || closeCalls != 1 {
		t.Fatalf("close_calls=%d", closeCalls)
	}
}

type controlRepositoryStub struct {
	readyCalls int
	readyErr   error
}

func (repository *controlRepositoryStub) Ready(context.Context) error {
	repository.readyCalls++
	return repository.readyErr
}

func (*controlRepositoryStub) Authority(context.Context, string) (gatewaycontrol.Authority, error) {
	return gatewaycontrol.Authority{}, errors.New("not configured")
}

func (*controlRepositoryStub) Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error) {
	return nil, errors.New("not configured")
}

func (*controlRepositoryStub) Record(context.Context, gatewaycontrol.DecisionEvent) error {
	return errors.New("not configured")
}

func validProductionControlConfigFixture() productionControlConfig {
	return productionControlConfig{
		DatabaseURL:      "postgresql://gateway_control@database.internal:5432/zasp?sslmode=verify-full",
		MaximumBodyBytes: 16 * 1024, OperationTimeout: 3 * time.Second, ReadinessTTL: 30 * time.Second, ShutdownTimeout: 10 * time.Second,
	}
}
