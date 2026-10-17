package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayinstallationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGatewayInstallationConfigClosedActivation(t *testing.T) {
	for _, name := range []string{"legacy", "disabled_empty", "disabled_pin", "invalid_flag", "enabled_missing_pin", "enabled_unknown_pin"} {
		t.Run(name, func(t *testing.T) {
			v := map[string]string{"ZASP_DATABASE_URL": "postgresql://gateway_control@database.internal:5432/zasp?sslmode=verify-full", "ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES": "16384", "ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT": "3s", "ZASP_GATEWAY_CONTROL_READINESS_TTL": "30s", "ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT": "10s"}
			switch name {
			case "disabled_empty":
				v["ZASP_GATEWAY_INSTALLATION_ACK_ENABLED"] = "false"
			case "disabled_pin":
				v["ZASP_GATEWAY_INSTALLATION_PROFILE_CHECKSUM"] = "unexpected"
			case "invalid_flag":
				v["ZASP_GATEWAY_INSTALLATION_ACK_ENABLED"] = "TRUE"
			case "enabled_missing_pin":
				v["ZASP_GATEWAY_INSTALLATION_ACK_ENABLED"] = "true"
			case "enabled_unknown_pin":
				v["ZASP_GATEWAY_INSTALLATION_ACK_ENABLED"] = "true"
				v["ZASP_GATEWAY_INSTALLATION_PROFILE_CHECKSUM"] = "unexpected"
			}
			_, e := loadProductionControlConfig(func(k string) string { return v[k] })
			want := name == "legacy" || name == "disabled_empty"
			if (e == nil) != want {
				t.Fatalf("err=%v accepted=%v", e, want)
			}
		})
	}
}

type installationFactoryRepository struct {
	controlRepositoryStub
	pin          string
	installation *installationCatalogFailure
}

func (r *installationFactoryRepository) InstallationRepositoryForProfile(pin string) (gatewaycontrol.InstallationRepository, error) {
	r.pin = pin
	return r.installation, nil
}

type installationCatalogFailure struct{ calls int }

func (s *installationCatalogFailure) InstallationReady(context.Context) error {
	s.calls++
	return errors.New("own catalog not installed")
}
func (s *installationCatalogFailure) RecordInstallation(context.Context, string, []byte) (wire.Receipt, error) {
	return wire.Receipt{}, errors.New("must not record")
}

func TestGatewayInstallationProductionMountSurvivesReadinessCache(t *testing.T) {
	config := validProductionControlConfigFixture()
	config.InstallationACKEnabled = true
	config.InstallationProfileChecksum = migrations.GatewayInstallationProfileChecksum()
	own := &installationCatalogFailure{}
	repository := &installationFactoryRepository{installation: own}
	closed := 0
	dependencies, e := buildProductionControlDependenciesWithFactory(context.Background(), config, func(context.Context, string, time.Duration) (gatewaycontrol.Repository, func() error, error) {
		return repository, func() error { closed++; return nil }, nil
	}, func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) })
	if e != nil {
		t.Fatal(e)
	}
	defer dependencies.Close()
	if repository.pin != config.InstallationProfileChecksum || own.calls != 0 {
		t.Fatal("missing selection or own catalog poisoned startup")
	}
	request := httptest.NewRequest(http.MethodPost, gatewaycontrol.InstallationPath, strings.NewReader(`{}`))
	request.Header.Set("Content-Type", gatewaycontrol.JSONMediaType)
	response := httptest.NewRecorder()
	dependencies.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || own.calls != 1 {
		t.Fatalf("selected mount=%d own calls=%d", response.Code, own.calls)
	}
	if dependencies.Ready(context.Background()) != nil {
		t.Fatal("own catalog poisoned global readiness")
	}
	if closed != 0 {
		t.Fatal("live pool closed")
	}
}

func TestGatewayInstallationProductionConfigSelectsOnlyCompiledProfiles(t *testing.T) {
	for _, pin := range []string{migrations.GatewayInstallationProfileChecksum(), migrations.GatewayInstallationAuditProfileChecksum()} {
		v := map[string]string{"ZASP_DATABASE_URL": "postgresql://gateway_control@database.internal:5432/zasp?sslmode=verify-full", "ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES": "16384", "ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT": "3s", "ZASP_GATEWAY_CONTROL_READINESS_TTL": "30s", "ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT": "10s", "ZASP_GATEWAY_INSTALLATION_ACK_ENABLED": "true", "ZASP_GATEWAY_INSTALLATION_PROFILE_CHECKSUM": pin}
		c, e := loadProductionControlConfig(func(k string) string { return v[k] })
		if e != nil || !c.InstallationACKEnabled || c.InstallationProfileChecksum != pin {
			t.Fatalf("config=%#v err=%v", c, e)
		}
	}
}
