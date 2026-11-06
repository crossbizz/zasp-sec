package main

import (
	"context"
	"errors"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentDeviceAssociationProductionClosedSelection(t *testing.T) {
	// Late actual selected mount controls; no application RED claimed.
	for _, entry := range []struct{ name, pin string }{{"normal", migrations.AgentDeviceAssociationProfileChecksum()}, {"audit", migrations.AgentDeviceAssociationAuditProfileChecksum()}} {
		t.Run(entry.name+"_selected_mount", func(t *testing.T) {
			config := validProductionControlConfigFixture()
			config.AgentDeviceAssociationEnabled = true
			config.AgentDeviceAssociationProfileChecksum = entry.pin
			own := &associationOwnCatalog{}
			base := &associationControlRepository{own: own}
			closed := false
			dependencies, e := buildProductionControlDependenciesWithFactory(context.Background(), config, func(context.Context, string, time.Duration) (gatewaycontrol.Repository, func() error, error) {
				return base, func() error { closed = true; return nil }, nil
			}, func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) })
			if e != nil {
				t.Fatal(e)
			}
			defer dependencies.Close()
			if base.selected != entry.pin || own.calls != 0 {
				t.Fatal("selected capability lost or poisoned startup")
			}
			request := httptest.NewRequest(http.MethodPost, gatewaycontrol.AssociationAcceptPath, strings.NewReader(`{}`))
			request.Header.Set("Content-Type", gatewaycontrol.JSONMediaType)
			out := httptest.NewRecorder()
			dependencies.Handler.ServeHTTP(out, request)
			if out.Code != 503 || own.calls != 1 {
				t.Fatal("optional capability missing after original readiness cache")
			}
			if dependencies.Ready(context.Background()) != nil || closed {
				t.Fatal("own profile poisoned original health/pool")
			}
		})
	}

	for _, name := range []string{"legacy", "disabled_empty", "disabled_pin", "invalid_flag", "missing_pin", "unknown_pin"} {
		t.Run(name, func(t *testing.T) {
			v := map[string]string{"ZASP_DATABASE_URL": "postgresql://gateway_control@database.internal:5432/zasp?sslmode=verify-full", "ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES": "16384", "ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT": "3s", "ZASP_GATEWAY_CONTROL_READINESS_TTL": "30s", "ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT": "10s"}
			switch name {
			case "disabled_empty":
				v["ZASP_AGENT_DEVICE_ASSOCIATION_ENABLED"] = "false"
			case "disabled_pin":
				v["ZASP_AGENT_DEVICE_ASSOCIATION_PROFILE_CHECKSUM"] = "unselected"
			case "invalid_flag":
				v["ZASP_AGENT_DEVICE_ASSOCIATION_ENABLED"] = "TRUE"
			case "missing_pin":
				v["ZASP_AGENT_DEVICE_ASSOCIATION_ENABLED"] = "true"
			case "unknown_pin":
				v["ZASP_AGENT_DEVICE_ASSOCIATION_ENABLED"] = "true"
				v["ZASP_AGENT_DEVICE_ASSOCIATION_PROFILE_CHECKSUM"] = "unknown"
			}
			_, e := loadProductionControlConfig(func(k string) string { return v[k] })
			if (e == nil) != (name == "legacy" || name == "disabled_empty") {
				t.Fatalf("err=%v", e)
			}
		})
	}
}

type associationControlRepository struct {
	controlRepositoryStub
	selected string
	own      *associationOwnCatalog
}

func (r *associationControlRepository) AssociationRepositoryForProfile(pin string) (gatewaycontrol.AssociationRepository, error) {
	r.selected = pin
	return r.own, nil
}

type associationOwnCatalog struct{ calls int }

func (s *associationOwnCatalog) AssociationReady(context.Context) error {
	s.calls++
	return errors.New("own catalog missing")
}
func (*associationOwnCatalog) AcceptAgentDevice(context.Context, []byte, wire.DeviceBinding) (wire.AcceptResponse, error) {
	return wire.AcceptResponse{}, errors.New("must not accept")
}
