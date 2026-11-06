package main

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type bootstrapControlRepository struct {
	controlRepositoryStub
	selected string
	own      *bootstrapOwnCatalog
}

func (r *bootstrapControlRepository) EnrollmentRepositoryForProfile(pin string) (gatewaycontrol.EnrollmentRepository, error) {
	r.selected = pin
	return r.own, nil
}

type bootstrapOwnCatalog struct{ calls int }

func (s *bootstrapOwnCatalog) EnrollmentReady(context.Context) error {
	s.calls++
	return errors.New("not installed")
}
func (*bootstrapOwnCatalog) EnrollGateway(context.Context, []byte, []byte, []byte) (wire.Receipt, error) {
	return wire.Receipt{}, errors.New("not authorized")
}
func TestGatewayEnrollmentProductionClosedSelection(t *testing.T) {
	for _, name := range []string{"legacy", "disabled_empty", "disabled_pin", "bad_flag", "missing_pin", "unknown_pin"} {
		t.Run(name, func(t *testing.T) {
			v := map[string]string{"ZASP_DATABASE_URL": "postgresql://gateway_control@database.internal:5432/zasp?sslmode=verify-full", "ZASP_GATEWAY_CONTROL_MAX_BODY_BYTES": "16384", "ZASP_GATEWAY_CONTROL_OPERATION_TIMEOUT": "3s", "ZASP_GATEWAY_CONTROL_READINESS_TTL": "30s", "ZASP_GATEWAY_CONTROL_SHUTDOWN_TIMEOUT": "10s"}
			switch name {
			case "disabled_empty":
				v["ZASP_GATEWAY_ENROLLMENT_ENABLED"] = "false"
			case "disabled_pin":
				v["ZASP_GATEWAY_ENROLLMENT_PROFILE_CHECKSUM"] = "unselected"
			case "bad_flag":
				v["ZASP_GATEWAY_ENROLLMENT_ENABLED"] = "TRUE"
			case "missing_pin":
				v["ZASP_GATEWAY_ENROLLMENT_ENABLED"] = "true"
			case "unknown_pin":
				v["ZASP_GATEWAY_ENROLLMENT_ENABLED"] = "true"
				v["ZASP_GATEWAY_ENROLLMENT_PROFILE_CHECKSUM"] = "unknown"
			}
			c, e := loadProductionControlConfig(func(k string) string { return v[k] })
			if (e == nil) != (name == "legacy" || name == "disabled_empty") {
				t.Fatalf("config=%#v err=%v", c, e)
			}
		})
	}
	// Late source acceptance controls: these were not part of an executed RED.
	for _, entry := range []struct{ name, pin string }{{"normal", migrations.GatewayBootstrapProfileChecksum()}, {"audit", migrations.GatewayBootstrapAuditProfileChecksum()}} {
		t.Run(entry.name+"_selected_mount", func(t *testing.T) {
			config := validProductionControlConfigFixture()
			config.EnrollmentEnabled = true
			config.EnrollmentProfileChecksum = entry.pin
			own := &bootstrapOwnCatalog{}
			repo := &bootstrapControlRepository{own: own}
			closed := false
			dependencies, e := buildProductionControlDependenciesWithFactory(context.Background(), config, func(context.Context, string, time.Duration) (gatewaycontrol.Repository, func() error, error) {
				return repo, func() error { closed = true; return nil }, nil
			}, func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) })
			if e != nil {
				t.Fatal(e)
			}
			defer dependencies.Close()
			if repo.selected != entry.pin || own.calls != 0 {
				t.Fatal("optional capability lost or own readiness poisoned startup")
			}
			request := httptest.NewRequest(http.MethodPost, gatewaycontrol.EnrollmentPath, strings.NewReader(`{}`))
			request.Header.Set("Content-Type", gatewaycontrol.JSONMediaType)
			out := httptest.NewRecorder()
			dependencies.Handler.ServeHTTP(out, request)
			if out.Code != 503 || own.calls != 1 {
				t.Fatalf("selected mount=%d owncalls=%d", out.Code, own.calls)
			}
			if dependencies.Ready(context.Background()) != nil || closed {
				t.Fatal("optional catalog poisoned original readiness/pool")
			}
		})
	}
}
