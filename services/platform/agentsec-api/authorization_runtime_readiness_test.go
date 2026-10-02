package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type runtimeAuthorizationProbeDriver struct {
	t              *testing.T
	role, key      string
	calls          int
	fail           bool
	inventoryFail  bool
	inventoryCalls int
}

func (d *runtimeAuthorizationProbeDriver) QueryRow(ctx context.Context, q string, args ...any) apiserver.PostgresRow {
	if q == migrations.AuthorizationInventoryReadySourceSQL() {
		d.inventoryCalls++
		if d.role != "zasp_security_agent_api" || len(args) != 0 {
			d.t.Error("inventory readiness used another principal or query binding")
		}
		if _, ok := ctx.Deadline(); !ok {
			d.t.Error("inventory readiness lacks deadline")
		}
		return inventoryAuthorizationProbeRow{ready: !d.inventoryFail}
	}
	d.calls++
	if q != `SELECT zasp_authorization80.ready($1), zasp_authorization80_audit.production_ready($1,$2,$3,$4)` || len(args) != 4 || args[2] != d.key || args[3] != d.role {
		d.t.Errorf("wrong fixed runtime readiness query or binding")
	}
	if _, ok := ctx.Deadline(); !ok {
		d.t.Error("readiness lacks deadline")
	}
	return runtimeAuthorizationProbeRow{ready: !d.fail}
}
func (*runtimeAuthorizationProbeDriver) Exec(context.Context, string, ...any) error {
	return errors.New("unexpected write")
}
func (*runtimeAuthorizationProbeDriver) Close() error { return nil }
func (*runtimeAuthorizationProbeDriver) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected transaction")
}

type runtimeAuthorizationProbeRow struct{ ready bool }

type inventoryAuthorizationProbeRow struct{ ready bool }

func (r inventoryAuthorizationProbeRow) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("wrong inventory readiness result shape")
	}
	*dest[0].(*bool) = r.ready
	return nil
}

func (r runtimeAuthorizationProbeRow) Scan(dest ...any) error {
	if len(dest) != 2 {
		return errors.New("wrong readiness result shape")
	}
	*dest[0].(*bool), *dest[1].(*bool) = r.ready, r.ready
	return nil
}

func TestP7GuardedRuntimeReadinessCallback(t *testing.T) {
	for _, name := range []string{"healthy", "services refused", "discovery refused", "agent refused", "inventory refused", "previous refused"} {
		t.Run(name, func(t *testing.T) {
			key := strings.Repeat("a", 64)
			coreDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_discovery_api", key: key, fail: name == "discovery refused"}
			agentDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_security_agent_api", key: key, fail: name == "agent refused", inventoryFail: name == "inventory refused"}
			core, _ := apiserver.NewPostgresJSONDatabase(coreDriver)
			agent, _ := apiserver.NewPostgresJSONDatabase(agentDriver)
			defer core.Close()
			defer agent.Close()
			if core.RequireCurrentAuthorization() != nil || agent.RequireCurrentAuthorization() != nil {
				t.Fatal("enforcing fixture")
			}
			serviceCalls, previousCalls := 0, 0
			failure := errors.New("controlled readiness failure")
			callback := authorizationRuntimeReadiness(func(context.Context) error {
				serviceCalls++
				if name == "services refused" {
					return failure
				}
				return nil
			}, func(context.Context) error {
				previousCalls++
				if name == "previous refused" {
					return failure
				}
				return nil
			}, core, agent, key, time.Second)
			err := callback(context.Background())
			if (err == nil) != (name == "healthy") {
				t.Errorf("callback error=%v", err)
			}
			wantCore, wantAgent, wantPrevious := 1, 1, 1
			if name == "services refused" {
				wantCore, wantAgent, wantPrevious = 0, 0, 0
			}
			if name == "discovery refused" {
				wantAgent, wantPrevious = 0, 0
			}
			if name == "agent refused" {
				wantPrevious = 0
			}
			wantInventory := 1
			if name == "services refused" || name == "discovery refused" || name == "agent refused" {
				wantInventory = 0
			}
			if name == "inventory refused" {
				wantPrevious = 0
			}
			if agentDriver.inventoryCalls != wantInventory {
				t.Errorf("inventory readiness calls=%d want=%d", agentDriver.inventoryCalls, wantInventory)
			}
			if serviceCalls != 1 || coreDriver.calls != wantCore || agentDriver.calls != wantAgent || previousCalls != wantPrevious {
				t.Errorf("calls services=%d core=%d agent=%d previous=%d", serviceCalls, coreDriver.calls, agentDriver.calls, previousCalls)
			}
		})
	}
}

// This is the exact gate called before production composition. It does not
// construct the provider, service connections, or complete runtime.
func TestP7GuardedRuntimeReadinessStartupGate(t *testing.T) {
	for _, name := range []string{"healthy", "discovery refused", "agent refused", "inventory refused", "expired context", "invalid key"} {
		t.Run(name, func(t *testing.T) {
			key := strings.Repeat("a", 64)
			coreDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_discovery_api", key: key, fail: name == "discovery refused"}
			agentDriver := &runtimeAuthorizationProbeDriver{t: t, role: "zasp_security_agent_api", key: key, fail: name == "agent refused", inventoryFail: name == "inventory refused"}
			core, _ := apiserver.NewPostgresJSONDatabase(coreDriver)
			agent, _ := apiserver.NewPostgresJSONDatabase(agentDriver)
			defer core.Close()
			defer agent.Close()
			if core.RequireCurrentAuthorization() != nil || agent.RequireCurrentAuthorization() != nil {
				t.Fatal("enforcing fixture")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if name == "expired context" {
				cancel()
			}
			if name == "invalid key" {
				key = "invalid"
			}
			err := checkAuthorizationRuntimeReady(ctx, core, agent, key)
			if name == "healthy" && err != nil || name != "healthy" && !errors.Is(err, errRuntimeUnavailable) {
				t.Fatalf("startup gate error=%v", err)
			}
			wantCore, wantAgent := 1, 1
			if name == "discovery refused" {
				wantAgent = 0
			}
			if name == "expired context" || name == "invalid key" {
				wantCore, wantAgent = 0, 0
			}
			if coreDriver.calls != wantCore || agentDriver.calls != wantAgent {
				t.Fatalf("startup gate calls core=%d agent=%d", coreDriver.calls, agentDriver.calls)
			}
			wantInventory := 1
			if name == "discovery refused" || name == "agent refused" || name == "expired context" || name == "invalid key" {
				wantInventory = 0
			}
			if agentDriver.inventoryCalls != wantInventory {
				t.Errorf("inventory readiness calls=%d want=%d", agentDriver.inventoryCalls, wantInventory)
			}
		})
	}
}
