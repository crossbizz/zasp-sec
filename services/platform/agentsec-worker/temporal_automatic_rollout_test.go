package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/sdk/client"
)

type automaticRolloutDatabase struct {
	automaticWorkerDatabase
	admitted bool
}

type rolloutInstalledDatabase struct {
	apiserver.JSONDatabase
	conn *pgx.Conn
}

func (d rolloutInstalledDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.conn.QueryRow(ctx, q, args...).Scan(&raw)
	return raw, err
}

type rolloutUnstartedClient struct{ client.Client }

// Actual registered executor SQL and the worker constructor's readiness hook.
// Absent/invalid readiness must fail before an SDK worker can use this client.
func TestAutomaticSelectorInstalledStartup(t *testing.T) {
	dsn := os.Getenv("ZASP_TEST77_ROLLOUT_DSN")
	if dsn == "" {
		t.Skip("owned installed fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	mode := os.Getenv("ZASP_TEST77_ROLLOUT_MODE")
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var principal string
	if err := conn.QueryRow(ctx, `SELECT session_user`).Scan(&principal); err != nil || principal != "rollout77_executor" {
		t.Fatal("wrong installed executor principal", principal, err)
	}
	t.Log("registered executor principal confirmed", mode)
	source := &temporalTestSelectorSource{session: temporalDiscoveryScheduleSource{dsn: dsn, timeout: 10 * time.Second}, automatic: mode != "absent"}
	var ref orchestration.TestSelectorRef
	if json.Unmarshal([]byte(os.Getenv("ZASP_TEST77_ROLLOUT_REF")), &ref) != nil || !ref.Valid() {
		t.Fatal("fixture ref")
	}
	if mode != "ready" {
		if err := source.Ready(ctx); err == nil {
			t.Fatal("unsafe selector readiness", mode)
		}
		if runtime, err := newTemporalSecurityAgentWorker(&rolloutUnstartedClient{}, "rollout-owned", &temporalSecurityAgentProduct{singleTestEnabled: true, testSelectorEnabled: true, automaticSourcesEnabled: mode != "absent"}, source.Ready, func() error { return nil }, time.Second, 1); err == nil || runtime != nil {
			t.Fatal("unsafe worker constructor", mode)
		}
		called := false
		if err := source.WithCurrentSelector(ctx, ref, func(orchestration.TestSelectorDesired) error { called = true; return nil }); err == nil || called {
			t.Fatal("unsafe current Schedule projection", mode)
		}
		return
	}
	if err := source.Ready(ctx); err != nil {
		t.Fatal("ready77 selector", err)
	}
	if err := source.WithCurrentSelector(ctx, ref, func(d orchestration.TestSelectorDesired) error {
		if !d.Enabled || d.Automatic {
			t.Fatal("omitted desired changed", d)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := &temporalSecurityAgentProduct{executor: rolloutInstalledDatabase{conn: conn}}
	if err := p.AdmitTestSelector(ctx, orchestration.TestSelectorStart{Ref: ref, Revision: 1}); err != nil {
		t.Fatal("omitted actual admission", err)
	}
}

func (d *automaticRolloutDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if strings.Contains(q, "zasp_temporal75.admit") {
		d.admitted = true
		return json.RawMessage(`{"created":0}`), nil
	}
	return d.automaticWorkerDatabase.QueryJSON(ctx, q, args...)
}

// A scheduled old Workflow must not run rule-blind75 when77 is absent/invalid.
func TestAutomaticSelectorAdmissionRollout(t *testing.T) {
	for _, mode := range []string{"absent", "invalid", "ready"} {
		t.Run(mode, func(t *testing.T) {
			db := &automaticRolloutDatabase{automaticWorkerDatabase: automaticWorkerDatabase{t: t, mode: mode}}
			p := &temporalSecurityAgentProduct{executor: db}
			r := workerAutomaticRef()
			err := p.AdmitTestSelector(context.Background(), orchestration.TestSelectorStart{Ref: orchestration.TestSelectorRef{OrganizationID: r.OrganizationID, WorkspaceID: r.WorkspaceID, EnvironmentID: r.EnvironmentID, DefinitionID: r.EventID}, Revision: 1})
			if mode == "ready" {
				if err != nil || !db.admitted {
					t.Fatal("ready77 omitted route", err, db.admitted)
				}
			} else if err == nil || db.admitted {
				t.Fatal("unsafe legacy selector admission", mode, err, db.admitted)
			}
		})
	}
}
