package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type automaticWorkerDatabase struct {
	apiserver.JSONDatabase
	t       *testing.T
	mode    string
	queries []string
	page    json.RawMessage
}

func (d *automaticWorkerDatabase) QueryJSON(ctx context.Context, sql string, args ...any) (json.RawMessage, error) {
	d.queries = append(d.queries, sql)
	if strings.Contains(sql, "to_regnamespace") {
		switch d.mode {
		case "absent":
			return json.RawMessage(`false`), nil
		case "probe_error":
			return nil, errors.New("probe outage")
		case "null_probe":
			return json.RawMessage(`null`), nil
		}
		return json.RawMessage(`true`), nil
	}
	if strings.Contains(sql, "executor_ready") {
		require.Equal(d.t, []any{migrations.TemporalAutomaticSourcesChecksum(), migrations.TemporalAutomaticSourcesFingerprint()}, args)
		switch d.mode {
		case "invalid":
			return json.RawMessage(`false`), nil
		case "ready_error":
			return nil, errors.New("catalog outage")
		case "null_ready":
			return json.RawMessage(`null`), nil
		}
		return json.RawMessage(`true`), nil
	}
	if strings.Contains(sql, "dispatch_page") || strings.Contains(sql, "catchup_definition") {
		deadline, ok := ctx.Deadline()
		require.True(d.t, ok)
		require.LessOrEqual(d.t, time.Until(deadline), 25*time.Second)
		var body map[string]json.RawMessage
		require.NoError(d.t, json.Unmarshal([]byte(args[0].(string)), &body))
		require.NotContains(d.t, body, "retry", "Workflow-only retry state must not expand the closed SQL contract")
		require.Contains(d.t, body, "after", "empty cursor must be explicit for closed SQL")
		return d.page, nil
	}
	d.t.Fatalf("unexpected automatic worker statement %s", sql)
	return nil, errors.New("unexpected")
}
func TestAutomaticSourceRuntimeCapabilityFailsClosed(t *testing.T) {
	for _, mode := range []string{"ready", "absent", "invalid", "probe_error", "ready_error", "null_probe", "null_ready"} {
		t.Run(mode, func(t *testing.T) {
			db := &automaticWorkerDatabase{t: t, mode: mode}
			installed, err := automaticSourcesAvailable(context.Background(), db)
			if mode == "ready" || mode == "absent" {
				require.NoError(t, err)
				require.Equal(t, mode == "ready", installed)
			} else {
				require.Error(t, err)
				require.False(t, installed)
			}
			for _, q := range db.queries {
				require.NotContains(t, q, "temporal75")
			}
		})
	}
}
func workerAutomaticRef() orchestration.AutomaticSourceRef {
	return orchestration.AutomaticSourceRef{OrganizationID: "pid_f0773000-0000-4000-8000-000000000001", WorkspaceID: "pid_f0773000-0000-4000-8000-000000000002", EnvironmentID: "pid_f0773000-0000-4000-8000-000000000003", EventID: "pid_f0773000-0000-4000-8000-000000000004"}
}
func TestAutomaticSourceProductPagesPreserveClosedSQLAndBudget(t *testing.T) {
	for _, catchup := range []bool{false, true} {
		db := &automaticWorkerDatabase{t: t, page: json.RawMessage(`{"after":"","more":false,"retry":false,"scanned":0,"admitted":0}`)}
		p := &temporalSecurityAgentProduct{executor: db, automaticSourcesEnabled: true}
		ref := workerAutomaticRef()
		var page orchestration.AutomaticPage
		var err error
		if catchup {
			page, err = p.AutomaticCatchupPage(context.Background(), orchestration.AutomaticCatchupStart{Ref: orchestration.TestSelectorRef{OrganizationID: ref.OrganizationID, WorkspaceID: ref.WorkspaceID, EnvironmentID: ref.EnvironmentID, DefinitionID: ref.EventID}, Revision: 1, Retry: true})
		} else {
			page, err = p.AutomaticSourcePage(context.Background(), orchestration.AutomaticSourceStart{Ref: ref, Retry: true})
		}
		require.NoError(t, err)
		require.Zero(t, page.Scanned)
		db.page = json.RawMessage(`{"after":"","more":false,"retry":false,"scanned":26,"admitted":0}`)
		_, err = p.AutomaticSourcePage(context.Background(), orchestration.AutomaticSourceStart{Ref: ref})
		require.Error(t, err)
		p.automaticSourcesEnabled = false
		before := len(db.queries)
		_, err = p.AutomaticSourcePage(context.Background(), orchestration.AutomaticSourceStart{Ref: ref})
		require.Error(t, err)
		require.Len(t, db.queries, before)
	}
}

type blockingAutomaticProduct struct{ entered, release chan struct{} }

func (p *blockingAutomaticProduct) AutomaticSourcePage(context.Context, orchestration.AutomaticSourceStart) (orchestration.AutomaticPage, error) {
	close(p.entered)
	<-p.release
	return orchestration.AutomaticPage{}, nil
}
func (p *blockingAutomaticProduct) AutomaticCatchupPage(context.Context, orchestration.AutomaticCatchupStart) (orchestration.AutomaticPage, error) {
	return orchestration.AutomaticPage{}, nil
}
func TestAutomaticSourceRuntimeCloseRetainsBorrowedClients(t *testing.T) {
	p := &blockingAutomaticProduct{make(chan struct{}), make(chan struct{})}
	a := &orchestration.AutomaticActivities{Product: p}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		_, _ = a.Source(context.Background(), orchestration.AutomaticSourceStart{Ref: workerAutomaticRef()})
	}()
	<-p.entered
	w := &temporalLifecycleWorker{release: make(chan struct{})}
	close(w.release)
	var closed atomic.Int32
	r := &temporalSecurityAgentRuntime{worker: w, activities: &orchestration.Activities{}, automaticActivities: a, ready: func(context.Context) error { return nil }, closeClients: func() error { closed.Add(1); return nil }, stopped: make(chan struct{}), timeout: 20 * time.Millisecond}
	require.Error(t, r.Close())
	require.Zero(t, closed.Load())
	_, err := a.Source(context.Background(), orchestration.AutomaticSourceStart{Ref: workerAutomaticRef()})
	require.Error(t, err)
	close(p.release)
	<-joined
	require.NoError(t, r.Close())
	require.EqualValues(t, 1, closed.Load())
}
