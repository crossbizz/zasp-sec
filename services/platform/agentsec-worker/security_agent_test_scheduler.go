package main

import (
	"context"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type existingTestScheduler struct {
	client  *existingTestClient
	store   existingTestArtifactReader
	gate    chan struct{}
	stopped chan struct{}
	mu      sync.Mutex
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
	// cursor is owned by the single gate holder; it is not authority.
	cursor domain.Scope
}

func newExistingTestScheduler(client *existingTestClient, store existingTestArtifactReader) (*existingTestScheduler, error) {
	if client == nil || nilWorkerDependency(store) || nilWorkerDependency(client.db) || client.now == nil || !workerIdentityPattern.MatchString(client.worker) {
		return nil, errRuntimeUnavailable
	}
	return &existingTestScheduler{client: client, store: store, gate: make(chan struct{}, 1), stopped: make(chan struct{})}, nil
}

func (p *existingTestScheduler) RunOnce(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.gate == nil {
		return errRuntimeUnavailable
	}
	select {
	case p.gate <- struct{}{}:
	case <-ctx.Done():
		return errRuntimeUnavailable
	case <-p.stopped:
		return errRuntimeUnavailable
	}
	defer func() { <-p.gate }()
	work, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errRuntimeUnavailable
	}
	done := make(chan struct{})
	p.cancel, p.done = cancel, done
	p.mu.Unlock()
	defer func() {
		cancel()
		p.mu.Lock()
		p.cancel, p.done = nil, nil
		close(done)
		p.mu.Unlock()
	}()
	scope, found, err := p.client.NextScope(work, p.cursor)
	if err == nil && !found && !p.cursor.IsZero() {
		scope, found, err = p.client.NextScope(work, domain.Scope{})
	}
	if err != nil || work.Err() != nil {
		return errRuntimeUnavailable
	}
	if !found {
		p.cursor = domain.Scope{}
		return nil
	}
	// Advance even if reconciliation fails, so other tenants get their turn.
	p.cursor = scope
	return p.client.ReconcileOne(work, scope, p.store)
}

func (p *existingTestScheduler) Close(ctx context.Context) error {
	if p == nil || ctx == nil || p.stopped == nil {
		return errRuntimeUnavailable
	}
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.stopped)
	}
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errRuntimeUnavailable
	}
}

// NextScope discovers work, not permission to mutate or invoke a target.
func (c *existingTestClient) NextScope(ctx context.Context, after domain.Scope) (domain.Scope, bool, error) {
	var zero domain.Scope
	if c == nil || !workerIdentityPattern.MatchString(c.worker) || !after.IsZero() && after.Validate() != nil {
		return zero, false, errRuntimeUnavailable
	}
	o, w, e := "", "", ""
	if !after.IsZero() {
		o, w, e = after.OrganizationID().String(), after.WorkspaceID().String(), after.EnvironmentID().String()
	}
	raw, err := c.query(ctx, "SELECT zasp_production_security_agent_existing_tests_reconcile_scopes($1,$2,$3,$4,$5,$6)", o, w, e, c.worker)
	if err != nil {
		return zero, false, errRuntimeUnavailable
	}
	var rows []struct {
		Organization string `json:"organization_id"`
		Workspace    string `json:"workspace_id"`
		Environment  string `json:"environment_id"`
	}
	if decodeRedTeamEvidenceJSON(redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2"}, raw, &rows) != nil || rows == nil || len(rows) > 1 {
		return zero, false, errRuntimeUnavailable
	}
	if len(rows) == 0 {
		return zero, false, nil
	}
	row := rows[0]
	org, eo := domain.ParseProductID(row.Organization)
	ws, ew := domain.ParseProductID(row.Workspace)
	env, ee := domain.ParseProductID(row.Environment)
	scope, es := domain.NewScope(org, ws, env)
	if eo != nil || ew != nil || ee != nil || es != nil || row.Organization+"/"+row.Workspace+"/"+row.Environment <= o+"/"+w+"/"+e {
		return zero, false, errRuntimeUnavailable
	}
	return scope, true, nil
}
