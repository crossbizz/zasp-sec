package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Explicit private composition only; no default constructor or handler uses it.
type SecurityAgentRelease61CompositionConfig struct {
	Worker, Action, Deployment, TestWorker JSONDatabase
	Store                                  artifactstore.ObjectReferencingArtifactStore
	Keys                                   policy.GatewayPolicyKeys
}

type SecurityAgentRelease61Composition struct {
	worker, action, deployment, test *securityAgentMultistepAdmissionRepository
	store                            artifactstore.ObjectReferencingArtifactStore
	keys                             policy.GatewayPolicyKeys
}

func NewSecurityAgentRelease61Composition(ctx context.Context, c SecurityAgentRelease61CompositionConfig) (*SecurityAgentRelease61Composition, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(c.Worker) || nilInterface(c.Action) || nilInterface(c.Deployment) || nilInterface(c.TestWorker) || nilInterface(c.Store) || !c.Keys.Valid() {
		return nil, ErrRepositoryConfiguration
	}
	f := &SecurityAgentRelease61Composition{worker: &securityAgentMultistepAdmissionRepository{c.Worker}, action: &securityAgentMultistepAdmissionRepository{c.Action}, deployment: &securityAgentMultistepAdmissionRepository{c.Deployment}, test: &securityAgentMultistepAdmissionRepository{c.TestWorker}, store: c.Store, keys: c.Keys}
	if err := f.Ready(ctx); err != nil {
		return nil, err
	}
	return f, nil
}

// Ready is repeated before every operation, not cached at construction.
func (f *SecurityAgentRelease61Composition) Ready(ctx context.Context) error {
	if f == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryOperation
	}
	if nilInterface(f.store) || !f.keys.Valid() {
		return ErrRepositoryConfiguration
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, entry := range []struct {
		lane string
		repo *securityAgentMultistepAdmissionRepository
	}{{"worker", f.worker}, {"action", f.action}, {"deployment", f.deployment}, {"test", f.test}} {
		if entry.repo == nil || nilInterface(entry.repo.database) {
			return ErrRepositoryConfiguration
		}
		raw, err := entry.repo.database.QueryJSON(bounded, `SELECT to_jsonb(zasp_sa_multistep_prior.orchestration_ready($1,$2,$3))`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), entry.lane)
		if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
			return ErrRepositoryUnavailable
		}
	}
	return nil
}

// ValidateSigningKey is a local preflight. It deliberately performs no
// readiness query, repository read or provider call.
func (f *SecurityAgentRelease61Composition) ValidateSigningKey(keyID string, key ed25519.PublicKey) error {
	if f == nil || nilInterface(f.store) || !f.keys.Contains(keyID, key) {
		return ErrRepositoryConfiguration
	}
	for _, repository := range []*securityAgentMultistepAdmissionRepository{f.worker, f.action, f.deployment, f.test} {
		if repository == nil || nilInterface(repository.database) {
			return ErrRepositoryConfiguration
		}
	}
	return nil
}

func (f *SecurityAgentRelease61Composition) invoke(ctx context.Context, call func(context.Context) (json.RawMessage, error)) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := f.Ready(bounded); err != nil {
		return nil, err
	}
	return call(bounded)
}

func (f *SecurityAgentRelease61Composition) State(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.worker.orchestrationState(ctx, q) })
}
func (f *SecurityAgentRelease61Composition) Progress(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.worker.transition(ctx, q) })
}
func (f *SecurityAgentRelease61Composition) Stop(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	var operation struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(q, &operation) != nil || operation.Operation != "stop" {
		return nil, ErrRepositoryOperation
	}
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.worker.transition(ctx, q) })
}
func (f *SecurityAgentRelease61Composition) Application(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.action.application(ctx, q, f.keys) })
}
func (f *SecurityAgentRelease61Composition) Deployment(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.deployment.deployment(ctx, q, f.keys) })
}
func (f *SecurityAgentRelease61Composition) TestAction(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.worker.testAction(ctx, q) })
}
func (f *SecurityAgentRelease61Composition) TestDispatch(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.test.testDispatch(ctx, q, f.store) })
}
func (f *SecurityAgentRelease61Composition) TestSettle(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.test.testSettle(ctx, q, f.store) })
}
func (f *SecurityAgentRelease61Composition) TestUncertain(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.test.testUncertain(ctx, q) })
}
func (f *SecurityAgentRelease61Composition) TestReconcile(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.worker.testReconcileUncertain(ctx, q) })
}
func (f *SecurityAgentRelease61Composition) Cleanup(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) { return f.action.cleanup(ctx, q, f.keys) })
}
func (f *SecurityAgentRelease61Composition) CleanupDeployment(ctx context.Context, q json.RawMessage) (json.RawMessage, error) {
	return f.invoke(ctx, func(ctx context.Context) (json.RawMessage, error) {
		return f.deployment.cleanupDeployment(ctx, q, f.keys)
	})
}
