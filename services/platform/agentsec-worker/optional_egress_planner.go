package main

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func optionalPlannerEgressFlag(value string) (bool, error) {
	switch value {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errWorkerConfiguration
	}
}

func validOptionalPlannerEgressProfile(enabled bool, pin string) bool {
	return !enabled && pin == "" || enabled && migrations.IsOptionalEgressProfileChecksum(pin)
}

func configureOptionalPlannerEgress(p *productionSecurityAgentPlanner, enabled bool, profilePin string) error {
	if p == nil || !validOptionalPlannerEgressProfile(enabled, profilePin) {
		return errRuntimeUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errRuntimeUnavailable
	}
	p.optionalEgressEnabled = enabled
	p.optionalEgressProfile = profilePin
	return nil
}

type optionalPlannerDispatchAdmission func(context.Context) error

func optionalPlannerEgressEnabled(p *productionSecurityAgentPlanner) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.optionalEgressEnabled
}

func optionalPlannerEgressProfile(p *productionSecurityAgentPlanner) string {
	if p == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.optionalEgressProfile
}

// A true switch result is only an off-switch admission, never new authority
// for model/backend/privacy/pricing. Those remain the sealed planner's job.
func admitOptionalPlannerEgress(ctx context.Context, p *productionSecurityAgentPlanner, admission optionalPlannerDispatchAdmission) error {
	if ctx == nil || ctx.Err() != nil || p == nil {
		return errWorkerExecution
	}
	p.mu.RLock()
	enabled, pin, closed, client := p.optionalEgressEnabled, p.optionalEgressProfile, p.closed, p.client
	p.mu.RUnlock()
	if closed {
		return errWorkerExecution
	}
	if !enabled {
		return nil
	}
	if !validOptionalPlannerEgressProfile(enabled, pin) {
		return authorization.ErrInvalid
	}
	if admission == nil {
		return authorization.ErrDenied
	}
	if err := admission(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errWorkerExecution
	}
	// The fresh gate consumed part of the original provider headroom. Never
	// start HTTP with less than the existing client deadline plus its margin.
	deadline, bounded := ctx.Deadline()
	if !bounded || client == nil || client.Timeout <= 0 {
		return errWorkerExecution
	}
	headroom := 31 * time.Second // Retain the original Temporal planner floor.
	if client.Timeout+time.Second > headroom {
		headroom = client.Timeout + time.Second
	}
	if !deadline.After(time.Now().Add(headroom)) {
		return errWorkerExecution
	}
	return nil
}

type optionalPlannerAuthorizer interface {
	AdmitOptionalPlannerDispatch(context.Context, authorization.WorkerOperation, json.RawMessage, string) error
}

type optionalPlannerDatabase interface {
	AdmitOptionalPlannerDispatch(context.Context, json.RawMessage, string) error
}

func admitBoundOptionalPlannerDispatch(ctx context.Context, authorizer optionalPlannerAuthorizer, start orchestration.StartRequest, family workerPlanningFamily, raw json.RawMessage, profilePin string) error {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(authorizer) || len(raw) > 4096 || !migrations.IsOptionalEgressProfileChecksum(profilePin) {
		return authorization.ErrInvalid
	}
	if _, err := orchestration.WorkflowID(start.Ref); err != nil || start.DefinitionVersion < 1 || start.DefinitionVersion > 1000000 || !redTeamLinkedDigestPattern.MatchString(start.InputDigest) {
		return authorization.ErrInvalid
	}
	var operation authorization.WorkerOperation
	switch family {
	case workerPlanningOrdered68:
		operation = "ordered68.planning.start"
	case workerPlanningTest74:
		operation = "test74.planning.start"
	case workerPlanningFinding:
		operation = "finding.planning.start"
	default:
		return authorization.ErrInvalid
	}
	fields, closed := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "definition_version", "operation", "payload")
	expected := temporalStartFields(start)
	delete(expected, "input_digest")
	if !closed {
		return authorization.ErrInvalid
	}
	for key, value := range expected {
		encoded, err := json.Marshal(value)
		if err != nil || !bytes.Equal(bytes.TrimSpace(fields[key]), encoded) {
			return authorization.ErrInvalid
		}
	}
	if !bytes.Equal(bytes.TrimSpace(fields["operation"]), []byte(`"start"`)) {
		return authorization.ErrInvalid
	}
	payload, closed := securityAgentOrderedJSONObject(fields["payload"])
	if !closed || len(payload) != 0 {
		return authorization.ErrInvalid
	}
	return authorizer.AdmitOptionalPlannerDispatch(ctx, operation, bytes.Clone(raw), profilePin)
}

func (d *workerFindingPlanningDatabase) AdmitOptionalPlannerDispatch(ctx context.Context, raw json.RawMessage, profilePin string) error {
	if d == nil || ctx == nil {
		return authorization.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return admitBoundOptionalPlannerDispatch(ctx, d.forward, d.start, d.family, raw, profilePin)
}

func optionalTemporalPlannerAdmission(db any, identity map[string]any, profilePin string) optionalPlannerDispatchAdmission {
	gate, ok := db.(optionalPlannerDatabase)
	if !ok || nilWorkerDependency(gate) {
		return nil
	}
	request := make(map[string]any, len(identity)+2)
	for key, value := range identity {
		request[key] = value
	}
	request["operation"], request["payload"] = "start", map[string]any{}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil
	}
	return func(ctx context.Context) error {
		return gate.AdmitOptionalPlannerDispatch(ctx, bytes.Clone(raw), profilePin)
	}
}
