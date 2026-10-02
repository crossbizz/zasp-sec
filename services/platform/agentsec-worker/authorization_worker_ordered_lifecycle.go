package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"strings"
	"time"
)

func orderedLifecycleOperation(statement string, raw json.RawMessage, ref orchestration.RunRef) (authorization.WorkerOperation, error) {
	if len(raw) > 4096 {
		return "", authorization.ErrInvalid
	}
	var operation authorization.WorkerOperation
	fields := []string{"organization_id", "workspace_id", "environment_id", "run_id"}
	switch statement {
	case `SELECT zasp_temporal69.inspect($1::jsonb)`:
		operation = "ordered69.inspect"
		fields = append(fields, "definition_version", "input_digest")
	case `SELECT zasp_temporal69.stop($1::jsonb)`:
		operation = "ordered69.stop"
		fields = append(fields, "definition_version", "input_digest", "reason")
	case `SELECT zasp_temporal69.inspect_message($1::jsonb)`:
		operation = "ordered69.message"
		fields = append(fields, "event_id", "decision_id", "kind")
	default:
		return "", authorization.ErrInvalid
	}
	if _, ok := securityAgentOrderedClosedObject(raw, fields...); !ok {
		return "", authorization.ErrInvalid
	}
	var q struct {
		OrganizationID string `json:"organization_id"`
		WorkspaceID    string `json:"workspace_id"`
		EnvironmentID  string `json:"environment_id"`
		RunID          string `json:"run_id"`
		Version        int64  `json:"definition_version"`
		Digest         string `json:"input_digest"`
		Reason         string `json:"reason"`
		EventID        string `json:"event_id"`
		DecisionID     string `json:"decision_id"`
		Kind           string `json:"kind"`
	}
	if decodeStrictWorkerJSON(raw, &q) != nil || q.OrganizationID != ref.OrganizationID || q.WorkspaceID != ref.WorkspaceID || q.EnvironmentID != ref.EnvironmentID || q.RunID != ref.RunID {
		return "", authorization.ErrInvalid
	}
	for _, id := range []string{q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID} {
		if !validSecurityAgentPlannerProductID(id) {
			return "", authorization.ErrInvalid
		}
	}
	if operation == "ordered69.message" {
		if !validSecurityAgentPlannerProductID(q.EventID) || !validSecurityAgentPlannerProductID(q.DecisionID) || q.Kind != "approval" && q.Kind != "cancel" {
			return "", authorization.ErrInvalid
		}
	} else {
		if q.Version < 1 || q.Version > 1000000 || len(q.Digest) != 64 || strings.ToLower(q.Digest) != q.Digest {
			return "", authorization.ErrInvalid
		}
		if _, err := hex.DecodeString(q.Digest); err != nil {
			return "", authorization.ErrInvalid
		}
		if operation == "ordered69.stop" && q.Reason != "workflow_cancelled" && q.Reason != "workflow_deadline" && q.Reason != "workflow_failed" {
			return "", authorization.ErrInvalid
		}
	}
	return operation, nil
}

// Lifecycle observes or stops an already committed run; it never grants new
// forward effects. Current named workers use captured authority, including
// committed notifications after requester revocation or terminal completion.
func (p *temporalSecurityAgentProduct) lifecycleQuery(ctx context.Context, legacy apiserver.JSONDatabase, statement string, ref orchestration.RunRef, fields map[string]any) (json.RawMessage, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nil, authorization.ErrInvalid
	}
	if p.workerForward == nil && p.workerCompensation == nil {
		return temporalQuery(ctx, legacy, statement, fields)
	}
	if p.workerCompensation == nil {
		return nil, authorization.ErrInvalid
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return nil, authorization.ErrInvalid
	}
	operation, err := orderedLifecycleOperation(statement, raw, ref)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	decision, err := p.workerCompensation.Authorize(bounded, operation, raw)
	if err != nil {
		return nil, err
	}
	return p.workerCompensation.Execute(bounded, decision)
}
