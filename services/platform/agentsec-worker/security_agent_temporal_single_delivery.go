package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"time"
)

// Bound once during production startup, before the processor is exposed. SQL
// owns classification and acceptance; transport cannot grant execution rights.
func (p *redTeamProcessor) bindSingleTestDelivery(database apiserver.JSONDatabase, wake func(context.Context, orchestration.StartRequest) error) error {
	if p == nil || nilWorkerDependency(database) || wake == nil || p.ownedDelivery != nil {
		return errRuntimeUnavailable
	}
	p.ownedDelivery = func(ctx context.Context, delivery jobqueue.Delivery) (bool, error) {
		payload, ok := validRedTeamDelivery(delivery)
		if !ok {
			return false, errWorkerExecution
		}
		read, err := singleTestDeliveryQuery(ctx, database, "read", payload)
		if err != nil {
			return false, err
		}
		if !read.Owned {
			return false, nil
		}
		if read.Start.Ref.OrganizationID != delivery.Job.Scope.OrganizationID().String() || read.Start.Ref.WorkspaceID != delivery.Job.Scope.WorkspaceID().String() || read.Start.Ref.EnvironmentID != delivery.Job.Scope.EnvironmentID().String() {
			return true, errWorkerExecution
		}
		if !read.Terminal {
			if err := wake(ctx, *read.Start); err != nil {
				return true, err
			}
		}
		accepted, err := singleTestDeliveryQuery(ctx, database, "accept", payload)
		if err != nil {
			return true, err
		}
		if !accepted.Owned || accepted.Start == nil || *accepted.Start != *read.Start || accepted.EffectKey != read.EffectKey || accepted.DeliveryDigest != read.DeliveryDigest || accepted.AcceptedAt == nil {
			return true, errWorkerExecution
		}
		// A verified terminal transition may race a successful wake, but cannot
		// change the accepted workflow/effect/message identity.
		return true, nil
	}
	return nil
}

type singleTestDeliveryDecision struct {
	Owned          bool                        `json:"owned"`
	Start          *orchestration.StartRequest `json:"start"`
	Terminal       bool                        `json:"terminal"`
	EffectKey      string                      `json:"effect_key"`
	DeliveryDigest string                      `json:"delivery_digest"`
	AcceptedAt     *string                     `json:"accepted_at"`
}

func singleTestDeliveryQuery(ctx context.Context, database apiserver.JSONDatabase, op string, payload redTeamOutboxPayload) (singleTestDeliveryDecision, error) {
	var value singleTestDeliveryDecision
	raw, err := temporalQuery(ctx, database, `SELECT zasp_temporal74.delivery($1::jsonb)`, map[string]any{"operation": op, "message": payload})
	if err != nil {
		return value, err
	}
	var fields map[string]json.RawMessage
	if len(raw) > 8192 || decodeStrictWorkerJSON(raw, &value) != nil || json.Unmarshal(raw, &fields) != nil || fields["owned"] == nil {
		return value, errWorkerExecution
	}
	if !value.Owned {
		if len(fields) != 1 || op != "read" {
			return value, errWorkerExecution
		}
		return value, nil
	}
	if len(fields) != 6 || value.Start == nil || !validRecoveryProductID(value.Start.Ref.RunID) || value.Start.DefinitionVersion < 1 || value.Start.DefinitionVersion > 1000000 || !redTeamLinkedDigestPattern.MatchString(value.Start.InputDigest) || !redTeamLinkedDigestPattern.MatchString(value.EffectKey) || !redTeamLinkedDigestPattern.MatchString(value.DeliveryDigest) {
		return value, errWorkerExecution
	}
	if _, err := orchestration.SingleTestWorkflowID(value.Start.Ref); err != nil {
		return value, errWorkerExecution
	}
	if value.AcceptedAt != nil {
		if _, err := time.Parse(time.RFC3339Nano, *value.AcceptedAt); err != nil {
			return value, errWorkerExecution
		}
	}
	return value, nil
}
