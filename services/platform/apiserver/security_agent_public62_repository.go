package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// SecurityAgentPublicRepository is the browser-session boundary for the
// separately registered ordered-action facade. It has no legacy fallback.
// Migration65 captures each committed admission/decision receipt in SQL, once
// at the inner mutation boundary even when resource operations call it again.
type SecurityAgentPublicRepository struct{ database JSONDatabase }

type SecurityAgentPublicTrigger struct {
	DefinitionID      string
	DefinitionVersion int64
	TriggerID         string
	TriggerVersion    int64
	IdempotencyKey    string
}
type SecurityAgentPublicActivation struct {
	ContractVersion   int    `json:"contract_version"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion int64  `json:"definition_version"`
	Activation        string `json:"activation"`
}
type SecurityAgentPublicTriggerResult struct {
	ContractVersion   int    `json:"contract_version"`
	RunID             string `json:"run_id"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion int64  `json:"definition_version"`
	State             string `json:"state"`
	Version           int64  `json:"version"`
}
type SecurityAgentPublicRun struct {
	ContractVersion   int                       `json:"contract_version"`
	OrganizationID    string                    `json:"organization_id"`
	WorkspaceID       string                    `json:"workspace_id"`
	EnvironmentID     string                    `json:"environment_id"`
	RunID             string                    `json:"run_id"`
	DefinitionID      string                    `json:"definition_id"`
	DefinitionVersion int64                     `json:"definition_version"`
	State             string                    `json:"state"`
	Version           int64                     `json:"version"`
	Admitted          bool                      `json:"admitted"`
	Steps             []SecurityAgentPublicStep `json:"steps"`
	Verification      string                    `json:"verification"`
}
type SecurityAgentPublicStep struct {
	StepID        string                        `json:"step_id"`
	Index         int                           `json:"index"`
	Action        string                        `json:"action"`
	State         string                        `json:"state"`
	Version       int64                         `json:"version"`
	Dependency    SecurityAgentPublicDependency `json:"dependency"`
	Authorization string                        `json:"authorization"`
	Approval      SecurityAgentPublicApproval   `json:"approval"`
	Receipt       *SecurityAgentPublicReceipt   `json:"receipt"`
	Settlement    string                        `json:"settlement"`
	Cleanup       SecurityAgentPublicCleanup    `json:"cleanup"`
}
type SecurityAgentPublicDependency struct {
	PredecessorStepID   *string `json:"predecessor_step_id"`
	RequiredReceiptKind *string `json:"required_receipt_kind"`
	Satisfied           bool    `json:"satisfied"`
	Blocked             bool    `json:"blocked"`
	Ready               bool    `json:"ready"`
}
type SecurityAgentPublicApproval struct {
	State      string  `json:"state"`
	Version    int64   `json:"version"`
	ApprovalID *string `json:"approval_id"`
}
type SecurityAgentPublicReceipt struct {
	Kind      string `json:"kind"`
	Version   int64  `json:"version"`
	Digest    string `json:"digest"`
	Reference string `json:"reference"`
}
type SecurityAgentPublicCleanup struct {
	State   string `json:"state"`
	Version int64  `json:"version"`
	Attempt int64  `json:"attempt"`
	Partial bool   `json:"partial"`
	Cleaned bool   `json:"cleaned"`
}
type SecurityAgentPublicPage struct {
	ContractVersion int                      `json:"contract_version"`
	Items           []SecurityAgentPublicRun `json:"items"`
	NextAfterRunID  *string                  `json:"next_after_run_id"`
}

const securityAgentPublicSQL = `SELECT zasp_ordered_public62.api($1,$2,$3::jsonb)`

var securityAgentPublicIdempotency = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

func NewSecurityAgentPublicRepository(database JSONDatabase) (*SecurityAgentPublicRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryOperation
	}
	return &SecurityAgentPublicRepository{database: database}, nil
}

func (r *SecurityAgentPublicRepository) valid(ctx context.Context, id RequestIdentity) bool {
	return r != nil && !nilInterface(r.database) && ctx != nil && ctx.Err() == nil && id.CredentialKind == CredentialBrowserSession && validRequestIdentity(id, true)
}
func public62ID(id string) bool {
	v, err := domain.ParseProductID(id)
	return err == nil && v.String() == id
}
func public62Version(v int64) bool { return v >= 1 && v <= 1000000 }

// Each operation goes through api, which validates registration and readiness
// both before work and immediately before return. Readiness is never cached.
func (r *SecurityAgentPublicRepository) invoke(ctx context.Context, id RequestIdentity, op string, fields map[string]any) (json.RawMessage, error) {
	if !r.valid(ctx, id) {
		return nil, ErrRepositoryOperation
	}
	if op == "activate" || op == "activate_resource" {
		definition, ok := fields["definition_id"].(string)
		if !ok || !public62ID(definition) {
			return nil, ErrRepositoryOperation
		}
		if err := requireAutomaticDefinitionActivation(ctx, r.database, id, definition); err != nil {
			return nil, err
		}
	}
	fields["organization_id"] = id.Scope.OrganizationID().String()
	fields["workspace_id"] = id.Scope.WorkspaceID().String()
	fields["environment_id"] = id.Scope.EnvironmentID().String()
	fields["actor_id"] = id.PrincipalID.String()
	fields["operation"] = op
	raw, err := json.Marshal(fields)
	if err != nil {
		return nil, ErrRepositoryOperation
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := r.database.QueryJSON(bounded, securityAgentPublicSQL, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), json.RawMessage(raw))
	if err != nil {
		return nil, public62ProviderError(err, op)
	}
	if bounded.Err() != nil || len(response) > 65536 {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}

// Return safe established sentinels, never errors.Join with provider details.
// Read operations cannot have an optimistic-write conflict: their 40001 means
// retained authority is contradictory or changed while it was being read.
func public62ProviderError(err error, op string) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		err = classifyPostgresError(pg)
	}
	if errors.Is(err, ErrRepositoryConflict) {
		if op == "activate" || op == "trigger" || op == "decide" || op == "cancel" || op == "activate_resource" || op == "trigger_resource" || op == "decide_resource" {
			return ErrRepositoryConflict
		}
		return ErrRepositoryUnavailable
	}
	if errors.Is(err, ErrRepositoryOperation) {
		return ErrRepositoryOperation
	}
	if errors.Is(err, ErrRepositoryNotFound) {
		return ErrRepositoryNotFound
	}
	return ErrRepositoryUnavailable
}

func (r *SecurityAgentPublicRepository) Ready(ctx context.Context, id RequestIdentity) error {
	raw, err := r.invoke(ctx, id, "ready", map[string]any{})
	if err != nil {
		return err
	}
	var v struct {
		ContractVersion int  `json:"contract_version"`
		Ready           bool `json:"ready"`
	}
	if public62Decode(raw, &v) != nil || v.ContractVersion != 62 || !v.Ready {
		return ErrRepositoryUnavailable
	}
	return nil
}
func (r *SecurityAgentPublicRepository) Activate(ctx context.Context, id RequestIdentity, definition string, version int64) (SecurityAgentPublicActivation, error) {
	var empty, v SecurityAgentPublicActivation
	if !r.valid(ctx, id) || !public62ID(definition) || !public62Version(version) {
		return empty, ErrRepositoryOperation
	}
	raw, err := r.invoke(ctx, id, "activate", map[string]any{"definition_id": definition, "definition_version": version})
	if err != nil {
		return empty, err
	}
	if public62Decode(raw, &v) != nil || v.ContractVersion != 62 || v.DefinitionID != definition || !public62Version(v.DefinitionVersion) || v.DefinitionVersion != version+1 || v.Activation != "supervised" {
		return empty, ErrRepositoryUnavailable
	}
	return v, nil
}
func (r *SecurityAgentPublicRepository) Trigger(ctx context.Context, id RequestIdentity, q SecurityAgentPublicTrigger) (SecurityAgentPublicTriggerResult, error) {
	var empty, v SecurityAgentPublicTriggerResult
	if !r.valid(ctx, id) || !public62ID(q.DefinitionID) || !public62ID(q.TriggerID) || !public62Version(q.DefinitionVersion) || !public62Version(q.TriggerVersion) || !securityAgentPublicIdempotency.MatchString(q.IdempotencyKey) {
		return empty, ErrRepositoryOperation
	}
	raw, err := r.invoke(ctx, id, "trigger", map[string]any{"definition_id": q.DefinitionID, "definition_version": q.DefinitionVersion, "trigger_id": q.TriggerID, "trigger_version": q.TriggerVersion, "idempotency_key": q.IdempotencyKey})
	if err != nil {
		return empty, err
	}
	expected, err := CanonicalDiscoveryID(id.Scope, "security_agent_run", q.DefinitionID+"\x1f"+q.TriggerID+"\x1f"+strconv.FormatInt(q.TriggerVersion, 10))
	if err != nil || public62Decode(raw, &v) != nil || v.ContractVersion != 62 || v.RunID != expected || v.DefinitionID != q.DefinitionID || v.DefinitionVersion != q.DefinitionVersion || v.State != "queued" || v.Version != 1 {
		return empty, ErrRepositoryUnavailable
	}
	return v, nil
}
func (r *SecurityAgentPublicRepository) Run(ctx context.Context, id RequestIdentity, run string) (SecurityAgentPublicRun, error) {
	var empty, v SecurityAgentPublicRun
	if !r.valid(ctx, id) || !public62ID(run) {
		return empty, ErrRepositoryOperation
	}
	raw, err := r.invoke(ctx, id, "detail", map[string]any{"run_id": run})
	if err != nil {
		return empty, err
	}
	if len(raw) > 8192 || public62Decode(raw, &v) != nil || v.RunID != run || !public62ValidRun(v, id) {
		return empty, ErrRepositoryUnavailable
	}
	return v, nil
}
func (r *SecurityAgentPublicRepository) Runs(ctx context.Context, id RequestIdentity, after string, limit int) (SecurityAgentPublicPage, error) {
	var empty, v SecurityAgentPublicPage
	if !r.valid(ctx, id) || after != "" && !public62ID(after) || limit < 1 || limit > 10 {
		return empty, ErrRepositoryOperation
	}
	raw, err := r.invoke(ctx, id, "list", map[string]any{"after_run_id": after, "limit": limit})
	if err != nil {
		return empty, err
	}
	if public62Decode(raw, &v) != nil || v.ContractVersion != 62 || len(v.Items) > limit {
		return empty, ErrRepositoryUnavailable
	}
	previous := after
	for _, item := range v.Items {
		if !public62ValidRun(item, id) || item.RunID <= previous {
			return empty, ErrRepositoryUnavailable
		}
		previous = item.RunID
	}
	if v.NextAfterRunID != nil && (len(v.Items) != limit || *v.NextAfterRunID != previous || !public62ID(*v.NextAfterRunID)) {
		return empty, ErrRepositoryUnavailable
	}
	return v, nil
}
