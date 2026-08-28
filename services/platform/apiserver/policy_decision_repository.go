package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	platformpolicy "github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const postgresListPolicyDecisionsSQL = `SELECT zasp_policy_list_runtime_decisions($1,$2,$3,$4,$5)`

type PolicyDecisionRepository struct{ database JSONDatabase }

func NewPolicyDecisionRepository(database JSONDatabase) (*PolicyDecisionRepository, error) {
	if nilPolicyDecisionValue(database) {
		return nil, ErrRepositoryConfiguration
	}
	return &PolicyDecisionRepository{database: database}, nil
}

func (repository *PolicyDecisionRepository) Ready(ctx context.Context) error {
	if repository == nil || nilPolicyDecisionValue(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	metadata := migrations.ProductionRecovery()
	payload, err := repository.database.QueryJSON(ctx, postgresProductionRecoveryReadinessSQL, metadata.Checksum(), migrations.ProductionRecoverySemanticFingerprint())
	if err != nil || ctx.Err() != nil || !bytes.Equal(payload, []byte("true")) {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *PolicyDecisionRepository) ListPolicyDecisions(ctx context.Context, scope domain.Scope, policyID string, limit int) ([]platformpolicy.RuntimeDecision, error) {
	if repository == nil || nilPolicyDecisionValue(repository.database) || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || !policyIDPattern.MatchString(policyID) || limit < 1 || limit > 100 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresListPolicyDecisionsSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), policyID, limit)
	if err != nil || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	var page struct {
		Items []platformpolicy.RuntimeDecision `json:"items"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&page) != nil || decoder.Decode(&struct{}{}) != io.EOF || page.Items == nil || len(page.Items) > limit || !validPolicyDecisions(page.Items, scope, policyID) {
		return nil, ErrRepositoryUnavailable
	}
	return append([]platformpolicy.RuntimeDecision(nil), page.Items...), nil
}

func nilPolicyDecisionValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ PolicyDecisionHistory = (*PolicyDecisionRepository)(nil)
