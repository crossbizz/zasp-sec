package apiserver

import (
	"context"
	"encoding/json"
	"testing"
)

type authorizationReadinessFixture struct{ JSONDatabase }

func (*authorizationReadinessFixture) CurrentAuthorizationRequired() bool { return true }
func (*authorizationReadinessFixture) SchemaVersion(context.Context) (string, error) {
	return ProductionRecoverySchemaVersion, nil
}
func (*authorizationReadinessFixture) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return nil, ErrRepositoryUnavailable
}

func TestP7AuthorizationConstructorPrincipal(t *testing.T) {
	if _, err := NewPostgresRepository(&authorizationReadinessFixture{}); err == nil {
		t.Fatal("schema availability was treated as current API principal readiness")
	}
}
