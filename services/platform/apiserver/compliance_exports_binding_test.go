package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

func TestComplianceExportBindsRequestedJobAndCanonicalFilters(t *testing.T) {
	_, db, _, identity := complianceHTTPFixture(t)
	r, _ := NewComplianceExportsRepository(db)
	digest := sha256.Sum256([]byte("compliance-cookie"))
	if _, err := r.Get(context.Background(), *identity, digest[:], identity.Scope.OrganizationID().String()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Errorf("accepted wrong job response %v", err)
	}
	canonical := ComplianceExportRequest{ControlID: "hipaa-policies"}
	if _, err := r.Create(context.Background(), *identity, digest[:], "one", canonical); err != nil {
		t.Fatal(err)
	}
	if db.createBody != `{"framework":"hipaa","control_id":"hipaa-policies"}` {
		t.Errorf("equivalent filter did not canonicalize: %s", db.createBody)
	}
	var value map[string]json.RawMessage
	_ = json.Unmarshal([]byte(db.createBody), &value)
}
