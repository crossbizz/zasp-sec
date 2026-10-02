package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"testing"
)

const compliancePolicyJSON = `{"id":"policy-001","asset":"policy-001","source":"policy","timestamp":"2026-01-02T00:00:00.000000Z","organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","target":{"source_kind":"policy","source_id":"policy-001","source_version":7},"freshness":"stale","metadata":{"verification":"definition_only"}}`

// Catch policy IDs being incorrectly forced through pid grammar and untrusted
// JSON being accepted through case aliases, duplicates, scope drift or extras.
func TestComplianceEvidenceStrictDecoding(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	value, err := decodeComplianceEvidence(json.RawMessage(compliancePolicyJSON), identity)
	if err != nil || value.Target.SourceID != "policy-001" || value.Target.SourceVersion != 7 || value.Timestamp != "2026-01-02T00:00:00.000000Z" {
		t.Fatalf("typed policy detail: %+v %v", value, err)
	}
	for _, raw := range []string{
		strings.Replace(compliancePolicyJSON, `"id":"policy-001"`, `"id":"policy-001","id":"policy-002"`, 1),
		strings.Replace(compliancePolicyJSON, `"id":`, `"ID":`, 1),
		strings.Replace(compliancePolicyJSON, `"source_version":7`, `"source_version":null`, 1),
		strings.Replace(compliancePolicyJSON, `"source_version":7`, `"source_version":0`, 1),
		strings.Replace(compliancePolicyJSON, `"verification":"definition_only"`, `"verification":"definition_only","secret":"bad"`, 1),
		strings.Replace(compliancePolicyJSON, `"source_kind":"policy"`, `"source_kind":"unknown"`, 1),
		strings.Replace(compliancePolicyJSON, `"source_id":"policy-001"`, `"source_id":"policy-002"`, 1),
		strings.Replace(compliancePolicyJSON, `pid_10000003-0000-4000-8000-000000000003`, `pid_90000003-0000-4000-8000-000000000003`, 1),
		strings.Replace(compliancePolicyJSON, `2026-01-02T00:00:00.000000Z`, `bad-time`, 1),
	} {
		if _, err := decodeComplianceEvidence(json.RawMessage(raw), identity); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Errorf("unsafe response accepted: %s %v", raw, err)
		}
	}
}

func TestComplianceRepositoryBindsScopeAndRejectsUnsafeInput(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit", "view_compliance"}
	database := &discoveryCallDatabase{schema: ProductionRecoverySchemaVersion, responses: map[string]json.RawMessage{postgresComplianceReadySQL: json.RawMessage(`true`), postgresComplianceReadSQL: json.RawMessage(compliancePolicyJSON)}}
	repository, err := NewComplianceRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("owned-compliance-session"))
	value, err := repository.GetEvidence(context.Background(), identity, digest[:], ComplianceTarget{SourceKind: "policy", SourceID: "policy-001", SourceVersion: 7})
	if err != nil || value.Target.SourceID != "policy-001" {
		t.Fatalf("read: %+v %v", value, err)
	}
	if database.query != postgresComplianceReadSQL || len(database.args) != 9 || database.args[0] != identity.Scope.OrganizationID().String() || database.args[1] != identity.Scope.WorkspaceID().String() || database.args[2] != identity.Scope.EnvironmentID().String() || database.args[3] != identity.PrincipalID.String() || database.args[5] != "getEvidence" {
		t.Fatalf("lost authority binding: %#v", database.args)
	}
	database.errors = map[string]error{postgresComplianceReadSQL: classifyPostgresError(&pgconn.PgError{Code: "40001", Message: "compliance source_changed"})}
	if _, err := repository.GetEvidence(context.Background(), identity, digest[:], ComplianceTarget{SourceKind: "policy", SourceID: "policy-001", SourceVersion: 6}); !errors.Is(err, ErrComplianceSourceChanged) {
		t.Fatalf("classified source conflict lost: %v", err)
	}
	database.errors = nil
	for _, target := range []ComplianceTarget{{SourceKind: "policy", SourceID: "pid_bad"}, {SourceKind: "unknown", SourceID: "policy-001"}, {SourceKind: "policy", SourceID: "policy-001", SourceVersion: -1}} {
		if _, err := repository.GetEvidence(context.Background(), identity, digest[:], target); !errors.Is(err, ErrRepositoryOperation) {
			t.Errorf("invalid target accepted: %v", err)
		}
	}
	identity.Permissions = []string{"view_compliance", "view"}
	if _, err := repository.GetEvidence(context.Background(), identity, digest[:], ComplianceTarget{SourceKind: "policy", SourceID: "policy-001"}); !errors.Is(err, ErrComplianceForbidden) {
		t.Fatalf("missing source permission accepted: %v", err)
	}
}
