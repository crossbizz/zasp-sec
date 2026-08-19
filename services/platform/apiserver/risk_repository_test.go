package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	riskFindingID       = "pid_40000001-0000-4000-8000-000000000001"
	riskPathID          = "pid_40000002-0000-4000-8000-000000000002"
	riskEvidence        = "pid_40000003-0000-4000-8000-000000000003"
	riskNodeOne         = "pid_40000004-0000-4000-8000-000000000004"
	riskNodeTwo         = "pid_40000005-0000-4000-8000-000000000005"
	riskForeignEvidence = "pid_40000006-0000-4000-8000-000000000006"
)

func validRiskFindingJSON() string {
	return `{"id":"` + riskFindingID + `","source":"posture","title":"Public tool access","severity":"high","status":"open","evidence_ids":["` + riskEvidence + `"],"risk_factors":[],"version":2,"created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:01Z"}`
}

func validRiskPathJSON() string {
	return `{"id":"` + riskPathID + `","entry_id":"` + riskNodeOne + `","sink_id":"` + riskNodeTwo + `","node_ids":["` + riskNodeOne + `","` + riskNodeTwo + `"],"state":"verified","evidence_ids":["` + riskEvidence + `"],"blocked_edge":-1,"version":1,"created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:01Z"}`
}

type invisibleRiskMutationDatabase struct {
	workflowCallDatabase
	queries []string
}

type riskProjectionDatabase struct {
	workflowCallDatabase
	responses map[string]json.RawMessage
}

func (database *riskProjectionDatabase) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	database.query, database.args = query, append([]any(nil), args...)
	return database.responses[query], nil
}

func (database *invisibleRiskMutationDatabase) QueryJSON(_ context.Context, query string, _ ...any) (json.RawMessage, error) {
	database.queries = append(database.queries, query)
	if query == postgresRiskFindingMutateSQL {
		return nil, ErrRepositoryNotFound
	}
	return json.RawMessage(`{"found":true,"result":{"body":` + validRiskFindingJSON() + `,"version":2,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","receipt_id":"pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc","replayed":true}}`), nil
}

func TestRiskRepositoryReadsOnlyTheExactScopeAndRejectsProviderShapeDrift(t *testing.T) {
	database := &workflowCallDatabase{response: json.RawMessage(validRiskFindingJSON())}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)

	finding, err := repository.GetRiskFinding(context.Background(), identity.Scope, riskFindingID)
	if err != nil || finding.ID != riskFindingID || finding.Version != 2 {
		t.Fatalf("GetRiskFinding = (%#v, %v)", finding, err)
	}
	want := []any{riskFindingID, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()}
	if database.query != postgresRiskFindingGetSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("query/args = %q/%#v, want %q/%#v", database.query, database.args, postgresRiskFindingGetSQL, want)
	}

	database.response = json.RawMessage(validRiskFindingJSON()[:len(validRiskFindingJSON())-1] + `,"unexpected":true}`)
	if _, err := repository.GetRiskFinding(context.Background(), identity.Scope, riskFindingID); err != ErrRepositoryUnavailable {
		t.Fatalf("shape drift error = %v", err)
	}
}

func TestRiskRepositoryUsesStableBoundedFindingAndPathPages(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &workflowCallDatabase{response: json.RawMessage(`{"items":[` + validRiskFindingJSON() + `],"next_id":"` + riskFindingID + `"}`)}
	repository, _ := NewPostgresRepository(database)

	page, err := repository.ListRiskFindingPage(context.Background(), identity.Scope, "", 1)
	if err != nil || len(page.Items) != 1 || page.NextID != riskFindingID {
		t.Fatalf("finding page = (%#v, %v)", page, err)
	}
	want := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), "", 1}
	if database.query != postgresRiskFindingPageSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("finding page args = %#v", database.args)
	}

	database.response = json.RawMessage(`{"items":[` + validRiskPathJSON() + `],"next_id":null}`)
	paths, err := repository.ListRiskAttackPathPage(context.Background(), identity.Scope, "", 100)
	if err != nil || len(paths.Items) != 1 || paths.NextID != "" {
		t.Fatalf("path page = (%#v, %v)", paths, err)
	}
	if database.query != postgresRiskAttackPathPageSQL {
		t.Fatalf("path page query = %q", database.query)
	}
}

func TestRiskRepositoryValidatesAttackPathAndBreakOptionCrossReferences(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	database := &riskProjectionDatabase{responses: map[string]json.RawMessage{
		postgresRiskAttackPathGetSQL: json.RawMessage(validRiskPathJSON()),
	}}
	repository, _ := NewPostgresRepository(database)

	path, err := repository.GetRiskAttackPath(context.Background(), identity.Scope, riskPathID)
	if err != nil || path.EntryID != riskNodeOne {
		t.Fatalf("path = (%#v, %v)", path, err)
	}
	database.responses[postgresRiskBreakOptionsGetSQL] = json.RawMessage(`{"items":[{"path_id":"` + riskPathID + `","target_id":"` + riskNodeOne + `","evidence_id":"` + riskEvidence + `","kind":"remove_node","rank":1}]}`)
	options, err := repository.GetRiskBreakOptions(context.Background(), identity.Scope, riskPathID)
	if err != nil || len(options) != 1 || options[0].PathID != riskPathID {
		t.Fatalf("options = (%#v, %v)", options, err)
	}

	database.responses[postgresRiskBreakOptionsGetSQL] = json.RawMessage(`{"items":[{"path_id":"` + riskFindingID + `","target_id":"` + riskNodeOne + `","evidence_id":"` + riskEvidence + `","kind":"remove_node","rank":1}]}`)
	if _, err := repository.GetRiskBreakOptions(context.Background(), identity.Scope, riskPathID); err != ErrRepositoryUnavailable {
		t.Fatalf("cross-scope option error = %v", err)
	}
}

func TestRiskRepositoryRejectsEvidenceReferencesOutsideTheirParentProjection(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	findingPayload := strings.Replace(validRiskFindingJSON(), `"risk_factors":[]`, `"risk_factors":[{"name":"Foreign evidence","evidence_id":"`+riskForeignEvidence+`"}]`, 1)
	findingDatabase := &workflowCallDatabase{response: json.RawMessage(findingPayload)}
	findingRepository, _ := NewPostgresRepository(findingDatabase)
	if _, err := findingRepository.GetRiskFinding(context.Background(), identity.Scope, riskFindingID); err != ErrRepositoryUnavailable {
		t.Fatalf("foreign finding-factor evidence error = %v", err)
	}

	optionDatabase := &riskProjectionDatabase{responses: map[string]json.RawMessage{
		postgresRiskAttackPathGetSQL:   json.RawMessage(validRiskPathJSON()),
		postgresRiskBreakOptionsGetSQL: json.RawMessage(`{"items":[{"path_id":"` + riskPathID + `","target_id":"` + riskNodeOne + `","evidence_id":"` + riskForeignEvidence + `","kind":"remove_node","rank":1}]}`),
	}}
	optionRepository, _ := NewPostgresRepository(optionDatabase)
	if _, err := optionRepository.GetRiskBreakOptions(context.Background(), identity.Scope, riskPathID); err != ErrRepositoryUnavailable {
		t.Fatalf("foreign break-option evidence error = %v", err)
	}
}

func TestRiskRepositoryMutationCarriesScopeVersionAuditAndReceiptAtomically(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	updatedFinding := strings.Replace(validRiskFindingJSON(), `"status":"open"`, `"status":"under_review"`, 1)
	updatedFinding = strings.Replace(updatedFinding, `"version":2`, `"version":3`, 1)
	database := &workflowCallDatabase{response: json.RawMessage(`{"body":` + updatedFinding + `,"version":3,"audit_id":"pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","correlation_id":"pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","receipt_id":"pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc","replayed":false}`)}
	repository, _ := NewPostgresRepository(database)
	mutation := RiskFindingMutation{Operation: "updateFinding", FindingID: riskFindingID, IdempotencyKey: "idem-risk-update-001", ExpectedVersion: 2, Status: "under_review", AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ReceiptID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc"}

	result, err := repository.MutateRiskFinding(context.Background(), identity, mutation)
	if err != nil || result.Version != 3 || result.Body.Status != "under_review" || result.Replayed {
		t.Fatalf("mutation = (%#v, %v)", result, err)
	}
	want := []any{"updateFinding", riskFindingID, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), mutation.IdempotencyKey, int64(2), "under_review", "", mutation.AuditID, mutation.CorrelationID, mutation.ReceiptID}
	if database.query != postgresRiskFindingMutateSQL || !reflect.DeepEqual(database.args, want) {
		t.Fatalf("mutation args = %#v, want %#v", database.args, want)
	}

	winnerAudit := "pid_dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	winnerCorrelation := "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	winnerReceipt := "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"
	database.response = json.RawMessage(`{"body":` + updatedFinding + `,"version":3,"audit_id":"` + winnerAudit + `","correlation_id":"` + winnerCorrelation + `","receipt_id":"` + winnerReceipt + `","replayed":true}`)
	result, err = repository.MutateRiskFinding(context.Background(), identity, mutation)
	if err != nil || !result.Replayed || result.AuditID != winnerAudit || result.CorrelationID != winnerCorrelation || result.ReceiptID != winnerReceipt {
		t.Fatalf("concurrent winner replay = (%#v, %v)", result, err)
	}
}

func TestRiskRepositoryAtomicMutationPreservesFindingVisibilityNotFound(t *testing.T) {
	database := &invisibleRiskMutationDatabase{}
	repository, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	mutation := RiskFindingMutation{Operation: "updateFinding", FindingID: riskFindingID, IdempotencyKey: "idem-risk-update-001", ExpectedVersion: 1, Status: "under_review", AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ReceiptID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc"}

	result, err := repository.MutateRiskFinding(context.Background(), identity, mutation)
	if !errors.Is(err, ErrRepositoryNotFound) || !reflect.DeepEqual(result, RiskFindingMutationResult{}) {
		t.Fatalf("invisible atomic mutation = (%#v, %v)", result, err)
	}
	if !reflect.DeepEqual(database.queries, []string{postgresRiskFindingMutateSQL}) {
		t.Fatalf("invisible mutation queries = %#v", database.queries)
	}
}

func TestRiskRepositoryRejectsMalformedProjectionValuesBeforeTheyReachHTTP(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	cases := []string{
		`{"id":"` + riskFindingID + `","source":"posture","title":"x","severity":"urgent","status":"open","evidence_ids":["` + riskEvidence + `"],"risk_factors":[],"version":1,"created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:01Z"}`,
		`{"id":"` + riskFindingID + `","source":"posture","title":"x","severity":"high","status":"accepted","evidence_ids":["` + riskEvidence + `"],"risk_factors":[],"version":1,"created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:01Z"}`,
	}
	for _, payload := range cases {
		database := &workflowCallDatabase{response: json.RawMessage(payload)}
		repository, _ := NewPostgresRepository(database)
		if _, err := repository.GetRiskFinding(context.Background(), identity.Scope, riskFindingID); err != ErrRepositoryUnavailable {
			t.Fatalf("payload %s error = %v", payload, err)
		}
	}
}
