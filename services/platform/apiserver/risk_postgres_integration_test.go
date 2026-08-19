package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRiskProjectionPostgresPaginationIsolationMutationReplayAndRollbackGuard(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	runner, _ := migrations.NewRunner(&integrationMigrationDatabase{connection: connection})
	for index, step := range []func(context.Context) error{runner.Up, runner.UpCore, runner.UpWorkflows, runner.UpWorkflowReceipts, runner.UpWorkflowReceiptSafety, runner.UpWorkflowReceiptProvenance, runner.UpProductionAdministration, runner.UpAPITokenRevealGrants, runner.UpProductionRiskProjection} {
		if err := step(ctx); err != nil {
			t.Fatalf("migration %d: %v", index+1, err)
		}
	}
	identity := fixtureRequestIdentity(t)
	organization, workspace, environment := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	for _, seed := range []struct {
		statement string
		arguments []any
	}{
		{`INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) SELECT $1,$2,$3,'pid_'||lpad(ordinal::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'posture','Finding '||ordinal,'high','open' FROM generate_series(1,100) ordinal`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) SELECT $1,$2,$3,'pid_'||lpad(ordinal::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),1,'pid_'||lpad((10000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0') FROM generate_series(1,100) ordinal`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES ($1,$2,$3,$4,'posture','Public tool access','high','open')`, []any{organization, workspace, environment, riskFindingID}},
		{`INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES ($1,$2,$3,$4,1,$5)`, []any{organization, workspace, environment, riskFindingID, riskEvidence}},
		{`INSERT INTO zasp_risk_attack_paths (organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES ($1,$2,$3,$4,$5,$6,'verified')`, []any{organization, workspace, environment, riskPathID, riskNodeOne, riskNodeTwo}},
		{`INSERT INTO zasp_risk_attack_path_nodes (organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES ($1,$2,$3,$4,1,$5),($1,$2,$3,$4,2,$6)`, []any{organization, workspace, environment, riskPathID, riskNodeOne, riskNodeTwo}},
		{`INSERT INTO zasp_risk_attack_path_evidence (organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES ($1,$2,$3,$4,1,$5)`, []any{organization, workspace, environment, riskPathID, riskEvidence}},
		{`INSERT INTO zasp_risk_break_options (organization_id,workspace_id,environment_id,path_id,rank,target_id,evidence_id,kind) VALUES ($1,$2,$3,$4,1,$5,$6,'remove_node')`, []any{organization, workspace, environment, riskPathID, riskNodeOne, riskEvidence}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newRiskHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}

	request := riskRequest(t, identity, "listFindings", http.MethodGet, "https://app.zasp.test/api/v1/findings?limit=100", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var first struct {
		Items    []RiskFinding `json:"items"`
		PageInfo struct {
			NextCursor *string `json:"next_cursor"`
			HasMore    bool    `json:"has_more"`
		} `json:"page_info"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &first) != nil || len(first.Items) != 100 || first.PageInfo.NextCursor == nil || !first.PageInfo.HasMore {
		t.Fatalf("first page = %d items=%d %s", response.Code, len(first.Items), response.Body.String())
	}
	request = riskRequest(t, identity, "listFindings", http.MethodGet, "https://app.zasp.test/api/v1/findings?limit=100&cursor="+*first.PageInfo.NextCursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var second struct {
		Items    []RiskFinding `json:"items"`
		PageInfo struct {
			NextCursor *string `json:"next_cursor"`
			HasMore    bool    `json:"has_more"`
		} `json:"page_info"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &second) != nil || len(second.Items) != 1 || second.PageInfo.NextCursor != nil || second.PageInfo.HasMore || second.Items[0].ID != riskFindingID {
		t.Fatalf("second page = %d %#v %s", response.Code, second, response.Body.String())
	}

	foreign := identity
	foreignOrganization, _ := domain.ParseProductID("pid_20000001-0000-4000-8000-000000000001")
	foreignWorkspace, _ := domain.ParseProductID("pid_20000002-0000-4000-8000-000000000002")
	foreignEnvironment, _ := domain.ParseProductID("pid_20000003-0000-4000-8000-000000000003")
	foreign.Scope, _ = domain.NewScope(foreignOrganization, foreignWorkspace, foreignEnvironment)
	request = riskRequest(t, foreign, "listFindings", http.MethodGet, "https://app.zasp.test/api/v1/findings?limit=100&cursor="+*first.PageInfo.NextCursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("foreign cursor = %d %s", response.Code, response.Body.String())
	}

	path, err := repository.GetRiskAttackPath(ctx, identity.Scope, riskPathID)
	options, optionsErr := repository.GetRiskBreakOptions(ctx, identity.Scope, riskPathID)
	if err != nil || optionsErr != nil || len(path.NodeIDs) != 2 || len(options) != 1 || options[0].TargetID != riskNodeOne {
		t.Fatalf("path/options = %#v/%#v (%v/%v)", path, options, err, optionsErr)
	}

	mutationRequest := riskRequest(t, identity, "updateFinding", http.MethodPatch, "https://app.zasp.test/api/v1/findings/"+riskFindingID, `{"status":"under_review"}`)
	mutationRequest.Header.Set("If-Match", `"1"`)
	mutationRequest.Header.Set("Idempotency-Key", "idem-pg-risk-update-001")
	mutationResponse := httptest.NewRecorder()
	handler.ServeHTTP(mutationResponse, mutationRequest)
	if mutationResponse.Code != http.StatusOK || mutationResponse.Header().Get("ETag") != `"2"` || mutationResponse.Header().Get("X-Audit-ID") == "" || mutationResponse.Header().Get("X-Mutation-Receipt-ID") == "" {
		t.Fatalf("mutation = %d headers=%v %s", mutationResponse.Code, mutationResponse.Header(), mutationResponse.Body.String())
	}
	mutationRequest = riskRequest(t, identity, "updateFinding", http.MethodPatch, "https://app.zasp.test/api/v1/findings/"+riskFindingID, `{"status":"under_review"}`)
	mutationRequest.Header.Set("If-Match", `"1"`)
	mutationRequest.Header.Set("Idempotency-Key", "idem-pg-risk-update-001")
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, mutationRequest)
	if replayResponse.Code != http.StatusOK || replayResponse.Header().Get("X-Audit-ID") != mutationResponse.Header().Get("X-Audit-ID") || replayResponse.Header().Get("X-Mutation-Receipt-ID") != mutationResponse.Header().Get("X-Mutation-Receipt-ID") {
		t.Fatalf("replay = %d headers=%v %s", replayResponse.Code, replayResponse.Header(), replayResponse.Body.String())
	}

	pat := identity
	pat.CredentialKind = CredentialBearerToken
	acceptRequest := riskRequest(t, pat, "acceptFindingRisk", http.MethodPost, "https://app.zasp.test/api/v1/findings/"+riskFindingID+"/accept-risk", `{"reason":"Approved exception"}`)
	acceptRequest.Header.Set("If-Match", `"2"`)
	acceptRequest.Header.Set("Idempotency-Key", "idem-pg-risk-accept-001")
	acceptResponse := httptest.NewRecorder()
	handler.ServeHTTP(acceptResponse, acceptRequest)
	if acceptResponse.Code != http.StatusOK || acceptResponse.Header().Get("ETag") != `"3"` || acceptResponse.Header().Get("X-Audit-ID") == "" || acceptResponse.Header().Get("X-Mutation-Receipt-ID") != "" {
		t.Fatalf("PAT mutation = %d headers=%v %s", acceptResponse.Code, acceptResponse.Header(), acceptResponse.Body.String())
	}
	var audits, receipts int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_audit WHERE resource_kind='finding'),(SELECT count(*) FROM zasp_workflow_receipts WHERE resource_kind='finding')`).Scan(&audits, &receipts); err != nil || audits != 2 || receipts != 1 {
		t.Fatalf("durable evidence = audits:%d receipts:%d err:%v", audits, receipts, err)
	}

	hostileFinding := "pid_70000001-0000-4000-8000-000000000001"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES ($1,$2,$3,$4,'posture','Malformed','high','open')`, organization, workspace, environment, hostileFinding); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES ($1,$2,$3,$4,2,$5)`, organization, workspace, environment, hostileFinding, "pid_70000002-0000-4000-8000-000000000002"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetRiskFinding(ctx, identity.Scope, hostileFinding); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("malformed durable projection error = %v", err)
	}
	if err := runner.DownProductionRiskProjection(ctx); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatalf("data-bearing v9 rollback = %v", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 9 {
		t.Fatalf("guarded v9 preserved = %d %v", version, err)
	}
	_ = database.Close()
}
