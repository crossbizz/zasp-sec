package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	invisibleFinding := "pid_81000001-0000-4000-8000-000000000001"
	invisibleAcceptFinding := "pid_81000003-0000-4000-8000-000000000003"
	for _, seed := range []struct {
		statement string
		arguments []any
	}{
		{`INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) SELECT $1,$2,$3,'pid_'||lpad(ordinal::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'posture','Finding '||ordinal,'high','open' FROM generate_series(1,1001) ordinal`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) SELECT $1,$2,$3,'pid_'||lpad(ordinal::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),1,'pid_'||lpad((10000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0') FROM generate_series(1,1001) ordinal`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES ($1,$2,$3,$4,'posture','Public tool access','high','open')`, []any{organization, workspace, environment, riskFindingID}},
		{`INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES ($1,$2,$3,$4,1,$5)`, []any{organization, workspace, environment, riskFindingID, riskEvidence}},
		{`INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES ($1,$2,$3,$4,'prowler','Uncorrelated provider observation','high','open'),($1,$2,$3,$5,'prowler','Second uncorrelated provider observation','high','open')`, []any{organization, workspace, environment, invisibleFinding, invisibleAcceptFinding}},
		{`INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES ($1,$2,$3,$4,1,'pid_81000002-0000-4000-8000-000000000002'),($1,$2,$3,$5,1,'pid_81000004-0000-4000-8000-000000000004')`, []any{organization, workspace, environment, invisibleFinding, invisibleAcceptFinding}},
		{`INSERT INTO zasp_risk_attack_paths (organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) SELECT $1,$2,$3,'pid_'||lpad((20000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'pid_'||lpad((50000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'pid_'||lpad((60000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),'verified' FROM generate_series(1,1001) ordinal`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_risk_attack_path_nodes (organization_id,workspace_id,environment_id,path_id,position,node_id) SELECT $1,$2,$3,'pid_'||lpad((20000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),position,CASE position WHEN 1 THEN 'pid_'||lpad((50000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0') ELSE 'pid_'||lpad((60000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0') END FROM generate_series(1,1001) ordinal CROSS JOIN generate_series(1,2) position`, []any{organization, workspace, environment}},
		{`INSERT INTO zasp_risk_attack_path_evidence (organization_id,workspace_id,environment_id,path_id,position,evidence_id) SELECT $1,$2,$3,'pid_'||lpad((20000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0'),1,'pid_'||lpad((70000000+ordinal)::text,8,'0')||'-0000-4000-8000-'||lpad(ordinal::text,12,'0') FROM generate_series(1,1001) ordinal`, []any{organization, workspace, environment}},
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

	findingCount, findingPages, findingLastID := len(first.Items), 1, first.Items[len(first.Items)-1].ID
	findingCursor := first.PageInfo.NextCursor
	for findingCursor != nil {
		request = riskRequest(t, identity, "listFindings", http.MethodGet, "https://app.zasp.test/api/v1/findings?limit=100&cursor="+*findingCursor, "")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var page struct {
			Items    []RiskFinding `json:"items"`
			PageInfo struct {
				NextCursor *string `json:"next_cursor"`
				HasMore    bool    `json:"has_more"`
			} `json:"page_info"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) < 1 || page.PageInfo.HasMore != (page.PageInfo.NextCursor != nil) {
			t.Fatalf("finding page %d = %d %#v %s", findingPages+1, response.Code, page, response.Body.String())
		}
		for _, item := range page.Items {
			if item.ID <= findingLastID {
				t.Fatalf("finding keyset was not strictly increasing: %s <= %s", item.ID, findingLastID)
			}
			findingLastID = item.ID
		}
		findingCount += len(page.Items)
		findingPages++
		findingCursor = page.PageInfo.NextCursor
	}
	if findingCount != 1002 || findingPages != 11 || findingLastID != riskFindingID {
		t.Fatalf("finding traversal = count:%d pages:%d last:%s", findingCount, findingPages, findingLastID)
	}
	for _, id := range []string{invisibleFinding, invisibleAcceptFinding} {
		if _, err := repository.GetRiskFinding(ctx, identity.Scope, id); !errors.Is(err, ErrRepositoryNotFound) {
			t.Fatalf("irrelevant Prowler detail %s must be absent: %v", id, err)
		}
	}
	request = riskRequest(t, identity, "getFinding", http.MethodGet, "https://app.zasp.test/api/v1/findings/"+invisibleFinding, "")
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": invisibleFinding}}))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("irrelevant Prowler HTTP detail = %d %s", response.Code, response.Body.String())
	}
	for attempt := 0; attempt < 2; attempt++ {
		request = riskRequest(t, identity, "updateFinding", http.MethodPatch, "https://app.zasp.test/api/v1/findings/"+invisibleFinding, `{"status":"under_review"}`)
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "updateFinding", PathParameters: map[string]string{"id": invisibleFinding}}))
		request.Header.Set("If-Match", `"1"`)
		request.Header.Set("Idempotency-Key", "idem-invisible-update-001")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("irrelevant Prowler repeated PATCH %d = %d %s", attempt+1, response.Code, response.Body.String())
		}
	}
	visibilityConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	visibilityDatabase, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: visibilityConnection})
	visibilityRepository, _ := NewPostgresRepository(visibilityDatabase)
	visibilityHandler, _ := newRiskHTTPHandler(visibilityRepository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	invisibleRequests := make([]*http.Request, 2)
	invisibleResponses := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
	for index := range invisibleRequests {
		invisibleRequests[index] = riskRequest(t, identity, "acceptFindingRisk", http.MethodPost, "https://app.zasp.test/api/v1/findings/"+invisibleAcceptFinding+"/accept-risk", `{"reason":"Approved exception"}`)
		invisibleRequests[index] = invisibleRequests[index].WithContext(context.WithValue(invisibleRequests[index].Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "acceptFindingRisk", PathParameters: map[string]string{"id": invisibleAcceptFinding}}))
		invisibleRequests[index].Header.Set("If-Match", `"1"`)
		invisibleRequests[index].Header.Set("Idempotency-Key", "idem-invisible-accept-001")
	}
	startInvisible := make(chan struct{})
	var invisibleGroup sync.WaitGroup
	for index, currentHandler := range []*riskHTTPHandler{handler, visibilityHandler} {
		invisibleGroup.Add(1)
		go func(index int, currentHandler *riskHTTPHandler) {
			defer invisibleGroup.Done()
			<-startInvisible
			currentHandler.ServeHTTP(invisibleResponses[index], invisibleRequests[index])
		}(index, currentHandler)
	}
	close(startInvisible)
	invisibleGroup.Wait()
	if invisibleResponses[0].Code != http.StatusNotFound || invisibleResponses[1].Code != http.StatusNotFound {
		t.Fatalf("irrelevant Prowler concurrent accept = first:%d/%s second:%d/%s", invisibleResponses[0].Code, invisibleResponses[0].Body.String(), invisibleResponses[1].Code, invisibleResponses[1].Body.String())
	}
	var invisibleRows, invisibleIdempotency, invisibleAudits, invisibleReceipts int
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM zasp_risk_findings WHERE id IN ($1,$2) AND status='open' AND version=1 AND acceptance_reason IS NULL),
		(SELECT count(*) FROM zasp_workflow_idempotency WHERE idempotency_key IN ('idem-invisible-update-001','idem-invisible-accept-001')),
		(SELECT count(*) FROM zasp_workflow_audit WHERE resource_id IN ($1,$2)),
		(SELECT count(*) FROM zasp_workflow_receipts WHERE resource_id IN ($1,$2))`, invisibleFinding, invisibleAcceptFinding).Scan(&invisibleRows, &invisibleIdempotency, &invisibleAudits, &invisibleReceipts); err != nil || invisibleRows != 2 || invisibleIdempotency != 0 || invisibleAudits != 0 || invisibleReceipts != 0 {
		t.Fatalf("irrelevant Prowler residue = rows:%d idempotency:%d audit:%d receipt:%d (%v)", invisibleRows, invisibleIdempotency, invisibleAudits, invisibleReceipts, err)
	}
	_ = visibilityDatabase.Close()

	request = riskRequest(t, identity, "listAttackPaths", http.MethodGet, "https://app.zasp.test/api/v1/attack-paths?limit=100", "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var pathPage struct {
		Items    []RiskAttackPath `json:"items"`
		PageInfo struct {
			NextCursor *string `json:"next_cursor"`
			HasMore    bool    `json:"has_more"`
		} `json:"page_info"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &pathPage) != nil || len(pathPage.Items) != 100 || pathPage.PageInfo.NextCursor == nil || !pathPage.PageInfo.HasMore {
		t.Fatalf("first attack-path page = %d %#v %s", response.Code, pathPage, response.Body.String())
	}
	pathCount, pathPages, pathLastID := len(pathPage.Items), 1, pathPage.Items[len(pathPage.Items)-1].ID
	pathCursor := pathPage.PageInfo.NextCursor
	for pathCursor != nil {
		request = riskRequest(t, identity, "listAttackPaths", http.MethodGet, "https://app.zasp.test/api/v1/attack-paths?limit=100&cursor="+*pathCursor, "")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		pathPage = struct {
			Items    []RiskAttackPath `json:"items"`
			PageInfo struct {
				NextCursor *string `json:"next_cursor"`
				HasMore    bool    `json:"has_more"`
			} `json:"page_info"`
		}{}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &pathPage) != nil || len(pathPage.Items) < 1 || pathPage.PageInfo.HasMore != (pathPage.PageInfo.NextCursor != nil) {
			t.Fatalf("attack-path page %d = %d %#v %s", pathPages+1, response.Code, pathPage, response.Body.String())
		}
		for _, item := range pathPage.Items {
			if item.ID <= pathLastID {
				t.Fatalf("attack-path keyset was not strictly increasing: %s <= %s", item.ID, pathLastID)
			}
			pathLastID = item.ID
		}
		pathCount += len(pathPage.Items)
		pathPages++
		pathCursor = pathPage.PageInfo.NextCursor
	}
	if pathCount != 1002 || pathPages != 11 || pathLastID != riskPathID {
		t.Fatalf("attack-path traversal = count:%d pages:%d last:%s", pathCount, pathPages, pathLastID)
	}

	path, err := repository.GetRiskAttackPath(ctx, identity.Scope, riskPathID)
	options, optionsErr := repository.GetRiskBreakOptions(ctx, identity.Scope, riskPathID)
	if err != nil || optionsErr != nil || len(path.NodeIDs) != 2 || len(options) != 1 || options[0].TargetID != riskNodeOne {
		t.Fatalf("path/options = %#v/%#v (%v/%v)", path, options, err, optionsErr)
	}
	highPathCount, err := repository.CountHighRiskPaths(ctx, identity.Scope)
	if err != nil || highPathCount != 1002 {
		t.Fatalf("valid high path count = %d (%v)", highPathCount, err)
	}
	hostilePath := "pid_80000001-0000-4000-8000-000000000001"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_attack_paths (organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES ($1,$2,$3,$4,$5,$6,'verified')`, organization, workspace, environment, hostilePath, riskNodeOne, riskNodeTwo); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetRiskAttackPath(ctx, identity.Scope, hostilePath); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("malformed detail must be absent: %v", err)
	}
	if _, err := repository.GetRiskBreakOptions(ctx, identity.Scope, hostilePath); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("malformed break-options path must be absent: %v", err)
	}
	malformedPage, err := repository.ListRiskAttackPathPage(ctx, identity.Scope, pathLastID, 100)
	if err != nil || len(malformedPage.Items) != 0 || malformedPage.NextID != "" {
		t.Fatalf("malformed list candidate must be absent: %#v (%v)", malformedPage, err)
	}
	highPathCount, err = repository.CountHighRiskPaths(ctx, identity.Scope)
	if err != nil || highPathCount != 1002 {
		t.Fatalf("malformed path contradicted home count = %d (%v)", highPathCount, err)
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
	recoveredReceipts, err := repository.ListWorkflowMutationReceipts(ctx, identity, 20)
	if err != nil || len(recoveredReceipts) != 1 {
		t.Fatalf("finding recovery receipts = (%#v, %v)", recoveredReceipts, err)
	}
	var recoveredFinding RiskFinding
	if err := decodeStrictRisk(recoveredReceipts[0].Result, &recoveredFinding); err != nil || !strings.HasSuffix(recoveredFinding.CreatedAt.Format(time.RFC3339Nano), "Z") || !strings.HasSuffix(recoveredFinding.UpdatedAt.Format(time.RFC3339Nano), "Z") || strings.Contains(string(recoveredReceipts[0].Result), "+00:00") {
		t.Fatalf("finding recovery result is not canonical UTC: %s (%v)", recoveredReceipts[0].Result, err)
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

	concurrentFinding := "pid_80000002-0000-4000-8000-000000000002"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES ($1,$2,$3,$4,'posture','Concurrent replay','high','open')`, organization, workspace, environment, concurrentFinding); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES ($1,$2,$3,$4,1,$5)`, organization, workspace, environment, concurrentFinding, "pid_80000003-0000-4000-8000-000000000003"); err != nil {
		t.Fatal(err)
	}
	secondConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	secondDatabase, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: secondConnection})
	secondRepository, _ := NewPostgresRepository(secondDatabase)
	secondHandler, _ := newRiskHTTPHandler(secondRepository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	requests := make([]*http.Request, 2)
	responses := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
	for index := range requests {
		requests[index] = riskRequest(t, identity, "updateFinding", http.MethodPatch, "https://app.zasp.test/api/v1/findings/"+concurrentFinding, `{"status":"under_review"}`)
		requests[index] = requests[index].WithContext(context.WithValue(requests[index].Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "updateFinding", PathParameters: map[string]string{"id": concurrentFinding}}))
		requests[index].Header.Set("If-Match", `"1"`)
		requests[index].Header.Set("Idempotency-Key", "idem-pg-risk-concurrent-001")
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	for index, currentHandler := range []*riskHTTPHandler{handler, secondHandler} {
		group.Add(1)
		go func(index int, currentHandler *riskHTTPHandler) {
			defer group.Done()
			<-start
			currentHandler.ServeHTTP(responses[index], requests[index])
		}(index, currentHandler)
	}
	close(start)
	group.Wait()
	if responses[0].Code != http.StatusOK || responses[1].Code != http.StatusOK || responses[0].Header().Get("X-Audit-ID") != responses[1].Header().Get("X-Audit-ID") || responses[0].Header().Get("X-Mutation-Receipt-ID") != responses[1].Header().Get("X-Mutation-Receipt-ID") || !equalIntegrationJSON(responses[0].Body.Bytes(), responses[1].Body.Bytes()) {
		t.Fatalf("concurrent same-key replay = first:%d/%v/%s second:%d/%v/%s", responses[0].Code, responses[0].Header(), responses[0].Body.String(), responses[1].Code, responses[1].Header(), responses[1].Body.String())
	}
	var concurrentIdempotency, concurrentAudits, concurrentReceipts int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_idempotency WHERE idempotency_key='idem-pg-risk-concurrent-001'),(SELECT count(*) FROM zasp_workflow_audit WHERE resource_id=$1),(SELECT count(*) FROM zasp_workflow_receipts WHERE resource_id=$1)`, concurrentFinding).Scan(&concurrentIdempotency, &concurrentAudits, &concurrentReceipts); err != nil || concurrentIdempotency != 1 || concurrentAudits != 1 || concurrentReceipts != 1 {
		t.Fatalf("concurrent durable cardinality = idempotency:%d audit:%d receipt:%d (%v)", concurrentIdempotency, concurrentAudits, concurrentReceipts, err)
	}
	_ = secondDatabase.Close()

	sharedEvidenceFinding := "pid_83000001-0000-4000-8000-000000000001"
	for _, seed := range []struct {
		statement string
		arguments []any
	}{
		{`INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES ($1,$2,$3,$4,'posture','Shared factor evidence','high','open')`, []any{organization, workspace, environment, sharedEvidenceFinding}},
		{`INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES ($1,$2,$3,$4,1,$5)`, []any{organization, workspace, environment, sharedEvidenceFinding, riskEvidence}},
		{`INSERT INTO zasp_risk_finding_factors (organization_id,workspace_id,environment_id,finding_id,position,name,evidence_id) VALUES ($1,$2,$3,$4,1,'Public input',$5),($1,$2,$3,$4,2,'Privileged sink',$5)`, []any{organization, workspace, environment, sharedEvidenceFinding, riskEvidence}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_finding_factors (organization_id,workspace_id,environment_id,finding_id,position,name,evidence_id) VALUES ($1,$2,$3,$4,3,'Public input',$5)`, organization, workspace, environment, sharedEvidenceFinding, riskEvidence); err == nil {
		t.Fatal("duplicate factor name was accepted")
	} else {
		var duplicateNameError *pgconn.PgError
		if !errors.As(err, &duplicateNameError) || duplicateNameError.Code != "23505" {
			t.Fatalf("duplicate factor name error = %v", err)
		}
	}
	sharedEvidenceProjection, err := repository.GetRiskFinding(ctx, identity.Scope, sharedEvidenceFinding)
	if err != nil || len(sharedEvidenceProjection.RiskFactors) != 2 || sharedEvidenceProjection.RiskFactors[0].Name != "Public input" || sharedEvidenceProjection.RiskFactors[1].Name != "Privileged sink" || sharedEvidenceProjection.RiskFactors[0].EvidenceID != riskEvidence || sharedEvidenceProjection.RiskFactors[1].EvidenceID != riskEvidence {
		t.Fatalf("shared parent evidence projection = %#v (%v)", sharedEvidenceProjection, err)
	}

	foreignEvidenceFinding := "pid_82000001-0000-4000-8000-000000000001"
	foreignEvidencePath := "pid_82000002-0000-4000-8000-000000000002"
	foreignEvidenceID := "pid_82000003-0000-4000-8000-000000000003"
	for _, seed := range []struct {
		statement string
		arguments []any
	}{
		{`INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES ($1,$2,$3,$4,'posture','Foreign factor evidence','high','open')`, []any{organization, workspace, environment, foreignEvidenceFinding}},
		{`INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES ($1,$2,$3,$4,1,$5)`, []any{organization, workspace, environment, foreignEvidenceFinding, riskEvidence}},
		{`INSERT INTO zasp_risk_finding_factors (organization_id,workspace_id,environment_id,finding_id,position,name,evidence_id) VALUES ($1,$2,$3,$4,1,'Foreign evidence',$5)`, []any{organization, workspace, environment, foreignEvidenceFinding, foreignEvidenceID}},
		{`INSERT INTO zasp_risk_attack_paths (organization_id,workspace_id,environment_id,id,entry_id,sink_id,state) VALUES ($1,$2,$3,$4,$5,$6,'verified')`, []any{organization, workspace, environment, foreignEvidencePath, riskNodeOne, riskNodeTwo}},
		{`INSERT INTO zasp_risk_attack_path_nodes (organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES ($1,$2,$3,$4,1,$5),($1,$2,$3,$4,2,$6)`, []any{organization, workspace, environment, foreignEvidencePath, riskNodeOne, riskNodeTwo}},
		{`INSERT INTO zasp_risk_attack_path_evidence (organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES ($1,$2,$3,$4,1,$5)`, []any{organization, workspace, environment, foreignEvidencePath, riskEvidence}},
		{`INSERT INTO zasp_risk_break_options (organization_id,workspace_id,environment_id,path_id,rank,target_id,evidence_id,kind) VALUES ($1,$2,$3,$4,1,$5,$6,'remove_node')`, []any{organization, workspace, environment, foreignEvidencePath, riskNodeOne, foreignEvidenceID}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	for _, check := range []struct {
		name  string
		query string
		id    string
	}{
		{"break option", `SELECT zasp_risk_break_options_get($1,$2,$3,$4)`, foreignEvidencePath},
		{"finding factor", `SELECT zasp_risk_finding_get($1,$2,$3,$4)`, foreignEvidenceFinding},
	} {
		var payload json.RawMessage
		err := connection.QueryRow(ctx, check.query, check.id, organization, workspace, environment).Scan(&payload)
		var projectionError *pgconn.PgError
		if !errors.As(err, &projectionError) || projectionError.Code != "22023" {
			t.Fatalf("%s foreign evidence projection = %s (%v)", check.name, payload, err)
		}
	}
	if _, err := repository.GetRiskFinding(ctx, identity.Scope, foreignEvidenceFinding); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("foreign finding-factor evidence repository error = %v", err)
	}
	if _, err := repository.GetRiskBreakOptions(ctx, identity.Scope, foreignEvidencePath); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("foreign break-option evidence repository error = %v", err)
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
