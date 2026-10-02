package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
)

// These examples exercise Zasp's actual permission model on the retained local
// service. A fresh owned store cannot change the active runtime configuration.
func TestLocalPermissionModel(t *testing.T) {
	if os.Getenv("ZASP_P5_MODEL_TEST") != "1" {
		t.Skip("requires retained local OpenFGA service; set ZASP_P5_MODEL_TEST=1")
	}
	modelBytes, err := os.ReadFile("model.json")
	if err != nil {
		t.Fatalf("product authorization model missing: %v", err)
	}
	var model fga.ClientWriteAuthorizationModelRequest
	if err := json.Unmarshal(modelBytes, &model); err != nil {
		t.Fatal(err)
	}
	endpoint, token := localOpenFGAConnection(t)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: endpoint, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
	if err != nil {
		t.Fatal("SDK configuration failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	store, err := client.CreateStore(ctx).Body(fga.ClientCreateStoreRequest{Name: "zasp-p5-owned-permission-examples"}).Execute()
	if err != nil {
		t.Fatal("owned development store creation failed")
	}
	if err := client.SetStoreId(store.Id); err != nil {
		t.Fatal("store pin failed")
	}
	written, err := client.WriteAuthorizationModel(ctx).Body(model).Execute()
	if err != nil {
		t.Fatal("product model publication rejected")
	}
	config := testConfig(endpoint)
	config.StoreID = store.Id
	config.ModelID = written.AuthorizationModelId
	config.Timeout = 5 * time.Second
	checker, err := NewOpenFGA(client, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("owned store=%s model=%s; no runtime configuration changed", store.Id, written.AuthorizationModelId)
	request := exampleRequest()
	hierarchy, err := Hierarchy(request)
	if err != nil {
		t.Fatal(err)
	}
	tuples := append([]fga.ClientTupleKey{}, hierarchy...)
	roles := []string{"organization_admin", "security_admin", "security_engineer", "developer_owner", "compliance_viewer", "read_only_viewer"}
	ids := []string{principal, "pid_40000000-0000-4000-8000-000000000002", "pid_40000000-0000-4000-8000-000000000003", "pid_40000000-0000-4000-8000-000000000004", "pid_40000000-0000-4000-8000-000000000005", "pid_40000000-0000-4000-8000-000000000006"}
	for i, role := range roles {
		r := request
		r.PrincipalID = ids[i]
		grant, err := ScopedRole(r, role)
		if err != nil {
			t.Fatal(err)
		}
		tuples = append(tuples, grant, fga.ClientTupleKey{User: "user:" + ids[i], Relation: "member", Object: "organization:" + org})
	}
	// The sibling has ancestry and membership but no scoped role. Admin is denied.
	sibling := request
	sibling.EnvironmentID = "pid_30000000-0000-4000-8000-000000000002"
	sibling.ResourceType = "environment"
	sibling.ResourceID = sibling.EnvironmentID
	parents, _ := Hierarchy(sibling)
	tuples = append(tuples, parents[1])
	otherWorkspace := request
	otherWorkspace.WorkspaceID = "pid_20000000-0000-4000-8000-000000000003"
	parents, _ = Hierarchy(otherWorkspace)
	tuples = append(tuples, parents...)
	otherOrg := request
	otherOrg.OrganizationID = "pid_10000000-0000-4000-8000-000000000002"
	otherOrg.WorkspaceID = "pid_20000000-0000-4000-8000-000000000002"
	otherOrg.EnvironmentID = "pid_30000000-0000-4000-8000-000000000003"
	parents, _ = Hierarchy(otherOrg)
	tuples = append(tuples, parents...)
	// A bad desired-state grant without membership must not cross tenants.
	crossGrant, _ := ScopedRole(otherOrg, "organization_admin")
	tuples = append(tuples, crossGrant)
	direct := request
	direct.PrincipalID = "pid_40000000-0000-4000-8000-000000000007"
	direct.Permission = "view_audit"
	directGrant, _ := ResourceGrant(direct)
	tuples = append(tuples, directGrant, fga.ClientTupleKey{User: "user:" + direct.PrincipalID, Relation: "member", Object: "organization:" + org})
	for _, kind := range []string{"agent", "service"} {
		machine := request
		machine.PrincipalKind = kind
		machine.TaskID = task
		machine.Permission = "run_tests"
		for _, taskID := range []string{task, "pid_60000000-0000-4000-8000-000000000002"} {
			machine.TaskID = taskID
			grant, err := DelegationGrant(machine)
			if err != nil {
				t.Fatal(err)
			}
			tuples = append(tuples, grant...)
		}
		machine.Permission = "view"
		grant, err := DelegationGrant(machine)
		if err != nil {
			t.Fatal(err)
		}
		tuples = append(tuples, grant...)
		tuples = append(tuples, fga.ClientTupleKey{User: kind + ":" + principal, Relation: "member", Object: "organization:" + org})
	}
	_, err = client.Write(ctx).Body(fga.ClientWriteRequest{Writes: tuples}).Options(fga.ClientWriteOptions{AuthorizationModelId: &config.ModelID}).Execute()
	if err != nil {
		t.Fatal("product example tuple publication failed")
	}
	permissions := []string{"investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance"}
	// Literal expectations come from the approved role decision, not model code.
	allowed := [][]bool{
		{true, true, true, true, true, true, true, true, true, true, true},
		{true, true, true, true, true, true, true, true, true, true, true},
		{true, false, false, true, false, true, false, true, true, false, false},
		{true, false, false, false, false, false, false, true, true, false, false},
		{false, false, false, false, false, false, false, false, true, true, true},
		{false, false, false, false, false, false, false, false, true, false, false},
	}
	checks := 0
	check := func(name string, r CheckRequest, want bool) {
		t.Helper()
		checks++
		decision, err := checker.Check(ctx, r)
		if err != nil || decision.Allowed != want || decision.ModelID != config.ModelID {
			t.Errorf("%s: allow=%v want=%v err=%v", name, decision.Allowed, want, err)
		}
	}
	for i, role := range roles {
		for j, permission := range permissions {
			r := request
			r.PrincipalID = ids[i]
			r.Permission = permission
			check(role+"/"+permission, r, allowed[i][j])
		}
	}
	check("admin sibling environment", sibling, false)
	check("admin other organization", otherOrg, false)
	check("admin other workspace", otherWorkspace, false)
	for _, id := range ids[:2] {
		sibling.PrincipalID = id
		check("both admin roles require exact grants", sibling, false)
	}
	check("explicit resource audit access", direct, true)
	direct.Permission = "view_compliance"
	check("audit grant is not compliance export", direct, false)
	direct.Permission = "view_audit"
	direct.ResourceID = "pid_50000000-0000-4000-8000-000000000002"
	check("direct grant cannot read sibling object", direct, false)
	for _, kind := range []string{"agent", "service"} {
		r := request
		r.PrincipalKind = kind
		r.TaskID = task
		r.Permission = "run_tests"
		check(kind+" bound task and target", r, true)
		r.TaskID = "pid_60000000-0000-4000-8000-000000000002"
		check(kind+" concurrent second task same target", r, true)
		r.Permission = "view"
		check(kind+" second task view grant", r, true)
		r.TaskID = task
		check(kind+" cannot borrow second task view", r, false)
		r.Permission = "run_tests"
		r.TaskID = "pid_60000000-0000-4000-8000-000000000003"
		check(kind+" wrong task", r, false)
		r.TaskID = task
		r.ResourceID = "pid_50000000-0000-4000-8000-000000000002"
		check(kind+" wrong target", r, false)
		r = request
		r.PrincipalKind = kind
		r.TaskID = task
		r.Permission = "manage_identity"
		check(kind+" cannot inherit creator admin", r, false)
		r.Permission = "run_tests"
		grant, err := DelegationGrant(r)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Write(ctx).Body(fga.ClientWriteRequest{Deletes: []fga.ClientTupleKeyWithoutCondition{{User: grant[1].User, Relation: grant[1].Relation, Object: grant[1].Object}}}).Options(fga.ClientWriteOptions{AuthorizationModelId: &config.ModelID}).Execute()
		if err != nil {
			t.Fatal("delegation revocation failed")
		}
		check(kind+" first task independently revoked", r, false)
		r.TaskID = "pid_60000000-0000-4000-8000-000000000002"
		check(kind+" second task survives first revocation", r, true)
	}
	// Remove membership while retaining its role tuples. This is model behavior,
	// not evidence of P6 delivery or the P7 SQL revocation race fence.
	_, err = client.Write(ctx).Body(fga.ClientWriteRequest{Deletes: []fga.ClientTupleKeyWithoutCondition{{User: "user:" + principal, Relation: "member", Object: "organization:" + org}}}).Options(fga.ClientWriteOptions{AuthorizationModelId: &config.ModelID}).Execute()
	if err != nil {
		t.Fatal("example membership removal failed")
	}
	check("removed membership", request, false)
	t.Logf("%d application permission checks; six roles, tenant/scope boundaries, direct grants, task-bound machines, membership removal", checks)
}
