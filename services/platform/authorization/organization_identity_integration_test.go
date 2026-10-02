package authorization

import (
	"context"
	"encoding/json"
	"errors"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"net/http"
	"os"
	"testing"
	"time"
)

// Breaks if the deployed model loses the organization permission, its membership
// intersection, or isolates organization authority incorrectly from scoped roles.
func TestOrganizationIdentityLocalModel(t *testing.T) {
	if os.Getenv("ZASP_P7_ORG_IDENTITY_MODEL_TEST") != "1" {
		t.Skip("requires owned local FGA store; set ZASP_P7_ORG_IDENTITY_MODEL_TEST=1")
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
	store, err := client.CreateStore(ctx).Body(fga.ClientCreateStoreRequest{Name: "zasp-p7-owned-organization-identity"}).Execute()
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

	ids := []string{principal, "pid_40000000-0000-4000-8000-000000000002", "pid_40000000-0000-4000-8000-000000000003", "pid_40000000-0000-4000-8000-000000000004"}
	snapshot := projectionFixture()
	snapshot.Revision.StoreID, snapshot.Revision.ModelID = config.StoreID, config.ModelID
	snapshot.Members = []ProjectionMember{{Kind: "user", ID: ids[0], OrganizationRole: "organization_admin"}, {Kind: "user", ID: ids[1], OrganizationRole: "security_admin"}, {Kind: "user", ID: ids[2]}, {Kind: "user", ID: ids[3]}, {Kind: "agent", ID: principal}, {Kind: "service", ID: principal}}
	snapshot.Roles = []ProjectionRole{{ProjectionScope: snapshot.Scopes[0], PrincipalID: ids[3], Role: "security_admin"}}
	snapshot.Grants = nil
	sibling := snapshot.Scopes[0]
	sibling.EnvironmentID = "pid_30000000-0000-4000-8000-000000000002"
	snapshot.Scopes = append(snapshot.Scopes, sibling)
	siblingResource := "pid_50000000-0000-4000-8000-000000000002"
	snapshot.Resources = append(snapshot.Resources, ProjectionResource{ProjectionScope: sibling, Kind: "finding", ID: siblingResource})
	tuples, err := Project(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	foreign := "pid_10000000-0000-4000-8000-000000000002"
	tuples = append(tuples, fga.ClientTupleKey{User: "user:" + principal, Relation: "member", Object: "organization:" + foreign})
	_, err = client.Write(ctx).Body(fga.ClientWriteRequest{Writes: tuples}).Options(fga.ClientWriteOptions{AuthorizationModelId: &config.ModelID}).Execute()
	if err != nil {
		t.Fatal("organization identity source tuples rejected by product model")
	}
	checks := 0
	check := func(name string, r CheckRequest, want bool) {
		t.Helper()
		checks++
		d, err := checker.Check(ctx, r)
		if err != nil || d.Allowed != want || d.ModelID != config.ModelID {
			t.Errorf("%s: allow=%v want=%v error=%v", name, d.Allowed, want, err)
		}
	}
	for i, id := range ids {
		r := organizationIdentityRequest()
		r.PrincipalID = id
		check("organization role "+id, r, i < 2)
	}
	r := organizationIdentityRequest()
	r.OrganizationID = foreign
	r.ResourceID = foreign
	check("foreign organization membership alone", r, false)
	for _, id := range ids[:2] {
		for _, scope := range snapshot.Scopes {
			for _, permission := range []string{"view", "manage_identity"} {
				r := exampleRequest()
				r.PrincipalID = id
				r.EnvironmentID = scope.EnvironmentID
				if scope.EnvironmentID == sibling.EnvironmentID {
					r.ResourceID = siblingResource
				}
				r.Permission = permission
				check("organization admin has no resource scope", r, false)
				r.ResourceType = "environment"
				r.ResourceID = r.EnvironmentID
				check("organization admin has no environment scope", r, false)
			}
		}
	}
	scoped := exampleRequest()
	scoped.PrincipalID = ids[3]
	scoped.Permission = "manage_identity"
	check("existing explicit scoped role retained", scoped, true)
	scoped.EnvironmentID = sibling.EnvironmentID
	scoped.ResourceID = siblingResource
	check("scoped role cannot reach sibling", scoped, false)
	for _, kind := range []string{"agent", "service"} {
		r := organizationIdentityRequest()
		r.PrincipalKind = kind
		r.TaskID = task
		if _, err := checker.Check(ctx, r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s request was not rejected", kind)
		}
		raw, err := client.Check(ctx).Body(fga.ClientCheckRequest{User: kind + ":" + principal, Relation: "manage_identity", Object: "organization:" + org}).Options(fga.ClientCheckOptions{AuthorizationModelId: &config.ModelID}).Execute()
		if err != nil || raw == nil || raw.GetAllowed() {
			t.Errorf("%s model membership granted organization authority", kind)
		}
	}
	// Reconcile a role downgrade using the desired source projection, not a
	// handwritten deletion that could conceal a projection revocation mistake.
	snapshot.Members[0].OrganizationRole = ""
	desired, err := Project(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	key := func(t fga.ClientTupleKey) string { return t.User + "|" + t.Relation + "|" + t.Object }
	for _, tuple := range desired {
		present[key(tuple)] = true
	}
	var deletes []fga.ClientTupleKeyWithoutCondition
	for _, tuple := range tuples {
		if tuple.Object == "organization:"+org && !present[key(tuple)] {
			deletes = append(deletes, fga.ClientTupleKeyWithoutCondition{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object})
		}
	}
	if len(deletes) != 1 {
		t.Fatalf("role downgrade changed %d organization tuples, want 1", len(deletes))
	}
	_, err = client.Write(ctx).Body(fga.ClientWriteRequest{Deletes: deletes}).Options(fga.ClientWriteOptions{AuthorizationModelId: &config.ModelID}).Execute()
	if err != nil {
		t.Fatal("organization role revocation failed")
	}
	check("role removed, membership retained", organizationIdentityRequest(), false)
	_, err = client.Write(ctx).Body(fga.ClientWriteRequest{Deletes: []fga.ClientTupleKeyWithoutCondition{{User: "user:" + ids[1], Relation: "member", Object: "organization:" + org}}}).Options(fga.ClientWriteOptions{AuthorizationModelId: &config.ModelID}).Execute()
	if err != nil {
		t.Fatal("organization membership revocation failed")
	}
	r = organizationIdentityRequest()
	r.PrincipalID = ids[1]
	check("membership removed, role retained", r, false)
	t.Logf("%d checker decisions plus machine request/model denials; role and membership revocation verified", checks)
}
