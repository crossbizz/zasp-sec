package authorization

import (
	"strings"
	"testing"
)

const org = "pid_10000000-0000-4000-8000-000000000001"
const workspace = "pid_20000000-0000-4000-8000-000000000001"
const environment = "pid_30000000-0000-4000-8000-000000000001"
const principal = "pid_40000000-0000-4000-8000-000000000001"
const resource = "pid_50000000-0000-4000-8000-000000000001"
const task = "pid_60000000-0000-4000-8000-000000000001"

func exampleRequest() CheckRequest {
	return CheckRequest{PrincipalKind: "user", PrincipalID: principal, OrganizationID: org, WorkspaceID: workspace, EnvironmentID: environment, ResourceType: "finding", ResourceID: resource, Permission: "view"}
}

// Catches unstable provider IDs, ambiguous object encoding and grants that skip
// exact scope or silently turn machines into members of a human role.
func TestPrincipalMapping(t *testing.T) {
	request := exampleRequest()
	got, err := Map(request)
	if err != nil || got.User != "user:"+principal || got.Object != "resource:"+org+"/"+workspace+"/"+environment+"/finding/"+resource || got.Relation != "view" {
		t.Fatalf("canonical binding: %#v %v", got, err)
	}
	hierarchy, err := Hierarchy(request)
	if err != nil || len(hierarchy) != 3 || hierarchy[0].Relation != "organization" || hierarchy[1].Relation != "workspace" || hierarchy[2].Relation != "environment" {
		t.Fatalf("single parent chain: %#v %v", hierarchy, err)
	}
	for _, mutate := range []func(*CheckRequest){
		func(r *CheckRequest) { r.PrincipalID = "member-live-provider" },
		func(r *CheckRequest) { r.PrincipalKind = "pat" },
		func(r *CheckRequest) { r.ResourceType = "finding#viewer" },
		func(r *CheckRequest) { r.WorkspaceID = r.OrganizationID },
		func(r *CheckRequest) { r.Permission = "export_evidence" },
		func(r *CheckRequest) { r.PrincipalKind = "agent" },
		func(r *CheckRequest) { r.ResourceType = "environment"; r.ResourceID = resource },
	} {
		bad := request
		mutate(&bad)
		if _, err := Map(bad); err == nil {
			t.Fatalf("accepted invalid binding: %#v", bad)
		}
	}
	for _, kind := range []string{"agent", "service"} {
		r := request
		r.PrincipalKind = kind
		r.TaskID = task
		got, err := Map(r)
		if err != nil || got.User != kind+":"+principal {
			t.Fatalf("machine mapping: %#v %v", got, err)
		}
		if _, err = ScopedRole(r, "organization_admin"); err == nil {
			t.Fatal("machine acquired human role")
		}
		grant, err := DelegationGrant(r)
		if err != nil || len(grant) != 2 || grant[1].Relation != "delegated_view" || grant[0].Condition == nil {
			t.Fatalf("unbounded delegation: %#v %v", grant, err)
		}
	}
	grant, err := ScopedRole(request, "security_admin")
	if err != nil || !strings.HasPrefix(grant.Object, "environment:") || grant.Relation != "security_admin" {
		t.Fatalf("scoped role: %#v %v", grant, err)
	}
	if _, err := ScopedRole(request, "owner"); err == nil {
		t.Fatal("unknown role allowed")
	}
}

// Distinct delegation keys prevent one task's projection from overwriting
// another task's grant, even for the same machine, target and permission.
func TestConcurrentDelegationMapping(t *testing.T) {
	r := exampleRequest()
	r.PrincipalKind, r.TaskID = "agent", task
	first, err := DelegationGrant(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(first[0].Object) > 256 {
		t.Fatal("delegation exceeds backend object limit")
	}
	r.TaskID = "pid_60000000-0000-4000-8000-000000000002"
	second, err := DelegationGrant(r)
	if err != nil || len(first) != 2 || len(second) != 2 || first[0].Object == second[0].Object || first[1].User == second[1].User || first[1].Object != second[1].Object {
		t.Fatalf("task grants collide: %#v %#v %v", first, second, err)
	}
	r.PrincipalKind = "user"
	r.TaskID = ""
	if _, err := DelegationGrant(r); err == nil {
		t.Fatal("human delegated as a machine")
	}
}

// Catches omitted bootstrap policy, lost optional routes and lossy aliases for
// the production manage_workflows bucket.
func TestOperationPolicy(t *testing.T) {
	for _, tc := range []struct{ id, permission, surface string }{
		{"createIntegration", "manage_workflows", "core"}, {"decideSecurityAgentApproval", "manage_workflows", "core"},
		{"createAuditExport", "view_audit", "audit"}, {"downloadComplianceExport", "view_compliance", "compliance"},
		{"downloadSecurityAgentExport", "view", "security_agent_export"}, {"bootstrapSession", "", "core"},
	} {
		p, err := LookupOperation(tc.id)
		if err != nil || p.Permission != tc.permission || p.Relation != tc.permission || p.Surface != tc.surface {
			t.Errorf("%s: %#v %v", tc.id, p, err)
		}
	}
	if _, err := LookupOperation("unknownOperation"); err == nil {
		t.Fatal("unknown operation accepted")
	}
	for _, id := range []string{"startRecoveryBackup", "startRecoveryRestore", "createSensorEnrollment", "rotateSensorToken"} {
		p, err := LookupOperation(id)
		if err != nil || !p.FreshAuth || !contains(p.Security, "ProductAPIToken") {
			t.Errorf("PAT/fresh-auth contract lost: %s %#v", id, p)
		}
	}
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
