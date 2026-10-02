package authorization

import (
	"encoding/json"
	"errors"
	"testing"
)

func organizationIdentityRequest() CheckRequest {
	r := exampleRequest()
	r.ResourceType, r.ResourceID, r.Permission = "organization_identity", org, "manage_identity"
	return r
}

// Breaks if organization identity falls back to a scoped resource or admits a
// machine, task, foreign organization, or a different permission.
func TestOrganizationIdentityBinding(t *testing.T) {
	r := organizationIdentityRequest()
	got, err := Map(r)
	want := Binding{User: "user:" + principal, Object: "organization:" + org, Relation: "manage_identity"}
	if err != nil || got != want {
		t.Errorf("binding = %#v, %v; want %#v", got, err, want)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*CheckRequest)
	}{
		{"foreign resource", func(r *CheckRequest) { r.ResourceID = resource }},
		{"different permission", func(r *CheckRequest) { r.Permission = "view" }},
		{"agent", func(r *CheckRequest) { r.PrincipalKind = "agent"; r.TaskID = task }},
		{"service", func(r *CheckRequest) { r.PrincipalKind = "service"; r.TaskID = task }},
		{"human task", func(r *CheckRequest) { r.TaskID = task }},
		{"missing workspace", func(r *CheckRequest) { r.WorkspaceID = "" }},
		{"missing environment", func(r *CheckRequest) { r.EnvironmentID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := r
			tc.mutate(&bad)
			if _, err := Map(bad); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid binding accepted: %v", err)
			}
		})
	}
	if _, err := Hierarchy(r); !errors.Is(err, ErrInvalid) {
		t.Error("organization identity admitted scoped ancestry")
	}
	if _, err := ScopedRole(r, "organization_admin"); !errors.Is(err, ErrInvalid) {
		t.Error("organization identity admitted scoped role")
	}
	if _, err := ResourceGrant(r); !errors.Is(err, ErrInvalid) {
		t.Error("organization identity admitted direct resource grant")
	}
	if _, err := DelegationGrant(r); !errors.Is(err, ErrInvalid) {
		t.Error("organization identity admitted delegation")
	}
}

// JSON is the SQL snapshot boundary. Losing its organization_role field must
// fail these tests even when ordinary membership and scoped roles still work.
func TestOrganizationIdentityProjection(t *testing.T) {
	for _, tc := range []struct {
		kind, role string
		want       bool
	}{
		{"user", "organization_admin", true}, {"user", "security_admin", true},
		{"user", "", false}, {"user", "security_engineer", false},
		{"agent", "organization_admin", false}, {"service", "security_admin", false},
	} {
		t.Run(tc.kind+"/"+tc.role, func(t *testing.T) {
			snapshot := projectionFixture()
			payload, _ := json.Marshal([]map[string]string{{"kind": tc.kind, "id": principal, "organization_role": tc.role}})
			if err := json.Unmarshal(payload, &snapshot.Members); err != nil {
				t.Fatal(err)
			}
			snapshot.Roles = nil
			snapshot.Grants = nil
			tuples, err := Project(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, tuple := range tuples {
				if tuple.Object == "organization:"+org && tuple.Relation == tc.role && tuple.User == tc.kind+":"+principal {
					found = true
				}
			}
			if found != tc.want {
				t.Fatalf("explicit organization role present=%v want=%v; tuples=%#v", found, tc.want, tuples)
			}
			if tc.want {
				snapshot.Members = nil
				if err := json.Unmarshal([]byte(`[{"kind":"user","id":"`+principal+`"}]`), &snapshot.Members); err != nil {
					t.Fatal(err)
				}
				revoked, err := Project(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				for _, tuple := range revoked {
					if tuple.Object == "organization:"+org && tuple.Relation == tc.role {
						t.Fatal("revoked source role still projected")
					}
				}
			}
		})
	}
	t.Run("scoped roles do not become organization roles", func(t *testing.T) {
		tuples, err := Project(projectionFixture())
		if err != nil {
			t.Fatal(err)
		}
		for _, tuple := range tuples {
			if tuple.Object == "organization:"+org && tuple.Relation != "member" {
				t.Fatalf("invented organization role: %#v", tuple)
			}
		}
	})
	t.Run("pseudo resource rejected", func(t *testing.T) {
		snapshot := projectionFixture()
		snapshot.Resources[0].Kind = "organization_identity"
		snapshot.Grants = nil
		if _, err := Project(snapshot); !errors.Is(err, ErrInvalid) {
			t.Fatalf("pseudo resource projected: %v", err)
		}
	})
}
