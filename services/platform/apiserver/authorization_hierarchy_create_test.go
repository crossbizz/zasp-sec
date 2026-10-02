package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// Catch checked creation reaching legacy SQL, copying permissions, or losing
// the prepared IDs and exact selected scope. No generated IDs are retried here.
func TestP7HierarchyCreateCheckedStatements(t *testing.T) {
	i := fixtureRequestIdentity(t)
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, RequestAuthorization{})
	for _, permissions := range [][]string{nil, {}, {"manage_identity", "manage_data_controls"}} {
		i.Permissions = permissions
		for _, workspace := range []bool{true, false} {
			db := &workflowCallDatabase{response: json.RawMessage(`{"version":1}`)}
			r, _ := NewPostgresRepository(db)
			m := administrationMutation{Operation: "createEnvironment", ID: "pid_78000001-0000-4000-8000-000000000001", WorkspaceID: w, Name: "Created", AuditID: "pid_78000002-0000-4000-8000-000000000002", InitialEnvironmentID: "pid_78000003-0000-4000-8000-000000000003"}
			want := "SELECT zasp_authorization80.create_environment($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)"
			args := []any{m.ID, o, w, m.Name, m.AuditID, p, w, e, []byte("[]")}
			if workspace {
				m.Operation = "createWorkspace"
				want = "SELECT zasp_authorization80.create_workspace($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)"
				args = []any{m.ID, o, m.Name, w, e, m.AuditID, p, m.InitialEnvironmentID, []byte("[]")}
			}
			if _, err := r.MutateAdministration(ctx, i, m); err != nil || db.query != want || !reflect.DeepEqual(db.args, args) {
				t.Errorf("checked %s permissions=%v query=%q args=%v error=%v", m.Operation, permissions, db.query, db.args, err)
			}
		}
	}
	db := &workflowCallDatabase{}
	r, _ := NewPostgresRepository(db)
	_, err := r.MutateAdministration(ctx, i, administrationMutation{Operation: "createEnvironment", WorkspaceID: "pid_78000004-0000-4000-8000-000000000004", AuditID: "pid_78000002-0000-4000-8000-000000000002"})
	if !errors.Is(err, ErrRepositoryNotFound) || db.query != "" {
		t.Fatalf("foreign workspace reached SQL: %q %v", db.query, err)
	}
}
