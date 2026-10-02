package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// Catch checked requests reaching legacy SQL or losing scope/actor/preconditions.
func TestP7DataControlsCheckedStatements(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, RequestAuthorization{})
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	for _, update := range []bool{false, true} {
		db := &workflowCallDatabase{response: json.RawMessage(`{"version":2}`)}
		r, _ := NewPostgresRepository(db)
		want, args := "SELECT zasp_authorization80.get_data_controls($1,$2,$3)", []any{o, w, e}
		var err error
		if update {
			want = "SELECT zasp_authorization80.update_data_controls($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
			m := administrationMutation{Operation: "updateDataControls", CollectionMode: "metadata_only", RetentionDays: 60, DeletionEnabled: true, ExpectedVersion: 1, EnvironmentClass: "production", AuditID: "pid_79000001-0000-4000-8000-000000000001"}
			args = append(args, m.CollectionMode, m.RetentionDays, m.DeletionEnabled, m.ExpectedVersion, m.EnvironmentClass, m.AuditID, identity.PrincipalID.String())
			_, err = r.MutateAdministration(ctx, identity, m)
		} else {
			_, err = r.ReadAdministration(ctx, identity, "getDataControls", nil)
		}
		if err != nil || db.query != want || !reflect.DeepEqual(db.args, args) {
			t.Errorf("checked update=%t query=%q args=%v error=%v", update, db.query, db.args, err)
		}
	}
}
