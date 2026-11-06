package apiserver

import (
	"bytes"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func environmentClassStatementAllowed(g RequestAuthorization, q string, args []any) (bool, bool) {
	if q != postgresClassifiedEnvironmentCreateSQL && q != postgresClassifiedEnvironmentUpdateSQL {
		return false, false
	}
	if g.Collection || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated {
		return true, false
	}
	o, w, e, a := g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.Identity.PrincipalID.String()
	if !authorizationNativeTargetAllowed(g, "environment", e) {
		return true, false
	}
	if q == postgresClassifiedEnvironmentCreateSQL {
		if g.OperationID != "createEnvironment" || len(args) != 11 || args[1] != o || args[2] != w || args[6] != a || args[7] != w || args[8] != e {
			return true, false
		}
		id, idOK := args[0].(string)
		name, nameOK := args[3].(string)
		class, classOK := args[4].(string)
		audit, auditOK := args[5].(string)
		permissions, permissionsOK := args[9].([]byte)
		pin, pinOK := args[10].(string)
		return true, idOK && validProductID(id) && nameOK && validAdministrationName(name) && classOK && validEnvironmentClass(class) && auditOK && validProductID(audit) && permissionsOK && bytes.Equal(permissions, []byte("[]")) && pinOK && migrations.IsEnvironmentClassProfileChecksum(pin)
	}
	if g.OperationID != "updateEnvironment" || len(args) != 10 || args[0] != o || args[1] != w || args[2] != e || args[3] != e || args[3] != g.PathParameters["id"] || args[8] != a {
		return true, false
	}
	name, nameOK := args[4].(string)
	audit, auditOK := args[7].(string)
	pin, pinOK := args[9].(string)
	version, versionOK := args[6].(int64)
	classOK := args[5] == nil
	if class, ok := args[5].(string); ok {
		classOK = validEnvironmentClass(class)
	}
	return true, nameOK && validAdministrationName(name) && auditOK && validProductID(audit) && pinOK && migrations.IsEnvironmentClassProfileChecksum(pin) && versionOK && version > 0 && classOK
}
