package apiserver

import (
	"strings"
	"testing"
)

func TestRedTeamInputArtifactReferenceRequiresExactTenantAndImmutableObject(t *testing.T) {
	scope := fixtureRequestIdentity(t).Scope
	valid := RedTeamArtifactReference{Reference: "s3://zasp-evidence/organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/pid_79000601-0000-4000-8000-000000000001", VersionID: "input-version-1", SHA256: strings.Repeat("a", 64), SizeBytes: 512}
	if !validRedTeamInputArtifact(scope, &valid) {
		t.Fatal("valid immutable input reference rejected")
	}
	if validRedTeamInputArtifact(scope, nil) {
		t.Fatal("missing input reference accepted")
	}
	for name, mutate := range map[string]func(*RedTeamArtifactReference){
		"foreign environment": func(value *RedTeamArtifactReference) {
			value.Reference = strings.Replace(value.Reference, scope.EnvironmentID().String(), "pid_79000602-0000-4000-8000-000000000002", 1)
		},
		"mutable version":    func(value *RedTeamArtifactReference) { value.VersionID = "" },
		"control version":    func(value *RedTeamArtifactReference) { value.VersionID = "version\n" },
		"zero checksum":      func(value *RedTeamArtifactReference) { value.SHA256 = strings.Repeat("0", 64) },
		"uppercase checksum": func(value *RedTeamArtifactReference) { value.SHA256 = strings.Repeat("A", 64) },
		"empty input":        func(value *RedTeamArtifactReference) { value.SizeBytes = 0 },
		"oversized input":    func(value *RedTeamArtifactReference) { value.SizeBytes = 65537 },
		"query":              func(value *RedTeamArtifactReference) { value.Reference += "?version=latest" },
		"traversal":          func(value *RedTeamArtifactReference) { value.Reference += "/../other" },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if validRedTeamInputArtifact(scope, &value) {
				t.Fatal("invalid artifact accepted")
			}
		})
	}
}
