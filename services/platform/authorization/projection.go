package authorization

import fga "github.com/openfga/go-sdk/client"

type ProjectionScope struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
}
type ProjectionMember struct {
	Kind             string `json:"kind"`
	ID               string `json:"id"`
	OrganizationRole string `json:"organization_role"`
}
type ProjectionRole struct {
	ProjectionScope
	PrincipalID string `json:"principal_id"`
	Role        string `json:"role"`
}
type ProjectionResource struct {
	ProjectionScope
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type ProjectionGrant struct {
	ProjectionResource
	PrincipalKind string `json:"principal_kind"`
	PrincipalID   string `json:"principal_id"`
	Permission    string `json:"permission"`
	TaskID        string `json:"task_id"`
}
type ProjectionSnapshot struct {
	Revision  Revision             `json:"revision"`
	Members   []ProjectionMember   `json:"members"`
	Scopes    []ProjectionScope    `json:"scopes"`
	Roles     []ProjectionRole     `json:"roles"`
	Resources []ProjectionResource `json:"resources"`
	Grants    []ProjectionGrant    `json:"grants"`
	Known     []fga.ClientTupleKey `json:"known"`
}

func Project(snapshot ProjectionSnapshot) ([]fga.ClientTupleKey, error) {
	return projectSnapshot(snapshot)
}
