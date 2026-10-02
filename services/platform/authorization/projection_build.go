package authorization

import (
	"encoding/json"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"sort"
)

func projectSnapshot(snapshot ProjectionSnapshot) ([]fga.ClientTupleKey, error) {
	if snapshot.Revision.validate() != nil {
		return nil, ErrInvalid
	}
	tuples := map[string]fga.ClientTupleKey{}
	members := map[string]bool{}
	scopes := map[ProjectionScope]bool{}
	parents := map[string]string{}
	resources := map[ProjectionResource]bool{}
	add := func(tuple fga.ClientTupleKey) { data, _ := json.Marshal(tuple); tuples[string(data)] = tuple }
	for _, member := range snapshot.Members {
		if _, err := domain.ParseProductID(member.ID); err != nil || (member.Kind != "user" && member.Kind != "agent" && member.Kind != "service") {
			return nil, ErrInvalid
		}
		subject := member.Kind + ":" + member.ID
		members[subject] = true
		add(fga.ClientTupleKey{User: subject, Relation: "member", Object: "organization:" + snapshot.Revision.OrganizationID})
		// Only the active human membership row can supply an organization role.
		// Scoped roles and machine memberships cannot confer identity authority.
		if member.Kind == "user" && (member.OrganizationRole == "organization_admin" || member.OrganizationRole == "security_admin") {
			add(fga.ClientTupleKey{User: subject, Relation: member.OrganizationRole, Object: "organization:" + snapshot.Revision.OrganizationID})
		}
	}
	for _, scope := range snapshot.Scopes {
		o, oe := domain.ParseProductID(scope.OrganizationID)
		w, we := domain.ParseProductID(scope.WorkspaceID)
		e, ee := domain.ParseProductID(scope.EnvironmentID)
		if _, err := domain.NewScope(o, w, e); err != nil || oe != nil || we != nil || ee != nil || scope.OrganizationID != snapshot.Revision.OrganizationID {
			return nil, ErrInvalid
		}
		if previous, ok := parents[scope.EnvironmentID]; ok && previous != scope.WorkspaceID {
			return nil, ErrInvalid
		}
		parents[scope.EnvironmentID] = scope.WorkspaceID
		scopes[scope] = true
		add(fga.ClientTupleKey{User: "organization:" + scope.OrganizationID, Relation: "organization", Object: "workspace:" + scope.OrganizationID + "/" + scope.WorkspaceID})
		add(fga.ClientTupleKey{User: "workspace:" + scope.OrganizationID + "/" + scope.WorkspaceID, Relation: "workspace", Object: "environment:" + scope.OrganizationID + "/" + scope.WorkspaceID + "/" + scope.EnvironmentID})
	}
	request := func(scope ProjectionScope, kind, id, principalKind, principalID, permission, taskID string) CheckRequest {
		return CheckRequest{OrganizationID: scope.OrganizationID, WorkspaceID: scope.WorkspaceID, EnvironmentID: scope.EnvironmentID, ResourceType: kind, ResourceID: id, PrincipalKind: principalKind, PrincipalID: principalID, Permission: permission, TaskID: taskID}
	}
	for _, grant := range snapshot.Roles {
		if !scopes[grant.ProjectionScope] || !members["user:"+grant.PrincipalID] {
			return nil, ErrInvalid
		}
		tuple, err := ScopedRole(request(grant.ProjectionScope, "environment", grant.EnvironmentID, "user", grant.PrincipalID, "view", ""), grant.Role)
		if err != nil {
			return nil, err
		}
		add(tuple)
	}
	for _, resource := range snapshot.Resources {
		if _, err := domain.ParseProductID(resource.ID); err != nil || !scopes[resource.ProjectionScope] || !resourceKind.MatchString(resource.Kind) || resource.Kind == "organization" || resource.Kind == "organization_identity" || resource.Kind == "workspace" || resource.Kind == "environment" {
			return nil, ErrInvalid
		}
		parent := resource.OrganizationID + "/" + resource.WorkspaceID + "/" + resource.EnvironmentID
		key := resource.Kind + ":" + resource.ID
		if previous, ok := parents[key]; ok && previous != parent {
			return nil, ErrInvalid
		}
		parents[key] = parent
		resources[resource] = true
		add(fga.ClientTupleKey{User: "environment:" + parent, Relation: "environment", Object: "resource:" + parent + "/" + resource.Kind + "/" + resource.ID})
	}
	for _, grant := range snapshot.Grants {
		if !resources[grant.ProjectionResource] || !members[grant.PrincipalKind+":"+grant.PrincipalID] {
			return nil, ErrInvalid
		}
		r := request(grant.ProjectionScope, grant.Kind, grant.ID, grant.PrincipalKind, grant.PrincipalID, grant.Permission, grant.TaskID)
		if grant.PrincipalKind == "user" {
			tuple, err := ResourceGrant(r)
			if err != nil {
				return nil, err
			}
			add(tuple)
		} else {
			rows, err := DelegationGrant(r)
			if err != nil {
				return nil, err
			}
			for _, tuple := range rows {
				add(tuple)
			}
		}
	}
	keys := make([]string, 0, len(tuples))
	for key := range tuples {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]fga.ClientTupleKey, 0, len(keys))
	for _, key := range keys {
		result = append(result, tuples[key])
	}
	return result, nil
}
