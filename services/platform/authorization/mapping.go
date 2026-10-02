package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	sdk "github.com/openfga/go-sdk"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type Binding struct{ User, Object, Relation string }

var resourceKind = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var permissions = map[string]bool{"investigate_sessions": true, "manage_api_tokens": true, "manage_data_controls": true, "manage_findings": true, "manage_identity": true, "manage_workflows": true, "revoke_sessions": true, "run_tests": true, "view": true, "view_audit": true, "view_compliance": true}
var roles = map[string]bool{"organization_admin": true, "security_admin": true, "security_engineer": true, "developer_owner": true, "compliance_viewer": true, "read_only_viewer": true}

// Map validates syntax and scope shape. It cannot prove SQL ownership or active
// membership: callers must load those facts, fence their revision and retain RLS.
// Human subjects are stable product principals, never Stytch provider references.
// A PAT uses its authenticated owning user subject plus separate token limits.
func Map(r CheckRequest) (Binding, error) {
	for _, id := range []string{r.PrincipalID, r.OrganizationID, r.WorkspaceID, r.EnvironmentID, r.ResourceID} {
		if _, err := domain.ParseProductID(id); err != nil {
			return Binding{}, ErrInvalid
		}
	}
	o, _ := domain.ParseProductID(r.OrganizationID)
	w, _ := domain.ParseProductID(r.WorkspaceID)
	e, _ := domain.ParseProductID(r.EnvironmentID)
	if _, err := domain.NewScope(o, w, e); err != nil || !permissions[r.Permission] || !resourceKind.MatchString(r.ResourceType) {
		return Binding{}, ErrInvalid
	}
	switch r.PrincipalKind {
	case "user":
		if r.TaskID != "" {
			return Binding{}, ErrInvalid
		}
	case "agent", "service":
		if _, err := domain.ParseProductID(r.TaskID); err != nil {
			return Binding{}, ErrInvalid
		}
	default:
		return Binding{}, ErrInvalid
	}
	object := "resource:" + r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID + "/" + r.ResourceType + "/" + r.ResourceID
	// Only the dedicated identity target uses organization authority. Existing
	// organization/workspace aliases retain their exact selected environment.
	switch r.ResourceType {
	case "organization_identity":
		if r.ResourceID != r.OrganizationID || r.Permission != "manage_identity" || r.PrincipalKind != "user" {
			return Binding{}, ErrInvalid
		}
		object = "organization:" + r.OrganizationID
	case "organization":
		if r.ResourceID != r.OrganizationID {
			return Binding{}, ErrInvalid
		}
		object = environmentObject(r)
	case "workspace":
		if r.ResourceID != r.WorkspaceID {
			return Binding{}, ErrInvalid
		}
		object = environmentObject(r)
	case "environment":
		if r.ResourceID != r.EnvironmentID {
			return Binding{}, ErrInvalid
		}
		object = environmentObject(r)
	}
	return Binding{User: r.PrincipalKind + ":" + r.PrincipalID, Object: object, Relation: r.Permission}, nil
}
func environmentObject(r CheckRequest) string {
	return "environment:" + r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID
}
func workspaceObject(r CheckRequest) string {
	return "workspace:" + r.OrganizationID + "/" + r.WorkspaceID
}

// Hierarchy returns one parent at each level. P6 must replace prior parents
// under its SQL desired-state lock, never append conflicting ancestry tuples.
func Hierarchy(r CheckRequest) ([]fga.ClientTupleKey, error) {
	if r.ResourceType == "organization_identity" {
		return nil, ErrInvalid
	}
	binding, err := Map(r)
	if err != nil {
		return nil, err
	}
	tuples := []fga.ClientTupleKey{{User: "organization:" + r.OrganizationID, Relation: "organization", Object: workspaceObject(r)}, {User: workspaceObject(r), Relation: "workspace", Object: environmentObject(r)}}
	if binding.Object != environmentObject(r) {
		tuples = append(tuples, fga.ClientTupleKey{User: environmentObject(r), Relation: "environment", Object: binding.Object})
	}
	return tuples, nil
}

// ScopedRole projects an already verified direct/group grant to one environment.
// Membership is a distinct tuple; neither fact alone authorizes an operation.
func ScopedRole(r CheckRequest, role string) (fga.ClientTupleKey, error) {
	binding, err := Map(r)
	if err != nil || r.PrincipalKind != "user" || !roles[role] || r.ResourceType == "organization_identity" {
		return fga.ClientTupleKey{}, ErrInvalid
	}
	return fga.ClientTupleKey{User: binding.User, Relation: role, Object: environmentObject(r)}, nil
}

// ResourceGrant projects a human's already authorized direct resource grant.
// This encoder does not authorize granting access.
func ResourceGrant(r CheckRequest) (fga.ClientTupleKey, error) {
	binding, err := Map(r)
	if err != nil || r.PrincipalKind != "user" || binding.Object == environmentObject(r) || r.ResourceType == "organization_identity" {
		return fga.ClientTupleKey{}, ErrInvalid
	}
	return fga.ClientTupleKey{User: binding.User, Relation: "direct_" + binding.Relation, Object: binding.Object}, nil
}

// DelegationGrant emits an independently revocable grant object and its resource
// attachment. Its canonical key binds scope, target, subject, task and permission.
// Multiple tasks never share the same grant key. P6 must own both tuples as one
// desired-state unit; P7 must still check current grantor/policy/approval/budget.
func DelegationGrant(r CheckRequest) ([]fga.ClientTupleKey, error) {
	binding, err := Map(r)
	if err != nil || r.PrincipalKind == "user" || binding.Object == environmentObject(r) {
		return nil, ErrInvalid
	}
	// Canonical components cannot contain slash. Hash the complete binding to
	// stay within OpenFGA's 256-byte object bound without discarding any scope.
	key := r.OrganizationID + "/" + r.WorkspaceID + "/" + r.EnvironmentID + "/" + r.ResourceType + "/" + r.ResourceID + "/" + r.PrincipalKind + "/" + r.PrincipalID + "/" + r.TaskID + "/" + r.Permission
	digest := sha256.Sum256([]byte(key))
	object := "delegation:" + r.OrganizationID + "/" + hex.EncodeToString(digest[:])
	conditionContext := map[string]interface{}{"bound_task": r.TaskID}
	return []fga.ClientTupleKey{
		{User: binding.User, Relation: "assignee", Object: object, Condition: &sdk.RelationshipCondition{Name: "task_bound", Context: &conditionContext}},
		{User: object + "#assignee", Relation: "delegated_" + r.Permission, Object: binding.Object},
	}, nil
}
