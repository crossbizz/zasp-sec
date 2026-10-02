// Package authorization defines the product permission boundary. It does not
// replace SQL isolation, authentication, or the P6/P7 revision fence.
package authorization

import (
	"context"
	"errors"
)

var ErrInvalid = errors.New("authorization request rejected")
var ErrUnavailable = errors.New("authorization unavailable")

// CheckRequest must be assembled from authenticated identity and server-loaded
// resource ancestry, never from a caller's claimed scope. TaskID is required for
// agent/service delegation. PAT restrictions remain a separate intersection.
type CheckRequest struct {
	PrincipalKind, PrincipalID                   string
	OrganizationID, WorkspaceID, EnvironmentID   string
	ResourceType, ResourceID, Permission, TaskID string
}
type Decision struct {
	Allowed bool
	ModelID string
}
type Checker interface {
	Check(context.Context, CheckRequest) (Decision, error)
}
