package domain

import "errors"

var ErrInvalidScope = errors.New("invalid scope")

type Scope struct {
	organizationID ProductID
	workspaceID    ProductID
	environmentID  ProductID
}

func NewScope(organizationID, workspaceID, environmentID ProductID) (Scope, error) {
	scope := Scope{
		organizationID: organizationID,
		workspaceID:    workspaceID,
		environmentID:  environmentID,
	}
	if err := scope.Validate(); err != nil {
		return Scope{}, ErrInvalidScope
	}
	return scope, nil
}

func (scope Scope) Validate() error {
	if !scope.organizationID.valid() || !scope.workspaceID.valid() || !scope.environmentID.valid() {
		return ErrInvalidScope
	}
	if scope.organizationID == scope.workspaceID || scope.organizationID == scope.environmentID || scope.workspaceID == scope.environmentID {
		return ErrInvalidScope
	}
	return nil
}

func (scope Scope) IsZero() bool {
	return scope == Scope{}
}

func (scope Scope) OrganizationID() ProductID {
	return scope.organizationID
}

func (scope Scope) WorkspaceID() ProductID {
	return scope.workspaceID
}

func (scope Scope) EnvironmentID() ProductID {
	return scope.environmentID
}
