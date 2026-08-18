package identity

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type GrantReader interface {
	ListGrants(context.Context, domain.ProductID, domain.ProductID) ([]WorkspaceGrant, error)
}

type AuthorizationContext struct {
	principalID    domain.ProductID
	scope          domain.Scope
	permission     Permission
	effectiveRoles []Role
}

func (authorization AuthorizationContext) PrincipalID() domain.ProductID {
	return authorization.principalID
}
func (authorization AuthorizationContext) Scope() domain.Scope    { return authorization.scope }
func (authorization AuthorizationContext) Permission() Permission { return authorization.permission }
func (authorization AuthorizationContext) EffectiveRoles() []Role {
	return append([]Role(nil), authorization.effectiveRoles...)
}

type AuthorizationService struct {
	grants GrantReader
}

func NewAuthorizationService(grants GrantReader) (*AuthorizationService, error) {
	if nilInterface(grants) {
		return nil, ErrConfiguration
	}
	return &AuthorizationService{grants: grants}, nil
}

func (service *AuthorizationService) Resolve(
	ctx context.Context,
	principal Principal,
	scope domain.Scope,
	permission Permission,
) (AuthorizationContext, error) {
	if service == nil || nilInterface(service.grants) || !validContext(ctx) || !principal.valid() ||
		scope.Validate() != nil || !permission.valid() || principal.organizationID != scope.OrganizationID() {
		return AuthorizationContext{}, ErrForbidden
	}
	effective := make([]Role, 0, 2)
	if roleAllows(principal.role, permission) {
		effective = append(effective, principal.role)
	}
	grants, err := service.grants.ListGrants(ctx, principal.organizationID, principal.id)
	if err != nil {
		return AuthorizationContext{}, ErrForbidden
	}
	for _, grant := range grants {
		if !grant.valid() || grant.organizationID != principal.organizationID || grant.principalID != principal.id {
			return AuthorizationContext{}, ErrForbidden
		}
		if grant.workspaceID == scope.WorkspaceID() && grant.environmentID == scope.EnvironmentID() && roleAllows(grant.role, permission) {
			alreadyPresent := false
			for _, role := range effective {
				alreadyPresent = alreadyPresent || role == grant.role
			}
			if !alreadyPresent {
				effective = append(effective, grant.role)
			}
		}
	}
	if len(effective) == 0 {
		return AuthorizationContext{}, ErrForbidden
	}
	return AuthorizationContext{principalID: principal.id, scope: scope, permission: permission, effectiveRoles: effective}, nil
}

func (service *AuthorizationService) Run(
	ctx context.Context,
	principal Principal,
	scope domain.Scope,
	permission Permission,
	handler func(context.Context, AuthorizationContext) error,
) (resultErr error) {
	if handler == nil {
		return ErrForbidden
	}
	authorization, err := service.Resolve(ctx, principal, scope, permission)
	if err != nil {
		return ErrForbidden
	}
	defer func() {
		if recover() != nil {
			resultErr = ErrForbidden
		}
	}()
	if err := handler(ctx, authorization); err != nil || ctx.Err() != nil {
		return ErrForbidden
	}
	return nil
}
