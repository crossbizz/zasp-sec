package identity

type Role string

const (
	RoleOrganizationAdmin Role = "organization_admin"
	RoleSecurityAdmin     Role = "security_admin"
	RoleSecurityEngineer  Role = "security_engineer"
	RoleDeveloperOwner    Role = "developer_owner"
	RoleComplianceViewer  Role = "compliance_viewer"
	RoleReadOnlyViewer    Role = "read_only_viewer"
)

func (role Role) valid() bool {
	switch role {
	case RoleOrganizationAdmin, RoleSecurityAdmin, RoleSecurityEngineer, RoleDeveloperOwner, RoleComplianceViewer, RoleReadOnlyViewer:
		return true
	default:
		return false
	}
}

type Permission string

const (
	PermissionView               Permission = "view"
	PermissionManageIdentity     Permission = "manage_identity"
	PermissionManageIntegrations Permission = "manage_integrations"
	PermissionManageFindings     Permission = "manage_findings"
	PermissionManagePolicies     Permission = "manage_policies"
	PermissionRunTests           Permission = "run_tests"
	PermissionManageAgents       Permission = "manage_agents"
	PermissionApproveActions     Permission = "approve_actions"
	PermissionExportEvidence     Permission = "export_evidence"
	PermissionViewAudit          Permission = "view_audit"
)

func (permission Permission) valid() bool {
	switch permission {
	case PermissionView, PermissionManageIdentity, PermissionManageIntegrations, PermissionManageFindings,
		PermissionManagePolicies, PermissionRunTests, PermissionManageAgents, PermissionApproveActions,
		PermissionExportEvidence, PermissionViewAudit:
		return true
	default:
		return false
	}
}

var builtInRoles = map[Role][]Permission{
	RoleOrganizationAdmin: {
		PermissionView, PermissionManageIdentity, PermissionManageIntegrations, PermissionManageFindings,
		PermissionManagePolicies, PermissionRunTests, PermissionManageAgents, PermissionApproveActions,
		PermissionExportEvidence, PermissionViewAudit,
	},
	RoleSecurityAdmin: {
		PermissionView, PermissionManageIntegrations, PermissionManageFindings, PermissionManagePolicies,
		PermissionRunTests, PermissionManageAgents, PermissionApproveActions, PermissionExportEvidence, PermissionViewAudit,
	},
	RoleSecurityEngineer: {
		PermissionView, PermissionManageFindings, PermissionManagePolicies, PermissionRunTests, PermissionManageAgents, PermissionApproveActions,
	},
	RoleDeveloperOwner:   {PermissionView, PermissionManageIntegrations, PermissionRunTests},
	RoleComplianceViewer: {PermissionView, PermissionExportEvidence, PermissionViewAudit},
	RoleReadOnlyViewer:   {PermissionView},
}

func BuiltInRoles() map[Role][]Permission {
	result := make(map[Role][]Permission, len(builtInRoles))
	for role, permissions := range builtInRoles {
		result[role] = append([]Permission(nil), permissions...)
	}
	return result
}

func roleAllows(role Role, permission Permission) bool {
	if !role.valid() || !permission.valid() {
		return false
	}
	for _, candidate := range builtInRoles[role] {
		if candidate == permission {
			return true
		}
	}
	return false
}
