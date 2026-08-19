package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	postgresGetOrganizationSQL           = `SELECT jsonb_build_object('id', id, 'name', name, 'domain', domain, 'version', version) FROM zasp_organizations WHERE id = $1`
	postgresListWorkspacesSQL            = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', id, 'organization_id', organization_id, 'name', name, 'version', version) AS item FROM zasp_workspaces WHERE organization_id=$1 ORDER BY id OFFSET $2 LIMIT $3) AS page`
	postgresGetWorkspaceSQL              = `SELECT jsonb_build_object('id', id, 'organization_id', organization_id, 'name', name, 'version', version) FROM zasp_workspaces WHERE organization_id=$1 AND id=$2`
	postgresListEnvironmentsSQL          = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', id, 'organization_id', organization_id, 'workspace_id', workspace_id, 'name', name, 'environment_class', environment_class, 'version', version) AS item FROM zasp_environments WHERE organization_id=$1 AND workspace_id=$2 ORDER BY id OFFSET $3 LIMIT $4) AS page`
	postgresGetEnvironmentSQL            = `SELECT jsonb_build_object('id', id, 'organization_id', organization_id, 'workspace_id', workspace_id, 'name', name, 'environment_class', environment_class, 'version', version) FROM zasp_environments WHERE organization_id=$1 AND id=$2`
	postgresListMembersSQL               = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', principal_id, 'organization_id', organization_id, 'organization_reference', organization_reference, 'member_reference', member_reference, 'role', role, 'active', active, 'version', version) AS item FROM zasp_identity_memberships WHERE organization_id=$1 ORDER BY principal_id OFFSET $2 LIMIT $3) AS page`
	postgresListGroupMappingsSQL         = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'group_reference'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('group_reference', group_reference, 'role', role, 'workspace_id', workspace_id, 'environment_id', environment_id, 'version', version) AS item FROM zasp_group_mappings WHERE organization_id=$1 ORDER BY group_reference OFFSET $2 LIMIT $3) AS page`
	postgresListAPITokensSQL             = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', id, 'name', name, 'principal_id', principal_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'permissions', permissions, 'created_at', created_at, 'expires_at', expires_at, 'last_used_at', last_used_at, 'revoked_at', revoked_at, 'version', version, 'audit_correlation_id', audit_correlation_id) AS item FROM zasp_product_api_tokens WHERE organization_id=$1 ORDER BY id OFFSET $2 LIMIT $3) AS page`
	postgresListAuditEventsSQL           = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'occurred_at' DESC, item->>'id' DESC), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'actor_id', actor_id, 'action', action, 'target_id', target_id, 'outcome', CASE outcome WHEN 'rejected' THEN 'denied' ELSE outcome END, 'metadata', metadata, 'occurred_at', occurred_at) AS item FROM zasp_admin_audit WHERE organization_id=$1 ORDER BY occurred_at DESC,id DESC OFFSET $2 LIMIT $3) AS page`
	postgresListSessionsSQL              = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', session_id, 'agent_id', 'product-console', 'principal_id', principal_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'state', CASE WHEN revoked_at IS NULL AND expires_at > now() THEN 'active' WHEN revoked_at IS NOT NULL THEN 'revoked' ELSE 'expired' END, 'authenticated_at', authenticated_at, 'expires_at', expires_at, 'version', version, 'events', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', event.id, 'session_id', event.session_id, 'class', event.class, 'label', event.label, 'evidence_id', event.evidence_id, 'source', event.source, 'confidence', event.confidence, 'at', event.at) ORDER BY event.at,event.id) FROM zasp_session_events AS event WHERE event.organization_id=session.organization_id AND event.session_id=session.session_id), '[]'::jsonb)) AS item FROM zasp_product_sessions AS session WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND ($6='' OR principal_id=$6) AND ($7='' OR $7='product-console') AND ($8::timestamptz IS NULL OR authenticated_at >= $8) AND ($9::timestamptz IS NULL OR authenticated_at <= $9) ORDER BY session_id OFFSET $4 LIMIT $5) AS page`
	postgresGetSessionSQL                = `SELECT jsonb_build_object('id', session_id, 'agent_id', 'product-console', 'principal_id', principal_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'state', CASE WHEN revoked_at IS NULL AND expires_at > now() THEN 'active' WHEN revoked_at IS NOT NULL THEN 'revoked' ELSE 'expired' END, 'authenticated_at', authenticated_at, 'expires_at', expires_at, 'version', version, 'events', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', event.id, 'session_id', event.session_id, 'class', event.class, 'label', event.label, 'evidence_id', event.evidence_id, 'source', event.source, 'confidence', event.confidence, 'at', event.at) ORDER BY event.at,event.id) FROM zasp_session_events AS event WHERE event.organization_id=session.organization_id AND event.session_id=session.session_id), '[]'::jsonb)) FROM zasp_product_sessions AS session WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND session_id=$4`
	postgresListSessionEventsSQL         = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(jsonb_build_object('id', id, 'session_id', session_id, 'class', class, 'label', label, 'evidence_id', evidence_id, 'source', source, 'confidence', confidence, 'at', at) ORDER BY at,id), '[]'::jsonb)) FROM zasp_session_events WHERE organization_id=$1 AND session_id=$2 AND EXISTS (SELECT 1 FROM zasp_product_sessions WHERE organization_id=$1 AND workspace_id=$3 AND environment_id=$4 AND session_id=$2)`
	postgresListComplianceControlsSQL    = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(jsonb_build_object('id', control.id, 'framework', control.framework, 'name', control.name, 'evidence_ids', COALESCE((SELECT jsonb_agg(evidence.id ORDER BY evidence.id) FROM zasp_compliance_evidence AS evidence WHERE evidence.organization_id=control.organization_id AND evidence.control_id=control.id), '[]'::jsonb), 'fresh_until', control.fresh_until) ORDER BY control.id), '[]'::jsonb)) FROM zasp_compliance_controls AS control WHERE organization_id=$1`
	postgresListComplianceEvidenceSQL    = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(jsonb_build_object('control', jsonb_build_object('id', control.id, 'framework', control.framework, 'name', control.name, 'evidence_ids', COALESCE((SELECT jsonb_agg(evidence.id ORDER BY evidence.id) FROM zasp_compliance_evidence AS evidence WHERE evidence.organization_id=control.organization_id AND evidence.control_id=control.id), '[]'::jsonb), 'fresh_until', control.fresh_until), 'freshness', CASE WHEN NOT EXISTS (SELECT 1 FROM zasp_compliance_evidence AS evidence WHERE evidence.organization_id=control.organization_id AND evidence.control_id=control.id) THEN 'missing' WHEN control.fresh_until > now() THEN 'fresh' ELSE 'stale' END, 'evidence', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', evidence.id, 'asset_id', evidence.asset_id, 'source', evidence.source, 'at', evidence.at) ORDER BY evidence.at,evidence.id) FROM zasp_compliance_evidence AS evidence WHERE evidence.organization_id=control.organization_id AND evidence.control_id=control.id), '[]'::jsonb)) ORDER BY control.id), '[]'::jsonb)) FROM zasp_compliance_controls AS control WHERE organization_id=$1`
	postgresGetDataControlsSQL           = `SELECT jsonb_build_object('environment_id', environment_id, 'environment_class', environment_class, 'collection_mode', collection_mode, 'retention_days', retention_days, 'deletion_enabled', deletion_enabled, 'version', version) FROM zasp_data_controls WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`
	postgresCreateWorkspaceSQL           = `WITH created AS (INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,$3) RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $2,$4,$5,$6,$7,'workspace.create',$1,'succeeded','{}'::jsonb FROM created) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'name',name,'version',version,'audit_correlation_id',$6::text) FROM created`
	postgresUpdateWorkspaceSQL           = `WITH updated AS (UPDATE zasp_workspaces SET name=$3,version=version+1 WHERE organization_id=$1 AND id=$2 AND version=$4 RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,$5,$6,$7,$8,'workspace.update',$2,'succeeded','{}'::jsonb FROM updated), result AS (SELECT jsonb_build_object('id',id,'organization_id',organization_id,'name',name,'version',version,'audit_correlation_id',$7::text) AS payload FROM updated) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_workspaces WHERE organization_id=$1 AND id=$2) THEN 'conflict' ELSE 'not_found' END))`
	postgresCreateEnvironmentSQL         = `WITH parent AS (SELECT id FROM zasp_workspaces WHERE organization_id=$2 AND id=$3), created AS (INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) SELECT $1,$2,$3,$4,'development' FROM parent RETURNING *), controls AS (INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) SELECT organization_id,workspace_id,id,environment_class,'metadata_only',30,true FROM created), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $2,$3,id,$5,$6,'environment.create',id,'succeeded','{}'::jsonb FROM created) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'workspace_id',workspace_id,'name',name,'environment_class',environment_class,'version',version,'audit_correlation_id',$5::text) FROM created`
	postgresUpdateEnvironmentSQL         = `WITH updated AS (UPDATE zasp_environments SET name=$3,version=version+1 WHERE organization_id=$1 AND id=$2 AND version=$4 RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,workspace_id,id,$5,$6,'environment.update',$2,'succeeded','{}'::jsonb FROM updated), result AS (SELECT jsonb_build_object('id',id,'organization_id',organization_id,'workspace_id',workspace_id,'name',name,'environment_class',environment_class,'version',version,'audit_correlation_id',$5::text) AS payload FROM updated) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_environments WHERE organization_id=$1 AND id=$2) THEN 'conflict' ELSE 'not_found' END))`
	postgresUpdateMemberRoleSQL          = `WITH updated AS (UPDATE zasp_identity_memberships SET role=$3,version=version+1 WHERE organization_id=$1 AND principal_id=$2 AND version=$4 AND active RETURNING *), revoked AS (UPDATE zasp_product_sessions SET revoked_at=COALESCE(revoked_at,transaction_timestamp()),version=version+1 WHERE organization_id=$1 AND principal_id=$2 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM updated)), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,$5,$6,$7,$8,'member.role.update',$2,'succeeded',jsonb_build_object('role',$3::text) FROM updated), result AS (SELECT jsonb_build_object('id',principal_id,'organization_id',organization_id,'organization_reference',organization_reference,'member_reference',member_reference,'role',role,'active',active,'version',version,'audit_correlation_id',$7::text) AS payload FROM updated) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2) THEN 'conflict' ELSE 'not_found' END))`
	postgresUpsertGroupMappingSQL        = `WITH changed AS (INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id,version) SELECT $1,$2,$3,$4,$5,1 WHERE $6=0 ON CONFLICT(organization_id,group_reference) DO UPDATE SET role=excluded.role,workspace_id=excluded.workspace_id,environment_id=excluded.environment_id,version=zasp_group_mappings.version+1,updated_at=transaction_timestamp() WHERE zasp_group_mappings.version=$6 RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,$4,$5,$7,$8,'group_mapping.update',$9,'succeeded',jsonb_build_object('group_reference',$2::text) FROM changed), result AS (SELECT jsonb_build_object('group_reference',group_reference,'role',role,'workspace_id',workspace_id,'environment_id',environment_id,'version',version,'audit_correlation_id',$7::text) AS payload FROM changed) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_group_mappings WHERE organization_id=$1 AND group_reference=$2) THEN 'conflict' ELSE 'not_found' END))`
	postgresCreateAPITokenSQL            = `WITH authorized AS (SELECT 1 FROM zasp_authorized_scopes WHERE principal_id=$2 AND organization_id=$1 AND workspace_id=$7 AND environment_id=$8), claimed AS (INSERT INTO zasp_admin_idempotency(organization_id,principal_id,operation,idempotency_key,request_digest) SELECT $1,$2,'createAPIToken',$3,$4 FROM authorized RETURNING 1), created AS (INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at,audit_correlation_id) SELECT digest($5,'sha256'),$6,$9,$2,$1,$7,$8,$10::jsonb,$11,$12 FROM claimed RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,$7,$8,$12,$2,'api_token.create',$6,'succeeded','{}'::jsonb FROM created) SELECT jsonb_build_object('id',id,'name',name,'principal_id',principal_id,'workspace_id',workspace_id,'environment_id',environment_id,'permissions',permissions,'created_at',created_at,'expires_at',expires_at,'last_used_at',last_used_at,'revoked_at',revoked_at,'version',version,'audit_correlation_id',audit_correlation_id) FROM created`
	postgresRotateAPITokenSQL            = `WITH target AS (SELECT 1 FROM zasp_product_api_tokens WHERE organization_id=$1 AND id=$5 AND version=$6 AND revoked_at IS NULL), claimed AS (INSERT INTO zasp_admin_idempotency(organization_id,principal_id,operation,idempotency_key,request_digest) SELECT $1,$2,'rotateAPIToken',$3,$4 FROM target RETURNING 1), revoked AS (UPDATE zasp_product_api_tokens SET revoked_at=transaction_timestamp(),version=version+1 WHERE organization_id=$1 AND id=$5 AND version=$6 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM claimed) RETURNING *), created AS (INSERT INTO zasp_product_api_tokens(token_digest,id,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at,audit_correlation_id) SELECT digest($7,'sha256'),$8,name,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at,$9 FROM revoked RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,workspace_id,environment_id,$9,$2,'api_token.rotate',$5,'succeeded',jsonb_build_object('replacement_id',$8::text) FROM created), result AS (SELECT jsonb_build_object('id',id,'name',name,'principal_id',principal_id,'workspace_id',workspace_id,'environment_id',environment_id,'permissions',permissions,'created_at',created_at,'expires_at',expires_at,'last_used_at',last_used_at,'revoked_at',revoked_at,'version',version,'audit_correlation_id',audit_correlation_id) AS payload FROM created) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_product_api_tokens WHERE organization_id=$1 AND id=$5) THEN 'conflict' ELSE 'not_found' END))`
	postgresRevokeAPITokenSQL            = `WITH revoked AS (UPDATE zasp_product_api_tokens SET revoked_at=COALESCE(revoked_at,transaction_timestamp()),version=CASE WHEN revoked_at IS NULL THEN version+1 ELSE version END WHERE organization_id=$1 AND id=$2 AND version=$3 RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,workspace_id,environment_id,$4,$5,'api_token.revoke',$2,'succeeded','{}'::jsonb FROM revoked), result AS (SELECT jsonb_build_object('id',id,'name',name,'principal_id',principal_id,'workspace_id',workspace_id,'environment_id',environment_id,'permissions',permissions,'created_at',created_at,'expires_at',expires_at,'last_used_at',last_used_at,'revoked_at',revoked_at,'version',version,'audit_correlation_id',$4::text) AS payload FROM revoked) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_product_api_tokens WHERE organization_id=$1 AND id=$2) THEN 'conflict' ELSE 'not_found' END))`
	postgresRevokeInvestigatedSessionSQL = `WITH revoked AS (UPDATE zasp_product_sessions SET revoked_at=COALESCE(revoked_at,transaction_timestamp()),version=CASE WHEN revoked_at IS NULL THEN version+1 ELSE version END WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND session_id=$4 AND version=$5 RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,$2,$3,$6,$7,'session.revoke',$8,'succeeded',jsonb_build_object('session_id',$4::text) FROM revoked), result AS (SELECT jsonb_build_object('version',version) AS payload FROM revoked) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_product_sessions WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND session_id=$4) THEN 'conflict' ELSE 'not_found' END))`
	postgresUpdateDataControlsSQL        = `WITH updated AS (UPDATE zasp_data_controls SET collection_mode=$4,retention_days=$5,deletion_enabled=$6,version=version+1,migration_seeded=false,updated_at=transaction_timestamp() WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND version=$7 AND environment_class=$8 RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,$2,$3,$9,$10,'data_controls.update',$3,'succeeded',jsonb_build_object('collection_mode',$4::text,'retention_days',$5::text) FROM updated), result AS (SELECT jsonb_build_object('environment_id',environment_id,'environment_class',environment_class,'collection_mode',collection_mode,'retention_days',retention_days,'deletion_enabled',deletion_enabled,'version',version,'audit_correlation_id',$9::text) AS payload FROM updated) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_data_controls WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3) THEN 'conflict' ELSE 'not_found' END))`
)

type administrationRepository interface {
	ReadAdministration(context.Context, RequestIdentity, string, map[string]string) (json.RawMessage, error)
	MutateAdministration(context.Context, RequestIdentity, administrationMutation) (json.RawMessage, error)
}

type administrationMutation struct {
	Operation, ID, ReplacementID, Name, Role, WorkspaceID, EnvironmentID string
	EnvironmentClass, CollectionMode, IdempotencyKey, RawToken, AuditID  string
	RetentionDays                                                        int
	DeletionEnabled                                                      bool
	Permissions                                                          json.RawMessage
	ExpiresAt                                                            time.Time
	ExpectedVersion                                                      int64
}

func (repository *PostgresRepository) ReadAdministration(ctx context.Context, identity RequestIdentity, operation string, parameters map[string]string) (json.RawMessage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, identity.CredentialKind == CredentialBrowserSession) || identity.Scope.Validate() != nil {
		return nil, ErrRepositoryOperation
	}
	switch operation {
	case "getOrganization":
		return repository.database.QueryJSON(ctx, postgresGetOrganizationSQL, identity.Scope.OrganizationID().String())
	case "listWorkspaces":
		return repository.database.QueryJSON(ctx, postgresListWorkspacesSQL, identity.Scope.OrganizationID().String(), adminOffset(parameters), adminLimit(parameters)+1)
	case "getWorkspace":
		return repository.database.QueryJSON(ctx, postgresGetWorkspaceSQL, identity.Scope.OrganizationID().String(), parameters["id"])
	case "listEnvironments":
		return repository.database.QueryJSON(ctx, postgresListEnvironmentsSQL, identity.Scope.OrganizationID().String(), parameters["workspace_id"], adminOffset(parameters), adminLimit(parameters)+1)
	case "getEnvironment":
		return repository.database.QueryJSON(ctx, postgresGetEnvironmentSQL, identity.Scope.OrganizationID().String(), parameters["id"])
	case "listMembers":
		return repository.database.QueryJSON(ctx, postgresListMembersSQL, identity.Scope.OrganizationID().String(), adminOffset(parameters), adminLimit(parameters)+1)
	case "listGroupMappings":
		return repository.database.QueryJSON(ctx, postgresListGroupMappingsSQL, identity.Scope.OrganizationID().String(), adminOffset(parameters), adminLimit(parameters)+1)
	case "listAPITokens":
		return repository.database.QueryJSON(ctx, postgresListAPITokensSQL, identity.Scope.OrganizationID().String(), adminOffset(parameters), adminLimit(parameters)+1)
	case "listAuditEvents":
		return repository.database.QueryJSON(ctx, postgresListAuditEventsSQL, identity.Scope.OrganizationID().String(), adminOffset(parameters), adminLimit(parameters)+1)
	case "listSessions":
		return repository.database.QueryJSON(ctx, postgresListSessionsSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), adminOffset(parameters), adminLimit(parameters)+1, parameters["principal_id"], parameters["agent_id"], optionalAdministrationTime(parameters["from"]), optionalAdministrationTime(parameters["to"]))
	case "getSession":
		return repository.database.QueryJSON(ctx, postgresGetSessionSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), parameters["id"])
	case "listSessionEvents":
		return repository.database.QueryJSON(ctx, postgresListSessionEventsSQL, identity.Scope.OrganizationID().String(), parameters["id"], identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
	case "listComplianceControls":
		return repository.database.QueryJSON(ctx, postgresListComplianceControlsSQL, identity.Scope.OrganizationID().String())
	case "listComplianceEvidence":
		return repository.database.QueryJSON(ctx, postgresListComplianceEvidenceSQL, identity.Scope.OrganizationID().String())
	case "getDataControls":
		return repository.database.QueryJSON(ctx, postgresGetDataControlsSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
	default:
		return nil, ErrRepositoryNotFound
	}
}

func (repository *PostgresRepository) MutateAdministration(ctx context.Context, identity RequestIdentity, mutation administrationMutation) (json.RawMessage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession || mutation.Operation == "" || !validAdministrationProductID(mutation.AuditID) {
		return nil, ErrRepositoryOperation
	}
	organization, workspace, environment, actor := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	switch mutation.Operation {
	case "createWorkspace":
		return repository.database.QueryJSON(ctx, postgresCreateWorkspaceSQL, mutation.ID, organization, mutation.Name, workspace, environment, mutation.AuditID, actor)
	case "updateWorkspace":
		return repository.preconditionedAdministrationMutation(ctx, postgresUpdateWorkspaceSQL, organization, mutation.ID, mutation.Name, mutation.ExpectedVersion, workspace, environment, mutation.AuditID, actor)
	case "createEnvironment":
		return repository.database.QueryJSON(ctx, postgresCreateEnvironmentSQL, mutation.ID, organization, mutation.WorkspaceID, mutation.Name, mutation.AuditID, actor)
	case "updateEnvironment":
		return repository.preconditionedAdministrationMutation(ctx, postgresUpdateEnvironmentSQL, organization, mutation.ID, mutation.Name, mutation.ExpectedVersion, mutation.AuditID, actor)
	case "updateMemberRole":
		return repository.preconditionedAdministrationMutation(ctx, postgresUpdateMemberRoleSQL, organization, mutation.ID, mutation.Role, mutation.ExpectedVersion, workspace, environment, mutation.AuditID, actor)
	case "updateGroupMappings":
		return repository.preconditionedAdministrationMutation(ctx, postgresUpsertGroupMappingSQL, organization, mutation.ID, mutation.Role, mutation.WorkspaceID, mutation.EnvironmentID, mutation.ExpectedVersion, mutation.AuditID, actor, mutation.WorkspaceID)
	case "createAPIToken":
		digest := sha256.Sum256([]byte(mutation.Operation + "\x00" + mutation.Name + "\x00" + mutation.WorkspaceID + "\x00" + mutation.EnvironmentID + "\x00" + string(mutation.Permissions) + "\x00" + mutation.ExpiresAt.Format(time.RFC3339Nano)))
		return repository.database.QueryJSON(ctx, postgresCreateAPITokenSQL, organization, actor, mutation.IdempotencyKey, digest[:], mutation.RawToken, mutation.ID, mutation.WorkspaceID, mutation.EnvironmentID, mutation.Name, mutation.Permissions, mutation.ExpiresAt, mutation.AuditID)
	case "rotateAPIToken":
		digest := sha256.Sum256([]byte(mutation.Operation + "\x00" + mutation.ID + "\x00" + strconv.FormatInt(mutation.ExpectedVersion, 10)))
		return repository.preconditionedAdministrationMutation(ctx, postgresRotateAPITokenSQL, organization, actor, mutation.IdempotencyKey, digest[:], mutation.ID, mutation.ExpectedVersion, mutation.RawToken, mutation.ReplacementID, mutation.AuditID)
	case "revokeAPIToken":
		return repository.preconditionedAdministrationMutation(ctx, postgresRevokeAPITokenSQL, organization, mutation.ID, mutation.ExpectedVersion, mutation.AuditID, actor)
	case "revokeSession":
		return repository.preconditionedAdministrationMutation(ctx, postgresRevokeInvestigatedSessionSQL, organization, workspace, environment, mutation.ID, mutation.ExpectedVersion, mutation.AuditID, actor, environment)
	case "updateDataControls":
		return repository.preconditionedAdministrationMutation(ctx, postgresUpdateDataControlsSQL, organization, workspace, environment, mutation.CollectionMode, mutation.RetentionDays, mutation.DeletionEnabled, mutation.ExpectedVersion, mutation.EnvironmentClass, mutation.AuditID, actor)
	default:
		return nil, ErrRepositoryNotFound
	}
}

func (repository *PostgresRepository) preconditionedAdministrationMutation(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	payload, err := repository.database.QueryJSON(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	var state struct {
		MutationState string `json:"_mutation_state"`
	}
	if json.Unmarshal(payload, &state) != nil {
		return nil, ErrRepositoryUnavailable
	}
	switch state.MutationState {
	case "":
		return payload, nil
	case "conflict":
		return nil, ErrRepositoryConflict
	case "not_found":
		return nil, ErrRepositoryNotFound
	default:
		return nil, ErrRepositoryUnavailable
	}
}

func adminOffset(parameters map[string]string) int {
	value, _ := strconv.Atoi(parameters["offset"])
	return value
}

func adminLimit(parameters map[string]string) int {
	value, _ := strconv.Atoi(parameters["limit"])
	if value < 1 || value > 100 {
		return 50
	}
	return value
}

func validAdministrationProductID(value string) bool {
	_, err := domain.ParseProductID(value)
	return err == nil
}

func optionalAdministrationTime(value string) any {
	if value == "" {
		return nil
	}
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}
