package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/identitysql"
)

const (
	postgresGetOrganizationSQL           = `SELECT jsonb_build_object('id', id, 'name', name, 'domain', domain, 'version', version) FROM zasp_organizations WHERE id = $1`
	postgresListWorkspacesSQL            = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', workspace.id, 'organization_id', workspace.organization_id, 'name', workspace.name, 'version', workspace.version) AS item FROM zasp_workspaces AS workspace WHERE workspace.organization_id=$1 AND EXISTS(SELECT 1 FROM zasp_authorized_scopes AS scope JOIN zasp_identity_memberships AS membership ON membership.organization_id=scope.organization_id AND membership.principal_id=scope.principal_id AND membership.active WHERE scope.organization_id=workspace.organization_id AND scope.workspace_id=workspace.id AND scope.principal_id=$2) AND ($3='' OR workspace.id>$3) ORDER BY workspace.id LIMIT $4) AS page`
	postgresListWorkspacesV19SQL         = `SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY item->>'id'),'[]'::jsonb)) FROM (SELECT jsonb_build_object('id',workspace.id,'organization_id',workspace.organization_id,'name',workspace.name,'version',workspace.version) AS item FROM zasp_workspaces workspace WHERE workspace.organization_id=$1 AND EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes($2,$1) scope WHERE scope.workspace_id=workspace.id) AND ($3='' OR workspace.id>$3) ORDER BY workspace.id LIMIT $4) page`
	postgresGetWorkspaceSQL              = `SELECT jsonb_build_object('id', workspace.id, 'organization_id', workspace.organization_id, 'name', workspace.name, 'version', workspace.version) FROM zasp_workspaces AS workspace WHERE workspace.organization_id=$1 AND workspace.id=$2 AND workspace.id=$4 AND EXISTS(SELECT 1 FROM zasp_authorized_scopes AS scope JOIN zasp_identity_memberships AS membership ON membership.organization_id=scope.organization_id AND membership.principal_id=scope.principal_id AND membership.active WHERE scope.organization_id=workspace.organization_id AND scope.workspace_id=workspace.id AND scope.environment_id=$5 AND scope.principal_id=$3)`
	postgresGetWorkspaceV19SQL           = `SELECT jsonb_build_object('id',workspace.id,'organization_id',workspace.organization_id,'name',workspace.name,'version',workspace.version) FROM zasp_workspaces workspace WHERE workspace.organization_id=$1 AND workspace.id=$2 AND workspace.id=$4 AND EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes($3,$1) scope WHERE scope.workspace_id=workspace.id AND scope.environment_id=$5)`
	postgresListEnvironmentsSQL          = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', environment.id, 'organization_id', environment.organization_id, 'workspace_id', environment.workspace_id, 'name', environment.name, 'environment_class', environment.environment_class, 'version', environment.version) AS item FROM zasp_environments AS environment WHERE environment.organization_id=$1 AND environment.workspace_id=$2 AND EXISTS(SELECT 1 FROM zasp_authorized_scopes AS scope JOIN zasp_identity_memberships AS membership ON membership.organization_id=scope.organization_id AND membership.principal_id=scope.principal_id AND membership.active WHERE scope.organization_id=environment.organization_id AND scope.workspace_id=environment.workspace_id AND scope.environment_id=environment.id AND scope.principal_id=$3) AND ($4='' OR environment.id>$4) ORDER BY environment.id LIMIT $5) AS page`
	postgresListEnvironmentsV19SQL       = `SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY item->>'id'),'[]'::jsonb)) FROM (SELECT jsonb_build_object('id',environment.id,'organization_id',environment.organization_id,'workspace_id',environment.workspace_id,'name',environment.name,'environment_class',environment.environment_class,'version',environment.version) AS item FROM zasp_environments environment WHERE environment.organization_id=$1 AND environment.workspace_id=$2 AND EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes($3,$1) scope WHERE scope.workspace_id=environment.workspace_id AND scope.environment_id=environment.id) AND ($4='' OR environment.id>$4) ORDER BY environment.id LIMIT $5) page`
	postgresGetEnvironmentSQL            = `SELECT jsonb_build_object('id', id, 'organization_id', organization_id, 'workspace_id', workspace_id, 'name', name, 'environment_class', environment_class, 'version', version) FROM zasp_environments WHERE organization_id=$1 AND workspace_id=$2 AND id=$3 AND id=$4`
	postgresListMembersSQL               = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', principal_id, 'organization_id', organization_id, 'organization_reference', organization_reference, 'member_reference', member_reference, 'role', role, 'active', active, 'version', version) AS item FROM zasp_identity_memberships WHERE organization_id=$1 AND ($2='' OR principal_id>$2) ORDER BY principal_id LIMIT $3) AS page`
	postgresListGroupMappingsSQL         = `SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY item->>'group_reference'),'[]'::jsonb)) FROM (SELECT jsonb_build_object('group_reference',group_reference,'role',role,'workspace_id',workspace_id,'environment_id',environment_id,'version',version) AS item FROM zasp_group_mappings WHERE organization_id=$1 AND ($2='' OR group_reference>$2) ORDER BY group_reference LIMIT $3) AS page`
	postgresListAPITokensSQL             = identitysql.ListAPITokens
	postgresListAPITokenRevealGrantsSQL  = identitysql.ListAPITokenRevealGrants
	postgresRevealGrantCleanupSQL        = `WITH candidates AS MATERIALIZED (SELECT reveal.organization_id,reveal.grant_id FROM zasp_api_token_reveal_grants AS reveal LEFT JOIN zasp_product_api_tokens AS token ON token.organization_id=reveal.organization_id AND token.id=reveal.token_id WHERE reveal.acknowledged_at IS NULL AND (reveal.expires_at<=transaction_timestamp() OR token.id IS NULL OR token.revoked_at IS NOT NULL OR token.expires_at<=transaction_timestamp()) ORDER BY reveal.organization_id,reveal.workspace_id,reveal.environment_id,reveal.principal_id,reveal.grant_id FOR UPDATE OF reveal SKIP LOCKED LIMIT $1), cleaned AS (UPDATE zasp_api_token_reveal_grants AS reveal SET acknowledged_at=transaction_timestamp(),ciphertext=NULL,nonce=NULL,authentication_tag=NULL FROM candidates WHERE reveal.organization_id=candidates.organization_id AND reveal.grant_id=candidates.grant_id AND reveal.acknowledged_at IS NULL RETURNING 1) SELECT jsonb_build_object('cleaned',count(*)) FROM cleaned`
	postgresRevealAPITokenSQL            = identitysql.RevealAPIToken
	postgresListAuditEventsSQL           = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY occurred_at DESC,id DESC), '[]'::jsonb)) FROM (SELECT id,occurred_at,jsonb_build_object('id', id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'actor_id', actor_id, 'action', action, 'target_id', target_id, 'outcome', CASE outcome WHEN 'rejected' THEN 'denied' ELSE outcome END, 'metadata', COALESCE((SELECT jsonb_object_agg(entry.key,entry.value) FROM jsonb_each_text(metadata) AS entry), '{}'::jsonb), 'occurred_at', occurred_at) AS item FROM zasp_admin_audit WHERE organization_id=$1 AND ($2::timestamptz IS NULL OR (occurred_at,id)<($2,$3)) ORDER BY occurred_at DESC,id DESC LIMIT $4) AS page`
	postgresListSessionsSQL              = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', session_id, 'agent_id', 'product-console', 'principal_id', principal_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'state', CASE WHEN revoked_at IS NULL AND expires_at > now() THEN 'active' WHEN revoked_at IS NOT NULL THEN 'revoked' ELSE 'expired' END, 'authenticated_at', authenticated_at, 'expires_at', expires_at, 'version', version, 'events', '[]'::jsonb) AS item FROM zasp_product_sessions AS session WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND ($4='' OR session_id>$4) AND ($6='' OR principal_id=$6) AND ($7='' OR $7='product-console') AND ($8::timestamptz IS NULL OR authenticated_at >= $8) AND ($9::timestamptz IS NULL OR authenticated_at <= $9) ORDER BY session_id LIMIT $5) AS page`
	postgresGetSessionSQL                = `SELECT jsonb_build_object('id', session_id, 'agent_id', 'product-console', 'principal_id', principal_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'state', CASE WHEN revoked_at IS NULL AND expires_at > now() THEN 'active' WHEN revoked_at IS NOT NULL THEN 'revoked' ELSE 'expired' END, 'authenticated_at', authenticated_at, 'expires_at', expires_at, 'version', version, 'events', '[]'::jsonb) FROM zasp_product_sessions AS session WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND session_id=$4`
	postgresListSessionEventsSQL         = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY at,id), '[]'::jsonb)) FROM (SELECT id,at,jsonb_build_object('id', id, 'session_id', session_id, 'class', class, 'label', label, 'evidence_id', evidence_id, 'source', source, 'confidence', confidence, 'at', at) AS item FROM zasp_session_events WHERE organization_id=$1 AND session_id=$2 AND EXISTS (SELECT 1 FROM zasp_product_sessions WHERE organization_id=$1 AND workspace_id=$3 AND environment_id=$4 AND session_id=$2) AND ($5::timestamptz IS NULL OR (at,id)>($5,$6)) ORDER BY at,id LIMIT $7) page`
	postgresListComplianceControlsSQL    = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', control.id, 'framework', control.framework, 'name', control.name, 'evidence_ids', COALESCE((SELECT jsonb_agg(summary.id ORDER BY summary.id) FROM (SELECT evidence.id FROM zasp_compliance_evidence AS evidence WHERE evidence.organization_id=control.organization_id AND evidence.control_id=control.id ORDER BY evidence.id LIMIT 100) AS summary), '[]'::jsonb), 'fresh_until', control.fresh_until) AS item FROM zasp_compliance_controls AS control WHERE organization_id=$1 AND ($2='' OR control.id>$2) ORDER BY control.id LIMIT $3) page`
	postgresListComplianceEvidenceSQL    = `SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item#>>'{control,id}',item#>>'{evidence,0,id}'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('control',jsonb_build_object('id',control.id,'framework',control.framework,'name',control.name,'evidence_ids',COALESCE((SELECT jsonb_agg(summary.id ORDER BY summary.id) FROM (SELECT related.id FROM zasp_compliance_evidence AS related WHERE related.organization_id=control.organization_id AND related.control_id=control.id ORDER BY related.id LIMIT 100) AS summary),'[]'::jsonb),'fresh_until',control.fresh_until),'freshness',CASE WHEN control.fresh_until>now() THEN 'fresh' ELSE 'stale' END,'evidence',jsonb_build_array(jsonb_build_object('id',evidence.id,'asset_id',evidence.asset_id,'source',evidence.source,'at',evidence.at))) AS item FROM zasp_compliance_evidence AS evidence JOIN zasp_compliance_controls AS control ON control.organization_id=evidence.organization_id AND control.id=evidence.control_id WHERE evidence.organization_id=$1 AND ($2='' OR (evidence.control_id,evidence.id)>($2,$3)) ORDER BY evidence.control_id,evidence.id LIMIT $4) page`
	postgresGetDataControlsSQL           = `SELECT jsonb_build_object('environment_id', environment_id, 'environment_class', environment_class, 'collection_mode', collection_mode, 'retention_days', retention_days, 'deletion_enabled', deletion_enabled, 'version', version) FROM zasp_data_controls WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`
	postgresCreateWorkspaceSQL           = `WITH authorized AS MATERIALIZED (SELECT 1 FROM zasp_authorized_scopes scope JOIN zasp_identity_memberships membership ON membership.principal_id=scope.principal_id AND membership.organization_id=scope.organization_id AND membership.active WHERE scope.principal_id=$7 AND scope.organization_id=$2 AND scope.workspace_id=$4 AND scope.environment_id=$5), created_workspace AS (INSERT INTO zasp_workspaces(id,organization_id,name) SELECT $1,$2,$3 FROM authorized RETURNING *), created_environment AS (INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) SELECT $8,$2,$1,'Development','development' FROM created_workspace RETURNING *), granted AS (INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) SELECT $7,$2,$1,$8,left($3||' / Development',128),$9::jsonb,false FROM created_environment), bootstrap AS (INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) SELECT $2,$1,$8,'session_bootstrap:'||$7,jsonb_build_object('correlation_id',$6::text) FROM created_environment), controls AS (INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) SELECT $2,$1,$8,'development','metadata_only',30,true FROM created_environment), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $2,$4,$5,$6,$7,'workspace.onboard',$1,'succeeded',jsonb_build_object('initial_environment_id',$8::text) FROM created_environment) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'name',name,'version',version,'initial_environment_id',$8::text,'audit_correlation_id',$6::text) FROM created_workspace`
	postgresUpdateWorkspaceSQL           = `WITH authorized AS MATERIALIZED (SELECT workspace.id FROM zasp_workspaces AS workspace JOIN zasp_authorized_scopes AS scope ON scope.organization_id=workspace.organization_id AND scope.workspace_id=workspace.id JOIN zasp_identity_memberships AS membership ON membership.organization_id=scope.organization_id AND membership.principal_id=scope.principal_id AND membership.active WHERE workspace.organization_id=$1 AND workspace.id=$2 AND workspace.id=$5 AND scope.environment_id=$6 AND scope.principal_id=$8), updated AS (UPDATE zasp_workspaces AS workspace SET name=$3,version=workspace.version+1 FROM authorized WHERE workspace.organization_id=$1 AND workspace.id=authorized.id AND workspace.version=$4 RETURNING workspace.*), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,$5,$6,$7,$8,'workspace.update',$2,'succeeded','{}'::jsonb FROM updated), result AS (SELECT jsonb_build_object('id',id,'organization_id',organization_id,'name',name,'version',version,'audit_correlation_id',$7::text) AS payload FROM updated) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM authorized) THEN 'conflict' ELSE 'not_found' END))`
	postgresCreateEnvironmentSQL         = `WITH parent AS (SELECT workspace.id FROM zasp_workspaces AS workspace JOIN zasp_authorized_scopes AS scope ON scope.organization_id=workspace.organization_id AND scope.workspace_id=workspace.id WHERE workspace.organization_id=$2 AND workspace.id=$3 AND scope.principal_id=$6 AND scope.environment_id=$8 AND workspace.id=$7), created AS (INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) SELECT $1,$2,$3,$4,'development' FROM parent RETURNING *), granted AS (INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) SELECT $6,$2,$3,$1,$4,$9::jsonb,false FROM created), bootstrap AS (INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) SELECT $2,$3,$1,'session_bootstrap:'||$6,jsonb_build_object('correlation_id',$5::text) FROM created), controls AS (INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled) SELECT organization_id,workspace_id,id,environment_class,'metadata_only',30,true FROM created), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $2,$3,id,$5,$6,'environment.create',id,'succeeded','{}'::jsonb FROM created) SELECT jsonb_build_object('id',id,'organization_id',organization_id,'workspace_id',workspace_id,'name',name,'environment_class',environment_class,'version',version,'audit_correlation_id',$5::text) FROM created`
	postgresUpdateEnvironmentSQL         = `WITH updated AS (UPDATE zasp_environments SET name=$5,version=version+1 WHERE organization_id=$1 AND workspace_id=$2 AND id=$3 AND id=$4 AND version=$6 RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,workspace_id,id,$7,$8,'environment.update',$3,'succeeded','{}'::jsonb FROM updated), result AS (SELECT jsonb_build_object('id',id,'organization_id',organization_id,'workspace_id',workspace_id,'name',name,'environment_class',environment_class,'version',version,'audit_correlation_id',$7::text) AS payload FROM updated) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_environments WHERE organization_id=$1 AND workspace_id=$2 AND id=$3 AND id=$4) THEN 'conflict' ELSE 'not_found' END))`
	postgresUpdateMemberRoleSQL          = identitysql.UpdateMemberRole
	postgresUpsertGroupMappingSQL        = identitysql.UpsertGroupMapping
	postgresCreateAPITokenSQL            = identitysql.CreateAPIToken
	postgresRotateAPITokenSQL            = identitysql.RotateAPIToken
	postgresRevokeAPITokenSQL            = identitysql.RevokeAPIToken
	postgresAcknowledgeAPITokenRevealSQL = identitysql.AcknowledgeAPITokenReveal
	postgresRevokeInvestigatedSessionSQL = identitysql.RevokeInvestigatedSession
	postgresUpdateDataControlsSQL        = `WITH updated AS (UPDATE zasp_data_controls SET collection_mode=$4,retention_days=$5,deletion_enabled=$6,version=version+1,migration_seeded=false,updated_at=transaction_timestamp() WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND version=$7 AND environment_class=$8 RETURNING *), audited AS (INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata) SELECT $1,$2,$3,$9,$10,'data_controls.update',$3,'succeeded',jsonb_build_object('collection_mode',$4::text,'retention_days',$5::text) FROM updated), result AS (SELECT jsonb_build_object('environment_id',environment_id,'environment_class',environment_class,'collection_mode',collection_mode,'retention_days',retention_days,'deletion_enabled',deletion_enabled,'version',version,'audit_correlation_id',$9::text) AS payload FROM updated) SELECT COALESCE((SELECT payload FROM result),jsonb_build_object('_mutation_state',CASE WHEN EXISTS(SELECT 1 FROM zasp_data_controls WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3) THEN 'conflict' ELSE 'not_found' END))`
)

const (
	postgresCreateWorkspaceCurrentSQL   = `SELECT zasp_authorization80.create_workspace($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`
	postgresCreateEnvironmentCurrentSQL = `SELECT zasp_authorization80.create_environment($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`
)

type administrationRepository interface {
	ReadAdministration(context.Context, RequestIdentity, string, map[string]string) (json.RawMessage, error)
	MutateAdministration(context.Context, RequestIdentity, administrationMutation) (json.RawMessage, error)
}

type administrationMutation struct {
	Operation, ID, ReplacementID, Name, Role, WorkspaceID, EnvironmentID string
	InitialEnvironmentID                                                 string
	EnvironmentClass, CollectionMode, IdempotencyKey, GrantID, AuditID   string
	RetentionDays                                                        int
	DeletionEnabled                                                      bool
	Permissions                                                          json.RawMessage
	ExpiresAt                                                            time.Time
	GrantExpiresAt                                                       time.Time
	TokenDigest, Ciphertext, Nonce, AuthenticationTag                    []byte
	revealKey                                                            []byte
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
		statement := postgresListWorkspacesSQL
		if isIdentityAdministrationSchema(repository.schema) {
			statement = postgresListWorkspacesV19SQL
		}
		statement = authorizationReadStatement(ctx, statement, `SELECT zasp_authorization80.hierarchy_page('workspace',$1,NULL,$2,$3,$4)`)
		return repository.database.QueryJSON(ctx, statement, identity.Scope.OrganizationID().String(), identity.PrincipalID.String(), parameters["after_id"], adminLimit(parameters)+1)
	case "getWorkspace":
		statement := postgresGetWorkspaceSQL
		if isIdentityAdministrationSchema(repository.schema) {
			statement = postgresGetWorkspaceV19SQL
		}
		return repository.database.QueryJSON(ctx, statement, identity.Scope.OrganizationID().String(), parameters["id"], identity.PrincipalID.String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
	case "listEnvironments":
		statement := postgresListEnvironmentsSQL
		if isIdentityAdministrationSchema(repository.schema) {
			statement = postgresListEnvironmentsV19SQL
		}
		statement = authorizationReadStatement(ctx, statement, `SELECT zasp_authorization80.hierarchy_page('environment',$1,$2,$3,$4,$5)`)
		return repository.database.QueryJSON(ctx, statement, identity.Scope.OrganizationID().String(), parameters["workspace_id"], identity.PrincipalID.String(), parameters["after_id"], adminLimit(parameters)+1)
	case "getEnvironment":
		return repository.database.QueryJSON(ctx, postgresGetEnvironmentSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), parameters["id"], identity.Scope.EnvironmentID().String())
	case "listMembers":
		return repository.database.QueryJSON(ctx, postgresListMembersSQL, identity.Scope.OrganizationID().String(), parameters["after_id"], adminLimit(parameters)+1)
	case "listGroupMappings":
		return repository.database.QueryJSON(ctx, postgresListGroupMappingsSQL, identity.Scope.OrganizationID().String(), parameters["after_id"], adminLimit(parameters)+1)
	case "listAPITokens":
		return repository.database.QueryJSON(ctx, authorizationReadStatement(ctx, postgresListAPITokensSQL, currentPATPageSQL), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), parameters["after_id"], adminLimit(parameters)+1)
	case "listAPITokenRevealGrants":
		return repository.database.QueryJSON(ctx, authorizationReadStatement(ctx, postgresListAPITokenRevealGrantsSQL, currentRevealPageSQL), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), parameters["after_id"], adminLimit(parameters)+1)
	case "revealAPIToken":
		return repository.database.QueryJSON(ctx, authorizationReadStatement(ctx, postgresRevealAPITokenSQL, currentRevealPATSQL), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), parameters["id"])
	case "listAuditEvents":
		return repository.database.QueryJSON(ctx, postgresListAuditEventsSQL, identity.Scope.OrganizationID().String(), optionalAdministrationTime(parameters["after_time"]), parameters["after_id"], adminLimit(parameters)+1)
	case "listSessions":
		if parameters["kind"] == "runtime" {
			return repository.readRuntimeSession(ctx, identity, operation, parameters)
		}
		if parameters["kind"] != "" && parameters["kind"] != "console" {
			return nil, ErrRepositoryOperation
		}
		return repository.database.QueryJSON(ctx, authorizationReadStatement(ctx, postgresListSessionsSQL, `SELECT zasp_authorization80.product_session_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), parameters["after_id"], adminLimit(parameters)+1, parameters["principal_id"], parameters["agent_id"], optionalAdministrationTime(parameters["from"]), optionalAdministrationTime(parameters["to"]))
	case "getSession":
		if runtimeSessionTarget(parameters["id"]) {
			return repository.readRuntimeSession(ctx, identity, operation, parameters)
		}
		return repository.database.QueryJSON(ctx, authorizationReadStatement(ctx, postgresGetSessionSQL, `SELECT zasp_authorization80.product_session_get($1,$2,$3,$4)`), identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), parameters["id"])
	case "listSessionEvents":
		if runtimeSessionTarget(parameters["id"]) {
			return repository.readRuntimeSession(ctx, identity, operation, parameters)
		}
		return repository.database.QueryJSON(ctx, authorizationReadStatement(ctx, postgresListSessionEventsSQL, `SELECT zasp_authorization80.product_session_event_page($1,$2,$3,$4,$5,$6,$7)`), identity.Scope.OrganizationID().String(), parameters["id"], identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), optionalAdministrationTime(parameters["after_time"]), parameters["after_id"], adminLimit(parameters)+1)
	case "getSessionEvent":
		return repository.readRuntimeSession(ctx, identity, operation, parameters)
	case "listComplianceControls":
		return repository.database.QueryJSON(ctx, postgresListComplianceControlsSQL, identity.Scope.OrganizationID().String(), parameters["after_id"], adminLimit(parameters)+1)
	case "listComplianceEvidence":
		return repository.database.QueryJSON(ctx, postgresListComplianceEvidenceSQL, identity.Scope.OrganizationID().String(), parameters["after_parent_id"], parameters["after_id"], adminLimit(parameters)+1)
	case "getDataControls":
		statement := authorizationReadStatement(ctx, postgresGetDataControlsSQL, `SELECT zasp_authorization80.get_data_controls($1,$2,$3)`)
		return repository.database.QueryJSON(ctx, statement, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String())
	default:
		return nil, ErrRepositoryNotFound
	}
}

func (repository *PostgresRepository) CleanupExpiredAPITokenRevealGrants(ctx context.Context, limit int) (int, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || limit < 1 || limit > 1000 {
		return 0, ErrRepositoryOperation
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRevealGrantCleanupSQL, limit)
	if err != nil {
		return 0, err
	}
	var raw map[string]json.RawMessage
	var result struct {
		Cleaned int `json:"cleaned"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 1 || raw["cleaned"] == nil || json.Unmarshal(payload, &result) != nil || result.Cleaned < 0 || result.Cleaned > limit {
		return 0, ErrRepositoryUnavailable
	}
	return result.Cleaned, nil
}

func (repository *PostgresRepository) MutateAdministration(ctx context.Context, identity RequestIdentity, mutation administrationMutation) (json.RawMessage, error) {
	if repository == nil || nilInterface(repository.database) || ctx == nil || !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession || mutation.Operation == "" || !validAdministrationProductID(mutation.AuditID) {
		return nil, ErrRepositoryOperation
	}
	organization, workspace, environment, actor := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	switch mutation.Operation {
	case "createWorkspace":
		if _, checked := requestAuthorizationFromContext(ctx); checked {
			return repository.database.QueryJSON(ctx, postgresCreateWorkspaceCurrentSQL, mutation.ID, organization, mutation.Name, workspace, environment, mutation.AuditID, actor, mutation.InitialEnvironmentID, []byte("[]"))
		}
		permissions, err := json.Marshal(identity.Permissions)
		if err != nil {
			return nil, ErrRepositoryOperation
		}
		return repository.database.QueryJSON(ctx, postgresCreateWorkspaceSQL, mutation.ID, organization, mutation.Name, workspace, environment, mutation.AuditID, actor, mutation.InitialEnvironmentID, permissions)
	case "updateWorkspace":
		return repository.preconditionedAdministrationMutation(ctx, postgresUpdateWorkspaceSQL, organization, mutation.ID, mutation.Name, mutation.ExpectedVersion, workspace, environment, mutation.AuditID, actor)
	case "createEnvironment":
		if mutation.WorkspaceID != workspace {
			return nil, ErrRepositoryNotFound
		}
		if _, checked := requestAuthorizationFromContext(ctx); checked {
			return repository.database.QueryJSON(ctx, postgresCreateEnvironmentCurrentSQL, mutation.ID, organization, mutation.WorkspaceID, mutation.Name, mutation.AuditID, actor, workspace, environment, []byte("[]"))
		}
		permissions, err := json.Marshal(identity.Permissions)
		if err != nil {
			return nil, ErrRepositoryOperation
		}
		return repository.database.QueryJSON(ctx, postgresCreateEnvironmentSQL, mutation.ID, organization, mutation.WorkspaceID, mutation.Name, mutation.AuditID, actor, workspace, environment, permissions)
	case "updateEnvironment":
		if mutation.ID != environment {
			return nil, ErrRepositoryNotFound
		}
		return repository.preconditionedAdministrationMutation(ctx, postgresUpdateEnvironmentSQL, organization, workspace, mutation.ID, environment, mutation.Name, mutation.ExpectedVersion, mutation.AuditID, actor)
	case "updateMemberRole":
		return repository.preconditionedAdministrationMutation(ctx, postgresUpdateMemberRoleSQL, organization, mutation.ID, mutation.Role, mutation.ExpectedVersion, workspace, environment, mutation.AuditID, actor)
	case "updateGroupMappings":
		return repository.preconditionedAdministrationMutation(ctx, postgresUpsertGroupMappingSQL, organization, mutation.ID, mutation.Role, mutation.WorkspaceID, mutation.EnvironmentID, mutation.ExpectedVersion, mutation.AuditID, actor, mutation.WorkspaceID)
	case "createAPIToken":
		if mutation.WorkspaceID != workspace || mutation.EnvironmentID != environment {
			return nil, ErrRepositoryNotFound
		}
		digest := sha256.Sum256([]byte(mutation.Operation + "\x00" + mutation.Name + "\x00" + mutation.WorkspaceID + "\x00" + mutation.EnvironmentID + "\x00" + string(mutation.Permissions) + "\x00" + mutation.ExpiresAt.Format(time.RFC3339Nano)))
		return repository.preconditionedAdministrationMutation(ctx, postgresCreateAPITokenSQL, organization, actor, mutation.IdempotencyKey, digest[:], mutation.TokenDigest, mutation.ID, mutation.WorkspaceID, mutation.EnvironmentID, mutation.Name, mutation.Permissions, mutation.ExpiresAt, mutation.AuditID, mutation.GrantID, mutation.GrantExpiresAt, mutation.Ciphertext, mutation.Nonce, mutation.AuthenticationTag)
	case "rotateAPIToken":
		digest := sha256.Sum256([]byte(mutation.Operation + "\x00" + mutation.ID + "\x00" + strconv.FormatInt(mutation.ExpectedVersion, 10)))
		return repository.preconditionedAdministrationMutation(ctx, postgresRotateAPITokenSQL, organization, actor, mutation.IdempotencyKey, digest[:], mutation.ID, mutation.ExpectedVersion, mutation.TokenDigest, mutation.ReplacementID, mutation.AuditID, workspace, environment, mutation.GrantID, mutation.GrantExpiresAt, mutation.Ciphertext, mutation.Nonce, mutation.AuthenticationTag)
	case "revokeAPIToken":
		return repository.preconditionedAdministrationMutation(ctx, postgresRevokeAPITokenSQL, organization, workspace, environment, mutation.ID, mutation.ExpectedVersion, mutation.AuditID, actor)
	case "acknowledgeAPITokenRevealGrant":
		return repository.preconditionedAdministrationMutation(ctx, postgresAcknowledgeAPITokenRevealSQL, organization, workspace, environment, actor, mutation.ID, mutation.AuditID)
	case "revokeSession":
		return repository.preconditionedAdministrationMutation(ctx, postgresRevokeInvestigatedSessionSQL, organization, workspace, environment, mutation.ID, mutation.ExpectedVersion, mutation.AuditID, actor, environment)
	case "updateDataControls":
		statement := authorizationReadStatement(ctx, postgresUpdateDataControlsSQL, `SELECT zasp_authorization80.update_data_controls($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`)
		return repository.preconditionedAdministrationMutation(ctx, statement, organization, workspace, environment, mutation.CollectionMode, mutation.RetentionDays, mutation.DeletionEnabled, mutation.ExpectedVersion, mutation.EnvironmentClass, mutation.AuditID, actor)
	default:
		return nil, ErrRepositoryNotFound
	}
}

func (repository *PostgresRepository) preconditionedAdministrationMutation(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	if repository.currentAuthorization {
		statement = identityAdministrationStatement(statement)
	}
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
