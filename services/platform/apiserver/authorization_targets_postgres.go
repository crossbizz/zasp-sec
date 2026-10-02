package apiserver

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresAuthorizationResolveSQL = `SELECT zasp_authorization80.resolve($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''))`

type authorizationQueryContextKey struct{}

// Resolver reads only internal identity/version metadata, before the Check.
type PostgresAuthorizationResolver struct {
	database              *PostgresJSONDatabase
	securityAgentDatabase *PostgresJSONDatabase
}

func NewPostgresAuthorizationResolver(database *PostgresJSONDatabase) (*PostgresAuthorizationResolver, error) {
	if database == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &PostgresAuthorizationResolver{database: database}, nil
}

func NewPostgresAuthorizationResolverWithSecurityAgent(database, securityAgentDatabase *PostgresJSONDatabase) (*PostgresAuthorizationResolver, error) {
	if database == nil || securityAgentDatabase == nil {
		return nil, ErrRepositoryConfiguration
	}
	return &PostgresAuthorizationResolver{database: database, securityAgentDatabase: securityAgentDatabase}, nil
}
func (r *PostgresAuthorizationResolver) ResolveAuthorization(ctx context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
	if r == nil || r.database == nil || ctx == nil || !validRequestIdentity(identity, false) {
		return AuthorizationTargets{}, authorization.ErrInvalid
	}
	policy, err := authorizationTargetPolicy(route.OperationID)
	if err != nil || policy.Mode == "credential" {
		return AuthorizationTargets{}, authorization.ErrInvalid
	}
	id := route.PathParameters[policy.Parameter]
	query, _ := ctx.Value(authorizationQueryContextKey{}).(url.Values)
	if policy.Kind == "session" {
		if route.OperationID == "listSessions" {
			if len(query["kind"]) > 1 || query.Get("kind") != "" && query.Get("kind") != "console" && query.Get("kind") != "runtime" {
				return AuthorizationTargets{}, authorization.ErrInvalid
			}
			if query.Get("kind") != "runtime" {
				policy.Kind = "product_session"
			}
		} else if !runtimeSessionTarget(id) {
			policy.Kind = "product_session"
		}
	}
	if policy.Kind == "activity_target" {
		switch route.PathParameters["kind"] {
		case "finding", "attack_path", "agent", "tool", "identity", "runtime", "asset":
			policy.Kind = route.PathParameters["kind"]
		default:
			return AuthorizationTargets{}, authorization.ErrInvalid
		}
	}
	if policy.Mode == "scope" {
		switch policy.Kind {
		case "organization", "organization_identity":
			id = identity.Scope.OrganizationID().String()
		case "workspace":
			id = identity.Scope.WorkspaceID().String()
		case "environment":
			id = identity.Scope.EnvironmentID().String()
		}
	}
	if inventoryResourceOperation(route.OperationID) {
		database := r.database
		if database.currentAuthorization {
			// Current inventory never borrows discovery's retained source14
			// SQL privileges. Its existing separate API login owns this profile.
			if r.securityAgentDatabase == nil || r.securityAgentDatabase == database || !r.securityAgentDatabase.currentAuthorization {
				return AuthorizationTargets{}, authorization.ErrUnavailable
			}
			database = r.securityAgentDatabase
		}
		return resolveAuthorizationDatabase(ctx, database, identity, route, policy, id)
	}
	if r.securityAgentDatabase == nil {
		return resolveAuthorizationDatabase(ctx, r.database, identity, route, policy, id)
	}
	switch policy.Kind {
	case "security_agent", "security_agent_run", "security_agent_approval", "security_agent_audit":
		return resolveAuthorizationDatabase(ctx, r.securityAgentDatabase, identity, route, policy, id)
	case "*", "workflow_receipt", "audit_event", "audit_export", "compliance_export", "compliance_evidence", "compliance_control":
		// Stored parents and mixed collections can include Temporal-owned runs.
		// Neither database's partial visibility is a complete candidate set.
		result := AuthorizationTargets{Collection: policy.Mode == "collection", Complete: true, Targets: []AuthorizationTarget{}}
		seen := make(map[[2]string]AuthorizationTarget)
		for _, database := range []*PostgresJSONDatabase{r.database, r.securityAgentDatabase} {
			part, err := resolveAuthorizationDatabase(ctx, database, identity, route, policy, id)
			if err != nil {
				return AuthorizationTargets{}, err
			}
			for _, target := range part.Targets {
				key := [2]string{target.Kind, target.ID}
				if previous, exists := seen[key]; exists {
					if previous != target {
						return AuthorizationTargets{}, authorization.ErrUnavailable
					}
					continue
				}
				if len(result.Targets) == 10000 {
					return AuthorizationTargets{}, authorization.ErrUnavailable
				}
				seen[key] = target
				result.Targets = append(result.Targets, target)
			}
		}
		return result, nil
	default:
		return resolveAuthorizationDatabase(ctx, r.database, identity, route, policy, id)
	}
}

// Each query owns only its connection's read lock. A mixed collection never
// holds one database lock while acquiring another.
func resolveAuthorizationDatabase(ctx context.Context, database *PostgresJSONDatabase, identity RequestIdentity, route RoutedOperation, policy authorizationOperationTarget, id string) (AuthorizationTargets, error) {
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || nilInterface(database.driver) {
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	var payload []byte
	var err error
	if inventoryResourceOperation(route.OperationID) && database.currentAuthorization {
		if err := database.inventoryAuthorizationSourceReady(ctx); err != nil {
			return AuthorizationTargets{}, authorization.ErrUnavailable
		}
	}
	workspace := identity.Scope.WorkspaceID().String()
	if route.OperationID == "listEnvironments" {
		workspace, err = authorizationWorkspaceSelector(ctx, identity)
		if err != nil {
			return AuthorizationTargets{}, err
		}
	}
	query := postgresAuthorizationResolveSQL
	arguments := []any{identity.Scope.OrganizationID().String(), workspace, identity.Scope.EnvironmentID().String(), policy.Kind, id, route.PathParameters["sourceKind"]}
	if policy.Mode == "inventory_collection" {
		query = postgresCurrentInventoryResolveSQL
		arguments = []any{identity.Scope.OrganizationID().String(), workspace, identity.Scope.EnvironmentID().String(), route.OperationID, id, migrations.AuthorizationInventoryProfileChecksum()}
	}
	if err = database.driver.QueryRow(ctx, query, arguments...).Scan(&payload); err != nil {
		return AuthorizationTargets{}, classifyPostgresError(err)
	}
	var rows []struct {
		Organization string `json:"organization_id"`
		Workspace    string `json:"workspace_id"`
		Environment  string `json:"environment_id"`
		Kind         string `json:"kind"`
		ID           string `json:"id"`
		Version      int64  `json:"version"`
		SourceID     string `json:"source_id"`
	}
	if json.Unmarshal(payload, &rows) != nil || rows == nil || len(rows) > 10000 {
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	result := AuthorizationTargets{Collection: policy.Mode == "collection" || policy.Mode == "inventory_collection", Complete: true, Targets: make([]AuthorizationTarget, 0, len(rows))}
	for _, row := range rows {
		o, err1 := domain.ParseProductID(row.Organization)
		w, err2 := domain.ParseProductID(row.Workspace)
		e, err3 := domain.ParseProductID(row.Environment)
		scope, err4 := domain.NewScope(o, w, e)
		parentPolicy := policy.Mode == "inventory_collection" || slices.Contains([]string{"*", "workflow_receipt", "security_agent_audit", "audit_event", "audit_export", "compliance_export", "compliance_control", "compliance_evidence"}, policy.Kind)
		kindMatches := row.Kind == policy.Kind || parentPolicy && slices.Contains([]string{"environment", "workspace", "agent", "tool", "identity", "runtime", "asset", "finding", "attack_path", "policy", "integration", "sensor", "security_agent", "security_agent_run", "security_agent_approval", "test", "test_run", "attack_lab_run", "recovery_backup", "recovery_restore", "session", "product_session", "discovery_sync", "discovery_schedule"}, row.Kind)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || o != identity.Scope.OrganizationID() || !kindMatches || row.Version < 0 {
			return AuthorizationTargets{}, authorization.ErrInvalid
		}
		result.Targets = append(result.Targets, AuthorizationTarget{Scope: scope, Kind: row.Kind, ID: row.ID, Version: row.Version, SourceID: row.SourceID})
	}
	if policy.Mode == "inventory_collection" {
		if err := validateInventoryCollection(identity, route, result); err != nil {
			return AuthorizationTargets{}, err
		}
	}
	return result, nil
}

func authorizationWorkspaceSelector(ctx context.Context, identity RequestIdentity) (string, error) {
	query, _ := ctx.Value(authorizationQueryContextKey{}).(url.Values)
	values, present := query["workspace_id"]
	if !present {
		return identity.Scope.WorkspaceID().String(), nil
	}
	if len(values) != 1 {
		return "", authorization.ErrInvalid
	}
	if _, err := domain.ParseProductID(values[0]); err != nil {
		return "", authorization.ErrInvalid
	}
	return values[0], nil
}
