package apiserver

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type AgentExposureFilterResolver struct {
	original AuthorizationTargetResolver
	database *PostgresJSONDatabase
	profile  string
}

func NewAgentExposureFilterResolver(original AuthorizationTargetResolver, database *PostgresJSONDatabase, pin string) (*AgentExposureFilterResolver, error) {
	if nilInterface(original) || database == nil || !migrations.IsAgentExposureFilterProfileChecksum(pin) {
		return nil, ErrRepositoryConfiguration
	}
	switch original.(type) {
	case *PostgresAuthorizationResolver, *ConnectorMaintenanceCallbackResolver:
	default:
		return nil, ErrRepositoryConfiguration
	}
	source, ok := postLoginSnapshotResolver(original)
	if !ok || source.database != database {
		return nil, ErrRepositoryConfiguration
	}
	return &AgentExposureFilterResolver{original, database, pin}, nil
}
func (r *AgentExposureFilterResolver) ResolveAuthorization(ctx context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || nilInterface(r.original) || !validRequestIdentity(identity, false) {
		return AuthorizationTargets{}, authorization.ErrInvalid
	}
	if route.OperationID != "listAgents" {
		return r.original.ResolveAuthorization(ctx, identity, route)
	}
	query, _ := ctx.Value(authorizationQueryContextKey{}).(url.Values)
	filters, _, _, ok := agentExposureQuery(query.Encode())
	if !ok {
		return AuthorizationTargets{}, authorization.ErrInvalid
	}
	selected, _ := parseAgentExposureFilters(filters)
	original, err := r.original.ResolveAuthorization(ctx, identity, route)
	if err != nil {
		return AuthorizationTargets{}, err
	}
	if !original.Complete || !original.Collection || len(original.Targets) > 10000 {
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	targets := append([]AuthorizationTarget(nil), original.Targets...)
	for _, t := range targets {
		if t.Scope != identity.Scope || t.Kind != "agent" || !validProductID(t.ID) || t.SourceID != "" && !validProductID(t.SourceID) || t.Version < 0 {
			return AuthorizationTargets{}, authorization.ErrUnavailable
		}
	}
	if _, present := selected["risk"]; present {
		d := r.database
		d.mu.RLock()
		if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
			d.mu.RUnlock()
			return AuthorizationTargets{}, authorization.ErrUnavailable
		}
		var raw []byte
		err = d.driver.QueryRow(ctx, postgresAgentExposureRiskSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), r.profile).Scan(&raw)
		d.mu.RUnlock()
		if err != nil {
			return AuthorizationTargets{}, classifyPostgresError(err)
		}
		var rows []struct {
			Organization string `json:"organization_id"`
			Workspace    string `json:"workspace_id"`
			Environment  string `json:"environment_id"`
			Kind         string `json:"kind"`
			ID           string `json:"id"`
			SourceID     string `json:"source_id"`
			Version      int64  `json:"version"`
		}
		if decodeStrictInventory(json.RawMessage(raw), &rows) != nil || rows == nil || len(rows) > 10000 || len(targets)+len(rows) > 10000 {
			return AuthorizationTargets{}, authorization.ErrUnavailable
		}
		for _, row := range rows {
			o, e1 := domain.ParseProductID(row.Organization)
			w, e2 := domain.ParseProductID(row.Workspace)
			e, e3 := domain.ParseProductID(row.Environment)
			scope, e4 := domain.NewScope(o, w, e)
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || scope != identity.Scope || row.Kind != "finding" || !validProductID(row.ID) || !validProductID(row.SourceID) || row.Version < 0 {
				return AuthorizationTargets{}, authorization.ErrUnavailable
			}
			targets = append(targets, AuthorizationTarget{Scope: scope, Kind: row.Kind, ID: row.ID, SourceID: row.SourceID, Version: row.Version})
		}
	}
	seen := map[[2]string]bool{}
	for _, t := range targets {
		k := [2]string{t.Kind, t.ID}
		if seen[k] {
			return AuthorizationTargets{}, authorization.ErrUnavailable
		}
		seen[k] = true
	}
	if ctx.Err() != nil {
		return AuthorizationTargets{}, authorization.ErrUnavailable
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Kind != targets[j].Kind {
			return targets[i].Kind < targets[j].Kind
		}
		return targets[i].ID < targets[j].ID
	})
	return AuthorizationTargets{Collection: true, Complete: true, Targets: targets}, nil
}
