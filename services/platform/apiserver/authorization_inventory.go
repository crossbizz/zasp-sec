package apiserver

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresCurrentInventoryDetailSQL        = `SELECT zasp_authorization80_inventory.detail($1,$2,$3,$4,$5,$6)`
	postgresCurrentInventoryCapabilitiesSQL  = `SELECT zasp_authorization80_inventory.capabilities_page($1,$2,$3,$4,NULLIF($5,''),$6,$7)`
	postgresCurrentInventoryRelationshipsSQL = `SELECT zasp_authorization80_inventory.relationships_page($1,$2,$3,$4,NULLIF($5,''),$6,$7)`
	postgresCurrentInventorySessionsSQL      = `SELECT zasp_authorization80_inventory.sessions_page($1,$2,$3,$4,NULLIF($5,''),$6,$7)`
	postgresCurrentInventoryUpdateSQL        = `SELECT zasp_authorization80_inventory.update_agent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)`
	postgresCurrentInventoryResolveSQL       = `SELECT zasp_authorization80_inventory.resolve($1,$2,$3,$4,$5,$6)`
)

// This source query is compiled and checks the profile's own catalog/ready
// routine identities before accepting their answer. It is never request SQL.
func (d *PostgresJSONDatabase) CurrentAuthorizationInventoryReady(ctx context.Context) error {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.inventoryAuthorizationSourceReady(ctx)
}

// Caller holds d.mu. No positive readiness result is cached across requests.
func (d *PostgresJSONDatabase) inventoryAuthorizationSourceReady(ctx context.Context) error {
	if !d.currentAuthorization || d.closed || nilInterface(d.driver) {
		return ErrRepositoryUnavailable
	}
	var ready bool
	if err := d.driver.QueryRow(ctx, migrations.AuthorizationInventoryReadySourceSQL()).Scan(&ready); err != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func inventoryAuthorizationQuery(ctx context.Context, legacy, current string, args ...any) (string, []any) {
	if _, ok := requestAuthorizationFromContext(ctx); !ok {
		return legacy, args
	}
	return current, append(append([]any(nil), args...), migrations.AuthorizationInventoryProfileChecksum())
}

func inventoryStatementAllowed(g RequestAuthorization, q string, args []any) (bool, bool) {
	count, actor, target, operation := 0, -1, 3, ""
	switch q {
	case postgresCurrentInventoryDetailSQL:
		count = 6
	case postgresCurrentInventoryCapabilitiesSQL:
		count, operation = 7, "getAgentCapabilities"
	case postgresCurrentInventoryRelationshipsSQL:
		count, operation = 7, "getAgentRelationships"
	case postgresCurrentInventorySessionsSQL:
		count, operation = 7, "listAgentSessions"
	case postgresCurrentInventoryUpdateSQL:
		count, actor, target, operation = 13, 3, 4, "updateAgent"
	default:
		return false, false
	}
	if len(args) != count || args[count-1] != migrations.AuthorizationInventoryProfileChecksum() {
		return true, false
	}
	for n, expected := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String()} {
		if args[n] != expected {
			return true, false
		}
	}
	id, ok := args[target].(string)
	if !ok || id == "" || id != g.PathParameters["id"] {
		return true, false
	}
	kind := "agent"
	if q == postgresCurrentInventoryDetailSQL {
		value, ok := args[4].(InventoryKind)
		if !ok {
			return true, false
		}
		kind = string(value)
		operation = map[InventoryKind]string{InventoryKindAgent: "getAgent", InventoryKindTool: "getTool", InventoryKindIdentity: "getIdentity", InventoryKindRuntime: "getRuntime", InventoryKindAsset: "getAsset"}[value]
	}
	if operation == "" || g.OperationID != operation || !authorizationNativeTargetAllowed(g, kind, id) || g.Collection != inventorySubresourceOperation(operation) {
		return true, false
	}
	if actor >= 0 {
		version, validVersion := args[6].(int64)
		_, validTags := args[9].(json.RawMessage)
		if args[actor] != g.Identity.PrincipalID.String() || !validVersion || version < 1 || version >= 1000000 || !validTags {
			return true, false
		}
	} else if inventorySubresourceOperation(operation) {
		limit, ok := args[5].(int)
		if !ok || limit < 1 || limit > 100 {
			return true, false
		}
		if _, ok := args[4].(string); !ok {
			return true, false
		}
	}
	return true, true
}

func inventorySubresourceOperation(operation string) bool {
	return operation == "getAgentCapabilities" || operation == "getAgentRelationships" || operation == "listAgentSessions"
}

func inventoryResourceOperation(operation string) bool {
	if inventorySubresourceOperation(operation) {
		return true
	}
	switch operation {
	case "listAgents", "listTools", "listIdentities", "listRuntimes", "getAgent", "getTool", "getIdentity", "getRuntime", "getAsset", "updateAgent":
		return true
	default:
		return false
	}
}

// These three closed routes have a required agent and optional resource
// candidates. The required parent is identified by its stored kind, scope and
// path ID, independently of resolver order. No generic collection can opt in.
func validateInventoryCollection(identity RequestIdentity, route RoutedOperation, targets AuthorizationTargets) error {
	if !targets.Collection {
		return authorization.ErrInvalid
	}
	if _, err := domain.ParseProductID(route.PathParameters["id"]); err != nil {
		return authorization.ErrInvalid
	}
	if len(targets.Targets) == 0 {
		return authorizationTargetDenied(route.OperationID)
	}
	seen := make(map[[2]string]bool)
	parent := false
	for _, target := range targets.Targets {
		key := [2]string{target.Kind, target.ID}
		if seen[key] || target.Scope != identity.Scope || target.Version < 0 || target.SourceID != "" && target.SourceID != target.ID {
			return authorization.ErrInvalid
		}
		seen[key] = true
		if _, err := domain.ParseProductID(target.ID); err != nil {
			return authorization.ErrInvalid
		}
		if target.Kind == "agent" && target.ID == route.PathParameters["id"] {
			parent = true
			continue
		}
		if route.OperationID == "listAgentSessions" {
			if target.Kind != "session" {
				return authorization.ErrInvalid
			}
		} else if !validInventoryKind(InventoryKind(target.Kind)) {
			return authorization.ErrInvalid
		}
	}
	if !parent {
		return authorization.ErrInvalid
	}
	return nil
}

// Native adapters must expose distinct current pools. Explicit custom adapters
// can model this admission contract, but mixed native/custom wiring is refused.
func inventoryDatabasesDistinct(primary, secondary JSONDatabase) bool {
	if nilInterface(primary) || nilInterface(secondary) {
		return false
	}

	if inventoryNativeDatabaseAdapter(primary) != inventoryNativeDatabaseAdapter(secondary) {
		return false
	}
	if inventoryNativeDatabaseAdapter(primary) {
		return true
	} // exact pool identity is checked by the caller
	if reflect.TypeOf(primary) != reflect.TypeOf(secondary) {
		return true
	}
	if !reflect.TypeOf(primary).Comparable() {
		return false
	}
	return primary != secondary
}

func inventoryNativeDatabaseAdapter(d JSONDatabase) bool {
	if _, ok := d.(*PostgresJSONDatabase); ok {
		return true
	}
	wrapper, ok := d.(interface{ NativeIdentityDatabase() *PostgresJSONDatabase })
	return ok && wrapper.NativeIdentityDatabase() != nil
}
