package apiserver

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

// Only the application's finite callback and exposure decorators can expose
// their original snapshot reader. Target resolution continues through the selected resolver.
// A mismatched reader/pin, nesting or an unrelated implementation refuses.
func postLoginSnapshotResolver(selected AuthorizationTargetResolver) (*PostgresAuthorizationResolver, bool) {
	switch resolver := selected.(type) {
	case *AgentExposureFilterResolver:
		if resolver == nil || resolver.database == nil || !migrations.IsAgentExposureFilterProfileChecksum(resolver.profile) {
			return nil, false
		}
		switch resolver.original.(type) {
		case *PostgresAuthorizationResolver, *ConnectorMaintenanceCallbackResolver:
		default:
			return nil, false
		}
		original, ok := postLoginSnapshotResolver(resolver.original)
		return original, ok && original != nil && original.database == resolver.database
	case *PostgresAuthorizationResolver:
		return resolver, resolver != nil && resolver.database != nil
	case *ConnectorMaintenanceCallbackResolver:
		if resolver == nil || resolver.database == nil {
			return nil, false
		}
		original, ok := resolver.original.(*PostgresAuthorizationResolver)
		if !ok || original == nil || original.database != resolver.database {
			return nil, false
		}
		pin, err := migrations.ConnectorMaintenanceProfileChecksum()
		if err != nil || resolver.profile != pin {
			return nil, false
		}
		return original, true
	default:
		return nil, false
	}
}
