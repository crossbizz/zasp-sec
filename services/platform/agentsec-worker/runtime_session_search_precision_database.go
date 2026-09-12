package main

func newPrecisePostgresRuntimeSessionSearchAuthority(database recoveryJSONDatabase) (*postgresRuntimeSessionSearchAuthority, error) {
	authority, err := newConfiguredPostgresRuntimeSessionSearchAuthority(database, "zasp-runtime-sessions-v2")
	if err != nil {
		return nil, err
	}
	authority.precision = true
	return authority, nil
}

func (authority *postgresRuntimeSessionSearchAuthority) acceptsLeaseCapability(lease runtimeSessionSearchLease) bool {
	if authority == nil {
		return false
	}
	if !authority.precision {
		return lease.projectionImplementationVersion == ""
	}
	return lease.projectionImplementationVersion == "runtime-projection-v1" || lease.projectionImplementationVersion == "runtime-projection-v2" || lease.projectionImplementationVersion == "runtime-projection-v3"
}
