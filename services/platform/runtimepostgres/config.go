package runtimepostgres

import "github.com/jackc/pgx/v5/pgxpool"

// ParsePoolConfig preserves pgx connection authority and pool defaults while
// avoiding repeated JIT compilation of the live catalog readiness predicates.
// Readiness still runs freshly at each application entry and exit.
func ParsePoolConfig(dsn string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["jit"] = "off"
	return config, nil
}
