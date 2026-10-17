package preflight

import (
	"crypto/tls"
	"encoding/json"
	"testing"
)

func TestPostgresExplicitAuthorityAgainstAmbientDefaults(t *testing.T) {
	for _, kind := range []string{"explicit", "hostile-environment", "different-host", "different-database", "owner-fallback", "unknown-secret-field"} {
		t.Run(kind, func(t *testing.T) {
			c := &NeonConfig{CredentialFile: "/private/selected.json", ExpectedHost: "ep-selected-pooler.us-west-2.aws.neon.tech", ExpectedDatabase: "zasp", ExpectedPrincipal: "zasp_api_runtime", ProfileRecipe: "worker-v1"}
			data := map[string]any{"host": c.ExpectedHost, "port": 5432, "database": c.ExpectedDatabase, "user": c.ExpectedPrincipal, "password": "fixture-database-secret"}
			switch kind {
			case "hostile-environment":
				for k, v := range map[string]string{"PGHOST": "foreign.invalid", "PGPORT": "1234", "PGUSER": "owner", "PGPASSWORD": "NEVER_USE_AMBIENT_PASSWORD", "PGDATABASE": "foreign", "PGSSLMODE": "disable", "PGOPTIONS": "-c role=owner", "PGSERVICE": "foreign", "PGSERVICEFILE": "/missing/foreign-service", "PGPASSFILE": "/missing/foreign-pass"} {
					t.Setenv(k, v)
				}
			case "different-host":
				data["host"] = "ep-foreign-pooler.us-west-2.aws.neon.tech"
			case "different-database":
				data["database"] = "foreign"
			case "owner-fallback":
				data["user"] = "owner"
			case "unknown-secret-field":
				data["sslmode"] = "disable"
			}
			raw, _ := json.Marshal(data)
			cfg, e := preflightPostgresConfig(c, raw)
			if kind != "explicit" {
				if e == nil {
					t.Fatal("private authority redirected or connection options accepted")
				}
				return
			}
			if e != nil || cfg == nil || cfg.ConnConfig == nil {
				t.Fatal("explicit private authority unavailable")
			}
			conn := cfg.ConnConfig
			if conn.Host != c.ExpectedHost || conn.Port != 5432 || conn.Database != c.ExpectedDatabase || conn.User != c.ExpectedPrincipal || conn.Password != "fixture-database-secret" || len(conn.Fallbacks) != 0 || cfg.MinConns != 0 || cfg.MaxConns != 1 {
				t.Fatal("ambient authority or fallback survived finite config")
			}
			if conn.TLSConfig == nil || conn.TLSConfig.InsecureSkipVerify || conn.TLSConfig.ServerName != c.ExpectedHost || conn.TLSConfig.MinVersion < tls.VersionTLS12 {
				t.Fatal("database TLS authority weakened")
			}
			for k := range conn.RuntimeParams {
				if k != "application_name" && k != "jit" {
					t.Fatal("arbitrary role/search path/runtime authority survived")
				}
			}
		})
	}
}
