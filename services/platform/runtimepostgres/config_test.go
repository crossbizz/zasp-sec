package runtimepostgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"reflect"
	"testing"
)

func TestOwnedPoolAvoidsReadinessJIT(t *testing.T) {
	for _, suffix := range []string{"", "&jit=on", "&jit=off"} {
		config, err := ParsePoolConfig("postgres://runtime_ingest@127.0.0.1:5432/zasp?sslmode=disable" + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if config.ConnConfig.RuntimeParams["jit"] != "off" {
			t.Fatal("owned readiness connection retained JIT compilation")
		}
	}
}

func TestPoolTuningPreservesConnectionAuthority(t *testing.T) {
	dsn := "postgres://outbox_authority@database.example.invalid:5432/zasp?sslmode=verify-full&row_security=on&search_path=pg_catalog%2Cpublic&application_name=zasp-outbox&statement_timeout=2000&options=-c%20jit%3Don%20-c%20row_security%3Don&connect_timeout=3&pool_max_conns=7&pool_min_conns=2"
	baseline, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	tuned, err := ParsePoolConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if tuned.ConnConfig.User != baseline.ConnConfig.User || tuned.ConnConfig.Database != baseline.ConnConfig.Database || tuned.ConnConfig.Host != baseline.ConnConfig.Host || tuned.ConnConfig.Port != baseline.ConnConfig.Port || tuned.ConnConfig.ConnectTimeout != baseline.ConnConfig.ConnectTimeout {
		t.Fatal("connection authority changed")
	}
	if tuned.ConnConfig.TLSConfig == nil || tuned.ConnConfig.TLSConfig.InsecureSkipVerify || tuned.ConnConfig.TLSConfig.ServerName != baseline.ConnConfig.TLSConfig.ServerName {
		t.Fatal("TLS authority changed")
	}
	if tuned.MaxConns != baseline.MaxConns || tuned.MinConns != baseline.MinConns || tuned.HealthCheckPeriod != baseline.HealthCheckPeriod || tuned.MaxConnLifetime != baseline.MaxConnLifetime {
		t.Fatal("pool resource contract changed")
	}
	params := make(map[string]string)
	for k, v := range tuned.ConnConfig.RuntimeParams {
		if k != "jit" {
			params[k] = v
		}
	}
	if !reflect.DeepEqual(params, baseline.ConnConfig.RuntimeParams) {
		t.Fatal("RLS, search path, statement budget or remaining session parameters changed")
	}
}

func TestPoolTuningPreservesMalformedDSNRefusal(t *testing.T) {
	for _, dsn := range []string{"postgres://%zz", "postgres://authority@localhost/zasp?connect_timeout=invalid", "postgres://authority@localhost/zasp?sslmode=invalid"} {
		if config, err := ParsePoolConfig(dsn); err == nil || config != nil {
			t.Fatal("malformed connection authority accepted")
		}
	}
}
