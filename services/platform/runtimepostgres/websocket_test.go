package runtimepostgres

import (
	"context"
	"strings"
	"testing"
)

func TestTransportDefaultsToTCP(t *testing.T) {
	for _, value := range []string{"", "tcp"} {
		t.Setenv(TransportSetting, value)
		config, err := ParsePoolConfig("postgres://u@db.example.test/zasp?sslmode=require")
		if err != nil || config.ConnConfig.DialFunc == nil || config.ConnConfig.TLSConfig == nil || config.ConnConfig.Port != 5432 {
			t.Fatalf("value %q: TCP configuration changed: %v", value, err)
		}
	}
}

func TestTransportRejectsUnknownValue(t *testing.T) {
	t.Setenv(TransportSetting, "http")
	if _, err := ParsePoolConfig("postgres://u@db.example.test/zasp?sslmode=require"); err == nil {
		t.Fatal("unknown transport accepted")
	}
	if _, err := Connect(context.Background(), "postgres://u@db.example.test/zasp?sslmode=require"); err == nil {
		t.Fatal("unknown transport accepted by Connect")
	}
}

func TestWebSocketTransportRefusesUnencryptedOrAddressDSN(t *testing.T) {
	t.Setenv(TransportSetting, "websocket")
	for _, dsn := range []string{
		"postgres://u@db.example.test/zasp?sslmode=disable",
		"postgres://u@127.0.0.1/zasp?sslmode=require",
		"postgres:///zasp?host=/var/run/postgresql",
	} {
		if _, err := ParsePoolConfig(dsn); err == nil {
			t.Fatalf("%s accepted", dsn)
		}
	}
}

func TestWebSocketTransportReplacesDialAndKeepsCredentialsOutOfErrors(t *testing.T) {
	t.Setenv(TransportSetting, "websocket")
	config, err := ParsePoolConfig("postgres://u:secret-value@db.example.test/zasp?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	c := config.ConnConfig
	if c.TLSConfig != nil || len(c.Fallbacks) != 0 || c.RuntimeParams["jit"] != "off" {
		t.Fatal("inner TLS or fallbacks were kept")
	}
	hosts, err := c.LookupFunc(context.Background(), "ignored")
	if err != nil || len(hosts) != 1 || hosts[0] != "db.example.test" {
		t.Fatalf("lookup = %v, %v", hosts, err)
	}
	t.Setenv(TransportSetting, "bogus")
	if _, err := ParsePoolConfig("postgres://u:secret-value@db.example.test/zasp?sslmode=require"); err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("error leaked or missing: %v", err)
	}
}
