package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type retentionDDLBootstrapFixture struct {
	calls int
	fail  bool
}

func (f *retentionDDLBootstrapFixture) BootstrapProductionRetentionPublicDDL(_ context.Context, r migrations.RetentionDDLBootstrapRequest) (migrations.RetentionDDLBootstrapReceipt, error) {
	f.calls++
	receipt := migrations.RetentionDDLBootstrapReceipt{Capability: "retention-public-create-v1", Principal: r.Principal, Database: r.Database, Schema: "public", Grantee: "zasp_discovery_authority", DatabaseOID: 101, SchemaOID: 2200, GranteeOID: 4000}
	if f.fail {
		return receipt, errors.New("private commit unknown")
	}
	return receipt, nil
}
func TestRetentionPublicDDLCommandUsesExactOwnerAndConfirmedHelper(t *testing.T) {
	env := map[string]string{retentionDDLPrincipalEnvironment: "schema_owner", retentionDDLDatabaseEnvironment: "production"}
	request, err := loadRetentionDDLBootstrap([]string{"bootstrap-retention-public-ddl"}, func(k string) string { return env[k] })
	if err != nil || request.Principal != "schema_owner" || request.Database != "production" {
		t.Fatal("explicit owner configuration rejected", err)
	}
	for _, args := range [][]string{{"bootstrap-retention-public-ddl", "other-role"}, {"up-retention-audit-profile"}, nil} {
		if _, err := loadRetentionDDLBootstrap(args, func(k string) string { return env[k] }); err == nil {
			t.Fatal("arbitrary bootstrap arguments accepted")
		}
	}
	if isForwardMigration([]string{"bootstrap-retention-public-ddl"}) || retentionOperatorCommand("bootstrap-retention-public-ddl") {
		t.Fatal("bootstrap silently used ordinary operator installer")
	}
	for _, fail := range []bool{false, true} {
		fixture := &retentionDDLBootstrapFixture{fail: fail}
		var out bytes.Buffer
		err := runRetentionDDLBootstrap(context.Background(), fixture, request, &out)
		if fail {
			if err == nil || out.Len() != 0 {
				t.Fatal("unknown commit emitted a success receipt")
			}
		} else if err != nil || fixture.calls != 1 || !strings.Contains(out.String(), `"capability":"retention-public-create-v1"`) || strings.Contains(out.String(), "private") {
			t.Fatal("exact shared helper was not used", err)
		}
	}
}
