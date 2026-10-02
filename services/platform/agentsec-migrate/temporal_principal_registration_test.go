package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestTemporalPrincipalRegistration(t *testing.T) {
	values := map[string]string{"ZASP_MIGRATION_DB_PRINCIPAL": "profile_operator", "ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL": "temporal_executor_login", "ZASP_TEMPORAL_COMPENSATION_DB_PRINCIPAL": "temporal_compensation_login"}
	get := func(k string) string { return values[k] }
	r, err := loadTemporalPrincipalRegistration([]string{"register-temporal-executor-principals"}, get)
	if err != nil {
		t.Fatal(err)
	}
	q := &releaseReadinessQueryer{}
	for i := 0; i < 2; i++ {
		if err := registerTemporalPrincipals(context.Background(), q, r); err != nil {
			t.Fatal(err)
		}
	}
	if len(q.statements) != 4 || q.statements[1] != "SELECT true FROM zasp_temporal68.register_principals($1,$2)" || !reflect.DeepEqual(q.arguments[1], []any{"temporal_executor_login", "temporal_compensation_login"}) {
		t.Fatalf("wrong native binding: %v %v", q.statements, q.arguments)
	}
	for _, at := range []int{1, 2} {
		failed := &releaseReadinessQueryer{failAt: at}
		if err := registerTemporalPrincipals(context.Background(), failed, r); !errors.Is(err, errReleasePrincipalRegistration) || len(failed.statements) != at {
			t.Fatalf("failed authority/native call continued: %v", err)
		}
	}
	for _, bad := range []string{"profile_operator", "temporal_compensation_login", "BadName", "a'; DROP ROLE x;--", "", "xx"} {
		values["ZASP_TEMPORAL_EXECUTOR_DB_PRINCIPAL"] = bad
		if _, err := loadTemporalPrincipalRegistration([]string{"register-temporal-executor-principals"}, get); err == nil {
			t.Fatalf("invalid principal accepted %q", bad)
		}
	}
}
