package apiserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Built-in function counters leave every installed body and security fence
// unchanged. Only this new registered API socket inherits the diagnostic GUC.
func ordered62FunctionTimingConnection(t *testing.T, ctx context.Context, owner, original *pgx.Conn) *pgx.Conn {
	t.Helper()
	login := original.Config().User
	var prior *string
	if err := owner.QueryRow(ctx, `SELECT (SELECT split_part(v,'=',2) FROM unnest(rolconfig) v WHERE v LIKE 'track_functions=%') FROM pg_roles WHERE rolname=$1`, login).Scan(&prior); err != nil {
		t.Fatal("read diagnostic role default", err)
	}
	restore := "ALTER ROLE " + pgx.Identifier{login}.Sanitize() + " RESET track_functions"
	if prior != nil {
		if *prior != "none" && *prior != "pl" && *prior != "all" {
			t.Fatal("unexpected original function tracking default")
		}
		restore = "ALTER ROLE " + pgx.Identifier{login}.Sanitize() + " SET track_functions TO '" + *prior + "'"
	}
	if _, err := owner.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" SET track_functions TO 'all'"); err != nil {
		t.Fatal("enable diagnostic role default", err)
	}
	restored := false
	defer func() {
		if !restored {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := owner.Exec(cleanup, restore); err != nil {
				t.Error("restore diagnostic role default", err)
			}
		}
	}()
	connection, err := pgx.ConnectConfig(ctx, original.Config().Copy())
	if err != nil {
		t.Fatal("same registered diagnostic socket", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = connection.Close(cleanup)
	})
	if _, err := owner.Exec(ctx, restore); err != nil {
		t.Fatal("immediate role default restoration", err)
	}
	restored = true
	var mode, principal string
	if err := connection.QueryRow(ctx, `SELECT current_setting('track_functions'),session_user`).Scan(&mode, &principal); err != nil || mode != "all" || principal != login {
		t.Fatal("function timing session differs", err)
	}
	return connection
}

func ordered62ReportFunctionTiming(t *testing.T, ctx context.Context, owner, tracked *pgx.Conn) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tracked.Close(cleanup); err != nil {
		t.Fatal("flush diagnostic API counters", err)
	}
	if _, err := owner.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
		t.Fatal(err)
	}
	rows, err := owner.Query(ctx, `SELECT schemaname,funcname,calls,total_time,self_time FROM pg_stat_user_functions WHERE calls>0 ORDER BY total_time DESC,schemaname,funcname LIMIT 40`)
	if err != nil {
		t.Fatal("read owned function counters", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var schema, function string
		var calls int64
		var total, self float64
		if err := rows.Scan(&schema, &function, &calls, &total, &self); err != nil {
			t.Fatal(err)
		}
		if schema != "public" && !strings.HasPrefix(schema, "zasp_") {
			continue
		}
		t.Logf("ordered62 function schema=%s name=%s calls=%d total_ms=%.3f self_ms=%.3f", schema, function, calls, total, self)
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("owned function timing counters absent")
	}
}
