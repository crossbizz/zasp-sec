package demoseed_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/demoseed"
	"github.com/zasp-ai/zasp-sec/services/platform/demoseed/demoseedtest"
)

// operatorConnection connects as the migration operator of an installed
// baseline. ZASP_DEMO_OPERATOR_TEST_DSN names it: the zasp_operator role as
// `agentsec-migrate install-baseline` requires it (LOGIN, CREATEROLE,
// BYPASSRLS, owner of the database), which is not a superuser. The tests of
// this file prove that role is enough for every demo command.
func operatorConnection(t *testing.T) (*pgx.Conn, context.Context) {
	t.Helper()
	dsn := os.Getenv("ZASP_DEMO_OPERATOR_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_DEMO_OPERATOR_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	var user string
	var super bool
	if err := connection.QueryRow(ctx, `SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).Scan(&user, &super); err != nil || user != "zasp_operator" || super {
		t.Fatalf("the test needs the non-superuser zasp_operator role, got %q superuser=%t err=%v", user, super, err)
	}
	return connection, ctx
}

func TestSeedAsTheOperator(t *testing.T) {
	connection, ctx := operatorConnection(t)
	directory := demoseedtest.NewDirectory()
	seeder, err := demoseed.New(connection, directory.Adapter(t), testWriter{t})
	if err != nil {
		t.Fatal(err)
	}
	report, err := seeder.Seed(ctx, demoseed.Request{Email: "jordan.rivera@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", report)
	scopes, err := seeder.Status(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("status %+v", scopes)
	{
		removals, err := seeder.Remove(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, removal := range removals {
			t.Logf("removed %+v", removal)
		}
	}
}

type testWriter struct{ t *testing.T }

func (writer testWriter) Write(line []byte) (int, error) {
	writer.t.Log(strings.TrimRight(string(line), "\n"))
	return len(line), nil
}
