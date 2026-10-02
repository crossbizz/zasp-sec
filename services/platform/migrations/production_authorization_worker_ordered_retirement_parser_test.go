package migrations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Parse the actual compiled PL body without invoking it or installing any
// profile. Removing the CASE parentheses reproduces native33413's42601.
func TestOrdered69RetirementPLParser(t *testing.T) {
	socket := os.Getenv("ZASP_RETIREMENT_PARSER_SOCKET")
	if socket == "" {
		t.Skip("explicit owned parser socket required")
	}
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || !strings.HasPrefix(filepath.Base(socket), "zasp-retirement-parser.") {
		t.Fatal("invalid owned parser socket")
	}
	source, _ := authorizationWorkerProfileSource()
	const start = "DO $ordered69_retirement$"
	const end = "END $ordered69_retirement$;"
	if strings.Count(source, start) != 1 || strings.Count(source, end) != 1 {
		t.Fatal("retirement compiler block changed")
	}
	begin := strings.Index(source, start) + len(start)
	finish := strings.Index(source, end) + len("END")
	body := source[begin:finish]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal("parser configuration")
	}
	config.Host = socket
	config.Port = 5432
	config.User = "zasp_parser"
	config.Database = "postgres"
	config.Password = ""
	config.TLSConfig = nil
	config.Fallbacks = nil
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("owned parser connection unavailable")
	}
	defer func() {
		clean, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if err := conn.Close(clean); err != nil {
			t.Error("parser close")
		}
	}()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal("parser transaction unavailable")
	}
	defer func() {
		clean, done := context.WithTimeout(context.Background(), 3*time.Second)
		defer done()
		if err := tx.Rollback(clean); err != nil {
			t.Error("parser rollback")
		}
	}()
	// CREATE compiles/checks the PL expressions; the function is never invoked.
	// No predecessor objects, roles, grants or product rows are fabricated.
	_, err = tx.Exec(ctx, "CREATE FUNCTION pg_temp.retirement_parser() RETURNS void LANGUAGE plpgsql AS $parser$"+body+";$parser$")
	if err != nil {
		var native *pgconn.PgError
		if errors.As(err, &native) {
			t.Fatalf("compiled retirement PL parser SQLSTATE=%s position=%d internal=%d", native.Code, native.Position, native.InternalPosition)
		}
		t.Fatal("compiled retirement PL parser unavailable")
	}
}
