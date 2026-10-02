package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var errAuditBrowserSetup = errors.New("audit browser setup rejected")

func validateAuditBrowserSetup(environment map[string]string) (string, error) {
	for key := range environment {
		if strings.HasPrefix(key, "PG") || (strings.HasPrefix(key, "ZASP_") && key != "ZASP_AUDIT_BROWSER_SETUP" && key != "ZASP_AUDIT_BROWSER_SETUP_DSN" && key != "ZASP_AUDIT_BROWSER_SETUP_PORT") {
			return "", errAuditBrowserSetup
		}
	}
	port := environment["ZASP_AUDIT_BROWSER_SETUP_PORT"]
	number, err := strconv.Atoi(port)
	if err != nil || number < 1024 || number > 65535 || strconv.Itoa(number) != port || environment["ZASP_AUDIT_BROWSER_SETUP"] != "true" {
		return "", errAuditBrowserSetup
	}
	dsn := environment["ZASP_AUDIT_BROWSER_SETUP_DSN"]
	if dsn != "postgres://zasp_e2e@127.0.0.1:"+port+"/postgres?sslmode=disable" {
		return "", errAuditBrowserSetup
	}
	return dsn, nil
}

// This helper only registers the fixed core login. The caller owns the PG
// process, complete migration/principal setup and all subsequent configuration.
func TestProductionCombinedE2EAuditBrowserSetup(t *testing.T) {
	environment := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		environment[key] = value
	}
	_, selected := environment["ZASP_AUDIT_BROWSER_SETUP"]
	explicit := false
	if run := flag.Lookup("test.run"); run != nil && run.Value.String() != "" {
		explicit, _ = regexp.MatchString(run.Value.String(), t.Name())
	}
	if !selected && !explicit {
		t.Skip("owned audit browser setup not selected")
	}
	dsn, err := validateAuditBrowserSetup(environment)
	if err != nil {
		t.Fatal(errAuditBrowserSetup)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("audit browser setup connection failed")
	}
	defer func() {
		closing, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if connection.Close(closing) != nil {
			t.Error("audit browser setup connection cleanup failed")
		}
	}()
	var identity bool
	if err := connection.QueryRow(ctx, `SELECT session_user='zasp_e2e' AND current_user='zasp_e2e' AND current_database()='postgres' AND inet_server_addr()='127.0.0.1'::inet AND inet_server_port()=$1`, int(connection.Config().Port)).Scan(&identity); err != nil || !identity {
		t.Fatal("audit browser setup session identity refused")
	}
	runner, err := migrations.NewRunner(&migrationDatabase{connection: connection})
	if err != nil {
		t.Fatal("audit browser setup runner failed")
	}
	if err := runner.RegisterAuditExportAPI(ctx, "zasp_e2e_api"); err != nil {
		t.Fatal("audit browser setup registration refused")
	}
	t.Log("audit browser setup registered fixed core API through compiled Runner")
}
