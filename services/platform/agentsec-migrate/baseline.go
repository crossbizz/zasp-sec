package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations/baseline"
)

// baselineCommand reports whether the arguments select a baseline command.
func baselineCommand(arguments []string) bool {
	return len(arguments) == 1 && (arguments[0] == "install-baseline" || arguments[0] == "verify-baseline" || arguments[0] == "baseline-script")
}

// writeBaselineScript prints the installation as a JSON array of single SQL
// statements, for a transport that cannot carry a multi-statement script (an
// HTTPS SQL endpoint). The caller runs them in order in one transaction as
// the operator. ZASP_BASELINE_EXISTING_ROLES lists, comma-separated, the
// product roles the cluster already has. It needs no database.
func writeBaselineScript(getenv func(string) string, stdout, stderr io.Writer) int {
	var existing []string
	for _, role := range strings.Split(getenv("ZASP_BASELINE_EXISTING_ROLES"), ",") {
		if role = strings.TrimSpace(role); role != "" {
			if !databasePrincipalPattern.MatchString(role) {
				_, _ = io.WriteString(stderr, "baseline refused: stage=configuration\n")
				return 1
			}
			existing = append(existing, role)
		}
	}
	statements, err := baseline.Script(existing, "zasp_authorization80.ready('"+migrations.ProductionAuthorizationEnforcement().Checksum()+"')")
	if err != nil {
		_, _ = io.WriteString(stderr, "baseline refused: stage=artifact\n")
		return 1
	}
	if json.NewEncoder(stdout).Encode(statements) != nil {
		return 1
	}
	return 0
}

// runBaselineCommand installs or verifies the baseline schema. It returns the
// process exit status. A refusal names its stage and, for a database error,
// the SQLSTATE and message: installation runs DDL only, so the message holds
// object names and never a credential.
func runBaselineCommand(ctx context.Context, arguments []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if arguments[0] == "baseline-script" {
		return writeBaselineScript(getenv, stdout, stderr)
	}
	dsn := getenv(postgresDSNEnvironment)
	if dsn == "" {
		_, _ = io.WriteString(stderr, "baseline refused: stage=configuration\n")
		return 1
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		_, _ = io.WriteString(stderr, "baseline refused: stage=database\n")
		return 1
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if arguments[0] == "verify-baseline" {
		state, err := baseline.Verify(ctx, conn)
		if err != nil {
			reportBaselineRefusal(stderr, err)
			return 1
		}
		_ = json.NewEncoder(stdout).Encode(state)
		if !state.Sealed || !state.Intact || !state.Current {
			return 1
		}
		return 0
	}
	err = baseline.Install(ctx, conn, baseline.Check{
		Name: "authorization readiness",
		SQL:  `SELECT zasp_authorization80.ready($1)`,
		Args: []any{migrations.ProductionAuthorizationEnforcement().Checksum()},
	})
	if err != nil {
		reportBaselineRefusal(stderr, err)
		return 1
	}
	_ = json.NewEncoder(stdout).Encode(map[string]any{"installed": true, "artifact": baseline.Checksum()})
	return 0
}

func reportBaselineRefusal(stderr io.Writer, err error) {
	stage, reason := "unknown", ""
	var staged *baseline.StageError
	if errors.As(err, &staged) {
		stage, reason = staged.Stage, staged.Reason
	}
	line := "baseline refused: stage=" + stage
	if reason != "" {
		line += " reason=" + reason
	}
	var database *pgconn.PgError
	if errors.As(err, &database) {
		line += " sqlstate=" + database.Code + " message=" + database.Message
	}
	_, _ = io.WriteString(stderr, line+"\n")
}
