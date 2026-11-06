package main

import (
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"io"
)

const retentionJournalChecksumEnvironment = "ZASP_RETENTION_JOURNAL_PROFILE_CHECKSUM"

type retentionJournalInput struct {
	command, principal, pin string
	scope                   optionalEgressScopeInput
}

func retentionJournalCommand(s string) bool {
	return s == "up-retention-writer-journal" || s == "enroll-retention-journal-scope"
}
func loadRetentionJournalCommand(args []string, getenv func(string) string) (*retentionJournalInput, error) {
	if len(args) != 1 || getenv == nil || !retentionJournalCommand(args[0]) {
		return nil, errInvalidMigrationCommand
	}
	x := &retentionJournalInput{command: args[0], principal: getenv(migrationPrincipalEnvironment), pin: getenv(retentionJournalChecksumEnvironment)}
	if !databasePrincipalPattern.MatchString(x.principal) || !migrations.IsRetentionJournalProfileChecksum(x.pin) {
		return nil, errInvalidMigrationCommand
	}
	if x.command == "enroll-retention-journal-scope" {
		body, err := readRetentionOperatorFile(getenv(retentionInputEnvironment))
		if err != nil {
			return nil, err
		}
		defer clear(body)
		if !optionalEgressClosedObject(body, "organization_id", "workspace_id", "environment_id") || decodeOptionalEgressInput(body, &x.scope) != nil || !optionalEgressScopeValid(x.scope) {
			return nil, errInvalidMigrationCommand
		}
	}
	return x, nil
}
func writeRetentionJournalChecksum(out io.Writer) error {
	if out == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(out).Encode(struct {
		Profile  string `json:"profile"`
		Checksum string `json:"checksum"`
		Parent   string `json:"parent_checksum"`
	}{migrations.RetentionJournalProfileName, migrations.RetentionJournalProfileChecksum(), migrations.RetentionAuditProfileChecksum()})
}
func runRetentionJournalOperator(ctx context.Context, q principalQueryer, x *retentionJournalInput) error {
	if ctx == nil || ctx.Err() != nil || q == nil || x == nil || !databasePrincipalPattern.MatchString(x.principal) || !migrations.IsRetentionJournalProfileChecksum(x.pin) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	statement := `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_retention_journal_v1.raw_ready($2)`
	args := []any{x.principal, x.pin}
	if x.command == "enroll-retention-journal-scope" {
		statement = `SELECT CASE WHEN session_user=$1 AND zasp_authorization79.operator() THEN zasp_retention_journal_v1.enroll_scope($3,$4,$5,$2) ELSE false END`
		args = append(args, x.scope.Organization, x.scope.Workspace, x.scope.Environment)
	} else if x.command != "up-retention-writer-journal" {
		return errInvalidMigrationCommand
	}
	if q.QueryRow(ctx, statement, args...).Scan(&ready) != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}
