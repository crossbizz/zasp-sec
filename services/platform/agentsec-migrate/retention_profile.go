package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const retentionInputEnvironment = "ZASP_RETENTION_CONFIGURATION_FILE"
const retentionChecksumEnvironment = "ZASP_RETENTION_PROFILE_CHECKSUM"

var retentionDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func retentionProfileCommand(command string) bool { return command == "up-retention-audit-profile" }
func retentionOperatorCommand(command string) bool {
	switch command {
	case "register-retention-principals", "register-retention-scope", "record-retention-cutover", "activate-retention-profile":
		return true
	}
	return false
}
func writeRetentionChecksum(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Profile string `json:"profile"`
		Audit   string `json:"audit"`
	}{migrations.RetentionProfileName, migrations.RetentionAuditProfileChecksum()})
}
func (r *registeredReleaseMigrationRunner) UpProductionRetentionAuditProfile(ctx context.Context) error {
	if r == nil || r.releaseMigrationRunner == nil || r.queryer == nil || ctx == nil || ctx.Err() != nil || !databasePrincipalPattern.MatchString(r.registration.migration) {
		return errReleasePrincipalRegistration
	}
	// This preflight must not read the FORCE-RLS binding as a NOINHERIT
	// login. The exact original binding, ownership and parents are checked by
	// Runner inside its own SET LOCAL ROLE authority transaction. Here retain
	// the independently configured session identity and existing membership.
	var configured bool
	if err := r.queryer.QueryRow(ctx, `SELECT session_user=$1 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`, r.registration.migration).Scan(&configured); err != nil || !configured {
		return errReleasePrincipalRegistration
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionRetentionAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionRetentionAuditProfile(ctx)
}
func retentionPostInstall(ctx context.Context, q principalQueryer, principal string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) {
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_retention_v1.prepared_ready($2)`, principal, migrations.RetentionAuditProfileChecksum()).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

type retentionPrincipals struct {
	Human       string `json:"human_principal"`
	Index       string `json:"index_principal"`
	Coordinator string `json:"coordinator_principal"`
	Sweep       string `json:"sweep_principal"`
}
type retentionCutover struct {
	Profile    string `json:"profile_checksum"`
	Release    string `json:"release_digest"`
	Consumers  string `json:"consumer_manifest_digest"`
	Deployment string `json:"deployment_evidence_digest"`
	Withdrawal string `json:"credential_withdrawal_digest"`
}
type retentionActivation struct {
	Receipt string `json:"receipt_digest"`
}
type retentionOperatorInput struct {
	principal, checksum, command string
	principals                   retentionPrincipals
	scope                        optionalEgressScopeInput
	activation                   retentionActivation
	body                         json.RawMessage
}

func (retentionOperatorInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[retention operator input]"))
}

// Use an immutable, private, bounded local operator file. No SQL source,
// connection string, secret or caller-supplied function name is accepted.
func readRetentionOperatorFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errInvalidMigrationCommand
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || (before.Mode().Perm() != 0400 && before.Mode().Perm() != 0600) || before.Size() < 2 || before.Size() > 16384 {
		return nil, errInvalidMigrationCommand
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errInvalidMigrationCommand
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(before, current) || current.Mode() != before.Mode() || current.Size() != before.Size() || !current.ModTime().Equal(before.ModTime()) {
		return nil, errInvalidMigrationCommand
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, errInvalidMigrationCommand
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(current, after) || after.Mode() != current.Mode() || after.Size() != current.Size() || int64(len(raw)) != current.Size() || !after.ModTime().Equal(current.ModTime()) {
		clear(raw)
		return nil, errInvalidMigrationCommand
	}
	return raw, nil
}
func loadRetentionOperator(args []string, getenv func(string) string) (*retentionOperatorInput, error) {
	if len(args) != 1 || getenv == nil || !retentionOperatorCommand(args[0]) {
		return nil, errInvalidMigrationCommand
	}
	r := &retentionOperatorInput{principal: getenv(migrationPrincipalEnvironment), checksum: getenv(retentionChecksumEnvironment), command: args[0]}
	if !databasePrincipalPattern.MatchString(r.principal) || !migrations.IsRetentionProfileChecksum(r.checksum) {
		return nil, errInvalidMigrationCommand
	}
	raw, err := readRetentionOperatorFile(getenv(retentionInputEnvironment))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	switch r.command {
	case "register-retention-principals":
		if !optionalEgressClosedObject(raw, "human_principal", "index_principal", "coordinator_principal", "sweep_principal") || decodeOptionalEgressInput(raw, &r.principals) != nil {
			return nil, errInvalidMigrationCommand
		}
		seen := map[string]bool{r.principal: true}
		for _, p := range []string{r.principals.Human, r.principals.Index, r.principals.Coordinator, r.principals.Sweep} {
			if !databasePrincipalPattern.MatchString(p) || seen[p] {
				return nil, errInvalidMigrationCommand
			}
			seen[p] = true
		}
	case "register-retention-scope":
		if !optionalEgressClosedObject(raw, "organization_id", "workspace_id", "environment_id") || decodeOptionalEgressInput(raw, &r.scope) != nil || !optionalEgressScopeValid(r.scope) {
			return nil, errInvalidMigrationCommand
		}
	case "record-retention-cutover":
		var c retentionCutover
		if !optionalEgressClosedObject(raw, "profile_checksum", "release_digest", "consumer_manifest_digest", "deployment_evidence_digest", "credential_withdrawal_digest") || decodeOptionalEgressInput(raw, &c) != nil || c.Profile != r.checksum {
			return nil, errInvalidMigrationCommand
		}
		for _, d := range []string{c.Profile, c.Release, c.Consumers, c.Deployment, c.Withdrawal} {
			if !retentionDigestPattern.MatchString(d) {
				return nil, errInvalidMigrationCommand
			}
		}
		// Preserve the exact approved JSON; PostgreSQL binds the whole value to
		// server database identity, operator and immutable parent profiles.
		r.body = append(json.RawMessage(nil), raw...)
	case "activate-retention-profile":
		if !optionalEgressClosedObject(raw, "receipt_digest") || decodeOptionalEgressInput(raw, &r.activation) != nil || !retentionDigestPattern.MatchString(r.activation.Receipt) {
			return nil, errInvalidMigrationCommand
		}
	}
	return r, nil
}
func runRetentionOperator(ctx context.Context, q principalQueryer, r *retentionOperatorInput, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || q == nil || r == nil || !databasePrincipalPattern.MatchString(r.principal) || !migrations.IsRetentionProfileChecksum(r.checksum) {
		return errReleasePrincipalRegistration
	}
	const prepared = `session_user=$1 AND zasp_authorization79.operator() AND zasp_retention_v1.prepared_ready($2)`
	const current = `session_user=$1 AND zasp_authorization79.operator() AND (zasp_retention_v1.prepared_ready($2) OR zasp_retention_v1.effective_catalog_ready($2))`
	prefix := `SELECT CASE WHEN ` + current + ` THEN `
	args := []any{r.principal, r.checksum}
	var statement string
	switch r.command {
	case "register-retention-principals":
		statement = prefix + `zasp_retention_v1.register_principal($3,'human-read') AND zasp_retention_v1.register_principal($4,'runtime-index') AND zasp_retention_v1.register_principal($5,'runtime-coordinator') AND zasp_retention_v1.register_principal($6,'sweep') ELSE false END`
		args = append(args, r.principals.Human, r.principals.Index, r.principals.Coordinator, r.principals.Sweep)
	case "register-retention-scope":
		statement = prefix + `zasp_retention_v1.register_scope($3,$4,$5) ELSE false END`
		args = append(args, r.scope.Organization, r.scope.Workspace, r.scope.Environment)
	case "activate-retention-profile":
		statement = `SELECT CASE WHEN session_user=$1 AND zasp_authorization79.operator() THEN zasp_retention_v1.activate($2,$3) ELSE false END`
		args = append(args, r.activation.Receipt)
	case "record-retention-cutover":
		var raw []byte
		statement = `SELECT CASE WHEN ` + prepared + ` THEN zasp_retention_v1.record_cutover($3::jsonb) ELSE NULL END`
		if err := q.QueryRow(ctx, statement, append(args, r.body)...).Scan(&raw); err != nil {
			return errReleasePrincipalRegistration
		}
		var receipt retentionActivation
		if !optionalEgressClosedObject(raw, "receipt_digest") || decodeOptionalEgressInput(raw, &receipt) != nil || !retentionDigestPattern.MatchString(receipt.Receipt) || out == nil {
			return errReleasePrincipalRegistration
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return errReleasePrincipalRegistration
		}
		return nil
	default:
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, statement, args...).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

// Preserve the registered NOINHERIT migration login. Only this transaction
// assumes its existing authority role; session_user remains the real operator.
// A cutover receipt is published only after confirmed COMMIT.
type retentionOperatorTransaction interface {
	principalQueryer
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

func withRetentionOperatorTransaction(ctx context.Context, begin func(context.Context) (retentionOperatorTransaction, error), action func(context.Context, principalQueryer, io.Writer) error, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || begin == nil || action == nil {
		return errReleasePrincipalRegistration
	}
	tx, err := begin(ctx)
	if err != nil || tx == nil {
		return errReleasePrincipalRegistration
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		return errReleasePrincipalRegistration
	}
	var buffered bytes.Buffer
	defer func() { clear(buffered.Bytes()) }()
	if action(ctx, tx, &buffered) != nil {
		return errReleasePrincipalRegistration
	}
	if ctx.Err() != nil || tx.Commit(ctx) != nil {
		return errReleasePrincipalRegistration
	}
	if buffered.Len() > 0 {
		if out == nil {
			return errReleasePrincipalRegistration
		}
		if _, err = out.Write(buffered.Bytes()); err != nil {
			return errReleasePrincipalRegistration
		}
	}
	return nil
}

const retentionDDLBootstrapCommand = "bootstrap-retention-public-ddl"
const retentionDDLPrincipalEnvironment = "ZASP_RETENTION_DDL_BOOTSTRAP_PRINCIPAL"
const retentionDDLDatabaseEnvironment = "ZASP_RETENTION_DDL_BOOTSTRAP_DATABASE"

type retentionDDLBootstrapper interface {
	BootstrapProductionRetentionPublicDDL(context.Context, migrations.RetentionDDLBootstrapRequest) (migrations.RetentionDDLBootstrapReceipt, error)
}

func loadRetentionDDLBootstrap(args []string, getenv func(string) string) (migrations.RetentionDDLBootstrapRequest, error) {
	if len(args) != 1 || args[0] != retentionDDLBootstrapCommand || getenv == nil {
		return migrations.RetentionDDLBootstrapRequest{}, errInvalidMigrationCommand
	}
	request := migrations.RetentionDDLBootstrapRequest{Principal: getenv(retentionDDLPrincipalEnvironment), Database: getenv(retentionDDLDatabaseEnvironment)}
	if request.Validate() != nil {
		return migrations.RetentionDDLBootstrapRequest{}, errInvalidMigrationCommand
	}
	return request, nil
}
func runRetentionDDLBootstrap(ctx context.Context, runner retentionDDLBootstrapper, request migrations.RetentionDDLBootstrapRequest, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || runner == nil || request.Validate() != nil || out == nil {
		return errInvalidMigrationCommand
	}
	receipt, err := runner.BootstrapProductionRetentionPublicDDL(ctx, request)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(receipt)
}
