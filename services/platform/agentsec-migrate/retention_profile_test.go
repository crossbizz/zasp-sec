package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type retentionCLIInstaller struct {
	*scriptedMigrationRunner
	installs int
}

func (r *retentionCLIInstaller) UpProductionRetentionAuditProfile(context.Context) error {
	r.installs++
	return nil
}

func TestRetentionOperatorRecipeAndClosedInputs(t *testing.T) {
	ctx := context.Background()
	installer := &retentionCLIInstaller{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
	registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: installer, queryer: &releaseReadinessQueryer{}, registration: discoveryPrincipalRegistration{migration: "retention_operator"}}
	args := []string{"up-retention-audit-profile"}
	if !isForwardMigration(args) || isForwardMigration(append(args, "extra")) {
		t.Fatal("exact recipe classification")
	}
	if err := runReleaseMigration(ctx, registered, args); err != nil || installer.installs != 1 {
		t.Fatal("prepare dispatch", err)
	}
	installer.version = 60
	if err := runReleaseMigration(ctx, registered, args); !errors.Is(err, migrations.ErrInvalidState) {
		t.Fatal("wrong parent accepted")
	}
	var out bytes.Buffer
	if writeRetentionChecksum(&out) != nil {
		t.Fatal("public checksum")
	}
	var value map[string]string
	if json.Unmarshal(out.Bytes(), &value) != nil || len(value) != 2 || value["profile"] != migrations.RetentionProfileName || value["audit"] != migrations.RetentionAuditProfileChecksum() {
		t.Fatal("wrong checksum")
	}
	path := filepath.Join(t.TempDir(), "retention.json")
	env := map[string]string{migrationPrincipalEnvironment: "retention_operator", retentionChecksumEnvironment: migrations.RetentionAuditProfileChecksum(), retentionInputEnvironment: path}
	getenv := func(k string) string { return env[k] }
	cases := []struct{ command, body, function string }{
		{"register-retention-principals", `{"human_principal":"retention_api","index_principal":"retention_index","coordinator_principal":"retention_coordinator","sweep_principal":"retention_sweep"}`, "register_principal"},
		{"register-retention-scope", `{"organization_id":"pid_0e000002-0000-4000-8000-000000000002","workspace_id":"pid_0e000003-0000-4000-8000-000000000003","environment_id":"pid_0e000004-0000-4000-8000-000000000004"}`, "register_scope"},
		{"activate-retention-profile", `{"receipt_digest":"` + strings.Repeat("1", 64) + `"}`, "activate"},
	}
	for _, tc := range cases {
		if os.WriteFile(path, []byte(tc.body), 0600) != nil {
			t.Fatal("file")
		}
		input, err := loadRetentionOperator([]string{tc.command}, getenv)
		if err != nil {
			t.Fatal(tc.command, err)
		}
		q := &releaseReadinessQueryer{}
		if runRetentionOperator(ctx, q, input, &out) != nil || len(q.statements) != 1 || !strings.Contains(q.statements[0], tc.function) || !strings.Contains(q.statements[0], "session_user=$1") || q.arguments[0][1] != env[retentionChecksumEnvironment] {
			t.Fatal("lost atomic guard", tc.command)
		}
		if runRetentionOperator(ctx, &releaseReadinessQueryer{failAt: 1}, input, &out) == nil {
			t.Fatal("failure admitted")
		}
	}
	for _, raw := range []string{`{"receipt_digest":"` + strings.Repeat("1", 64) + `","activate":true}`, `{"receipt_digest":null}`, `{"RECEIPT_DIGEST":"` + strings.Repeat("1", 64) + `"}`, `{"receipt_digest":"` + strings.Repeat("1", 64) + `","receipt_digest":"` + strings.Repeat("2", 64) + `"}`} {
		_ = os.WriteFile(path, []byte(raw), 0600)
		if _, err := loadRetentionOperator([]string{"activate-retention-profile"}, getenv); err == nil {
			t.Fatal("ambiguous activation accepted")
		}
	}
	_ = os.WriteFile(path, []byte(cases[2].body), 0644)
	_ = os.Chmod(path, 0644)
	if _, err := loadRetentionOperator([]string{"activate-retention-profile"}, getenv); err == nil {
		t.Fatal("public file accepted")
	}
}

type retentionReceiptRow struct{ raw []byte }

func (r retentionReceiptRow) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("invalid destinations")
	}
	p, ok := dest[0].(*[]byte)
	if !ok {
		return errors.New("invalid destination")
	}
	*p = append([]byte(nil), r.raw...)
	return nil
}

type retentionReceiptQueryer struct {
	row       retentionReceiptRow
	statement string
	args      []any
}

func (q *retentionReceiptQueryer) QueryRow(_ context.Context, s string, args ...any) pgx.Row {
	q.statement = s
	q.args = args
	return q.row
}
func TestRetentionCutoverPreservesWholeArtifactAndConfirmsReceipt(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cutover.json")
	pin := migrations.RetentionAuditProfileChecksum()
	raw := `{"profile_checksum":"` + pin + `","release_digest":"` + strings.Repeat("1", 64) + `","consumer_manifest_digest":"` + strings.Repeat("2", 64) + `","deployment_evidence_digest":"` + strings.Repeat("3", 64) + `","credential_withdrawal_digest":"` + strings.Repeat("4", 64) + `"}`
	if os.WriteFile(file, []byte(raw), 0600) != nil {
		t.Fatal("file")
	}
	env := map[string]string{migrationPrincipalEnvironment: "retention_operator", retentionChecksumEnvironment: pin, retentionInputEnvironment: file}
	input, err := loadRetentionOperator([]string{"record-retention-cutover"}, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if string(input.body) != raw {
		t.Fatal("approved artifact rewritten")
	}
	var out bytes.Buffer
	q := &retentionReceiptQueryer{row: retentionReceiptRow{[]byte(`{"receipt_digest":"` + strings.Repeat("5", 64) + `"}`)}}
	if runRetentionOperator(context.Background(), q, input, &out) != nil || !strings.Contains(q.statement, "prepared_ready($2)") || !strings.Contains(q.statement, "record_cutover($3::jsonb)") || len(q.args) != 3 || string(q.args[2].(json.RawMessage)) != raw {
		t.Fatal("lost complete cutover binding")
	}
	for _, invalid := range []string{`null`, `{}`, `{"receipt_digest":"bad"}`, `{"receipt_digest":"` + strings.Repeat("5", 64) + `","extra":true}`} {
		q.row.raw = []byte(invalid)
		out.Reset()
		if runRetentionOperator(context.Background(), q, input, &out) == nil || out.Len() != 0 {
			t.Fatal("unconfirmed receipt published")
		}
	}
}

type retentionOperatorTestTransaction struct {
	query             releaseReadinessQueryer
	commands          []string
	commitError       bool
	committed, rolled bool
}

func (t *retentionOperatorTestTransaction) QueryRow(c context.Context, s string, args ...any) pgx.Row {
	return t.query.QueryRow(c, s, args...)
}
func (t *retentionOperatorTestTransaction) Exec(_ context.Context, s string, _ ...any) (pgconn.CommandTag, error) {
	t.commands = append(t.commands, s)
	return pgconn.NewCommandTag("SET"), nil
}
func (t *retentionOperatorTestTransaction) Commit(context.Context) error {
	t.committed = true
	if t.commitError {
		return errors.New("private uncertain commit detail")
	}
	return nil
}
func (t *retentionOperatorTestTransaction) Rollback(context.Context) error {
	t.rolled = true
	return nil
}
func TestRetentionOperatorUsesLocalOriginalAuthorityAndPublishesAfterCommit(t *testing.T) {
	for _, fail := range []bool{false, true} {
		tx := &retentionOperatorTestTransaction{commitError: fail}
		var out bytes.Buffer
		err := withRetentionOperatorTransaction(context.Background(), func(context.Context) (retentionOperatorTransaction, error) { return tx, nil }, func(_ context.Context, _ principalQueryer, w io.Writer) error {
			if tx.committed || out.Len() != 0 {
				t.Fatal("receipt published before COMMIT")
			}
			_, e := w.Write([]byte(`{"receipt_digest":"` + strings.Repeat("6", 64) + `"}`))
			return e
		}, &out)
		if len(tx.commands) != 1 || tx.commands[0] != "SET LOCAL ROLE zasp_discovery_authority" || !tx.committed || !tx.rolled {
			t.Fatal("original authority transaction missing")
		}
		if fail && (err == nil || out.Len() != 0) || !fail && (err != nil || out.Len() == 0) {
			t.Fatal("uncertain receipt published or confirmed receipt lost")
		}
	}
}

type retentionNoInheritPreflight struct {
	configured    bool
	protectedRead bool
	args          []any
}

func (q *retentionNoInheritPreflight) QueryRow(_ context.Context, s string, args ...any) pgx.Row {
	q.args = args
	if strings.Contains(s, "zasp_discovery_principal_bindings") || strings.Contains(s, "zasp_authorization79.operator") {
		q.protectedRead = true
		return releaseReadinessErrorRow{}
	}
	return scriptedPrincipalRow{value: q.configured}
}
func TestRetentionPrepareCommandPreservesConfiguredNoInheritLogin(t *testing.T) {
	for _, configured := range []bool{true, false} {
		installer := &retentionCLIInstaller{scriptedMigrationRunner: &scriptedMigrationRunner{version: 61}}
		q := &retentionNoInheritPreflight{configured: configured}
		registered := &registeredReleaseMigrationRunner{releaseMigrationRunner: installer, queryer: q, registration: discoveryPrincipalRegistration{migration: "retention_operator"}}
		err := runReleaseMigration(context.Background(), registered, []string{"up-retention-audit-profile"})
		if q.protectedRead || len(q.args) != 1 || q.args[0] != "retention_operator" {
			t.Fatal("preflight read protected binding or lost configured login")
		}
		if configured && (err != nil || installer.installs != 1) || !configured && (!errors.Is(err, errReleasePrincipalRegistration) || installer.installs != 0) {
			t.Fatal("NOINHERIT refused or wrong session reached installer")
		}
	}
}
