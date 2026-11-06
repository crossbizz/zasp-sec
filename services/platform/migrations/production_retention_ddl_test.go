package migrations

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Transaction fixtures prove ordering/receipt publication only. Actual owner,
// ACL and NOINHERIT semantics require the original guarded native fixture.
func TestRetentionPublicDDLBootstrapTransactionBoundary(t *testing.T) {
	request := RetentionDDLBootstrapRequest{Principal: "schema_owner", Database: "production"}
	for _, phase := range []string{"authorized", "idempotent", "unauthorized", "wrong identity", "unsafe role", "grant failed", "postcheck failed", "commit unknown", "context interrupted"} {
		t.Run(phase, func(t *testing.T) {
			allowed := phase != "unauthorized" && phase != "wrong identity" && phase != "unsafe role"
			tx := &fakeTransaction{rows: []Row{
				fakeRow{values: []any{allowed, int64(101), int64(2200), int64(4000)}},
				fakeRow{values: []any{phase != "postcheck failed"}},
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "context interrupted" {
				tx.rows[1] = retentionDDLPostcheckCancellation{Row: tx.rows[1], cancel: cancel}
			}
			if phase == "grant failed" {
				tx.execErrorAt = 2
			}
			if phase == "commit unknown" {
				tx.commitError = errors.New("private uncertain commit")
			}
			db := &fakeDatabase{transaction: tx}
			runner, err := NewRunner(db)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := runner.BootstrapProductionRetentionPublicDDL(ctx, request)
			committed := phase == "authorized" || phase == "idempotent"
			if committed {
				if err != nil || receipt.Principal != request.Principal || receipt.Database != request.Database || receipt.Schema != "public" || receipt.Grantee != "zasp_discovery_authority" || receipt.Capability != "retention-public-create-v1" || receipt.DatabaseOID != 101 || receipt.SchemaOID != 2200 || receipt.GranteeOID != 4000 {
					t.Fatal("confirmed receipt lost fixed identity", err)
				}
			} else if err == nil || !reflect.DeepEqual(receipt, RetentionDDLBootstrapReceipt{}) {
				t.Fatal("failure published bootstrap success")
			}
			events := strings.Join(db.events, "\n")
			grant := strings.Index(events, "exec:GRANT CREATE ON SCHEMA public TO zasp_discovery_authority")
			if !allowed && grant >= 0 {
				t.Fatal("unproven owner or unsafe role reached GRANT")
			}
			if allowed && (grant < strings.Index(events, "query:") || !strings.Contains(events, "zasp-schema-migrations")) {
				t.Fatal("grant escaped guarded migration lock")
			}
			if !committed && !strings.Contains(events, "rollback") {
				t.Fatal("failed bootstrap did not roll back")
			}
			for _, forbidden := range []string{"SET LOCAL ROLE", "WITH GRANT OPTION", "ALTER ROLE", "REVOKE", "CREATE FUNCTION", "GRANT ALL", "GRANT CREATE ON DATABASE"} {
				// WITH GRANT OPTION must never appear in executed DDL.
				for _, event := range db.events {
					if strings.HasPrefix(event, "exec:") && strings.Contains(event, forbidden) {
						t.Fatal("bootstrap expanded authority", forbidden)
					}
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	db := &fakeDatabase{transaction: &fakeTransaction{}}
	runner, _ := NewRunner(db)
	if result, err := runner.BootstrapProductionRetentionPublicDDL(ctx, request); err == nil || result != (RetentionDDLBootstrapReceipt{}) || len(db.events) != 0 {
		t.Fatal("cancelled bootstrap touched database or published success")
	}
	for _, invalid := range []RetentionDDLBootstrapRequest{{Principal: "owner;grant", Database: "production"}, {Principal: "schema_owner"}, {Database: "production"}} {
		if _, err := runner.BootstrapProductionRetentionPublicDDL(context.Background(), invalid); err == nil || len(db.events) != 0 {
			t.Fatal("invalid identity reached database")
		}
	}
}

func TestRetentionPublicDDLInstallerNeverProvisionsItsOwnCapability(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing requires owner", true: "installed structural replay"}[installed], func(t *testing.T) {
			rows := []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{installed}}}
			rows = append(rows, fakeRow{values: []any{installed}})
			tx := &fakeTransaction{rows: rows}
			db := &fakeDatabase{transaction: tx}
			runner, _ := NewRunner(db)
			err := runner.UpProductionRetentionAuditProfile(context.Background())
			if !installed && !errors.Is(err, ErrRetentionPublicDDLPrerequisite) {
				t.Fatal("missing capability did not expose owner prerequisite", err)
			}
			if installed && err != nil {
				t.Fatal("installed structural replay newly required DDL", err)
			}
			events := strings.Join(db.events, "\n")
			if strings.Contains(events, "exec:GRANT") || strings.Contains(events, "CREATE FUNCTION") || strings.Contains(events, "SET LOCAL ROLE NONE") {
				t.Fatal("ordinary installer silently provisioned authority")
			}
		})
	}
}

type retentionDDLPostcheckCancellation struct {
	Row
	cancel context.CancelFunc
}

func (r retentionDDLPostcheckCancellation) Scan(dest ...any) error {
	err := r.Row.Scan(dest...)
	if err == nil {
		r.cancel()
	}
	return err
}
