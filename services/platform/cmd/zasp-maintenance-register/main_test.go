package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestRegistrationConfigurationPinsAndPrincipalIsolation(t *testing.T) {
	connector, err := migrations.ConnectorMaintenanceProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	activation, err := migrations.ApprovalActivationProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"ZASP_POSTGRES_DSN": "postgres://operator@127.0.0.1:32100/postgres?sslmode=disable", "ZASP_CONNECTOR_MAINTENANCE_DB_PRINCIPAL": "zasp_e2e_outbox", "ZASP_APPROVAL_MAINTENANCE_DB_PRINCIPAL": "zasp_e2e_approval_maintenance", "ZASP_CONNECTOR_MAINTENANCE_KEY_FILE": "/owned/connector", "ZASP_APPROVAL_MAINTENANCE_KEY_FILE": "/owned/approval", "ZASP_CONNECTOR_MAINTENANCE_PROFILE_CHECKSUM": connector, "ZASP_APPROVAL_MAINTENANCE_PROFILE_CHECKSUM": migrations.ApprovalMaintenanceProfileChecksum(), "ZASP_APPROVAL_ACTIVATION_PROFILE_CHECKSUM": activation}
	getenv := func(name string) string { return values[name] }
	if _, err := loadConfig(getenv); err != nil {
		t.Fatal("exact static configuration refused")
	}
	for name, original := range values {
		values[name] = ""
		if _, err := loadConfig(getenv); err != errRefused {
			t.Fatalf("missing %s admitted", name)
		}
		values[name] = original
	}
	values["ZASP_APPROVAL_MAINTENANCE_DB_PRINCIPAL"] = values["ZASP_CONNECTOR_MAINTENANCE_DB_PRINCIPAL"]
	if _, err := loadConfig(getenv); err != errRefused {
		t.Fatal("shared purpose principal admitted")
	}
}

func TestRegistrationKeyCustody(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "forward")
	if err := os.WriteFile(path, []byte(strings.Repeat("f", 32)), 0400); err != nil {
		t.Fatal(err)
	}
	seed, err := readSeed(path)
	if err != nil || len(seed) != 32 {
		t.Fatal("owned exact seed refused")
	}
	clear(seed)
	for _, mutation := range []string{"permissions", "length", "symlink", "hardlink", "relative"} {
		t.Run(mutation, func(t *testing.T) {
			name := filepath.Join(root, mutation)
			switch mutation {
			case "permissions":
				_ = os.WriteFile(name, make([]byte, 32), 0600)
			case "length":
				_ = os.WriteFile(name, make([]byte, 33), 0400)
			case "symlink":
				_ = os.Symlink(path, name)
			case "hardlink":
				_ = os.Link(path, name)
			case "relative":
				name = "forward"
			}
			if key, err := readSeed(name); err == nil || len(key) != 0 {
				t.Fatal("unsafe seed admitted")
			}
			if mutation == "hardlink" {
				_ = os.Remove(name)
			}
		})
	}
}

type registrationRow struct {
	ok  bool
	err error
}

func (r registrationRow) Scan(values ...any) error {
	if r.err != nil {
		return r.err
	}
	*(values[0].(*bool)) = r.ok
	return nil
}

type registrationFixture struct {
	calls             []string
	fail              int
	committed, rolled bool
	arguments         [][]any
}

func (f *registrationFixture) record(sql string, args []any) error {
	f.calls = append(f.calls, sql)
	f.arguments = append(f.arguments, args)
	if len(f.calls) == f.fail {
		return errors.New("private database detail")
	}
	return nil
}
func (f *registrationFixture) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, f.record(sql, args)
}
func (f *registrationFixture) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	return registrationRow{ok: true, err: f.record(sql, args)}
}
func (f *registrationFixture) Commit(context.Context) error   { f.committed = true; return nil }
func (f *registrationFixture) Rollback(context.Context) error { f.rolled = true; return nil }

func TestRegistrationTransactionKeepsSeedsBoundAndRollsBack(t *testing.T) {
	c := registrationConfig{connector: "zasp_e2e_outbox", approval: "zasp_e2e_approval_maintenance", connectorPin: strings.Repeat("a", 64), approvalPin: strings.Repeat("b", 64), activationPin: strings.Repeat("c", 64)}
	var keys [4][32]byte
	for i := range keys {
		for j := range keys[i] {
			keys[i][j] = byte(i + 1)
		}
	}
	for fail := 0; fail <= 7; fail++ {
		f := &registrationFixture{fail: fail}
		err := registerKeys(context.Background(), c, f, keys)
		if fail != 0 {
			if err == nil || f.committed || !f.rolled {
				t.Fatalf("failure %d escaped rollback", fail)
			}
			continue
		}
		if err != nil || !f.committed || !f.rolled || len(f.calls) != 7 || f.calls[0] != "SET LOCAL ROLE zasp_discovery_authority" || f.calls[1] != catalogSQL || f.calls[6] != catalogSQL {
			t.Fatal("closed authority/catalog transaction changed")
		}
		if strings.Contains(strings.Join(f.calls, " "), string(keys[0][:])) {
			t.Fatal("seed interpolated into SQL")
		}
		for i, at := range []int{2, 4, 5} {
			if i == 0 {
				if f.arguments[at][0] != c.connector {
					t.Fatal("connector principal changed")
				}
				sum := sha256.Sum256(keys[0][:])
				if f.arguments[at][1] != hex.EncodeToString(sum[:]) {
					t.Fatal("connector key version changed")
				}
			}
		}
	}
}
