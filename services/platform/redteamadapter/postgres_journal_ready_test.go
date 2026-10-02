package redteamadapter

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestPostgresJournalReadyRequiresPinnedReleaseAndAdapter(t *testing.T) {
	const release = `SELECT to_jsonb(zasp_production_security_agent_existing_tests_client_ready($1,$2))`
	const principal = `SELECT to_jsonb(zasp_red_team_principal_ready($1))`
	for _, tc := range []struct {
		name, release, principal string
		fail                     bool
	}{
		{"ready", "true", "true", false},
		{"release drift", "false", "true", true},
		{"wrong principal", "true", "false", true},
		{"null", "null", "true", true},
		{"trailing", "true false", "true", true},
		{"string", `"true"`, "true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &jsonDatabaseStub{responses: map[string]json.RawMessage{release: json.RawMessage(tc.release), principal: json.RawMessage(tc.principal)}}
			j, err := NewPostgresInvocationJournal(db, strings.Repeat("d", 64), strings.Repeat("e", 64))
			if err != nil {
				t.Fatal(err)
			}
			if err := j.Ready(context.Background()); (err != nil) != tc.fail {
				t.Fatalf("ready=%v", err)
			}
			if !reflect.DeepEqual(db.arguments[0], []any{strings.Repeat("d", 64), strings.Repeat("e", 64)}) {
				t.Fatal("release pins missing")
			}
			if tc.release == "true" && !reflect.DeepEqual(db.arguments[1], []any{"zasp_red_team_adapter"}) {
				t.Fatal("adapter identity missing")
			}
			db.err = errors.New("secret database error")
			if err := j.Ready(context.Background()); err != ErrAdapter {
				t.Fatalf("unsanitized failure: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			before := len(db.statements)
			if j.Ready(ctx) == nil || j.Ready(nil) == nil || len(db.statements) != before {
				t.Fatal("invalid context reached database")
			}
		})
	}
	var absent *PostgresInvocationJournal
	if absent.Ready(context.Background()) == nil {
		t.Fatal("nil journal ready")
	}
}

type nilJournalDatabase struct{}

func (*nilJournalDatabase) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return nil, errors.New("must not be called")
}

func TestPostgresJournalConfigurationIsExactAndZeroIO(t *testing.T) {
	checksum, fingerprint := migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()
	database := &jsonDatabaseStub{}
	base, err := NewPostgresInvocationJournal(database, checksum, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if base.ValidOrderedConfiguration(checksum, fingerprint) {
		t.Fatal("base journal accepted as ordered")
	}
	journal, err := base.ordered()
	if err != nil {
		t.Fatal(err)
	}
	if !journal.ValidOrderedConfiguration(checksum, fingerprint) || len(database.statements) != 0 {
		t.Fatal("exact configuration was not accepted without I/O")
	}
	for name, pins := range map[string][2]string{
		"stale checksum":    {strings.Repeat("a", 64), fingerprint},
		"stale fingerprint": {checksum, strings.Repeat("b", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			if journal.ValidOrderedConfiguration(pins[0], pins[1]) || len(database.statements) != 0 {
				t.Fatal("stale release configuration accepted or performed I/O")
			}
		})
	}
	var absent *PostgresInvocationJournal
	if absent.ValidOrderedConfiguration(checksum, fingerprint) {
		t.Fatal("typed nil journal accepted")
	}
	if (&PostgresInvocationJournal{}).ValidOrderedConfiguration(checksum, fingerprint) {
		t.Fatal("zero-value journal accepted")
	}
	var typedNil *nilJournalDatabase
	if _, err := NewPostgresInvocationJournal(typedNil, checksum, fingerprint); err == nil {
		t.Fatal("typed nil database accepted")
	}
}
