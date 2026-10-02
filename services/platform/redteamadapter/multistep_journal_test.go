package redteamadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestOrderedJournalPrivateBoundary(t *testing.T) {
	r := journalRequestFixture(t)
	const start = `SELECT zasp_sa_multistep_prior.test_invocation_start($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	const complete = `SELECT zasp_sa_multistep_prior.test_invocation_complete($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	for _, mode := range []string{"exact", "wrong_release", "extra", "null", "duplicate", "version", "comparison", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			body := string(journalReceiptFixture(r, false))
			switch mode {
			case "extra":
				body = strings.TrimSuffix(body, "}") + `,"public_route":true}`
			case "null":
				body = "null"
			case "duplicate":
				body = strings.Replace(body, `"attempt":1`, `"attempt":1,"attempt":1`, 1)
			case "version":
				body = strings.Replace(body, `"version":7`, `"version":0`, 1)
			case "comparison":
				body = strings.Replace(body, `"test_definition_version":1`, `"test_definition_version":0`, 1)
			case "oversized":
				body += strings.Repeat(" ", 16384)
			}
			db := &jsonDatabaseStub{responses: map[string]json.RawMessage{start: []byte(body), complete: journalReceiptFixture(r, true)}}
			checksum := migrations.ProductionSecurityAgentMultistep().Checksum()
			if mode == "wrong_release" {
				checksum = strings.Repeat("a", 64)
			}
			base, _ := NewPostgresInvocationJournal(db, checksum, migrations.SecurityAgentMultistepRegisteredFingerprint())
			boundary, ok := any(base).(interface {
				ordered() (*PostgresInvocationJournal, error)
			})
			if !ok {
				t.Fatal("private ordered invocation client absent")
			}
			client, err := boundary.ordered()
			if mode == "wrong_release" {
				if err == nil || len(db.statements) != 0 {
					t.Fatal("unregistered pins admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.Start(context.Background(), r)
			if mode != "exact" {
				if err == nil {
					t.Fatal("malformed ordered journal accepted", mode, got)
				}
				return
			}
			protected := false
			if err != nil || got.State != "started" || client.Complete(context.Background(), r, 1, InvocationObservation{HTTPStatus: 200, ResponseDigest: strings.Repeat("c", 64), Protected: &protected, CredentialVersionDigest: strings.Repeat("d", 64)}) != nil {
				t.Fatal("exact private journal refused", got, err)
			}
			if len(db.statements) != 2 || db.statements[0] != start || db.statements[1] != complete {
				t.Fatal("ordered call reached historical entrypoint", db.statements)
			}
		})
	}
}
