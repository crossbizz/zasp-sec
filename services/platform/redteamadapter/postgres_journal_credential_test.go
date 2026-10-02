package redteamadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPostgresJournalRequiresCredentialVersionBeforeCompletion(t *testing.T) {
	r := journalRequestFixture(t)
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("0", 64)} {
		db := &jsonDatabaseStub{responses: map[string]json.RawMessage{postgresJournalCompleteSQL: journalReceiptFixture(r, true)}}
		j, _ := NewPostgresInvocationJournal(db, strings.Repeat("d", 64), strings.Repeat("e", 64))
		protected := false
		observation := InvocationObservation{HTTPStatus: 200, ResponseDigest: strings.Repeat("c", 64), Protected: &protected, CredentialVersionDigest: digest}
		if j.Complete(context.Background(), r, 1, observation) == nil || len(db.statements) != 0 {
			t.Fatalf("invalid version reached completion: %q", digest)
		}
	}
}

func TestPostgresJournalRejectsMissingOrSubstitutedCredentialReceipt(t *testing.T) {
	r := journalRequestFixture(t)
	valid := string(journalReceiptFixture(r, true))
	field := `"credential_version_digest":"` + strings.Repeat("d", 64) + `"`
	for name, body := range map[string]string{
		"missing":      strings.Replace(valid, field+",", "", 1),
		"null":         strings.Replace(valid, field, `"credential_version_digest":null`, 1),
		"zero":         strings.Replace(valid, field, `"credential_version_digest":"`+strings.Repeat("0", 64)+`"`, 1),
		"duplicate":    strings.Replace(valid, field, field+","+field, 1),
		"alias":        strings.Replace(valid, "credential_version_digest", "Credential_version_digest", 1),
		"substitution": strings.Replace(valid, field, `"credential_version_digest":"`+strings.Repeat("e", 64)+`"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			db := &jsonDatabaseStub{responses: map[string]json.RawMessage{postgresJournalCompleteSQL: json.RawMessage(body)}}
			j, _ := NewPostgresInvocationJournal(db, strings.Repeat("d", 64), strings.Repeat("e", 64))
			protected := false
			if j.Complete(context.Background(), r, 1, InvocationObservation{HTTPStatus: 200, ResponseDigest: strings.Repeat("c", 64), Protected: &protected, CredentialVersionDigest: strings.Repeat("d", 64)}) == nil {
				t.Fatal("unbound credential receipt accepted")
			}
		})
	}
}
