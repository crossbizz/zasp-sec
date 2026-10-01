package apiserver

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestAPITokenRevealAcceptsEquivalentExpiryInstants(t *testing.T) {
	for _, operation := range []string{"createAPIToken", "rotateAPIToken"} {
		t.Run(operation, func(t *testing.T) {
			identity, key, envelope, raw := encryptedRevealFixture(t, operation)
			for _, test := range []struct{ name, expires string }{
				{"UTC control", "2026-09-18T04:46:03Z"},
				{"Postgres UTC offset", "2026-09-18T04:46:03+00:00"},
				{"positive offset", "2026-09-18T06:16:03+01:30"},
				{"negative offset", "2026-09-17T21:46:03-07:00"},
				{"trailing zero fraction", "2026-09-18T04:46:03.000000+00:00"},
			} {
				t.Run(test.name, func(t *testing.T) {
					candidate := envelope
					candidate.ExpiresAt = test.expires
					got, err := decryptAPITokenReveal(key, identity, candidate)
					if err != nil || got != raw {
						t.Fatal("equivalent expiry did not recover the original credential")
					}
				})
			}
		})
	}
}

func TestAPITokenRevealRejectsChangedBindingsAndMalformedEnvelope(t *testing.T) {
	for _, operation := range []string{"createAPIToken", "rotateAPIToken"} {
		t.Run(operation, func(t *testing.T) {
			identity, key, envelope, _ := encryptedRevealFixture(t, operation)
			for _, test := range []struct{ name, expires string }{
				{"changed second", "2026-09-18T04:46:04Z"},
				{"changed nanosecond", "2026-09-18T04:46:03.000000001Z"},
				{"invalid timestamp", "not-a-timestamp"},
				{"missing timezone", "2026-09-18T04:46:03"},
				{"single digit hour", "2026-09-18T4:46:03Z"},
				{"comma fraction", "2026-09-18T04:46:03,000Z"},
				{"offset hour overflow", "2026-09-19T04:46:03+24:00"},
				{"offset minute overflow", "2026-09-18T05:46:03+00:60"},
				{"subnanosecond alteration", "2026-09-18T04:46:03.0000000001Z"},
			} {
				t.Run(test.name, func(t *testing.T) {
					candidate := envelope
					candidate.ExpiresAt = test.expires
					assertRevealRefused(t, key, identity, candidate)
				})
			}
			for _, field := range []string{"organization", "workspace", "environment", "principal"} {
				t.Run("wrong "+field, func(t *testing.T) {
					candidate := identity
					foreign, err := domain.ParseProductID("pid_20000001-0000-4000-8000-000000000001")
					if err != nil {
						t.Fatal("invalid identity fixture")
					}
					organization, workspace, environment := identity.Scope.OrganizationID(), identity.Scope.WorkspaceID(), identity.Scope.EnvironmentID()
					switch field {
					case "organization":
						organization = foreign
					case "workspace":
						workspace = foreign
					case "environment":
						environment = foreign
					case "principal":
						candidate.PrincipalID = foreign
					}
					candidate.Scope, err = domain.NewScope(organization, workspace, environment)
					if err != nil {
						t.Fatal("invalid scope fixture")
					}
					assertRevealRefused(t, key, candidate, envelope)
				})
			}
			t.Run("wrong key", func(t *testing.T) {
				assertRevealRefused(t, bytes.Repeat([]byte{0x62}, 32), identity, envelope)
			})
			t.Run("altered tag", func(t *testing.T) {
				candidate := envelope
				tag, err := base64.RawURLEncoding.DecodeString(candidate.AuthenticationTag)
				if err != nil {
					t.Fatal("invalid encrypted fixture")
				}
				tag[0] ^= 1
				candidate.AuthenticationTag = base64.RawURLEncoding.EncodeToString(tag)
				assertRevealRefused(t, key, identity, candidate)
			})
			for _, field := range []string{"ciphertext", "nonce", "tag"} {
				t.Run("noncanonical "+field, func(t *testing.T) {
					candidate := envelope
					switch field {
					case "ciphertext":
						candidate.Ciphertext += "\n"
					case "nonce":
						candidate.Nonce += "\n"
					case "tag":
						candidate.AuthenticationTag += "\n"
					}
					assertRevealRefused(t, key, identity, candidate)
				})
			}
		})
	}
}

func encryptedRevealFixture(t *testing.T, operation string) (RequestIdentity, []byte, apiTokenRevealEnvelope, string) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	key := bytes.Repeat([]byte{0x61}, 32)
	raw := "zasp_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	mutation := administrationMutation{
		ID: "pid_11000005-0000-4000-8000-000000000005", ReplacementID: "pid_11000007-0000-4000-8000-000000000007",
		GrantID: "pid_41000003-0000-4000-8000-000000000003", revealKey: key,
	}
	if err := prepareAPITokenReveal(identity, &mutation, operation, raw, time.Date(2026, 9, 18, 4, 36, 3, 0, time.UTC)); err != nil {
		t.Fatal("could not encrypt reveal fixture")
	}
	tokenID := mutation.ID
	if operation == "rotateAPIToken" {
		tokenID = mutation.ReplacementID
	}
	return identity, key, apiTokenRevealEnvelope{
		GrantID: mutation.GrantID, TokenID: tokenID, Operation: operation, ExpiresAt: "2026-09-18T04:46:03Z",
		Ciphertext: base64.RawURLEncoding.EncodeToString(mutation.Ciphertext), Nonce: base64.RawURLEncoding.EncodeToString(mutation.Nonce), AuthenticationTag: base64.RawURLEncoding.EncodeToString(mutation.AuthenticationTag),
	}, raw
}

func assertRevealRefused(t *testing.T, key []byte, identity RequestIdentity, envelope apiTokenRevealEnvelope) {
	t.Helper()
	got, err := decryptAPITokenReveal(key, identity, envelope)
	if !errors.Is(err, ErrRepositoryNotFound) || got != "" {
		t.Fatal("invalid reveal did not fail closed")
	}
}
