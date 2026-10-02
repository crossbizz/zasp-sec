package apiserver

import (
	"strings"
	"testing"
)

// These tests catch raw credential disclosure and accidental loss of ordinary
// explanation text at the server's private-to-public rationale boundary.
func TestSecurityAgentRationaleRedactsRecognizedValues(t *testing.T) {
	for _, test := range []struct{ name, input, want string }{
		{"ordinary", "Isolate this session while evidence is reviewed.", "Isolate this session while evidence is reviewed."},
		{"unicode", "Review café access.", "Review café access."},
		{"email", "Contact person@example.invalid before isolation.", "Contact [REDACTED] before isolation."},
		{"ssn", "Evidence contains 123-45-6789.", "Evidence contains [REDACTED]."},
		{"provider tokens", "Rotate ghp_seededtoken and sk-or-v1-seededtoken.", "Rotate [REDACTED] and [REDACTED]."},
		{"assignment", "Remove password=hunter2; review evidence.", "Remove password=[REDACTED]; review evidence."},
		{"quoted assignment", `Remove API_KEY: "secret with spaces"; review.`, "Remove API_KEY: [REDACTED]; review."},
		{"single quoted", "Remove secret='two words'; review.", "Remove secret=[REDACTED]; review."},
		{"escaped quote", `Remove token="secret\"more"; review.`, "Remove token=[REDACTED]; review."},
		{"bearer", "Authorization: Bearer sensitive-value; review.", "Authorization: Bearer [REDACTED]; review."},
		{"basic", "Authorization: Basic dXNlcjpwYXNz; review.", "Authorization: Basic [REDACTED]; review."},
		{"access token", "Remove access_token=seeded; review.", "Remove access_token=[REDACTED]; review."},
		{"secret access key", "Remove secret_access_key=seeded; review.", "Remove secret_access_key=[REDACTED]; review."},
		{"refresh token", "Remove refresh-token=seeded; review.", "Remove refresh-token=[REDACTED]; review."},
		{"url userinfo", "Review https" + "://alice:password@example.invalid/path now.", "Review [REDACTED] now."},
		{"url query", "Review https://example.invalid/path?access_key=seeded&x=1 now.", "Review [REDACTED] now."},
		{"encoded query", "Review https://example.invalid/?%74oken=secret now.", "Review [REDACTED] now."},
		{"url access token", "Review https://example.invalid/?access_token=secret now.", "Review [REDACTED] now."},
		{"ordinary url", "Review https://example.invalid/help now.", "Review https://example.invalid/help now."},
		{"maximum bytes", strings.Repeat("a", 500), strings.Repeat("a", 500)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := sanitizeSecurityAgentRationale(test.input)
			if !ok || got != test.want {
				t.Fatalf("rationale redaction mismatch: accepted=%t", ok)
			}
		})
	}
}

// Marker-only fixtures are constructed explicitly; no private key material is stored.
func TestSecurityAgentRationaleWithholdsUnsafeText(t *testing.T) {
	for _, test := range []struct{ name, input string }{
		{"empty", ""}, {"whitespace", "   "}, {"oversize", strings.Repeat("a", 501)},
		{"utf8 byte bound", strings.Repeat("é", 251)}, {"invalid utf8", string([]byte{0xff})},
		{"newline", "safe\nunsafe"}, {"nul", "safe\x00unsafe"}, {"bidi", "safe\u202eunsafe"},
		{"private key", "-----BEGIN " + "PRIVATE KEY----- seeded"},
		{"rsa key", "-----BEGIN " + "RSA PRIVATE KEY----- seeded"},
		{"unclosed quote", `token="secret with spaces`},
		{"quoted trailing value", `token="secret"unquoted-secret`},
		{"marker trailing value", "token=[REDACTED]unquoted-secret"},
		{"unquoted escape", `password=secret\ with\ spaces`},
		{"empty credential", "password=; review"},
		{"empty bearer", "Authorization: Bearer ; review"},
		{"bad url escape", "Review https://example.invalid/?token=%xx"},
		{"quoted url credential", `Review https` + `://alice:"hunter2"@example.invalid now.`},
		{"angle url credential", "Review https://alice:<hunter2>@example.invalid now."},
		{"single quote url credential", "Review https" + "://alice:'hunter2'@example.invalid now."},
		{"space url credential", "Review https://alice: hunter2 @example.invalid now."},
		{"expansion overflow", strings.Repeat("a", 490) + " sk-x"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := sanitizeSecurityAgentRationale(test.input)
			if ok || got != "" {
				t.Fatal("unsafe rationale was not completely withheld")
			}
		})
	}
}
