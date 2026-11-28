package identity

import "testing"

func TestCanonicalMemberEmail(t *testing.T) {
	for _, input := range []string{"a@example.com", " A@Example.COM "} {
		if email, ok := CanonicalMemberEmail(input); !ok || email != "a@example.com" {
			t.Fatalf("email %q = %q, valid %t", input, email, ok)
		}
	}
	for _, input := range []string{"", "Jordan <jordan@example.com>", "jane@example.com,john@example.com", "not an address", "a@bad-.org", "a\r\nx@example.com"} {
		if _, ok := CanonicalMemberEmail(input); ok {
			t.Fatalf("accepted invalid mailbox %q", input)
		}
	}
}
