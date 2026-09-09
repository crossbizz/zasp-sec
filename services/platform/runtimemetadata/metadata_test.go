package runtimemetadata

import (
	"strings"
	"testing"
)

func TestSelectorsMinimizeContentWithoutInventingAuthority(t *testing.T) {
	process, err := DigestSelector("process", "/usr/bin/agent")
	if err != nil || len(process) != 64 || strings.Contains(process, "agent") {
		t.Fatal("invalid process digest")
	}
	same, _ := DigestSelector("process", "/usr/bin/agent")
	different, _ := DigestSelector("file", "/usr/bin/agent")
	if process != same || process == different {
		t.Fatal("selector digest is not deterministic and domain separated")
	}
	lower, _ := DigestSelector("domain", "api.example.com")
	upper, _ := DigestSelector("domain", "API.EXAMPLE.COM")
	if lower != upper {
		t.Fatal("DNS selector did not canonicalize case")
	}
	valid := Fields{PrincipalID: "pid_10000001-0000-4000-8000-000000000001", ProcessDigest: process, FileDigest: different, DomainDigest: lower, CredentialID: "pid_10000002-0000-4000-8000-000000000002", ResourceDigest: process, Decision: "block"}
	if !valid.Valid("otlp") || valid.Valid("tetragon") {
		t.Fatal("semantic and kernel metadata authority conflated")
	}
	for _, field := range []Fields{
		{PrincipalID: "member-1"}, {CredentialID: "raw-secret"}, {Decision: "permit"},
		{ProcessDigest: strings.Repeat("A", 64)}, {FileDigest: strings.Repeat("a", 63)}, {DomainDigest: strings.Repeat("g", 64)}, {ResourceDigest: "https://api.example.com"},
	} {
		if field.Valid("otlp") {
			t.Fatalf("invalid metadata accepted: %#v", field)
		}
	}
	for _, source := range []string{"", "gateway", "unknown"} {
		if (Fields{}).Valid(source) {
			t.Fatal("unsupported metadata source accepted")
		}
	}
}

func TestSelectorInputsRejectUnsupportedFieldsAndNoncanonicalValues(t *testing.T) {
	for _, input := range []struct{ field, value string }{
		{"credential", "provider-secret"}, {"raw_query", "*:*"}, {"process", ""}, {"file", "/tmp/file\n"},
		{"resource", " token "}, {"file", strings.Repeat("a", 4097)}, {"process", string([]byte{0xff})},
		{"domain", "api.example.com."}, {"domain", "-bad.example.com"}, {"domain", "a..example.com"},
		{"domain", "https://example.com"}, {"domain", "*.example.com"}, {"domain", strings.Repeat("a", 64) + ".com"},
	} {
		if _, err := DigestSelector(input.field, input.value); err == nil {
			t.Fatalf("invalid selector accepted: %q %q", input.field, input.value)
		}
	}
}
