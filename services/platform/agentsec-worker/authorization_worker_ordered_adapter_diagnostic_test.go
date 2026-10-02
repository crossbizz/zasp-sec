package main

import (
	"regexp"
	"strings"
	"testing"
)

func orderedAdapterStartupDiagnostic(output []byte) string {
	frame := regexp.MustCompile(`^\s*ordered_runner_server_test\.go:[0-9]+: `)
	labels := []struct{ prefix, phase string }{
		{"owned FGA pins required", "fga-pins"},
		{"unknown controlled customer boundary", "customer-mode"},
		{"owned adapter coordinates required", "coordinates"},
		{"owned loopback database required", "database-address"},
		{"foreign database fallback", "database-fallback"},
		{"owned pool", "database-pool"},
		{"actual registered adapter login", "adapter-login"},
		{"owned FGA service unavailable", "fga-service"},
		{"owned FGA service identity", "fga-service-identity"},
		{"owned FGA credential missing", "fga-credential"},
		{"actual Ordered journal readiness", "journal-ready"},
		{"actual adapter send/credential cardinality", "send-cardinality"},
	}
	for _, line := range strings.Split(string(output), "\n") {
		match := frame.FindStringIndex(line)
		if match == nil {
			continue
		}
		for _, label := range labels {
			if strings.HasPrefix(line[match[1]:], label.prefix) {
				return label.phase
			}
		}
	}
	return "unknown"
}

// Only static fixture labels may cross the adapter-child failure boundary.
// In particular, never relay its error suffix, raw output, DSN or credentials.
func TestOrderedAdapterStartupDiagnostic(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"    ordered_runner_server_test.go:71: owned FGA pins required\n", "fga-pins"},
		{"    ordered_runner_server_test.go:153: actual Ordered journal readiness secret=must-not-escape\n", "journal-ready"},
		{"    ordered_runner_server_test.go:101: actual registered adapter login postgres://secret\n", "adapter-login"},
		{"    ordered_runner_server_test.go:280: actual adapter send/credential cardinality 0 0\n", "send-cardinality"},
		{"panic: untrusted exception including secret\n", "unknown"},
		{"owned FGA service unavailable without a test source frame", "unknown"},
	} {
		if got := orderedAdapterStartupDiagnostic([]byte(tc.input)); got != tc.want || strings.Contains(got, "secret") {
			t.Fatal("unsafe or missing startup classification", got, tc.want)
		}
	}
}
