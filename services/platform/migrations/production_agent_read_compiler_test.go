package migrations

import "testing"

// Compiler identity/cache behavior only, never native installation or current authorization proof.
func TestAgentReadCompilerIdentity(t *testing.T) {
	for _, audit := range []bool{false, true} {
		name := "normal"
		if audit {
			name = "audit"
		}
		t.Run(name, func(t *testing.T) {
			source, pin := agentReadProfileSource(audit)
			cached, cachedPin := compiledAgentReadProfileSource(audit)
			expected := AgentReadProfileChecksum()
			if audit {
				expected = AgentReadAuditProfileChecksum()
			}
			if source == "" || source != cached || pin != cachedPin || pin != expected || !IsAgentReadProfileChecksum(pin) {
				t.Fatal("actual compiler and immutable profile identity differ")
			}
			if AgentReadProfileChecksum() == AgentReadAuditProfileChecksum() || IsAgentReadProfileChecksum("") || IsAgentReadProfileChecksum("not-a-profile") {
				t.Fatal("profile variants or closed pin contract lost")
			}
		})
	}
}
