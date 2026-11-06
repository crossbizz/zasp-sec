package migrations

import "testing"

// Trusted immutable compiler identity/cache behavior; not database or provider proof.
// Added after first implementation as coverage, never claimed as initial RED.
func TestAgentOwnershipWriteCompilerIdentity(t *testing.T) {
	for _, audit := range []bool{false, true} {
		name := "normal"
		if audit {
			name = "audit"
		}
		t.Run(name, func(t *testing.T) {
			source, pin := agentOwnershipWriteProfileSource(audit)
			cached, cachedPin := compiledAgentOwnershipWriteProfileSource(audit)
			expected := AgentOwnershipWriteProfileChecksum()
			if audit {
				expected = AgentOwnershipWriteAuditProfileChecksum()
			}
			if source == "" || source != cached || pin != cachedPin || pin != expected || !IsAgentOwnershipWriteProfileChecksum(pin) {
				t.Fatal("actual compiler and immutable profile identity differ")
			}
			if AgentOwnershipWriteProfileChecksum() == AgentOwnershipWriteAuditProfileChecksum() || IsAgentOwnershipWriteProfileChecksum("") || IsAgentOwnershipWriteProfileChecksum("not-a-profile") {
				t.Fatal("profile variants or closed checksum contract lost")
			}
		})
	}
}
