package migrations

import "testing"

// Trusted immutable compiler identity/cache behavior; not database or provider proof.
// Added after first implementation as coverage, never claimed as initial RED.
func TestAgentExposureFilterCompilerIdentity(t *testing.T) {
	for _, audit := range []bool{false, true} {
		name := "normal"
		if audit {
			name = "audit"
		}
		t.Run(name, func(t *testing.T) {
			source, pin := agentExposureFilterProfileSource(audit)
			cached, cachedPin := compiledAgentExposureProfileSource(audit)
			expected := AgentExposureFilterProfileChecksum()
			if audit {
				expected = AgentExposureFilterAuditProfileChecksum()
			}
			if source == "" || source != cached || pin != cachedPin || pin != expected || !IsAgentExposureFilterProfileChecksum(pin) {
				t.Fatal("actual compiler and immutable profile identity differ")
			}
			if AgentExposureFilterProfileChecksum() == AgentExposureFilterAuditProfileChecksum() || IsAgentExposureFilterProfileChecksum("") || IsAgentExposureFilterProfileChecksum("not-a-profile") {
				t.Fatal("profile variants or closed checksum contract lost")
			}
		})
	}
}
