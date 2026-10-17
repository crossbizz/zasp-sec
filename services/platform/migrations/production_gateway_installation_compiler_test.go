package migrations

import "testing"

// Late immutable compiler identity coverage, not SQL/credential/native acceptance.
// The actual absent-installer RED is retained separately without this test.
func TestGatewayInstallationCompilerIdentity(t *testing.T) {
	for _, audit := range []bool{false, true} {
		name := "normal"
		if audit {
			name = "audit"
		}
		t.Run(name, func(t *testing.T) {
			source, pin := gatewayInstallationProfileSource(audit)
			cached, cachedPin := compiledGatewayInstallationSource(audit)
			expected := GatewayInstallationProfileChecksum()
			if audit {
				expected = GatewayInstallationAuditProfileChecksum()
			}
			if source == "" || source != cached || pin != cachedPin || pin != expected || !IsGatewayInstallationProfileChecksum(pin) {
				t.Fatal("immutable gateway installation compiler identity mismatch")
			}
			if GatewayInstallationProfileChecksum() == GatewayInstallationAuditProfileChecksum() || IsGatewayInstallationProfileChecksum("") || IsGatewayInstallationProfileChecksum("not-a-profile") {
				t.Fatal("compiled Normal/Audit identity contract lost")
			}
		})
	}
}
