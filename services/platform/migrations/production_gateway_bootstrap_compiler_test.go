package migrations

import "testing"

// Late immutable compiler identity coverage, not SQL/credential/native acceptance.
// The actual absent-installer RED is retained separately without this test.
func TestGatewayBootstrapCompilerIdentity(t *testing.T) {
	for _, audit := range []bool{false, true} {
		name := "normal"
		if audit {
			name = "audit"
		}
		t.Run(name, func(t *testing.T) {
			source, pin := gatewayBootstrapProfileSource(audit)
			cached, cachedPin := compiledGatewayBootstrapSource(audit)
			expected := GatewayBootstrapProfileChecksum()
			if audit {
				expected = GatewayBootstrapAuditProfileChecksum()
			}
			if source == "" || source != cached || pin != cachedPin || pin != expected || !IsGatewayBootstrapProfileChecksum(pin) {
				t.Fatal("immutable gateway bootstrap compiler identity mismatch")
			}
			if GatewayBootstrapProfileChecksum() == GatewayBootstrapAuditProfileChecksum() || IsGatewayBootstrapProfileChecksum("") || IsGatewayBootstrapProfileChecksum("not-a-profile") {
				t.Fatal("compiled Normal/Audit identity contract lost")
			}
		})
	}
}
