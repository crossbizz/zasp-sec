package migrations

import "testing"

// Late immutable compiler identity coverage, not SQL/token/native acceptance.
// The actual absent-installer RED is retained separately without this test.
func TestSensorNodeCoverageCompilerIdentity(t *testing.T) {
	for _, audit := range []bool{false, true} {
		name := "normal"
		if audit {
			name = "audit"
		}
		t.Run(name, func(t *testing.T) {
			source, pin := sensorNodeCoverageProfileSource(audit)
			cached, cachedPin := compiledSensorNodeCoverageSource(audit)
			expected := SensorNodeCoverageProfileChecksum()
			if audit {
				expected = SensorNodeCoverageAuditProfileChecksum()
			}
			if source == "" || source != cached || pin != cachedPin || pin != expected || !IsSensorNodeCoverageProfileChecksum(pin) {
				t.Fatal("immutable sensor coverage compiler identity mismatch")
			}
			if SensorNodeCoverageProfileChecksum() == SensorNodeCoverageAuditProfileChecksum() || IsSensorNodeCoverageProfileChecksum("") || IsSensorNodeCoverageProfileChecksum("not-a-profile") {
				t.Fatal("compiled Normal/Audit identity contract lost")
			}
		})
	}
}
