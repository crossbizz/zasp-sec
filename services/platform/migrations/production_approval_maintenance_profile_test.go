package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestApprovalMaintenanceSourcePinBindsWholeSupplementaryBody(t *testing.T) {
	cooked, pin := approvalMaintenanceSource()
	h := sha256.Sum256([]byte(approvalMaintenanceSQL))
	if pin != hex.EncodeToString(h[:]) || len(pin) != 64 || strings.Contains(cooked, "-- approval maintenance checksum") || cooked != strings.ReplaceAll(approvalMaintenanceSQL, "-- approval maintenance checksum", pin) {
		t.Fatal("whole source checksum binding refused")
	}
	if strings.Contains(cooked, "CREATE TRIGGER") || strings.Contains(cooked, "CREATE OR REPLACE FUNCTION zasp_authorization79.") || strings.Contains(cooked, "CREATE OR REPLACE VIEW zasp_authorization79.") {
		t.Fatal("supplement changed inherited source")
	}
}
