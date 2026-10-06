package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAuditWorkerSuccessorPreservesLegacyCompiledBytes(t *testing.T) {
	legacy, checksum := authorizationWorkerProfileSource()
	digest := sha256.Sum256([]byte(legacy))
	if checksum != "5b129ed0592dde0af626a47bb656a572e009c1cefa182293429a454727af7bf9" || hex.EncodeToString(digest[:]) != "233c2caf66299ad50ee1a573c116746c905a885612a72980b6ce41c916a68850" {
		t.Fatal("original independently exported worker source changed")
	}
	source, next := authorizationWorkerAuditProfileSource()
	if next == checksum || strings.Count(source, "DO $audit_worker_boundary$") != 1 || strings.Count(source, "DO $higher_readiness$") != 1 || strings.Count(source, "DO $readiness_graph$") != 1 {
		t.Fatal("distinct audit recipe missing")
	}
	if strings.Contains(legacy, "DO $audit_worker_boundary$") || strings.Contains(legacy, AuthorizationWorkerAuditProfileName) {
		t.Fatal("audit successor leaked into original recipe")
	}
	if strings.Index(source, "END $owners$;") < 0 || strings.Index(source, "DO $audit_worker_boundary$") < strings.Index(source, "END $owners$;") {
		t.Fatal("boundary verification precedes final ownership")
	}
	if strings.Contains(source, "-- worker profile checksum") || strings.Contains(source, "-- worker catalog body digest") {
		t.Fatal("unbound composed installer identity")
	}
}
