package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOrderedCheckpointKeepsHistoricalIdentitiesSeparate(t *testing.T) {
	if orderedCurrentDevelopmentManifestFileSHA256 != "f78003bb5827232f7f603da7490d1fd840818e5c62c18c3b3f85588fcda6b4cd" || orderedCurrentDevelopmentModuleFileSHA256 != "921fe1a2c6fc30e4d66c9ad0b2455376b5bb1afc001ee40bcef35665cfa02208" {
		t.Fatal("historical pin changed")
	}
	if _, err := decodeOrderedCurrentDevelopment(authorizationWorkerOrderedCurrentManifest); err == nil || !strings.Contains(err.Error(), "file identity changed") {
		t.Fatal("historical decoder accepted checkpoint bytes")
	}
	if err := admitOrderedCurrentPrivate([]byte("[]")); err == nil || !strings.Contains(err.Error(), "file identity changed") {
		t.Fatal("historical private admission accepted checkpoint")
	}
	if source, err := authorizationWorkerOrderedCurrentSource(); source != "" || err == nil {
		t.Fatal("historical installation refusal changed")
	}
	digest := sha256.Sum256([]byte(authorizationWorkerOrderedCurrentModule))
	if hex.EncodeToString(digest[:]) == orderedCurrentDevelopmentModuleFileSHA256 {
		t.Fatal("checkpoint module represented as historical identity")
	}
	if err := checkOrderedCheckpointDevelopmentModule(authorizationWorkerOrderedCurrentModule); err != nil {
		t.Fatal(err)
	}
	if err := checkOrderedCheckpointDevelopmentModule(authorizationWorkerOrderedCurrentModule + "\n"); err == nil {
		t.Fatal("changed checkpoint module admitted")
	}
	if _, err := decodeOrderedCheckpointDevelopment(append(append([]byte(nil), authorizationWorkerOrderedCurrentManifest...), '\n')); err == nil {
		t.Fatal("changed checkpoint manifest admitted")
	}
	if source, err := authorizationWorkerOrderedCheckpointSource(); source != "" || err == nil || !strings.Contains(err.Error(), "not installable") {
		t.Fatal("checkpoint became installable")
	}
}
