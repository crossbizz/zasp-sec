package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type workerReleaseArtifact struct {
	Format       string `json:"format"`
	Profile      string `json:"profile"`
	Checksum     string `json:"checksum"`
	SourceSHA256 string `json:"source_sha256"`
	Source       string `json:"source"`
}

func writeWorkerReleaseArtifact(destination, source, checksum string) error {
	if !filepath.IsAbs(destination) || len(source) == 0 || len(source) > 64*1024*1024 || len(checksum) != 64 || strings.IndexFunc(checksum, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) >= 0 {
		return errors.New("invalid static release artifact")
	}
	digest := sha256.Sum256([]byte(source))
	raw, err := json.Marshal(workerReleaseArtifact{"zasp-worker-compiled-release-v1", AuthorizationWorkerProfileName, checksum, hex.EncodeToString(digest[:]), source})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(raw, '\n'))
	return errors.Join(writeErr, f.Close())
}

func TestWorkerReleaseArtifactFormatPrivacy(t *testing.T) {
	file := filepath.Join(t.TempDir(), "release.json")
	t.Setenv("OPENAI_API_KEY", "secret-must-not-be-exported")
	const source = "SELECT 1;\n"
	checksum := strings.Repeat("a", 64)
	if err := writeWorkerReleaseArtifact(file, source, checksum); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("release artifact missing", err)
	}
	var got workerReleaseArtifact
	if json.Unmarshal(raw, &got) != nil || got.Format != "zasp-worker-compiled-release-v1" || got.Profile != AuthorizationWorkerProfileName || got.Checksum != checksum || got.Source != source || got.SourceSHA256 != "b4e0497804e46e0a0b0b8c31975b062152d551bac49c3c2e80932567b4085dcd" {
		t.Fatal("release artifact identity/bytes mismatch")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 5 || strings.Contains(string(raw), "secret-must-not-be-exported") {
		t.Fatal("release artifact fields leaked")
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("release artifact permissions")
	}
	if err := writeWorkerReleaseArtifact(file, "changed", checksum); !errors.Is(err, os.ErrExist) {
		t.Fatal("release artifact overwrite allowed")
	}
	second, _ := os.ReadFile(file)
	if string(second) != string(raw) {
		t.Fatal("release artifact changed on rejected overwrite")
	}
	for _, bad := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), "secret"} {
		p := filepath.Join(t.TempDir(), "invalid.json")
		if writeWorkerReleaseArtifact(p, source, bad) == nil {
			t.Fatal("invalid identity exported")
		}
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid export left file")
		}
	}
}

// Invoke only with a frozen source snapshot and an explicit new output file.
// This calls the real compiler; no database registration is consulted.
func TestExportWorkerCompiledRelease(t *testing.T) {
	destination := os.Getenv("ZASP_WORKER_RELEASE_OUTPUT")
	if destination == "" {
		t.Skip("explicit compiled release destination required")
	}
	source, checksum := authorizationWorkerProfileSource()
	if err := writeWorkerReleaseArtifact(destination, source, checksum); err != nil {
		t.Fatal("compiled release export refused")
	}
	digest := sha256.Sum256([]byte(source))
	t.Log("independently compiled worker checksum", checksum, "source_sha256", hex.EncodeToString(digest[:]), "source_bytes", len(source))
}
