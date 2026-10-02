package apiserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const ordered69PredecessorArtifactSHA = "794b6c269b2e2f81fae2fbbc54f52773e0adb5187156eed19f522e5297539216"
const ordered69PredecessorSourceSHA = "50d1c3065ed09da35d810890421e22094ccce5cbd9e290b18e71bcc3d7101d1a"

// New explicit test only; no shared producer edits/default path changes. The
// frozen predecessor producer builds real settled artifacts before this hook.
func TestP7Ordered69PredecessorCatalogCapture(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") == "" {
		t.Skip("explicit predecessor catalog capture required")
	}
	if os.Getenv("ZASP_ORDERED_PREDECESSOR_CAPTURE") != "1" {
		t.Fatal("invalid predecessor capture mode")
	}
	artifact, destination := os.Getenv("ZASP_ORDERED_PREDECESSOR_RELEASE"), os.Getenv("ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT")
	if !filepath.IsAbs(artifact) || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		t.Fatal("explicit predecessor artifact/output required")
	}
	if err := readWorkerPredecessorArtifact(artifact); err != nil {
		t.Fatal("frozen predecessor artifact refused")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("new predecessor output required")
	}
	consumed := false
	runOrderedActualRunnerWithSettledConsumer(t, "", func(c ordered68ApprovedTestContext, directory string) {
		assertOrdered69SettledRecovery(c, directory)
		if t.Failed() {
			return
		}
		captureOrdered69PredecessorCatalog(t, c.ctx, c.owner, destination)
		consumed = true
	})
	if !consumed {
		t.Fatal("predecessor capture consumer not reached")
	}
	t.Log("local-reference predecessor compiler artifactSHA256", ordered69PredecessorArtifactSHA, "sourceSHA256", ordered69PredecessorSourceSHA, "approved-deployed", false)
}

func readWorkerPredecessorArtifact(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.New("artifact unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
		return errors.New("artifact invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 {
		return errors.New("artifact invalid")
	}
	return verifyWorkerPredecessorArtifact(raw)
}

func verifyWorkerPredecessorArtifact(raw []byte) error {
	bad := errors.New("artifact invalid")
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != ordered69PredecessorArtifactSHA {
		return bad
	}
	var fields map[string]string
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 5 || fields["format"] != "zasp-worker-compiled-release-v1" || fields["profile"] != "canonical61-temporal78-authorization79-80-worker-v1" || fields["checksum"] != ordered69PredecessorCompiledChecksum || fields["source_sha256"] != ordered69PredecessorSourceSHA {
		return bad
	}
	source := sha256.Sum256([]byte(fields["source"]))
	if hex.EncodeToString(source[:]) != ordered69PredecessorSourceSHA {
		return bad
	}
	return nil
}

func TestWorkerUpgradePredecessorArtifactBinding(t *testing.T) {
	artifact := os.Getenv("ZASP_ORDERED_PREDECESSOR_RELEASE")
	if artifact == "" {
		t.Skip("explicit frozen reference required")
	}
	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal("reference unavailable")
	}
	if verifyWorkerPredecessorArtifact(raw) != nil {
		t.Fatal("reviewed compiler reference refused")
	}
	for _, value := range [][]byte{[]byte(`{}`), append(append([]byte{}, raw...), ' '), []byte(`{"checksum":"` + ordered69PredecessorCompiledChecksum + `","source":"private"}`)} {
		if verifyWorkerPredecessorArtifact(value) == nil {
			t.Fatal("unbound compiler artifact accepted")
		}
	}
}
