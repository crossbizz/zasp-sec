package authorization

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Public synthetic fixture, not a production credential. Vectors were checked
// independently with HMAC and explicit SHA256 ipad/opad; no implementation is
// imported into the tests to compute the expected derived key.
const currentSyntheticSeed = "0123456789abcdef0123456789abcdef"

var currentKeyVectors = []struct {
	purpose           ComplianceCurrentPurpose
	verifier, version string
}{
	{ComplianceCurrentExecution, "973c55425b762ac63655ea046def9f727bf3949a5d04d385194f26800e533c96", "ac23efa46f80d01c19862b8063c035c234bb2abe68661bfb9432c291e137c681"},
	{ComplianceCurrentCleanup, "02879bc36d920c91d5389461e484da4dfb056dff232e34d19cebe2be5560d08b", "0f7021f915b6c65968912f1a764c789da863c74c3926d165fc56fe84cde635b7"},
}

func currentKeyFixture(t *testing.T, purpose ComplianceCurrentPurpose) *ComplianceCurrentKey {
	t.Helper()
	k, err := NewComplianceCurrentKey(purpose, []byte(currentSyntheticSeed))
	if err != nil || k == nil {
		t.Fatalf("valid current purpose/seed refused: error=%v", err)
	}
	return k
}
func TestComplianceCurrentKeyLiteralVectors(t *testing.T) {
	for _, v := range currentKeyVectors {
		t.Run(string(v.purpose), func(t *testing.T) {
			k := currentKeyFixture(t, v.purpose)
			if got := hex.EncodeToString(k.Verifier()); got != v.verifier {
				t.Fatalf("derived verifier differs from literal vector: %s", got)
			}
			if k.Version() != v.version {
				t.Fatalf("key version differs from literal vector: %s", k.Version())
			}
			digest := sha256.Sum256(k.Verifier())
			if hex.EncodeToString(digest[:]) != k.Version() {
				t.Fatal("version not SHA256 of derived32 verifier")
			}
		})
	}
	if bytes.Equal(currentKeyFixture(t, ComplianceCurrentExecution).Verifier(), currentKeyFixture(t, ComplianceCurrentCleanup).Verifier()) {
		t.Fatal("execution and cleanup key domains collide")
	}
	for _, legacy := range []string{"4ca51d5974b7bdc066dcb219c26e740cc998da8597ac13b3f4c9e44765271bf4", "35091e7ec390a0207d84d0181bb479d59e9fc98271d1d1a84063a85c36635ed4"} {
		for _, v := range currentKeyVectors {
			if hex.EncodeToString(currentKeyFixture(t, v.purpose).Verifier()) == legacy {
				t.Fatal("new key purpose collided with original domain literal")
			}
		}
	}
}
func TestComplianceCurrentKeyClosedPurposeAndSeedBounds(t *testing.T) {
	for _, p := range []ComplianceCurrentPurpose{"", "worker-forward", "captured-compensation", "compliance-current-execution", "compliance-current-cleanup-v2", "unknown"} {
		if k, err := NewComplianceCurrentKey(p, []byte(currentSyntheticSeed)); !errors.Is(err, ErrInvalid) || k != nil {
			t.Fatal("unsupported purpose admitted")
		}
	}
	for _, size := range []int{0, 1, 31, 4097} {
		if k, err := NewComplianceCurrentKey(ComplianceCurrentExecution, bytes.Repeat([]byte{'a'}, size)); !errors.Is(err, ErrInvalid) || k != nil {
			t.Fatalf("invalid seed size admitted: %d", size)
		}
	}
	for _, size := range []int{32, 4096} {
		if k, err := NewComplianceCurrentKey(ComplianceCurrentExecution, bytes.Repeat([]byte{'a'}, size)); err != nil || k == nil {
			t.Fatalf("valid seed bound refused: %d", size)
		}
	}
}
func TestComplianceCurrentKeyImmutableCopiesAndSafeFormatting(t *testing.T) {
	seed := []byte(currentSyntheticSeed)
	k, err := NewComplianceCurrentKey(ComplianceCurrentExecution, seed)
	if err != nil {
		t.Fatal(err)
	}
	before := k.Verifier()
	version := k.Version()
	clear(seed)
	copyOut := k.Verifier()
	clear(copyOut)
	if len(before) != 32 || !bytes.Equal(before, k.Verifier()) || k.Version() != version {
		t.Fatal("seed/verifier mutation changed private key")
	}
	for _, format := range []string{"%v", "%#v", "%+#v", "%s", "%q"} {
		if got := fmt.Sprintf(format, k); got != "[compliance current authorization key]" {
			t.Fatalf("unsafe key formatting for %s", format)
		}
	}
	var nilKey *ComplianceCurrentKey
	if nilKey.Version() != "" || nilKey.Verifier() != nil {
		t.Fatal("nil key yielded key material")
	}
}
func currentKeyWriteFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "seed")
	if err := os.WriteFile(path, []byte(currentSyntheticSeed), 0400); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestComplianceCurrentKeyHeldFileLoader(t *testing.T) {
	path := currentKeyWriteFixture(t)
	for _, v := range currentKeyVectors {
		k, err := LoadComplianceCurrentKeyFile(v.purpose, path)
		if err != nil || k == nil {
			t.Fatalf("valid owner-readonly file refused: error=%v", err)
		}
		if hex.EncodeToString(k.Verifier()) != v.verifier || k.Version() != v.version {
			t.Fatal("file loader changed derivation domain")
		}
	}
}
func TestComplianceCurrentKeyFileLoaderRefusals(t *testing.T) {
	path := currentKeyWriteFixture(t)
	checks := []struct{ name, path string }{
		{"relative", "seed"}, {"unclean", filepath.Dir(path) + "/../" + filepath.Base(filepath.Dir(path)) + "/seed"},
		{"missing", path + "-missing"}, {"directory", filepath.Dir(path)},
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	checks = append(checks, struct{ name, path string }{"symlink", link})
	fifo := path + "-fifo"
	if err := syscall.Mkfifo(fifo, 0400); err != nil {
		t.Fatal(err)
	}
	checks = append(checks, struct{ name, path string }{"fifo", fifo})
	ancestorLink := filepath.Dir(path) + "-alias"
	if err := os.Symlink(filepath.Dir(path), ancestorLink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(ancestorLink) })
	checks = append(checks, struct{ name, path string }{"symlink-ancestor", filepath.Join(ancestorLink, "seed")})
	for _, size := range []int{31, 4097} {
		short := filepath.Join(filepath.Dir(path), fmt.Sprintf("size-%d", size))
		if err := os.WriteFile(short, bytes.Repeat([]byte{'a'}, size), 0400); err != nil {
			t.Fatal(err)
		}
		checks = append(checks, struct{ name, path string }{fmt.Sprintf("size-%d", size), short})
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if k, err := LoadComplianceCurrentKeyFile(ComplianceCurrentExecution, c.path); !errors.Is(err, ErrInvalid) || k != nil {
				t.Fatal("nonregular/noncanonical file accepted")
			}
		})
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadComplianceCurrentKeyFile(ComplianceCurrentExecution, path); !errors.Is(err, ErrInvalid) || k != nil {
		t.Fatal("writable seed admitted")
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	hardlink := path + "-hard"
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadComplianceCurrentKeyFile(ComplianceCurrentExecution, path); !errors.Is(err, ErrInvalid) || k != nil {
		t.Fatal("multiply-linked seed admitted")
	}
	for _, p := range []ComplianceCurrentPurpose{"worker-forward", "captured-compensation", ""} {
		if k, err := LoadComplianceCurrentKeyFile(p, path); !errors.Is(err, ErrInvalid) || k != nil {
			t.Fatal("legacy/unknown purpose admitted by new loader")
		}
	}
	_, err := LoadComplianceCurrentKeyFile(ComplianceCurrentExecution, path+"-missing")
	for _, format := range []string{"%v", "%#v", "%+#v"} {
		if text := fmt.Sprintf(format, err); strings.Contains(text, path) || strings.Contains(text, currentSyntheticSeed) {
			t.Fatal("file error exposed path or seed")
		}
	}
}
