package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/cmd/zaspctl/internal/addons"
	"github.com/zasp-ai/zasp-sec/services/platform/addonsandbox"
)

func TestStaticProfilesAreLocalIsolatedAndClosed(t *testing.T) {
	for _, scanner := range []string{"cisco_skill_scanner", "nvidia_skillspector"} {
		pin := "sha256:" + strings.Repeat("a", 64)
		p, err := getProfile(scanner, pin)
		if err != nil {
			t.Fatal(err)
		}
		args := p.arguments("/tmp/staged", "name")
		for _, need := range []string{"unix:///var/run/docker.sock", "--pull=never", "--runtime=runsc", "--network=none", "--cap-drop=ALL", "--read-only", "--user=65532:65532", "--security-opt=no-new-privileges=true", "--pids-limit=64", "--memory=768m", "type=bind,src=/tmp/staged,dst=/review,readonly", "--entrypoint", pin, "/review", "sarif"} {
			if !slices.Contains(args, need) {
				t.Fatal(need)
			}
		}
		if scanner == "nvidia_skillspector" && !slices.Contains(args, "--no-llm") {
			t.Fatal("LLM flag missing")
		}
		second, _ := getProfile(scanner, "sha256:"+strings.Repeat("b", 64))
		if second.digest() == p.digest() {
			t.Fatal("digest ignored image pin")
		}
		if _, err = getProfile(scanner, "registry/scanner:latest"); err == nil {
			t.Fatal("mutable image accepted")
		}
	}
}
func TestSnapshotBindsActualBytesAndDropsExecutionBits(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# A guide\n"), 0700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snapshot")
	digest, err := snapshotSkill(src, dest)
	if err != nil {
		t.Fatal(err)
	}
	if digest != addons.Scan(src).ManifestDigest || digest != addons.Scan(dest).ManifestDigest {
		t.Fatal("copied content differs")
	}
	info, err := os.Stat(filepath.Join(dest, "SKILL.md"))
	if err != nil || info.Mode().Perm() != 0444 {
		t.Fatal("snapshot source not read-only")
	}
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# A changed guide\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if digest == addons.Scan(src).ManifestDigest {
		t.Fatal("manifest ignores bytes")
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "outside")); err != nil {
		t.Fatal(err)
	}
	if _, err = snapshotSkill(src, filepath.Join(t.TempDir(), "invalid")); err == nil {
		t.Fatal("accepted a partial symlink manifest")
	}
}
func TestSARIFReportsAreBoundedAndIndicatorsAreExplicit(t *testing.T) {
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Cisco"}},"results":[{"ruleId":"DATA_EXFIL_NETWORK_REQUESTS"},{"ruleId":"UNMAPPED_RULE"}]}]}`)
	counts, flags, err := observations("cisco_skill_scanner", raw)
	if err != nil || counts["UNMAPPED_RULE"] != 1 || !slices.Equal(flags, []string{"network_reference"}) {
		t.Fatal(err)
	}
	if _, _, err := observations("cisco_skill_scanner", []byte(`{"version":"2.1.0","runs":[]}`)); err == nil {
		t.Fatal("incomplete run reported")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := reportSink{cancel: cancel}
	_, err = s.Write(bytes.Repeat([]byte("x"), 2<<20+1))
	if err == nil || !s.exceeded || ctx.Err() == nil || s.data.Len() != 0 {
		t.Fatal("report limit bypassed")
	}
	seed := bytes.Repeat([]byte{10}, 32)
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(seed)), 0600); err != nil {
		t.Fatal(err)
	}
	sig, err := signReceipt(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := base64.StdEncoding.DecodeString(string(sig))
	if !ed25519.Verify(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), append([]byte(addonsandbox.SignatureContext), raw...), signature) {
		t.Fatal("invalid receipt signature")
	}
}
