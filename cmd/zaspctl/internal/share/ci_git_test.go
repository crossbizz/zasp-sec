package share

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAttestorReadsOnlyImmutableGitTree(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("git fixture: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	skill := filepath.Join(dir, "skills", "ticket")
	if err := os.MkdirAll(skill, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(skill, "SKILL.md")
	if err := os.WriteFile(p, []byte("---\nname: ticket\n---\nRead a ticket."), 0600); err != nil {
		t.Fatal(err)
	}
	run("add", "skills")
	run("-c", "user.name=Fixture", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
	rev := run("rev-parse", "HEAD")
	ctx := context.Background()
	original, err := scanCommit(ctx, dir, "skills/ticket", rev)
	if err != nil || original.ManifestDigest == "" {
		t.Fatalf("snapshot: %v", err)
	}
	if err := os.WriteFile(p, []byte("edited after commit"), 0600); err != nil {
		t.Fatal(err)
	}
	again, err := scanCommit(ctx, dir, "skills/ticket", rev)
	if err != nil || again.ManifestDigest != original.ManifestDigest {
		t.Fatal("signer read mutable checkout")
	}
	for _, root := range []string{"../skills", "/skills", "skills/not-present"} {
		if _, err := scanCommit(ctx, dir, root, rev); err == nil {
			t.Errorf("unbounded root %s accepted", root)
		}
	}
}
