package runtimepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAcceptsOnlyAPrivateDirectoryOutsideKubernetes(t *testing.T) {
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(private, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	for name, test := range map[string]struct {
		value, host string
		uid         int
		want        string
	}{
		"unset":             {"", "", uid, ""},
		"private":           {private, "", uid, private},
		"inside kubernetes": {private, "10.0.0.1", uid, ""},
		"another owner":     {private, "", uid + 1, ""},
		"open to others":    {open, "", uid, ""},
		"relative":          {"state", "", uid, ""},
		"not clean":         {private + "/", "", uid, ""},
		"file system root":  {"/", "", uid, ""},
		"a file":            {file, "", uid, ""},
		"a symbolic link":   {link, "", uid, ""},
		"missing":           {filepath.Join(private, "missing"), "", uid, ""},
	} {
		if got := resolve(test.value, test.host, test.uid); got != test.want {
			t.Errorf("%s: resolve = %q, want %q", name, got, test.want)
		}
	}
}

func TestFixedIsUnchangedWithoutALocalRoot(t *testing.T) {
	if os.Getenv(RootVariable) != "" {
		t.Skip("a local runtime root is set")
	}
	const path = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
	if got := Fixed(path); got != path {
		t.Fatalf("Fixed = %q, want %q", got, path)
	}
}
