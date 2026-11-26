package runtimesecret

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStartupCredentialsUseProtectedFilesOrExistingEnvironment(t *testing.T) {
	name := "ZASP_STYTCH_SECRET"
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	env := map[string]string{name + "_FILE": p, "other": "unchanged"}
	get := func(k string) string { return env[k] }
	if _, err := FromFiles(get, name); err == nil {
		t.Fatal("missing file accepted")
	}
	for _, value := range []string{"", "line\nsecond", "null\x00byte", "trailing\r\n", strings.Repeat("x", 16386)} {
		if err := os.WriteFile(p, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := FromFiles(get, name); err == nil {
			t.Fatal("invalid value accepted")
		}
	}
	if err := os.WriteFile(p, []byte("private-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	environ, err := FromFiles(get, name)
	if err != nil || environ(name) != "private-value" || environ("other") != "unchanged" {
		t.Fatal("incorrect projection", err)
	}
	env[name] = "direct"
	if _, err = FromFiles(get, name); err == nil || strings.Contains(err.Error(), "private-value") {
		t.Fatal("ambiguous source accepted or error disclosed value")
	}
	delete(env, name)
	if err = os.Chmod(p, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err = FromFiles(get, name); err == nil {
		t.Fatal("group-readable credential accepted")
	}
	delete(env, name+"_FILE")
	env[name] = "direct"
	environ, err = FromFiles(get, name)
	if err != nil || environ(name) != "direct" {
		t.Fatal("legacy lookup changed", err)
	}
}

func TestPrivateProjectionAllowsTrustedRotationAndRejectsUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "projection")
	if err := os.WriteFile(target, []byte("bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "current")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPrivateFile(link, 10); err != nil || string(got) != "bytes" {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateFile(link, 10); err == nil {
		t.Fatal("accepted writable parent")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadPrivateFile(fifo, 10); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked on FIFO")
	}
}
