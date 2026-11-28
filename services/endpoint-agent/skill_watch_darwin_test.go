//go:build darwin && cgo

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSkillInstallAndNestedAtomicEditWakeIdleWatcher(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, ".agents", "skills")
	w, err := newSkillWatcher([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	wait := func(timeout time.Duration, want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), timeout)
		defer cancel()
		if w.wait(ctx) != want {
			t.Fatalf("expected skill event = %v", want)
		}
	}
	write := func(name string) {
		t.Helper()
		if err := os.WriteFile(name, []byte("sample"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(base, "unrelated"))
	wait(time.Second, false)
	bundle := filepath.Join(root, "new-skill")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(bundle, "SKILL.md"))
	wait(8*time.Second, true)
	write(filepath.Join(base, "staged"))
	if err := os.Rename(filepath.Join(base, "staged"), filepath.Join(bundle, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	wait(8*time.Second, true)
	wait(time.Second, false)
}

func TestSkillAssignmentCanonicalizesSystemAliasesOnly(t *testing.T) {
	parent, err := os.MkdirTemp("/tmp", "zasp-skill-project-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(parent)
	physical, err := canonicalSkillBase(parent)
	if err != nil || physical != "/private"+parent {
		t.Fatal(physical, err)
	}
	link := filepath.Join(t.TempDir(), "project")
	if err := os.Symlink(physical, link); err != nil {
		t.Fatal(err)
	}
	if _, err = canonicalSkillBase(link); err == nil {
		t.Fatal("accepted a linked project assignment")
	}
}

// Exercise the LaunchAgent command, its peer-checked socket and the CLI process
// boundary. The installed-baseline test separately checks the real rule engine.
func TestWatchSkillsSubmitsOnlyAtEnrollmentAndAfterChanges(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the LaunchAgent must run as an employee")
	}
	dir, err := os.MkdirTemp("/private/tmp", "zasp-skills-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	scanner := filepath.Join(dir, "scanner")
	script := "#!/bin/sh\n[ \"$1 $2 $3 $4 $5 $6 $7 $8\" = 'addons inventory --local --harness all --json --scope project' ] && [ \"$9\" = '--project' ] || exit 2\nprintf '%s\\n' '{}'\n"
	if err := os.WriteFile(scanner, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	captured := make(chan request, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var req request
			if err := json.NewDecoder(conn).Decode(&req); err == nil {
				switch req.Operation {
				case "inventory-enabled":
					json.NewEncoder(conn).Encode(response{InventoryEnabled: true})
				case "inventory":
					json.NewEncoder(conn).Encode(response{})
					captured <- req
				}
			}
			conn.Close()
		}
	}()
	go func() { done <- watchInstalledSkills(ctx, socket, scanner, project) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("watcher did not stop")
		}
	})
	expectReport := func() {
		t.Helper()
		select {
		case req := <-captured:
			if req.Project != project || string(req.Hook) != "{}" {
				t.Fatalf("unexpected report %+v", req)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no inventory submitted")
		}
	}
	expectReport()
	if err := os.WriteFile(filepath.Join(project, "unrelated"), []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-captured:
		t.Fatal("unrelated write triggered a scan")
	case <-time.After(time.Second):
	}
	bundle := filepath.Join(project, ".claude", "skills", "added")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	expectReport()
}
