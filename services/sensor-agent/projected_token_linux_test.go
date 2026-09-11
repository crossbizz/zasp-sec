package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Two disposable containers share /projection. Only the root writer has a RW
// mount. The UID 65532 reader keeps one tokenReader across every publication.
func TestProjectedLineageTokenRotationMount(t *testing.T) {
	phase := os.Getenv("ZASP_TEST_PROJECTED_TOKEN_PHASE")
	if phase == "" {
		t.Skip("requires isolated RO projection and RW writer containers")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	cases := []string{"first", "rotated", "malformed", "removed", "recovered", "writable", "world-readable", "foreign-owner", "foreign-group", "hardlink", "file-symlink", "version-symlink", "data-traversal", "visible-traversal", "foreign-link-owner", "writable-version", "fifo", "short", "long", "recovered-final"}
	if phase == "writer" {
		if os.Geteuid() != 0 {
			t.Fatal("writer must be root")
		}
		if err := os.Chmod("/projection", 0777|os.ModeSticky|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown("/projection", 0, 65532); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown("/control", 65532, 65532); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod("/control", 0777); err != nil {
			t.Fatal(err)
		}
		for i, name := range cases {
			projectedTokenPublishFixture(t, i, name)
			if err := os.WriteFile("/control/ready", []byte(fmt.Sprint(i)), 0644); err != nil {
				t.Fatal(err)
			}
			projectedTokenWaitFixture(t, "/control/done", i)
		}
		projectedTokenWaitFixture(t, "/control/stress-start", 1)
		for i := 20; i < 220; i++ {
			projectedTokenPublishFixture(t, i, "rotated")
		}
		if err := os.WriteFile("/control/stress-end", []byte("1"), 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if phase != "reader" || os.Geteuid() != 65532 {
		t.Fatal("invalid reader fixture")
	}
	reader, err := newTokenReader("/projection/token")
	if err != nil {
		t.Fatal(err)
	}
	reader.projected = true
	defer reader.Close()
	parent, err := reader.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	if !projectedTokenReadOnly(parent) {
		parent.Close()
		t.Fatal("reader fixture isn't read-only")
	}
	parent.Close()
	for i, name := range cases {
		projectedTokenWaitFixture(t, "/control/ready", i)
		t.Run(name, func(t *testing.T) {
			raw, err := readLineageToken(reader, 65532)
			defer clear(raw)
			valid := name == "first" || name == "rotated" || strings.HasPrefix(name, "recovered")
			if valid {
				if err != nil || string(raw) != projectedTokenFixture(i) {
					t.Fatal("current projected credential unavailable or stale", err)
				}
			} else if err == nil || len(raw) != 0 {
				t.Fatal("invalid projection returned a credential")
			}
		})
		if err := os.WriteFile("/control/done", []byte(fmt.Sprint(i)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/control/stress-start", []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	allowed := make(map[string]bool)
	for i := 19; i < 220; i++ {
		allowed[projectedTokenFixture(i)] = true
	}
	rejected, accepted := 0, 0
	for i := 0; i < 1000; i++ {
		raw, err := readLineageToken(reader, 65532)
		if err != nil {
			if len(raw) != 0 {
				clear(raw)
				t.Fatal("failed concurrent read retained credential")
			}
			rejected++
		} else {
			if !allowed[string(raw)] {
				clear(raw)
				t.Fatal("concurrent read returned unpublished credential")
			}
			accepted++
		}
		clear(raw)
	}
	projectedTokenWaitFixture(t, "/control/stress-end", 1)
	raw, err := readLineageToken(reader, 65532)
	if err != nil || string(raw) != projectedTokenFixture(219) {
		clear(raw)
		t.Fatal("final concurrent publication wasn't observed", err)
	}
	clear(raw)
	t.Logf("concurrent publication reads: accepted=%d rejected=%d", accepted, rejected)
	if raw, err := readLineageToken(reader, 0); err == nil || len(raw) != 0 {
		clear(raw)
		t.Fatal("root authority accepted")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if raw, err := readLineageToken(reader, 65532); err == nil || len(raw) != 0 {
		clear(raw)
		t.Fatal("closed reader returned credential")
	}
}

func projectedTokenWaitFixture(t *testing.T, path string, step int) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil && string(raw) == fmt.Sprint(step) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("projection fixture handshake timed out", filepath.Base(path), step)
}

func projectedTokenFixture(step int) string {
	return "zasp_sensor_v1." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(step + 2)}, 32))
}

func projectedTokenPublishFixture(t *testing.T, step int, name string) {
	t.Helper()
	version := fmt.Sprintf("..2026_09_11_12_00_00.%09d", step)
	directory := filepath.Join("/projection", version)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Mkdir(directory, 0755))
	must(os.Chown(directory, 0, 65532))
	must(os.Chmod(directory, 0755|os.ModeSetgid))
	file := filepath.Join(directory, "token")
	value := projectedTokenFixture(step)
	if name == "malformed" {
		value = strings.Repeat("x", 81)
	}
	if name == "short" {
		value = value[:80]
	}
	if name == "long" {
		value += "\n"
	}
	if name != "removed" {
		must(os.WriteFile(file, []byte(value), 0440))
		must(os.Chown(file, 0, 65532))
	}
	switch name {
	case "writable":
		must(os.Chmod(file, 0660))
	case "world-readable":
		must(os.Chmod(file, 0444))
	case "foreign-owner":
		must(os.Chown(file, 65532, 65532))
	case "foreign-group":
		must(os.Chown(file, 0, 0))
	case "hardlink":
		must(os.Link(file, filepath.Join(directory, "alias")))
	case "file-symlink":
		must(os.Rename(file, filepath.Join(directory, "alternate")))
		must(os.Symlink("alternate", file))
	case "version-symlink":
		must(os.Rename(directory, directory+"-actual"))
		must(os.Symlink(version+"-actual", directory))
	case "writable-version":
		must(os.Chmod(directory, 0775|os.ModeSetgid))
	case "fifo":
		must(os.Remove(file))
		must(unix.Mkfifo(file, 0440))
	}
	target := version
	if name == "data-traversal" {
		target = "../projection/" + version
	}
	must(os.Symlink(target, "/projection/..data_tmp"))
	must(os.Rename("/projection/..data_tmp", "/projection/..data"))
	visible := "..data/token"
	if name == "visible-traversal" {
		visible = "../projection/..data/token"
	}
	prior, err := os.Readlink("/projection/token")
	if os.IsNotExist(err) || prior != visible {
		if err := os.Remove("/projection/token"); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		must(os.Symlink(visible, "/projection/token"))
	} else if err != nil {
		t.Fatal(err)
	}
	uid := 0
	if name == "foreign-link-owner" {
		uid = 65532
	}
	must(os.Lchown("/projection/token", uid, 65532))
}

func TestProjectedLineageTokenRejectsWritableMount(t *testing.T) {
	if os.Getenv("ZASP_TEST_PROJECTED_TOKEN_PHASE") != "writable-reader" {
		t.Skip("requires isolated writable projection")
	}
	if os.Geteuid() != 65532 {
		t.Fatal("requires nonroot")
	}
	reader, err := newTokenReader("/projection/token")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.projected = true
	parent, err := reader.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if projectedTokenReadOnly(parent) {
		t.Fatal("fixture should be writable")
	}
	if raw, err := readLineageToken(reader, 65532); err == nil || len(raw) != 0 {
		clear(raw)
		t.Fatal("writable projection accepted")
	}
}
