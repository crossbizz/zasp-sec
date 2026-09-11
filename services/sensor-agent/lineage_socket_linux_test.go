package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLineageSocketLinuxPinsOriginalSocketInode(t *testing.T) {
	path, _ := lineageSocketFixture(t)
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if endpoint.socket == nil {
		t.Fatal("socket inode not pinned")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	held, err := endpoint.socket.Stat()
	if err != nil || !os.SameFile(held, endpoint.initial) {
		t.Fatalf("original inode handle lost: %v", err)
	}
	current, err := os.Lstat(path)
	if err != nil || os.SameFile(held, current) {
		t.Fatal("replacement reused held socket inode")
	}
	endpoint.Close()
	if _, err := endpoint.socket.Stat(); err == nil {
		t.Fatal("close leaked socket inode handle")
	}
}

func TestLineageSocketLinuxPeerUIDMismatch(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires isolated root fixture with SETUID/SETGID/CHOWN capabilities")
	}
	dir, err := os.MkdirTemp("/tmp", "zasp-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tetragon.sock")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestLineageSocketLinuxPeerHelper$")
	command.Env = append(os.Environ(), "ZASP_LINEAGE_PEER_FIXTURE="+path)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); command.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "ready" {
		t.Fatal("peer helper failed to listen")
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	endpoint, err := newProductionLineageSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if conn, err := endpoint.DialOnce(ctx); conn != nil || err != errLineageSocket {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("filesystem-owned root socket accepted non-root peer")
	}
	if ctx.Err() != nil {
		t.Fatal("timeout masked peer rejection")
	}
}

func TestLineageSocketLinuxPeerHelper(t *testing.T) {
	path := os.Getenv("ZASP_LINEAGE_PEER_FIXTURE")
	if path == "" {
		t.Skip("child helper only")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fmt.Println("ready")
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var value [1]byte
	connection.Read(value[:])
}
