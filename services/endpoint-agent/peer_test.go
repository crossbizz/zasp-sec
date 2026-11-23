package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Both sides use the native socket credential API before handling a hook.
func TestKernelCredentialOnBothEnds(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ep-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, conn := range []*net.UnixConn{client, server} {
		uid, err := acceptedPeer(conn)
		if err != nil || uid != os.Geteuid() {
			t.Fatalf("wanted local peer, got %d: %v", uid, err)
		}
	}
}
