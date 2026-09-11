package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func lineageSocketFixture(t *testing.T) (string, *net.UnixListener) {
	t.Helper()
	// macOS's default test temp path can exceed the Unix sockaddr limit.
	dir, err := os.MkdirTemp("/tmp", "zasp-ls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "tetragon.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() { listener.Close() })
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	return path, listener
}

func TestLineageSocketAuthenticatesAndDialsOnlyOnce(t *testing.T) {
	path, listener := lineageSocketFixture(t)
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := endpoint.DialOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var value [1]byte
	if n, err := connection.Read(value[:]); err != nil || n != 1 || value[0] != 'x' {
		t.Fatalf("read: %d %v", n, err)
	}
	if next, err := endpoint.DialOnce(ctx); next != nil || !errors.Is(err, errLineageSocket) {
		t.Fatal("endpoint permitted another connection")
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(value[:]); err == nil {
		t.Fatal("close retained transport")
	}
	if err := endpoint.Close(); err != nil {
		t.Fatal("close is not idempotent")
	}
}

func TestLineageSocketRejectsUnsafeEndpointAndReplacement(t *testing.T) {
	for _, kind := range []string{"symlink", "file", "world-access", "writable-parent", "wrong-owner", "replacement", "parent-mode-after-open"} {
		t.Run(kind, func(t *testing.T) {
			path, _ := lineageSocketFixture(t)
			owner := uint32(os.Getuid())
			var endpoint *lineageSocket
			var err error
			if kind == "replacement" || kind == "parent-mode-after-open" {
				endpoint, err = newLineageSocket(path, owner)
				if err != nil {
					t.Fatal(err)
				}
				defer endpoint.Close()
			}
			switch kind {
			case "symlink":
				target := path + ".target"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "world-access":
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			case "writable-parent", "parent-mode-after-open":
				if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				owner++
			case "replacement":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer replacement.Close()
				if err := os.Chmod(path, 0o660); err != nil {
					t.Fatal(err)
				}
			}
			if endpoint == nil {
				endpoint, err = newLineageSocket(path, owner)
			}
			if endpoint != nil {
				defer endpoint.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				connection, dialErr := endpoint.DialOnce(ctx)
				if connection != nil {
					connection.Close()
					t.Fatal("unsafe endpoint connected")
				}
				err = dialErr
			}
			if !errors.Is(err, errLineageSocket) {
				t.Fatalf("rejection: %v", err)
			}
		})
	}
}

func TestLineageSocketCloseAndConcurrentDial(t *testing.T) {
	path, _ := lineageSocketFixture(t)
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var group sync.WaitGroup
	connections := make(chan net.Conn, 16)
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if conn, err := endpoint.DialOnce(ctx); err == nil {
				connections <- conn
			}
		}()
	}
	group.Wait()
	close(connections)
	count := 0
	for connection := range connections {
		count++
		connection.Close()
	}
	if count != 1 {
		t.Fatalf("dial successes: %d", count)
	}
	endpoint.Close()
	if conn, err := endpoint.DialOnce(ctx); conn != nil || !errors.Is(err, errLineageSocket) {
		t.Fatal("closed endpoint reused")
	}
}

func TestLineageSocketCancellationAndProductionPlatformGate(t *testing.T) {
	path, _ := lineageSocketFixture(t)
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := endpoint.DialOnce(ctx); conn != nil || !errors.Is(err, errLineageSocket) {
		t.Fatal("cancelled dial accepted")
	}
	if conn, err := endpoint.DialOnce(nil); conn != nil || !errors.Is(err, errLineageSocket) {
		t.Fatal("nil context accepted")
	}
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		if endpoint, err := newProductionLineageSocket(path); endpoint != nil || !errors.Is(err, errLineageSocket) {
			if endpoint != nil {
				endpoint.Close()
			}
			t.Fatal("non-production fixture accepted as trusted root Linux endpoint")
		}
	}
}

func TestLineageSocketConcurrentCloseRevokesAnyDialResult(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		path, _ := lineageSocketFixture(t)
		endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := make(chan struct{})
		result := make(chan net.Conn, 1)
		closed := make(chan struct{})
		go func() { <-start; connection, _ := endpoint.DialOnce(ctx); result <- connection }()
		go func() { <-start; endpoint.Close(); close(closed) }()
		close(start)
		connection := <-result
		<-closed
		if connection != nil {
			if _, err := connection.Write([]byte("x")); err == nil {
				t.Fatal("concurrent close left usable transport")
			}
			connection.Close()
		}
		cancel()
	}
}

func TestLineageSocketLinuxParentPinSurvivesPathReplacement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production descriptor-relative Linux connection")
	}
	path, original := lineageSocketFixture(t)
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	oldDir := filepath.Dir(path)
	moved := oldDir + "-moved"
	if err := os.Rename(oldDir, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(moved) })
	if err := os.Mkdir(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := endpoint.DialOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	original.SetDeadline(time.Now().Add(time.Second))
	accepted, err := original.AcceptUnix()
	if err != nil {
		t.Fatalf("did not connect through pinned parent: %v", err)
	}
	accepted.Close()
}
