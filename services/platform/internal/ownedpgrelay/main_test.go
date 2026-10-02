package main

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// PostgreSQL CancelRequest has no response: its server closes the connection
// while the requesting client still keeps stdin open waiting for that EOF.
func TestRelayServerEOFJoinsInheritedStdin(t *testing.T) {
	if os.Getenv("ZASP_RELAY_SERVER_EOF_CHILD") == "true" {
		connection, remote := net.Pipe()
		go func() { time.Sleep(50 * time.Millisecond); _ = remote.Close() }()
		if err := relay(context.Background(), os.Stdin, os.Stdout, connection); err != nil {
			t.Fatal(err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRelayServerEOFJoinsInheritedStdin$", "-test.timeout=1s")
	command.Env = append(os.Environ(), "ZASP_RELAY_SERVER_EOF_CHILD=true")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("server EOF left inherited stdin reader running: %v\n%s", err, output)
	}
}

func TestRelayCopiesBytesAndJoinsOnCancellation(t *testing.T) {
	in, source := io.Pipe()
	sink, out := io.Pipe()
	connection, remote := net.Pipe()
	defer remote.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { relay(ctx, in, out, connection); close(done) }()
	writeDone := make(chan error, 1)
	go func() { _, err := source.Write([]byte{0, 1, 255, 9}); writeDone <- err }()
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(remote, buffer); err != nil || string(buffer) != string([]byte{0, 1, 255, 9}) {
		t.Fatalf("request bytes=%v error=%v", buffer, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := remote.Write([]byte{7, 0, 254, 8}); writeDone <- err }()
	if _, err := io.ReadFull(sink, buffer); err != nil || string(buffer) != string([]byte{7, 0, 254, 8}) {
		t.Fatalf("response bytes=%v error=%v", buffer, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay goroutines not joined")
	}
	if _, err := source.Write([]byte{1}); err == nil {
		t.Fatal("relay stdin remained open")
	}
	if _, err := remote.Write([]byte{1}); err == nil {
		t.Fatal("relay connection remained open")
	}
}

func TestRelayJoinsOnStdinEOF(t *testing.T) {
	in, source := io.Pipe()
	sink, out := io.Pipe()
	defer sink.Close()
	connection, remote := net.Pipe()
	defer remote.Close()
	done := make(chan struct{})
	go func() { relay(context.Background(), in, out, connection); close(done) }()
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stdin EOF left relay goroutines running")
	}
	if _, err := remote.Write([]byte{1}); err == nil {
		t.Fatal("stdin EOF left database socket open")
	}
}
