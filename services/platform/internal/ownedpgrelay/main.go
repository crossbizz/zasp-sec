// ownedpgrelay is a local acceptance helper, never a product service. It runs
// only inside the owned network-none PostgreSQL container and has no options.
package main

import (
	"context"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", "127.0.0.1:5432")
	if err != nil {
		os.Exit(1)
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := relay(ctx, os.Stdin, os.Stdout, connection); err != nil {
		os.Exit(1)
	}
}

func relay(ctx context.Context, input io.ReadCloser, output io.WriteCloser, connection net.Conn) error {
	// Inherited stdio starts as blocking descriptors. Closing an os.File does
	// not interrupt a read already blocked in that syscall. Register nonblocking
	// wrappers with Go's poller so server EOF and cancellation can join both
	// copies even while the client keeps stdin open or stops reading stdout.
	if file, ok := input.(*os.File); ok {
		pollable, err := pollableRelayFile(file)
		if err != nil {
			_ = connection.Close()
			_ = input.Close()
			_ = output.Close()
			return err
		}
		input = pollable
	}
	if file, ok := output.(*os.File); ok {
		pollable, err := pollableRelayFile(file)
		if err != nil {
			_ = connection.Close()
			_ = input.Close()
			_ = output.Close()
			return err
		}
		output = pollable
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(connection, input); done <- struct{}{} }()
	go func() { _, _ = io.Copy(output, connection); done <- struct{}{} }()
	joined := 0
	select {
	case <-done:
		joined++
	case <-ctx.Done():
	}
	_ = connection.Close()
	_ = input.Close()
	_ = output.Close()
	for joined < 2 {
		<-done
		joined++
	}
	return nil
}

func pollableRelayFile(file *os.File) (*os.File, error) {
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	// Transfer ownership to a distinct descriptor; two os.File wrappers must
	// never both own one fd, since either finalizer could close the other.
	pollable := os.NewFile(uintptr(fd), file.Name())
	if err := file.Close(); err != nil {
		_ = pollable.Close()
		return nil, err
	}
	return pollable, nil
}
