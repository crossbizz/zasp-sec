package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

var errLineageSocket = errors.New("sensor lineage local endpoint unavailable")

// This endpoint belongs only to the trusted Tetragon-side producer. Access to
// Tetragon's raw socket grants control methods too; it must never be mounted into
// the sensor consumer. UID/permissions authenticate a local OS boundary, not a
// server image, host namespace or Kubernetes pod.
type lineageSocket struct {
	mu           sync.Mutex
	root         *os.Root
	parent       *os.File
	socket       *os.File // Linux O_PATH handle prevents original inode reuse.
	path, name   string
	owner        uint32
	initial      os.FileInfo
	used, closed bool
	connection   net.Conn
}

func newProductionLineageSocket(path string) (*lineageSocket, error) {
	if runtime.GOOS != "linux" {
		return nil, errLineageSocket
	}
	return newLineageSocket(path, 0)
}

// Explicit UID injection supports local fixtures only. Production uses the
// Linux-only root-owned constructor above and the controlled deployment mount.
func newLineageSocket(path string, owner uint32) (*lineageSocket, error) {
	if !validAbsolute(path) || len(filepath.Base(path)) > 64 {
		return nil, errLineageSocket
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errLineageSocket
	}
	parent, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errLineageSocket
	}
	endpoint := &lineageSocket{root: root, parent: parent, path: path, name: filepath.Base(path), owner: owner}
	initial, err := root.Lstat(endpoint.name)
	if err != nil || !endpoint.validSocket(initial) || !endpoint.validParent() {
		endpoint.Close()
		return nil, errLineageSocket
	}
	endpoint.initial = initial
	endpoint.socket, err = lineagePinSocket(root, endpoint.name)
	if err != nil || !endpoint.unchanged() {
		endpoint.Close()
		return nil, errLineageSocket
	}
	return endpoint, nil
}

func (endpoint *lineageSocket) validParent() bool {
	info, err := endpoint.parent.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == endpoint.owner
}

func (endpoint *lineageSocket) validSocket(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeType != os.ModeSocket || info.Mode().Perm()&0o007 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == endpoint.owner && stat.Nlink == 1
}

func (endpoint *lineageSocket) unchanged() bool {
	info, err := endpoint.root.Lstat(endpoint.name)
	if err != nil || !endpoint.validParent() || !endpoint.validSocket(info) || !os.SameFile(endpoint.initial, info) {
		return false
	}
	if endpoint.socket != nil {
		pinned, err := endpoint.socket.Stat()
		if err != nil || !endpoint.validSocket(pinned) || !os.SameFile(pinned, info) {
			return false
		}
	}
	return true
}

// DialOnce consumes the endpoint even if an attempted connection fails. A
// reconnect needs a newly constructed endpoint and a new source generation.
// Close serializes with the bounded dial so the pinned directory FD cannot be
// closed/reused between constructing the Linux path and validating the peer.
func (endpoint *lineageSocket) DialOnce(ctx context.Context) (net.Conn, error) {
	if endpoint == nil || ctx == nil || ctx.Err() != nil {
		return nil, errLineageSocket
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if endpoint.closed || endpoint.used {
		return nil, errLineageSocket
	}
	endpoint.used = true
	if !endpoint.unchanged() {
		return nil, errLineageSocket
	}
	address, err := lineageSocketAddress(endpoint)
	if err != nil {
		return nil, errLineageSocket
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", address)
	if err != nil {
		return nil, errLineageSocket
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, errLineageSocket
	}
	uid, err := lineageSocketPeerUID(unixConnection)
	if err != nil || uid != endpoint.owner || !endpoint.unchanged() || !lineageSocketPathStillPinned(endpoint) || ctx.Err() != nil {
		connection.Close()
		return nil, errLineageSocket
	}
	endpoint.connection = connection
	return connection, nil
}

func (endpoint *lineageSocket) Close() error {
	if endpoint == nil {
		return nil
	}
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	if endpoint.closed {
		return nil
	}
	endpoint.closed = true
	if endpoint.connection != nil {
		endpoint.connection.Close()
	}
	if endpoint.socket != nil {
		endpoint.socket.Close()
	}
	first, second := endpoint.parent.Close(), endpoint.root.Close()
	if first != nil || second != nil {
		return errLineageSocket
	}
	return nil
}
