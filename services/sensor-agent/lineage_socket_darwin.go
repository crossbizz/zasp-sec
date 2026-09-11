package main

import (
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lineagePinSocket(_ *os.Root, _ string) (*os.File, error) { return nil, nil }

// macOS support is for local socket fixtures. Production is Linux-only and uses
// the descriptor-relative address, which macOS Unix sockets don't provide.
func lineageSocketAddress(endpoint *lineageSocket) (string, error) {
	if !lineageSocketPathStillPinned(endpoint) {
		return "", errLineageSocket
	}
	return endpoint.path, nil
}

func lineageSocketPathStillPinned(endpoint *lineageSocket) bool {
	current, err := os.Stat(filepath.Dir(endpoint.path))
	pinned, pinnedErr := endpoint.parent.Stat()
	return err == nil && pinnedErr == nil && os.SameFile(current, pinned)
}

func lineageSocketPeerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, errLineageSocket
	}
	var uid uint32
	var peerErr error
	controlErr := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil || credentials == nil {
			peerErr = errLineageSocket
			return
		}
		uid = credentials.Uid
	})
	if controlErr != nil || peerErr != nil {
		return 0, errLineageSocket
	}
	return uid, nil
}
