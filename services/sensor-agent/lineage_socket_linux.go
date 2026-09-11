package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func lineagePinSocket(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func lineageSocketAddress(endpoint *lineageSocket) (string, error) {
	return fmt.Sprintf("/proc/self/fd/%d/%s", endpoint.parent.Fd(), endpoint.name), nil
}

func lineageSocketPathStillPinned(_ *lineageSocket) bool { return true }

func lineageSocketPeerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, errLineageSocket
	}
	var uid uint32
	var peerErr error
	controlErr := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
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
