//go:build darwin && cgo

package device

/*
#include <sys/types.h>
#include <unistd.h>
static int isDaemon(int fd) {
	uid_t uid; gid_t gid;
	return getpeereid(fd, &uid, &gid) == 0 && uid == 0;
}
*/
import "C"
import (
	"io"
	"net"
	"time"
)

func queryEndpoint() ([]byte, error) {
	conn, err := net.DialTimeout("unix", "/Library/Application Support/Zasp/run/endpoint.sock", time.Second)
	if err != nil {
		return nil, unavailable
	}
	defer conn.Close()
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, unavailable
	}
	if err := socket.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, unavailable
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return nil, unavailable
	}
	isRoot := false
	if raw.Control(func(fd uintptr) { isRoot = C.isDaemon(C.int(fd)) != 0 }) != nil || !isRoot {
		return nil, unavailable
	}
	if _, err := io.WriteString(socket, "{\"operation\":\"status\"}\n"); err != nil {
		return nil, unavailable
	}
	if err := socket.CloseWrite(); err != nil {
		return nil, unavailable
	}
	return io.ReadAll(io.LimitReader(socket, 2049))
}
