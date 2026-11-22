//go:build linux

package skillfixture

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const marker = "Zasp synthetic file marker v1\n"
const signalText = "fixture-v1"

func privilegedEnvironment() bool {
	// Hosted jobs receive only the two trust settings and ordinary operating
	// system metadata. Reject unrecognized variables rather than relying on
	// every provider to use a particular secret variable naming convention.
	for _, pair := range os.Environ() {
		name, value, _ := strings.Cut(pair, "=")
		if value == "" {
			continue
		}
		switch name {
		case "ZASP_SKILL_FIXTURE_SCOPE", "ZASP_SKILL_FIXTURE_PUBLIC_KEY",
			"PATH", "HOME", "HOSTNAME", "LANG", "LC_ALL", "TERM", "TZ", "TMPDIR",
			"GOMAXPROCS", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_EXECUTION_ENV",
			"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT", "KUBERNETES_SERVICE_PORT_HTTPS",
			"KUBERNETES_PORT", "KUBERNETES_PORT_443_TCP", "KUBERNETES_PORT_443_TCP_ADDR",
			"KUBERNETES_PORT_443_TCP_PORT", "KUBERNETES_PORT_443_TCP_PROTO":
		default:
			return true
		}
	}
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	return false
}

func Child() error {
	if privilegedEnvironment() {
		return ErrRefused
	}
	// The released child understands no supplied path, command or address.
	f, err := os.OpenFile("marker", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrRefused
	}
	body, err := io.ReadAll(io.LimitReader(f, int64(len(marker)+1)))
	closeErr := f.Close()
	if err != nil || closeErr != nil || string(body) != marker {
		return ErrRefused
	}
	conn, err := net.DialTimeout("unix", "witness.sock", time.Second)
	if err != nil {
		return ErrRefused
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = io.WriteString(conn, signalText)
	return err
}

func observedFileAccess(fd int) bool {
	var buf [4096]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil || n < unix.SizeofInotifyEvent {
		return false
	}
	// Watch a single, fixed file: events carry no child name. The exchange is
	// performed only after the watch was created, in an owner-only workspace.
	for offset := 0; offset+unix.SizeofInotifyEvent <= n; offset += unix.SizeofInotifyEvent {
		mask := binary.NativeEndian.Uint32(buf[offset+4 : offset+8])
		if mask&unix.IN_ACCESS != 0 {
			return true
		}
	}
	return false
}

func Witness(parent context.Context, c Claim) (Result, error) {
	if privilegedEnvironment() {
		return Result{}, ErrRefused
	}
	ctx, cancel := context.WithDeadline(parent, minTime(time.Now().Add(MaxDuration), time.Unix(c.ExpiresAt, 0)))
	defer cancel()
	dir, err := os.MkdirTemp("", "zasp-fixture-")
	if err != nil {
		return Result{}, ErrRefused
	}
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "marker")
	if err = os.WriteFile(target, []byte(marker), 0600); err != nil {
		return Result{}, ErrRefused
	}
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return Result{}, ErrRefused
	}
	defer unix.Close(fd)
	if _, err = unix.InotifyAddWatch(fd, target, unix.IN_ACCESS); err != nil {
		return Result{}, ErrRefused
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "witness.sock"), Net: "unix"})
	if err != nil {
		return Result{}, ErrRefused
	}
	defer listener.Close()
	deadline, _ := ctx.Deadline()
	_ = listener.SetDeadline(deadline)
	exe, err := os.Executable()
	if err != nil {
		return Result{}, ErrRefused
	}
	cmd := exec.CommandContext(ctx, exe, "--synthetic-skill-child")
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: unix.SIGKILL}
	cmd.Env = []string{"LANG=C"}
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return Result{}, ErrRefused
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// A short-lived child can exit before accept. Use the descriptor's kernel
	// credentials as proof of the peer, independent of the child's stdout.
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	conn, acceptErr := listener.AcceptUnix()
	socketOK := false
	if acceptErr == nil {
		_ = conn.SetDeadline(deadline)
		raw, e := conn.SyscallConn()
		var cred *unix.Ucred
		if e == nil {
			e = raw.Control(func(fd uintptr) { cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
		}
		body, readErr := io.ReadAll(io.LimitReader(conn, int64(len(signalText)+1)))
		conn.Close()
		socketOK = e == nil && cred != nil && int(cred.Pid) == cmd.Process.Pid && cred.Uid == uint32(os.Geteuid()) && readErr == nil && string(body) == signalText
	}
	waitErr := <-done
	seen := []string{}
	if observedFileAccess(fd) {
		seen = append(seen, "file.read")
	}
	if waitErr == nil {
		seen = append(seen, "process.exec")
	}
	if socketOK {
		seen = append(seen, "local_socket.connect")
	}
	return result(c, seen, len(seen) == 3 && ctx.Err() == nil, time.Now()), nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
