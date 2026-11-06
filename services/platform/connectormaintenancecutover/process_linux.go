package connectormaintenancecutover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Proc observes one exact local writer only. It cannot establish a fleet inventory.
type proc struct{}

func statIdentity(ctx context.Context, pid int) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", ErrRefused
	}
	f, e := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil || len(b) > 8192 || ctx.Err() != nil {
		return "", ErrRefused
	}
	s := string(b)
	i := strings.LastIndex(s, ") ")
	if i < 0 {
		return "", ErrRefused
	}
	fields := strings.Fields(s[i+2:])
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return "", ErrRefused
	}
	if !strings.HasPrefix(s, strconv.Itoa(pid)+" (") {
		return "", ErrRefused
	}
	if _, e = strconv.ParseUint(fields[19], 10, 64); e != nil {
		return "", ErrRefused
	}
	return fields[19], nil
}
func (proc) live(ctx context.Context, pid int) (identity, error) {
	start, e := statIdentity(ctx, pid)
	if e != nil {
		return identity{}, ErrRefused
	}
	name := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	exe, e := os.Readlink(name)
	if e != nil || strings.HasSuffix(exe, " (deleted)") || !filepath.IsAbs(exe) {
		return identity{}, ErrRefused
	}
	// The procfs exe link is intentionally followed; its opened inode is pinned.
	f, e := os.Open(name)
	if e != nil {
		return identity{}, ErrRefused
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 256<<20 {
		return identity{}, ErrRefused
	}
	h := sha256.New()
	buf := make([]byte, 65536)
	var total int64
	for {
		if ctx.Err() != nil {
			return identity{}, ErrRefused
		}
		n, err := f.Read(buf)
		total += int64(n)
		if total > 256<<20 {
			return identity{}, ErrRefused
		}
		h.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return identity{}, ErrRefused
		}
	}
	after, e := f.Stat()
	again, e2 := statIdentity(ctx, pid)
	pathAfter, e3 := os.Stat(name)
	target, e4 := os.Readlink(name)
	if e != nil || e2 != nil || e3 != nil || e4 != nil || again != start || target != exe || !os.SameFile(before, after) || !os.SameFile(before, pathAfter) || before.Size() != after.Size() || total != before.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return identity{}, ErrRefused
	}
	a, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return identity{}, ErrRefused
	}
	return identity{pid: pid, start: start, dev: uint64(a.Dev), ino: a.Ino, executable: exe, sha256: hex.EncodeToString(h.Sum(nil))}, nil
}
func (proc) absent(ctx context.Context, old identity) error {
	if ctx == nil || ctx.Err() != nil || old.pid <= 0 || old.start == "" {
		return ErrRefused
	}
	// Only disappearance establishes absence. A zombie/reused PID/unknown read
	// refuses conservatively; no signal or executable-equivalence guess occurs.
	_, e := os.Lstat(filepath.Join("/proc", strconv.Itoa(old.pid)))
	if !os.IsNotExist(e) || ctx.Err() != nil {
		return ErrRefused
	}
	return nil
}
