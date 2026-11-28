// Package testopenfga reads the credentials for a locally owned native proof.
package testopenfga

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
)

func ReadOwnedToken(endpoint, path string) (string, error) {
	refused := errors.New("native projection fixture credentials refused")
	if endpoint == "" || path == "" || len(endpoint) > 512 || len(path) > 4096 {
		return "", refused
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || u.String() != endpoint {
		return "", refused
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != u.Port() || u.Host != net.JoinHostPort(u.Hostname(), strconv.Itoa(port)) {
		return "", refused
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", refused
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return "", refused
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uint32(os.Getuid()) {
		return "", refused
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", refused
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || (before.Mode().Perm() != 0400 && before.Mode().Perm() != 0600) || before.Size() < 8 || before.Size() > 4096 {
		return "", refused
	}
	info, ok := before.Sys().(*syscall.Stat_t)
	if !ok || info.Uid != uint32(os.Getuid()) || info.Nlink != 1 {
		return "", refused
	}
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	after, statErr := file.Stat()
	live, pathErr := os.Lstat(path)
	if err != nil || statErr != nil || pathErr != nil || int64(len(body)) != before.Size() || !sameTokenIdentity(before, after) || !sameTokenIdentity(before, live) {
		return "", refused
	}
	for _, b := range body {
		if b < 33 || b > 126 || b == ',' {
			return "", refused
		}
	}
	if err := file.Close(); err != nil {
		return "", refused
	}
	return string(body), nil
}

func sameTokenIdentity(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	y, ok := b.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	xs, xn, xok := tokenChangeTime(x)
	ys, yn, yok := tokenChangeTime(y)
	return xok && yok && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && a.ModTime().Equal(b.ModTime()) && xs == ys && xn == yn
}

// Linux and Darwin expose the same kernel ctime using different Stat_t field
// names. Admit only their known seconds/nanoseconds grammar; unknown layouts
// refuse instead of silently dropping the change-time check.
func tokenChangeTime(stat *syscall.Stat_t) (int64, int64, bool) {
	if stat == nil {
		return 0, 0, false
	}
	value := reflect.ValueOf(stat).Elem().FieldByName("Ctim")
	if !value.IsValid() {
		value = reflect.ValueOf(stat).Elem().FieldByName("Ctimespec")
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0, 0, false
	}
	sec, nsec := value.FieldByName("Sec"), value.FieldByName("Nsec")
	integer := func(v reflect.Value) bool {
		if !v.IsValid() {
			return false
		}
		switch v.Kind() {
		case reflect.Int, reflect.Int32, reflect.Int64:
			return true
		}
		return false
	}
	if !integer(sec) || !integer(nsec) || nsec.Int() < 0 || nsec.Int() >= 1_000_000_000 {
		return 0, 0, false
	}
	return sec.Int(), nsec.Int(), true
}

// ConsumerToken binds the forwarded FGA configuration to the owning process's
// explicit credential pair. The retained developer service has one fixed URL.
func ConsumerToken(ctx context.Context, endpoint, file string) (string, error) {
	ownedURL := os.Getenv("ZASP_P6_NATIVE_OPENFGA_URL")
	ownedFile := os.Getenv("ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE")
	if ownedURL != "" || ownedFile != "" {
		if endpoint != ownedURL || file != ownedFile {
			return "", errors.New("forwarded OpenFGA fixture does not match its owner")
		}
		return ReadOwnedToken(ownedURL, ownedFile)
	}
	if endpoint != "http://127.0.0.1:8088" || file != "/test/in-memory-only" {
		return "", errors.New("unknown retained OpenFGA fixture")
	}
	data, err := exec.CommandContext(ctx, "docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		return "", errors.New("retained OpenFGA fixture unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		return "", errors.New("invalid retained OpenFGA fixture")
	}
	for _, entry := range containers[0].Config.Env {
		if token, ok := strings.CutPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS="); ok && token != "" && !strings.Contains(token, ",") {
			return token, nil
		}
	}
	return "", errors.New("retained OpenFGA credential unavailable")
}
