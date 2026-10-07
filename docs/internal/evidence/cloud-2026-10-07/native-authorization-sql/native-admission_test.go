package apiserver

import (
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type authorizationProjectionCredentials struct{ url, token, tokenFile string }

// Native selection is explicit: partial or refused native inputs never fall
// back to retained Docker discovery. These credentials belong to the owned
// test lifetime; selection alone is not SQL/API or native-runtime acceptance.
func resolveAuthorizationProjectionCredentials(getenv func(string) string, legacy func() (authorizationProjectionCredentials, error)) (authorizationProjectionCredentials, error) {
	refused := errors.New("native projection fixture credentials refused")
	if getenv == nil || legacy == nil {
		return authorizationProjectionCredentials{}, refused
	}
	endpoint, path := getenv("ZASP_P6_NATIVE_OPENFGA_URL"), getenv("ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE")
	if endpoint == "" && path == "" {
		return legacy()
	}
	if endpoint == "" || path == "" || len(endpoint) > 512 || len(path) > 4096 {
		return authorizationProjectionCredentials{}, refused
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || u.String() != endpoint {
		return authorizationProjectionCredentials{}, refused
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != u.Port() || u.Host != net.JoinHostPort(u.Hostname(), strconv.Itoa(port)) {
		return authorizationProjectionCredentials{}, refused
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return authorizationProjectionCredentials{}, refused
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return authorizationProjectionCredentials{}, refused
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != uint32(os.Getuid()) {
		return authorizationProjectionCredentials{}, refused
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return authorizationProjectionCredentials{}, refused
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || (before.Mode().Perm() != 0400 && before.Mode().Perm() != 0600) || before.Size() < 8 || before.Size() > 4096 {
		return authorizationProjectionCredentials{}, refused
	}
	info, ok := before.Sys().(*syscall.Stat_t)
	if !ok || info.Uid != uint32(os.Getuid()) || info.Nlink != 1 {
		return authorizationProjectionCredentials{}, refused
	}
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	after, statErr := file.Stat()
	live, pathErr := os.Lstat(path)
	if err != nil || statErr != nil || pathErr != nil || int64(len(body)) != before.Size() || !sameProjectionTokenIdentity(before, after) || !sameProjectionTokenIdentity(before, live) {
		return authorizationProjectionCredentials{}, refused
	}
	for _, b := range body {
		if b < 33 || b > 126 || b == ',' {
			return authorizationProjectionCredentials{}, refused
		}
	}
	if err := file.Close(); err != nil {
		return authorizationProjectionCredentials{}, refused
	}
	return authorizationProjectionCredentials{url: endpoint, token: string(body), tokenFile: path}, nil
}

func sameProjectionTokenIdentity(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	y, ok := b.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	xs, xn, xok := projectionTokenChangeTime(x)
	ys, yn, yok := projectionTokenChangeTime(y)
	return xok && yok && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && a.ModTime().Equal(b.ModTime()) && xs == ys && xn == yn
}

// Linux and Darwin expose the same kernel ctime using different Stat_t field
// names. Admit only their known seconds/nanoseconds grammar; unknown layouts
// refuse instead of silently dropping the change-time check.
func projectionTokenChangeTime(stat *syscall.Stat_t) (int64, int64, bool) {
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

func TestAuthorizationProjectionNativeCredentialAdmission(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "token")
	token := strings.Repeat("n", 32)
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	legacyCalls := 0
	legacy := func() (authorizationProjectionCredentials, error) {
		legacyCalls++
		return authorizationProjectionCredentials{url: "http://127.0.0.1:8088", token: "legacy", tokenFile: "/test/in-memory-only"}, nil
	}
	get := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	t.Run("explicit_native", func(t *testing.T) {
		before := legacyCalls
		pins, err := resolveAuthorizationProjectionCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path}), legacy)
		if err != nil {
			t.Fatal(err)
		}
		if pins.url != "http://127.0.0.1:18088" || pins.token != token || pins.tokenFile != path || legacyCalls != before {
			t.Fatal("explicit native fixture was not selected")
		}
	})
	t.Run("legacy_unchanged", func(t *testing.T) {
		before := legacyCalls
		pins, err := resolveAuthorizationProjectionCredentials(get(nil), legacy)
		if err != nil || pins.url != "http://127.0.0.1:8088" || pins.token != "legacy" || legacyCalls != before+1 {
			t.Fatal("legacy fixture changed")
		}
	})
	t.Run("no_fallback_on_native_refusal", func(t *testing.T) {
		for _, v := range []map[string]string{
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088"},
			{"ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://remote.invalid:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088/path", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088?private=not-for-errors", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://u:secret@127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088#fragment", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:0", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:018088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:65536", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://::1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path},
			{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": "relative-token"},
		} {
			before := legacyCalls
			_, err := resolveAuthorizationProjectionCredentials(get(v), legacy)
			if err == nil || legacyCalls != before || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "not-for-errors") {
				t.Fatal("native refusal fell back or leaked input")
			}
		}
	})
	t.Run("private_token_only", func(t *testing.T) {
		for _, mode := range []os.FileMode{0644, 0640, 0000} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			before := legacyCalls
			_, err := resolveAuthorizationProjectionCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path}), legacy)
			if err == nil || legacyCalls != before {
				t.Fatal("unsafe native token was admitted")
			}
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "token-link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		_, err := resolveAuthorizationProjectionCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": link}), legacy)
		if err == nil {
			t.Fatal("symlink token admitted")
		}
	})
	t.Run("owned_readonly_ipv6", func(t *testing.T) {
		if err := os.WriteFile(path, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0400); err != nil {
			t.Fatal(err)
		}
		pins, err := resolveAuthorizationProjectionCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://[::1]:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path}), legacy)
		if err != nil || pins.url != "http://[::1]:18088" || pins.token != token {
			t.Fatal("owned readonly IPv6 fixture refused")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("nonexclusive_or_nonregular_token", func(t *testing.T) {
		alias := filepath.Join(root, "hardlink")
		if err := os.Link(path, alias); err != nil {
			t.Fatal(err)
		}
		for _, candidate := range []string{path, alias, root, filepath.Join(root, "missing")} {
			before := legacyCalls
			_, err := resolveAuthorizationProjectionCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": candidate}), legacy)
			if err == nil || legacyCalls != before {
				t.Fatal("nonexclusive or nonregular token admitted")
			}
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("invalid_token_bytes", func(t *testing.T) {
		for _, body := range []string{"short", strings.Repeat("n", 4097), "native token", "native\ntoken", "native,token"} {
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := resolveAuthorizationProjectionCredentials(get(map[string]string{"ZASP_P6_NATIVE_OPENFGA_URL": "http://127.0.0.1:18088", "ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE": path}), legacy)
			if err == nil {
				t.Fatal("invalid native token admitted")
			}
		}
	})
}
