package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var errLocalOpenFGAFixture = errors.New("local OpenFGA fixture rejected")

// Native source services opt in with a token-file selector. Without selectors,
// retain the inspected Compose container as the development fixture authority.
func localOpenFGAConnection(t *testing.T) (string, string) {
	t.Helper()
	endpoint, token, selected, err := selectLocalOpenFGAConnection(os.Getenv("ZASP_LOCAL_OPENFGA_TOKEN_FILE"), os.Getenv("ZASP_LOCAL_OPENFGA_URL"))
	if err != nil {
		t.Fatal(errLocalOpenFGAFixture)
	}
	if selected {
		return endpoint, token
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, "docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		t.Fatal("retained OpenFGA container unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		t.Fatal("local service inspection failed")
	}
	for _, entry := range containers[0].Config.Env {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		t.Fatal("local service credential not found or ambiguous")
	}
	return endpoint, token
}

func selectLocalOpenFGAConnection(tokenFile, endpoint string) (string, string, bool, error) {
	if tokenFile == "" && endpoint == "" {
		return "http://127.0.0.1:8088", "", false, nil
	}
	refuse := func() (string, string, bool, error) { return "", "", true, errLocalOpenFGAFixture }
	if tokenFile == "" || !filepath.IsAbs(tokenFile) {
		return refuse()
	}
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8088"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" {
		return refuse()
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return refuse()
	}
	info, err := os.Lstat(tokenFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		return refuse()
	}
	payload, err := os.ReadFile(tokenFile)
	if err != nil || len(payload) > 4096 {
		return refuse()
	}
	token := strings.TrimSpace(string(payload))
	if token == "" || strings.ContainsAny(token, ", \t\r\n") {
		return refuse()
	}
	return endpoint, token, true, nil
}

func TestLocalOpenFGASelectorUsesExplicitFileAndKeepsDockerDefault(t *testing.T) {
	endpoint, token, selected, err := selectLocalOpenFGAConnection("", "")
	if err != nil || selected || endpoint != "http://127.0.0.1:8088" || token != "" {
		t.Fatal("default inspected Docker fixture changed")
	}
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("local-fixture-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"", "http://127.0.0.1:8088", "http://[::1]:8088"} {
		got, token, selected, err := selectLocalOpenFGAConnection(file, endpoint)
		if err != nil || !selected || token != "local-fixture-token" || got == "" {
			t.Fatal("explicit loopback token-file fixture rejected")
		}
	}
}

func TestLocalOpenFGASelectorRejectsRemoteOrAmbiguousEndpoints(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("local-fixture-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"http://example.com:8088", "http://localhost:8088", "http://0.0.0.0:8088", "https://127.0.0.1:8088", "http://token@127.0.0.1:8088", "http://127.0.0.1:8088?token=value", "http://127.0.0.1:8088#value", "http://127.0.0.1:8088/path", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1"} {
		if _, _, selected, err := selectLocalOpenFGAConnection(file, endpoint); !selected || !errors.Is(err, errLocalOpenFGAFixture) {
			t.Fatal("unsafe endpoint reached local fixture")
		}
	}
	if _, _, selected, err := selectLocalOpenFGAConnection("", "http://127.0.0.1:8088"); !selected || !errors.Is(err, errLocalOpenFGAFixture) {
		t.Fatal("endpoint-only selector fell back to Docker")
	}
}

func TestLocalOpenFGASelectorRejectsUnsafeFilesWithoutFallback(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid")
	if err := os.WriteFile(valid, []byte("local-fixture-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	paths := []string{"relative-token", filepath.Join(directory, "missing"), directory, symlink}
	for _, tc := range []struct {
		name, payload string
		mode          os.FileMode
	}{{"empty", "", 0o600}, {"large", strings.Repeat("x", 4097), 0o600}, {"group-readable", "local-fixture-token", 0o640}, {"ambiguous", "first,second", 0o600}, {"whitespace", "first second", 0o600}} {
		path := filepath.Join(directory, tc.name)
		if err := os.WriteFile(path, []byte(tc.payload), tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	for _, path := range paths {
		if _, _, selected, err := selectLocalOpenFGAConnection(path, ""); !selected || !errors.Is(err, errLocalOpenFGAFixture) {
			t.Fatal("unsafe explicit file fell back to Docker")
		}
	}
}
