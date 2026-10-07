package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newAuthorizationProjectionFGA(t *testing.T, wrappers ...func(http.RoundTripper) http.RoundTripper) (*fga.OpenFgaClient, runtimeservices.Config) {
	t.Helper()
	pins, err := resolveAuthorizationProjectionCredentials(os.Getenv, legacyAuthorizationProjectionCredentials)
	if err != nil {
		t.Fatal(err)
	}
	token := pins.token
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	t.Cleanup(transport.CloseIdleConnections)
	var roundTripper http.RoundTripper = transport
	for _, wrap := range wrappers {
		roundTripper = wrap(roundTripper)
	}
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: pins.url, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: roundTripper, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
	if err != nil {
		t.Fatal("SDK initialization rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := client.CreateStore(ctx).Body(fga.ClientCreateStoreRequest{Name: "zasp-p6-owned-projection"}).Execute()
	if err != nil {
		t.Fatal("owned store creation failed")
	}
	if client.SetStoreId(store.Id) != nil {
		t.Fatal("store pin rejected")
	}
	modelData, err := os.ReadFile("../authorization/model.json")
	if err != nil {
		t.Fatal(err)
	}
	var model fga.ClientWriteAuthorizationModelRequest
	if json.Unmarshal(modelData, &model) != nil {
		t.Fatal("model invalid")
	}
	written, err := client.WriteAuthorizationModel(ctx).Body(model).Execute()
	if err != nil {
		t.Fatal("owned model publication rejected")
	}
	config := runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: "zasp-test", TaskQueue: "zasp-agent", DiscoveryTaskQueue: "zasp-discovery", FGAURL: pins.url, StoreID: store.Id, ModelID: written.AuthorizationModelId, FGATokenFile: pins.tokenFile, Timeout: 5 * time.Second}
	t.Logf("owned OpenFGA store=%s model=%s; active configuration unchanged", config.StoreID, config.ModelID)
	return client, config
}

func legacyAuthorizationProjectionCredentials() (authorizationProjectionCredentials, error) {
	data, err := exec.Command("docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		return authorizationProjectionCredentials{}, errors.New("retained local service unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		return authorizationProjectionCredentials{}, errors.New("local service inspection unavailable")
	}
	token := ""
	for _, entry := range containers[0].Config.Env {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		return authorizationProjectionCredentials{}, errors.New("local credential unavailable")
	}

	return authorizationProjectionCredentials{url: "http://127.0.0.1:8088", token: token, tokenFile: "/test/in-memory-only"}, nil
}

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
