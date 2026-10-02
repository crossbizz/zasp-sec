package apiserver

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Regressions: a real HOME, implicit module cache, ambient PG files, or Node26
// from a global PATH must not enter this controlled Node22 fixture.
func TestSingleTestRecoveryNativeDriverEnvironment(t *testing.T) {
	home := t.TempDir()
	got := map[string]string{}
	for _, entry := range singleRecoveryChildEnvironment(home, map[string]string{"OPENAI_API_KEY": "controlled-excluded", "HOME": "/not-owned", "ZASP_SINGLE_RECOVERY_NATIVE_RUN": "owned-run"}) {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatal("invalid environment")
		}
		if _, exists := got[k]; exists {
			t.Fatal("duplicate environment key", k)
		}
		got[k] = v
	}
	want := map[string]string{
		"HOME": home, "XDG_CONFIG_HOME": filepath.Join(home, ".config"), "XDG_CACHE_HOME": filepath.Join(home, ".cache"),
		"PATH":       "/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/Users/manishmaheshwari/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.13.darwin-arm64/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"GOMODCACHE": "/Users/manishmaheshwari/go/pkg/mod", "GOCACHE": filepath.Join(home, "go-build"),
		"LC_ALL": "C", "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOMAXPROCS": "2",
		"PGPASSFILE": "/dev/null", "PGSERVICEFILE": "/dev/null", "PGSERVICE": "", "PGPASSWORD": "", "PGSSLMODE": "disable", "PGSSLCERT": "/dev/null", "PGSSLKEY": "/dev/null", "PGSSLROOTCERT": "/dev/null",
		"ZASP_SINGLE_RECOVERY_NATIVE_RUN": "owned-run",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("child environment is not the exact isolated tool/cache/PG boundary")
	}
}

func TestSingleTestRecoveryWorkerCompileEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOCACHE", "/ambient/cache-must-not-enter")
	runtimeEnv := map[string]string{}
	for _, entry := range singleRecoveryChildEnvironment(home, nil) {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || runtimeEnv[key] != "" {
			t.Fatal("runtime environment shape")
		}
		runtimeEnv[key] = value
	}
	binary := filepath.Join(t.TempDir(), "recovery-worker.test")
	controlledCache := filepath.Join(t.TempDir(), "controlled-cache")
	cmd, err := singleRecoveryWorkerCompileCommandForCache(home, binary, controlledCache)
	if err != nil {
		t.Fatal("controlled compile environment unavailable", err)
	}
	compileEnv := map[string]string{}
	for _, entry := range cmd.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatal("compile environment shape")
		}
		if _, exists := compileEnv[key]; exists {
			t.Fatal("duplicate compile environment key", key)
		}
		compileEnv[key] = value
	}
	if runtimeEnv["GOCACHE"] != filepath.Join(home, "go-build") || compileEnv["GOCACHE"] != controlledCache {
		t.Fatal("compile cache did not replace exactly the runtime cache", runtimeEnv["GOCACHE"], compileEnv["GOCACHE"])
	}
	delete(runtimeEnv, "GOCACHE")
	delete(compileEnv, "GOCACHE")
	if !reflect.DeepEqual(compileEnv, runtimeEnv) {
		t.Fatal("compile environment changed a runtime isolation value")
	}
	wantGo := filepath.Join(runtime.GOROOT(), "bin", "go")
	wantArgs := []string{wantGo, "test", "-mod=readonly", "-p=1", "-c", "-o", binary, "./agentsec-worker"}
	if cmd.Path != wantGo || !reflect.DeepEqual(cmd.Args, wantArgs) || cmd.Dir != ".." {
		t.Fatal("worker compile tool, command, or source changed", cmd.Path, cmd.Args, cmd.Dir)
	}
}

func TestSingleTestRecoveryWorkerCompileCacheAvailability(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	if err := singleRecoveryCompileCacheAvailable(missing); err == nil || strings.Contains(err.Error(), missing) {
		t.Fatal("missing cache did not fail closed with a static error")
	}
	cache := filepath.Join(root, "cache")
	if err := os.Mkdir(cache, 0700); err != nil || singleRecoveryCompileCacheAvailable(cache) != nil {
		t.Fatal("owned cache directory refused", err)
	}
	link := filepath.Join(root, "cache-link")
	if err := os.Symlink(cache, link); err != nil {
		t.Fatal(err)
	}
	if err := singleRecoveryCompileCacheAvailable(link); err == nil {
		t.Fatal("symlinked compile cache accepted")
	}
}

func TestSingleTestRecoveryWorkerCompileFailureCategories(t *testing.T) {
	deadline, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	secret := errors.New("secret compiler payload")
	for _, test := range []struct {
		name string
		ctx  context.Context
		err  error
		want string
	}{
		{"deadline-context", deadline, secret, "worker test compilation deadline"},
		{"deadline-error", context.Background(), context.DeadlineExceeded, "worker test compilation deadline"},
		{"canceled-context", canceled, secret, "worker test compilation canceled"},
		{"canceled-error", context.Background(), context.Canceled, "worker test compilation canceled"},
		{"failed", context.Background(), secret, "worker test compilation failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := singleRecoveryCompileFailure(test.ctx, test.err)
			if got == nil || got.Error() != test.want || strings.Contains(got.Error(), "secret") {
				t.Fatal("compile failure classification", got)
			}
		})
	}
}

// This invokes the actual parser, without connecting. Every potentially read
// content file is controlled here before parsing, including on the RED path.
func TestSingleTestRecoveryNativeDriverParserIsolation(t *testing.T) {
	fake := t.TempDir()
	pass := filepath.Join(fake, "pass")
	service := filepath.Join(fake, "service")
	cert := filepath.Join(fake, "cert")
	for path, body := range map[string]string{pass: "127.0.0.1:17233:postgres:zasp_test:controlled-password\n", service: "[controlled]\napplication_name=ambient-service\n", cert: "controlled invalid certificate\n"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, boundary := range []string{"child", "parent"} {
		t.Run(boundary, func(t *testing.T) {
			for _, mode := range []string{"pass", "service", "certificate"} {
				t.Run(mode, func(t *testing.T) {
					// Never let a missing safeguard fall back to real account content in RED.
					t.Setenv("PGPASSFILE", pass)
					t.Setenv("PGSERVICEFILE", service)
					t.Setenv("PGSERVICE", "")
					t.Setenv("PGPASSWORD", "")
					t.Setenv("PGSSLMODE", "disable")
					t.Setenv("PGSSLCERT", cert)
					t.Setenv("PGSSLKEY", cert)
					t.Setenv("PGSSLROOTCERT", cert)
					if mode == "service" {
						t.Setenv("PGSERVICE", "controlled")
					}
					if mode == "certificate" {
						t.Setenv("PGSSLMODE", "require")
					}
					if boundary == "parent" {
						singleRecoveryIsolateParent(t, t.TempDir())
					} else {
						for _, entry := range singleRecoveryChildEnvironment(t.TempDir(), nil) {
							k, v, _ := strings.Cut(entry, "=")
							if strings.HasPrefix(k, "PG") {
								t.Setenv(k, v)
							}
						}
					}
					dsn, err := singleRecoveryOwnedDSN("postgres://zasp_test@127.0.0.1:17233/postgres?sslmode=disable")
					if err != nil {
						t.Fatal("owned DSN construction")
					}
					cfg, err := pgx.ParseConfig(dsn)
					if err != nil {
						t.Fatal("owned parser consumed controlled ambient configuration")
					}
					if cfg.Password != "" || cfg.RuntimeParams["application_name"] != "" || cfg.TLSConfig != nil || len(cfg.Fallbacks) != 0 || cfg.Host != "127.0.0.1" || cfg.Port != 17233 {
						t.Fatal("ambient PG input influenced owned connection")
					}
					// The fixture reparses ConnString for API/worker pools, then selects its
					// registered role. These derived connections must keep every isolation key.
					for _, role := range []string{"worker_test_executor", "worker_test_compensation", "ordered_test_red_adapter"} {
						derived, err := pgx.ParseConfig(cfg.ConnString())
						if err != nil {
							t.Fatal("derived connection lost isolation")
						}
						derived.User = role
						if derived.User != role || derived.Host != "127.0.0.1" || derived.Port != 17233 || derived.Database != "postgres" || derived.Password != "" || derived.TLSConfig != nil || len(derived.Fallbacks) != 0 {
							t.Fatal("derived role connection changed boundary")
						}
					}
				})
			}
		})
	}
	for _, raw := range []string{"postgres://zasp_test@remote.invalid:17233/postgres?sslmode=disable", "postgres" + "://zasp_test:controlled@127.0.0.1:17233/postgres?sslmode=disable", "postgres://zasp_test@127.0.0.1:17233/postgres?sslmode=disable&service=controlled", "postgres://zasp_test@127.0.0.1:17233/other?sslmode=disable"} {
		if _, err := singleRecoveryOwnedDSN(raw); err == nil {
			t.Fatal("non-owned DSN admitted")
		}
	}
}
