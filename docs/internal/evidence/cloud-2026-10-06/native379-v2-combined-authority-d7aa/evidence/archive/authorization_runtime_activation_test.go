package apiserver

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A fresh process isolates the existing private OnceValues variable from other
// tests. The phase probe wraps the real compiled-pin loader, rather than warming
// its cache in a readiness fixture or adding a production injection mechanism.
func TestP7AuthorizationActivationPreparesRuntimePins(t *testing.T) {
	const marker = "ZASP_TEST_AUTHORIZATION_ACTIVATION_CHILD"
	if os.Getenv(marker) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestP7AuthorizationActivationPreparesRuntimePins$", "-test.v")
		command.Env = append(os.Environ(), marker+"=1")
		output, err := command.CombinedOutput()
		t.Logf("fresh-process activation checks:\n%s", output)
		if err != nil {
			t.Fatalf("activation child: %v", err)
		}
		return
	}
	original := authorizationRuntimeChecksums
	defer func() { authorizationRuntimeChecksums = original }()
	var loads atomic.Int32
	firstDriver := &guardedReadinessDriver{t: t, independent: true, production: true}
	first, _ := NewPostgresJSONDatabase(firstDriver)
	defer first.Close()
	authorizationRuntimeChecksums = sync.OnceValues(func() (string, string) {
		loads.Add(1)
		if first.currentAuthorization {
			t.Error("compiled pins first loaded after enforcement enabled")
		}
		return original()
	})
	t.Run("invalid activation does not initialize or enable", func(t *testing.T) {
		if (*PostgresJSONDatabase)(nil).RequireCurrentAuthorization() != ErrRepositoryConfiguration {
			t.Fatal("nil activation")
		}
		unsupported, _ := NewPostgresJSONDatabase(&databaseDriver{})
		defer unsupported.Close()
		if unsupported.RequireCurrentAuthorization() != ErrRepositoryConfiguration || unsupported.currentAuthorization {
			t.Fatal("unsupported activation")
		}
		closed, _ := NewPostgresJSONDatabase(&guardedReadinessDriver{t: t})
		_ = closed.Close()
		if closed.RequireCurrentAuthorization() != ErrRepositoryConfiguration || closed.currentAuthorization {
			t.Fatal("closed activation")
		}
		if loads.Load() != 0 || firstDriver.calls != 0 {
			t.Fatal("invalid activation initialized or queried")
		}
	})
	t.Run("valid activation prepares real immutable pins before mode", func(t *testing.T) {
		if first.RequireCurrentAuthorization() != nil {
			t.Fatal("activation")
		}
		if loads.Load() != 1 || !first.currentAuthorization || firstDriver.calls != 0 {
			t.Fatalf("loads=%d mode=%t queries=%d", loads.Load(), first.currentAuthorization, firstDriver.calls)
		}
		checksum, audit := authorizationRuntimeChecksums()
		if checksum != migrations.ProductionAuthorizationEnforcement().Checksum() || audit != migrations.AuthorizationAuditProfileChecksum() {
			t.Fatal("immutable source-derived pins differ")
		}
		firstDriver.args = []any{checksum, audit, strings.Repeat("a", 64), "zasp_discovery_api"}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := first.CurrentAuthorizationRuntimeReady(ctx, "zasp_discovery_api", strings.Repeat("a", 64)); err != nil {
			t.Fatal(err)
		}
		if loads.Load() != 1 || firstDriver.calls != 1 {
			t.Fatal("readiness rebuilt pins or skipped live query")
		}
	})
	t.Run("concurrent activation uses one compiled pin load", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d := &guardedReadinessDriver{t: t, independent: true, production: true}
				db, _ := NewPostgresJSONDatabase(d)
				defer db.Close()
				if db.RequireCurrentAuthorization() != nil || db.RequireCurrentAuthorization() != nil {
					t.Error("concurrent activation")
				}
				checksum, audit := authorizationRuntimeChecksums()
				d.args = []any{checksum, audit, strings.Repeat("a", 64), "zasp_security_agent_api"}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := db.CurrentAuthorizationRuntimeReady(ctx, "zasp_security_agent_api", strings.Repeat("a", 64)); err != nil || d.calls != 1 {
					t.Error("concurrent live readiness")
				}
			}()
		}
		wg.Wait()
		if loads.Load() != 1 {
			t.Fatalf("loads=%d", loads.Load())
		}
	})
	t.Run("prepared pins retain context identity and query result guards", func(t *testing.T) {
		for _, name := range []string{"expired", "wrong role", "short key", "uppercase key", "independent refused", "profile refused", "scan error", "late cancel", "closed", "non enforcing"} {
			t.Run(name, func(t *testing.T) {
				driver := &guardedReadinessDriver{t: t, independent: name != "independent refused", production: name != "profile refused", fail: name == "scan error"}
				db, _ := NewPostgresJSONDatabase(driver)
				defer db.Close()
				if name != "non enforcing" {
					if db.RequireCurrentAuthorization() != nil {
						t.Fatal("activation")
					}
				}
				role, key := "zasp_discovery_api", strings.Repeat("a", 64)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				switch name {
				case "expired":
					cancel()
				case "wrong role":
					role = "zasp_security_agent_worker"
				case "short key":
					key = "a"
				case "uppercase key":
					key = strings.Repeat("A", 64)
				case "late cancel":
					driver.cancel = cancel
				case "closed":
					_ = db.Close()
				}
				checksum, audit := authorizationRuntimeChecksums()
				driver.args = []any{checksum, audit, key, role}
				if !errors.Is(db.CurrentAuthorizationRuntimeReady(ctx, role, key), ErrRepositoryUnavailable) {
					t.Fatal("guard accepted")
				}
				want := 1
				switch name {
				case "expired", "wrong role", "short key", "uppercase key", "closed", "non enforcing":
					want = 0
				}
				if driver.calls != want {
					t.Fatalf("queries=%d want=%d", driver.calls, want)
				}
			})
		}
		if loads.Load() != 1 {
			t.Fatal("guard checks reconstructed pins")
		}
	})
	t.Run("initialization panic leaves mode disabled and mutex unlocked", func(t *testing.T) {
		saved := authorizationRuntimeChecksums
		defer func() { authorizationRuntimeChecksums = saved }()
		var calls int
		authorizationRuntimeChecksums = sync.OnceValues(func() (string, string) { calls++; panic("controlled immutable loader failure") })
		db, _ := NewPostgresJSONDatabase(&guardedReadinessDriver{t: t})
		defer db.Close()
		for i := 0; i < 2; i++ {
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				_ = db.RequireCurrentAuthorization()
			}()
			if !panicked || db.currentAuthorization {
				t.Fatal("failed initialization enabled enforcement")
			}
			if !db.mu.TryLock() {
				t.Fatal("initialization retained mutex")
			}
			db.mu.Unlock()
		}
		if calls != 1 {
			t.Fatalf("panic loader calls=%d", calls)
		}
	})
}
