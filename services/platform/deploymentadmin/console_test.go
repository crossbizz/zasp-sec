package deploymentadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

const testPassword = "fixture-installation-password-32-characters"

func configured(t *testing.T, id, dsn, password string) *Config {
	t.Helper()
	private := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(private, []byte(password), 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"ZASP_PUBLIC_ORIGIN": "https://" + id + ".example.test", "ZASP_DEPLOYMENT_ADMIN_ID": id, "ZASP_DEPLOYMENT_ADMIN_DSN": dsn, "ZASP_DEPLOYMENT_ADMIN_PASSWORD_FILE": private}
	config, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// Each run creates an isolated server with two deployments on the same cluster.
// CI installs PG18 and runs this test under an unprivileged service user.
func consoleDatabases(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("initdb"); err != nil || os.Getuid() == 0 {
		t.Skip("requires PostgreSQL test binaries and an unprivileged user")
	}
	dir := t.TempDir()
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", name, err, out)
		}
	}
	run("initdb", "--no-sync", "--auth-local=trust", "--auth-host=trust", "-U", "fixture", "-D", dir)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	run("pg_ctl", "-D", dir, "-l", filepath.Join(dir, "server.log"), "-o", fmt.Sprintf("-h 127.0.0.1 -p %d -k %s", port, dir), "-w", "start")
	t.Cleanup(func() { run("pg_ctl", "-D", dir, "-m", "immediate", "-w", "stop") })
	dsn := fmt.Sprintf("postgres://fixture@127.0.0.1:%d/postgres?sslmode=disable", port)
	admin, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	for _, site := range []string{"sitea", "siteb"} {
		for _, q := range []string{"CREATE ROLE " + site + " LOGIN", "CREATE DATABASE " + site + " OWNER " + site, "REVOKE ALL ON DATABASE " + site + " FROM PUBLIC"} {
			if _, err = admin.Exec(t.Context(), q); err != nil {
				t.Fatal(err)
			}
		}
	}
	return fmt.Sprintf("postgres://%%s@127.0.0.1:%d/%%s?sslmode=disable", port)
}

func TestDeploymentConsole(t *testing.T) {
	layout := consoleDatabases(t)
	a := configured(t, "alpha", fmt.Sprintf(layout, "sitea", "sitea"), testPassword)
	b := configured(t, "beta", fmt.Sprintf(layout, "siteb", "siteb"), testPassword)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(418) })
	client := func(r *http.Request) string { return r.RemoteAddr }
	mount := func(c *Config) http.Handler {
		t.Helper()
		h, db, err := Mount(t.Context(), c, next, client)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return h
	}
	primary := mount(a)
	replica := mount(a)
	other := mount(b)
	// Neither another deployment nor a changed public origin may adopt this DB.
	for _, wrong := range []Config{{id: b.id, origin: a.origin, dsn: a.dsn}, {id: a.id, origin: b.origin, dsn: a.dsn}, {id: a.id, origin: a.origin, dsn: fmt.Sprintf(layout, "fixture", "sitea")}} {
		if _, db, err := Mount(t.Context(), &wrong, next, client); err == nil {
			db.Close()
			t.Fatal("accepted an incorrect installation or superuser login")
		}
	}
	var peer = "192.0.2.1:1234"
	call := func(h http.Handler, method, origin, path, body string, cookie *http.Cookie, csrf string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, origin+path, strings.NewReader(body))
		r.RemoteAddr = peer
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s %s: got %d %s, want %d", method, path, w.Code, w.Body.String(), want)
		}
		return w
	}
	sp, settings := basePath+"session", basePath+"settings"
	login := `{"password":"` + testPassword + `"}`
	call(primary, "GET", a.origin, "/api/v1/admin/members", "", nil, "", 418)
	call(primary, "GET", a.origin, settings, "", &http.Cookie{Name: "zasp_session", Value: "organization-admin"}, "", 401)
	call(primary, "POST", a.origin, sp, `{"password":"incorrect"}`, nil, "", 401)
	crossOrigin := httptest.NewRequest("POST", a.origin+sp, strings.NewReader(login))
	crossOrigin.Header.Set("Origin", b.origin)
	rr := httptest.NewRecorder()
	primary.ServeHTTP(rr, crossOrigin)
	if rr.Code != 403 {
		t.Fatal("cross-origin login accepted")
	}
	out := call(primary, "POST", a.origin, sp, login, nil, "", 200)
	cookie := out.Result().Cookies()[0]
	if cookie.Name != cookieName || !cookie.HttpOnly || !cookie.Secure || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 1800 {
		t.Fatal("invalid session cookie attributes")
	}
	var identity session
	if err := json.Unmarshal(out.Body.Bytes(), &identity); err != nil || identity.DeploymentID != a.id || identity.CSRF == "" {
		t.Fatal("invalid session snapshot")
	}
	call(other, "GET", b.origin, sp, "", cookie, "", 401)
	call(replica, "GET", a.origin, sp, "", cookie, "", 200)
	var before Settings
	if err := json.Unmarshal(call(replica, "GET", a.origin, settings, "", cookie, "", 200).Body.Bytes(), &before); err != nil || before.Version != 1 || before.DeploymentID != a.id {
		t.Fatal(before, err)
	}
	update := `{"version":1,"nango":{"api_url":"https://private.example.test","login_hint":"operator@example.test","credential_ref":"vault://secret/service/nango#operator"},"opensearch":{"api_url":"http://search.internal.svc:9200"}}`
	call(primary, "PUT", a.origin, settings, update, cookie, "", 403)
	call(primary, "PUT", a.origin, settings, update, cookie, "forged", 403)
	call(primary, "PUT", a.origin, settings, strings.Replace(update, "\"version\":1", "\"deployment_id\":\"beta\",\"version\":1", 1), cookie, identity.CSRF, 400)
	call(primary, "PUT", a.origin, settings, strings.Replace(update, "\"login_hint\":", "\"password\":", 1), cookie, identity.CSRF, 400)
	// Only one writer can replace the version observed above.
	var writers sync.WaitGroup
	results := make(chan int, 2)
	for _, handler := range []http.Handler{primary, replica} {
		writers.Go(func() {
			r := httptest.NewRequest("PUT", a.origin+settings, strings.NewReader(update))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", a.origin)
			r.Header.Set("X-CSRF-Token", identity.CSRF)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			results <- w.Code
		})
	}
	writers.Wait()
	codes := map[int]int{}
	codes[<-results]++
	codes[<-results]++
	if codes[200] != 1 || codes[409] != 1 {
		t.Fatalf("concurrent writers %v", codes)
	}
	read := call(mount(a), "GET", a.origin, settings, "", cookie, "", 200)
	if !bytes.Contains(read.Body.Bytes(), []byte("operator@example.test")) || strings.Contains(read.Body.String(), testPassword) || read.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("settings persistence or privacy headers")
	}
	rotated := configured(t, a.id, a.dsn, "rotated-fixture-password-at-least-32")
	call(mount(rotated), "GET", a.origin, sp, "", cookie, "", 401)
	call(primary, "DELETE", a.origin, sp, "", cookie, "", 403)
	call(primary, "DELETE", a.origin, sp, "", cookie, identity.CSRF, 204)
	call(replica, "GET", a.origin, settings, "", cookie, "", 401)
	expiring := call(primary, "POST", a.origin, sp, login, nil, "", 200).Result().Cookies()[0]
	connection, err := pgx.Connect(t.Context(), a.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	if _, err := connection.Exec(t.Context(), "UPDATE deployment_console.sessions SET expires_at = now() - interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	call(replica, "GET", a.origin, settings, "", expiring, "", 401)
	peer = "198.51.100.2:443"
	for i := 0; i < 6; i++ {
		call(primary, "POST", a.origin, sp, `{"password":"incorrect"}`, nil, "", 401)
	}
	limited := call(replica, "POST", a.origin, sp, login, nil, "", 429)
	if limited.Header().Get("Retry-After") == "" {
		t.Fatal("missing throttle cooldown")
	}
}

func TestDeploymentAdminPointersAndDisabledRoute(t *testing.T) {
	for _, value := range []string{"http://example.org", "https://user:pass@example.org", "https://example.org/?token=secret", "https://example.org/#password", "javascript:alert(1)", "//example.org"} {
		if (Pointer{APIURL: value}).valid() {
			t.Errorf("accepted unsafe URL %q", value)
		}
	}
	for _, ref := range []string{"token-value", "Bearer somevalue", "kubernetes://production/secret?key"} {
		if (Pointer{CredentialRef: ref}).valid() {
			t.Errorf("accepted invalid credential reference %q", ref)
		}
	}
	for _, ref := range []string{"kubernetes://production/lookup#username", "vault://kv/service/search#operator", "arn:aws:secretsmanager:us-east-1:123456789012:secret:services/search"} {
		if !(Pointer{CredentialRef: ref}).valid() {
			t.Errorf("rejected reference %q", ref)
		}
	}
	if (Pointer{LoginHint: "password is secret"}).valid() {
		t.Error("accepted freeform secret material")
	}
	h, closer, err := Mount(t.Context(), nil, http.NotFoundHandler(), nil)
	if closer != nil || err != nil {
		t.Fatal("disabled mount failed")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", basePath+"session", nil))
	if w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("disabled console must fail closed")
	}
}

func TestConsoleCredentialLoadingFailsClosed(t *testing.T) {
	dir := t.TempDir()
	password, dsn := filepath.Join(dir, "password"), filepath.Join(dir, "database-url")
	for path, value := range map[string]string{password: testPassword, dsn: "postgres://operator:db-password@db.example.test/console?sslmode=verify-full"} {
		if err := os.WriteFile(path, []byte(value+"\n"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	env := map[string]string{
		"ZASP_DEPLOYMENT_ADMIN_ID": "installation-a", "ZASP_PUBLIC_ORIGIN": "https://a.example.test",
		"ZASP_DEPLOYMENT_ADMIN_PASSWORD_FILE": password, "ZASP_DEPLOYMENT_ADMIN_DSN_FILE": dsn,
	}
	read := func() (*Config, error) { return Load(func(key string) string { return env[key] }) }
	if _, err := read(); err != nil {
		t.Fatal("valid projected credential pair rejected")
	}
	for _, bad := range []string{"postgres://operator@db.example.test/db?sslmode=disable", "postgres://operator@127.0.0.1/db?host=db.example.test&sslmode=disable", "postgres://operator@db.example.test/db?sslmode=verify-full&sslmode=disable"} {
		if err := os.WriteFile(dsn, []byte(bad), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := read(); err == nil {
			t.Fatal("unsafe connection configuration accepted")
		}
	}
	if err := os.WriteFile(dsn, []byte("postgres://operator@db.example.test/db?sslmode=verify-full"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(password, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := read(); err == nil {
		t.Fatal("world-readable operator password accepted")
	}
	delete(env, "ZASP_DEPLOYMENT_ADMIN_PASSWORD_FILE")
	if _, err := read(); err == nil {
		t.Fatal("incomplete configuration accepted")
	}
}
