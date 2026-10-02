package apiserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// This catches missing command dispatch, wrong key derivation, replay revision
// churn, rotation without revocation fencing, and API self-registration.
func TestP7AuthorizationVerifierCLIProcess(t *testing.T) {
	for _, p := range []string{"go", "initdb", "postgres", "pg_ctl", "pg_isready"} {
		if _, err := exec.LookPath(p); err != nil {
			t.Fatalf("required owned-fixture program unavailable: %s", p)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "agentsec-migrate")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, "../agentsec-migrate").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	t.Log("built actual agentsec-migrate executable")
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("owned connection failed")
	}
	defer owner.Close(context.Background())
	migrateP7Authorization(t, ctx, owner)
	execute := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatal("owned verifier fixture setup failed")
		}
	}
	// Remove only the helper's disposable key. No real verifier is touched.
	execute("DELETE FROM zasp_authorization80.verifier")
	const org = "pid_80c11001-0000-4000-8000-000000000001"
	execute("INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Verifier CLI','verifier-cli.invalid')", org)
	secrets := make([]string, 2)
	keys := make([]*authorization.AttestationKey, 2)
	for i := range secrets {
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			t.Fatal("fixture entropy failed")
		}
		secrets[i] = hex.EncodeToString(value)
		keys[i], err = authorization.NewAttestationKey([]byte(secrets[i]))
		if err != nil {
			t.Fatal("fixture key rejected")
		}
	}
	apiURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("owned API configuration failed")
	}
	apiURL.User = url.User("auth80_api")
	invoke := func(label, database, principal, secret string, want int, wantMessage string) {
		t.Helper()
		c := exec.CommandContext(ctx, binary, "register-authorization-verifier")
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "ZASP_") {
				c.Env = append(c.Env, v)
			}
		}
		c.Env = append(c.Env, "ZASP_POSTGRES_DSN="+database, "ZASP_MIGRATION_DB_PRINCIPAL="+principal, "ZASP_WORKFLOW_SIGNING_KEY="+secret, "ZASP_MIGRATION_TIMEOUT=30s")
		var stdout, stderr bytes.Buffer
		c.Stdout = &stdout
		c.Stderr = &stderr
		err := c.Run()
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal("CLI failed to exit normally")
			}
			code = exit.ExitCode()
		}
		output := append(append([]byte{}, stdout.Bytes()...), stderr.Bytes()...)
		for i, s := range secrets {
			for _, private := range []string{s, string(keys[i].Verifier()), hex.EncodeToString(keys[i].Verifier()), base64.StdEncoding.EncodeToString(keys[i].Verifier())} {
				if bytes.Contains(output, []byte(private)) {
					t.Fatal("CLI disclosed verifier material")
				}
			}
		}
		if bytes.Contains(output, []byte(database)) {
			t.Fatal("CLI disclosed database configuration")
		}
		if code != want || stdout.Len() != 0 {
			t.Fatalf("%s: exit=%d expected=%d or nonempty stdout", label, code, want)
		}
		if want == 0 && stderr.Len() != 0 {
			t.Fatalf("%s: unexpected success stderr", label)
		}
		if want != 0 {
			lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
			if len(lines) != 1 || !strings.HasSuffix(lines[0], " "+wantMessage) {
				t.Fatalf("%s: error was not the fixed public message", label)
			}
		}
		t.Logf("actual CLI register-authorization-verifier %s: exit=%d stdout=%q stderr=%q secret_output=false", label, code, stdout.String(), stderr.String())
	}
	ready := func(key *authorization.AttestationKey, want bool) {
		t.Helper()
		var v bool
		if err := owner.QueryRow(ctx, "SELECT zasp_authorization80.key_ready($1)", key.Version()).Scan(&v); err != nil || v != want {
			t.Fatalf("key readiness wanted=%t got=%t", want, v)
		}
	}
	type revision struct{ desired, applied, outbox int64 }
	readRevision := func() revision {
		t.Helper()
		var r revision
		if err := owner.QueryRow(ctx, "SELECT desired,applied,(SELECT count(*) FROM zasp_authorization79.outbox WHERE organization_id=$1) FROM zasp_authorization79.organizations WHERE organization_id=$1", org).Scan(&r.desired, &r.applied, &r.outbox); err != nil {
			t.Fatal("revision read failed")
		}
		return r
	}
	ready(keys[0], false)
	initial := readRevision()
	invoke("first-registration", dsn, "zasp_e2e", secrets[0], 0, "")
	ready(keys[0], true)
	ready(keys[1], false)
	first := readRevision()
	if first.desired != initial.desired+1 || first.applied != initial.applied || first.outbox != initial.outbox+1 {
		t.Fatal("first registration did not touch exactly one pending revision")
	}
	invoke("missing-key", dsn, "zasp_e2e", "", 1, "release migration configuration rejected")
	invoke("exact-replay", dsn, "zasp_e2e", secrets[0], 0, "")
	if readRevision() != first {
		t.Fatal("same-key registration rewrote revision")
	}
	invoke("rotation", dsn, "zasp_e2e", secrets[1], 0, "")
	ready(keys[0], false)
	ready(keys[1], true)
	rotated := readRevision()
	if rotated.desired != first.desired+1 || rotated.applied != first.applied || rotated.outbox != first.outbox+1 {
		t.Fatal("rotation did not invalidate current revision")
	}
	invoke("rotation-replay", dsn, "zasp_e2e", secrets[1], 0, "")
	invoke("wrong-session-user", apiURL.String(), "zasp_e2e", secrets[0], 1, "release migration failed")
	invoke("API-self-registration", apiURL.String(), "auth80_api", secrets[0], 1, "release migration failed")
	if readRevision() != rotated {
		t.Fatal("replay or refused API changed revision")
	}
	ready(keys[0], false)
	ready(keys[1], true)
	var exact bool
	if err := owner.QueryRow(ctx, "SELECT count(*)=1 AND bool_and(version=$1 AND key=$2) FROM zasp_authorization80.verifier", keys[1].Version(), keys[1].Verifier()).Scan(&exact); err != nil || !exact {
		t.Fatal("stored verifier differs from application-derived key")
	}
	t.Logf("first registration/replay/rotation/API refusal: desired=%d -> %d -> %d, applied unchanged=%d; exact derived verifier stored once; no projection/FGA claim", initial.desired, first.desired, rotated.desired, rotated.applied)
}
