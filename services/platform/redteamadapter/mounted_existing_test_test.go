package redteamadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This test process is mounted into the cached engine image. Only the customer
// transport and its secret provider are controlled; the HTTPS parser, HMAC,
// credential version, live lease resolution and invocation journal are real.
func TestMountedExistingTestAdapter(t *testing.T) {
	if os.Getenv("ZASP_RED_TEAM_RUNTIME_PROOF") != "true" {
		t.Skip("owned mounted runtime only")
	}
	if os.Getuid() != 1000 || os.Getgid() != 1000 {
		t.Fatal("owned container user required")
	}
	dsn, err := url.Parse(os.Getenv("ZASP_RED_TEAM_RUNTIME_DSN"))
	if err != nil || dsn.Scheme != "postgres" || dsn.Hostname() != "host.docker.internal" || dsn.Port() == "" || dsn.User.Username() != "zasp_e2e" || dsn.Path != "/postgres" || dsn.RawQuery != "sslmode=disable" {
		t.Fatal("owned database rejected")
	}
	mode := os.Getenv("ZASP_EXISTING_TEST_MOUNTED_RESPONSE")
	if mode != "pass" && mode != "fail" && mode != "engine_error" {
		t.Fatal("controlled response rejected")
	}
	run := os.Getenv("ZASP_RED_TEAM_RUNTIME_RUN_ID")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 220*time.Second)
	defer timeout()
	owner, err := pgx.Connect(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	dsn.User = url.User("zasp_e2e_red_team_adapter")
	connection, err := pgx.Connect(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	journal, err := NewPostgresInvocationJournal(ownedJournalDatabase{connection}, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	if err != nil || journal.Ready(ctx) != nil {
		t.Fatal("registered55 journal unavailable", err)
	}
	var mu sync.Mutex
	calls := 0
	secret := bytes.Repeat([]byte("s"), 64)
	customer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 65537))
		digest := sha256.Sum256(body)
		var committed bool
		err := owner.QueryRow(r.Context(), `SELECT count(*)=1 FROM zasp_security_agent_test_invocations WHERE test_run_id=$1 AND category='prompt_injection' AND state='started' AND request_digest=$2`, run, digest[:]).Scan(&committed)
		auth, authErr := AuthorizeTargetPayload(r.Context(), mustMountedCredentials(t, secret), "ref:red-team/target_e2e_0001", body)
		if readErr != nil || err != nil || !committed || authErr != nil || r.Header.Get("X-Zasp-Payload-Digest") != "sha256:"+hex.EncodeToString(digest[:]) || r.Header.Get("X-Zasp-Signature") != auth.Signature {
			t.Errorf("target authority rejected: committed=%v err=%v", committed, err)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if mode == "engine_error" {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"error":"controlled target unavailable"}`)
			return
		}
		if mode == "fail" {
			_, _ = io.WriteString(w, `{"output":"ZASP_RED_TEAM_PROMPT_INJECTION"}`)
		} else {
			_, _ = io.WriteString(w, `{"output":"I cannot comply with that unsafe request."}`)
		}
	}))
	defer customer.Close()
	invoker, err := newHTTPSInvoker(&http.Client{Transport: newRewriteRoundTripper(t, customer)}, mustMountedCredentials(t, secret), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte("r"), 64)
	handler, err := NewJournaledHandler(Config{WorkerToken: token, MaximumRequestBytes: 64 << 10}, journal, invoker, journal)
	if err != nil {
		t.Fatal(err)
	}
	const directory = "/var/run/secrets/zasp-red-team/"
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mounted-adapter"}, DNSNames: []string{"agentsec-red-team-adapter.zasp.svc.cluster.local"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}))
	}()
	defer func() {
		_ = server.Close()
		if err := <-done; err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	for name, body := range map[string][]byte{"adapter-ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "adapter-token": token} {
		if err := os.WriteFile(directory+name, body, 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(directory+"ready", []byte("registered55\n"), 0400); err != nil {
		t.Fatal(err)
	}
	<-ctx.Done()
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("expected exactly one durable target invocation, got %d", calls)
	}
}

type mountedSecretProvider struct{ secret []byte }

func (p mountedSecretProvider) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if aws.ToString(in.SecretId) != "zasp/red-team/targets/target_e2e_0001" || aws.ToString(in.VersionStage) != "AWSCURRENT" {
		return nil, ErrAdapter
	}
	return &secretsmanager.GetSecretValueOutput{SecretBinary: append([]byte(nil), p.secret...), VersionId: aws.String(strings.Repeat("1", 32))}, nil
}
func mustMountedCredentials(t *testing.T, secret []byte) *SecretsCredentialResolver {
	t.Helper()
	resolver, err := NewSecretsCredentialResolver(mountedSecretProvider{secret}, "zasp/red-team/targets", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}
