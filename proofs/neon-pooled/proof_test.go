package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var testPGEnvironmentVariables = []string{
	"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
	"PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT",
	"PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLNEGOTIATION",
	"PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS",
	"PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION", "PGCHANNELBINDING", "PGREQUIREAUTH",
}

func TestPooledNeonURLDerivesOrPreservesPoolerEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "postgresql direct endpoint",
			raw:  "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&channel_binding=require",
			want: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech/proof?sslmode=require&channel_binding=require",
		},
		{
			name: "postgres direct endpoint with explicit port",
			raw:  "postgres://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech:5432/proof?sslmode=verify-full",
			want: "postgres://proof-user:proof-pass@ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech:5432/proof?sslmode=verify-full",
		},
		{
			name: "already pooled endpoint",
			raw:  "postgresql://proof-user:proof-pass@ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech/proof?sslmode=verify-ca",
			want: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech/proof?sslmode=verify-ca",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := pooledNeonURL(test.raw)
			if err != nil {
				t.Fatalf("pooledNeonURL() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("pooledNeonURL() returned an unexpected URL")
			}
		})
	}
}

func TestPooledNeonURLRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "non Postgres protocol", raw: "https://ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require"},
		{name: "arbitrary host", raw: "postgresql://proof-user:proof-pass@database.example.com/proof?sslmode=require"},
		{name: "Neon suffix lookalike", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.neon.tech.example.com/proof?sslmode=require"},
		{name: "missing endpoint label", raw: "postgresql://proof-user:proof-pass@us-east-2.aws.neon.tech/proof?sslmode=require"},
		{name: "malformed endpoint label", raw: "postgresql://proof-user:proof-pass@ep_bad.us-east-2.aws.neon.tech/proof?sslmode=require"},
		{name: "missing TLS mode", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof"},
		{name: "weak TLS mode", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=prefer"},
		{name: "disabled TLS mode", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=disable"},
		{name: "ambiguous TLS modes", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&sslmode=disable"},
		{name: "ambiguous channel binding", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&channel_binding=require&channel_binding=disable"},
		{name: "unsafe channel binding", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&channel_binding=disable"},
		{name: "host override", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&host=database.example.com"},
		{name: "port override", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&port=6543"},
		{name: "service override", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&service=unsafe"},
		{name: "service file", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&servicefile=%2Ftmp%2Fservice"},
		{name: "passfile", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&passfile=%2Ftmp%2Fpass"},
		{name: "TLS root file", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&sslrootcert=%2Ftmp%2Froot"},
		{name: "TLS certificate file", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&sslcert=%2Ftmp%2Fcert"},
		{name: "TLS key file", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&sslkey=%2Ftmp%2Fkey"},
		{name: "arbitrary runtime option", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require&options=-c%20search_path%3Dunsafe"},
		{name: "missing user", raw: "postgresql://:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require"},
		{name: "missing password", raw: "postgresql://proof-user@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require"},
		{name: "empty password", raw: "postgresql://proof-user:@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require"},
		{name: "missing database", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/?sslmode=require"},
		{name: "fragment", raw: "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require#fragment"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := pooledNeonURL(test.raw); err == nil {
				t.Fatal("pooledNeonURL() accepted unsafe configuration")
			}
		})
	}
}

func TestRunConcurrentReadsStartsExactlyTenWorkersTogether(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	var active atomic.Int32
	var maximum atomic.Int32
	release := make(chan struct{})
	allEntered := make(chan struct{})

	read := func(context.Context) error {
		calls.Add(1)
		current := active.Add(1)
		updateMaximum(&maximum, current)
		if current == concurrentReadCount {
			close(allEntered)
		}
		<-release
		active.Add(-1)
		return nil
	}

	resultChannel := make(chan readRunResult, 1)
	go func() {
		resultChannel <- runConcurrentReads(context.Background(), read)
	}()

	select {
	case <-allEntered:
	case <-time.After(time.Second):
		t.Fatal("ten workers did not enter the read together")
	}
	close(release)

	result := <-resultChannel
	if calls.Load() != concurrentReadCount {
		t.Fatalf("read call count = %d, want %d", calls.Load(), concurrentReadCount)
	}
	if result.completed != concurrentReadCount {
		t.Fatalf("completed read count = %d, want %d", result.completed, concurrentReadCount)
	}
	if len(result.failures) != 0 {
		t.Fatalf("failure count = %d, want 0", len(result.failures))
	}
	if maximum.Load() < 2 {
		t.Fatalf("maximum concurrent reads = %d, want at least 2", maximum.Load())
	}
}

func TestRunConcurrentReadsCollectsEveryWorkerFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	read := func(context.Context) error {
		worker := calls.Add(1)
		if worker%2 == 0 {
			return fmt.Errorf("worker %d failed", worker)
		}
		return nil
	}

	result := runConcurrentReads(context.Background(), read)

	if calls.Load() != concurrentReadCount {
		t.Fatalf("read call count = %d, want %d", calls.Load(), concurrentReadCount)
	}
	if result.completed != concurrentReadCount/2 {
		t.Fatalf("completed read count = %d, want %d", result.completed, concurrentReadCount/2)
	}
	if len(result.failures) != concurrentReadCount/2 {
		t.Fatalf("failure count = %d, want %d", len(result.failures), concurrentReadCount/2)
	}
}

func TestRunConcurrentReadsRecoversWorkerPanics(t *testing.T) {
	t.Parallel()

	const panicSecret = "panic-secret-must-not-escape"
	var calls atomic.Int32
	read := func(context.Context) error {
		worker := calls.Add(1)
		if worker%2 == 0 {
			panic(panicSecret)
		}
		return nil
	}

	result := runConcurrentReads(context.Background(), read)

	if calls.Load() != concurrentReadCount {
		t.Fatalf("read call count = %d, want %d", calls.Load(), concurrentReadCount)
	}
	if result.completed != concurrentReadCount/2 {
		t.Fatalf("completed read count = %d, want %d", result.completed, concurrentReadCount/2)
	}
	if len(result.failures) != concurrentReadCount/2 {
		t.Fatalf("failure count = %d, want %d", len(result.failures), concurrentReadCount/2)
	}
	for _, failure := range result.failures {
		if !errors.Is(failure, errWorkerPanic) || strings.Contains(failure.Error(), panicSecret) {
			t.Fatalf("worker failure = %q, want fixed internal failure", failure)
		}
	}
}

func TestRunConcurrentReadsPassesCancellationToEveryWorker(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	read := func(ctx context.Context) error {
		calls.Add(1)
		return ctx.Err()
	}

	result := runConcurrentReads(ctx, read)

	if calls.Load() != concurrentReadCount {
		t.Fatalf("read call count = %d, want %d", calls.Load(), concurrentReadCount)
	}
	if result.completed != 0 {
		t.Fatalf("completed read count = %d, want 0", result.completed)
	}
	if len(result.failures) != concurrentReadCount {
		t.Fatalf("failure count = %d, want %d", len(result.failures), concurrentReadCount)
	}
	for _, failure := range result.failures {
		if !errors.Is(failure, context.Canceled) {
			t.Fatalf("worker failure = %v, want context cancellation", failure)
		}
	}
}

func TestExecuteProofClosesAfterCheckingNoAcquiredConnections(t *testing.T) {
	t.Parallel()

	pool := &recordingPool{maximumOverlap: 2}
	opener := func(_ context.Context, target validatedConnection) (proofPool, error) {
		if err := validateEffectivePGXConfig(target.config, target.expected); err != nil {
			t.Fatal("opener received a mismatched effective config")
		}
		return pool, nil
	}

	summary, err := executeProof(context.Background(), validDirectNeonURL(), opener)

	if err != nil {
		t.Fatalf("executeProof() error = %v", err)
	}
	if summary != successSummary {
		t.Fatalf("executeProof() summary = %q, want fixed success summary", summary)
	}
	if pool.readCalls.Load() != concurrentReadCount {
		t.Fatalf("pool read count = %d, want %d", pool.readCalls.Load(), concurrentReadCount)
	}
	if pool.acquiredChecks != 1 || pool.closedDuringAcquiredCheck {
		t.Fatal("acquired connections were not checked exactly once before close")
	}
	if pool.closeCalls != 1 {
		t.Fatalf("pool close count = %d, want 1", pool.closeCalls)
	}
}

func TestExecuteProofDoesNotOpenPoolForRejectedURL(t *testing.T) {
	t.Parallel()

	opened := false
	opener := func(context.Context, validatedConnection) (proofPool, error) {
		opened = true
		return &recordingPool{}, nil
	}

	if _, err := executeProof(context.Background(), "postgresql://database.example.com/proof?sslmode=require", opener); err == nil {
		t.Fatal("executeProof() accepted a rejected URL")
	}
	if opened {
		t.Fatal("executeProof() opened a pool for rejected configuration")
	}
}

func TestExecuteProofRejectsPGEnvironmentBeforeOpening(t *testing.T) {
	variables := []string{
		"PGHOST",
		"PGPORT",
		"PGDATABASE",
		"PGUSER",
		"PGPASSWORD",
		"PGSERVICEFILE",
		"PGPASSFILE",
	}
	for _, variable := range variables {
		t.Run(variable, func(t *testing.T) {
			clearPGEnvironment(t)
			t.Setenv(variable, "conflicting-value")
			opened := false
			opener := func(context.Context, validatedConnection) (proofPool, error) {
				opened = true
				return &recordingPool{}, nil
			}

			if _, err := executeProof(context.Background(), validDirectNeonURL(), opener); err == nil {
				t.Fatal("executeProof() accepted a PG environment override")
			}
			if opened {
				t.Fatal("executeProof() opened a pool with a PG environment override")
			}
		})
	}
}

func TestValidatedPGXConnectionPinsEffectiveDestinationAndTLS(t *testing.T) {
	clearPGEnvironment(t)

	target, err := validatedPGXConnection(validDirectNeonURL())
	if err != nil {
		t.Fatalf("validatedPGXConnection() error = %v", err)
	}
	config := target.config
	if config.Host != "ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech" {
		t.Fatal("effective pgx host did not match the derived pooled endpoint")
	}
	if config.Port != 5432 {
		t.Fatalf("effective pgx port = %d, want 5432", config.Port)
	}
	if config.User != "proof-user" || config.Password != "proof-pass" || config.Database != "proof" {
		t.Fatal("effective pgx identity did not match the explicit URL fields")
	}
	if config.TLSConfig == nil || config.TLSConfig.ServerName != config.Host || config.TLSConfig.InsecureSkipVerify {
		t.Fatal("effective pgx TLS did not verify the derived pooled hostname")
	}
	if config.TLSConfig.VerifyPeerCertificate != nil || len(config.Fallbacks) != 0 || len(config.RuntimeParams) != 0 {
		t.Fatal("effective pgx config retained a verification, host, or runtime fallback")
	}
	if config.ChannelBinding != "prefer" {
		t.Fatalf("effective channel binding = %q, want prefer", config.ChannelBinding)
	}
	if err := validateEffectivePGXConfig(config, target.expected); err != nil {
		t.Fatalf("validateEffectivePGXConfig() error = %v", err)
	}
}

func TestEffectivePGXValidationRejectsConnectionOverrides(t *testing.T) {
	clearPGEnvironment(t)
	target, err := validatedPGXConnection(validDirectNeonURL())
	if err != nil {
		t.Fatalf("validatedPGXConnection() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*pgx.ConnConfig)
	}{
		{name: "host", mutate: func(config *pgx.ConnConfig) { config.Host = "database.example.com" }},
		{name: "port", mutate: func(config *pgx.ConnConfig) { config.Port = 6543 }},
		{name: "user", mutate: func(config *pgx.ConnConfig) { config.User = "other-user" }},
		{name: "password", mutate: func(config *pgx.ConnConfig) { config.Password = "other-password" }},
		{name: "database", mutate: func(config *pgx.ConnConfig) { config.Database = "other-database" }},
		{name: "missing TLS", mutate: func(config *pgx.ConnConfig) { config.TLSConfig = nil }},
		{name: "unverified TLS", mutate: func(config *pgx.ConnConfig) { config.TLSConfig.InsecureSkipVerify = true }},
		{name: "TLS hostname", mutate: func(config *pgx.ConnConfig) { config.TLSConfig.ServerName = "database.example.com" }},
		{name: "TLS verifier", mutate: func(config *pgx.ConnConfig) {
			config.TLSConfig.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		}},
		{name: "fallback host", mutate: func(config *pgx.ConnConfig) {
			config.Fallbacks = []*pgconn.FallbackConfig{{Host: config.Host, Port: config.Port, TLSConfig: config.TLSConfig}}
		}},
		{name: "runtime parameter", mutate: func(config *pgx.ConnConfig) { config.RuntimeParams["options"] = "unsafe" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := target.config.Copy()
			test.mutate(config)
			if err := validateEffectivePGXConfig(config, target.expected); err == nil {
				t.Fatal("validateEffectivePGXConfig() accepted a connection override")
			}
		})
	}
}

func TestPreparedPGXPoolConfigRevalidatesEveryConnection(t *testing.T) {
	clearPGEnvironment(t)
	target, err := validatedPGXConnection(validDirectNeonURL())
	if err != nil {
		t.Fatalf("validatedPGXConnection() error = %v", err)
	}

	poolConfig, err := preparePGXPoolConfig(target)
	if err != nil {
		t.Fatalf("preparePGXPoolConfig() error = %v", err)
	}
	if poolConfig.MaxConns != concurrentReadCount || poolConfig.BeforeConnect == nil {
		t.Fatal("pool config omitted its size limit or connection-time validation")
	}
	if err := validateEffectivePGXConfig(poolConfig.ConnConfig, target.expected); err != nil {
		t.Fatal("pool config changed the validated destination")
	}

	mismatched := poolConfig.ConnConfig.Copy()
	mismatched.Host = "database.example.com"
	if err := poolConfig.BeforeConnect(context.Background(), mismatched); !errors.Is(err, errConfiguration) {
		t.Fatal("connection-time validation accepted a mismatched destination")
	}
}

func TestExecuteProofCollectsFailuresAndClosesPool(t *testing.T) {
	t.Parallel()

	pool := &recordingPool{
		maximumOverlap: 2,
		readError:      errors.New("driver detail must stay internal"),
	}
	opener := func(context.Context, validatedConnection) (proofPool, error) { return pool, nil }

	_, err := executeProof(context.Background(), validDirectNeonURL(), opener)

	if err == nil || err.Error() != "concurrent reads failed" {
		t.Fatalf("executeProof() error = %v, want fixed read failure", err)
	}
	if pool.readCalls.Load() != concurrentReadCount {
		t.Fatalf("pool read count = %d, want %d", pool.readCalls.Load(), concurrentReadCount)
	}
	if pool.acquiredChecks != 1 || pool.closeCalls != 1 {
		t.Fatal("executeProof() skipped acquisition check or close after read failures")
	}
}

func TestExecuteProofClosesPoolOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pool := &recordingPool{maximumOverlap: 2, useContextError: true}
	opener := func(context.Context, validatedConnection) (proofPool, error) { return pool, nil }

	_, err := executeProof(ctx, validDirectNeonURL(), opener)

	if err == nil || err.Error() != "concurrent reads failed" {
		t.Fatalf("executeProof() error = %v, want fixed read failure", err)
	}
	if pool.readCalls.Load() != concurrentReadCount {
		t.Fatalf("pool read count = %d, want %d", pool.readCalls.Load(), concurrentReadCount)
	}
	if pool.closeCalls != 1 {
		t.Fatalf("pool close count = %d, want 1", pool.closeCalls)
	}
}

func TestExecuteProofRecoversWorkerPanicsWithoutDisclosureAndClosesPool(t *testing.T) {
	t.Parallel()

	const panicSecret = "pool-panic-secret-must-not-escape"
	pool := &recordingPool{maximumOverlap: 2, panicValue: panicSecret}
	opener := func(context.Context, validatedConnection) (proofPool, error) { return pool, nil }

	_, err := executeProof(context.Background(), validDirectNeonURL(), opener)

	if err == nil || err.Error() != errConcurrentReads.Error() || strings.Contains(err.Error(), panicSecret) {
		t.Fatalf("executeProof() error = %q, want fixed read failure", err)
	}
	if pool.readCalls.Load() != concurrentReadCount {
		t.Fatalf("pool read count = %d, want %d", pool.readCalls.Load(), concurrentReadCount)
	}
	if pool.acquiredChecks != 1 || pool.closeCalls != 1 {
		t.Fatal("executeProof() skipped acquisition check or close after worker panic")
	}
}

func TestExecuteProofRejectsMissingOverlapAndLeaksBeforeClosing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		acquired       int32
		maximumOverlap int32
		wantError      string
	}{
		{name: "missing overlap", maximumOverlap: 1, wantError: "concurrent read overlap was not observed"},
		{name: "acquired connection leak", acquired: 1, maximumOverlap: 2, wantError: "pool retained an acquired connection"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pool := &recordingPool{acquired: test.acquired, maximumOverlap: test.maximumOverlap}
			opener := func(context.Context, validatedConnection) (proofPool, error) { return pool, nil }

			_, err := executeProof(context.Background(), validDirectNeonURL(), opener)

			if err == nil || err.Error() != test.wantError {
				t.Fatalf("executeProof() error = %v, want %q", err, test.wantError)
			}
			if pool.acquiredChecks != 1 || pool.closedDuringAcquiredCheck {
				t.Fatal("acquired connections were not checked before close")
			}
			if pool.closeCalls != 1 {
				t.Fatalf("pool close count = %d, want 1", pool.closeCalls)
			}
		})
	}
}

type recordingPool struct {
	acquired                  int32
	acquiredChecks            int
	closed                    bool
	closedDuringAcquiredCheck bool
	closeCalls                int
	maximumOverlap            int32
	panicValue                any
	readCalls                 atomic.Int32
	readError                 error
	useContextError           bool
}

func (pool *recordingPool) Read(ctx context.Context) error {
	pool.readCalls.Add(1)
	if pool.panicValue != nil {
		panic(pool.panicValue)
	}
	if pool.useContextError {
		return ctx.Err()
	}
	return pool.readError
}

func (pool *recordingPool) MaximumOverlap() int32 {
	return pool.maximumOverlap
}

func (pool *recordingPool) AcquiredConns() int32 {
	pool.acquiredChecks++
	pool.closedDuringAcquiredCheck = pool.closed
	return pool.acquired
}

func (pool *recordingPool) Close() {
	pool.closeCalls++
	pool.closed = true
}

func validDirectNeonURL() string {
	return "postgresql://proof-user:proof-pass@ep-cool-darkness-123456.us-east-2.aws.neon.tech/proof?sslmode=require"
}

func updateMaximum(maximum *atomic.Int32, candidate int32) {
	for {
		current := maximum.Load()
		if candidate <= current || maximum.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func clearPGEnvironment(t *testing.T) {
	t.Helper()
	for _, variable := range testPGEnvironmentVariables {
		t.Setenv(variable, "")
	}
}
