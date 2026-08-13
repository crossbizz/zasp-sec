package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

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
	opener := func(context.Context, string) (proofPool, error) {
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
	opener := func(context.Context, string) (proofPool, error) {
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

func TestExecuteProofCollectsFailuresAndClosesPool(t *testing.T) {
	t.Parallel()

	pool := &recordingPool{
		maximumOverlap: 2,
		readError:      errors.New("driver detail must stay internal"),
	}
	opener := func(context.Context, string) (proofPool, error) { return pool, nil }

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
	opener := func(context.Context, string) (proofPool, error) { return pool, nil }

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
			opener := func(context.Context, string) (proofPool, error) { return pool, nil }

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
	readCalls                 atomic.Int32
	readError                 error
	useContextError           bool
}

func (pool *recordingPool) Read(ctx context.Context) error {
	pool.readCalls.Add(1)
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
