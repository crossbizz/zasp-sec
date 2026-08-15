package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

const expectedSuccessLine = "OPA SDK proof passed: allow=true block=true deterministic=true evaluations=2000 p95_under_10ms=true.\n"

func successfulProofResult() ProofResult {
	return ProofResult{
		AllowMatched:        true,
		BlockMatched:        true,
		Deterministic:       true,
		WarmupPerDecision:   100,
		MeasuredPerDecision: 1_000,
		AllowP95:            time.Millisecond,
		BlockP95:            time.Millisecond,
	}
}

func TestRunMainWritesOnlyFixedSuccess(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, func(context.Context, ProofOptions) (ProofResult, error) {
		return successfulProofResult(), nil
	})
	if code != 0 || stdout.String() != expectedSuccessLine || stderr.Len() != 0 {
		t.Fatalf("runMain() = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestRunMainUsesFixedFailureCategoriesWithoutDetails(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "configuration", err: errConfiguration, want: "configuration"},
		{name: "policy", err: errPolicy, want: "policy"},
		{name: "evaluation", err: errEvaluation, want: "evaluation"},
		{name: "latency", err: errLatency, want: "latency"},
		{name: "deadline", err: context.DeadlineExceeded, want: "deadline"},
		{name: "panic category", err: errPanic, want: "panic"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			sensitive := errors.New("secret input /private/provider/path")
			code := runMain(&stdout, &stderr, func(context.Context, ProofOptions) (ProofResult, error) {
				return ProofResult{}, errors.Join(test.err, sensitive)
			})
			want := "OPA SDK proof failed: " + test.want + " rejected.\n"
			if code != 1 || stdout.Len() != 0 || stderr.String() != want {
				t.Fatalf("runMain() = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String()+stderr.String(), "secret") || strings.Contains(stdout.String()+stderr.String(), "/private") {
				t.Fatalf("sensitive detail escaped: %q %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunMainContainsPanics(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, func(context.Context, ProofOptions) (ProofResult, error) {
		panic("secret panic detail")
	})
	if code != 1 || stdout.Len() != 0 || stderr.String() != "OPA SDK proof failed: panic rejected.\n" {
		t.Fatalf("runMain() = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestRunMainSuppliesOnlyProductionOptionsAndDeadline(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runMain(&stdout, &stderr, func(ctx context.Context, options ProofOptions) (ProofResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("runner context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > proofTimeout {
			t.Fatalf("runner deadline remaining = %v", remaining)
		}
		if options.warmupPerDecision != productionWarmupPerDecision ||
			options.measuredPerDecision != productionMeasuredPerDecision ||
			options.maximumP95 != productionMaximumP95 || options.now == nil || options.prepare == nil {
			t.Fatalf("runner options = %#v", options)
		}
		return successfulProofResult(), nil
	})
	if code != 0 || stdout.String() != expectedSuccessLine || stderr.Len() != 0 {
		t.Fatalf("runMain() = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestRunMainRejectsMalformedSuccessfulResults(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ProofResult)
		want   string
	}{
		{name: "allow mismatch", mutate: func(result *ProofResult) { result.AllowMatched = false }, want: "evaluation"},
		{name: "block mismatch", mutate: func(result *ProofResult) { result.BlockMatched = false }, want: "evaluation"},
		{name: "nondeterminism", mutate: func(result *ProofResult) { result.Deterministic = false }, want: "evaluation"},
		{name: "warmup drift", mutate: func(result *ProofResult) { result.WarmupPerDecision-- }, want: "configuration"},
		{name: "measurement drift", mutate: func(result *ProofResult) { result.MeasuredPerDecision-- }, want: "configuration"},
		{name: "allow p95 drift", mutate: func(result *ProofResult) { result.AllowP95 = productionMaximumP95 + 1 }, want: "latency"},
		{name: "block p95 drift", mutate: func(result *ProofResult) { result.BlockP95 = productionMaximumP95 + 1 }, want: "latency"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			result := successfulProofResult()
			test.mutate(&result)
			code := runMain(&stdout, &stderr, func(context.Context, ProofOptions) (ProofResult, error) {
				return result, nil
			})
			want := "OPA SDK proof failed: " + test.want + " rejected.\n"
			if code != 1 || stdout.Len() != 0 || stderr.String() != want {
				t.Fatalf("runMain() = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunMainFailsWhenFixedSuccessCannotBeWritten(t *testing.T) {
	var stderr bytes.Buffer
	code := runMain(errorWriter{}, &stderr, func(context.Context, ProofOptions) (ProofResult, error) {
		return successfulProofResult(), nil
	})
	if code != 1 || stderr.String() != "OPA SDK proof failed: configuration rejected.\n" {
		t.Fatalf("runMain() = code %d stderr %q", code, stderr.String())
	}
}
