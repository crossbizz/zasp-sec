package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

const (
	proofTimeout = 30 * time.Second
	successLine  = "OPA SDK proof passed: allow=true block=true deterministic=true evaluations=2000 p95_under_10ms=true.\n"
)

type proofRunner func(context.Context, ProofOptions) (ProofResult, error)

func main() {
	os.Exit(runMain(os.Stdout, os.Stderr, RunProof))
}

func runMain(stdout io.Writer, stderr io.Writer, runner proofRunner) (code int) {
	wrote := false
	defer func() {
		if recover() != nil && !wrote {
			_, _ = io.WriteString(stderr, failureLine("panic"))
			code = 1
		}
	}()

	if stdout == nil || stderr == nil || runner == nil {
		if stderr != nil {
			_, _ = io.WriteString(stderr, failureLine("configuration"))
		}
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), proofTimeout)
	defer cancel()
	result, err := runner(ctx, ProductionOptions())
	if err != nil {
		_, _ = io.WriteString(stderr, failureLine(errorCategory(err)))
		wrote = true
		return 1
	}
	if category := invalidResultCategory(result); category != "" {
		_, _ = io.WriteString(stderr, failureLine(category))
		wrote = true
		return 1
	}
	if !writeExact(stdout, successLine) {
		_, _ = io.WriteString(stderr, failureLine("configuration"))
		wrote = true
		return 1
	}
	wrote = true
	return 0
}

func writeExact(writer io.Writer, value string) bool {
	written, err := io.WriteString(writer, value)
	return err == nil && written == len(value)
}

func invalidResultCategory(result ProofResult) string {
	if !result.AllowMatched || !result.BlockMatched || !result.Deterministic {
		return "evaluation"
	}
	if result.WarmupPerDecision != productionWarmupPerDecision || result.MeasuredPerDecision != productionMeasuredPerDecision {
		return "configuration"
	}
	if result.AllowP95 < 0 || result.BlockP95 < 0 || result.AllowP95 > productionMaximumP95 || result.BlockP95 > productionMaximumP95 {
		return "latency"
	}
	return ""
}

func errorCategory(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, errPanic):
		return "panic"
	case errors.Is(err, errConfiguration):
		return "configuration"
	case errors.Is(err, errPolicy):
		return "policy"
	case errors.Is(err, errLatency):
		return "latency"
	case errors.Is(err, errEvaluation):
		return "evaluation"
	default:
		return "evaluation"
	}
}

func failureLine(category string) string {
	return "OPA SDK proof failed: " + category + " rejected.\n"
}
