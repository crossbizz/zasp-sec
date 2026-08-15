package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Break caught: removing the real embedded OPA evaluation or changing either
// fixed synthetic decision makes the proof stop matching both outcomes.
func TestRunProofEvaluatesExactAllowAndBlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := RunProof(ctx, ProductionOptions())
	if err != nil {
		t.Fatalf("RunProof() error = %v", err)
	}
	if !result.AllowMatched || !result.BlockMatched || !result.Deterministic {
		t.Fatalf("RunProof() result = %#v", result)
	}
	if result.WarmupPerDecision != 100 || result.MeasuredPerDecision != 1000 {
		t.Fatalf("RunProof() counts = %#v", result)
	}
}

type evaluatorFunc func(context.Context, DecisionInput) (rego.ResultSet, error)

func (f evaluatorFunc) Eval(ctx context.Context, input DecisionInput) (rego.ResultSet, error) {
	return f(ctx, input)
}

func decisionResult(value any) rego.ResultSet {
	return rego.ResultSet{{Expressions: []*rego.ExpressionValue{{Value: value}}}}
}

func deterministicClock(step time.Duration) func() time.Time {
	current := time.Unix(0, 0)
	return func() time.Time {
		value := current
		current = current.Add(step)
		return value
	}
}

func focusedOptions(evaluator decisionEvaluator) ProofOptions {
	return ProofOptions{
		warmupPerDecision:   1,
		measuredPerDecision: 1,
		maximumP95:          10 * time.Millisecond,
		now:                 deterministicClock(time.Millisecond),
		prepare: func(context.Context) (decisionEvaluator, error) {
			return evaluator, nil
		},
	}
}

func TestRunProofPreparesOnceAndUsesExactInputs(t *testing.T) {
	preparations := 0
	calls := 0
	evaluator := evaluatorFunc(func(_ context.Context, input DecisionInput) (rego.ResultSet, error) {
		calls++
		if input != fixedInput(input.Action) {
			t.Fatalf("unexpected input: %#v", input)
		}
		switch input.Action {
		case "tool:read":
			return decisionResult(true), nil
		case "tool:delete":
			return decisionResult(false), nil
		default:
			t.Fatalf("unexpected action: %q", input.Action)
			return nil, nil
		}
	})
	options := ProductionOptions()
	options.now = deterministicClock(time.Microsecond)
	options.prepare = func(context.Context) (decisionEvaluator, error) {
		preparations++
		return evaluator, nil
	}

	if _, err := RunProof(context.Background(), options); err != nil {
		t.Fatalf("RunProof() error = %v", err)
	}
	if preparations != 1 {
		t.Fatalf("preparations = %d, want 1", preparations)
	}
	if calls != 2*(productionWarmupPerDecision+productionMeasuredPerDecision) {
		t.Fatalf("calls = %d", calls)
	}
}

func TestRunProofRejectsMalformedOrWrongDecisions(t *testing.T) {
	tests := map[string]rego.ResultSet{
		"undefined":            nil,
		"multiple results":     append(decisionResult(true), decisionResult(true)...),
		"missing expression":   {{}},
		"multiple expressions": {{Expressions: []*rego.ExpressionValue{{Value: true}, {Value: true}}}},
		"non boolean":          decisionResult("true"),
		"wrong boolean":        decisionResult(false),
	}
	for name, result := range tests {
		t.Run(name, func(t *testing.T) {
			evaluator := evaluatorFunc(func(context.Context, DecisionInput) (rego.ResultSet, error) {
				return result, nil
			})
			_, err := RunProof(context.Background(), focusedOptions(evaluator))
			if !errors.Is(err, errEvaluation) {
				t.Fatalf("RunProof() error = %v, want evaluation category", err)
			}
		})
	}
}

func TestRunProofFailsClosedOnPreparationEvaluationAndPanic(t *testing.T) {
	t.Run("preparation error", func(t *testing.T) {
		options := focusedOptions(nil)
		options.prepare = func(context.Context) (decisionEvaluator, error) {
			return nil, errors.New("sensitive preparation detail")
		}
		_, err := RunProof(context.Background(), options)
		if !errors.Is(err, errPolicy) {
			t.Fatalf("RunProof() error = %v, want policy category", err)
		}
	})

	t.Run("evaluation error", func(t *testing.T) {
		evaluator := evaluatorFunc(func(context.Context, DecisionInput) (rego.ResultSet, error) {
			return nil, errors.New("sensitive evaluation detail")
		})
		_, err := RunProof(context.Background(), focusedOptions(evaluator))
		if !errors.Is(err, errEvaluation) {
			t.Fatalf("RunProof() error = %v, want evaluation category", err)
		}
	})

	t.Run("preparation panic", func(t *testing.T) {
		options := focusedOptions(nil)
		options.prepare = func(context.Context) (decisionEvaluator, error) {
			panic("sensitive preparation panic")
		}
		_, err := RunProof(context.Background(), options)
		if !errors.Is(err, errPanic) {
			t.Fatalf("RunProof() error = %v, want panic category", err)
		}
	})

	t.Run("evaluation panic", func(t *testing.T) {
		evaluator := evaluatorFunc(func(context.Context, DecisionInput) (rego.ResultSet, error) {
			panic("sensitive evaluation panic")
		})
		_, err := RunProof(context.Background(), focusedOptions(evaluator))
		if !errors.Is(err, errPanic) {
			t.Fatalf("RunProof() error = %v, want panic category", err)
		}
	})
}

func TestRunProofPreservesCancellationDuringPreparation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	options := focusedOptions(nil)
	options.prepare = func(context.Context) (decisionEvaluator, error) {
		cancel()
		return nil, context.Canceled
	}

	_, err := RunProof(ctx, options)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunProof() error = %v, want context cancellation", err)
	}
}

func TestNearestRankP95UsesExactNearestRankWithoutMutation(t *testing.T) {
	tests := []struct {
		name    string
		samples []time.Duration
		want    time.Duration
	}{
		{name: "one", samples: []time.Duration{7 * time.Millisecond}, want: 7 * time.Millisecond},
		{name: "twenty", samples: append([]time.Duration{20 * time.Millisecond}, repeatDuration(19, time.Millisecond)...), want: time.Millisecond},
		{name: "one thousand", samples: append(repeatDuration(949, time.Millisecond), append([]time.Duration{9 * time.Millisecond}, repeatDuration(50, 20*time.Millisecond)...)...), want: 9 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := append([]time.Duration(nil), test.samples...)
			got, err := nearestRankP95(test.samples)
			if err != nil || got != test.want {
				t.Fatalf("nearestRankP95() = %v, %v; want %v", got, err, test.want)
			}
			for index := range before {
				if before[index] != test.samples[index] {
					t.Fatalf("input mutated at %d", index)
				}
			}
		})
	}
}

func repeatDuration(count int, value time.Duration) []time.Duration {
	result := make([]time.Duration, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestNearestRankP95RejectsEmptyAndNegativeSamples(t *testing.T) {
	for name, samples := range map[string][]time.Duration{
		"empty":    nil,
		"negative": {time.Millisecond, -time.Nanosecond},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := nearestRankP95(samples); !errors.Is(err, errLatency) {
				t.Fatalf("nearestRankP95() error = %v, want latency category", err)
			}
		})
	}
}

func TestRunProofAppliesExactIndependentLatencyThresholds(t *testing.T) {
	evaluator := evaluatorFunc(func(_ context.Context, input DecisionInput) (rego.ResultSet, error) {
		return decisionResult(input.Action == "tool:read"), nil
	})

	t.Run("exact threshold passes", func(t *testing.T) {
		options := focusedOptions(evaluator)
		options.now = deterministicClock(10 * time.Millisecond)
		result, err := RunProof(context.Background(), options)
		if err != nil {
			t.Fatalf("RunProof() error = %v", err)
		}
		if result.AllowP95 != 10*time.Millisecond || result.BlockP95 != 10*time.Millisecond {
			t.Fatalf("p95 result = %#v", result)
		}
	})

	t.Run("one nanosecond over fails", func(t *testing.T) {
		options := focusedOptions(evaluator)
		options.now = deterministicClock(10*time.Millisecond + time.Nanosecond)
		if _, err := RunProof(context.Background(), options); !errors.Is(err, errLatency) {
			t.Fatalf("RunProof() error = %v, want latency category", err)
		}
	})

	t.Run("block threshold is independent", func(t *testing.T) {
		clock := []time.Time{
			time.Unix(0, 0), time.Unix(0, int64(time.Millisecond)),
			time.Unix(0, int64(time.Millisecond)), time.Unix(0, int64(12*time.Millisecond)),
		}
		options := focusedOptions(evaluator)
		options.now = func() time.Time {
			value := clock[0]
			clock = clock[1:]
			return value
		}
		if _, err := RunProof(context.Background(), options); !errors.Is(err, errLatency) {
			t.Fatalf("RunProof() error = %v, want latency category", err)
		}
	})
}
