package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
)

const (
	productionWarmupPerDecision   = 100
	productionMeasuredPerDecision = 1_000
	productionMaximumP95          = 10 * time.Millisecond
)

var (
	errConfiguration = errors.New("configuration rejected")
	errPolicy        = errors.New("policy rejected")
	errEvaluation    = errors.New("evaluation rejected")
	errLatency       = errors.New("latency rejected")
	errPanic         = errors.New("panic rejected")
)

//go:embed policy.rego
var embeddedPolicy string

type DecisionInput struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	Subject        string `json:"subject"`
	Action         string `json:"action"`
	Resource       string `json:"resource"`
	Environment    string `json:"environment"`
}

type ProofResult struct {
	AllowMatched        bool
	BlockMatched        bool
	Deterministic       bool
	WarmupPerDecision   int
	MeasuredPerDecision int
	AllowP95            time.Duration
	BlockP95            time.Duration
}

type decisionEvaluator interface {
	Eval(context.Context, map[string]any) (rego.ResultSet, error)
}

type prepareEvaluator func(context.Context) (decisionEvaluator, error)

type ProofOptions struct {
	warmupPerDecision   int
	measuredPerDecision int
	maximumP95          time.Duration
	now                 func() time.Time
	inputDocument       func(DecisionInput) (map[string]any, error)
	prepare             prepareEvaluator
}

func ProductionOptions() ProofOptions {
	return ProofOptions{
		warmupPerDecision:   productionWarmupPerDecision,
		measuredPerDecision: productionMeasuredPerDecision,
		maximumP95:          productionMaximumP95,
		now:                 time.Now,
		inputDocument:       inputDocument,
		prepare:             prepareProductionEvaluator,
	}
}

type preparedEvaluator struct {
	query rego.PreparedEvalQuery
}

func (e preparedEvaluator) Eval(ctx context.Context, input map[string]any) (rego.ResultSet, error) {
	return e.query.Eval(ctx, rego.EvalInput(input))
}

func inputDocument(input DecisionInput) (map[string]any, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("%w: input encoding", errConfiguration)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: input decoding", errConfiguration)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return document, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing input", errConfiguration)
	}
	return nil
}

func prepareProductionEvaluator(ctx context.Context) (decisionEvaluator, error) {
	query, err := rego.New(
		rego.Query("data.zasp.runtime.allow"),
		rego.Module("zasp_runtime.rego", embeddedPolicy),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: preparation", errPolicy)
	}
	return preparedEvaluator{query: query}, nil
}

func RunProof(ctx context.Context, options ProofOptions) (result ProofResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result = ProofResult{}
			resultErr = errPanic
		}
	}()

	if err := validateOptions(ctx, options); err != nil {
		return ProofResult{}, err
	}
	evaluator, err := options.prepare(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ProofResult{}, ctxErr
		}
		return ProofResult{}, fmt.Errorf("%w: prepare", errPolicy)
	}
	if evaluator == nil {
		return ProofResult{}, fmt.Errorf("%w: nil evaluator", errPolicy)
	}

	allowInput := fixedInput("tool:read")
	blockInput := fixedInput("tool:delete")
	allowDocument, err := options.inputDocument(allowInput)
	if err != nil {
		return ProofResult{}, fmt.Errorf("%w: allow input", errConfiguration)
	}
	blockDocument, err := options.inputDocument(blockInput)
	if err != nil {
		return ProofResult{}, fmt.Errorf("%w: block input", errConfiguration)
	}
	if err := warmUp(ctx, evaluator, allowDocument, true, options.warmupPerDecision); err != nil {
		return ProofResult{}, err
	}
	if err := warmUp(ctx, evaluator, blockDocument, false, options.warmupPerDecision); err != nil {
		return ProofResult{}, err
	}
	allowSamples, err := measure(ctx, evaluator, allowDocument, true, options.measuredPerDecision, options.now)
	if err != nil {
		return ProofResult{}, err
	}
	blockSamples, err := measure(ctx, evaluator, blockDocument, false, options.measuredPerDecision, options.now)
	if err != nil {
		return ProofResult{}, err
	}
	allowP95, err := nearestRankP95(allowSamples)
	if err != nil {
		return ProofResult{}, err
	}
	blockP95, err := nearestRankP95(blockSamples)
	if err != nil {
		return ProofResult{}, err
	}
	if allowP95 > options.maximumP95 || blockP95 > options.maximumP95 {
		return ProofResult{}, errLatency
	}

	return ProofResult{
		AllowMatched:        true,
		BlockMatched:        true,
		Deterministic:       true,
		WarmupPerDecision:   options.warmupPerDecision,
		MeasuredPerDecision: options.measuredPerDecision,
		AllowP95:            allowP95,
		BlockP95:            blockP95,
	}, nil
}

func validateOptions(ctx context.Context, options ProofOptions) error {
	if ctx == nil || options.warmupPerDecision <= 0 || options.measuredPerDecision <= 0 ||
		options.maximumP95 <= 0 || options.now == nil || options.inputDocument == nil || options.prepare == nil {
		return errConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func fixedInput(action string) DecisionInput {
	return DecisionInput{
		OrganizationID: "org_aaaaaaaaaaaaaaaa",
		WorkspaceID:    "wsp_aaaaaaaaaaaaaaaa",
		Subject:        "agent:demo",
		Action:         action,
		Resource:       "resource:approved",
		Environment:    "test",
	}
}

func warmUp(ctx context.Context, evaluator decisionEvaluator, input map[string]any, expected bool, count int) error {
	for range count {
		if err := evaluateExpected(ctx, evaluator, input, expected); err != nil {
			return err
		}
	}
	return nil
}

func measure(ctx context.Context, evaluator decisionEvaluator, input map[string]any, expected bool, count int, now func() time.Time) ([]time.Duration, error) {
	samples := make([]time.Duration, 0, count)
	for range count {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		started := now()
		results, evalErr := evaluator.Eval(ctx, input)
		elapsed := now().Sub(started)
		if elapsed < 0 {
			return nil, errLatency
		}
		if err := validateEvaluation(ctx, results, evalErr, expected); err != nil {
			return nil, err
		}
		samples = append(samples, elapsed)
	}
	return samples, nil
}

func evaluateExpected(ctx context.Context, evaluator decisionEvaluator, input map[string]any, expected bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	results, err := evaluator.Eval(ctx, input)
	return validateEvaluation(ctx, results, err, expected)
}

func validateEvaluation(ctx context.Context, results rego.ResultSet, evalErr error, expected bool) error {
	if evalErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: query", errEvaluation)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 ||
		results[0].Expressions[0] == nil || len(results[0].Bindings) != 0 {
		return fmt.Errorf("%w: result shape", errEvaluation)
	}
	decision, ok := results[0].Expressions[0].Value.(bool)
	if !ok || decision != expected {
		return fmt.Errorf("%w: decision", errEvaluation)
	}
	return nil
}

func nearestRankP95(samples []time.Duration) (time.Duration, error) {
	if len(samples) == 0 {
		return 0, errLatency
	}
	ordered := append([]time.Duration(nil), samples...)
	for _, sample := range ordered {
		if sample < 0 {
			return 0, errLatency
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (95*len(ordered)+99)/100 - 1
	return ordered[index], nil
}
