package migrations

import (
	"context"
	"encoding/json"
	"io"
	"strings"
)

const globalSetSQL = `SELECT public.zasp_production_security_agent_existing_tests_global_set($1,$2,$3,$4,$5,$6)`
const globalReadSQL = `SELECT public.zasp_production_security_agent_existing_tests_global_read($1,$2)`

type GlobalExecutionControlRequest struct {
	Enabled         bool
	ExpectedVersion int64
	RequestID       string
	CorrelationID   string
}

type GlobalExecutionControlResult struct {
	Enabled  bool  `json:"enabled"`
	Version  int64 `json:"version"`
	Replayed bool  `json:"replayed"`
}

// Token-level decoding preserves presence, exact names and duplicates. Struct
// unmarshalling alone would silently report a stop for missing/null enabled.
func decodeGlobalExecutionControlResult(body string) (GlobalExecutionControlResult, error) {
	var result GlobalExecutionControlResult
	invalid := func() (GlobalExecutionControlResult, error) { return GlobalExecutionControlResult{}, ErrInvalidState }
	if len(body) > 1024 {
		return invalid()
	}
	decoder := json.NewDecoder(strings.NewReader(body))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return invalid()
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return invalid()
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return invalid()
		}
		seen[key] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || string(raw) == "null" {
			return invalid()
		}
		switch key {
		case "enabled":
			err = json.Unmarshal(raw, &result.Enabled)
		case "version":
			err = json.Unmarshal(raw, &result.Version)
		case "replayed":
			err = json.Unmarshal(raw, &result.Replayed)
		default:
			return invalid()
		}
		if err != nil {
			return invalid()
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || len(seen) != 3 || result.Version < 1 {
		return invalid()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid()
	}
	return result, nil
}

func (runner *Runner) ReadGlobalExecutionControl(ctx context.Context) (GlobalExecutionControlResult, error) {
	return runner.globalExecutionControl(ctx, globalReadSQL, []any{ProductionSecurityAgentExistingTests().Checksum(), SecurityAgentExistingTestsFingerprint()})
}

func (runner *Runner) SetGlobalExecutionControl(ctx context.Context, request GlobalExecutionControlRequest) (GlobalExecutionControlResult, error) {
	return runner.globalExecutionControl(ctx, globalSetSQL, []any{ProductionSecurityAgentExistingTests().Checksum(), SecurityAgentExistingTestsFingerprint(), request.Enabled, request.ExpectedVersion, request.RequestID, request.CorrelationID})
}

func (runner *Runner) globalExecutionControl(ctx context.Context, statement string, arguments []any) (GlobalExecutionControlResult, error) {
	if runner == nil || nilInterface(runner.database) {
		return GlobalExecutionControlResult{}, ErrInvalidRunner
	}
	var result GlobalExecutionControlResult
	err := runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		var body string
		if err := scanRow(ctx, transaction, statement, arguments, &body); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		var err error
		result, err = decodeGlobalExecutionControlResult(body)
		return err
	})
	// Deferred database constraints can fail at commit after a valid response.
	if err != nil {
		return GlobalExecutionControlResult{}, err
	}
	return result, nil
}
