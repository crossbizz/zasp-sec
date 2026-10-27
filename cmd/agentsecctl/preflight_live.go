package main

import (
	"context"
	"io"
	"path/filepath"

	"github.com/zasp-ai/zasp-sec/services/platform/preflight"
)

func runPreflightCommand(output io.Writer, input io.Reader, arguments []string) error {
	if len(arguments) == 1 || len(arguments) == 3 && arguments[1] == "evaluate" && arguments[2] == "--offline" {
		var value PreflightInput
		if decodeCommandInput(input, &value) != nil {
			return errPreflightRejected
		}
		evaluation, e := EvaluatePreflight(value)
		if e != nil && len(evaluation.Checks) == 0 {
			return e
		}
		// Preserve the original evaluator as labeled offline compatibility. Its
		// policy result is distinct from live installation or production readiness.
		report := struct {
			Schema          string           `json:"schema"`
			Mode            string           `json:"mode"`
			Source          string           `json:"source"`
			Ready           bool             `json:"ready"`
			Production      bool             `json:"production_end_to_end_verified"`
			EvaluationReady bool             `json:"evaluation_ready"`
			Checks          []PreflightCheck `json:"checks"`
		}{Schema: "agentsec-preflight-report-v1", Mode: "offline", Source: "offline-evaluation", EvaluationReady: evaluation.Ready, Checks: evaluation.Checks}
		if err := encodeJSON(output, report); err != nil {
			return err
		}
		return e
	}
	if len(arguments) != 6 || arguments[1] != "run" || arguments[2] != "--mode" || (arguments[3] != "before-install" && arguments[3] != "installed") || arguments[4] != "--config-file" || !filepath.IsAbs(arguments[5]) {
		return errInvalidArguments
	}
	body, e := readOwnedRecoveryFile(arguments[5], preflight.MaximumConfigBytes, true)
	if e != nil {
		return errPreflightRejected
	}
	defer clear(body)
	config, e := preflight.DecodeConfig(body)
	if e != nil {
		return errPreflightRejected
	}
	runner, e := preflight.NewRunner(config)
	if e != nil {
		return errPreflightRejected
	}
	defer runner.Close()
	report, e := runner.Run(context.Background(), arguments[3])
	if len(report.Checks) == 0 {
		return errPreflightRejected
	}
	if err := encodeJSON(output, report); err != nil {
		return err
	}
	if e != nil {
		return errPreflightRejected
	}
	return nil
}
