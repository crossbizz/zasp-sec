package preflight

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the production config decoder and full runner, including the AWS
// credential rejection path. Independent provider observations must survive it.
func TestConnectedCoreObservationsSurviveMissingAWSAuthority(t *testing.T) {
	for _, mode := range []string{"before-install", "installed"} {
		t.Run(mode, func(t *testing.T) {
			original := sdkContractConfig(t)
			original.Credentials.Kind = "operator_file"
			original.Credentials.File = filepath.Join(t.TempDir(), "absent-aws.json")
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal("controlled config encoding unavailable")
			}
			var intended map[string]json.RawMessage
			if json.Unmarshal(raw, &intended) != nil {
				t.Fatal("controlled config map unavailable")
			}
			intended["stytch"], err = json.Marshal(stytchProbeConfig(t))
			if err != nil {
				t.Fatal("controlled identity config unavailable")
			}
			raw, err = json.Marshal(intended)
			if err != nil {
				t.Fatal("controlled complete config unavailable")
			}
			config, err := DecodeConfig(raw)
			if err != nil {
				t.Fatal("valid independent provider configuration rejected")
			}
			transport := &stytchProbeTransport{mode: "observed-null-fields"}
			runner := &Runner{config: config, http: &http.Client{Transport: transport, Timeout: time.Second}}
			report, err := runner.Run(context.Background(), mode)
			if err == nil || report.Ready || report.ProductionEndToEndVerified || len(report.Checks) != 8 {
				t.Fatal("incomplete original prerequisites became readiness or lost report")
			}
			if transport.calls != 2 || transport.forbidden || report.Checks[6].Status != "pass" {
				t.Fatal("AWS failure suppressed exact nonrenewing provider observations")
			}
			if report.Checks[0].Status != "fail" || report.Checks[5].Status != "fail" {
				t.Fatal("independent success cleared another required blocker")
			}
		})
	}
}
