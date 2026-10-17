package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

// A failed readiness decision must still tell the operator which prerequisite
// failed. It must never turn a blocker into a successful command exit.
func TestPreflightCommandsRetainBlockerReports(t *testing.T) {
	preflight := validPreflight()
	preflight.IAMRole = false
	sensor := validPreflight()
	sensor.SensorMode, sensor.BTFPresent = "required", false
	upgrade := UpgradeInput{CurrentVersion: "1.4.2", TargetVersion: "1.5.0", MigrationCompatible: false, BundleFormatCompatible: true, RollbackArtifactReference: "oci://zasp/release@sha256:abc", RecoveryReference: "s3://recovery/manifest.json"}
	rollback := upgrade
	rollback.MigrationCompatible, rollback.RecoveryReference = true, ""
	for _, c := range []struct {
		name, command, failed string
		input                 any
		want                  error
		count                 int
	}{
		{"core prerequisite", "preflight", "iam_irsa", preflight, errPreflightRejected, 8},
		{"required sensor", "preflight", "sensor", sensor, errPreflightRejected, 8},
		{"migration blocker", "upgrade-preflight", "migration", upgrade, errUpgradeRejected, 4},
		{"missing rollback", "upgrade-preflight", "rollback", rollback, errUpgradeRejected, 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			body, err := json.Marshal(c.input)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := runCommand(&output, bytes.NewReader(body), []string{c.command}, "dev"); !errors.Is(err, c.want) {
				t.Fatalf("blocker must retain command failure: %v", err)
			}
			var report PreflightReport
			decoder := json.NewDecoder(&output)
			if err := decoder.Decode(&report); err != nil || report.Ready || len(report.Checks) != c.count {
				t.Fatalf("operator blocker report unavailable: checks=%d ready=%t error=%v", len(report.Checks), report.Ready, err)
			}
			var trailing any
			if decoder.Decode(&trailing) != io.EOF {
				t.Fatal("report contains additional output")
			}
			found := false
			for _, item := range report.Checks {
				if item.Name == c.failed {
					found = item.Required && item.Status == checkFail && item.Hint != ""
				}
			}
			if !found {
				t.Fatal("required blocker and its remediation hint were lost")
			}
		})
	}
	t.Run("invalid input has no readiness report", func(t *testing.T) {
		for _, body := range []string{`{"sensor_mode":"unknown"}`, `{"sensor_mode":"optional","secret":"not-accepted"}`} {
			var output bytes.Buffer
			if err := runCommand(&output, bytes.NewBufferString(body), []string{"preflight"}, "dev"); err == nil || output.Len() != 0 {
				t.Fatal("invalid input produced readiness output or succeeded")
			}
		}
	})
	t.Run("unwritable report remains a command failure", func(t *testing.T) {
		body, _ := json.Marshal(preflight)
		if err := runCommand(preflightReportFailingWriter{}, bytes.NewReader(body), []string{"preflight"}, "dev"); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("output failure was hidden: %v", err)
		}
	})
}

type preflightReportFailingWriter struct{}

func (preflightReportFailingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
