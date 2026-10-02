package apiserver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These controls catch omitted/reordered consumer phases, swallowed skips and
// lost cleanup after startup or a consumer fails. No service is constructed.
func TestSingleTestRecoveryNativeDriverLifecycle(t *testing.T) {
	for _, fault := range []string{"", "preflight", "start", "install", "fixtures", "admit", "worker", "readback", "skip-worker", "cleanup"} {
		t.Run(fault, func(t *testing.T) {
			calls := []string{}
			sentinel := errors.New("controlled failure")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			phase := func(name string) func(context.Context) (bool, error) {
				return func(context.Context) (bool, error) {
					calls = append(calls, name)
					if name == fault {
						cancel()
						return false, sentinel
					}
					return fault != "skip-"+name, nil
				}
			}
			steps := singleRecoveryDriverSteps{
				Preflight: func() error {
					calls = append(calls, "preflight")
					if fault == "preflight" {
						return sentinel
					}
					return nil
				},
				Start: func(context.Context) (func(context.Context) error, error) {
					calls = append(calls, "start")
					close := func(c context.Context) error {
						calls = append(calls, "cleanup")
						deadline, ok := c.Deadline()
						if c.Err() != nil || !ok || time.Until(deadline) > 20*time.Second {
							t.Error("cleanup bound/cancellation")
						}
						if fault == "cleanup" {
							return sentinel
						}
						return nil
					}
					if fault == "start" {
						return close, sentinel
					}
					return close, nil
				},
				Install: phase("install"), Fixtures: phase("fixtures"), Admit: phase("admit"), Worker: phase("worker"), Readback: phase("readback"),
			}
			err := runSingleRecoveryNativePhases(ctx, steps)
			want := []string{"preflight", "start", "install", "fixtures", "admit", "worker", "readback", "cleanup"}
			switch fault {
			case "preflight":
				want = want[:1]
			case "start":
				want = []string{"preflight", "start", "cleanup"}
			case "install", "fixtures", "admit", "worker", "readback", "skip-worker":
				name := fault
				if name == "skip-worker" {
					name = "worker"
				}
				for i, v := range want {
					if v == name {
						want = append(append([]string{}, want[:i+1]...), "cleanup")
						break
					}
				}
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("phases %v want %v", calls, want)
			}
			if (err != nil) != (fault != "") {
				t.Fatalf("failure/skip lost: %v", err)
			}
		})
	}
}

func TestSingleTestRecoveryNativeDriverPreflight(t *testing.T) {
	good := singleRecoveryDriverPrerequisites{Mode: "1", WorkerSource: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RecoverySource: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CaptureManifest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ContextProof: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", RunnerSource: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	for _, name := range []string{"empty-mode", "unknown-mode", "empty-worker", "changed-worker", "capture", "context", "runner", "overlap"} {
		t.Run(name, func(t *testing.T) {
			q := good
			switch name {
			case "empty-mode":
				q.Mode = ""
			case "unknown-mode":
				q.Mode = "yes"
			case "empty-worker":
				q.WorkerSource = ""
			case "changed-worker":
				q.WorkerSource = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			case "capture":
				q.CaptureManifest = ""
			case "context":
				q.ContextProof = "bad"
			case "runner":
				q.RunnerSource = ""
			case "overlap":
				q.Overlap = true
			}
			if singleRecoveryDriverPreflight(q, good) == nil {
				t.Fatal("unsafe prerequisites accepted")
			}
		})
	}
	if err := singleRecoveryDriverPreflight(good, good); err != nil {
		t.Fatal(err)
	}
	if singleRecoveryDriverPreflight(good, singleRecoveryDriverPrerequisites{}) == nil {
		t.Fatal("unaccepted source pins enabled native")
	}
	for _, value := range []string{"localhost:7233", "203.0.113.1:7233", "127.0.0.1:0", "127.0.0.1:07233", "127.0.0.1:65536", "127.0.0.1:7233/path"} {
		if singleRecoveryOwnedEndpoint(value) == nil {
			t.Error("endpoint accepted", value)
		}
	}
	if err := singleRecoveryOwnedEndpoint("127.0.0.1:17233"); err != nil {
		t.Fatal(err)
	}
}

func TestSingleTestRecoveryNativeDriverFixtureBounds(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "controlled-must-not-inherit")
	for _, q := range []struct {
		limits []int
		want   int
	}{{nil, 1}, {[]int{1}, 1}, {[]int{2}, 2}} {
		got, err := singleRecoveryFixtureConcurrency(q.limits)
		if err != nil || got != q.want {
			t.Fatal("bounded fixture concurrency", got, err)
		}
	}
	for _, q := range [][]int{{0}, {3}, {-1}, {1, 2}} {
		if _, err := singleRecoveryFixtureConcurrency(q); err == nil {
			t.Fatal("unsupported fixture concurrency")
		}
	}
	env := singleRecoveryChildEnvironment(t.TempDir(), map[string]string{"OPENAI_API_KEY": "never-inherit", "ZASP_SINGLE_RECOVERY_NATIVE_RUN": "owned"})
	for _, v := range env {
		if strings.Contains(v, "OPENAI") || strings.Contains(v, "never-inherit") || strings.Contains(v, "controlled-must-not-inherit") {
			t.Fatal("child inherited secret")
		}
	}
	if singleRecoveryOriginalRun == singleRecoveryForwardRun || !validProductID(singleRecoveryOriginalRun) || !validProductID(singleRecoveryForwardRun) {
		t.Fatal("distinct fixture identities")
	}
}

func TestSingleTestRecoveryNativeDriverCleanupBounds(t *testing.T) {
	if !singleRecoveryJoinedCancellation(context.Canceled) || singleRecoveryJoinedCancellation(context.DeadlineExceeded) || singleRecoveryJoinedCancellation(errors.Join(context.Canceled, errors.New("ownership uncertain"))) {
		t.Fatal("uncertain ownership treated as joined")
	}
	if runSingleRecoveryNativePhases(context.Background(), singleRecoveryDriverSteps{}) == nil {
		t.Fatal("missing phase accepted")
	}
	if singleRecoveryNativeSourcePreflight() == nil {
		t.Fatal("unaccepted native pins opened driver")
	}
	done, err := singleRecoverySubtest(t, "controlled-skipped-consumer", func(t *testing.T) { t.Skip("controlled skip") })
	if done || err != nil {
		t.Fatal("skip reported as completed")
	}
}
