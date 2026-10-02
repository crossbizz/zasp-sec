package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

type singleRecoveryDriverSteps struct {
	Preflight                                  func() error
	Start                                      func(context.Context) (func(context.Context) error, error)
	Install, Fixtures, Admit, Worker, Readback func(context.Context) (bool, error)
}
type singleRecoveryDriverPrerequisites struct {
	Mode, WorkerSource, RecoverySource, CaptureManifest, ContextProof, RunnerSource string
	Overlap                                                                         bool
}

func singleRecoveryFixtureConcurrency(limits []int) (int, error) {
	if len(limits) == 0 {
		return 1, nil
	}
	if len(limits) != 1 || (limits[0] != 1 && limits[0] != 2) {
		return 0, errors.New("fixture concurrency must be one or two")
	}
	return limits[0], nil
}

func runSingleRecoveryNativePhases(ctx context.Context, s singleRecoveryDriverSteps) (result error) {
	if s.Preflight == nil || s.Start == nil || s.Install == nil || s.Fixtures == nil || s.Admit == nil || s.Worker == nil || s.Readback == nil {
		return errors.New("incomplete native driver")
	}
	if err := s.Preflight(); err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cleanup, err := s.Start(ctx)
	if cleanup != nil {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			result = errors.Join(result, cleanup(closeCtx))
		}()
	}
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	if cleanup == nil {
		return errors.New("missing native ownership cleanup")
	}
	for _, step := range []struct {
		name string
		run  func(context.Context) (bool, error)
	}{{"install", s.Install}, {"fixtures", s.Fixtures}, {"admit", s.Admit}, {"worker", s.Worker}, {"readback", s.Readback}} {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := step.run(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
		if !done {
			return fmt.Errorf("%s did not complete", step.name)
		}
	}
	return nil
}
func singleRecoveryDriverPreflight(got, want singleRecoveryDriverPrerequisites) error {
	if got.Mode != "1" || want.Mode != "1" || got.Overlap || want.Overlap {
		return errors.New("explicit exclusive native approval required")
	}
	pairs := [][2]string{{got.WorkerSource, want.WorkerSource}, {got.RecoverySource, want.RecoverySource}, {got.CaptureManifest, want.CaptureManifest}, {got.ContextProof, want.ContextProof}, {got.RunnerSource, want.RunnerSource}}
	for _, pair := range pairs {
		for _, value := range pair {
			if len(value) != 64 {
				return errors.New("missing reviewed native binding")
			}
			for _, c := range value {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					return errors.New("invalid native binding")
				}
			}
		}
		if pair[0] != pair[1] {
			return errors.New("native binding changed")
		}
	}
	return nil
}
func singleRecoveryOwnedEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host != "127.0.0.1" {
		return errors.New("owned IPv4 loopback endpoint required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return errors.New("invalid owned port")
	}
	return nil
}
