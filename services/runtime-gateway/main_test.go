package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunPrintsExactBuildVersion(t *testing.T) {
	t.Parallel()

	for _, version := range []string{
		"dev",
		"0.1.0-test.1",
		"A_b+c.d-9",
		strings.Repeat("a", 64),
	} {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			if err := run(&output, version); err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if got, want := output.String(), "runtime-gateway build "+version+"\n"; got != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func TestRunRejectsInvalidBuildVersionWithoutOutput(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"",
		".1.0.0",
		"-dev",
		" dev",
		"dev ",
		"dev build",
		"dev\nnext",
		"dev\rnext",
		"dev/path",
		"dévelop",
		"dev\x00next",
		strings.Repeat("a", 65),
	}
	for _, version := range invalid {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			if err := run(&output, version); !errors.Is(err, errInvalidBuildVersion) {
				t.Fatalf("run() error = %v, want errInvalidBuildVersion", err)
			}
			if output.Len() != 0 {
				t.Fatalf("output = %q, want empty", output.String())
			}
		})
	}
}

func TestRunReturnsWriterFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("write failed")
	if err := run(errorWriter{err: want}, "dev"); !errors.Is(err, want) {
		t.Fatalf("run() error = %v, want %v", err, want)
	}
}

func TestRunRejectsNilWriter(t *testing.T) {
	t.Parallel()

	if err := run(nil, "dev"); !errors.Is(err, errOutputUnavailable) {
		t.Fatalf("run() error = %v, want errOutputUnavailable", err)
	}
}

func TestDefaultBuildVersion(t *testing.T) {
	t.Parallel()

	if buildVersion != "dev" {
		t.Fatalf("buildVersion = %q, want dev", buildVersion)
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}
