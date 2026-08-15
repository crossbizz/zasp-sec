package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunPrintsExactVersion(t *testing.T) {
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
			if err := run(&output, []string{"version"}, version); err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if got, want := output.String(), "agentsecctl version "+version+"\n"; got != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func TestRunRejectsInvalidArgumentsWithoutOutput(t *testing.T) {
	t.Parallel()

	for name, arguments := range map[string][]string{
		"missing": nil,
		"unknown": {"build"},
		"extra":   {"version", "extra"},
	} {
		arguments := arguments
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			if err := run(&output, arguments, "dev"); !errors.Is(err, errInvalidArguments) {
				t.Fatalf("run() error = %v, want errInvalidArguments", err)
			}
			if output.Len() != 0 {
				t.Fatalf("output = %q, want empty", output.String())
			}
		})
	}
}

func TestRunRejectsInvalidVersionWithoutOutput(t *testing.T) {
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
			if err := run(&output, []string{"version"}, version); !errors.Is(err, errInvalidBuildVersion) {
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
	if err := run(errorWriter{err: want}, []string{"version"}, "dev"); !errors.Is(err, want) {
		t.Fatalf("run() error = %v, want %v", err, want)
	}
}

func TestRunRejectsNilWriter(t *testing.T) {
	t.Parallel()

	if err := run(nil, []string{"version"}, "dev"); !errors.Is(err, errOutputUnavailable) {
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
