package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestParseGatewayProcessOperationAcceptsOnlyCanonicalSelectiveAcknowledgment(t *testing.T) {
	digest := sha256.Sum256([]byte("request"))
	eventID := gatewayRuntimeSequenceID(701)
	incidentID := gatewayRuntimeSequenceID(702)
	operation, err := parseGatewayProcessOperation([]string{"acknowledge-quarantine", eventID, hex.EncodeToString(digest[:]), "7", incidentID})
	if err != nil || operation.Mode != "acknowledge-quarantine" || operation.Acknowledgment.EventID != eventID || operation.Acknowledgment.RequestDigest != digest || operation.Acknowledgment.ConfirmedFloor != 7 || operation.Acknowledgment.IncidentID != incidentID {
		t.Fatalf("operation=%#v err=%v", operation, err)
	}
	if serving, err := parseGatewayProcessOperation(nil); err != nil || serving.Mode != "serve" {
		t.Fatalf("serving=%#v err=%v", serving, err)
	}
	for _, arguments := range [][]string{
		{"acknowledge-quarantine", eventID, strings.ToUpper(hex.EncodeToString(digest[:])), "7", incidentID},
		{"acknowledge-quarantine", eventID, hex.EncodeToString(digest[:]), "07", incidentID},
		{"acknowledge-quarantine", "event", hex.EncodeToString(digest[:]), "7", incidentID},
		{"acknowledge-quarantine", eventID, hex.EncodeToString(digest[:]), "7", "incident"},
		{"acknowledge-quarantine", eventID, hex.EncodeToString(digest[:]), "7"},
		{"serve"},
	} {
		if candidate, err := parseGatewayProcessOperation(arguments); !errors.Is(err, errRuntimeUnavailable) || candidate.Mode != "" {
			t.Fatalf("arguments=%q candidate=%#v err=%v", arguments, candidate, err)
		}
	}
}

func TestRunGatewayQuarantineAcknowledgmentClosesAndEmitsExactReceipt(t *testing.T) {
	digest := sha256.Sum256([]byte("request"))
	acknowledgment := gatewayQuarantineAcknowledgment{EventID: gatewayRuntimeSequenceID(703), RequestDigest: digest, ConfirmedFloor: 11, IncidentID: gatewayRuntimeSequenceID(704)}
	acknowledged := gatewayQuarantineAcknowledgment{}
	closed := 0
	dependencies := productionGatewayDependencies{
		AcknowledgeQuarantine: func(_ context.Context, value gatewayQuarantineAcknowledgment) error { acknowledged = value; return nil },
		Close:                 func() error { closed++; return nil },
	}
	var output bytes.Buffer
	if err := runGatewayQuarantineAcknowledgment(context.Background(), &output, dependencies, acknowledgment); err != nil {
		t.Fatal(err)
	}
	if acknowledged != acknowledgment || closed != 1 || output.String() != `{"event_id":"`+acknowledgment.EventID+`","confirmed_floor":11,"incident_id":"`+acknowledgment.IncidentID+`","acknowledged":true}`+"\n" {
		t.Fatalf("acknowledged=%#v closed=%d output=%q", acknowledged, closed, output.String())
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}
