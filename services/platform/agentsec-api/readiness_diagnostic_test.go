package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestReadinessDiagnosticNamesTheRefusingCheckOnceAndNotItsCancelledSiblings(t *testing.T) {
	var output bytes.Buffer
	diagnostic := newReadinessDiagnostic(&output)
	refuse := func(context.Context) error { return errors.New("postgres://user:secret@host refused") }
	pass := func(context.Context) error { return nil }

	if err := diagnostic.named("policy-history", refuse)(context.Background()); err == nil {
		t.Fatal("refusal was swallowed")
	}
	// The same refusal on the next probe is not repeated.
	_ = diagnostic.named("policy-history", refuse)(context.Background())
	_ = diagnostic.named("product-repository", pass)(context.Background())
	// A check that fails because the shared context was cancelled is a
	// consequence of another refusal and is not reported.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_ = diagnostic.named("identity-provider", refuse)(cancelled)
	_ = diagnostic.named("approval-notifications", refuse)(context.Background())
	// After readiness recovers, the same check refusing again is reported.
	diagnostic.ready()
	_ = diagnostic.named("approval-notifications", refuse)(context.Background())

	want := `{"event":"readiness_refused","service":"agentsec-api","check":"policy-history"}` + "\n" +
		`{"event":"readiness_refused","service":"agentsec-api","check":"approval-notifications"}` + "\n" +
		`{"event":"readiness_refused","service":"agentsec-api","check":"approval-notifications"}` + "\n"
	if output.String() != want {
		t.Fatalf("diagnostic output = %q", output.String())
	}
}

func TestReadinessDiagnosticIsOptional(t *testing.T) {
	var diagnostic *readinessDiagnostic
	check := func(context.Context) error { return nil }
	if diagnostic.named("policy-history", check)(context.Background()) != nil {
		t.Fatal("nil diagnostic changed a check")
	}
	diagnostic.ready()
}
