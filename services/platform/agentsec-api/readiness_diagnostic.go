package main

import (
	"context"
	"io"
	"sync"
)

// readinessDiagnostic names the readiness check that refused, so an operator
// facing a not-ready API can tell an unavailable search index from an
// unregistered database principal. Names come from the fixed list at the call
// site; no dependency error text is written.
type readinessDiagnostic struct {
	mu     sync.Mutex
	output io.Writer
	last   string
}

func newReadinessDiagnostic(output io.Writer) *readinessDiagnostic {
	return &readinessDiagnostic{output: output}
}

// named wraps one check. A check that fails only because a sibling's failure
// cancelled the shared context is not reported: it is a consequence, not a
// cause.
func (diagnostic *readinessDiagnostic) named(name string, check func(context.Context) error) func(context.Context) error {
	if diagnostic == nil || check == nil {
		return check
	}
	return func(ctx context.Context) error {
		err := check(ctx)
		if err != nil && ctx != nil && ctx.Err() == nil {
			diagnostic.report(name)
		}
		return err
	}
}

// report writes one line when the refusing check changes, not on every probe.
func (diagnostic *readinessDiagnostic) report(name string) {
	diagnostic.mu.Lock()
	defer diagnostic.mu.Unlock()
	if diagnostic.output == nil || diagnostic.last == name {
		return
	}
	diagnostic.last = name
	_, _ = io.WriteString(diagnostic.output, "{\"event\":\"readiness_refused\",\"service\":\"agentsec-api\",\"check\":\""+name+"\"}\n")
}

// ready clears the last refusal so a later refusal by the same check is
// reported again.
func (diagnostic *readinessDiagnostic) ready() {
	if diagnostic == nil {
		return
	}
	diagnostic.mu.Lock()
	diagnostic.last = ""
	diagnostic.mu.Unlock()
}
