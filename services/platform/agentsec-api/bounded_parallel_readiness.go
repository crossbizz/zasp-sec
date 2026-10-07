package main

import "context"

// All checks share their caller's deadline. Completion includes each check's
// cleanup; no check may outlive this gate, including after a sibling refuses.
func boundedParallelReadiness(ctx context.Context, checks ...func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || len(checks) == 0 {
		return errRuntimeUnavailable
	}
	for _, check := range checks {
		if check == nil {
			return errRuntimeUnavailable
		}
	}
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(checks))
	for _, check := range checks {
		go func() { results <- check(bounded) }()
	}
	failed := false
	for range checks {
		if <-results != nil {
			failed = true
			cancel()
		}
	}
	if failed || bounded.Err() != nil {
		return errRuntimeUnavailable
	}
	return nil
}

// Reconciler availability is inspected only after every metadata closure joins.
func currentComponentReadiness(ctx context.Context, final func() bool, checks ...func(context.Context) error) error {
	if final == nil || boundedParallelReadiness(ctx, checks...) != nil || !final() || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	return nil
}
