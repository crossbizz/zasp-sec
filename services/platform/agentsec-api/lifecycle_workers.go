package main

import (
	"context"
	"errors"
)

func runLifecycleWorkers(ctx context.Context, workers ...func(context.Context) error) error {
	if ctx == nil || len(workers) == 0 {
		return errRuntimeUnavailable
	}
	for _, worker := range workers {
		if worker == nil {
			return errRuntimeUnavailable
		}
	}
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(workers))
	for _, worker := range workers {
		go func(run func(context.Context) error) {
			results <- run(workerContext)
		}(worker)
	}
	remaining := len(workers)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		case err := <-results:
			remaining--
			if err != nil && !errors.Is(err, context.Canceled) {
				cancel()
				return errRuntimeUnavailable
			}
			if ctx.Err() == nil {
				cancel()
				return errRuntimeUnavailable
			}
		}
	}
	return ctx.Err()
}
