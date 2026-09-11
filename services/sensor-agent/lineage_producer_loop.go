package main

import (
	"context"
	"time"
)

type lineageProducerLoopConfig struct {
	Scope            lineageProducerConfig
	NodeName         string
	Pump             lineagePumpConfig
	OperationTimeout time.Duration
}

func runLineageProducerLoop(ctx context.Context, spool *lineageSpool, receipts *lineageReceiptReader, config lineageProducerLoopConfig, start func(context.Context) (*lineageGeneration, error), ticks <-chan time.Time, setReady func(bool)) error {
	if ctx == nil || spool == nil || receipts == nil || start == nil || ticks == nil || setReady == nil || !validKubernetesName(config.NodeName) || !enrollmentBindingPattern.MatchString(config.Scope.EnrollmentBinding) || !validLineageDestination(config.Scope.Destination) || config.Scope.ConsumerUID != receipts.owner || !validLineagePumpConfig(config.Pump) || config.Pump.MaximumDuration == 0 || config.OperationTimeout < time.Second || config.OperationTimeout > 30*time.Second {
		return errLineageGeneration
	}
	var active *lineageGeneration
	var completed <-chan struct{}
	// The loop owns each generation but borrows spool, receipts and startup
	// dependencies. Join the pump before the caller can close borrowed resources.
	// Local filesystem calls aren't a hard wall-clock shutdown guarantee.
	defer func() {
		setReady(false)
		if active != nil {
			active.cancel()
			<-completed
		}
	}()
	tick := func() {
		operation, cancel := context.WithTimeout(ctx, config.OperationTimeout)
		_, err := spool.ReconcileProducer(operation, receipts, config.Scope)
		cancel()
		if err != nil || ctx.Err() != nil {
			setReady(false)
			return
		}
		if active != nil {
			select {
			case <-completed:
				active, completed = nil, nil
			default:
				setReady(true)
				return
			}
		}
		// Don't even open a provider subscription while all generation slots are
		// occupied. Create repeats capacity and identity checks under ownership.
		spool.mu.Lock()
		inventory, err := spool.reclaimInventory()
		room := err == nil && spool.active == nil && len(inventory.directories) < lineageSpoolSlots
		spool.mu.Unlock()
		if !room {
			setReady(false)
			return
		}
		generation, err := start(ctx)
		if err != nil || generation == nil {
			generation.Close()
			setReady(false)
			return
		}
		if generation.cancel == nil || generation.context == nil || generation.storage == nil || generation.storage.spool != spool || generation.Source().EnrollmentBinding != config.Scope.EnrollmentBinding || generation.Source().NodeName != config.NodeName || ctx.Err() != nil {
			generation.Close()
			setReady(false)
			return
		}
		active = generation
		done := make(chan struct{})
		completed = done
		go func() {
			defer close(done)
			defer generation.Close()
			// A sealed rotation is normal. Other outcomes leave exact evidence
			// for the next reconciliation tick, never historical relabeling.
			_, _ = runLineagePump(ctx, generation, config.Pump)
		}()
		setReady(true)
	}
	if ctx.Err() == nil {
		tick()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-completed:
			active, completed = nil, nil
			setReady(false)
			// Restart only on a caller tick, never in a disconnect spin loop.
		case _, ok := <-ticks:
			if !ok {
				return errLineageGeneration
			}
			tick()
		}
	}
}
