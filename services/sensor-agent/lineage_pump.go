package main

import (
	"context"
	"errors"
	"math"
	"time"
)

var errLineagePump = errors.New("sensor lineage pump stopped")
var errLineagePumpCounter = errors.New("sensor lineage pump counter exhausted")

type lineagePumpConfig struct {
	BatchSize                    int
	FlushInterval, CheckInterval time.Duration
	MaximumDuration              time.Duration
}

func validLineagePumpConfig(config lineagePumpConfig) bool {
	return config.BatchSize >= 1 && config.BatchSize <= 1000 && config.FlushInterval >= 50*time.Millisecond && config.FlushInterval <= 30*time.Second && config.CheckInterval >= 50*time.Millisecond && config.CheckInterval <= time.Minute && (config.MaximumDuration == 0 || config.MaximumDuration >= 100*time.Millisecond && config.MaximumDuration <= 24*time.Hour)
}

type lineagePumpResult struct {
	Reason                       string
	Records, Chunks              int
	Bytes                        int64
	Dropped, Filtered, Uncertain uint64
	Sealed                       bool
}

type lineagePumpStorage interface {
	Append(context.Context, [][]byte) (lineageSpoolChunk, error)
	Seal(context.Context, string, uint64, uint64) error
}

type lineagePumpReceive struct {
	line []byte
	err  error
}
type lineagePumpCounts struct {
	received, rejected, filtered uint64
	overflow                     bool
}

func incrementLineagePumpCount(value *uint64) bool {
	if *value == math.MaxUint64 {
		return false
	}
	*value++
	return true
}

// Only one worker mutates counts. The owner reads them only after done closes.
// At most one result is queued and one is held by a blocked sender; gRPC's own
// transport buffers are separate. Cancellation never requires room in the queue.
func receiveLineagePump(ctx context.Context, subscription *lineageSubscription, output chan<- lineagePumpReceive, counts *lineagePumpCounts, done chan<- struct{}) {
	defer close(done)
	for {
		line, err := subscription.Next()
		switch {
		case errors.Is(err, errLineageEventFiltered):
			if incrementLineagePumpCount(&counts.filtered) {
				continue
			}
			counts.overflow, err = true, errLineagePumpCounter
		case errors.Is(err, errLineageEvent):
			if incrementLineagePumpCount(&counts.rejected) {
				continue
			}
			counts.overflow, err = true, errLineagePumpCounter
		case err == nil:
			if !incrementLineagePumpCount(&counts.received) {
				counts.overflow, err = true, errLineagePumpCounter
			}
		}
		select {
		case output <- lineagePumpReceive{line: line, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

// Owns one admitted generation for one run. Borrowed identity resources remain
// open. There is no reconnect, deletion or historical adoption here. Production
// must supply bounded configuration and the separate durable consumer/reclaimer.
func runLineagePump(ctx context.Context, generation *lineageGeneration, config lineagePumpConfig) (lineagePumpResult, error) {
	if generation == nil {
		return lineagePumpResult{}, errLineagePump
	}
	return runLineagePumpWithStorage(ctx, generation, config, generation.storage)
}

// The normal entry point always supplies the generation's held spool. The narrow
// dependency permits failure tests wrapping actual publication, not fake events.
func runLineagePumpWithStorage(ctx context.Context, generation *lineageGeneration, config lineagePumpConfig, storage lineagePumpStorage) (result lineagePumpResult, err error) {
	if ctx == nil || generation == nil || generation.context == nil || generation.subscription == nil || generation.storage == nil || nilClusterValue(generation.api) || generation.boot == nil || nilClusterValue(storage) || !validLineagePumpConfig(config) {
		return result, errLineagePump
	}
	if !generation.pumpStarted.CompareAndSwap(false, true) {
		return result, errLineagePump
	}
	defer generation.Close()
	generation.storage.spool.mu.Lock()
	fresh := generation.storage.source == generation.source && generation.storage.records == 0 && generation.storage.chunks == 0 && generation.storage.bytes == 0 && !generation.storage.sealed && !generation.storage.poisoned && generation.storage.valid()
	generation.storage.spool.mu.Unlock()
	if !fresh {
		return result, errLineagePump
	}
	runContext, cancelRun := context.WithCancel(ctx)
	stopGeneration := context.AfterFunc(generation.context, cancelRun)
	defer func() { stopGeneration(); cancelRun() }()
	receiveContext, cancelReceive := context.WithCancel(runContext)
	defer cancelReceive()
	received := make(chan lineagePumpReceive, 1)
	joined := make(chan struct{})
	counts := &lineagePumpCounts{}
	go receiveLineagePump(receiveContext, generation.subscription, received, counts, joined)
	flushTimer, checkTimer := time.NewTicker(config.FlushInterval), time.NewTicker(config.CheckInterval)
	defer flushTimer.Stop()
	defer checkTimer.Stop()
	var rotation <-chan time.Time
	if config.MaximumDuration != 0 {
		timer := time.NewTimer(config.MaximumDuration)
		defer timer.Stop()
		rotation = timer.C
	}
	batch := make([][]byte, 0, config.BatchSize)
	batchBytes := 0
	committed := uint64(0)
	canceled := func() bool { return ctx.Err() != nil || generation.context.Err() != nil || runContext.Err() != nil }
	checkIdentity := func(checkContext context.Context) string {
		if canceled() {
			return "shutdown"
		}
		if checkContext.Err() != nil {
			return "identity_unavailable"
		}
		identity, err := resolveLineageIdentity(checkContext, generation.source.NodeName, generation.api, generation.boot)
		if canceled() {
			return "shutdown"
		}
		if checkContext.Err() != nil {
			return "identity_unavailable"
		}
		if err != nil {
			return "identity_unavailable"
		}
		if identity.NodeName != generation.source.NodeName || identity.ClusterUID != generation.source.ClusterUID || identity.NodeUID != generation.source.NodeUID || identity.BootID != generation.source.BootID {
			return "identity_changed"
		}
		return ""
	}
	flush := func(flushContext context.Context) string {
		if len(batch) == 0 {
			return ""
		}
		if reason := checkIdentity(flushContext); reason != "" {
			return reason
		}
		chunk, err := storage.Append(flushContext, batch)
		if errors.Is(err, errLineageSpoolFull) {
			return "capacity"
		}
		if err != nil {
			// Publication can be visible despite an error. Neither seal nor a
			// definite-drop count may claim that this batch was never persisted.
			result.Uncertain = uint64(len(batch))
			return "spool_error"
		}
		committed += uint64(chunk.Records)
		result.Records += chunk.Records
		result.Chunks++
		result.Bytes += chunk.Bytes
		clear(batch)
		batch = batch[:0]
		batchBytes = 0
		return ""
	}
	for result.Reason == "" {
		if canceled() {
			result.Reason = "shutdown"
			break
		}
		select {
		case <-runContext.Done():
			result.Reason = "shutdown"
		case <-generation.context.Done():
			result.Reason = "shutdown"
		case <-rotation:
			result.Reason = "rotation"
		case <-checkTimer.C:
			result.Reason = checkIdentity(runContext)
		case <-flushTimer.C:
			result.Reason = flush(runContext)
		case item := <-received:
			if item.err != nil {
				result.Reason = "disconnect"
				if errors.Is(item.err, errLineagePumpCounter) {
					result.Reason = "counter_overflow"
				}
				break
			}
			if !validLineageSpoolRecordShape(item.line, generation.source.NodeName) {
				result.Reason = "source_mismatch"
				break
			}
			if batchBytes+len(item.line)+1 > lineageChunkBytes {
				if result.Reason = flush(runContext); result.Reason != "" {
					break
				}
			}
			batch = append(batch, item.line)
			batchBytes += len(item.line) + 1
			if len(batch) == config.BatchSize {
				result.Reason = flush(runContext)
			}
		}
	}
	// One cleanup budget covers receive join, final identity/flush and seal. A
	// canceled caller never permits a final event flush, but may record known
	// termination counters in already-owned storage. Local FS calls aren't a hard
	// wall-clock guarantee. A join timeout leaves termination unknown and unsealed.
	cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCleanup()
	cancelReceive()
	generation.subscription.Close()
	select {
	case <-joined:
	case <-cleanupContext.Done():
		result.Reason = "shutdown_timeout"
		return result, errLineagePump
	}
	if (result.Reason == "disconnect" || result.Reason == "rotation") && len(batch) != 0 {
		deadline, _ := cleanupContext.Deadline()
		finalContext, cancelFinal := context.WithDeadline(runContext, deadline)
		if reason := flush(finalContext); reason != "" {
			result.Reason = reason
		}
		cancelFinal()
	}
	// Counts are now immutable. received includes queued and sender-held records,
	// not only records dequeued into batch. Upstream loss is not measurable here.
	result.Filtered = counts.filtered
	if counts.overflow || counts.received < committed || counts.received-committed < result.Uncertain {
		result.Reason = "counter_overflow"
		return result, errLineagePump
	}
	uncommitted := counts.received - committed - result.Uncertain
	if counts.rejected > math.MaxUint64-uncommitted {
		result.Reason = "counter_overflow"
		return result, errLineagePump
	}
	result.Dropped = counts.rejected + uncommitted
	if result.Uncertain != 0 {
		return result, errLineagePump
	}
	if storage.Seal(cleanupContext, result.Reason, result.Dropped, result.Filtered) != nil {
		return result, errLineagePump
	}
	result.Sealed = true
	if result.Reason != "shutdown" && result.Reason != "rotation" {
		return result, errLineagePump
	}
	return result, nil
}
