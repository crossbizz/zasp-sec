package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

var errLineageGeneration = errors.New("sensor lineage generation unavailable")

type lineageGeneration struct {
	source       sensoradapter.LineageSource
	subscription *lineageSubscription
	storage      *lineageSpoolGeneration
	cancel       context.CancelFunc
	close        sync.Once
	context      context.Context
	api          lineageIdentityAPI
	boot         *hostBootReader
	pumpStarted  atomic.Bool
}

// The production owner supplies its held lineageSpool. This narrow publication
// dependency also permits exercising post-publication cancellation with the
// real spool in tests, without filesystem or timing hooks in the writer.
type lineageGenerationPublisher interface {
	Create(context.Context, sensoradapter.LineageSource) (*lineageSpoolGeneration, error)
}

// Takes endpoint ownership even on failure. API, boot and spool are borrowed;
// their owner must outlive this generation. Only the newly created generation
// and its checked subscription belong to this object. Production callers must
// provide the controlled host mounts, procfs boot reader and Kubernetes client.
// This constructor doesn't grant tenant authority or authenticate those mounts.
func startLineageGeneration(ctx context.Context, nodeName, binding string, api lineageIdentityAPI, boot *hostBootReader, endpoint *lineageSocket, spool lineageGenerationPublisher) (_ *lineageGeneration, err error) {
	if ctx == nil || ctx.Err() != nil || !validKubernetesName(nodeName) || !enrollmentBindingPattern.MatchString(binding) || nilClusterValue(api) || boot == nil || endpoint == nil || nilClusterValue(spool) {
		endpoint.Close()
		return nil, errLineageGeneration
	}
	lifetime, cancel := context.WithCancel(ctx)
	generation := &lineageGeneration{cancel: cancel, context: lifetime, api: api, boot: boot}
	startup, cancelStartup := context.WithTimeout(lifetime, 15*time.Second)
	stopStartup := context.AfterFunc(startup, cancel)
	defer func() {
		stopStartup()
		cancelStartup()
		if err != nil {
			generation.Close()
			endpoint.Close()
		}
	}()
	before, identityErr := resolveLineageIdentity(startup, nodeName, api, boot)
	if identityErr != nil {
		return nil, errLineageGeneration
	}
	generation.subscription, err = newLineageSubscription(lifetime, endpoint)
	if err != nil {
		return nil, errLineageGeneration
	}
	// GetEvents has submitted the client request. It doesn't acknowledge server
	// registration or establish an event-history fence. These repeated identity
	// observations reject drift around setup, not arbitrary provider replay.
	after, identityErr := resolveLineageIdentity(startup, nodeName, api, boot)
	if identityErr != nil || after != before || startup.Err() != nil {
		return nil, errLineageGeneration
	}
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return nil, errLineageGeneration
	}
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80
	generation.source = sensoradapter.LineageSource{
		Profile:           "tetragon-local-stream-v1",
		GenerationID:      fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]),
		EnrollmentBinding: binding,
		NodeName:          before.NodeName, ClusterUID: before.ClusterUID, NodeUID: before.NodeUID, BootID: before.BootID,
	}
	generation.storage, err = spool.Create(startup, generation.source)
	if err != nil || startup.Err() != nil || !stopStartup() || lifetime.Err() != nil {
		return nil, errLineageGeneration
	}
	return generation, nil
}

func (generation *lineageGeneration) Source() sensoradapter.LineageSource {
	if generation == nil {
		return sensoradapter.LineageSource{}
	}
	return generation.source
}

// Close cancels a blocked receive before releasing storage. No seal is implied:
// the future pump must explicitly record known termination/gap counters first.
// Bare close or startup failure leaves termination unknown and data untouched.
func (generation *lineageGeneration) Close() error {
	if generation == nil {
		return nil
	}
	generation.close.Do(func() {
		if generation.cancel != nil {
			generation.cancel()
		}
		if generation.subscription != nil {
			generation.subscription.Close()
		}
		if generation.storage != nil {
			generation.storage.Close()
		}
	})
	return nil
}
