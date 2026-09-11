package sensoradapter

import (
	"encoding/json"
)

// This byte bound applies in addition to the configured entry-count bound.
// It bounds encoded sanitized identity, not raw provider events or credentials.
const maximumCacheEncodedBytes = 8 << 20

type cachedProcessIdentity struct {
	Node          string `json:"node"`
	PID           uint32 `json:"pid"`
	StartedAt     string `json:"started_at"`
	ExecID        string `json:"exec_id"`
	Namespace     string `json:"namespace"`
	PodName       string `json:"pod_name"`
	PodUID        string `json:"pod_uid"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
}

func cachedIdentity(key processCorrelationKey, process providerProcess) cachedProcessIdentity {
	return cachedProcessIdentity{Node: key.node, PID: process.PID, StartedAt: process.StartTime, ExecID: process.ExecID, Namespace: process.Pod.Namespace, PodName: process.Pod.Name, PodUID: process.Pod.UID, ContainerID: process.Pod.Container.ID, ContainerName: process.Pod.Container.Name}
}

func (identity cachedProcessIdentity) process() providerProcess {
	return providerProcess{PID: identity.PID, StartTime: identity.StartedAt, ExecID: identity.ExecID, Binary: "correlated", Pod: providerPod{Namespace: identity.Namespace, Name: identity.PodName, UID: identity.PodUID, Container: providerContainer{ID: identity.ContainerID, Name: identity.ContainerName}}}
}

func cacheIdentitySize(identity cachedProcessIdentity) (int, error) {
	// Validate every bounded scalar before serialization, so a hostile decoded
	// checkpoint cannot trigger a second unbounded allocation while validating.
	process := identity.process()
	if !boundedText(identity.Node, 253) || identity.PID == 0 || !validProcessIdentity(process) {
		return 0, ErrStream
	}
	started, _ := parseProviderTimestamp(identity.StartedAt)
	if started.Format("2006-01-02T15:04:05.000000000Z") != identity.StartedAt {
		return 0, ErrStream
	}
	payload, err := json.Marshal(identity)
	if err != nil {
		return 0, ErrStream
	}
	return len(payload) + 1, nil
}

func (normalizer *Normalizer) checkpoint() ([]cachedProcessIdentity, error) {
	if normalizer == nil {
		return nil, ErrStream
	}
	normalizer.mu.Lock()
	defer normalizer.mu.Unlock()
	result := make([]cachedProcessIdentity, 0, len(normalizer.order))
	for _, key := range normalizer.order {
		process, ok := normalizer.values[key]
		if !ok {
			return nil, ErrStream
		}
		result = append(result, cachedIdentity(key, process))
	}
	return result, nil
}

func (normalizer *Normalizer) restoreCheckpoint(identities []cachedProcessIdentity) error {
	if normalizer == nil {
		return ErrStream
	}
	normalizer.mu.Lock()
	defer normalizer.mu.Unlock()
	if len(identities) > normalizer.maximum {
		return ErrStream
	}
	values := make(map[processCorrelationKey]providerProcess)
	order := make([]processCorrelationKey, 0, len(identities))
	encodedBytes := 2
	for _, identity := range identities {
		size, err := cacheIdentitySize(identity)
		if err != nil || size > maximumCacheEncodedBytes-encodedBytes {
			return ErrStream
		}
		process := identity.process()
		key, ok := correlationKey(identity.Node, process)
		if _, duplicate := values[key]; !ok || duplicate {
			return ErrStream
		}
		values[key] = process
		order = append(order, key)
		encodedBytes += size
	}
	// Publish the entire restored cache only after all validation succeeds.
	normalizer.values, normalizer.order, normalizer.encodedBytes = values, order, encodedBytes
	return nil
}
