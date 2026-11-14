package main

import (
	"net/netip"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
)

const (
	// A resolution joins to connections for this long. Clients reuse an
	// answer for at most its TTL, and public model APIs use short TTLs.
	egressResolutionLifetime = time.Hour
	maximumEgressResolutions = 50_000
	// last_seen advances in the published document at most this often, so a
	// busy workload does not rewrite the ConfigMap on every connection.
	egressLastSeenGranularity = time.Hour
)

type egressPair struct{ client, destination netip.Addr }

type egressResolution struct {
	token   string
	expires time.Time
}

type egressWorkloadKey struct{ namespace, kind, name string }

// egressTracker joins DNS answers to connections. It keeps catalog tokens
// only: a name that matches nothing in the catalog is dropped before it is
// stored, and no address or name is ever published.
type egressTracker struct {
	mu          sync.Mutex
	now         func() time.Time
	resolutions map[egressPair]egressResolution
	workloads   map[egressWorkloadKey]map[string]time.Time
	changed     bool
	// Counters for the one-line status the daemon prints.
	matchedNames, joinedConnections, droppedResolutions uint64
}

func newEgressTracker(now func() time.Time) *egressTracker {
	return &egressTracker{now: now, resolutions: map[egressPair]egressResolution{}, workloads: map[egressWorkloadKey]map[string]time.Time{}}
}

// observeResolution records a DNS answer when the name is in the catalog.
func (tracker *egressTracker) observeResolution(resolution dnsResolution) {
	token, ok := agentsignals.EgressHost(resolution.name)
	if !ok || !resolution.client.IsValid() {
		return
	}
	now := tracker.now()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.matchedNames++
	for _, address := range resolution.addresses {
		pair := egressPair{resolution.client, address}
		if _, known := tracker.resolutions[pair]; !known && len(tracker.resolutions) >= maximumEgressResolutions {
			tracker.expireResolutions(now)
			if len(tracker.resolutions) >= maximumEgressResolutions {
				tracker.droppedResolutions++
				continue
			}
		}
		tracker.resolutions[pair] = egressResolution{token: token, expires: now.Add(egressResolutionLifetime)}
	}
}

func (tracker *egressTracker) expireResolutions(now time.Time) {
	for pair, resolution := range tracker.resolutions {
		if !resolution.expires.After(now) {
			delete(tracker.resolutions, pair)
		}
	}
}

// observeConnection records a workload's outbound connection when the same
// source address was given the destination address as the answer for a
// catalog name. It reports whether the connection joined.
func (tracker *egressTracker) observeConnection(namespace, kind, name string, source, destination netip.Addr) bool {
	if !source.IsValid() || !destination.IsValid() || !agentsignals.ValidEgressWorkloadIdentity(namespace, kind, name) {
		return false
	}
	now := tracker.now()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	resolution, ok := tracker.resolutions[egressPair{source.Unmap(), destination.Unmap()}]
	if !ok || !resolution.expires.After(now) {
		return false
	}
	tracker.joinedConnections++
	key := egressWorkloadKey{namespace, kind, name}
	tokens := tracker.workloads[key]
	if tokens == nil {
		if len(tracker.workloads) >= agentsignals.MaximumEgressWorkloads {
			return false
		}
		tokens = map[string]time.Time{}
		tracker.workloads[key] = tokens
	}
	if prior, seen := tokens[resolution.token]; !seen || now.Sub(prior) >= egressLastSeenGranularity {
		tokens[resolution.token] = now
		tracker.changed = true
	}
	return true
}

// restore loads a previously published document so a restarted sensor keeps
// what it saw within the retention window.
func (tracker *egressTracker) restore(document agentsignals.EgressObservations) {
	now := tracker.now()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	for _, workload := range document.Workloads {
		key := egressWorkloadKey{workload.Namespace, workload.Kind, workload.Name}
		for _, destination := range workload.Destinations {
			seen, err := time.Parse(time.RFC3339, destination.LastSeen)
			if err != nil || seen.After(now) || now.Sub(seen) > agentsignals.EgressObservationRetention {
				continue
			}
			if tracker.workloads[key] == nil {
				tracker.workloads[key] = map[string]time.Time{}
			}
			if seen.After(tracker.workloads[key][destination.Token]) {
				tracker.workloads[key][destination.Token] = seen
			}
		}
	}
}

// snapshot prunes what fell out of the retention window and returns the
// document to publish, and whether it differs from the last one taken.
func (tracker *egressTracker) snapshot(node string) (agentsignals.EgressObservations, bool) {
	now := tracker.now()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.expireResolutions(now)
	document := agentsignals.EgressObservations{Version: agentsignals.EgressObservationsVersion, Node: node, GeneratedAt: agentsignals.FormatEgressTime(now), Workloads: []agentsignals.EgressWorkload{}}
	for key, tokens := range tracker.workloads {
		workload := agentsignals.EgressWorkload{Namespace: key.namespace, Kind: key.kind, Name: key.name}
		for token, seen := range tokens {
			if now.Sub(seen) > agentsignals.EgressObservationRetention {
				delete(tokens, token)
				tracker.changed = true
				continue
			}
			workload.Destinations = append(workload.Destinations, agentsignals.EgressDestination{Token: token, LastSeen: agentsignals.FormatEgressTime(seen)})
		}
		if len(tokens) == 0 {
			delete(tracker.workloads, key)
			continue
		}
		document.Workloads = append(document.Workloads, workload)
	}
	document.Normalize()
	changed := tracker.changed
	tracker.changed = false
	return document, changed
}

// markChanged makes the next snapshot report a change; the publisher calls
// it when a write failed so the document is offered again.
func (tracker *egressTracker) markChanged() {
	tracker.mu.Lock()
	tracker.changed = true
	tracker.mu.Unlock()
}

func (tracker *egressTracker) counters() (matched, joined, dropped uint64) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.matchedNames, tracker.joinedConnections, tracker.droppedResolutions
}
