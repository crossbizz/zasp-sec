package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
)

func indexedAddress(index int) netip.Addr {
	return netip.AddrFrom4([4]byte{100, byte(index >> 16), byte(index >> 8), byte(index)})
}

func TestEgressTrackerMarkChangedForcesNextSnapshot(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	tracker := newEgressTracker(func() time.Time { return now })
	if _, changed := tracker.snapshot("node-a"); changed {
		t.Fatal("a new tracker reported a change")
	}
	tracker.markChanged()
	if document, changed := tracker.snapshot("node-a"); !changed || len(document.Workloads) != 0 || document.Node != "node-a" {
		t.Fatalf("after markChanged: %+v, changed %v", document, changed)
	}
	if _, changed := tracker.snapshot("node-a"); changed {
		t.Fatal("markChanged applied to more than one snapshot")
	}
}

func TestEgressTrackerIgnoresUnusableResolutionsAndConnections(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	tracker := newEgressTracker(func() time.Time { return now })
	pod, openai := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("104.18.6.192")
	tracker.observeResolution(dnsResolution{name: "api.openai.com", addresses: []netip.Addr{openai}})
	tracker.observeResolution(dnsResolution{client: pod, name: "example.com", addresses: []netip.Addr{openai}})
	if matched, _, _ := tracker.counters(); matched != 0 || len(tracker.resolutions) != 0 {
		t.Fatalf("stored an unusable resolution: matched %d, %d stored", matched, len(tracker.resolutions))
	}
	tracker.observeResolution(dnsResolution{client: pod, name: "api.openai.com", addresses: []netip.Addr{openai}})
	if tracker.observeConnection("shop", "Deployment", "web", netip.Addr{}, openai) || tracker.observeConnection("shop", "Deployment", "web", pod, netip.Addr{}) {
		t.Fatal("a connection without addresses joined")
	}
	if tracker.observeConnection("Shop", "Deployment", "web", pod, openai) || tracker.observeConnection("shop", "ReplicaSet", "web", pod, openai) {
		t.Fatal("a connection with an invalid workload identity joined")
	}
	// Tetragon may report IPv4 sockets as IPv4-mapped IPv6.
	if !tracker.observeConnection("shop", "Deployment", "web", netip.MustParseAddr("::ffff:10.1.2.3"), netip.MustParseAddr("::ffff:104.18.6.192")) {
		t.Fatal("a mapped connection did not join its IPv4 resolution")
	}
	if matched, joined, dropped := tracker.counters(); matched != 1 || joined != 1 || dropped != 0 {
		t.Fatalf("counters = %d, %d, %d", matched, joined, dropped)
	}
}

func TestEgressTrackerResolutionCapacity(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	tracker := newEgressTracker(func() time.Time { return now })
	pod := netip.MustParseAddr("10.1.2.3")
	for index := range maximumEgressResolutions {
		tracker.resolutions[egressPair{pod, indexedAddress(index)}] = egressResolution{token: "openai", expires: now.Add(time.Minute)}
	}
	fresh, known := netip.MustParseAddr("160.79.104.10"), indexedAddress(7)
	tracker.observeResolution(dnsResolution{client: pod, name: "api.anthropic.com", addresses: []netip.Addr{fresh, known}})
	if _, stored := tracker.resolutions[egressPair{pod, fresh}]; stored || len(tracker.resolutions) != maximumEgressResolutions {
		t.Fatalf("the table grew past its bound: %d", len(tracker.resolutions))
	}
	if tracker.resolutions[egressPair{pod, known}].token != "anthropic" {
		t.Fatal("a full table refused to refresh a pair it already holds")
	}
	if _, _, dropped := tracker.counters(); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	// Once the held answers expire, a new one is admitted after a sweep; the
	// refreshed pair has a new lifetime and survives the sweep.
	now = now.Add(2 * time.Minute)
	tracker.observeResolution(dnsResolution{client: pod, name: "api.anthropic.com", addresses: []netip.Addr{fresh}})
	if _, stored := tracker.resolutions[egressPair{pod, fresh}]; !stored || len(tracker.resolutions) != 2 {
		t.Fatalf("expired answers were not swept: %d held", len(tracker.resolutions))
	}
	if !tracker.observeConnection("shop", "Deployment", "support-bot", pod, fresh) {
		t.Fatal("the admitted answer did not join")
	}
}

func TestEgressTrackerWorkloadCapacity(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	tracker := newEgressTracker(func() time.Time { return now })
	for index := range agentsignals.MaximumEgressWorkloads {
		tracker.workloads[egressWorkloadKey{"shop", "Deployment", "web-" + indexedAddress(index).String()}] = map[string]time.Time{"openai": now}
	}
	pod, openai := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("104.18.6.192")
	tracker.observeResolution(dnsResolution{client: pod, name: "api.openai.com", addresses: []netip.Addr{openai}})
	if tracker.observeConnection("shop", "Deployment", "one-too-many", pod, openai) {
		t.Fatal("a workload past the bound was recorded")
	}
	if _, present := tracker.workloads[egressWorkloadKey{"shop", "Deployment", "one-too-many"}]; present || len(tracker.workloads) != agentsignals.MaximumEgressWorkloads {
		t.Fatalf("the workload table grew to %d", len(tracker.workloads))
	}
	existing := egressWorkloadKey{"shop", "Deployment", "web-" + indexedAddress(3).String()}
	now = now.Add(2 * time.Hour)
	tracker.observeResolution(dnsResolution{client: pod, name: "api.openai.com", addresses: []netip.Addr{openai}})
	if !tracker.observeConnection(existing.namespace, existing.kind, existing.name, pod, openai) || !tracker.workloads[existing]["openai"].Equal(now) {
		t.Fatal("a workload already held stopped advancing at the bound")
	}
}

func TestEgressTrackerRestoreKeepsOnlyUsableNewestEntries(t *testing.T) {
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	tracker := newEgressTracker(func() time.Time { return now })
	pod, openai := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("104.18.6.192")
	tracker.observeResolution(dnsResolution{client: pod, name: "api.openai.com", addresses: []netip.Addr{openai}})
	tracker.observeConnection("shop", "Deployment", "live", pod, openai)
	tracker.snapshot("node-a")
	hourAgo, dayAgo := agentsignals.FormatEgressTime(now.Add(-time.Hour)), agentsignals.FormatEgressTime(now.Add(-24*time.Hour))
	tracker.restore(agentsignals.EgressObservations{Workloads: []agentsignals.EgressWorkload{
		// The live observation is newer than the stored one and must win.
		{Namespace: "shop", Kind: "Deployment", Name: "live", Destinations: []agentsignals.EgressDestination{{Token: "openai", LastSeen: dayAgo}}},
		{Namespace: "shop", Kind: "Job", Name: "batch", Destinations: []agentsignals.EgressDestination{
			{Token: "anthropic", LastSeen: dayAgo}, {Token: "anthropic", LastSeen: hourAgo}, {Token: "anthropic", LastSeen: dayAgo},
			{Token: "cohere", LastSeen: "yesterday"},
			{Token: "google", LastSeen: agentsignals.FormatEgressTime(now.Add(time.Minute))},
			{Token: "mistral", LastSeen: agentsignals.FormatEgressTime(now.Add(-agentsignals.EgressObservationRetention - time.Second))},
		}},
		{Namespace: "shop", Kind: "Job", Name: "stale", Destinations: []agentsignals.EgressDestination{{Token: "groq", LastSeen: "2020-01-01T00:00:00Z"}}},
	}})
	document, changed := tracker.snapshot("node-a")
	if changed {
		t.Fatal("restoring a published document reported a change")
	}
	if len(document.Workloads) != 2 {
		t.Fatalf("workloads = %+v", document.Workloads)
	}
	live, batch := document.Workloads[0], document.Workloads[1] // canonical order: Deployment before Job
	if batch.Name != "batch" || len(batch.Destinations) != 1 || batch.Destinations[0].Token != "anthropic" || batch.Destinations[0].LastSeen != hourAgo {
		t.Fatalf("batch = %+v", batch)
	}
	if live.Name != "live" || len(live.Destinations) != 1 || live.Destinations[0].LastSeen != agentsignals.FormatEgressTime(now) {
		t.Fatalf("live = %+v", live)
	}
}
