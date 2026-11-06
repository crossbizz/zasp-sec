package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"sort"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	coordinationv1 "k8s.io/api/coordination/v1"
)

func retainedHeartbeat(env nodecoveragewire.Envelope) sensoradapter.Heartbeat {
	return sensoradapter.Heartbeat{Sequence: env.Sequence, Status: env.Status, Capabilities: append([]string(nil), env.Capabilities...), Kernel: env.Kernel, BTF: env.BTF, EventRate: env.EventRate, Drops: env.Drops}
}
func (c *ClusterCoordinator) retainedEnvelopeMatches(env nodecoveragewire.Envelope, m *retainedManifest) bool {
	return env.Sequence == m.Sequence && env.StateUID == m.StateUID && env.StorageEpoch == m.StorageEpoch && env.SourceObservedAt.Equal(m.SourceObservedAt) && env.SourceObservedAt.Add(time.Duration(env.TTLSeconds)*time.Second).Equal(m.ExpiresAt) && env.TTLSeconds == int64(c.config.ReportTTL/time.Second) && env.CoverageSchema == nodecoveragewire.CoverageSchema && c.config.Coverage != nil && sameRetainedSelection(env.Selection, *c.config.Coverage)
}
func sameRetainedSelection(a, b nodecoveragewire.NodeCoverageSelection) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func (c *ClusterCoordinator) restoreRetained(ctx context.Context, state retainedState) ([]byte, nodecoveragewire.Envelope, []retainedChunkRef, error) {
	body, refs, e := c.readRetainedBody(ctx, state)
	if e != nil {
		return nil, nodecoveragewire.Envelope{}, nil, e
	}
	env, e := nodecoveragewire.ParseEnvelope(body)
	if e != nil || !c.retainedEnvelopeMatches(env, state.Manifest) {
		return nil, nodecoveragewire.Envelope{}, nil, ErrCluster
	}
	return body, env, refs, nil
}
func (c *ClusterCoordinator) cacheRetained(body []byte, env nodecoveragewire.Envelope) (sensoradapter.Heartbeat, error) {
	c.pendingRetainedBody = bytes.Clone(body)
	return retainedHeartbeat(env), nil
}

// pendingOrPrepare dispatches here only after explicit opt-in. Legacy bytes and
// freshness markers are never reinterpreted as retained observations.
func (c *ClusterCoordinator) pendingRetainedOrPrepare(ctx context.Context, now time.Time) (sensoradapter.Heartbeat, error) {
	started := time.Now()
	c.pendingRetainedBody = nil
	anchor, state, e := c.loadRetainedState(ctx, true)
	if e != nil {
		return sensoradapter.Heartbeat{}, e
	}
	if state.Phase == "pending" {
		body, env, _, e := c.restoreRetained(ctx, state)
		if e != nil {
			return sensoradapter.Heartbeat{}, e
		}
		return c.cacheRetained(body, env)
	}
	if state.Phase == "preparing" {
		body, env, refs, readErr := c.restoreRetained(ctx, state)
		if readErr == nil && nodecoveragewire.ValidateFreshEnvelope(env, now.Add(time.Since(started))) == nil {
			sealed := *state.Manifest
			sealed.Chunks = refs
			sealed.MarkerSHA256 = c.retainedMarker(&sealed)
			state.Manifest = &sealed
			state.Phase = "pending"
			if _, e = c.storeRetainedState(ctx, anchor, state); e != nil {
				return sensoradapter.Heartbeat{}, e
			}
			return c.cacheRetained(body, env)
		}
		// A preparing record is proof that no send was permitted. CAS cannot erase a
		// concurrently sealed pending record; its resourceVersion has changed.
		state.Phase = "idle"
		state.Manifest = nil
		if _, e = c.storeRetainedState(ctx, anchor, state); e != nil {
			return sensoradapter.Heartbeat{}, e
		}
		return sensoradapter.Heartbeat{}, ErrClusterRetryable
	}
	if state.StorageEpoch == math.MaxInt64 || state.ResolvedAttemptSequence == math.MaxInt64 {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	result, e := sensoradapter.ObserveNodeCoverage(ctx, c.config.CoverageReader, *c.config.Coverage, now, c.config.ReportTTL)
	if e != nil {
		return sensoradapter.Heartbeat{}, ErrClusterRetryable
	}
	aggregate, observed, e := aggregateCoverageReport(result, result.InventoryObservedAt)
	if e != nil {
		return sensoradapter.Heartbeat{}, e
	}
	reports := make([]nodecoveragewire.NodeCoverageV2, 0, len(result.Reports))
	reports = append(reports, result.Reports...)
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].NodeUID+"/"+reports[i].BootID < reports[j].NodeUID+"/"+reports[j].BootID
	})
	selected := append([]nodecoveragewire.SelectedNode{}, result.SelectedNodes...)
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].NodeUID+"/"+selected[i].BootID < selected[j].NodeUID+"/"+selected[j].BootID
	})
	env := nodecoveragewire.Envelope{Heartbeat: nodecoveragewire.Heartbeat{Sequence: state.ResolvedAttemptSequence + 1, Status: aggregate.Status, Capabilities: aggregate.Capabilities, Kernel: aggregate.Kernel, BTF: aggregate.BTF, EventRate: aggregate.EventRate, Drops: aggregate.Drops}, CoverageSchema: nodecoveragewire.CoverageSchema, StateUID: state.StateUID, StorageEpoch: state.StorageEpoch + 1, Selection: *c.config.Coverage, TargetDigest: result.TargetDigest, InventoryObservedAt: result.InventoryObservedAt, SourceObservedAt: observed, TTLSeconds: int64(c.config.ReportTTL / time.Second), SensorDaemonSetUID: result.SensorDaemonSetUID, TetragonDaemonSetUID: result.TetragonDaemonSetUID, SelectedNodes: selected, Reports: reports}
	if nodecoveragewire.ValidateFreshEnvelope(env, now.Add(time.Since(started))) != nil {
		return sensoradapter.Heartbeat{}, ErrClusterRetryable
	}
	body, e := nodecoveragewire.MarshalEnvelope(env)
	if e != nil {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	manifest := &retainedManifest{Schema: "zasp-node-coverage-manifest-v1", StateUID: state.StateUID, StorageEpoch: env.StorageEpoch, Sequence: env.Sequence, WireSchema: nodecoveragewire.HeartbeatSchema, SelectionDigest: c.coveragePendingConfigDigest(), BodyBytes: len(body), BodySHA256: retainedDigest(body), SourceObservedAt: observed, ExpiresAt: observed.Add(c.config.ReportTTL), Chunks: make([]retainedChunkRef, 0, (len(body)+retainedChunkBytes-1)/retainedChunkBytes)}
	for start, index := 0, 0; start < len(body); start, index = start+retainedChunkBytes, index+1 {
		end := min(start+retainedChunkBytes, len(body))
		part := body[start:end]
		manifest.Chunks = append(manifest.Chunks, retainedChunkRef{Index: index, Name: retainedSlotName(state.StateUID, index), Bytes: len(part), SHA256: retainedDigest(part)})
	}
	manifest.MarkerSHA256 = c.retainedMarker(manifest)
	state.Phase = "preparing"
	state.StorageEpoch = env.StorageEpoch
	state.Manifest = manifest
	anchor, e = c.storeRetainedState(ctx, anchor, state)
	if e != nil {
		return sensoradapter.Heartbeat{}, e
	}
	refs := append([]retainedChunkRef(nil), manifest.Chunks...)
	for i, ref := range refs {
		if ctx.Err() != nil {
			return sensoradapter.Heartbeat{}, ErrClusterRetryable
		}
		start := i * retainedChunkBytes
		lease, e := c.writeRetainedSlot(ctx, anchor, state.StorageEpoch, ref, body[start:start+ref.Bytes])
		if e != nil {
			return sensoradapter.Heartbeat{}, e
		}
		uid := string(lease.UID)
		refs[i].UID = &uid
	}
	// Read back exact stored bytes before publishing the send authority.
	restored, _, e := c.readRetainedBody(ctx, state)
	if e != nil || !bytes.Equal(restored, body) {
		return sensoradapter.Heartbeat{}, ErrClusterRetryable
	}
	if nodecoveragewire.ValidateFreshEnvelope(env, now.Add(time.Since(started))) != nil {
		return sensoradapter.Heartbeat{}, ErrClusterRetryable
	}
	sealed := *manifest
	sealed.Chunks = refs
	sealed.MarkerSHA256 = c.retainedMarker(&sealed)
	state.Manifest = &sealed
	state.Phase = "pending"
	if _, e = c.storeRetainedState(ctx, anchor, state); e != nil {
		return sensoradapter.Heartbeat{}, e
	}
	return c.cacheRetained(body, env)
}

func (c *ClusterCoordinator) retainedReceiptMatches(receipt nodecoveragewire.Receipt, env nodecoveragewire.Envelope, body []byte) bool {
	if _, e := nodecoveragewire.MarshalReceipt(receipt); e != nil {
		return false
	}
	return receipt.SensorID == c.config.SensorID && receipt.Sequence == env.Sequence && receipt.RequestDigest == retainedDigest(body) && receipt.SourceObservedAt.Equal(env.SourceObservedAt) && receipt.ExpiresAt.Equal(env.SourceObservedAt.Add(time.Duration(env.TTLSeconds)*time.Second)) && (receipt.Disposition == "accepted" || receipt.Disposition == "expired_not_committed")
}
func (c *ClusterCoordinator) commitRetainedReceipt(ctx context.Context, body []byte, receipt nodecoveragewire.Receipt) error {
	env, e := nodecoveragewire.ParseEnvelope(body)
	if e != nil || !c.retainedReceiptMatches(receipt, env, body) {
		return ErrCluster
	}
	anchor, state, e := c.loadRetainedState(ctx, false)
	if e != nil {
		return e
	}
	if state.Phase != "pending" || state.Manifest.Sequence != env.Sequence || state.Manifest.StorageEpoch != env.StorageEpoch {
		return ErrClusterRetryable
	}
	stored, _, _, e := c.restoreRetained(ctx, state)
	if e != nil || !bytes.Equal(stored, body) {
		return ErrCluster
	}
	state.Phase = "idle"
	state.ResolvedAttemptSequence = env.Sequence
	state.Manifest = nil
	_, e = c.storeRetainedState(ctx, anchor, state)
	return e
}
func safeRetainedHeartbeat(sink RetainedHeartbeatSink, ctx context.Context, body []byte) (receipt nodecoveragewire.Receipt, err error) {
	defer func() {
		if recover() != nil {
			receipt = nodecoveragewire.Receipt{}
			err = ErrClusterRetryable
		}
	}()
	return sink.SendRetainedHeartbeat(ctx, bytes.Clone(body))
}
func (c *ClusterCoordinator) validRetainedLeader(leader *coordinationv1.Lease) bool {
	return validOwnedLease(leader, clusterLeaderLeaseName, c.config.Namespace, clusterLeaderAuthority) && retainedValidUID(string(leader.UID)) && leader.DeletionTimestamp == nil && len(leader.Finalizers) == 0 && leader.Spec.HolderIdentity != nil && *leader.Spec.HolderIdentity == c.config.PodName
}
func (c *ClusterCoordinator) tickRetained(ctx context.Context, local NodeReport, now time.Time, started time.Time) error {
	defer func() { c.pendingRetainedBody = nil }()
	leader, owned, e := c.acquireLeader(ctx, now)
	if e != nil || !owned {
		return e
	}
	if !c.validRetainedLeader(leader) {
		return ErrCluster
	}
	_, state, e := c.loadRetainedState(ctx, true)
	if e != nil {
		return e
	}
	if state.Phase == "idle" {
		if e = c.upsertCoverage(ctx, local, now); e != nil {
			return e
		}
	}
	if _, e = c.pendingRetainedOrPrepare(ctx, now.Add(time.Since(started))); e != nil {
		return e
	}
	body := bytes.Clone(c.pendingRetainedBody)
	env, e := nodecoveragewire.ParseEnvelope(body)
	if e != nil {
		return ErrCluster
	}
	// Leadership checks are bounded liveness checks; state CAS and exact pending
	// bytes remain sequence authority across separate Kubernetes objects.
	leader, owned, e = c.acquireLeader(ctx, now.Add(time.Since(started)))
	if e != nil || !owned {
		return e
	}
	if !c.validRetainedLeader(leader) {
		return ErrCluster
	}
	_, pending, e := c.loadRetainedState(ctx, false)
	if e != nil || pending.Phase != "pending" || !c.retainedEnvelopeMatches(env, pending.Manifest) || pending.Manifest.BodySHA256 != retainedDigest(body) || ctx.Err() != nil {
		return ErrClusterRetryable
	}
	receipt, e := safeRetainedHeartbeat(c.config.RetainedHeartbeats, ctx, body)
	if e != nil {
		return ErrClusterRetryable
	}
	if !c.retainedReceiptMatches(receipt, env, body) {
		return ErrCluster
	}
	return c.commitRetainedReceipt(ctx, body, receipt)
}
