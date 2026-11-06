package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const retainedStateAnnotation = "zasp.io/coverage-retention-state"
const retainedSlotAnnotation = "zasp.io/coverage-slot"
const retainedSlotAuthority = "heartbeat-coverage-slot"
const retainedChunkBytes = 65536
const retainedMaxChunks = 256
const retainedMaxManifestBytes = 81920
const retainedMaxAnnotations = 204800

var retainedUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var retainedHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func retainedValidUID(s string) bool {
	return retainedUUID.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func retainedDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

type retainedChunkRef struct {
	Index  int     `json:"index"`
	Name   string  `json:"name"`
	UID    *string `json:"uid"`
	Bytes  int     `json:"bytes"`
	SHA256 string  `json:"sha256"`
}
type retainedManifest struct {
	Schema           string             `json:"schema"`
	StateUID         string             `json:"state_uid"`
	StorageEpoch     int64              `json:"storage_epoch"`
	Sequence         int64              `json:"sequence"`
	WireSchema       string             `json:"wire_schema"`
	SelectionDigest  string             `json:"selection_digest"`
	BodyBytes        int                `json:"body_bytes"`
	BodySHA256       string             `json:"body_sha256"`
	SourceObservedAt time.Time          `json:"source_observed_at"`
	ExpiresAt        time.Time          `json:"expires_at"`
	Chunks           []retainedChunkRef `json:"chunks"`
	MarkerSHA256     string             `json:"marker_sha256"`
}
type retainedState struct {
	Schema                  string            `json:"schema"`
	StateUID                string            `json:"state_uid"`
	StorageEpoch            int64             `json:"storage_epoch"`
	ResolvedAttemptSequence int64             `json:"resolved_attempt_sequence"`
	Phase                   string            `json:"phase"`
	Manifest                *retainedManifest `json:"manifest"`
}
type retainedSlot struct {
	Schema       string `json:"schema"`
	StateUID     string `json:"state_uid"`
	StorageEpoch int64  `json:"storage_epoch"`
	Index        int    `json:"index"`
	Bytes        int    `json:"bytes"`
	SHA256       string `json:"sha256"`
	Data         string `json:"data"`
}

// Canonical application-owned metadata refuses aliases, duplicates and unknown
// keys. Observation wire decoding remains the shared independent contract.
func decodeRetainedMetadata(raw string, out any, max int) bool {
	if raw == "" || len(raw) > max {
		return false
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	b, e := json.Marshal(out)
	return e == nil && string(b) == raw
}
func retainedAnnotationSize(annotations map[string]string) int {
	n := 0
	for k, v := range annotations {
		n += len(k) + len(v)
	}
	return n
}
func retainedSlotName(uid string, index int) string {
	return "zasp-covslot-" + retainedDigest([]byte("zasp.node-coverage.slots.v1\x00" + uid))[:32] + fmt.Sprintf("-%03d", index)
}
func (c *ClusterCoordinator) retainedMarker(m *retainedManifest) string {
	b, e := json.Marshal(m)
	if e != nil {
		return ""
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return ""
	}
	delete(fields, "marker_sha256")
	b, e = json.Marshal(fields)
	if e != nil {
		return ""
	}
	return retainedDigest(append([]byte("zasp.node-coverage.pending.v1\x00"+c.coveragePendingConfigDigest()+"\x00"), b...))
}
func (c *ClusterCoordinator) validRetainedManifest(m *retainedManifest, s retainedState) bool {
	if m == nil || m.Schema != "zasp-node-coverage-manifest-v1" || m.StateUID != s.StateUID || m.StorageEpoch != s.StorageEpoch || m.Sequence < 1 || s.ResolvedAttemptSequence == int64(^uint64(0)>>1) || m.Sequence != s.ResolvedAttemptSequence+1 || m.WireSchema != "sensor-heartbeat-node-coverage-v2" || m.SelectionDigest != c.coveragePendingConfigDigest() || m.BodyBytes < 1 || m.BodyBytes > retainedChunkBytes*retainedMaxChunks || !retainedHash.MatchString(m.BodySHA256) || m.SourceObservedAt.IsZero() || m.SourceObservedAt.Location() != time.UTC || !m.ExpiresAt.Equal(m.SourceObservedAt.Add(c.config.ReportTTL)) || len(m.Chunks) != (m.BodyBytes+retainedChunkBytes-1)/retainedChunkBytes || len(m.Chunks) < 1 || len(m.Chunks) > retainedMaxChunks || m.MarkerSHA256 != c.retainedMarker(m) {
		return false
	}
	b, e := json.Marshal(m)
	if e != nil || len(b) > retainedMaxManifestBytes {
		return false
	}
	for i, ref := range m.Chunks {
		size := retainedChunkBytes
		if i == len(m.Chunks)-1 {
			size = m.BodyBytes - i*retainedChunkBytes
		}
		if ref.Index != i || ref.Name != retainedSlotName(s.StateUID, i) || ref.Bytes != size || !retainedHash.MatchString(ref.SHA256) {
			return false
		}
		if s.Phase == "pending" {
			if ref.UID == nil || !retainedValidUID(*ref.UID) {
				return false
			}
		} else if ref.UID != nil {
			return false
		}
	}
	return true
}
func (c *ClusterCoordinator) validRetainedState(s retainedState, anchor *coordinationv1.Lease) bool {
	if s.Schema != "zasp-node-coverage-state-v1" || s.StateUID != string(anchor.UID) || s.StorageEpoch < 0 || s.ResolvedAttemptSequence < 0 {
		return false
	}
	switch s.Phase {
	case "idle":
		return s.Manifest == nil
	case "preparing", "pending":
		return s.StorageEpoch > 0 && c.validRetainedManifest(s.Manifest, s)
	default:
		return false
	}
}
func (c *ClusterCoordinator) validRetainedAnchor(anchor *coordinationv1.Lease) bool {
	return validOwnedLease(anchor, clusterStateLeaseName, c.config.Namespace, clusterStateAuthority) && anchor.DeletionTimestamp == nil && len(anchor.Finalizers) == 0 && len(anchor.OwnerReferences) == 0 && retainedValidUID(string(anchor.UID)) && retainedAnnotationSize(anchor.Annotations) <= retainedMaxAnnotations
}
func (c *ClusterCoordinator) loadRetainedState(ctx context.Context, create bool) (*coordinationv1.Lease, retainedState, error) {
	anchor, e := c.config.Leases.Get(ctx, clusterStateLeaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(e) && create {
		holder := c.config.PodName
		anchor, e = c.config.Leases.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: clusterStateLeaseName, Namespace: c.config.Namespace, Labels: ownedLabels(clusterStateAuthority), Annotations: map[string]string{clusterSequenceAnnotation: "0"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder}}, metav1.CreateOptions{})
		if e != nil {
			anchor, e = c.config.Leases.Get(ctx, clusterStateLeaseName, metav1.GetOptions{})
		}
	}
	if e != nil {
		return nil, retainedState{}, ErrClusterRetryable
	}
	if !c.validRetainedAnchor(anchor) || c.retainedAnchorUID != "" && c.retainedAnchorUID != string(anchor.UID) || anchor.Annotations[clusterPendingAnnotation] != "" || anchor.Annotations[clusterCoveragePendingAnnotation] != "" {
		return nil, retainedState{}, ErrCluster
	}
	c.retainedAnchorUID = string(anchor.UID)
	seq, e := parseSequence(anchor.Annotations[clusterSequenceAnnotation])
	if e != nil {
		return nil, retainedState{}, ErrCluster
	}
	var state retainedState
	raw := anchor.Annotations[retainedStateAnnotation]
	if raw == "" {
		if c.retainedStateSeen || len(anchor.Annotations) != 1 {
			return nil, retainedState{}, ErrCluster
		}
		state = retainedState{Schema: "zasp-node-coverage-state-v1", StateUID: string(anchor.UID), ResolvedAttemptSequence: seq, Phase: "idle"}
	} else {
		if len(anchor.Annotations) != 2 || !decodeRetainedMetadata(raw, &state, 128<<10) || !c.validRetainedState(state, anchor) || state.ResolvedAttemptSequence != seq {
			return nil, retainedState{}, ErrCluster
		}
		c.retainedStateSeen = true
	}
	return anchor, state, nil
}
func (c *ClusterCoordinator) storeRetainedState(ctx context.Context, anchor *coordinationv1.Lease, state retainedState) (*coordinationv1.Lease, error) {
	if !c.validRetainedAnchor(anchor) || !c.validRetainedState(state, anchor) {
		return nil, ErrCluster
	}
	raw, e := json.Marshal(state)
	if e != nil || len(raw) > 128<<10 {
		return nil, ErrCluster
	}
	next := anchor.DeepCopy()
	next.Annotations = map[string]string{clusterSequenceAnnotation: strconv.FormatInt(state.ResolvedAttemptSequence, 10), retainedStateAnnotation: string(raw)}
	next.Spec.HolderIdentity = &c.config.PodName
	if retainedAnnotationSize(next.Annotations) > retainedMaxAnnotations {
		return nil, ErrCluster
	}
	updated, e := c.config.Leases.Update(ctx, next, metav1.UpdateOptions{})
	if e != nil {
		// Unknown mutations are recognized only from the exact durable desired state.
		updated, e = c.config.Leases.Get(ctx, clusterStateLeaseName, metav1.GetOptions{})
		if e != nil || !c.validRetainedAnchor(updated) || updated.UID != anchor.UID || !reflect.DeepEqual(updated.Annotations, next.Annotations) {
			return nil, ErrClusterRetryable
		}
	}
	if !c.validRetainedAnchor(updated) || updated.UID != anchor.UID || !reflect.DeepEqual(updated.Annotations, next.Annotations) {
		return nil, ErrCluster
	}
	c.retainedStateSeen = true
	return updated, nil
}
func (c *ClusterCoordinator) validRetainedSlotLease(l *coordinationv1.Lease, uid, name string) bool {
	if !validOwnedLease(l, name, c.config.Namespace, retainedSlotAuthority) || !retainedValidUID(string(l.UID)) || l.DeletionTimestamp != nil || len(l.Finalizers) != 0 || len(l.OwnerReferences) != 1 || len(l.Annotations) != 1 || retainedAnnotationSize(l.Annotations) > 131072 {
		return false
	}
	o := l.OwnerReferences[0]
	return o.APIVersion == "coordination.k8s.io/v1" && o.Kind == "Lease" && o.Name == clusterStateLeaseName && string(o.UID) == uid && (o.Controller == nil || !*o.Controller) && (o.BlockOwnerDeletion == nil || !*o.BlockOwnerDeletion)
}
func decodeRetainedSlot(raw string) (retainedSlot, []byte, bool) {
	var s retainedSlot
	if !decodeRetainedMetadata(raw, &s, 131072) || s.Schema != "zasp-node-coverage-slot-v1" || !retainedValidUID(s.StateUID) || s.StorageEpoch < 1 || s.Index < 0 || s.Index >= retainedMaxChunks || s.Bytes < 1 || s.Bytes > retainedChunkBytes || !retainedHash.MatchString(s.SHA256) {
		return s, nil, false
	}
	b, e := base64.RawURLEncoding.DecodeString(s.Data)
	return s, b, e == nil && len(b) == s.Bytes && base64.RawURLEncoding.EncodeToString(b) == s.Data && retainedDigest(b) == s.SHA256
}
func (c *ClusterCoordinator) writeRetainedSlot(ctx context.Context, anchor *coordinationv1.Lease, epoch int64, ref retainedChunkRef, body []byte) (*coordinationv1.Lease, error) {
	desired := retainedSlot{Schema: "zasp-node-coverage-slot-v1", StateUID: string(anchor.UID), StorageEpoch: epoch, Index: ref.Index, Bytes: len(body), SHA256: retainedDigest(body), Data: base64.RawURLEncoding.EncodeToString(body)}
	if desired.Bytes != ref.Bytes || desired.SHA256 != ref.SHA256 {
		return nil, ErrCluster
	}
	encoded, e := json.Marshal(desired)
	if e != nil || len(encoded) > 131072 {
		return nil, ErrCluster
	}
	current, e := c.config.Leases.Get(ctx, ref.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		created, createErr := c.config.Leases.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: c.config.Namespace, Labels: ownedLabels(retainedSlotAuthority), Annotations: map[string]string{retainedSlotAnnotation: string(encoded)}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "coordination.k8s.io/v1", Kind: "Lease", Name: clusterStateLeaseName, UID: anchor.UID}}}}, metav1.CreateOptions{})
		if createErr == nil && c.validRetainedSlotLease(created, string(anchor.UID), ref.Name) && created.Annotations[retainedSlotAnnotation] == string(encoded) {
			return created, nil
		}
		current, e = c.config.Leases.Get(ctx, ref.Name, metav1.GetOptions{})
	}
	if e != nil {
		return nil, ErrClusterRetryable
	}
	if !c.validRetainedSlotLease(current, string(anchor.UID), ref.Name) {
		return nil, ErrCluster
	}
	old, _, ok := decodeRetainedSlot(current.Annotations[retainedSlotAnnotation])
	if !ok || old.StateUID != desired.StateUID || old.Index != ref.Index {
		return nil, ErrCluster
	}
	if old.StorageEpoch > epoch {
		return nil, ErrClusterRetryable
	}
	if old.StorageEpoch == epoch {
		if current.Annotations[retainedSlotAnnotation] != string(encoded) {
			return nil, ErrCluster
		}
		return current, nil
	}
	next := current.DeepCopy()
	next.Annotations = map[string]string{retainedSlotAnnotation: string(encoded)}
	updated, e := c.config.Leases.Update(ctx, next, metav1.UpdateOptions{})
	if e != nil {
		updated, e = c.config.Leases.Get(ctx, ref.Name, metav1.GetOptions{})
		if e != nil {
			return nil, ErrClusterRetryable
		}
		// Do not retry the old epoch with newly fetched newer resourceVersion.
		if !c.validRetainedSlotLease(updated, string(anchor.UID), ref.Name) || updated.UID != current.UID || updated.Annotations[retainedSlotAnnotation] != string(encoded) {
			return nil, ErrClusterRetryable
		}
	}
	if !c.validRetainedSlotLease(updated, string(anchor.UID), ref.Name) || updated.UID != current.UID || updated.Annotations[retainedSlotAnnotation] != string(encoded) {
		return nil, ErrCluster
	}
	return updated, nil
}
func (c *ClusterCoordinator) readRetainedBody(ctx context.Context, s retainedState) ([]byte, []retainedChunkRef, error) {
	if !c.validRetainedManifest(s.Manifest, s) {
		return nil, nil, ErrCluster
	}
	m := s.Manifest
	body := make([]byte, 0, m.BodyBytes)
	refs := append([]retainedChunkRef(nil), m.Chunks...)
	for i, ref := range refs {
		l, e := c.config.Leases.Get(ctx, ref.Name, metav1.GetOptions{})
		if e != nil {
			return nil, nil, ErrClusterRetryable
		}
		if !c.validRetainedSlotLease(l, s.StateUID, ref.Name) || ref.UID != nil && *ref.UID != string(l.UID) {
			return nil, nil, ErrCluster
		}
		slot, raw, ok := decodeRetainedSlot(l.Annotations[retainedSlotAnnotation])
		if !ok || slot.StateUID != s.StateUID || slot.StorageEpoch != s.StorageEpoch || slot.Index != i || slot.Bytes != ref.Bytes || slot.SHA256 != ref.SHA256 {
			return nil, nil, ErrCluster
		}
		uid := string(l.UID)
		refs[i].UID = &uid
		body = append(body, raw...)
	}
	if len(body) != m.BodyBytes || retainedDigest(body) != m.BodySHA256 {
		return nil, nil, ErrCluster
	}
	return body, refs, nil
}
