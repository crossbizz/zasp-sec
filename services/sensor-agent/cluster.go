package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

const (
	clusterLeaderLeaseName    = "zasp-sensor-heartbeat-leader"
	clusterStateLeaseName     = "zasp-sensor-heartbeat-state"
	clusterAuthorityLabel     = "zasp.io/sensor-authority"
	clusterLeaderAuthority    = "heartbeat-leader"
	clusterStateAuthority     = "heartbeat-state"
	clusterNodeAuthority      = "node-report"
	clusterNodeSelector       = clusterAuthorityLabel + "=" + clusterNodeAuthority
	tetragonPodSelector       = "app.kubernetes.io/name=tetragon"
	clusterReportAnnotation   = "zasp.io/node-report"
	clusterSequenceAnnotation = "zasp.io/heartbeat-sequence"
	clusterPendingAnnotation  = "zasp.io/pending-heartbeat"
	clusterTimestampLayout    = "2006-01-02T15:04:05.000Z"
)

var (
	ErrCluster            = errors.New("sensor cluster authority rejected")
	ErrClusterRetryable   = errors.New("sensor cluster authority temporarily unavailable")
	kubernetesNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

type clusterLeaseAPI interface {
	Get(context.Context, string, metav1.GetOptions) (*coordinationv1.Lease, error)
	Create(context.Context, *coordinationv1.Lease, metav1.CreateOptions) (*coordinationv1.Lease, error)
	Update(context.Context, *coordinationv1.Lease, metav1.UpdateOptions) (*coordinationv1.Lease, error)
	List(context.Context, metav1.ListOptions) (*coordinationv1.LeaseList, error)
}

type clusterPodAPI interface {
	ListPods(context.Context, metav1.ListOptions) (*corev1.PodList, error)
}

type heartbeatSink interface {
	Heartbeat(context.Context, sensoradapter.Heartbeat) error
}

type NodeReport struct {
	NodeName     string
	ObservedAt   time.Time
	Status       string
	Capabilities []string
	Kernel       string
	BTF          bool
	EventRate    uint64
	Drops        uint64
}

type clusterReportWire struct {
	NodeName     string   `json:"node_name"`
	ObservedAt   string   `json:"observed_at"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
	Kernel       string   `json:"kernel"`
	BTF          bool     `json:"btf"`
	EventRate    uint64   `json:"event_rate"`
	Drops        uint64   `json:"drops"`
}

type ClusterCoordinatorConfig struct {
	Namespace     string
	PodName       string
	NodeName      string
	LeaseDuration time.Duration
	ReportTTL     time.Duration
	Leases        clusterLeaseAPI
	Pods          clusterPodAPI
	Heartbeats    heartbeatSink
	Now           func() time.Time
}

type ClusterCoordinator struct {
	mu     sync.Mutex
	config ClusterCoordinatorConfig
}

func NewClusterCoordinator(config ClusterCoordinatorConfig) (*ClusterCoordinator, error) {
	if !validKubernetesName(config.Namespace) || !validKubernetesName(config.PodName) || !validKubernetesName(config.NodeName) || config.LeaseDuration < 5*time.Second || config.LeaseDuration > time.Minute || config.LeaseDuration%time.Second != 0 || config.ReportTTL <= config.LeaseDuration || config.ReportTTL > 5*time.Minute || config.ReportTTL%time.Second != 0 || nilClusterValue(config.Leases) || nilClusterValue(config.Pods) || nilClusterValue(config.Heartbeats) || config.Now == nil {
		return nil, ErrCluster
	}
	now, ok := clusterNow(config.Now)
	if !ok {
		return nil, ErrCluster
	}
	_ = now
	return &ClusterCoordinator{config: config}, nil
}

func (coordinator *ClusterCoordinator) Tick(ctx context.Context, local NodeReport) error {
	if coordinator == nil || ctx == nil || ctx.Err() != nil {
		return ErrClusterRetryable
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	now, ok := clusterNow(coordinator.config.Now)
	if !ok {
		return ErrClusterRetryable
	}
	local.NodeName, local.ObservedAt = coordinator.config.NodeName, now
	if !validNodeReport(local) {
		return ErrCluster
	}
	if err := coordinator.upsertNodeReport(ctx, local, now); err != nil {
		return err
	}
	leader, owned, err := coordinator.acquireLeader(ctx, now)
	if err != nil || !owned {
		return err
	}
	heartbeat, err := coordinator.pendingOrPrepare(ctx, now)
	if err != nil {
		return err
	}
	if err := safeHeartbeat(coordinator.config.Heartbeats, ctx, heartbeat); err != nil {
		return ErrClusterRetryable
	}
	if err := coordinator.commitHeartbeat(ctx, leader, heartbeat); err != nil {
		return err
	}
	return nil
}

func (coordinator *ClusterCoordinator) upsertNodeReport(ctx context.Context, report NodeReport, now time.Time) error {
	name := nodeReportLeaseName(report.NodeName)
	payload, err := encodeNodeReport(report)
	if err != nil {
		return ErrCluster
	}
	duration := int32(coordinator.config.ReportTTL / time.Second)
	holder := coordinator.config.PodName
	renew := metav1.NewMicroTime(now)
	value, err := coordinator.config.Leases.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = coordinator.config.Leases.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: coordinator.config.Namespace, Labels: ownedLabels(clusterNodeAuthority), Annotations: map[string]string{clusterReportAnnotation: payload}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, RenewTime: &renew}}, metav1.CreateOptions{})
		return clusterMutationError(err)
	}
	if err != nil || !validOwnedLease(value, name, coordinator.config.Namespace, clusterNodeAuthority) {
		return ErrCluster
	}
	prior, decodeErr := decodeNodeReport(value.Annotations[clusterReportAnnotation])
	if decodeErr != nil || prior.NodeName != report.NodeName {
		return ErrCluster
	}
	updated := value.DeepCopy()
	updated.Labels = ownedLabels(clusterNodeAuthority)
	updated.Annotations = map[string]string{clusterReportAnnotation: payload}
	updated.Spec.HolderIdentity = &holder
	updated.Spec.LeaseDurationSeconds = &duration
	updated.Spec.RenewTime = &renew
	_, err = coordinator.config.Leases.Update(ctx, updated, metav1.UpdateOptions{})
	return clusterMutationError(err)
}

func (coordinator *ClusterCoordinator) acquireLeader(ctx context.Context, now time.Time) (*coordinationv1.Lease, bool, error) {
	duration := int32(coordinator.config.LeaseDuration / time.Second)
	holder := coordinator.config.PodName
	current := metav1.NewMicroTime(now)
	value, err := coordinator.config.Leases.Get(ctx, clusterLeaderLeaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		created, createErr := coordinator.config.Leases.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: clusterLeaderLeaseName, Namespace: coordinator.config.Namespace, Labels: ownedLabels(clusterLeaderAuthority)}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder, LeaseDurationSeconds: &duration, AcquireTime: &current, RenewTime: &current}}, metav1.CreateOptions{})
		if createErr != nil {
			return nil, false, clusterMutationError(createErr)
		}
		return created, true, nil
	}
	if err != nil || !validOwnedLease(value, clusterLeaderLeaseName, coordinator.config.Namespace, clusterLeaderAuthority) || value.Spec.HolderIdentity == nil || value.Spec.LeaseDurationSeconds == nil || value.Spec.RenewTime == nil || *value.Spec.LeaseDurationSeconds < 5 || *value.Spec.LeaseDurationSeconds > 60 {
		return nil, false, ErrCluster
	}
	owned := *value.Spec.HolderIdentity == holder
	expired := value.Spec.RenewTime.Add(time.Duration(*value.Spec.LeaseDurationSeconds) * time.Second).Before(now)
	if !owned && !expired {
		return value, false, nil
	}
	updated := value.DeepCopy()
	takeover := !owned
	updated.Spec.HolderIdentity = &holder
	updated.Spec.LeaseDurationSeconds = &duration
	updated.Spec.RenewTime = &current
	if takeover {
		updated.Spec.AcquireTime = &current
		transitions := int32(1)
		if updated.Spec.LeaseTransitions != nil {
			if *updated.Spec.LeaseTransitions == math.MaxInt32 {
				return nil, false, ErrCluster
			}
			transitions = *updated.Spec.LeaseTransitions + 1
		}
		updated.Spec.LeaseTransitions = &transitions
	}
	result, updateErr := coordinator.config.Leases.Update(ctx, updated, metav1.UpdateOptions{})
	if updateErr != nil {
		return nil, false, clusterMutationError(updateErr)
	}
	return result, true, nil
}

func (coordinator *ClusterCoordinator) pendingOrPrepare(ctx context.Context, now time.Time) (sensoradapter.Heartbeat, error) {
	state, err := coordinator.config.Leases.Get(ctx, clusterStateLeaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		holder := coordinator.config.PodName
		state, err = coordinator.config.Leases.Create(ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: clusterStateLeaseName, Namespace: coordinator.config.Namespace, Labels: ownedLabels(clusterStateAuthority), Annotations: map[string]string{clusterSequenceAnnotation: "0"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder}}, metav1.CreateOptions{})
	}
	if err != nil {
		return sensoradapter.Heartbeat{}, clusterMutationError(err)
	}
	if !validOwnedLease(state, clusterStateLeaseName, coordinator.config.Namespace, clusterStateAuthority) {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	sequence, err := parseSequence(state.Annotations[clusterSequenceAnnotation])
	if err != nil {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	if pending := state.Annotations[clusterPendingAnnotation]; pending != "" {
		heartbeat, decodeErr := decodePendingHeartbeat(pending)
		if decodeErr != nil || heartbeat.Sequence != sequence+1 {
			return sensoradapter.Heartbeat{}, ErrCluster
		}
		return heartbeat, nil
	}
	if sequence == math.MaxInt64 {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	heartbeat, err := coordinator.aggregate(ctx, now)
	if err != nil {
		return sensoradapter.Heartbeat{}, err
	}
	heartbeat.Sequence = sequence + 1
	pending, err := encodePendingHeartbeat(heartbeat)
	if err != nil {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	updated := state.DeepCopy()
	updated.Spec.HolderIdentity = &coordinator.config.PodName
	updated.Annotations = map[string]string{clusterSequenceAnnotation: strconv.FormatInt(sequence, 10), clusterPendingAnnotation: pending}
	if _, err = coordinator.config.Leases.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return sensoradapter.Heartbeat{}, clusterMutationError(err)
	}
	return heartbeat, nil
}

func (coordinator *ClusterCoordinator) commitHeartbeat(ctx context.Context, _ *coordinationv1.Lease, heartbeat sensoradapter.Heartbeat) error {
	state, err := coordinator.config.Leases.Get(ctx, clusterStateLeaseName, metav1.GetOptions{})
	if err != nil {
		return clusterMutationError(err)
	}
	if !validOwnedLease(state, clusterStateLeaseName, coordinator.config.Namespace, clusterStateAuthority) {
		return ErrCluster
	}
	sequence, err := parseSequence(state.Annotations[clusterSequenceAnnotation])
	if err != nil || heartbeat.Sequence != sequence+1 {
		return ErrCluster
	}
	pending, err := decodePendingHeartbeat(state.Annotations[clusterPendingAnnotation])
	if err != nil || !reflect.DeepEqual(pending, heartbeat) {
		return ErrCluster
	}
	updated := state.DeepCopy()
	updated.Spec.HolderIdentity = &coordinator.config.PodName
	updated.Annotations = map[string]string{clusterSequenceAnnotation: strconv.FormatInt(heartbeat.Sequence, 10)}
	_, err = coordinator.config.Leases.Update(ctx, updated, metav1.UpdateOptions{})
	return clusterMutationError(err)
}

func (coordinator *ClusterCoordinator) aggregate(ctx context.Context, now time.Time) (sensoradapter.Heartbeat, error) {
	pods, err := coordinator.config.Pods.ListPods(ctx, metav1.ListOptions{LabelSelector: tetragonPodSelector})
	if err != nil || pods == nil || len(pods.Items) < 1 || len(pods.Items) > 1000 {
		return sensoradapter.Heartbeat{}, ErrClusterRetryable
	}
	expected := map[string]bool{}
	status := "healthy"
	for _, pod := range pods.Items {
		if pod.Namespace != "" && pod.Namespace != coordinator.config.Namespace || !validKubernetesName(pod.Name) || !validKubernetesName(pod.Spec.NodeName) {
			return sensoradapter.Heartbeat{}, ErrCluster
		}
		if _, exists := expected[pod.Spec.NodeName]; exists {
			return sensoradapter.Heartbeat{}, ErrCluster
		}
		ready := pod.Status.Phase == corev1.PodRunning && pod.DeletionTimestamp == nil && podReady(pod)
		expected[pod.Spec.NodeName] = ready
		if !ready {
			status = "degraded"
		}
	}
	leases, err := coordinator.config.Leases.List(ctx, metav1.ListOptions{LabelSelector: clusterNodeSelector})
	if err != nil || leases == nil || len(leases.Items) > 1000 {
		return sensoradapter.Heartbeat{}, ErrClusterRetryable
	}
	reports := map[string]NodeReport{}
	for index := range leases.Items {
		value := &leases.Items[index]
		if !validOwnedLease(value, value.Name, coordinator.config.Namespace, clusterNodeAuthority) {
			return sensoradapter.Heartbeat{}, ErrCluster
		}
		report, decodeErr := decodeNodeReport(value.Annotations[clusterReportAnnotation])
		if decodeErr != nil || value.Name != nodeReportLeaseName(report.NodeName) {
			return sensoradapter.Heartbeat{}, ErrCluster
		}
		if _, exists := reports[report.NodeName]; exists {
			return sensoradapter.Heartbeat{}, ErrCluster
		}
		reports[report.NodeName] = report
	}
	capabilities := map[string]bool{"file": true, "network": true, "process": true}
	kernels := map[string]struct{}{}
	btf := true
	var rate, drops uint64
	for node, ready := range expected {
		report, found := reports[node]
		fresh := found && !report.ObservedAt.After(now.Add(5*time.Second)) && !report.ObservedAt.Before(now.Add(-coordinator.config.ReportTTL))
		if !ready || !fresh || report.Status != "healthy" {
			status = "degraded"
		}
		if !fresh {
			btf = false
			continue
		}
		kernels[report.Kernel] = struct{}{}
		btf = btf && report.BTF
		for capability := range capabilities {
			if !containsString(report.Capabilities, capability) {
				delete(capabilities, capability)
			}
		}
		if math.MaxUint64-rate < report.EventRate || rate+report.EventRate > 1_000_000_000 {
			rate = 1_000_000_000
			status = "degraded"
		} else {
			rate += report.EventRate
		}
		if math.MaxUint64-drops < report.Drops || drops+report.Drops > 1_000_000_000 {
			drops = 1_000_000_000
			status = "degraded"
		} else {
			drops += report.Drops
		}
	}
	resultCapabilities := make([]string, 0, len(capabilities))
	for value := range capabilities {
		resultCapabilities = append(resultCapabilities, value)
	}
	sort.Strings(resultCapabilities)
	if len(resultCapabilities) == 0 {
		resultCapabilities = []string{"process"}
		status = "degraded"
	}
	kernel := "unknown"
	if len(kernels) == 1 {
		for value := range kernels {
			kernel = value
		}
	} else if len(kernels) > 1 {
		kernel = "mixed"
		status = "degraded"
	}
	return sensoradapter.Heartbeat{Status: status, Capabilities: resultCapabilities, Kernel: kernel, BTF: btf, EventRate: rate, Drops: drops}, nil
}

func encodeNodeReport(report NodeReport) (string, error) {
	if !validNodeReport(report) {
		return "", ErrCluster
	}
	wire := clusterReportWire{NodeName: report.NodeName, ObservedAt: report.ObservedAt.Format(clusterTimestampLayout), Status: report.Status, Capabilities: append([]string(nil), report.Capabilities...), Kernel: report.Kernel, BTF: report.BTF, EventRate: report.EventRate, Drops: report.Drops}
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) > 4096 {
		return "", ErrCluster
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}
func decodeNodeReport(encoded string) (NodeReport, error) {
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded || len(payload) > 4096 {
		return NodeReport{}, ErrCluster
	}
	var wire clusterReportWire
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return NodeReport{}, ErrCluster
	}
	observed, err := time.Parse(clusterTimestampLayout, wire.ObservedAt)
	report := NodeReport{NodeName: wire.NodeName, ObservedAt: observed, Status: wire.Status, Capabilities: wire.Capabilities, Kernel: wire.Kernel, BTF: wire.BTF, EventRate: wire.EventRate, Drops: wire.Drops}
	canonical, canonicalErr := encodeNodeReport(report)
	if err != nil || canonicalErr != nil || canonical != encoded {
		return NodeReport{}, ErrCluster
	}
	return report, nil
}
func encodePendingHeartbeat(value sensoradapter.Heartbeat) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > 4096 {
		return "", ErrCluster
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}
func decodePendingHeartbeat(encoded string) (sensoradapter.Heartbeat, error) {
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded || len(payload) > 4096 {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	var value sensoradapter.Heartbeat
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	canonical, canonicalErr := encodePendingHeartbeat(value)
	if canonicalErr != nil || canonical != encoded || !validPendingHeartbeat(value) {
		return sensoradapter.Heartbeat{}, ErrCluster
	}
	return value, nil
}

func validNodeReport(value NodeReport) bool {
	return validKubernetesName(value.NodeName) && !value.ObservedAt.IsZero() && value.ObservedAt.Location() == time.UTC && value.ObservedAt.Equal(value.ObservedAt.Truncate(time.Millisecond)) && (value.Status == "healthy" || value.Status == "degraded") && validCapabilities(value.Capabilities) && boundedClusterText(value.Kernel, 128) && value.EventRate <= 1_000_000_000 && value.Drops <= 1_000_000_000
}
func validPendingHeartbeat(value sensoradapter.Heartbeat) bool {
	return value.Sequence > 0 && (value.Status == "healthy" || value.Status == "degraded") && validCapabilities(value.Capabilities) && boundedClusterText(value.Kernel, 128) && value.EventRate <= 1_000_000_000 && value.Drops <= 1_000_000_000
}
func validCapabilities(values []string) bool {
	if len(values) < 1 || len(values) > 32 {
		return false
	}
	prior := ""
	for _, value := range values {
		if value != "file" && value != "network" && value != "process" || value <= prior {
			return false
		}
		prior = value
	}
	return true
}
func boundedClusterText(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
func validKubernetesName(value string) bool {
	return len(value) >= 1 && len(value) <= 253 && kubernetesNamePattern.MatchString(value)
}
func ownedLabels(authority string) map[string]string {
	return map[string]string{"app.kubernetes.io/name": "zasp-sensor-agent", clusterAuthorityLabel: authority}
}
func validOwnedLease(value *coordinationv1.Lease, name, namespace, authority string) bool {
	return value != nil && value.Name == name && value.Namespace == namespace && reflect.DeepEqual(value.Labels, ownedLabels(authority)) && value.ResourceVersion != ""
}
func nodeReportLeaseName(node string) string {
	digest := sha256.Sum256([]byte("zasp-sensor-node-v1\x00" + node))
	return "zasp-sensor-node-" + hex.EncodeToString(digest[:12])
}
func parseSequence(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || strconv.FormatInt(parsed, 10) != value || parsed < 0 {
		return 0, ErrCluster
	}
	return parsed, nil
}
func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}
func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}
func clusterNow(now func() time.Time) (time.Time, bool) {
	var value time.Time
	ok := true
	func() {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		value = now()
	}()
	if !ok || value.IsZero() {
		return time.Time{}, false
	}
	return value.UTC().Truncate(time.Millisecond), true
}
func clusterMutationError(err error) error {
	if err == nil {
		return nil
	}
	if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) || apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsTooManyRequests(err) {
		return ErrClusterRetryable
	}
	return ErrClusterRetryable
}
func safeHeartbeat(sink heartbeatSink, ctx context.Context, value sensoradapter.Heartbeat) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrClusterRetryable
		}
	}()
	return sink.Heartbeat(ctx, value)
}
func nilClusterValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
