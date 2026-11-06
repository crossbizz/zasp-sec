// Package nodecoveragewire contains the bounded retained sensor observation contract.
package nodecoveragewire

import (
	"errors"
	"time"
)

const (
	MaxEnvelopeBytes      = 16 << 20
	MaxReportBytes        = 8192
	MaxSelectedNodes      = 1000
	MaxReports            = 1000
	HeartbeatSchema       = "sensor-heartbeat-node-coverage-v2"
	CoverageSchema        = "zasp-node-coverage-retained-v1"
	ReadSchema            = "sensor-coverage-node-observation-v2"
	ObservationReadSchema = "zasp-node-observation-read-v1"
)

var ErrInvalid = errors.New("selected sensor coverage unavailable")

type CoverageTarget struct {
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	Release          string `json:"release"`
	ReleaseNamespace string `json:"release_namespace"`
	Image            string `json:"image"`
	ServiceAccount   string `json:"service_account"`
	Container        string `json:"container"`
}

type NodeCoverageSelection struct {
	SourceProfile     string            `json:"source_profile"`
	ClusterUID        string            `json:"cluster_uid"`
	EnrollmentBinding string            `json:"enrollment_binding"`
	MatchLabels       map[string]string `json:"match_labels"`
	Sensor            CoverageTarget    `json:"sensor"`
	Tetragon          CoverageTarget    `json:"tetragon"`
}

type NodeCoverageV2 struct {
	Schema             string    `json:"schema"`
	EnrollmentBinding  string    `json:"enrollment_binding"`
	ClusterUID         string    `json:"cluster_uid"`
	NodeName           string    `json:"node_name"`
	NodeUID            string    `json:"node_uid"`
	BootID             string    `json:"boot_id"`
	ReporterPodName    string    `json:"reporter_pod_name"`
	ReporterPodUID     string    `json:"reporter_pod_uid"`
	TetragonPodName    string    `json:"tetragon_pod_name"`
	TetragonPodUID     string    `json:"tetragon_pod_uid"`
	GenerationID       string    `json:"generation_id"`
	SourceProfile      string    `json:"source_profile"`
	IdentityObservedAt time.Time `json:"identity_observed_at"`
	MeasuredAt         time.Time `json:"measured_at"`
	Status             string    `json:"status"`
	Capabilities       []string  `json:"capabilities"`
	Kernel             string    `json:"kernel"`
	BTF                bool      `json:"btf"`
	EventRate          uint64    `json:"event_rate"`
	Drops              uint64    `json:"drops"`
}

type Heartbeat struct {
	Sequence     int64    `json:"sequence"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
	Kernel       string   `json:"kernel"`
	BTF          bool     `json:"btf"`
	EventRate    uint64   `json:"event_rate"`
	Drops        uint64   `json:"drops"`
}
type SelectedNode struct {
	NodeName string `json:"node_name"`
	NodeUID  string `json:"node_uid"`
	BootID   string `json:"boot_id"`
}
type Envelope struct {
	Heartbeat
	CoverageSchema       string                `json:"coverage_schema"`
	StateUID             string                `json:"state_uid"`
	StorageEpoch         int64                 `json:"storage_epoch"`
	Selection            NodeCoverageSelection `json:"selection"`
	TargetDigest         string                `json:"target_digest"`
	InventoryObservedAt  time.Time             `json:"inventory_observed_at"`
	SourceObservedAt     time.Time             `json:"source_observed_at"`
	TTLSeconds           int64                 `json:"ttl_seconds"`
	SensorDaemonSetUID   string                `json:"sensor_daemonset_uid"`
	TetragonDaemonSetUID string                `json:"tetragon_daemonset_uid"`
	SelectedNodes        []SelectedNode        `json:"selected_nodes"`
	Reports              []NodeCoverageV2      `json:"reports"`
}
type Receipt struct {
	SensorID         string    `json:"sensor_id"`
	Sequence         int64     `json:"sequence"`
	RequestDigest    string    `json:"request_digest"`
	Disposition      string    `json:"disposition"`
	ResolvedAt       time.Time `json:"resolved_at"`
	SourceObservedAt time.Time `json:"source_observed_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	Replayed         bool      `json:"replayed"`
}
type ObservationRead struct {
	Schema  string               `json:"schema"`
	State   string               `json:"state"`
	Receipt *AcceptedObservation `json:"receipt"`
}
type AcceptedObservation struct {
	Sequence         int64     `json:"sequence"`
	RequestDigest    string    `json:"request_digest"`
	ReceivedAt       time.Time `json:"received_at"`
	SourceObservedAt time.Time `json:"source_observed_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	Observation      Envelope  `json:"observation"`
}
