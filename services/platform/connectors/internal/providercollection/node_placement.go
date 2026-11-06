package providercollection

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// KubernetesAgentPlacement is evidence of the observed owner chain and node
// incarnation. It grants no runtime health, policy coverage or Kubernetes access.
type KubernetesAgentPlacement struct {
	Schema        string                          `json:"schema"`
	ClusterUID    string                          `json:"cluster_uid"`
	ControllerUID string                          `json:"controller_uid"`
	ObservedAt    time.Time                       `json:"observed_at"`
	Placements    []KubernetesAgentPlacementTuple `json:"placements"`
}
type KubernetesAgentPlacementTuple struct {
	ReplicaSetUID string `json:"replicaset_uid"`
	PodUID        string `json:"pod_uid"`
	NodeUID       string `json:"node_uid"`
	BootID        string `json:"boot_id"`
}

var placementUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidPlacementUID(v string) bool {
	return placementUUID.MatchString(v) && v != "00000000-0000-0000-0000-000000000000"
}
func (v KubernetesAgentPlacementTuple) Key() string {
	return strings.Join([]string{v.ReplicaSetUID, v.PodUID, v.NodeUID, v.BootID}, "/")
}
func (v KubernetesAgentPlacement) Validate() bool {
	if v.Schema != "kubernetes-agent-placement-v1" || !ValidPlacementUID(v.ClusterUID) || !ValidPlacementUID(v.ControllerUID) || v.ObservedAt.IsZero() || v.ObservedAt.Location() != time.UTC || v.ObservedAt.Year() < 1 || v.ObservedAt.Year() > 9999 || v.Placements == nil || len(v.Placements) < 1 || len(v.Placements) > 1000 {
		return false
	}
	previous := ""
	pods := map[string]bool{}
	for _, row := range v.Placements {
		key := row.Key()
		if !ValidPlacementUID(row.ReplicaSetUID) || !ValidPlacementUID(row.PodUID) || !ValidPlacementUID(row.NodeUID) || !ValidPlacementUID(row.BootID) || key <= previous || pods[row.PodUID] {
			return false
		}
		previous = key
		pods[row.PodUID] = true
	}
	raw, err := json.Marshal(v)
	return err == nil && len(raw) <= 262144
}
func validKubernetesAgentPlacement(value any) bool {
	fields, ok := value.(map[string]any)
	if !ok || len(fields) != 5 {
		return false
	}
	for _, key := range []string{"schema", "cluster_uid", "controller_uid", "observed_at", "placements"} {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	rows, ok := fields["placements"].([]any)
	if !ok || len(rows) < 1 || len(rows) > 1000 {
		return false
	}
	for _, row := range rows {
		f, ok := row.(map[string]any)
		if !ok || len(f) != 4 {
			return false
		}
		for _, key := range []string{"replicaset_uid", "pod_uid", "node_uid", "boot_id"} {
			if _, ok := f[key].(string); !ok {
				return false
			}
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return false
	}
	var v KubernetesAgentPlacement
	return json.Unmarshal(raw, &v) == nil && v.Validate()
}
