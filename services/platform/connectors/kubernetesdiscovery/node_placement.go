package kubernetesdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// Explicitly selected through the existing collector-version contract. Earlier
// recipes and continuations retain their original default behavior.
const NodePlacementCollectorVersion = "kubernetes_node_placement_v2"

func (api *KubernetesCollectionAPI) NodePlacementEnabled() bool {
	return api != nil && api.nodePlacement
}

const placementMaximumObjects = 1000
const placementMaximumCalls = 8192

type placementOwner struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller"`
}
type placementMetadata struct {
	Name              string           `json:"name"`
	Namespace         string           `json:"namespace"`
	UID               string           `json:"uid"`
	ResourceVersion   string           `json:"resourceVersion"`
	DeletionTimestamp *time.Time       `json:"deletionTimestamp"`
	OwnerReferences   []placementOwner `json:"ownerReferences"`
}
type placementObject struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   placementMetadata `json:"metadata"`
	Spec       struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		NodeInfo struct {
			BootID string `json:"bootID"`
		} `json:"nodeInfo"`
	} `json:"status"`
}
type placementList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Continue        string `json:"continue"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []placementObject `json:"items"`
}
type placementBudget struct {
	remaining int64
	calls     int
}

func (api *KubernetesCollectionAPI) placementRead(ctx context.Context, credential []byte, path string, budget *placementBudget, out any) error {
	if ctx.Err() != nil || budget.remaining < 1 || budget.calls >= placementMaximumCalls {
		return providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	budget.calls++
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, api.endpoint+path, nil)
	if err != nil {
		return ErrInvalid
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(credential))
	response, err := doKubernetesCollectionRequest(api.client, request)
	if err != nil || ctx.Err() != nil || response == nil {
		closeKubernetesResponse(response)
		return providercollection.ClassifyProviderHTTPFailure(ctx, err, 0, "", time.Now().UTC())
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return providercollection.ClassifyProviderHTTPFailure(ctx, nil, response.StatusCode, response.Header.Get("Retry-After"), time.Now().UTC())
	}
	raw, ok := readKubernetesCollectionBody(response.Body, min(budget.remaining, kubernetesMaximumResponseBytes))
	if !ok {
		return providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	budget.remaining -= int64(len(raw))
	if !validPlacementJSON(raw) || !decodeKubernetesCollectionResponse(raw, out) {
		return providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return nil
}
func validPlacementMetadata(m placementMetadata, namespace string) bool {
	return m.Namespace == namespace && kubernetesNamePattern.MatchString(m.Name) && providercollection.ValidPlacementUID(m.UID) && len(m.ResourceVersion) > 0 && len(m.ResourceVersion) <= 128 && len(m.OwnerReferences) <= 16
}
func exactPlacementOwner(obj placementObject, kind, namespace string) (placementOwner, bool) {
	if obj.Metadata.Namespace != namespace {
		return placementOwner{}, false
	}
	var found placementOwner
	count := 0
	for _, owner := range obj.Metadata.OwnerReferences {
		if owner.Controller {
			found = owner
			count++
		}
	}
	return found, count == 1 && found.APIVersion == "apps/v1" && found.Kind == kind && kubernetesNamePattern.MatchString(found.Name) && providercollection.ValidPlacementUID(found.UID)
}

// Lists a complete namespace once per snapshot, shared by every Agent on the
// Deployment page. Pagination and total bytes/calls are bounded, never clipped.
func (api *KubernetesCollectionAPI) placementList(ctx context.Context, credential []byte, path, kind, namespace string, budget *placementBudget) ([]placementObject, error) {
	result := make([]placementObject, 0)
	continuation := ""
	seenTokens := map[string]bool{}
	seenUID := map[string]bool{}
	seenName := map[string]bool{}
	rv := ""
	for {
		query := url.Values{"limit": []string{strconv.Itoa(kubernetesMaximumPageItems)}}
		if continuation != "" {
			query.Set("continue", continuation)
		}
		var page placementList
		if err := api.placementRead(ctx, credential, path+"?"+query.Encode(), budget, &page); err != nil {
			return nil, err
		}
		expectedVersion := "apps/v1"
		if kind == "Pod" {
			expectedVersion = "v1"
		}
		if page.APIVersion != expectedVersion || page.Kind != kind+"List" || page.Metadata.ResourceVersion == "" || rv != "" && rv != page.Metadata.ResourceVersion || len(page.Items) > kubernetesMaximumPageItems || len(result)+len(page.Items) > placementMaximumObjects {
			return nil, ErrInvalid
		}
		rv = page.Metadata.ResourceVersion
		for _, item := range page.Items {
			if item.Kind != kind || item.APIVersion != expectedVersion || !validPlacementMetadata(item.Metadata, namespace) || seenUID[item.Metadata.UID] || seenName[item.Metadata.Name] {
				return nil, ErrInvalid
			}
			seenUID[item.Metadata.UID] = true
			seenName[item.Metadata.Name] = true
			result = append(result, item)
		}
		continuation = page.Metadata.Continue
		if continuation == "" {
			break
		}
		if len(result) >= placementMaximumObjects || !validKubernetesContinuation(continuation) || seenTokens[continuation] {
			return nil, ErrInvalid
		}
		seenTokens[continuation] = true
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Metadata.UID < result[j].Metadata.UID })
	return result, nil
}

type placementSnapshot struct {
	Cluster     placementObject
	ReplicaSets map[string][]placementObject
	Pods        map[string][]placementObject
	Nodes       map[string]placementObject
}

func (api *KubernetesCollectionAPI) placementSnapshot(ctx context.Context, credential []byte, namespaces []string, controllers map[string]placementObject, budget *placementBudget) (placementSnapshot, error) {
	snapshot := placementSnapshot{ReplicaSets: map[string][]placementObject{}, Pods: map[string][]placementObject{}, Nodes: map[string]placementObject{}}
	if err := api.placementRead(ctx, credential, "/api/v1/namespaces/kube-system", budget, &snapshot.Cluster); err != nil {
		return snapshot, err
	}
	if snapshot.Cluster.APIVersion != "v1" || snapshot.Cluster.Kind != "Namespace" || snapshot.Cluster.Metadata.Name != "kube-system" || !validPlacementMetadata(snapshot.Cluster.Metadata, "") || snapshot.Cluster.Metadata.DeletionTimestamp != nil {
		return snapshot, ErrInvalid
	}
	nodeNames := map[string]bool{}
	for _, namespace := range namespaces {
		sets, err := api.placementList(ctx, credential, "/apis/apps/v1/namespaces/"+namespace+"/replicasets", "ReplicaSet", namespace, budget)
		if err != nil {
			return snapshot, err
		}
		snapshot.ReplicaSets[namespace] = sets
		pods, err := api.placementList(ctx, credential, "/api/v1/namespaces/"+namespace+"/pods", "Pod", namespace, budget)
		if err != nil {
			return snapshot, err
		}
		snapshot.Pods[namespace] = pods
		relevantSets := map[string]placementObject{}
		for _, set := range sets {
			if set.Metadata.DeletionTimestamp != nil {
				continue
			}
			owner, ok := exactPlacementOwner(set, "Deployment", namespace)
			controller, selected := controllers[owner.UID]
			if !ok {
				for _, candidate := range set.Metadata.OwnerReferences {
					if candidate.Controller {
						if _, selected := controllers[candidate.UID]; selected {
							return snapshot, ErrInvalid
						}
					}
				}
			}
			if ok && selected {
				if owner.Name != controller.Metadata.Name {
					return snapshot, ErrInvalid
				}
				relevantSets[set.Metadata.UID] = set
			}
		}
		for _, pod := range pods {
			if pod.Metadata.DeletionTimestamp != nil {
				continue
			}
			owner, ok := exactPlacementOwner(pod, "ReplicaSet", namespace)
			set, selected := relevantSets[owner.UID]
			if !ok {
				for _, candidate := range pod.Metadata.OwnerReferences {
					if candidate.Controller {
						if _, selected := relevantSets[candidate.UID]; selected {
							return snapshot, ErrInvalid
						}
					}
				}
			}
			if ok && selected {
				if owner.Name != set.Metadata.Name || !kubernetesNamePattern.MatchString(pod.Spec.NodeName) {
					return snapshot, ErrInvalid
				}
				nodeNames[pod.Spec.NodeName] = true
			}
		}
	}
	if len(nodeNames) > placementMaximumObjects {
		return snapshot, ErrInvalid
	}
	names := make([]string, 0, len(nodeNames))
	for name := range nodeNames {
		names = append(names, name)
	}
	sort.Strings(names)
	seenNodeUID := map[string]bool{}
	for _, name := range names {
		var node placementObject
		if err := api.placementRead(ctx, credential, "/api/v1/nodes/"+name, budget, &node); err != nil {
			return snapshot, err
		}
		if node.APIVersion != "v1" || node.Kind != "Node" || node.Metadata.Name != name || !validPlacementMetadata(node.Metadata, "") || !providercollection.ValidPlacementUID(node.Status.NodeInfo.BootID) || node.Metadata.DeletionTimestamp != nil || seenNodeUID[node.Metadata.UID] {
			return snapshot, ErrInvalid
		}
		seenNodeUID[node.Metadata.UID] = true
		snapshot.Nodes[name] = node
	}
	return snapshot, nil
}
func (api *KubernetesCollectionAPI) enrichAgentPlacements(ctx context.Context, credential, original []byte, entities []json.RawMessage, remaining int64, observed time.Time) ([]json.RawMessage, error) {
	// Captured before the first dependency read and retained through both snapshots.
	budget := placementBudget{remaining: remaining}
	var input placementList
	if !validPlacementJSON(original) || !decodeKubernetesCollectionResponse(original, &input) {
		return nil, ErrInvalid
	}
	controllers := map[string]placementObject{}
	namespaces := map[string]bool{}
	for _, raw := range entities {
		var entity map[string]json.RawMessage
		if json.Unmarshal(raw, &entity) != nil {
			return nil, ErrInvalid
		}
		var kind, native string
		_ = json.Unmarshal(entity["kind"], &kind)
		_ = json.Unmarshal(entity["source_native_id"], &native)
		if kind != "kubernetes_agent" {
			continue
		}
		matched := false
		for _, controller := range input.Items {
			if "kubernetes:deployment:"+controller.Metadata.UID == native {
				if controller.APIVersion != "apps/v1" || controller.Kind != "Deployment" || !validPlacementMetadata(controller.Metadata, controller.Metadata.Namespace) || !kubernetesNamePattern.MatchString(controller.Metadata.Namespace) || controller.Metadata.DeletionTimestamp != nil {
					return nil, ErrInvalid
				}
				controllers[controller.Metadata.UID] = controller
				namespaces[controller.Metadata.Namespace] = true
				matched = true
				break
			}
		}
		if !matched {
			return nil, ErrInvalid
		}
	}
	if len(controllers) == 0 {
		return entities, nil
	}
	orderedNamespaces := make([]string, 0, len(namespaces))
	for namespace := range namespaces {
		orderedNamespaces = append(orderedNamespaces, namespace)
	}
	sort.Strings(orderedNamespaces)
	first, err := api.placementSnapshot(ctx, credential, orderedNamespaces, controllers, &budget)
	if err != nil {
		return nil, err
	}
	// Revalidate each selected controller through its exact namespaced resource.
	ids := make([]string, 0, len(controllers))
	for id := range controllers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		expected := controllers[id]
		var actual placementObject
		if err := api.placementRead(ctx, credential, "/apis/apps/v1/namespaces/"+expected.Metadata.Namespace+"/deployments/"+expected.Metadata.Name, &budget, &actual); err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(actual, expected) {
			return nil, ErrInvalid
		}
	}
	second, err := api.placementSnapshot(ctx, credential, orderedNamespaces, controllers, &budget)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(first, second) || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	placements := map[string]providercollection.KubernetesAgentPlacement{}
	for id, controller := range controllers {
		facts := providercollection.KubernetesAgentPlacement{Schema: "kubernetes-agent-placement-v1", ClusterUID: first.Cluster.Metadata.UID, ControllerUID: id, ObservedAt: observed, Placements: make([]providercollection.KubernetesAgentPlacementTuple, 0)}
		sets := map[string]placementObject{}
		for _, set := range first.ReplicaSets[controller.Metadata.Namespace] {
			if set.Metadata.DeletionTimestamp != nil {
				continue
			}
			owner, ok := exactPlacementOwner(set, "Deployment", controller.Metadata.Namespace)
			if ok && owner.UID == id && owner.Name == controller.Metadata.Name {
				sets[set.Metadata.UID] = set
			}
		}
		for _, pod := range first.Pods[controller.Metadata.Namespace] {
			if pod.Metadata.DeletionTimestamp != nil {
				continue
			}
			owner, ok := exactPlacementOwner(pod, "ReplicaSet", controller.Metadata.Namespace)
			set, found := sets[owner.UID]
			if ok && found && owner.Name == set.Metadata.Name {
				node, found := first.Nodes[pod.Spec.NodeName]
				if !found {
					return nil, ErrInvalid
				}
				facts.Placements = append(facts.Placements, providercollection.KubernetesAgentPlacementTuple{ReplicaSetUID: set.Metadata.UID, PodUID: pod.Metadata.UID, NodeUID: node.Metadata.UID, BootID: node.Status.NodeInfo.BootID})
			}
		}
		sort.Slice(facts.Placements, func(i, j int) bool { return facts.Placements[i].Key() < facts.Placements[j].Key() })
		if len(facts.Placements) == 0 {
			continue
		}
		if !facts.Validate() {
			return nil, ErrInvalid
		}
		placements[id] = facts
	}
	result := make([]json.RawMessage, 0, len(entities))
	for _, raw := range entities {
		var entity map[string]json.RawMessage
		_ = json.Unmarshal(raw, &entity)
		var kind, native string
		_ = json.Unmarshal(entity["kind"], &kind)
		_ = json.Unmarshal(entity["source_native_id"], &native)
		if kind == "kubernetes_agent" {
			var attrs map[string]json.RawMessage
			if json.Unmarshal(entity["attributes"], &attrs) != nil {
				return nil, ErrInvalid
			}
			id := native[len("kubernetes:deployment:"):]
			fact, ok := placements[id]
			if !ok {
				result = append(result, raw)
				continue
			}
			attrs["placement"], err = json.Marshal(fact)
			if err != nil {
				return nil, ErrInvalid
			}
			entity["attributes"], err = json.Marshal(attrs)
			if err != nil || len(entity["attributes"]) > 262144 {
				return nil, ErrInvalid
			}
			var entityID, displayName string
			_ = json.Unmarshal(entity["id"], &entityID)
			_ = json.Unmarshal(entity["display_name"], &displayName)
			raw, err = marshalKubernetesEntity(entityID, kind, native, displayName, entity["stable_fields"], entity["attributes"])
			if err != nil {
				return nil, ErrInvalid
			}
		}
		result = append(result, raw)
	}
	return result, nil
}

// Kubernetes objects legitimately carry fields beyond this minimal observation.
// Reject ambiguous aliases/duplicates without accepting Go's case-folded field
// matching as an alternative identity source.
func validPlacementJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	reserved := map[string]string{}
	for _, key := range []string{"apiVersion", "kind", "metadata", "name", "namespace", "uid", "resourceVersion", "deletionTimestamp", "ownerReferences", "controller", "spec", "nodeName", "status", "nodeInfo", "bootID", "items", "continue"} {
		reserved[strings.ToLower(key)] = key
	}
	var walk func(int, bool) bool
	walk = func(depth int, identity bool) bool {
		if depth > 64 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok {
					return false
				}
				fold := strings.ToLower(key)
				if seen[key] {
					return false
				}
				seen[key] = true
				if exact, known := reserved[fold]; identity && known && key != exact {
					return false
				}
				childIdentity := identity && (key == "metadata" || key == "spec" || key == "status" || key == "nodeInfo" || key == "ownerReferences" || key == "items")
				if !walk(depth+1, childIdentity) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !walk(depth+1, identity) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !walk(0, true) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
