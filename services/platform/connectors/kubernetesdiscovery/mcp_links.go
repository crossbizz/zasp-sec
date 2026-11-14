package kubernetesdiscovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// Which agents use which MCP servers of the cluster.
//
// An MCP server that runs in the cluster is reached through a Service, under
// the Service's DNS names. An agent that uses the server is configured with
// one of those names: in a container argument, in an environment variable or
// in a ConfigMap its pod template mounts or reads its environment from.
//
// The workload phases read one resource kind per page and keep nothing
// between pages, so they cannot compare one workload with another. The last
// phase of a collection (mcplinks) therefore reads, in memory and within one
// page, the Services, the workloads and the ConfigMaps the agent workloads
// name, and emits one relationship per agent and server it could match:
//
//	agent -depends_on-> MCP server    (attributes: type agent_mcp_server)
//
// The entities of both ends were emitted by the workload phases; their ids
// are a function of the workload's uid and kind, so the phase names them
// without having kept them. Argument elements, environment values and
// ConfigMap data are compared with the Service names and dropped: nothing of
// them is stored, logged or put in the page. Secrets are never requested.
//
// DOCUMENTED: https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/
// (a Service is assigned <service>.<namespace>.svc.<cluster-domain>; a pod
// of the same namespace also resolves the bare Service name) and
// https://kubernetes.io/docs/concepts/services-networking/service/ (a
// Service with a selector routes to the pods whose labels match it).
//
// The phase needs list on services and on configmaps. It never fails a
// collection: without the permission, or on any answer it cannot use, it
// relates nothing and the collection completes. The first page records on
// the cluster whether the two lists are allowed (attribute mcp_links), which
// the integration shows as a coverage gap.
const (
	kubernetesPhaseMCPLinks = "mcplinks"

	kubernetesLinkListLimit      = 200
	kubernetesLinkListPages      = 25
	kubernetesLinkResponseBytes  = int64(16 * 1024 * 1024)
	kubernetesLinkConfigMapReads = 256
	kubernetesLinkConfigMapBytes = int64(2 * 1024 * 1024)
	kubernetesMaximumMCPLinks    = 2000
	// A value longer than this is not an address.
	kubernetesLinkValueBytes = 64 * 1024

	kubernetesMCPLinksCollected        = "collected"
	kubernetesMCPLinksServicesDenied   = "services_denied"
	kubernetesMCPLinksConfigMapsDenied = "configmaps_denied"
)

type kubernetesLinkServiceList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Selector map[string]string `json:"selector"`
		} `json:"spec"`
	} `json:"items"`
}

// kubernetesLinkTemplate is the part of a pod template the link phase reads
// and the workload phases do not: the template's labels (to find the
// Services that select it) and the places an address is configured. The
// values decoded here are compared and dropped (kubernetesLinkTexts).
type kubernetesLinkTemplate struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Containers     []kubernetesLinkContainer `json:"containers"`
		InitContainers []kubernetesLinkContainer `json:"initContainers"`
		Volumes        []struct {
			ConfigMap *struct {
				Name string `json:"name"`
			} `json:"configMap"`
		} `json:"volumes"`
	} `json:"spec"`
}

type kubernetesLinkContainer struct {
	Command []string `json:"command"`
	Args    []string `json:"args"`
	Env     []struct {
		Value     string `json:"value"`
		ValueFrom *struct {
			ConfigMapKeyRef *struct {
				Name string `json:"name"`
				Key  string `json:"key"`
			} `json:"configMapKeyRef"`
		} `json:"valueFrom"`
	} `json:"env"`
	EnvFrom []struct {
		ConfigMapRef *struct {
			Name string `json:"name"`
		} `json:"configMapRef"`
	} `json:"envFrom"`
}

type kubernetesLinkWorkloadList struct {
	Items []struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			Template    kubernetesLinkTemplate `json:"template"`
			JobTemplate struct {
				Spec struct {
					Template kubernetesLinkTemplate `json:"template"`
				} `json:"spec"`
			} `json:"jobTemplate"`
		} `json:"spec"`
	} `json:"items"`
}

type kubernetesLinkConfigMapList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Items      []struct {
		Data map[string]string `json:"data"`
	} `json:"items"`
}

// kubernetesLinkAgent is an agent workload and where its configuration is.
type kubernetesLinkAgent struct {
	entityID, uid, namespace, resourceKind string
	template                               kubernetesLinkTemplate
}

// kubernetesLinkServer is an MCP server workload and the labels of its pods.
type kubernetesLinkServer struct {
	entityID, uid, namespace string
	labels                   map[string]string
}

// linkGet sends one bounded GET. status is 0 when there was no usable answer.
func (api *KubernetesCollectionAPI) linkGet(ctx context.Context, credential []byte, path string, query url.Values, limit int64) ([]byte, int) {
	bounded, cancel := context.WithTimeout(ctx, api.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, api.endpoint+path+"?"+query.Encode(), nil)
	if err != nil {
		return nil, 0
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(credential))
	response, err := doKubernetesCollectionRequest(api.client, request)
	if err != nil || bounded.Err() != nil || response == nil {
		closeKubernetesResponse(response)
		return nil, 0
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode
	}
	body, ok := readKubernetesCollectionBody(response.Body, limit)
	if !ok {
		return nil, 0
	}
	return body, http.StatusOK
}

// kubernetesMCPLinkStatus is recorded on the cluster entity: whether the
// credential may list Services and ConfigMaps, the two reads the link phase
// adds. "" when the answer was neither a success nor a refusal.
func (api *KubernetesCollectionAPI) kubernetesMCPLinkStatus(ctx context.Context, credential []byte, runtimeObservations string) string {
	query := url.Values{}
	query.Set("limit", "1")
	switch _, status := api.linkGet(ctx, credential, "/api/v1/services", query, kubernetesLinkResponseBytes); status {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return kubernetesMCPLinksServicesDenied
	default:
		return ""
	}
	// The runtime observation probe already asked whether ConfigMaps can be
	// listed.
	switch runtimeObservations {
	case "collected":
		return kubernetesMCPLinksCollected
	case "access_denied":
		return kubernetesMCPLinksConfigMapsDenied
	}
	return ""
}

// fetchKubernetesMCPLinksPage is the last page of a collection: it holds
// relationships only.
func (api *KubernetesCollectionAPI) fetchKubernetesMCPLinksPage(ctx context.Context, credential []byte, request CollectionPageRequest) (CollectionPage, error) {
	relationships := api.kubernetesMCPLinks(ctx, credential, request.Subject)
	if ctx.Err() != nil {
		return CollectionPage{}, providercollection.ClassifyProviderError(ctx, ctx.Err())
	}
	if len(relationships) > request.RemainingRelationships {
		return CollectionPage{}, providercollection.ErrPageCapacity
	}
	page, err := NewCollectionPage(request.Subject, nextKubernetesCompleteCursor(request.Cursor, request.Subject.ID), true, nil, relationships)
	if err != nil || int64(len(page.Raw)) > request.RemainingBytes || strings.Contains(string(page.Raw), string(credential)) {
		return CollectionPage{}, providercollection.StableProviderFailure(collection.FailureMalformed)
	}
	return page, nil
}

// kubernetesMCPLinks reads what the link phase needs and returns the
// relationships, sorted. Any read it cannot make ends it with what it has.
func (api *KubernetesCollectionAPI) kubernetesMCPLinks(ctx context.Context, credential []byte, subject collection.SubjectBinding) []json.RawMessage {
	// namespace -> Service name -> selector.
	services := map[string]map[string]map[string]string{}
	continuation := ""
	for range kubernetesLinkListPages {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(kubernetesLinkListLimit))
		if continuation != "" {
			query.Set("continue", continuation)
		}
		body, status := api.linkGet(ctx, credential, "/api/v1/services", query, kubernetesLinkResponseBytes)
		var list kubernetesLinkServiceList
		if status != http.StatusOK || !decodeKubernetesCollectionResponse(body, &list) || list.APIVersion != "v1" || list.Kind != "ServiceList" {
			return nil
		}
		for _, item := range list.Items {
			// A Service without a selector names no pods of the cluster.
			if !kubernetesNamePattern.MatchString(item.Metadata.Namespace) || !kubernetesNamePattern.MatchString(item.Metadata.Name) || len(item.Spec.Selector) == 0 {
				continue
			}
			if services[item.Metadata.Namespace] == nil {
				services[item.Metadata.Namespace] = map[string]map[string]string{}
			}
			services[item.Metadata.Namespace][item.Metadata.Name] = item.Spec.Selector
		}
		if continuation = list.Metadata.Continue; continuation == "" || !validKubernetesContinuation(continuation) {
			break
		}
	}
	if len(services) == 0 {
		return nil
	}
	var agents []kubernetesLinkAgent
	var servers []kubernetesLinkServer
	var egress kubernetesEgressObservations
	egressRead := false
	for _, phase := range []string{"deployments", "statefulsets", "daemonsets", "jobs", "cronjobs"} {
		path, _ := kubernetesCollectionPhasePath(phase)
		apiVersion, listKind, _ := kubernetesCollectionPhaseType(phase)
		continuation = ""
		for range kubernetesLinkListPages {
			query := url.Values{}
			query.Set("limit", strconv.Itoa(kubernetesLinkListLimit))
			if continuation != "" {
				query.Set("continue", continuation)
			}
			body, status := api.linkGet(ctx, credential, path, query, kubernetesLinkResponseBytes)
			// The same answer is decoded twice: once as the workload phases
			// decode it (names only), once for the link fields.
			var list kubernetesCollectionList
			var links kubernetesLinkWorkloadList
			if status != http.StatusOK || !decodeKubernetesCollectionResponse(body, &list) || !decodeKubernetesCollectionResponse(body, &links) || list.APIVersion != apiVersion || list.Kind != listKind || len(links.Items) != len(list.Items) {
				return nil
			}
			if !egressRead && len(list.Items) > 0 {
				egress, egressRead = api.fetchKubernetesEgressObservations(ctx, credential), true
			}
			for index, item := range list.Items {
				if links.Items[index].Metadata.UID != item.Metadata.UID {
					return nil
				}
				kind, _, podSpec, _, resourceKind, valid := kubernetesWorkloadIdentity(phase, item, egress)
				if !valid || !kubernetesUIDPattern.MatchString(item.Metadata.UID) || !kubernetesNamePattern.MatchString(item.Metadata.Name) {
					continue
				}
				template := links.Items[index].Spec.Template
				if phase == "cronjobs" {
					template = links.Items[index].Spec.JobTemplate.Spec.Template
				}
				if kind == "kubernetes_agent" || kind == "kubernetes_inferred_agent" {
					agents = append(agents, kubernetesLinkAgent{entityID: deterministicKubernetesInventoryID(subject, kind, item.Metadata.UID), uid: item.Metadata.UID, namespace: item.Metadata.Namespace, resourceKind: resourceKind, template: template})
				}
				if kubernetesMCPServerRecorded(phase, item.Metadata.Labels, podSpec) {
					servers = append(servers, kubernetesLinkServer{entityID: deterministicKubernetesInventoryID(subject, "kubernetes_mcp_server", item.Metadata.UID), uid: item.Metadata.UID, namespace: item.Metadata.Namespace, labels: template.Metadata.Labels})
				}
			}
			if continuation = list.Metadata.Continue; continuation == "" || !validKubernetesContinuation(continuation) {
				break
			}
		}
	}
	if len(agents) == 0 || len(servers) == 0 {
		return nil
	}
	// The names every server is reached under: "<service>.<namespace>" for
	// any pod, "<namespace>/<service>" for a pod of the same namespace.
	qualified, local := map[string][]int{}, map[string][]int{}
	for index, server := range servers {
		for name, selector := range services[server.namespace] {
			if !kubernetesSelectorMatches(selector, server.labels) {
				continue
			}
			qualified[name+"."+server.namespace] = append(qualified[name+"."+server.namespace], index)
			local[server.namespace+"/"+name] = append(local[server.namespace+"/"+name], index)
		}
	}
	if len(qualified) == 0 {
		return nil
	}
	configMaps := map[string]map[string]string{}
	configMapReads, configMapsDenied := 0, false
	readConfigMap := func(namespace, name string) map[string]string {
		key := namespace + "/" + name
		if data, read := configMaps[key]; read {
			return data
		}
		if configMapsDenied || configMapReads >= kubernetesLinkConfigMapReads || !kubernetesNamePattern.MatchString(name) {
			return nil
		}
		configMapReads++
		query := url.Values{}
		query.Set("fieldSelector", "metadata.name="+name)
		query.Set("limit", "1")
		body, status := api.linkGet(ctx, credential, "/api/v1/namespaces/"+namespace+"/configmaps", query, kubernetesLinkConfigMapBytes)
		var list kubernetesLinkConfigMapList
		switch {
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			configMapsDenied = true
		case status == http.StatusOK && decodeKubernetesCollectionResponse(body, &list) && list.APIVersion == "v1" && list.Kind == "ConfigMapList" && len(list.Items) == 1:
			configMaps[key] = list.Items[0].Data
			return list.Items[0].Data
		}
		configMaps[key] = nil
		return nil
	}
	type link struct{ agent, server int }
	found := map[link]bool{}
	for agentIndex, agent := range agents {
		matched := map[int]bool{}
		visit := func(text string) {
			kubernetesMatchServiceNames(text, agent.namespace, qualified, local, matched)
		}
		kubernetesLinkTexts(agent, readConfigMap, visit)
		for serverIndex := range matched {
			// A workload is not its own client.
			if servers[serverIndex].uid != agent.uid {
				found[link{agentIndex, serverIndex}] = true
			}
		}
	}
	relationships := make([]json.RawMessage, 0, len(found))
	for pair := range found {
		agent, server := agents[pair.agent], servers[pair.server]
		relationship, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "depends_on", agent.uid+":mcp_server:"+server.uid), "depends_on",
			"kubernetes:"+strings.ToLower(agent.resourceKind)+":"+agent.uid+":mcp_server:"+server.uid, agent.entityID, server.entityID, "agent_mcp_server")
		if err != nil {
			return nil
		}
		relationships = append(relationships, relationship)
	}
	sort.Slice(relationships, func(left, right int) bool { return string(relationships[left]) < string(relationships[right]) })
	if len(relationships) > kubernetesMaximumMCPLinks {
		relationships = relationships[:kubernetesMaximumMCPLinks]
	}
	return relationships
}

// kubernetesLinkTexts gives visit every text of an agent's pod template that
// can hold an address. Nothing it passes on is kept by the caller.
func kubernetesLinkTexts(agent kubernetesLinkAgent, readConfigMap func(namespace, name string) map[string]string, visit func(string)) {
	visitMap := func(name string) {
		for _, value := range readConfigMap(agent.namespace, name) {
			visit(value)
		}
	}
	for _, containers := range [][]kubernetesLinkContainer{agent.template.Spec.Containers, agent.template.Spec.InitContainers} {
		for _, container := range containers {
			for _, element := range container.Command {
				visit(element)
			}
			for _, element := range container.Args {
				visit(element)
			}
			for _, variable := range container.Env {
				visit(variable.Value)
				if variable.ValueFrom != nil && variable.ValueFrom.ConfigMapKeyRef != nil {
					if value, present := readConfigMap(agent.namespace, variable.ValueFrom.ConfigMapKeyRef.Name)[variable.ValueFrom.ConfigMapKeyRef.Key]; present {
						visit(value)
					}
				}
			}
			for _, source := range container.EnvFrom {
				if source.ConfigMapRef != nil {
					visitMap(source.ConfigMapRef.Name)
				}
			}
		}
	}
	for _, volume := range agent.template.Spec.Volumes {
		if volume.ConfigMap != nil {
			visitMap(volume.ConfigMap.Name)
		}
	}
}

func kubernetesSelectorMatches(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if got, present := labels[key]; !present || got != value {
			return false
		}
	}
	return true
}

// kubernetesMatchServiceNames marks the servers whose Service name text
// holds. A name is looked for as a whole host: a run of host characters
// bounded by anything else.
//
//   - "<service>.<namespace>.svc" and "<service>.<namespace>.svc.<domain>"
//     are Service names wherever they stand;
//   - "<service>.<namespace>" and, for a pod of the Service's namespace, the
//     bare "<service>" are ordinary words too, so they count only where the
//     text uses them as a host: after "://" or "@", before ":<port>", or as
//     the whole value.
func kubernetesMatchServiceNames(text, namespace string, qualified, local map[string][]int, matched map[int]bool) {
	if len(text) == 0 || len(text) > kubernetesLinkValueBytes {
		return
	}
	lower := strings.ToLower(text)
	whole := strings.TrimSpace(lower)
	for start := 0; start < len(lower); {
		if !kubernetesHostCharacter(lower[start]) {
			start++
			continue
		}
		end := start
		for end < len(lower) && kubernetesHostCharacter(lower[end]) {
			end++
		}
		token := strings.Trim(lower[start:end], ".-")
		tokenStart := start + strings.Index(lower[start:end], token)
		tokenEnd := tokenStart + len(token)
		start = end
		if token == "" {
			continue
		}
		if base, _, found := strings.Cut(token, ".svc."); found || strings.HasSuffix(token, ".svc") {
			if !found {
				base = strings.TrimSuffix(token, ".svc")
			}
			for _, server := range qualified[base] {
				matched[server] = true
			}
			continue
		}
		asHost := token == whole ||
			tokenStart >= 3 && lower[tokenStart-3:tokenStart] == "://" || tokenStart >= 1 && lower[tokenStart-1] == '@' ||
			tokenEnd+1 < len(lower) && lower[tokenEnd] == ':' && lower[tokenEnd+1] >= '0' && lower[tokenEnd+1] <= '9'
		if !asHost {
			continue
		}
		for _, server := range qualified[token] {
			matched[server] = true
		}
		for _, server := range local[namespace+"/"+token] {
			matched[server] = true
		}
	}
}

func kubernetesHostCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '-'
}
