package kubernetesdiscovery

import (
	"encoding/json"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// A workload whose pod template runs an MCP server (an image or a command
// the catalog recognises) is also recorded as an MCP server, beside the
// workload itself. Only the pod template is read: the cluster API does not
// say which agents call the server, so no agent is related to it, and its
// tools cannot be listed without calling it.

// kubernetesMCPServerWorkload reports whether a pod template runs an MCP
// server. Init containers are not servers.
func kubernetesMCPServerWorkload(spec kubernetesCollectionPodSpec) bool {
	for _, container := range spec.Containers {
		if agentsignals.MCPServerImage(container.Image) || agentsignals.MCPServerCommand(container.Command...) || agentsignals.MCPServerCommand(container.Args...) {
			return true
		}
	}
	return false
}

// normalizeKubernetesMCPServer returns the MCP server entity of a workload
// and its edge from the namespace, or nothing when the workload is not one.
// The workload has already passed normalizeKubernetesWorkload's checks.
func normalizeKubernetesMCPServer(subject collection.SubjectBinding, phase string, item kubernetesCollectionItem) (json.RawMessage, json.RawMessage, bool) {
	definitions := map[string][2]string{"deployments": {"Deployment", "apps"}, "statefulsets": {"StatefulSet", "apps"}, "daemonsets": {"DaemonSet", "apps"}}
	definition, served := definitions[phase]
	if label, labelled := item.Metadata.Labels["zasp.ai/entity-kind"]; !served || labelled && label != "mcp-server" && label != "agent" || !kubernetesMCPServerWorkload(item.Spec.Template.Spec) {
		return nil, nil, true
	}
	native := "kubernetes:" + strings.ToLower(definition[0]) + ":" + item.Metadata.UID + ":mcp_server"
	entityID := deterministicKubernetesInventoryID(subject, "kubernetes_mcp_server", item.Metadata.UID)
	stable, _ := json.Marshal(struct {
		APIGroup     string `json:"api_group"`
		APIVersion   string `json:"api_version"`
		Cluster      string `json:"cluster"`
		Name         string `json:"name"`
		Namespace    string `json:"namespace"`
		ResourceKind string `json:"resource_kind"`
	}{definition[1], "v1", subject.ID, item.Metadata.Name, item.Metadata.Namespace, definition[0]})
	attributes, _ := json.Marshal(struct {
		Namespaced bool   `json:"namespaced"`
		Source     string `json:"source"`
		Transport  string `json:"transport"`
	}{true, "workload", agentsignals.MCPTransportHTTP})
	entity, err := marshalKubernetesEntity(entityID, "kubernetes_mcp_server", native, item.Metadata.Namespace+"/"+item.Metadata.Name, stable, attributes)
	if err != nil {
		return nil, nil, false
	}
	namespaceID := deterministicKubernetesInventoryID(subject, "kubernetes_namespace", "namespace:"+item.Metadata.Namespace)
	attached, err := marshalKubernetesRelationship(deterministicKubernetesInventoryID(subject, "attached_to", "mcp_server:"+item.Metadata.UID), "attached_to", native+":namespace:"+item.Metadata.Namespace, namespaceID, entityID, "namespace_mcp_server")
	if err != nil {
		return nil, nil, false
	}
	return entity, attached, true
}
