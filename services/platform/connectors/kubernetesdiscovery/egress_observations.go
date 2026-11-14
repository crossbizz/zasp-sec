package kubernetesdiscovery

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
)

// Runtime observations: the node sensor's egress-discovery role publishes,
// per node, which workloads it saw call a model API or a remote MCP server
// (catalog tokens only). The documents are ConfigMaps carrying a label; the
// collector reads them with the cluster credential it already holds.

const (
	kubernetesEgressListPages     = 5
	kubernetesEgressListLimit     = 100
	kubernetesEgressResponseBytes = int64(4 * 1024 * 1024)
)

type kubernetesEgressKey struct{ namespace, kind, name string }

// kubernetesEgressObservations maps a workload to the sorted catalog tokens
// seen for it on any node within the retention window.
type kubernetesEgressObservations map[kubernetesEgressKey][]string

func kubernetesWorkloadPhase(phase string) bool {
	switch phase {
	case "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs":
		return true
	}
	return false
}

type kubernetesEgressConfigMapList struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Data map[string]string `json:"data"`
	} `json:"items"`
}

// listKubernetesEgressConfigMaps reads one page of the labelled ConfigMaps
// and returns the HTTP status (0 when there was no usable answer).
func (api *KubernetesCollectionAPI) listKubernetesEgressConfigMaps(ctx context.Context, credential []byte, limit int, continuation string) (kubernetesEgressConfigMapList, int) {
	query := url.Values{}
	query.Set("labelSelector", agentsignals.EgressObservationsLabel+"="+agentsignals.EgressObservationsLabelValue)
	query.Set("limit", strconv.Itoa(limit))
	if continuation != "" {
		query.Set("continue", continuation)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, api.endpoint+"/api/v1/configmaps?"+query.Encode(), nil)
	if err != nil {
		return kubernetesEgressConfigMapList{}, 0
	}
	request.Close = true
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(credential))
	response, err := doKubernetesCollectionRequest(api.client, request)
	if err != nil || response == nil {
		closeKubernetesResponse(response)
		return kubernetesEgressConfigMapList{}, 0
	}
	body, ok := readKubernetesCollectionBody(response.Body, kubernetesEgressResponseBytes)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return kubernetesEgressConfigMapList{}, response.StatusCode
	}
	var list kubernetesEgressConfigMapList
	if !ok || !decodeKubernetesCollectionResponse(body, &list) || list.APIVersion != "v1" || list.Kind != "ConfigMapList" {
		return kubernetesEgressConfigMapList{}, 0
	}
	return list, http.StatusOK
}

// kubernetesRuntimeObservationStatus is recorded on the cluster entity so
// the integration can say when the runtime signal is not counted:
// "collected" when the credential may list the ConfigMaps (whether or not
// the sensor role is installed), "access_denied" when it may not, and ""
// when the answer was anything else.
func (api *KubernetesCollectionAPI) kubernetesRuntimeObservationStatus(ctx context.Context, credential []byte) string {
	switch _, status := api.listKubernetesEgressConfigMaps(ctx, credential, 1, ""); status {
	case http.StatusOK:
		return "collected"
	case http.StatusUnauthorized, http.StatusForbidden:
		return "access_denied"
	}
	return ""
}

// fetchKubernetesEgressObservations never fails a collection. A cluster
// without the sensor role has no such ConfigMaps; a credential that may not
// list ConfigMaps gets 403. In both cases, and on any malformed or oversized
// answer, workloads are judged on their pod templates alone, exactly as
// before the role existed. A document that does not validate is skipped: it
// is not the sensor's.
func (api *KubernetesCollectionAPI) fetchKubernetesEgressObservations(ctx context.Context, credential []byte) kubernetesEgressObservations {
	now := api.clock().UTC()
	merged := map[kubernetesEgressKey]map[string]bool{}
	continuation := ""
	for range kubernetesEgressListPages {
		list, status := api.listKubernetesEgressConfigMaps(ctx, credential, kubernetesEgressListLimit, continuation)
		if status != http.StatusOK {
			break
		}
		for _, item := range list.Items {
			document, valid := agentsignals.ParseEgressObservations([]byte(item.Data[agentsignals.EgressObservationsKey]))
			if !valid {
				continue
			}
			for _, workload := range document.Workloads {
				for _, token := range workload.Current(now) {
					key := kubernetesEgressKey{workload.Namespace, workload.Kind, workload.Name}
					if merged[key] == nil {
						merged[key] = map[string]bool{}
					}
					merged[key][token] = true
				}
			}
		}
		continuation = list.Metadata.Continue
		if continuation == "" || !validKubernetesContinuation(continuation) {
			break
		}
	}
	observations := make(kubernetesEgressObservations, len(merged))
	for key, tokens := range merged {
		for token := range tokens {
			observations[key] = append(observations[key], token)
		}
		sort.Strings(observations[key])
	}
	return observations
}
