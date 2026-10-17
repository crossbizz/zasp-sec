package preflight

import (
	"regexp"
	"strings"
)

// OpenSearchConfig pins the domain and selected deployed-container authority.
type OpenSearchConfig struct {
	DomainName         string   `json:"domain_name"`
	DomainARN          string   `json:"domain_arn"`
	Endpoint           string   `json:"endpoint"`
	VPCID              string   `json:"vpc_id"`
	SubnetIDs          []string `json:"subnet_ids"`
	SecurityGroupIDs   []string `json:"security_group_ids"`
	KMSKeyARN          string   `json:"kms_key_arn"`
	SessionSearchPhase string   `json:"session_search_phase"`
	Container          string   `json:"container"`
	Image              string   `json:"image"`
}

// This observation is decoded only from the independently authenticated selected
// Pod GET, never from config or user-supplied host observations.
type openSearchWorkload struct {
	Namespace, PodName, PodUID, ServiceAccount, Purpose, Container, Image string
	Env                                                                   map[string]string
	EnvFrom, IndirectEnv                                                  bool
}

func deriveOpenSearchFootprint(config OpenSearchConfig, selected AWSSelectedWorkload, observed openSearchWorkload) ([]string, error) {
	if selected.PodName == "" || selected.PodUID == "" || observed.PodName != selected.PodName || observed.PodUID != selected.PodUID || observed.Purpose != selected.Purpose || observed.Namespace != "agentsec" || observed.Container != config.Container || observed.Image != config.Image || !regexp.MustCompile(`^[A-Za-z0-9._/:+-]+@sha256:[0-9a-f]{64}$`).MatchString(config.Image) || observed.EnvFrom || observed.IndirectEnv {
		return nil, ErrRejected
	}
	switch config.SessionSearchPhase {
	case "compatibility", "backfill", "query", "precision-consumers", "precision-intake":
	default:
		return nil, ErrRejected
	}
	if observed.Env["ZASP_OPENSEARCH_ENDPOINT"] != config.Endpoint || config.Endpoint == "" {
		return nil, ErrRejected
	}
	switch observed.Purpose {
	case `aws_iam_role.runtime["index"]`:
		if observed.ServiceAccount != "zasp-runtime-index" || observed.Container != "runtime-index" || observed.Env["ZASP_WORKER_MODE"] != "runtime-index" || observed.Env["ZASP_OPENSEARCH_INDEX"] != "zasp-runtime-events-v1" {
			return nil, ErrRejected
		}
		stage, session := observed.Env["ZASP_RUNTIME_STAGE_VERSION"], observed.Env["ZASP_RUNTIME_SESSION_INDEX"]
		if stage != "runtime-index-v1" && stage != "runtime-index-v2" || stage == "runtime-index-v2" && session != "zasp-runtime-sessions-v2" || session != "zasp-runtime-sessions-v1" && session != "zasp-runtime-sessions-v2" || config.SessionSearchPhase == "compatibility" && session != "zasp-runtime-sessions-v1" {
			return nil, ErrRejected
		}
		return []string{"zasp-runtime-events-v1", session}, nil
	case "aws_iam_role.projection_search":
		if observed.ServiceAccount != "zasp-projection-search" || observed.Container != "projection-search" || observed.Env["ZASP_WORKER_MODE"] != "projection-search" || observed.Env["ZASP_OPENSEARCH_INDEX"] != "zasp-inventory-v1" {
			return nil, ErrRejected
		}
		return []string{"zasp-inventory-v1"}, nil
	default:
		return nil, ErrRejected
	}
}

// Endpoint selection remains a domain-bound canonical origin, never caller URL
// fallback or a credential-discovery route. Domain identity is checked separately.
func validOpenSearchEndpointTarget(endpoint, region string) bool {
	suffix := ".es.amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix += ".cn"
	}
	return regexp.MustCompile(`^https://vpc-[a-z0-9-]+\.` + regexp.QuoteMeta(region+suffix) + `$`).MatchString(endpoint)
}
