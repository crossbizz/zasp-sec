package agentsignals

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Runtime egress: DNS names a workload resolved and then connected to. The
// node sensor matches names against this catalog and keeps only the catalog
// token; a name that matches nothing is dropped on the node and never leaves
// it.

type egressHost struct {
	// match is an exact host, or a suffix when it starts with a dot.
	match    string
	token    string
	strength strength
}

// Model APIs are strong: a workload that calls one at run time uses a model,
// which is the same bar as holding a model provider credential. Tooling that
// agents and ordinary services both use is weak.
var egressHosts = []egressHost{
	{"api.openai.com", "openai", strong}, {".openai.azure.com", "azure_openai", strong}, {".services.ai.azure.com", "azure_openai", strong},
	{"api.anthropic.com", "anthropic", strong},
	{"generativelanguage.googleapis.com", "google", strong}, {"aiplatform.googleapis.com", "google", strong}, {"-aiplatform.googleapis.com", "google", strong},
	{"api.cohere.com", "cohere", strong}, {"api.cohere.ai", "cohere", strong}, {"api.mistral.ai", "mistral", strong}, {"api.groq.com", "groq", strong},
	{"api.together.xyz", "together", strong}, {"api.together.ai", "together", strong}, {"api.fireworks.ai", "fireworks", strong},
	{"api.perplexity.ai", "perplexity", strong}, {"api.deepseek.com", "deepseek", strong}, {"api.x.ai", "xai", strong},
	{"openrouter.ai", "openrouter", strong}, {"api.replicate.com", "replicate", strong},
	{"api-inference.huggingface.co", "huggingface", strong}, {"router.huggingface.co", "huggingface", strong},
	{"api.smith.langchain.com", "langchain", strong}, {"backend.composio.dev", "composio", strong},
	{"cloud.langfuse.com", "langfuse", weak}, {"api.tavily.com", "tavily", weak}, {"api.e2b.dev", "e2b", weak}, {"api.browserbase.com", "browserbase", weak},
}

// EgressHost classifies a DNS name. It returns the catalog token and true
// when the name is a model API, a remote MCP server or agent tooling.
func EgressHost(name string) (string, bool) {
	token, _, ok := classifyEgressHost(name)
	return token, ok
}

func classifyEgressHost(name string) (string, strength, bool) {
	host := strings.TrimSuffix(strings.ToLower(name), ".")
	if len(host) < 4 || len(host) > 253 {
		return "", 0, false
	}
	for _, candidate := range egressHosts {
		if host == candidate.match || (candidate.match[0] == '.' || candidate.match[0] == '-') && strings.HasSuffix(host, candidate.match) && len(host) > len(candidate.match) {
			return candidate.token, candidate.strength, true
		}
	}
	labels := strings.Split(host, ".")
	// Amazon Bedrock and AgentCore data planes: bedrock-runtime.<region>,
	// bedrock-agent-runtime.<region>, bedrock-agentcore.<region>.
	if strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".api.aws") {
		switch {
		case strings.HasPrefix(labels[0], "bedrock-agentcore"):
			return "agentcore", strong, true
		case strings.HasPrefix(labels[0], "bedrock-runtime"), strings.HasPrefix(labels[0], "bedrock-agent-runtime"):
			return "bedrock", strong, true
		}
		return "", 0, false
	}
	// Hosted MCP servers are published as mcp.<vendor domain>. Cluster-local
	// names are left to the static signals.
	if labels[0] == "mcp" && len(labels) >= 3 && labels[len(labels)-1] != "local" && labels[len(labels)-1] != "internal" {
		return "mcp_remote", strong, true
	}
	return "", 0, false
}

var egressTokens = func() map[string]strength {
	tokens := map[string]strength{"agentcore": strong, "bedrock": strong, "mcp_remote": strong}
	for _, candidate := range egressHosts {
		if tokens[candidate.token] < candidate.strength {
			tokens[candidate.token] = candidate.strength
		}
	}
	return tokens
}()

// Egress records runtime egress tokens the node sensor reported. A token
// outside the catalog is ignored, so a forged report cannot add a signal the
// product does not know.
func (evidence *Evidence) Egress(tokens ...string) {
	for _, token := range tokens {
		if value, ok := egressTokens[token]; ok {
			evidence.set().add("egress", token, value)
		}
	}
}

// The node sensor publishes one document per node in a ConfigMap carrying
// EgressObservationsLabel; the Kubernetes collector reads them with the
// credential it already holds.
const (
	EgressObservationsVersion    = "egress-observations-v1"
	EgressObservationsLabel      = "zasp.ai/egress-observations"
	EgressObservationsLabelValue = "v1"
	EgressObservationsKey        = "observations.json"
	// EgressObservationRetention is how long an observation counts after it
	// was last seen.
	EgressObservationRetention = 7 * 24 * time.Hour
	MaximumEgressWorkloads     = 2000
	MaximumEgressDocumentBytes = 512 << 10
	egressTimeLayout           = "2006-01-02T15:04:05Z"
)

type EgressObservations struct {
	Version     string           `json:"version"`
	Node        string           `json:"node"`
	GeneratedAt string           `json:"generated_at"`
	Workloads   []EgressWorkload `json:"workloads"`
}

// EgressWorkload names the owner the sensor's event source resolved for the
// pod: a Deployment, StatefulSet, DaemonSet, Job or CronJob.
type EgressWorkload struct {
	Namespace    string              `json:"namespace"`
	Kind         string              `json:"kind"`
	Name         string              `json:"name"`
	Destinations []EgressDestination `json:"destinations"`
}

type EgressDestination struct {
	Token    string `json:"token"`
	LastSeen string `json:"last_seen"`
}

var (
	egressNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	egressKinds       = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Job": true, "CronJob": true}
)

// FormatEgressTime renders the document's timestamp form.
func FormatEgressTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(egressTimeLayout)
}

func parseEgressTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(egressTimeLayout, value)
	return parsed, err == nil && parsed.Format(egressTimeLayout) == value
}

// ValidEgressWorkloadIdentity reports whether the sensor may record the
// workload: a known owner kind and Kubernetes-shaped names.
func ValidEgressWorkloadIdentity(namespace, kind, name string) bool {
	return egressKinds[kind] && len(namespace) <= 63 && egressNamePattern.MatchString(namespace) && egressNamePattern.MatchString(name)
}

// Normalize sorts the document into its one canonical order.
func (document *EgressObservations) Normalize() {
	for index := range document.Workloads {
		destinations := document.Workloads[index].Destinations
		sort.Slice(destinations, func(left, right int) bool { return destinations[left].Token < destinations[right].Token })
	}
	sort.Slice(document.Workloads, func(left, right int) bool {
		a, b := document.Workloads[left], document.Workloads[right]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
}

// ParseEgressObservations decodes and validates one document. Unknown
// fields, unknown tokens, unsorted or duplicate entries and oversized
// documents are refused: the document is written by the product's own
// sensor, so anything else is not that document.
func ParseEgressObservations(body []byte) (EgressObservations, bool) {
	if len(body) == 0 || len(body) > MaximumEgressDocumentBytes {
		return EgressObservations{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var document EgressObservations
	if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF {
		return EgressObservations{}, false
	}
	if document.Version != EgressObservationsVersion || !egressNamePattern.MatchString(document.Node) || len(document.Workloads) > MaximumEgressWorkloads {
		return EgressObservations{}, false
	}
	if _, ok := parseEgressTime(document.GeneratedAt); !ok {
		return EgressObservations{}, false
	}
	priorWorkload := ""
	for _, workload := range document.Workloads {
		key := workload.Namespace + "\x00" + workload.Kind + "\x00" + workload.Name
		if !ValidEgressWorkloadIdentity(workload.Namespace, workload.Kind, workload.Name) || priorWorkload != "" && key <= priorWorkload || len(workload.Destinations) == 0 || len(workload.Destinations) > len(egressTokens) {
			return EgressObservations{}, false
		}
		priorWorkload = key
		priorToken := ""
		for _, destination := range workload.Destinations {
			if _, known := egressTokens[destination.Token]; !known || destination.Token <= priorToken {
				return EgressObservations{}, false
			}
			if _, ok := parseEgressTime(destination.LastSeen); !ok {
				return EgressObservations{}, false
			}
			priorToken = destination.Token
		}
	}
	return document, true
}

// Current returns the tokens of one workload that were seen within the
// retention window ending at now.
func (workload EgressWorkload) Current(now time.Time) []string {
	var tokens []string
	for _, destination := range workload.Destinations {
		if seen, ok := parseEgressTime(destination.LastSeen); ok && !seen.Before(now.Add(-EgressObservationRetention)) && !seen.After(now.Add(time.Hour)) {
			tokens = append(tokens, destination.Token)
		}
	}
	return tokens
}

// Recorded invocations: API calls the provider's own audit log says a
// principal made. They are stronger than any declaration, so all are strong.
var invocationEvents = map[string]string{
	"invokemodel": "bedrock_model", "invokemodelwithresponsestream": "bedrock_model", "converse": "bedrock_model", "conversestream": "bedrock_model",
	"invokeagent": "bedrock_agent", "invokeinlineagent": "bedrock_agent", "invokeflow": "bedrock_agent",
	"invokeagentruntime": "agentcore",
}

// InvocationEventNames lists the audit event names Invoked understands, for
// a collector that has to ask for them by name.
func InvocationEventNames() []string {
	return []string{"Converse", "ConverseStream", "InvokeAgent", "InvokeAgentRuntime", "InvokeFlow", "InvokeInlineAgent", "InvokeModel", "InvokeModelWithResponseStream"}
}

// Invoked records model and agent invocations found in an audit log, by
// event name.
func (evidence *Evidence) Invoked(eventNames ...string) {
	for _, name := range eventNames {
		if token, ok := invocationEvents[strings.ToLower(name)]; ok {
			evidence.set().add("invoke", token, strong)
		}
	}
}

// AddSignals merges already-recorded catalog signals (class:token) into the
// evidence. Unknown classes are ignored. Used to join signals found by
// different readers of one subject.
func (evidence *Evidence) AddSignals(signals ...string) {
	for _, signal := range signals {
		class, token, ok := strings.Cut(signal, ":")
		if !ok {
			continue
		}
		switch class {
		case "egress":
			evidence.Egress(token)
		case "invoke":
			for _, known := range invocationEvents {
				if known == token {
					evidence.set().add("invoke", token, strong)
					break
				}
			}
		}
	}
}

// EgressHostPrefilter is a regular expression fragment (RE2 and CloudWatch
// Logs Insights syntax, no delimiters) that every catalog host name
// matches. A log reader uses it to ask the log service only for names that
// could be in the catalog; EgressHost still decides. It matches more than
// the catalog on purpose and must never be used as the classifier.
const EgressHostPrefilter = `openai|anthropic|bedrock-|googleapis|cohere|mistral|groq|together|fireworks|perplexity|deepseek|api\.x\.ai|openrouter|replicate|huggingface|langchain|composio|langfuse|tavily|e2b\.dev|browserbase|services\.ai\.azure|^mcp\.`
