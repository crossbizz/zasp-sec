package gcpdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/internal/providercollection"
)

// The services of one project. Each is one line of the integration's
// coverage: a project that refuses a service, or has its API switched off,
// is counted there and never fails the collection.
const (
	serviceResourceManager = iota
	serviceAgentEngine
	serviceEndpoints
	serviceConversationalAgents
	serviceGeminiEnterprise
	serviceCloudRun
	serviceCloudFunctions
	serviceIAM
	serviceModelArmor
	serviceAuditLogs
	serviceInheritedIAM
	gcpServiceCount
)

var gcpServices = [gcpServiceCount]struct{ key, name string }{
	{"resource-manager", "Projects (Resource Manager)"},
	{"agent-engine", "Vertex AI Agent Engine"},
	{"vertex-endpoints", "Vertex AI endpoints"},
	{"conversational-agents", "Conversational Agents (Dialogflow CX)"},
	{"gemini-enterprise", "Gemini Enterprise agents"},
	{"cloud-run", "Cloud Run"},
	{"cloud-functions", "Cloud Functions"},
	{"iam", "Service accounts and IAM policy"},
	{"model-armor", "Model Armor"},
	{"audit-logs", "Cloud Audit Logs (Vertex AI data access)"},
	{"iam-inherited", "Inherited IAM roles (folders and organization)"},
}

// Agent posture checks of this collector. Each is a finding rule the product
// explains (compliancemap, and the risk view of the web application).
const (
	// The service account an agent runs as holds an administrator-level
	// role on its project.
	AgentCheckServiceAccountAdmin = "agent_service_account_admin_role"
	// A Vertex AI agent runs in a project where Model Armor screens neither
	// Vertex AI (no floor setting) nor has a template in the agent's location.
	AgentCheckModelArmorMissing = "agent_model_armor_missing"
)

// Roles that let their holder change anything in a project or grant itself
// more. UNVERIFIED: the names are Google Cloud's basic and predefined roles
// as remembered, not checked against the published role list.
var gcpAdministratorRoles = map[string]bool{
	"roles/owner": true, "roles/editor": true, "roles/iam.securityAdmin": true, "roles/iam.serviceAccountAdmin": true,
	"roles/resourcemanager.projectIamAdmin": true, "roles/resourcemanager.folderAdmin": true, "roles/resourcemanager.organizationAdmin": true,
}

// The locations Model Armor serves, each at modelarmor.<location>.rep.googleapis.com.
// DOCUMENTED: the "endpoints" of https://modelarmor.googleapis.com/$discovery/rest?version=v1
var gcpModelArmorLocations = map[string]bool{
	"us-central1": true, "us-east1": true, "us-east7": true, "us-west1": true, "europe-west1": true, "europe-west4": true, "us-east4": true, "asia-southeast1": true,
	"europe-west2": true, "europe-west3": true, "asia-south1": true, "europe-southwest1": true, "asia-northeast1": true, "asia-northeast3": true,
	"australia-southeast1": true, "australia-southeast2": true, "northamerica-northeast1": true, "northamerica-northeast2": true, "europe-west9": true, "southamerica-east1": true,
}

var (
	gcpResourceSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	gcpServiceAccountPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}@[a-z0-9][a-z0-9.-]{3,200}\.gserviceaccount\.com$`)
	gcpRolePattern            = regexp.MustCompile(`^(roles|projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/roles|organizations/[0-9]{1,19}/roles)/[A-Za-z0-9_.]{1,128}$`)
	gcpFrameworkPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	gcpStatePattern           = regexp.MustCompile(`^[A-Z][A-Z_]{0,31}$`)
	gcpHostPattern            = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){1,8}$`)
)

type projectRead struct {
	entities, relationships, findings []json.RawMessage
	// outcomes is, per service, outcomeOK, outcomeDenied or outcomeDisabled.
	outcomes [gcpServiceCount]callOutcome
}

// serviceTally folds the outcomes of the calls of one service in one project.
type serviceTally struct {
	mutex                sync.Mutex
	ok, denied, disabled bool
}

func (tally *serviceTally) add(outcome callOutcome) {
	tally.mutex.Lock()
	defer tally.mutex.Unlock()
	switch outcome {
	case outcomeDenied:
		tally.denied = true
	case outcomeDisabled:
		tally.disabled = true
	default:
		tally.ok = true
	}
}

// result: a refusal anywhere is a gap; an API that is switched off and
// answered nowhere is unavailable; anything else was read.
func (tally *serviceTally) result() callOutcome {
	tally.mutex.Lock()
	defer tally.mutex.Unlock()
	switch {
	case tally.denied:
		return outcomeDenied
	case tally.disabled && !tally.ok:
		return outcomeDisabled
	default:
		return outcomeOK
	}
}

// gcpResource is a resource name with its project made the project id (an
// API may answer with the number) and its location cut out.
type gcpResource struct {
	Name, Location, ID string
}

// parseGCPResource accepts projects/<p>/locations/<l>/<collection>/<id>...
// whose last collection is want.
func parseGCPResource(name, projectID, want string) (gcpResource, bool) {
	parts := strings.Split(name, "/")
	if len(name) > 512 || len(parts) < 6 || len(parts)%2 != 0 || parts[0] != "projects" || parts[2] != "locations" || parts[len(parts)-2] != want || !gcpLocationPattern.MatchString(parts[3]) {
		return gcpResource{}, false
	}
	for _, part := range parts {
		if !gcpResourceSegmentPattern.MatchString(part) {
			return gcpResource{}, false
		}
	}
	parts[1] = projectID
	return gcpResource{Name: strings.Join(parts, "/"), Location: parts[3], ID: parts[len(parts)-1]}, true
}

type gcpAgentAttributes struct {
	Status         string                 `json:"status"`
	Posture        agentsignals.Posture   `json:"posture"`
	Discovery      agentsignals.Discovery `json:"discovery"`
	AgentFramework string                 `json:"agent_framework,omitempty"`
	IdentityType   string                 `json:"identity_type,omitempty"`
	ServiceAccount string                 `json:"service_account,omitempty"`
	LastInvokedAt  string                 `json:"last_invoked_at,omitempty"`
	ModelArmor     string                 `json:"model_armor,omitempty"`
}

// gcpInvocations is what the audit log shows: per service account, the
// newest model or agent invocation and its method names; per reasoning
// engine, the newest query.
type gcpInvocations struct {
	principals map[string]*gcpInvocation
	engines    map[string]time.Time
}

type gcpInvocation struct {
	last    time.Time
	methods []string
}

// gcpIdentities is the IAM reading of a project: its service accounts and
// the roles its policy binds each service account to.
type gcpIdentities struct {
	listed   bool
	accounts map[string]bool // email -> disabled
	roles    map[string][]string
}

type gcpWorkload struct {
	resource       gcpResource
	resourceType   string
	display        string
	serviceAccount string
	evidence       agentsignals.Evidence
	untrustedInput bool
	active         bool
	// mcpServer: the Cloud Run service is an MCP server, by its own
	// functional type or by its image or command. endpointHost is the host
	// of its URL and openInvoker whether the IAM invoker check is off.
	mcpServer    bool
	endpointHost string
	openInvoker  bool
}

// gcpAncestor is what one folder or organization above a project answered.
type gcpAncestor struct {
	parent  string
	outcome callOutcome
	roles   map[string][]string
	readAt  time.Time
}

// gcpTool is a tool a Conversational Agents agent declares.
type gcpTool struct {
	resource gcpResource
	display  string
}

// readProject reads everything the collector knows how to read in one
// project. Only a failure that must fail the page is returned.
// readProjectIdentities is the identities pass of one project: every service
// account the project lists, with the roles the IAM policies of the project
// and of the folders and organization above it bind it to. The accounts are
// contained in the scope, not in the project, so that they stand whatever
// the later pass finds of the project.
func (api *GCPCollectionAPI) readProjectIdentities(ctx context.Context, token []byte, subject collection.SubjectBinding, scopeEntityID string, project gcpProject) (projectRead, []string, error) {
	var read projectRead
	var tallies [gcpServiceCount]serviceTally
	identities, err := api.projectIdentities(ctx, token, project, &tallies[serviceIAM], &tallies[serviceInheritedIAM])
	if err != nil {
		return projectRead{}, nil, err
	}
	emails := make([]string, 0, len(identities.accounts))
	for email := range identities.accounts {
		emails = append(emails, email)
	}
	sort.Strings(emails)
	ids := make([]string, 0, len(emails))
	for _, email := range emails {
		attributes := map[string]any{"status": map[bool]string{false: "ACTIVE", true: "DISABLED"}[identities.accounts[email]]}
		if roles := identities.roles[email]; len(roles) > 0 {
			attributes["roles"] = joinGCPRoles(roles)
			if admin := administratorRoles(roles); len(admin) > 0 {
				attributes["admin_roles"] = joinGCPRoles(admin)
			}
		}
		native := "gcp:service_account:" + email
		id := gcpInventoryID(subject, "gcp_service_account", native)
		entity, ok := gcpEntity(id, "gcp_service_account", native, email, map[string]any{"name": email, "object_type": "service_account", "project": project.ID, "scope": subject.ID}, attributes)
		if !ok {
			return projectRead{}, nil, providercollection.StableProviderFailure(collection.FailureMalformed)
		}
		read.entities = append(read.entities, entity)
		read.relationships = append(read.relationships, gcpRelationship(subject, "contains", "scope_object", "gcp:scope:"+subject.ID, native, scopeEntityID, id))
		ids = append(ids, id)
	}
	read.outcomes[serviceIAM], read.outcomes[serviceInheritedIAM] = tallies[serviceIAM].result(), tallies[serviceInheritedIAM].result()
	return read, ids, nil
}

// projectIdentities reads the service accounts of a project and the roles
// its own IAM policy and the policies above it bind service accounts to.
func (api *GCPCollectionAPI) projectIdentities(ctx context.Context, token []byte, project gcpProject, iam, inheritedIAM *serviceTally) (gcpIdentities, error) {
	var identities gcpIdentities
	var inherited map[string][]string
	readers := []func(context.Context) error{
		func(ctx context.Context) (err error) {
			identities, err = api.readIdentities(ctx, token, project, iam)
			return
		},
		func(ctx context.Context) (err error) {
			inherited, err = api.readInheritedRoles(ctx, token, project, inheritedIAM)
			return
		},
	}
	if err := fanOut(ctx, len(readers), func(ctx context.Context, index int) error { return readers[index](ctx) }); err != nil {
		return gcpIdentities{}, err
	}
	// A role bound on a folder or the organization above the project holds
	// in the project too: it joins the roles of the project's own policy.
	for email, roles := range inherited {
		identities.roles[email] = sortedUniqueStrings(append(identities.roles[email], roles...))
	}
	return identities, nil
}

// readProject is the second pass of one project: the project itself and
// everything in it but its service accounts. known reports whether the
// identities pass of this collection emitted a service account entity.
func (api *GCPCollectionAPI) readProject(ctx context.Context, token []byte, subject collection.SubjectBinding, scopeEntityID string, project gcpProject, known func(string) bool) (projectRead, error) {
	var read projectRead
	var tallies [gcpServiceCount]serviceTally
	tallies[serviceResourceManager].add(outcomeOK)
	observedAt := api.clock()
	projectNative := "gcp:project:" + project.ID
	projectEntityID := gcpInventoryID(subject, "gcp_project", projectNative)
	malformed := providercollection.StableProviderFailure(collection.FailureMalformed)
	emit := func(kind, native, display string, stable, attributes any, parentID, parentNative string) (string, bool) {
		id := gcpInventoryID(subject, kind, native)
		entity, ok := gcpEntity(id, kind, native, display, stable, attributes)
		if !ok {
			return "", false
		}
		read.entities = append(read.entities, entity)
		read.relationships = append(read.relationships, gcpRelationship(subject, "contains", "project_object", parentNative, native, parentID, id))
		return id, true
	}
	projectEntity, ok := gcpEntity(projectEntityID, "gcp_project", projectNative, project.DisplayName, map[string]any{"name": project.DisplayName, "project": project.ID, "project_number": project.Number, "scope": subject.ID}, map[string]any{"status": "ACTIVE"})
	if !ok {
		return projectRead{}, malformed
	}
	read.entities = append(read.entities, projectEntity)
	read.relationships = append(read.relationships, gcpRelationship(subject, "contains", "scope_project", "gcp:scope:"+subject.ID, projectNative, scopeEntityID, projectEntityID))

	// The independent readers of the project run side by side.
	var (
		identities  gcpIdentities
		invocations gcpInvocations
		engines     []gcpEngine
		endpoints   []gcpEndpoint
		dialogflow  []gcpListedAgent
		gemini      []gcpListedAgent
		functions   []gcpWorkload
		services    []gcpWorkload
	)
	readers := []func(context.Context) error{
		func(ctx context.Context) (err error) {
			// The roles are needed again for signals and findings; the
			// coverage of this read was counted by the identities pass.
			identities, err = api.projectIdentities(ctx, token, project, &tallies[serviceIAM], &tallies[serviceInheritedIAM])
			return
		},
		func(ctx context.Context) (err error) {
			invocations, err = api.readInvocations(ctx, token, project, &tallies[serviceAuditLogs])
			return
		},
		func(ctx context.Context) (err error) {
			engines, endpoints, err = api.readVertex(ctx, token, project, &tallies[serviceAgentEngine], &tallies[serviceEndpoints])
			return
		},
		func(ctx context.Context) (err error) {
			dialogflow, err = api.readDialogflow(ctx, token, project, &tallies[serviceConversationalAgents])
			return
		},
		func(ctx context.Context) (err error) {
			gemini, err = api.readGeminiEnterprise(ctx, token, project, &tallies[serviceGeminiEnterprise])
			return
		},
		func(ctx context.Context) (err error) {
			functions, err = api.readFunctions(ctx, token, project, &tallies[serviceCloudFunctions])
			return
		},
		func(ctx context.Context) (err error) {
			services, err = api.readRunServices(ctx, token, project, &tallies[serviceCloudRun])
			return
		},
	}
	if err := fanOut(ctx, len(readers), func(ctx context.Context, index int) error { return readers[index](ctx) }); err != nil {
		return projectRead{}, err
	}
	// Model Armor is asked only about the locations that host an agent.
	engineLocations := map[string]bool{}
	for _, engine := range engines {
		engineLocations[engine.resource.Location] = true
	}
	modelArmor, err := api.readModelArmor(ctx, token, project, engineLocations, &tallies[serviceModelArmor])
	if err != nil {
		return projectRead{}, err
	}

	// A service account is an identity the identities pass of this
	// collection emitted. A workload refers to it only when that is known:
	// a relationship to an identity no page emitted fails the whole
	// collection (TestCollectionRejectsADanglingIdentityRelationship).
	accountEntity := func(email string) (string, error) {
		if email == "" {
			return "", nil
		}
		if id := gcpInventoryID(subject, "gcp_service_account", "gcp:service_account:"+email); known(id) {
			return id, nil
		}
		return "", nil
	}
	var accountFailure error
	usedAccounts := map[string]bool{}
	// agent emits one agent entity with what is known about its identity.
	agent := func(kind, native, display string, stable map[string]any, attributes gcpAgentAttributes, serviceAccount string) (string, bool) {
		if serviceAccount != "" {
			attributes.ServiceAccount = serviceAccount
			usedAccounts[serviceAccount] = true
			if invoked, found := invocations.principals[serviceAccount]; found && attributes.LastInvokedAt == "" {
				attributes.LastInvokedAt = invoked.last.UTC().Format("2006-01-02T15:00:00Z")
			}
		}
		stable["project"], stable["scope"] = project.ID, subject.ID
		id, emitted := emit(kind, native, display, stable, attributes, projectEntityID, projectNative)
		if !emitted {
			return "", false
		}
		if kind == "gcp_agent_engine" || kind == "gcp_inferred_agent" {
			accountID, err := accountEntity(serviceAccount)
			if err != nil {
				accountFailure = err
				return "", false
			}
			if accountID != "" {
				read.relationships = append(read.relationships, gcpRelationship(subject, "uses_identity", "service_account", native, "gcp:service_account:"+serviceAccount, id, accountID))
			}
		}
		if len(administratorRoles(identities.roles[serviceAccount])) > 0 {
			read.findings = append(read.findings, gcpFinding(subject, id, native, AgentCheckServiceAccountAdmin, observedAt))
		}
		if attributes.ModelArmor == "none" {
			read.findings = append(read.findings, gcpFinding(subject, id, native, AgentCheckModelArmorMissing, observedAt))
		}
		return id, true
	}
	// refused is the failure of an emission: a provider failure met while
	// looking up a service account, or else a malformed object.
	refused := func() error {
		if accountFailure != nil {
			return accountFailure
		}
		return malformed
	}

	for _, engine := range engines {
		attributes := gcpAgentAttributes{Status: "ACTIVE", Posture: agentsignals.Posture{CredentialActive: true}, Discovery: agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "vertex_ai_agent_engine", nil),
			AgentFramework: engine.framework, IdentityType: engine.identityType, ModelArmor: modelArmor.verdict(engine.resource.Location)}
		if queried, found := invocations.engines[engine.resource.Name]; found {
			attributes.LastInvokedAt = queried.UTC().Format("2006-01-02T15:00:00Z")
		}
		if _, ok := agent("gcp_agent_engine", "gcp:"+engine.resource.Name, engine.display, map[string]any{"location": engine.resource.Location, "name": engine.display, "object_type": "reasoning_engine"}, attributes, engine.serviceAccount); !ok {
			return projectRead{}, refused()
		}
	}
	for _, listed := range dialogflow {
		attributes := gcpAgentAttributes{Status: "ACTIVE", Posture: agentsignals.Posture{CredentialActive: true}, Discovery: agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "conversational_agents", nil)}
		agentNative := "gcp:" + listed.resource.Name
		agentID, ok := agent("gcp_conversational_agent", agentNative, listed.display, map[string]any{"location": listed.resource.Location, "name": listed.display, "object_type": "dialogflow_cx_agent"}, attributes, "")
		if !ok {
			return projectRead{}, refused()
		}
		// The tools the agent declares. Only a tool's name is kept; its
		// risk class is read off the words of that name.
		for _, tool := range listed.tools {
			toolNative := "gcp:" + tool.resource.Name
			toolID := gcpInventoryID(subject, "gcp_agent_tool", toolNative)
			entity, entityOK := gcpEntity(toolID, "gcp_agent_tool", toolNative, tool.display, map[string]any{"agent": listed.display, "location": tool.resource.Location, "name": tool.display, "object_type": "dialogflow_cx_tool", "project": project.ID, "scope": subject.ID}, map[string]any{"risk": agentsignals.MCPToolRisk(tool.display)})
			if !entityOK {
				return projectRead{}, malformed
			}
			read.entities = append(read.entities, entity)
			read.relationships = append(read.relationships, gcpRelationship(subject, "contains", "agent_tool", agentNative, toolNative, agentID, toolID))
		}
	}
	for _, listed := range gemini {
		attributes := gcpAgentAttributes{Status: listed.state, Posture: agentsignals.Posture{CredentialActive: listed.active}, Discovery: agentsignals.NewDiscovery(agentsignals.MethodProviderAPI, "gemini_enterprise", nil)}
		if _, ok := agent("gcp_gemini_enterprise_agent", "gcp:"+listed.resource.Name, listed.display, map[string]any{"location": listed.resource.Location, "name": listed.display, "object_type": "gemini_enterprise_agent"}, attributes, ""); !ok {
			return projectRead{}, refused()
		}
	}
	for _, endpoint := range endpoints {
		native := "gcp:" + endpoint.resource.Name
		endpointID, emitted := emit("gcp_model_endpoint", native, endpoint.display, map[string]any{"location": endpoint.resource.Location, "name": endpoint.display, "object_type": "vertex_ai_endpoint", "project": project.ID, "scope": subject.ID}, map[string]any{"status": "ACTIVE"}, projectEntityID, projectNative)
		if !emitted {
			return projectRead{}, malformed
		}
		for _, model := range endpoint.models {
			attributes := map[string]any{"status": "ACTIVE"}
			for key, value := range map[string]string{"model": model.model, "model_version": model.version, "service_account": model.serviceAccount} {
				if value != "" {
					attributes[key] = value
				}
			}
			modelNative := native + "/deployedModels/" + model.id
			modelDisplay := endpoint.display + "/" + model.display
			if len(modelDisplay) > 256 {
				modelDisplay = model.display
			}
			modelID, modelEmitted := emit("gcp_deployed_model", modelNative, modelDisplay, map[string]any{"endpoint": endpoint.display, "location": endpoint.resource.Location, "name": model.display, "object_type": "deployed_model", "project": project.ID, "scope": subject.ID}, attributes, endpointID, native)
			if !modelEmitted {
				return projectRead{}, malformed
			}
			accountID, err := accountEntity(model.serviceAccount)
			if err != nil {
				return projectRead{}, err
			}
			if accountID != "" {
				read.relationships = append(read.relationships, gcpRelationship(subject, "uses_identity", "service_account", modelNative, "gcp:service_account:"+model.serviceAccount, modelID, accountID))
			}
		}
	}
	// A second-generation function is also a Cloud Run service; it is listed
	// once, as the function.
	functionServices := map[string]bool{}
	for _, function := range functions {
		if function.resourceType == "" {
			functionServices[function.resource.Name] = true
		}
	}
	workloads := make([]gcpWorkload, 0, len(functions)+len(services))
	for _, function := range functions {
		if function.resourceType != "" {
			workloads = append(workloads, function)
		}
	}
	for _, service := range services {
		if !functionServices[service.resource.Name] {
			workloads = append(workloads, service)
		}
	}
	for _, workload := range workloads {
		if workload.mcpServer {
			// A Cloud Run service that is an MCP server is a tool of the
			// inventory, not an agent. Its identity in the MCP registry is
			// the host of its URL.
			attributes := map[string]any{"status": "ACTIVE", "source": "workload", "transport": agentsignals.MCPTransportHTTP, "auth": agentsignals.MCPAuthDeclared}
			if workload.openInvoker {
				attributes["auth"] = agentsignals.MCPAuthNone
			}
			if workload.endpointHost != "" {
				attributes["endpoint_host"] = workload.endpointHost
			}
			if _, emitted := emit("gcp_mcp_server", "gcp:"+workload.resource.Name+":mcp_server", workload.display, map[string]any{"location": workload.resource.Location, "name": workload.display, "object_type": "cloud_run_service", "project": project.ID, "scope": subject.ID}, attributes, projectEntityID, projectNative); !emitted {
				return projectRead{}, malformed
			}
			continue
		}
		if workload.serviceAccount == "" {
			// Without a service account of its own a Cloud Run service or
			// function runs as the Compute Engine default service account.
			// UNVERIFIED: the default's address is from memory.
			workload.serviceAccount = project.Number + "-compute@developer.gserviceaccount.com"
		}
		workload.evidence.GCPRoles(identities.roles[workload.serviceAccount]...)
		if invoked, found := invocations.principals[workload.serviceAccount]; found {
			workload.evidence.GCPInvoked(invoked.methods...)
		}
		if !workload.evidence.IsAgent() {
			continue
		}
		status := "ACTIVE"
		if !workload.active {
			status = "INACTIVE"
		}
		attributes := gcpAgentAttributes{Status: status, Posture: agentsignals.Posture{CredentialActive: workload.active, UntrustedInput: workload.untrustedInput}, Discovery: agentsignals.NewDiscovery(agentsignals.MethodInferred, workload.resourceType, workload.evidence.Signals())}
		if _, ok := agent("gcp_inferred_agent", "gcp:"+workload.resource.Name, workload.display, map[string]any{"location": workload.resource.Location, "name": workload.display, "object_type": workload.resourceType, "resource_type": workload.resourceType}, attributes, workload.serviceAccount); !ok {
			return projectRead{}, refused()
		}
	}
	// A service account the audit log shows invoking a model, and that runs
	// nothing listed above, is itself the inferred agent.
	principals := make([]string, 0, len(invocations.principals))
	for principal := range invocations.principals {
		if !usedAccounts[principal] {
			principals = append(principals, principal)
		}
	}
	sort.Strings(principals)
	for _, principal := range principals {
		var evidence agentsignals.Evidence
		evidence.GCPInvoked(invocations.principals[principal].methods...)
		evidence.GCPRoles(identities.roles[principal]...)
		if !evidence.IsAgent() {
			continue
		}
		attributes := gcpAgentAttributes{Status: "ACTIVE", Posture: agentsignals.Posture{CredentialActive: true}, Discovery: agentsignals.NewDiscovery(agentsignals.MethodInferred, "service_account", evidence.Signals())}
		if _, ok := agent("gcp_inferred_agent", "gcp:projects/"+project.ID+"/invokers/"+principal, principal, map[string]any{"location": "global", "name": principal, "object_type": "service_account", "resource_type": "service_account"}, attributes, principal); !ok {
			return projectRead{}, refused()
		}
	}
	for service := range tallies {
		read.outcomes[service] = tallies[service].result()
	}
	return read, nil
}

func administratorRoles(roles []string) []string {
	var result []string
	for _, role := range roles {
		if gcpAdministratorRoles[role] {
			result = append(result, role)
		}
	}
	return result
}

// joinGCPRoles writes at most 24 role names, comma-separated.
func joinGCPRoles(roles []string) string {
	if len(roles) > 24 {
		roles = roles[:24]
	}
	return strings.Join(roles, ",")
}

// readIdentities lists the project's service accounts and reads its IAM
// policy. The policy names the roles bound on the project itself; roles
// inherited from a folder or the organization are not in it.
func (api *GCPCollectionAPI) readIdentities(ctx context.Context, token []byte, project gcpProject, tally *serviceTally) (gcpIdentities, error) {
	identities := gcpIdentities{accounts: map[string]bool{}, roles: map[string][]string{}}
	outcome, err := api.list(ctx, token, gcpIAMHost, "/v1/projects/"+project.ID+"/serviceAccounts", url.Values{"pageSize": {"100"}}, "accounts", 20, func(raw json.RawMessage) {
		var account struct {
			Email    string `json:"email"`
			Disabled bool   `json:"disabled"`
		}
		if json.Unmarshal(raw, &account) == nil && gcpServiceAccountPattern.MatchString(account.Email) {
			identities.accounts[account.Email] = account.Disabled
		}
	})
	if err != nil {
		return gcpIdentities{}, err
	}
	tally.add(outcome)
	identities.listed = outcome == outcomeOK
	var policy struct {
		Bindings []gcpBinding `json:"bindings"`
	}
	outcome, err = api.call(ctx, token, http.MethodPost, gcpResourceManagerHost, "/v3/projects/"+project.ID+":getIamPolicy", "", []byte(`{"options":{"requestedPolicyVersion":3}}`), &policy)
	if err != nil {
		return gcpIdentities{}, err
	}
	tally.add(outcome)
	if outcome != outcomeOK {
		return identities, nil
	}
	// Only service accounts are kept; a person is never recorded.
	identities.roles = serviceAccountRoles(policy.Bindings)
	return identities, nil
}

// readInvocations reads a bounded slice of the project's data access audit
// log for Vertex AI: the newest entries of the last seven days, at most five
// pages of 200. Of an entry only the time, the method name, the resource
// name and the calling service account are read; request and response
// payloads are never decoded. The log exists only where the customer
// enabled data access audit logs for aiplatform.googleapis.com.
//
// UNVERIFIED: the log name (cloudaudit.googleapis.com%2Fdata_access) and the
// method names Vertex AI writes are from memory; the members of an entry are
// documented (audit_log.proto).
func (api *GCPCollectionAPI) readInvocations(ctx context.Context, token []byte, project gcpProject, tally *serviceTally) (gcpInvocations, error) {
	invocations := gcpInvocations{principals: map[string]*gcpInvocation{}, engines: map[string]time.Time{}}
	since := api.clock().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	filter := `logName="projects/` + project.ID + `/logs/cloudaudit.googleapis.com%2Fdata_access" AND protoPayload.serviceName="aiplatform.googleapis.com" AND timestamp>="` + since + `"`
	continuation := ""
	for page := 0; page < 5; page++ {
		request := map[string]any{"resourceNames": []string{"projects/" + project.ID}, "filter": filter, "orderBy": "timestamp desc", "pageSize": 200}
		if continuation != "" {
			request["pageToken"] = continuation
		}
		body, _ := json.Marshal(request)
		var listed struct {
			Entries []struct {
				Timestamp    string `json:"timestamp"`
				ProtoPayload struct {
					MethodName         string `json:"methodName"`
					ResourceName       string `json:"resourceName"`
					AuthenticationInfo struct {
						PrincipalEmail string `json:"principalEmail"`
					} `json:"authenticationInfo"`
				} `json:"protoPayload"`
			} `json:"entries"`
			NextPageToken string `json:"nextPageToken"`
		}
		outcome, err := api.call(ctx, token, http.MethodPost, gcpLoggingHost, "/v2/entries:list", "", body, &listed)
		if err != nil {
			return gcpInvocations{}, err
		}
		if outcome != outcomeOK {
			if page == 0 {
				tally.add(outcome)
			}
			return invocations, nil
		}
		tally.add(outcomeOK)
		for _, entry := range listed.Entries {
			at, timeErr := time.Parse(time.RFC3339, entry.Timestamp)
			if timeErr != nil || agentsignals.GCPInvocationToken(entry.ProtoPayload.MethodName) == "" {
				continue
			}
			if principal := strings.ToLower(entry.ProtoPayload.AuthenticationInfo.PrincipalEmail); gcpServiceAccountPattern.MatchString(principal) {
				invocation := invocations.principals[principal]
				if invocation == nil {
					invocation = &gcpInvocation{}
					invocations.principals[principal] = invocation
				}
				if at.After(invocation.last) {
					invocation.last = at
				}
				if len(invocation.methods) < 32 {
					invocation.methods = append(invocation.methods, entry.ProtoPayload.MethodName)
				}
			}
			if engine, isEngine := parseGCPResource(entry.ProtoPayload.ResourceName, project.ID, "reasoningEngines"); isEngine && at.After(invocations.engines[engine.Name]) {
				invocations.engines[engine.Name] = at
			}
		}
		if listed.NextPageToken == "" || listed.NextPageToken == continuation || len(listed.NextPageToken) > 4096 {
			break
		}
		continuation = listed.NextPageToken
	}
	return invocations, nil
}

// locations lists the locations a regional API serves in the project.
func (api *GCPCollectionAPI) locations(ctx context.Context, token []byte, host, path string) ([]string, callOutcome, error) {
	var locations []string
	outcome, err := api.list(ctx, token, host, path, url.Values{"pageSize": {"200"}}, "locations", 3, func(raw json.RawMessage) {
		var location struct {
			LocationID string `json:"locationId"`
		}
		if json.Unmarshal(raw, &location) == nil && gcpLocationPattern.MatchString(location.LocationID) && len(locations) < gcpMaximumLocations {
			locations = append(locations, location.LocationID)
		}
	})
	sort.Strings(locations)
	return locations, outcome, err
}

type gcpEngine struct {
	resource                                         gcpResource
	display, framework, identityType, serviceAccount string
}

type gcpEndpoint struct {
	resource gcpResource
	display  string
	models   []gcpDeployedModel
}

type gcpDeployedModel struct {
	id, display, model, version, serviceAccount string
}

type gcpListedAgent struct {
	resource       gcpResource
	display, state string
	active         bool
	tools          []gcpTool
}

func gcpDisplay(displayName, fallback string) string {
	if validGCPText(displayName, 256) {
		return displayName
	}
	return fallback
}

func gcpServiceAccountOrEmpty(value string) string {
	if value = strings.ToLower(value); gcpServiceAccountPattern.MatchString(value) {
		return value
	}
	return ""
}

// readVertex lists the reasoning engines and the endpoints of every Vertex
// AI location of the project. A reasoning engine's environment variables are
// not read at all: Agent Engine is an agent by the provider's own record.
func (api *GCPCollectionAPI) readVertex(ctx context.Context, token []byte, project gcpProject, engineTally, endpointTally *serviceTally) ([]gcpEngine, []gcpEndpoint, error) {
	locations, outcome, err := api.locations(ctx, token, gcpAIPlatformHost, "/v1/projects/"+project.ID+"/locations")
	if err != nil {
		return nil, nil, err
	}
	if outcome != outcomeOK {
		engineTally.add(outcome)
		endpointTally.add(outcome)
		return nil, nil, nil
	}
	regional := locations[:0]
	for _, location := range locations {
		// global and the multi-regions have no regional host of this form.
		if strings.Contains(location, "-") {
			regional = append(regional, location)
		}
	}
	var mutex sync.Mutex
	var engines []gcpEngine
	var endpoints []gcpEndpoint
	err = fanOut(ctx, len(regional)*2, func(ctx context.Context, index int) error {
		location := regional[index/2]
		host, parent := location+"-"+gcpAIPlatformHost, "/v1/projects/"+project.ID+"/locations/"+location
		if index%2 == 0 {
			outcome, err := api.list(ctx, token, host, parent+"/reasoningEngines", url.Values{"pageSize": {"100"}}, "reasoningEngines", 10, func(raw json.RawMessage) {
				var engine struct {
					Name        string `json:"name"`
					DisplayName string `json:"displayName"`
					Spec        struct {
						AgentFramework    string `json:"agentFramework"`
						ServiceAccount    string `json:"serviceAccount"`
						EffectiveIdentity string `json:"effectiveIdentity"`
						IdentityType      string `json:"identityType"`
					} `json:"spec"`
				}
				var resource gcpResource
				ok := false
				if json.Unmarshal(raw, &engine) == nil {
					resource, ok = parseGCPResource(engine.Name, project.ID, "reasoningEngines")
				}
				if !ok {
					return
				}
				item := gcpEngine{resource: resource, display: gcpDisplay(engine.DisplayName, resource.ID), serviceAccount: gcpServiceAccountOrEmpty(engine.Spec.ServiceAccount)}
				if item.serviceAccount == "" {
					item.serviceAccount = gcpServiceAccountOrEmpty(engine.Spec.EffectiveIdentity)
				}
				if framework := strings.ToLower(engine.Spec.AgentFramework); gcpFrameworkPattern.MatchString(framework) {
					item.framework = framework
				}
				switch engine.Spec.IdentityType {
				case "SERVICE_ACCOUNT", "AGENT_IDENTITY":
					item.identityType = strings.ToLower(engine.Spec.IdentityType)
				}
				mutex.Lock()
				engines = append(engines, item)
				mutex.Unlock()
			})
			engineTally.add(outcome)
			return err
		}
		outcome, err := api.list(ctx, token, host, parent+"/endpoints", url.Values{"pageSize": {"100"}}, "endpoints", 10, func(raw json.RawMessage) {
			var endpoint struct {
				Name           string `json:"name"`
				DisplayName    string `json:"displayName"`
				DeployedModels []struct {
					ID             string `json:"id"`
					Model          string `json:"model"`
					ModelVersionID string `json:"modelVersionId"`
					DisplayName    string `json:"displayName"`
					ServiceAccount string `json:"serviceAccount"`
				} `json:"deployedModels"`
			}
			var resource gcpResource
			ok := false
			if json.Unmarshal(raw, &endpoint) == nil {
				resource, ok = parseGCPResource(endpoint.Name, project.ID, "endpoints")
			}
			if !ok {
				return
			}
			item := gcpEndpoint{resource: resource, display: gcpDisplay(endpoint.DisplayName, resource.ID)}
			seen := map[string]bool{}
			for _, model := range endpoint.DeployedModels {
				if !gcpResourceSegmentPattern.MatchString(model.ID) || seen[model.ID] || len(item.models) >= 64 {
					continue
				}
				seen[model.ID] = true
				deployed := gcpDeployedModel{id: model.ID, display: gcpDisplay(model.DisplayName, model.ID), serviceAccount: gcpServiceAccountOrEmpty(model.ServiceAccount)}
				if validGCPText(model.Model, 512) {
					deployed.model = model.Model
				}
				if validGCPText(model.ModelVersionID, 64) {
					deployed.version = model.ModelVersionID
				}
				item.models = append(item.models, deployed)
			}
			mutex.Lock()
			endpoints = append(endpoints, item)
			mutex.Unlock()
		})
		endpointTally.add(outcome)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if len(regional) == 0 {
		engineTally.add(outcomeOK)
		endpointTally.add(outcomeOK)
	}
	sort.Slice(engines, func(left, right int) bool { return engines[left].resource.Name < engines[right].resource.Name })
	sort.Slice(endpoints, func(left, right int) bool { return endpoints[left].resource.Name < endpoints[right].resource.Name })
	return uniqueGCPEngines(engines), uniqueGCPEndpoints(endpoints), nil
}

func uniqueGCPEngines(values []gcpEngine) []gcpEngine {
	result := values[:0]
	for index, value := range values {
		if index == 0 || value.resource.Name != values[index-1].resource.Name {
			result = append(result, value)
		}
	}
	return result
}

func uniqueGCPEndpoints(values []gcpEndpoint) []gcpEndpoint {
	result := values[:0]
	for index, value := range values {
		if index == 0 || value.resource.Name != values[index-1].resource.Name {
			result = append(result, value)
		}
	}
	return result
}

func uniqueGCPAgents(values []gcpListedAgent) []gcpListedAgent {
	sort.Slice(values, func(left, right int) bool { return values[left].resource.Name < values[right].resource.Name })
	result := values[:0]
	for index, value := range values {
		if index == 0 || value.resource.Name != values[index-1].resource.Name {
			result = append(result, value)
		}
	}
	return result
}

// readDialogflow lists the Conversational Agents (Dialogflow CX) agents of
// every location of the project.
//
// UNVERIFIED: the host of a regional location, <location>-dialogflow.googleapis.com,
// is from memory; the discovery document names only the global host.
func (api *GCPCollectionAPI) readDialogflow(ctx context.Context, token []byte, project gcpProject, tally *serviceTally) ([]gcpListedAgent, error) {
	locations, outcome, err := api.locations(ctx, token, gcpDialogflowHost, "/v3/projects/"+project.ID+"/locations")
	if err != nil {
		return nil, err
	}
	tally.add(outcome)
	if outcome != outcomeOK {
		return nil, nil
	}
	var mutex sync.Mutex
	var agents []gcpListedAgent
	err = fanOut(ctx, len(locations), func(ctx context.Context, index int) error {
		location := locations[index]
		host := location + "-" + gcpDialogflowHost
		if location == "global" {
			host = gcpDialogflowHost
		}
		outcome, err := api.list(ctx, token, host, "/v3/projects/"+project.ID+"/locations/"+location+"/agents", url.Values{"pageSize": {"100"}}, "agents", 10, func(raw json.RawMessage) {
			var agent struct {
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			}
			if json.Unmarshal(raw, &agent) != nil {
				return
			}
			if resource, ok := parseGCPResource(agent.Name, project.ID, "agents"); ok {
				mutex.Lock()
				agents = append(agents, gcpListedAgent{resource: resource, display: gcpDisplay(agent.DisplayName, resource.ID), state: "ACTIVE", active: true})
				mutex.Unlock()
			}
		})
		tally.add(outcome)
		return err
	})
	if err != nil {
		return nil, err
	}
	agents = uniqueGCPAgents(agents)
	// The tools each agent declares (at most 100 agents, 200 tools each).
	listed := min(len(agents), 100)
	err = fanOut(ctx, listed, func(ctx context.Context, index int) error {
		resource := agents[index].resource
		host := resource.Location + "-" + gcpDialogflowHost
		if resource.Location == "global" {
			host = gcpDialogflowHost
		}
		var tools []gcpTool
		outcome, err := api.list(ctx, token, host, "/v3/"+resource.Name+"/tools", url.Values{"pageSize": {"100"}}, "tools", 2, func(raw json.RawMessage) {
			var tool struct {
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			}
			if json.Unmarshal(raw, &tool) != nil {
				return
			}
			if toolResource, ok := parseGCPResource(tool.Name, project.ID, "tools"); ok {
				tools = append(tools, gcpTool{resource: toolResource, display: gcpDisplay(tool.DisplayName, toolResource.ID)})
			}
		})
		tally.add(outcome)
		sort.Slice(tools, func(left, right int) bool { return tools[left].resource.Name < tools[right].resource.Name })
		unique := tools[:0]
		for position, tool := range tools {
			if position == 0 || tool.resource.Name != tools[position-1].resource.Name {
				unique = append(unique, tool)
			}
		}
		agents[index].tools = unique
		return err
	})
	return agents, err
}

func sortedUniqueStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for index, value := range values {
		if index == 0 || value != values[index-1] {
			result = append(result, value)
		}
	}
	return result
}

// serviceAccountRoles returns, per service account, the roles the bindings
// of an IAM policy give it. Only service accounts are kept.
func serviceAccountRoles(bindings []gcpBinding) map[string][]string {
	roles := map[string][]string{}
	for _, binding := range bindings {
		if !gcpRolePattern.MatchString(binding.Role) {
			continue
		}
		for _, member := range binding.Members {
			if email, isServiceAccount := strings.CutPrefix(member, "serviceAccount:"); isServiceAccount && gcpServiceAccountPattern.MatchString(email) {
				roles[email] = append(roles[email], binding.Role)
			}
		}
	}
	for email := range roles {
		roles[email] = sortedUniqueStrings(roles[email])
	}
	return roles
}

type gcpBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// readInheritedRoles reads the IAM policies of the folders and the
// organization above the project, up to twelve levels, and returns the roles
// they bind service accounts to. Those roles hold in the project as well. An
// ancestor the service account may not read ends the walk and is a coverage
// gap: the roles bound there, and above it, are then not known.
func (api *GCPCollectionAPI) readInheritedRoles(ctx context.Context, token []byte, project gcpProject, tally *serviceTally) (map[string][]string, error) {
	roles := map[string][]string{}
	digest := sha256.Sum256(token)
	parent := project.Parent
	if parent == "" {
		tally.add(outcomeOK)
	}
	for hop := 0; hop < gcpMaximumFolderHops && parent != ""; hop++ {
		key := string(digest[:16]) + "\x1f" + parent
		api.inheritedMutex.Lock()
		ancestor, cached := api.inherited[key]
		api.inheritedMutex.Unlock()
		if !cached || api.clock().Sub(ancestor.readAt) > 10*time.Minute {
			ancestor = gcpAncestor{readAt: api.clock()}
			var policy struct {
				Bindings []gcpBinding `json:"bindings"`
			}
			outcome, err := api.call(ctx, token, http.MethodPost, gcpResourceManagerHost, "/v3/"+parent+":getIamPolicy", "", []byte(`{"options":{"requestedPolicyVersion":3}}`), &policy)
			if err != nil {
				return nil, err
			}
			ancestor.outcome = outcome
			if outcome == outcomeOK {
				ancestor.roles = serviceAccountRoles(policy.Bindings)
			}
			if strings.HasPrefix(parent, "folders/") {
				var folder struct {
					Parent string `json:"parent"`
				}
				outcome, err := api.call(ctx, token, http.MethodGet, gcpResourceManagerHost, "/v3/"+parent, "", nil, &folder)
				if err != nil {
					return nil, err
				}
				if outcome == outcomeOK && gcpParentPattern.MatchString(folder.Parent) {
					ancestor.parent = folder.Parent
				} else if ancestor.outcome == outcomeOK {
					// What lies above this folder cannot be read.
					ancestor.outcome = outcomeDenied
				}
			}
			api.inheritedMutex.Lock()
			if len(api.inherited) > 4096 {
				api.inherited = map[string]gcpAncestor{}
			}
			api.inherited[key] = ancestor
			api.inheritedMutex.Unlock()
		}
		for email, bound := range ancestor.roles {
			roles[email] = append(roles[email], bound...)
		}
		if ancestor.outcome != outcomeOK {
			tally.add(outcomeDenied)
			return roles, nil
		}
		tally.add(outcomeOK)
		parent = ancestor.parent
	}
	return roles, nil
}

// readGeminiEnterprise lists the agents of the Gemini Enterprise (formerly
// Agentspace) apps of the project: the engines of the default collection in
// the global, us and eu locations, and the agents of each engine's default
// assistant.
//
// UNVERIFIED: the collection id default_collection, the assistant id
// default_assistant and the eu host are from memory; the methods, their
// paths and the us host are documented.
func (api *GCPCollectionAPI) readGeminiEnterprise(ctx context.Context, token []byte, project gcpProject, tally *serviceTally) ([]gcpListedAgent, error) {
	hosts := []struct{ location, host string }{{"global", gcpDiscoveryEngineHost}, {"us", "discoveryengine.us.rep.googleapis.com"}, {"eu", "discoveryengine.eu.rep.googleapis.com"}}
	var mutex sync.Mutex
	var agents []gcpListedAgent
	err := fanOut(ctx, len(hosts), func(ctx context.Context, index int) error {
		var engines []string
		outcome, err := api.list(ctx, token, hosts[index].host, "/v1alpha/projects/"+project.ID+"/locations/"+hosts[index].location+"/collections/default_collection/engines", nil, "engines", 1, func(raw json.RawMessage) {
			var engine struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(raw, &engine) != nil || len(engines) >= 50 {
				return
			}
			if resource, ok := parseGCPResource(engine.Name, project.ID, "engines"); ok {
				engines = append(engines, resource.Name)
			}
		})
		tally.add(outcome)
		if err != nil || outcome != outcomeOK {
			return err
		}
		for _, engine := range engines {
			outcome, err := api.list(ctx, token, hosts[index].host, "/v1alpha/"+engine+"/assistants/default_assistant/agents", url.Values{"pageSize": {"100"}}, "agents", 10, func(raw json.RawMessage) {
				var agent struct {
					Name        string `json:"name"`
					DisplayName string `json:"displayName"`
					State       string `json:"state"`
				}
				if json.Unmarshal(raw, &agent) != nil {
					return
				}
				resource, ok := parseGCPResource(agent.Name, project.ID, "agents")
				if !ok {
					return
				}
				state := "UNKNOWN"
				if gcpStatePattern.MatchString(agent.State) {
					state = agent.State
				}
				mutex.Lock()
				agents = append(agents, gcpListedAgent{resource: resource, display: gcpDisplay(agent.DisplayName, resource.ID), state: state, active: state == "ENABLED" || state == "PRIVATE" || state == "CONFIGURED"})
				mutex.Unlock()
			})
			tally.add(outcome)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return uniqueGCPAgents(agents), err
}

// readFunctions lists the Cloud Functions of every location in one call. A
// function whose service configuration names a Cloud Run service is returned
// twice: once as the function, and once with an empty resourceType and that
// service as its resource, so the caller can leave the service out.
func (api *GCPCollectionAPI) readFunctions(ctx context.Context, token []byte, project gcpProject, tally *serviceTally) ([]gcpWorkload, error) {
	var workloads []gcpWorkload
	outcome, err := api.list(ctx, token, gcpFunctionsHost, "/v2/projects/"+project.ID+"/locations/-/functions", url.Values{"pageSize": {"500"}}, "functions", 10, func(raw json.RawMessage) {
		var function struct {
			Name          string `json:"name"`
			State         string `json:"state"`
			ServiceConfig struct {
				Service              string                     `json:"service"`
				ServiceAccountEmail  string                     `json:"serviceAccountEmail"`
				EnvironmentVariables map[string]json.RawMessage `json:"environmentVariables"`
				SecretEnvironment    []struct {
					Key string `json:"key"`
				} `json:"secretEnvironmentVariables"`
			} `json:"serviceConfig"`
		}
		if json.Unmarshal(raw, &function) != nil {
			return
		}
		resource, ok := parseGCPResource(function.Name, project.ID, "functions")
		if !ok {
			return
		}
		workload := gcpWorkload{resource: resource, resourceType: "cloud_function", display: resource.ID, serviceAccount: gcpServiceAccountOrEmpty(function.ServiceConfig.ServiceAccountEmail), active: function.State == "" || function.State == "ACTIVE"}
		// Only the names of environment variables are looked at; their
		// values are left undecoded.
		for name := range function.ServiceConfig.EnvironmentVariables {
			workload.evidence.EnvironmentNames(name)
		}
		for _, secret := range function.ServiceConfig.SecretEnvironment {
			workload.evidence.EnvironmentNames(secret.Key)
		}
		workloads = append(workloads, workload)
		if service, isService := parseGCPResource(function.ServiceConfig.Service, project.ID, "services"); isService {
			workloads = append(workloads, gcpWorkload{resource: service})
		}
	})
	tally.add(outcome)
	sort.SliceStable(workloads, func(left, right int) bool { return workloads[left].resource.Name < workloads[right].resource.Name })
	return workloads, err
}

// readRunServices lists the Cloud Run services of every region of the
// project. The service list does not take a location wildcard, so the
// regions are listed first.
func (api *GCPCollectionAPI) readRunServices(ctx context.Context, token []byte, project gcpProject, tally *serviceTally) ([]gcpWorkload, error) {
	locations, outcome, err := api.locations(ctx, token, gcpRunHost, "/v1/projects/"+project.ID+"/locations")
	if err != nil {
		return nil, err
	}
	tally.add(outcome)
	if outcome != outcomeOK {
		return nil, nil
	}
	var mutex sync.Mutex
	var workloads []gcpWorkload
	err = fanOut(ctx, len(locations), func(ctx context.Context, index int) error {
		outcome, err := api.list(ctx, token, gcpRunHost, "/v2/projects/"+project.ID+"/locations/"+locations[index]+"/services", url.Values{"pageSize": {"100"}}, "services", 10, func(raw json.RawMessage) {
			var service struct {
				Name               string `json:"name"`
				FunctionalType     string `json:"functionalType"`
				Ingress            string `json:"ingress"`
				URI                string `json:"uri"`
				InvokerIAMDisabled bool   `json:"invokerIamDisabled"`
				Template           struct {
					ServiceAccount string `json:"serviceAccount"`
					Containers     []struct {
						Image   string   `json:"image"`
						Command []string `json:"command"`
						Args    []string `json:"args"`
						Env     []struct {
							Name string `json:"name"`
						} `json:"env"`
					} `json:"containers"`
				} `json:"template"`
			}
			if json.Unmarshal(raw, &service) != nil {
				return
			}
			resource, ok := parseGCPResource(service.Name, project.ID, "services")
			if !ok {
				return
			}
			// Anyone on the internet can call a service that takes all
			// ingress and has the invoker check switched off.
			workload := gcpWorkload{resource: resource, resourceType: "cloud_run_service", display: resource.ID, serviceAccount: gcpServiceAccountOrEmpty(service.Template.ServiceAccount), active: true,
				untrustedInput: service.InvokerIAMDisabled && service.Ingress == "INGRESS_TRAFFIC_ALL"}
			// An MCP server: Cloud Run's own record says so, or the image or
			// the command is one, the way a Kubernetes workload is recognised.
			// The command and its arguments are matched and never kept.
			workload.mcpServer = service.FunctionalType == "FUNCTIONAL_TYPE_MCP_SERVER"
			workload.openInvoker = service.InvokerIAMDisabled
			if parsed, parseErr := url.Parse(service.URI); parseErr == nil && parsed.Scheme == "https" && gcpHostPattern.MatchString(strings.ToLower(parsed.Hostname())) {
				workload.endpointHost = strings.ToLower(parsed.Hostname())
			}
			for _, container := range service.Template.Containers {
				workload.mcpServer = workload.mcpServer || agentsignals.MCPServerImage(container.Image) || agentsignals.MCPServerCommand(container.Command...) || agentsignals.MCPServerCommand(container.Args...)
				workload.evidence.Image(container.Image)
				// The decoder above reads the name of a variable and nothing else.
				for _, variable := range container.Env {
					workload.evidence.EnvironmentNames(variable.Name)
				}
			}
			if service.FunctionalType == "FUNCTIONAL_TYPE_AGENT" {
				workload.evidence.GCPDeclaredAgent()
			}
			mutex.Lock()
			workloads = append(workloads, workload)
			mutex.Unlock()
		})
		tally.add(outcome)
		return err
	})
	sort.Slice(workloads, func(left, right int) bool { return workloads[left].resource.Name < workloads[right].resource.Name })
	return workloads, err
}

// gcpModelArmor is what Model Armor said about a project. known is false
// when it could not be asked (a refusal): nothing is concluded then.
type gcpModelArmor struct {
	known        bool
	floorSetting bool
	templates    map[string]bool
}

// verdict is the model_armor attribute of an agent in location: the floor
// setting screens Vertex AI in the whole project, a template exists in the
// agent's location, neither, or "" when Model Armor could not be read.
func (state gcpModelArmor) verdict(location string) string {
	switch {
	case !state.known:
		return ""
	case state.floorSetting:
		return "floor_setting"
	case state.templates[location]:
		return "template"
	default:
		return "none"
	}
}

// readModelArmor reads the project's floor setting and, for each location
// that hosts an agent, whether a template exists there. A project whose
// Model Armor API is switched off has neither: that is a certain "none".
//
// UNVERIFIED: that the floor setting of a project is read at location
// "global" on the host modelarmor.googleapis.com is from memory; the method
// path and its members (enableFloorSettingEnforcement, aiPlatformFloorSetting
// with inspectOnly and inspectAndBlock) are documented.
func (api *GCPCollectionAPI) readModelArmor(ctx context.Context, token []byte, project gcpProject, locations map[string]bool, tally *serviceTally) (gcpModelArmor, error) {
	state := gcpModelArmor{templates: map[string]bool{}}
	if len(locations) == 0 {
		tally.add(outcomeOK)
		return state, nil
	}
	var floor struct {
		EnableFloorSettingEnforcement bool `json:"enableFloorSettingEnforcement"`
		AIPlatformFloorSetting        *struct {
			InspectOnly     bool `json:"inspectOnly"`
			InspectAndBlock bool `json:"inspectAndBlock"`
		} `json:"aiPlatformFloorSetting"`
	}
	outcome, err := api.call(ctx, token, http.MethodGet, gcpModelArmorHost, "/v1/projects/"+project.ID+"/locations/global/floorSetting", "", nil, &floor)
	if err != nil {
		return gcpModelArmor{}, err
	}
	tally.add(outcome)
	switch outcome {
	case outcomeDenied:
		return state, nil
	case outcomeDisabled:
		state.known = true
		return state, nil
	case outcomeOK:
		state.floorSetting = floor.EnableFloorSettingEnforcement && floor.AIPlatformFloorSetting != nil && (floor.AIPlatformFloorSetting.InspectOnly || floor.AIPlatformFloorSetting.InspectAndBlock)
	}
	served := make([]string, 0, len(locations))
	for location := range locations {
		if gcpModelArmorLocations[location] {
			served = append(served, location)
		}
	}
	sort.Strings(served)
	var mutex sync.Mutex
	refused := false
	err = fanOut(ctx, len(served), func(ctx context.Context, index int) error {
		location := served[index]
		found := false
		outcome, err := api.list(ctx, token, "modelarmor."+location+".rep.googleapis.com", "/v1/projects/"+project.ID+"/locations/"+location+"/templates", url.Values{"pageSize": {"1"}}, "templates", 1, func(json.RawMessage) { found = true })
		tally.add(outcome)
		mutex.Lock()
		defer mutex.Unlock()
		state.templates[location] = found
		refused = refused || outcome == outcomeDenied
		return err
	})
	// A refused template list leaves the answer open.
	state.known = !refused
	return state, err
}

// gcpServiceSummary is the last page: one gcp_service entity per service,
// saying whether it was read, refused or switched off everywhere.
func gcpServiceSummary(subject collection.SubjectBinding, scopeEntityID string, counters gcpCounters) ([]json.RawMessage, []json.RawMessage, bool) {
	entities := make([]json.RawMessage, 0, gcpServiceCount)
	relationships := make([]json.RawMessage, 0, gcpServiceCount)
	for index, service := range gcpServices {
		attributes := map[string]any{"status": "collected"}
		switch denied, disabled, ok := counters[index][outcomeDenied], counters[index][outcomeDisabled], counters[index][outcomeOK]; {
		case denied > 0:
			attributes["status"], attributes["affected_projects"] = "access_denied", strconv.Itoa(denied)
		case disabled > 0 && ok == 0:
			attributes["status"], attributes["affected_projects"] = "unavailable", strconv.Itoa(disabled)
		}
		native := "gcp:service:" + subject.ID + ":" + service.key
		id := gcpInventoryID(subject, "gcp_service", native)
		entity, entityOK := gcpEntity(id, "gcp_service", native, service.name, map[string]any{"name": service.name, "scope": subject.ID, "service": service.key}, attributes)
		if !entityOK {
			return nil, nil, false
		}
		entities = append(entities, entity)
		relationships = append(relationships, gcpRelationship(subject, "contains", "scope_service", "gcp:scope:"+subject.ID, native, scopeEntityID, id))
	}
	return entities, relationships, true
}
