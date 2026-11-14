package agentsignals

import "strings"

// Google Cloud signals. The Google Cloud collector reads the names below
// from the provider (a role name, an audit method name, a declared
// functional type); what it records is the catalog token.

// IAM roles that let a principal call a model or an agent on Vertex AI. A
// role alone says the principal may call a model, not that it does, so it is
// a weak signal: it lists a workload only together with a signal of another
// class (an environment variable name, an image, a recorded invocation).
//
// The role names are Google Cloud's predefined roles as remembered:
// UNVERIFIED against the published role list.
var gcpRoles = map[string]entry{
	"roles/aiplatform.user":      {token: "vertex_ai_user", strength: weak},
	"roles/aiplatform.admin":     {token: "vertex_ai_user", strength: weak},
	"roles/discoveryengine.user": {token: "gemini_enterprise_user", strength: weak},
	"roles/dialogflow.client":    {token: "conversational_agents_client", strength: weak},
}

// GCPRoles records which model or agent access the IAM roles of a service
// account grant. Role names are matched without regard to case.
func (evidence *Evidence) GCPRoles(roles ...string) {
	for _, role := range roles {
		if candidate, ok := gcpRoles[strings.ToLower(strings.TrimSpace(role))]; ok {
			evidence.set().add("iam", candidate.token, candidate.strength)
		}
	}
}

// Vertex AI methods the Cloud Audit Logs data access log records, by the
// last element of the method name (google.cloud.aiplatform.v1.
// PredictionService.GenerateContent is "generatecontent").
var gcpInvocationMethods = map[string]string{
	"generatecontent": "vertex_ai_model", "streamgeneratecontent": "vertex_ai_model", "predict": "vertex_ai_model", "rawpredict": "vertex_ai_model",
	"streamrawpredict": "vertex_ai_model", "serverstreamingpredict": "vertex_ai_model", "streamingpredict": "vertex_ai_model", "directpredict": "vertex_ai_model",
	"counttokens": "vertex_ai_model", "embedcontent": "vertex_ai_model", "chatcompletions": "vertex_ai_model",
	"queryreasoningengine": "vertex_ai_agent", "streamqueryreasoningengine": "vertex_ai_agent",
}

// GCPInvocationToken returns the catalog token of a Vertex AI audit method
// name ("" when the method is not a model or agent invocation).
func GCPInvocationToken(methodName string) string {
	name := strings.ToLower(methodName)
	if index := strings.LastIndexByte(name, '.'); index >= 0 {
		name = name[index+1:]
	}
	return gcpInvocationMethods[name]
}

// GCPInvoked records model and agent invocations found in the Cloud Audit
// Logs, by method name.
func (evidence *Evidence) GCPInvoked(methodNames ...string) {
	for _, name := range methodNames {
		if token := GCPInvocationToken(name); token != "" {
			evidence.set().add("invoke", token, strong)
		}
	}
}

// GCPDeclaredAgent records that the provider's own record of a workload
// declares it an agent (the functional type of a Cloud Run service).
func (evidence *Evidence) GCPDeclaredAgent() {
	evidence.set().add("surface", "cloud_run_agent", strong)
}
