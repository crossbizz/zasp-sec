package githubdiscovery

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

// The whole collection of an installation, driven by the shared collection
// client exactly as the worker drives it, ends in a typed snapshot in which
// the inferred agent project is an agent related to its repository.
func TestCollectionClientCompletesATypedSnapshotWithAnAgentProject(t *testing.T) {
	t.Parallel()
	roundTripper := &installationRoundTripper{responses: []installationHTTPResponse{
		{status: http.StatusOK, body: `{"id":9001,"app_id":77,"app_slug":"zasp-security","permissions":{"actions":"read","contents":"read","metadata":"read"},"account":{"id":501,"login":"acme","type":"Organization"}}`},
		{status: http.StatusOK, body: `{"total_count":1,"repositories":[{"id":101,"name":"alpha","full_name":"acme/alpha","private":true,"archived":false,"default_branch":"main","permissions":{"admin":false,"maintain":false,"pull":true,"push":false,"triage":false},"owner":{"login":"acme"}}]}`},
		agentProjectTree(false, agentProjectBlob("README.md", 10), agentProjectDirectory("tools"), agentProjectBlob("tools/.mcp.json", 80)),
		{status: http.StatusOK, body: `{"total_count":1,"workflows":[{"id":801,"name":"Build and deploy","path":".github/workflows/build-and-deploy.yml","state":"active"}]}`},
		{status: http.StatusOK, body: `{"total_count":1,"environments":[{"id":901,"name":"production"}]}`},
	}}
	api, err := newInstallationCollectionAPI(roundTripper, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	driver, artifacts := newTypedSnapshotArtifacts(t)
	client, err := NewCollectionClient(api, artifacts, CollectionClientConfig{CollectorVersion: "collector_v1", ParserVersion: "parser_v1", ToolVersion: "tool_v1", Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	request := typedSnapshotRequest(t, collection.ProviderGitHub, collection.CredentialGitHubInstallation, "ref:github/installation/customer-0001", agentProjectSubject)
	outcome, err := client.CollectWithCredential(context.Background(), request, []byte(agentProjectCredential))
	byKind, relationships := requireTypedSnapshot(t, request, outcome, err, map[string]typedSnapshotEnvelope{
		"github_installation":  {"asset", 9000},
		"github_app":           {"tool", 9000},
		"github_organization":  {"asset", 9000},
		"github_permission":    {"asset", 9000},
		"github_repository":    {"tool", 9000},
		"github_workflow":      {"tool", 9000},
		"github_environment":   {"asset", 9000},
		"github_agent_project": {"agent", 6000},
	})
	if len(roundTripper.requests) != 5 || len(driver.objects) != 6 {
		t.Fatalf("provider calls = %d, artifacts = %d", len(roundTripper.requests), len(driver.objects))
	}
	for key, object := range driver.objects {
		if bytes.Contains(object.Body, []byte(agentProjectCredential)) {
			t.Fatalf("artifact %s stores the credential", key)
		}
	}
	if len(byKind["github_agent_project"]) != 1 {
		t.Fatalf("agent projects = %+v", byKind["github_agent_project"])
	}
	project := byKind["github_agent_project"][0]
	if project.ID != deterministicGitHubInventoryID(agentProjectSubject, "github_agent_project", "101") || project.SourceNativeID != "github:repository:101:agent_project" || project.DisplayName != "acme/alpha" ||
		string(project.StableFields) != `{"installation_id":9001,"name":"acme/alpha","owner":"acme","repository":"alpha"}` ||
		string(project.Attributes) != `{"discovery":{"method":"inferred","platform":"github_repository","signals":["manifest:mcp_config"]},"posture":`+agentProjectPosture+`}` {
		t.Fatalf("agent project = %+v\nstable %s\nattributes %s", project, project.StableFields, project.Attributes)
	}
	if !typedSnapshotEdge(relationships, "contains", deterministicGitHubInventoryID(agentProjectSubject, "github_repository", "101"), project.ID) {
		t.Fatalf("agent project is not related to its repository: %+v", relationships)
	}
}
