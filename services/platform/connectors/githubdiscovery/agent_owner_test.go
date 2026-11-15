package githubdiscovery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
)

// An agent project carries the default owner its repository's CODEOWNERS
// file names. The file is read once, after the configuration; nothing else
// of it is kept, and a repository without the file names no owner.
func TestAgentProjectCarriesTheDefaultCodeowner(t *testing.T) {
	t.Parallel()
	codeowners := "# never-recorded-comment\n*.md @acme/docs\n* @acme/platform dana@example.com\n/secrets/ @acme/never-recorded-team\n"
	page, err, urls := fetchAgentProjectPage(t,
		agentProjectTree(false, agentProjectBlob("README.md", 10), agentProjectBlob("tools/.mcp.json", 80), agentProjectBlob(".github/CODEOWNERS", len(codeowners))),
		installationHTTPResponse{status: http.StatusNotFound, body: `{}`}, agentProjectContent(codeowners))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(urls) != fmt.Sprint([]string{agentProjectTreeURL, agentProjectContentURL("tools/.mcp.json"), agentProjectContentURL(".github/CODEOWNERS")}) {
		t.Fatalf("provider calls = %v", urls)
	}
	if len(page.Entities) != 1 {
		t.Fatalf("page = %s", page.Raw)
	}
	var entity struct {
		Kind       string         `json:"kind"`
		Attributes map[string]any `json:"attributes"`
	}
	if err := json.Unmarshal(page.Entities[0], &entity); err != nil {
		t.Fatal(err)
	}
	if entity.Kind != "github_agent_project" || entity.Attributes["created_by"] != "@acme/platform" || entity.Attributes["created_by_source"] != "codeowners" || entity.Attributes["created_at"] != nil {
		t.Fatalf("entity = %s", page.Entities[0])
	}
	if strings.Contains(string(page.Raw), "never-recorded") || strings.Contains(string(page.Raw), "dana@example.com") {
		t.Fatalf("the page kept more of the file than its default owner: %s", page.Raw)
	}
	// Without the file the project has no owner claim, and nothing is read
	// for one.
	plain, err, plainURLs := fetchAgentProjectPage(t, agentProjectTree(false, agentProjectBlob("tools/.mcp.json", 80)), installationHTTPResponse{status: http.StatusNotFound, body: `{}`})
	if err != nil {
		t.Fatal(err)
	}
	requireAgentProject(t, plain, `["manifest:mcp_config"]`)
	if len(plainURLs) != 2 {
		t.Fatalf("provider calls = %v", plainURLs)
	}
}

func TestCodeownersDefaultOwner(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct{ content, want string }{
		"a team":                        {"* @acme/platform\n", "@acme/platform"},
		"a user":                        {"*\t@octocat @second\n", "@octocat"},
		"an email address":              {"* dana.reyes@example.com\n", "dana.reyes@example.com"},
		"the last default rule wins":    {"* @acme/first\ndocs/ @acme/docs\n* @acme/last\n", "@acme/last"},
		"a later rule without an owner": {"* @acme/first\n*\n", ""},
		"no default rule":               {"docs/ @acme/docs\n*.go @acme/go\n", ""},
		"a comment":                     {"# * @acme/commented\n* @acme/real # trailing\n", "@acme/real"},
		"an owner that is not one":      {"* platform-team\n", ""},
		"an empty file":                 {"", ""},
	} {
		if got := agentsignals.CodeownersDefaultOwner([]byte(test.content)); got != test.want {
			t.Errorf("%s: owner = %q, want %q", name, got, test.want)
		}
	}
}
