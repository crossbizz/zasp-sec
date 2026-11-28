package windowsinventory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

func TestAssignedProjectInventory(t *testing.T) {
	c := Config{
		Origin: "https://fixture.invalid", Binding: endpointprotocol.Binding{Organization: "org", Workspace: "work", Environment: "dev", Device: "win", Generation: 1},
		AssignedSID: "S-1-5-21-1-2-3-1001", Scope: "project", ProjectRoot: `C:\Repos\Assigned Project`,
	}
	seed := make([]byte, ed25519.SeedSize)
	report := []byte(`{"schema_version":"zaspctl.local.v1","command":"inventory","status":"complete","coverage":{"mode":"local_only","roots":[{"scope":"project","root":".agents/skills","status":"complete"}]},"items":[{"scope":"project","path":".agents/skills/private-note","manifest_digest":"sha256:` + strings.Repeat("a", 64) + `"}]}`)
	var s State
	if err := s.Admit(c, seed, report); err != nil || len(s.Pending) != 1 || len(s.Pending[0].Items) != 1 {
		t.Fatalf("admit first project inventory: %v", err)
	}
	queued, err := json.Marshal(s.Pending)
	if err != nil || bytes.Contains(queued, []byte("Assigned Project")) || bytes.Contains(queued, []byte("private-note")) {
		t.Fatal("project and skill names must stay on the endpoint")
	}
	if err := s.Admit(c, seed, report); err != nil || s.Sequence != 1 {
		t.Fatalf("unchanged report queued again: %v", err)
	}
	changed := bytes.Replace(report, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)), 1)
	installation := s.Pending[0].Items[0].ID
	if err := s.Admit(c, seed, changed); err != nil || s.Sequence != 2 || s.Pending[0].Items[0].ID != installation {
		t.Fatalf("changed skill did not update its installation: %v", err)
	}
	c.ProjectRoot = `C:\Repos\Other`
	if err := s.Admit(c, seed, report); err == nil {
		t.Fatal("reused enrolled state after assigning another project")
	}
	for _, path := range []string{"", ".", `C:\`, `C:relative`, `C:\a\..\b`, `\\server\share\project`} {
		c.ProjectRoot = path
		if c.Valid() {
			t.Errorf("accepted project path %q", path)
		}
	}
	c.ProjectRoot = `C:\Repos\Project`
	c.Scope = "personal"
	if c.Valid() {
		t.Error("personal scope must not include a project assignment")
	}
}
