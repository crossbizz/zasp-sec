package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/addonevidence"
	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

// Exercise the collector's inventory command for an employee project. OS-specific
// watcher tests establish how the file addition and edit trigger this command.
func exerciseInstalledSkillInventory(t *testing.T, b *installedBaseline, reviewer installedPrincipal, seed []byte,
	send func(endpointprotocol.Inventory), device func() map[string]any) {
	t.Helper()
	dir := t.TempDir()
	build := func(module, pkg, name string) string {
		t.Helper()
		exe := filepath.Join(dir, name)
		cmd := exec.CommandContext(b.ctx, "go", "-C", module, "build", "-mod=readonly", "-o", exe, pkg)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v %s", name, err, out)
		}
		return exe
	}
	cli := build("../../../cmd/zaspctl", ".", "zaspctl")
	encoder := build("../../endpoint-agent", "./testdata/serialize-inventory", "serialize-inventory")
	project := filepath.Join(dir, "employee-project")
	root := filepath.Join(project, ".agents", "skills")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	privateName := "private-fixture-skill"
	skill := filepath.Join(root, privateName)
	const privateText = "Internal documentation for the employee collection fixture."
	const privatePackage = "staff-package-fixture"
	checkPrivacy := func(raw []byte) {
		t.Helper()
		for _, forbidden := range []string{project, ".agents/skills", privateName, privateText, privatePackage, "SKILL.md", "package.json"} {
			if bytes.Contains(raw, []byte(forbidden)) {
				t.Fatalf("private fixture detail %q crossed the device boundary", forbidden)
			}
		}
	}
	var seq uint64
	collect := func() []endpointprotocol.Installation {
		t.Helper()
		scan := exec.CommandContext(b.ctx, cli, "addons", "inventory", "--local", "--harness", "codex", "--scope", "project", "--project", project, "--json")
		report, err := scan.Output()
		if err != nil {
			t.Fatalf("CLI inventory: %v %s", err, report)
		}
		input, err := json.Marshal(map[string]any{"project": project, "seed": seed, "sequence": seq, "report": json.RawMessage(report)})
		if err != nil {
			t.Fatal(err)
		}
		encode := exec.CommandContext(b.ctx, encoder)
		encode.Stdin = bytes.NewReader(input)
		wire, err := encode.CombinedOutput()
		if err != nil {
			t.Fatalf("device serialization: %v %s", err, wire)
		}
		checkPrivacy(wire)
		var snapshots []endpointprotocol.Inventory
		if err := json.Unmarshal(wire, &snapshots); err != nil || len(snapshots) == 0 {
			t.Fatalf("invalid inventory snapshots: %v", err)
		}
		var seen []endpointprotocol.Installation
		for _, v := range snapshots {
			if !v.Valid() || v.Generation <= seq {
				t.Fatal("invalid or stale signed snapshot")
			}
			send(v)
			seq = v.Generation
			seen = append(seen, v.Items...)
		}
		return seen
	}
	if items := collect(); len(items) != 0 {
		t.Fatal("empty project reported an installation")
	}
	if err := os.Mkdir(skill, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte(privateText), 0600); err != nil {
		t.Fatal(err)
	}
	setDependency := func(version string) {
		t.Helper()
		manifest, _ := json.Marshal(map[string]any{"dependencies": map[string]string{privatePackage: version}})
		if err := os.WriteFile(filepath.Join(skill, "package.json"), manifest, 0600); err != nil {
			t.Fatal(err)
		}
	}
	registry := &discoveryWorkflowSurface{addons: &addonReviewHandler{database: b.product, newProductID: newWorkflowProductID}}
	versionFor := func(found []endpointprotocol.Installation, want map[string]int) string {
		t.Helper()
		if len(found) != 1 || found[0].Digest == "" {
			t.Fatalf("wanted one complete skill scan; received %d installations", len(found))
		}
		info, err := json.Marshal(device())
		if err != nil {
			t.Fatal(err)
		}
		checkPrivacy(info)
		var detail struct {
			Partitions []struct {
				Rows []struct {
					Installation string `json:"installation_id"`
					Version      string `json:"skill_version_id"`
					Scan         *struct {
						Ruleset string         `json:"ruleset"`
						Counts  map[string]int `json:"rule_counts"`
						Skipped int            `json:"skipped_count"`
					} `json:"skill_scan"`
				} `json:"observed_installations"`
			} `json:"partition_summaries"`
		}
		if err := json.Unmarshal(info, &detail); err != nil {
			t.Fatal(err)
		}
		for _, p := range detail.Partitions {
			for _, row := range p.Rows {
				if row.Installation != found[0].ID {
					continue
				}
				if !validProductID(row.Version) || row.Scan == nil || row.Scan.Ruleset != addonevidence.CurrentRuleset || row.Scan.Skipped != 0 || !reflect.DeepEqual(row.Scan.Counts, want) {
					t.Fatalf("invalid automatic finding counts for installed digest: %+v", row)
				}
				reply := b.serve(registry, reviewer, "getAddonVersion", http.MethodGet, "/api/v1/addon-versions/"+row.Version, map[string]string{"id": row.Version}, "", nil)
				checkPrivacy(reply.Body.Bytes())
				var review struct {
					Origin   string
					Digest   string `json:"manifest_digest"`
					Findings []struct {
						Rule  string `json:"rule_id"`
						Count int
					}
				}
				if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &review) != nil || review.Origin != "endpoint" || review.Digest != found[0].Digest {
					t.Fatalf("invalid add-on review for signed device scan: %d %s", reply.Code, reply.Body)
				}
				counts := map[string]int{}
				for _, f := range review.Findings {
					counts[f.Rule] = f.Count
				}
				if !reflect.DeepEqual(counts, want) {
					t.Fatalf("registry counts %v, expected %v", counts, want)
				}
				return row.Version
			}
		}
		t.Fatal("device detail lacks its collected skill")
		return ""
	}

	setDependency("^1.0.0")
	want := map[string]int{"dependency.unpinned": 1}
	added := collect()
	first := versionFor(added, want)
	if repeated := versionFor(collect(), want); repeated != first {
		t.Fatal("unchanged skill acquired a duplicate review")
	}
	setDependency("1.0.0")
	updated := collect()
	if next := versionFor(updated, map[string]int{}); next == first || updated[0].Digest == added[0].Digest || updated[0].ID != added[0].ID {
		t.Fatal("edit must create a new version of the same installation")
	}
	t.Log("verified installed skill addition, repeated delivery and edit through signed device inventory and Add-ons review")
}
