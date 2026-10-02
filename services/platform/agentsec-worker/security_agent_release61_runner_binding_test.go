package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

func TestRelease61RunnerRequiresCanonicalDispatchedArtifact(t *testing.T) {
	testLinkedRunnerArtifactBinding(t, false)
}

func TestTemporalEffectRunnerRequiresCanonicalDispatchedArtifact(t *testing.T) {
	testLinkedRunnerArtifactBinding(t, true)
}

func testLinkedRunnerArtifactBinding(t *testing.T, effect bool) {
	for _, mode := range []string{"exact", "parent", "step", "child", "scope", "manifest_digest", "version", "bytes", "image"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			scope := fixtureRedTeamScope(t)
			parent := "pid_89000020-0000-4000-8000-000000000001"
			step, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_step", parent+"\x1f1")
			child, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_test_run", parent+"\x1f"+step+"\x1frun_test")
			id, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", parent+"\x1f"+step)
			input := redTeamRunnerInput{SchemaVersion: "red-team-runner-input-v2", RunnerImageDigest: "sha256:" + strings.Repeat("a", 64), OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: child, DefinitionID: "pid_89000021-0000-4000-8000-000000000001", DefinitionVersion: 1, TargetID: "pid_89000022-0000-4000-8000-000000000001", TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, InputDigest: strings.Repeat("d", 64)}
			if mode == "child" {
				input.RunID = parent
			}
			if mode == "scope" {
				input.OrganizationID = parent
			}
			if mode == "image" {
				input.RunnerImageDigest = "sha256:" + strings.Repeat("b", 64)
			}
			body, _ := json.Marshal(input)
			store, err := artifactstore.New(&release61ArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1048576})
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := release61PutArtifact(ctx, store, scope, id, body)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "parent" {
				parent = step
			}
			if mode == "step" {
				step = parent
			}
			if mode == "manifest_digest" {
				manifest.SHA256 = strings.Repeat("e", 64)
			}
			if mode == "version" {
				manifest.VersionID = "foreign-version"
			}
			if mode == "bytes" {
				body = append(body, ' ')
			}
			root := t.TempDir()
			token := filepath.Join(root, "token")
			if os.WriteFile(token, []byte(strings.Repeat("t", 64)), 0400) != nil {
				t.Fatal("token")
			}
			calls := 0
			runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "registry.example/redteam@sha256:" + strings.Repeat("a", 64), Artifacts: store, Command: redTeamCommandFunc(func(ctx context.Context, _ string, _ []string, env []string, _ string) error {
				calls++
				if _, bounded := ctx.Deadline(); !bounded {
					t.Error("runner command has no bound")
				}
				if effect {
					joined := strings.Join(env, "\n")
					if strings.Contains(joined, "ZASP_RED_TEAM_RUN_LEASE=") || !strings.Contains(joined, "ZASP_RED_TEAM_EFFECT_KEY="+strings.Repeat("f", 64)) || !strings.Contains(joined, "/v1/effects/evaluate") {
						t.Error("runner sent legacy or missing effect authority")
					}
				}
				return errWorkerExecution
			}), NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.platform.svc.cluster.local/v1/evaluate", TargetTokenFile: token, TargetCAFile: writeRedTeamTestCA(t, root), TempRoot: root, Timeout: time.Minute, Clock: func() time.Time { return time.Now().UTC() }})
			if err != nil {
				t.Fatal(err)
			}
			if effect {
				_, err = runner.runTemporalEffect(ctx, scope, parent, step, strings.Repeat("f", 64), body, manifest)
			} else {
				_, err = runner.runRelease61(ctx, scope, parent, step, strings.Repeat("a", 32), body, manifest)
			}
			want := 0
			if mode == "exact" {
				want = 1
			}
			if err == nil || calls != want {
				t.Fatal("dispatched input did not fence command", mode, calls, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.IsDir() {
					t.Fatal("runner temporary workspace leaked")
				}
			}
		})
	}
}
