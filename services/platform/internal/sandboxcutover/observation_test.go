package sandboxcutover

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestObservationProcessPreservesOnlyBoundedSuccessfulStdout(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("owned process groups unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body, err := runObservationProcess(ctx, exec.Command("/bin/sh", "-c", "printf '{\"schema\":\"fixture\"}'"))
	if err != nil || string(body) != `{"schema":"fixture"}` {
		t.Fatal("owned observation stdout", string(body), err)
	}
	for _, program := range []string{"printf private-error >&2; exit 1", "printf malformed; exit 1", "printf unexpected-stderr >&2"} {
		body, err := runObservationProcess(ctx, exec.Command("/bin/sh", "-c", program))
		if err == nil || len(body) != 0 {
			t.Fatal("failed or noisy child exposed successful evidence")
		}
	}
	stopped, stop := context.WithCancel(context.Background())
	stop()
	command := exec.Command("/bin/sh", "-c", "exit 0")
	if _, err := runObservationProcess(stopped, command); !errors.Is(err, context.Canceled) || command.Process != nil {
		t.Fatal("canceled process started", err)
	}
}

func TestObservationProcessRejectsRetainedStdinCopier(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("owned process groups unavailable")
	}
	for _, fileInput := range []bool{false, true} {
		t.Run(strconv.FormatBool(fileInput), func(t *testing.T) {
			root := t.TempDir()
			stopFile, ready := filepath.Join(root, "stop"), filepath.Join(root, "leader-exited")
			escapedDone := filepath.Join(root, "escaped-done")
			child := `const fs=require('fs'),deadline=Date.now()+5000;process.on('SIGTERM',()=>{});setInterval(()=>{if(fs.existsSync(` + strconv.Quote(stopFile) + `)||Date.now()>=deadline){fs.writeFileSync(` + strconv.Quote(escapedDone) + `,'done');process.exit(0)}},10)`
			leader := `const fs=require('fs'),cp=require('child_process');const child=cp.spawn(process.execPath,['-e',` + strconv.Quote(child) + `],{detached:true,stdio:'inherit'});child.unref();fs.writeFileSync(` + strconv.Quote(ready) + `,'ready');process.stdout.write('{}');process.exit(0)`
			command := exec.Command(observationNode(t), "-e", leader)
			body := bytes.Repeat([]byte("x"), 4<<20)
			if fileInput {
				path := filepath.Join(root, "request")
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				command.Stdin = file
			} else {
				command.Stdin = bytes.NewReader(body)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			type result struct {
				body []byte
				err  error
			}
			done := make(chan result, 1)
			go func() { body, err := runObservationProcess(ctx, command); done <- result{body, err} }()
			joined := false
			t.Cleanup(func() {
				_ = os.WriteFile(stopFile, nil, 0600)
				cancel()
				if !joined {
					select {
					case <-done:
					case <-time.After(4 * time.Second):
						t.Error("retained stdin fixture did not join owner")
					}
				}
				if _, err := os.Stat(ready); err == nil {
					for until := time.Now().Add(2 * time.Second); time.Now().Before(until); {
						if _, err := os.Stat(escapedDone); err == nil {
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
					t.Error("escaped fixture did not acknowledge cooperative stop")
				}
			})
			select {
			case got := <-done:
				joined = true
				if got.err == nil || len(got.body) != 0 {
					t.Fatal("escaped retained-pipe descendant received success/cleanup evidence")
				}
				if !fileInput && command.Process != nil {
					t.Fatal("unsupported copier input launched a process")
				}
			case <-time.After(time.Second):
				if _, err := os.Stat(ready); err != nil {
					t.Fatal("fixture never reached leader exit", err)
				}
				t.Fatal("Wait remained blocked after direct-child exit with retained stdin")
			}
			if fileInput {
				if _, err := os.Stat(ready); err != nil {
					t.Fatal("owned file case did not execute actual retained-descriptor fixture", err)
				}
			}
		})
	}
}

type observationFixture struct {
	config        ObservationConfig
	log, override string
}

func newObservationFixture(t *testing.T) *observationFixture {
	t.Helper()
	k := newKubeFixture(t)
	root := t.TempDir()
	node := observationNode(t)
	base, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	f := &observationFixture{config: ObservationConfig{Binding: k.config.Binding, CAPEM: k.config.CAPEM, BearerToken: k.config.BearerToken, ReleaseDirectory: base, NodeExecutable: node, KubectlExecutable: filepath.Join(root, "kubectl")}, log: filepath.Join(root, "calls"), override: filepath.Join(root, "rv")}
	names := []string{"agentsec-api", "agentsec-runtime-outbox", "agentsec-runtime-coordinator", "agentsec-runtime-archive", "agentsec-runtime-index", "agentsec-runtime-correlation", "agentsec-runtime-projection", "agentsec-runtime-complete", "agentsec-event-ingest", "agentsec-gateway-control", "agentsec-runtime-session-index-v2"}
	selects := map[string]map[string]string{
		"agentsec-api":                      {"ZASP_RUNTIME_SESSION_INDEX": "zasp-runtime-sessions-v1"},
		"agentsec-runtime-archive":          {"ZASP_RUNTIME_STAGE_VERSION": "runtime-archive-v1"},
		"agentsec-runtime-index":            {"ZASP_RUNTIME_STAGE_VERSION": "runtime-index-v1", "ZASP_RUNTIME_SESSION_INDEX": "zasp-runtime-sessions-v1"},
		"agentsec-runtime-session-index-v2": {"ZASP_RUNTIME_STAGE_VERSION": "runtime-index-v1", "ZASP_RUNTIME_SESSION_INDEX": "zasp-runtime-sessions-v2"},
		"agentsec-runtime-correlation":      {"ZASP_RUNTIME_STAGE_VERSION": "runtime-correlation-v2"},
		"agentsec-runtime-projection":       {"ZASP_RUNTIME_STAGE_VERSION": "runtime-projection-v1"},
		"agentsec-runtime-complete":         {"ZASP_RUNTIME_STAGE_VERSION": "runtime-complete-v1"},
	}
	docs := map[string]any{"namespace": map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": k.config.Binding.Namespace, "uid": k.config.Binding.NamespaceUID}}}
	deployments, sets, pods, expected := []any{}, []any{}, []any{}, []any{}
	for _, name := range names {
		var template map[string]any
		if err := json.Unmarshal([]byte(oldAPITemplate), &template); err != nil {
			t.Fatal(err)
		}
		template["metadata"].(map[string]any)["labels"] = map[string]any{"app": name}
		container := template["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
		env := []any{}
		for key, value := range selects[name] {
			env = append(env, map[string]any{"name": key, "value": value})
		}
		container["env"] = env
		// Keep this fixture's API bytes identical to the independently pinned
		// old template. The real Node observer still validates all11 consumers.
		body, err := marshalKube(template)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		images := map[string]string{"api": "docker-pullable://" + container["image"].(string)}
		expected = append(expected, map[string]any{"name": name, "templateDigest": hex.EncodeToString(sum[:]), "imageIDs": images})
		meta := func(uid string) map[string]any {
			return map[string]any{"name": uid, "namespace": k.config.Binding.Namespace, "uid": uid, "generation": 1}
		}
		dm := meta(name + "-deployment")
		dm["name"] = name
		dm["resourceVersion"] = "opaque:initial/rv"
		deployments = append(deployments, map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": dm, "spec": map[string]any{"replicas": 1, "template": template}, "status": map[string]any{"observedGeneration": 1, "replicas": 1, "updatedReplicas": 1, "readyReplicas": 1, "availableReplicas": 1}})
		rm := meta(name + "-rs")
		rm["ownerReferences"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": name, "uid": name + "-deployment", "controller": true}}
		sets = append(sets, map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": rm, "spec": map[string]any{"replicas": 1, "template": template}, "status": map[string]any{"observedGeneration": 1, "replicas": 1, "readyReplicas": 1, "availableReplicas": 1}})
		pm := meta(name + "-pod")
		pm["labels"] = map[string]any{"app": name}
		pm["annotations"] = map[string]any{"zasp.io/schema-version": "50"}
		pm["ownerReferences"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": name + "-rs", "uid": name + "-rs", "controller": true}}
		pods = append(pods, map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": pm, "spec": template["spec"], "status": map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}, "containerStatuses": []any{map[string]any{"name": "api", "imageID": images["api"], "ready": true, "state": map[string]any{"running": map[string]any{"startedAt": "2026-09-12T00:00:00Z"}}}}}})
	}
	docs["deployment"], docs["replicaset"], docs["pod"] = deployments, sets, pods
	body, _ := json.Marshal(expected)
	f.config.ExpectedJSON = string(body)
	data, _ := json.Marshal(docs)
	program := `#!` + node + `\nconst fs=require('fs'),assert=require('assert/strict'),docs=` + string(data) + `;const a=process.argv.slice(2);assert.equal(a[0],'--kubeconfig');assert.equal(a[2],'--context');assert.equal(a[3],'sandbox-cutover');assert.equal(a[4],'get');assert.ok(['namespace','deployment','replicaset','pod'].includes(a[5]));const k=JSON.parse(fs.readFileSync(a[1]));assert.equal(fs.statSync(a[1]).mode&511,384);assert.equal(k.clusters[0].cluster.server,` + strconv.Quote(k.config.Binding.KubernetesServer) + `);assert.equal(k.users[0].user.token,` + strconv.Quote(k.config.BearerToken) + `);assert.equal(k.users[0].user.exec,undefined);assert.equal(process.env.KUBECONFIG,undefined);assert.equal(process.env.NODE_OPTIONS,undefined);fs.appendFileSync(` + strconv.Quote(f.log) + `,JSON.stringify({args:a,kubeconfig:a[1]})+'\n');if(fs.existsSync(` + strconv.Quote(f.override) + `))docs.deployment.find(d=>d.metadata.name==='agentsec-api').metadata.resourceVersion=fs.readFileSync(` + strconv.Quote(f.override) + `,'utf8');process.stdout.write(JSON.stringify(a[5]==='namespace'?docs.namespace:{apiVersion:'v1',kind:'List',items:docs[a[5]]}));`
	program = strings.Replace(program, `\n`, "\n", 1)
	program = strings.Replace(program, "assert.equal(process.env.KUBECONFIG,undefined);", "assert.equal(process.env.HOME,require('path').dirname(a[1]));assert.equal(process.env.XDG_CACHE_HOME,require('path').join(process.env.HOME,'cache'));assert.equal(process.env.KUBECONFIG,undefined);", 1)
	program = strings.Replace(program, "process.stdout.write(JSON.stringify(", "assert.equal(fs.statSync(require('path').join(process.env.HOME,'request.json')).mode&511,384);if(fs.existsSync("+strconv.Quote(f.log+".pause")+")){fs.writeFileSync("+strconv.Quote(f.log+".entered")+",'ready');setInterval(()=>{},1000)}else process.stdout.write(JSON.stringify(", 1)
	if err := os.WriteFile(f.config.KubectlExecutable, []byte(program), 0700); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestObservationRunsRealReadOnlyBridgeWithPinnedPrivateConfig(t *testing.T) {
	f := newObservationFixture(t)
	t.Setenv("KUBECONFIG", "/ambient/forbidden")
	t.Setenv("NODE_OPTIONS", "--invalid-ambient-option")
	client, err := NewObservation(f.config)
	if err != nil {
		t.Fatal("configured observation refused", err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first, err := client.ObserveBackfill(ctx, f.config.Binding)
	if err != nil || first.API.UID != "agentsec-api-deployment" || first.API.ResourceVersion != "opaque:initial/rv" || first.API.TemplateDigest != f.config.Binding.From.APITemplateDigest || len(first.IdentityDigest) != 64 || first.ObservedAt.IsZero() {
		t.Fatal("real bridge identity", first, err)
	}
	second, err := client.RevalidateBackfill(ctx, f.config.Binding, first)
	if err != nil || second.API != first.API || second.IdentityDigest != first.IdentityDigest {
		t.Fatal("fresh bridge changed stable identity", second, err)
	}
	calls, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != 10 {
		t.Fatal("revalidation did not execute full fresh read set", len(lines))
	}
	for _, line := range lines {
		var call struct{ Kubeconfig string }
		if json.Unmarshal([]byte(line), &call) != nil {
			t.Fatal("invalid fixture log")
		}
		if _, err := os.Stat(call.Kubeconfig); !os.IsNotExist(err) {
			t.Fatal("private credential file survived completed observation")
		}
	}
	if err := os.WriteFile(f.override, []byte("changed-rv"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RevalidateBackfill(ctx, f.config.Binding, first); err == nil {
		t.Fatal("changed API resourceVersion admitted")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ObserveBackfill(ctx, f.config.Binding); err == nil {
		t.Fatal("closed observer started a new read")
	}
}

func TestObservationPublicationWaitsForConfirmedCleanupAndFinalDeadline(t *testing.T) {
	for _, mode := range []string{"cleanup-error", "deadline-during-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			client := &ObservationClient{previous: map[Observation]string{}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			value := Observation{ObservedAt: time.Now().UTC(), IdentityDigest: strings.Repeat("a", 64), API: APIIdentity{UID: "api-1", ResourceVersion: "rv-1", TemplateDigest: strings.Repeat("b", 64)}}
			cleanup := func() error {
				if mode == "cleanup-error" {
					return errors.New("owned cleanup failed")
				}
				<-ctx.Done()
				return nil
			}
			got, err := client.publish(ctx, value, []byte("validated-private-envelope"), nil, cleanup)
			if err == nil || got != (Observation{}) {
				t.Fatal("cleanup failure/expiry published evidence", got, err)
			}
			if len(client.previous) != 0 {
				t.Fatal("failed cleanup retained usable previous-envelope evidence")
			}
		})
	}
}

func TestObservationZeroValueRefusesWithoutStarting(t *testing.T) {
	var client ObservationClient
	if _, err := client.ObserveBackfill(context.Background(), ReleaseBinding{}); err == nil {
		t.Fatal("zero observer accepted")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestObservationConstructorClosesConfigurationChoices(t *testing.T) {
	f := newObservationFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*ObservationConfig)
	}{
		{"wrong server scheme", func(c *ObservationConfig) {
			c.Binding.KubernetesServer = strings.Replace(c.Binding.KubernetesServer, "https:", "http:", 1)
		}},
		{"server path", func(c *ObservationConfig) { c.Binding.KubernetesServer += "/alternate" }},
		{"CA pin", func(c *ObservationConfig) { c.Binding.KubernetesCADigest = strings.Repeat("0", 64) }},
		{"extra CA", func(c *ObservationConfig) { c.CAPEM += c.CAPEM }},
		{"token control", func(c *ObservationConfig) { c.BearerToken += "\n" }},
		{"missing expected consumers", func(c *ObservationConfig) { c.ExpectedJSON = "[]" }},
		{"null expected", func(c *ObservationConfig) { c.ExpectedJSON = "null" }},
		{"unknown expected field", func(c *ObservationConfig) {
			c.ExpectedJSON = strings.Replace(c.ExpectedJSON, `{"imageIDs":`, `{"extra":true,"imageIDs":`, 1)
		}},
		{"duplicate expected field", func(c *ObservationConfig) {
			c.ExpectedJSON = strings.Replace(c.ExpectedJSON, `"name":"agentsec-api"`, `"name":"other","name":"agentsec-api"`, 1)
		}},
		{"wrong API template", func(c *ObservationConfig) { c.Binding.From.APITemplateDigest = strings.Repeat("b", 64) }},
		{"unpinned image", func(c *ObservationConfig) {
			c.ExpectedJSON = strings.ReplaceAll(c.ExpectedJSON, "@sha256:"+strings.Repeat("a", 64), ":latest")
		}},
		{"relative node", func(c *ObservationConfig) { c.NodeExecutable = "node" }},
		{"missing kubectl", func(c *ObservationConfig) { c.KubectlExecutable = filepath.Join(t.TempDir(), "missing") }},
		{"relative artifact root", func(c *ObservationConfig) { c.ReleaseDirectory = "." }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.config
			tc.change(&c)
			client, err := NewObservation(c)
			if err == nil {
				client.Close()
				t.Fatal("untrusted selector/configuration admitted")
			}
		})
	}
	if _, err := os.Stat(f.log); !os.IsNotExist(err) {
		t.Fatal("constructor started a cluster read")
	}
}

func TestObservationStrictlyDecodesFullReturnedEnvelope(t *testing.T) {
	f := newObservationFixture(t)
	client, err := NewObservation(f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := client.ObserveBackfill(context.Background(), f.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(client.previous[first])
	started := first.ObservedAt.Add(-time.Millisecond)
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"schema", func(e map[string]any) { e["schema"] = "precision-observation" }},
		{"unknown root", func(e map[string]any) { e["authority"] = true }},
		{"resourceVersion", func(e map[string]any) { e["apiResourceVersion"] = "" }},
		{"namespace UID", func(e map[string]any) { e["observation"].(map[string]any)["namespaceUID"] = "other-namespace" }},
		{"stale", func(e map[string]any) {
			e["observation"].(map[string]any)["observedAt"] = time.Now().Add(-time.Minute).UnixMilli()
		}},
		{"future", func(e map[string]any) {
			e["observation"].(map[string]any)["observedAt"] = time.Now().Add(time.Minute).UnixMilli()
		}},
		{"missing consumer", func(e map[string]any) {
			o := e["observation"].(map[string]any)
			o["deployments"] = o["deployments"].([]any)[1:]
		}},
		{"wrong API template", func(e map[string]any) {
			o := e["observation"].(map[string]any)
			o["deployments"].([]any)[0].(map[string]any)["templateDigest"] = strings.Repeat("b", 64)
		}},
		{"unobserved generation", func(e map[string]any) {
			o := e["observation"].(map[string]any)
			o["deployments"].([]any)[0].(map[string]any)["observedGeneration"] = 2
		}},
		{"no ready pods", func(e map[string]any) {
			o := e["observation"].(map[string]any)
			o["deployments"].([]any)[0].(map[string]any)["pods"] = []any{}
		}},
		{"wrong actual image", func(e map[string]any) {
			o := e["observation"].(map[string]any)
			d := o["deployments"].([]any)[0].(map[string]any)
			d["pods"].([]any)[0].(map[string]any)["imageIDs"] = map[string]any{"api": "other@sha256:" + strings.Repeat("a", 64)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var envelope map[string]any
			if json.Unmarshal(raw, &envelope) != nil {
				t.Fatal("fixture envelope")
			}
			tc.change(envelope)
			body, _ := json.Marshal(envelope)
			if got, err := client.decode(body, started); err == nil {
				t.Fatal("invalid bridge evidence admitted", got)
			}
		})
	}
	for _, body := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), append([]byte(`{"schema":"duplicate",`), raw[1:]...)} {
		if _, err := client.decode(body, started); err == nil {
			t.Fatal("duplicate/trailing envelope admitted")
		}
	}
}

func TestObservationRejectsWireKeyAliases(t *testing.T) {
	f := newObservationFixture(t)
	client, err := NewObservation(f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := client.ObserveBackfill(context.Background(), f.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(client.previous[first])
	for _, path := range []string{
		"schema", "observation", "apiResourceVersion",
		"observation/context", "observation/namespace", "observation/namespaceUID", "observation/observedAt", "observation/deployments",
		"observation/deployments/0/name", "observation/deployments/0/uid", "observation/deployments/0/generation", "observation/deployments/0/observedGeneration", "observation/deployments/0/templateDigest", "observation/deployments/0/replicaSetUID", "observation/deployments/0/pods",
		"observation/deployments/0/pods/0/name", "observation/deployments/0/pods/0/uid", "observation/deployments/0/pods/0/imageIDs",
	} {
		for _, retain := range []bool{false, true} {
			t.Run(path+"/overwrite="+strconv.FormatBool(retain), func(t *testing.T) {
				body := observationAliasJSON(t, raw, path, retain)
				if got, err := client.decode(body, first.ObservedAt.Add(-time.Millisecond)); err == nil {
					t.Fatal("case-folded wire field became accepted observation", got)
				}
			})
		}
	}
	for _, key := range []string{"name", "templateDigest", "imageIDs"} {
		for _, retain := range []bool{false, true} {
			t.Run("expected/"+key+"/overwrite="+strconv.FormatBool(retain), func(t *testing.T) {
				body := observationAliasJSON(t, []byte(`{"expected":`+f.config.ExpectedJSON+`}`), "expected/0/"+key, retain)
				var wrapped struct {
					Expected json.RawMessage `json:"expected"`
				}
				if err := json.Unmarshal(body, &wrapped); err != nil {
					t.Fatal(err)
				}
				config := f.config
				config.ExpectedJSON = string(wrapped.Expected)
				if accepted, err := NewObservation(config); err == nil {
					accepted.Close()
					t.Fatal("case-folded expected field admitted by constructor")
				}
			})
		}
	}
}

// Deliberately emit both spellings in source order so a case-insensitive
// decoder overwrites the original null with the otherwise valid value.
func observationAliasJSON(t *testing.T, raw []byte, path string, retain bool) []byte {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(path, "/")
	var parent any = root
	for _, part := range parts[:len(parts)-1] {
		switch value := parent.(type) {
		case map[string]any:
			parent = value[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(value) {
				t.Fatal("invalid alias fixture path")
			}
			parent = value[index]
		default:
			t.Fatal("invalid alias fixture parent")
		}
	}
	key := parts[len(parts)-1]
	object := parent.(map[string]any)
	if _, exists := object[key]; !exists {
		t.Fatal("missing alias fixture key")
	}
	canonical, _ := json.Marshal(root)
	original, _ := json.Marshal(object)
	alias := strings.ToUpper(key[:1]) + key[1:]
	from, to := `"`+key+`":`, `"`+alias+`":`
	if retain {
		to = from + `null,` + to
	}
	changed := bytes.Replace(original, []byte(from), []byte(to), 1)
	return bytes.Replace(canonical, original, changed, 1)
}

func TestObservationWireValidationPreservesOpaqueImageMapKeys(t *testing.T) {
	// Container-name keys are data, even when they happen to match wire fields.
	const body = `{"name":"agentsec-api","templateDigest":"digest","imageIDs":{"schema":"image-a","generation":"image-b","imageIDs":"image-c"}}`
	var expected observationExpected
	if err := strictObservationJSON([]byte(body), &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected.ImageIDs) != 3 || expected.ImageIDs["schema"] != "image-a" || expected.ImageIDs["generation"] != "image-b" || expected.ImageIDs["imageIDs"] != "image-c" {
		t.Fatal("opaque container-name keys were normalized or discarded", expected.ImageIDs)
	}
}

func TestObservationCloseCancelsOwnedActiveReadAndRemovesCredentials(t *testing.T) {
	f := newObservationFixture(t)
	if err := os.WriteFile(f.log+".pause", nil, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewObservation(f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type outcome struct {
		value Observation
		err   error
	}
	done := make(chan outcome, 1)
	go func() { value, err := client.ObserveBackfill(ctx, f.config.Binding); done <- outcome{value, err} }()
	entered := false
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		if _, err := os.Stat(f.log + ".entered"); err == nil {
			entered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !entered {
		t.Fatal("read boundary did not become active")
	}
	started := time.Now()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("Close did not bound owned active process cleanup")
	}
	select {
	case got := <-done:
		if got.err == nil || got.value != (Observation{}) {
			t.Fatal("Close published active observation")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join active call")
	}
	lines, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	var call struct{ Kubeconfig string }
	if json.Unmarshal(bytes.TrimSpace(lines), &call) != nil {
		t.Fatal("paused first-read fixture emitted unexpected calls")
	}
	if _, err := os.Stat(filepath.Dir(call.Kubeconfig)); !os.IsNotExist(err) {
		t.Fatal("Close retained owned credential/request directory")
	}
	if _, err := client.ObserveBackfill(context.Background(), f.config.Binding); err == nil {
		t.Fatal("closed observer admitted new process")
	}
}

func TestObservationCacheRequiresExactValueAndHasBoundedCapacity(t *testing.T) {
	f := newObservationFixture(t)
	client, err := NewObservation(f.config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	first, err := client.ObserveBackfill(ctx, f.config.Binding)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(f.log)
	for _, changed := range []Observation{{ObservedAt: first.ObservedAt.Add(time.Nanosecond), IdentityDigest: first.IdentityDigest, API: first.API}, {ObservedAt: first.ObservedAt, IdentityDigest: first.IdentityDigest, API: APIIdentity{UID: first.API.UID, ResourceVersion: "forged", TemplateDigest: first.API.TemplateDigest}}} {
		if _, err := client.RevalidateBackfill(ctx, f.config.Binding, changed); err == nil {
			t.Fatal("digest-only or partial previous observation reused")
		}
	}
	after, _ := os.ReadFile(f.log)
	if !bytes.Equal(before, after) {
		t.Fatal("forged previous value reached cluster reads")
	}
	accepted := 1
	for ; accepted < 16; accepted++ {
		if _, err := client.ObserveBackfill(ctx, f.config.Binding); err != nil {
			break
		}
	}
	if accepted != 8 {
		t.Fatal("private observation cache failed its bounded contract", accepted)
	}
	before, _ = os.ReadFile(f.log)
	if _, err := client.ObserveBackfill(ctx, f.config.Binding); err == nil {
		t.Fatal("full cache accepted another envelope")
	}
	after, _ = os.ReadFile(f.log)
	if !bytes.Equal(before, after) {
		t.Fatal("full cache started unnecessary process")
	}
}

func observationNode(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestObservationProcessBoundsBothPipes(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("owned process groups unavailable")
	}
	for _, program := range []string{`process.stdout.write(Buffer.alloc(4194305,120));setInterval(()=>{},1000)`, `process.stderr.write(Buffer.alloc(4097,120));setInterval(()=>{},1000)`} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		body, err := runObservationProcess(ctx, exec.Command(observationNode(t), "-e", program))
		cancel()
		if err == nil || len(body) != 0 {
			t.Fatal("oversized output became evidence")
		}
	}
}

func TestObservationProcessOwnsDescendantBeyondLeaderAndPipes(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("owned process groups unavailable")
	}
	for _, mode := range []string{"inherited-pipes", "closed-pipes", "leader-exits"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			node := observationNode(t)
			ready, stopFile := filepath.Join(root, "ready"), filepath.Join(root, "stop")
			child := `const fs=require('fs'),net=require('net');process.on('SIGTERM',()=>{});const ready=` + strconv.Quote(ready) + `;const server=net.createServer(c=>c.end()).listen(0,'127.0.0.1',()=>{const tmp=ready+'.'+process.pid;fs.writeFileSync(tmp,String(server.address().port),{flag:'wx'});fs.renameSync(tmp,ready)});setInterval(()=>{if(fs.existsSync(` + strconv.Quote(stopFile) + `))process.exit(0)},20)`
			leader := `const fs=require('fs'),cp=require('child_process');process.on('SIGTERM',()=>{});cp.spawn(process.execPath,['-e',` + strconv.Quote(child) + `],{stdio:` + strconv.Quote(map[bool]string{true: "ignore", false: "inherit"}[mode == "closed-pipes"]) + `});const tick=setInterval(()=>{if(fs.existsSync(` + strconv.Quote(stopFile) + `))process.exit(0);if(fs.existsSync(` + strconv.Quote(ready) + `)&&` + strconv.FormatBool(mode == "leader-exits") + `){process.stdout.write('{}');process.exit(0)}},20)`
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			type result struct {
				body []byte
				err  error
			}
			done := make(chan result, 1)
			go func() {
				body, err := runObservationProcess(ctx, exec.Command(node, "-e", leader))
				done <- result{body, err}
			}()
			joined := false
			var address string
			t.Cleanup(func() {
				_ = os.WriteFile(stopFile, nil, 0600)
				cancel()
				if !joined {
					select {
					case <-done:
					case <-time.After(4 * time.Second):
						t.Error("owned test process did not stop")
					}
				}
				if address != "" {
					for until := time.Now().Add(2 * time.Second); time.Now().Before(until); {
						connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
						if err != nil {
							return
						}
						connection.Close()
						time.Sleep(10 * time.Millisecond)
					}
					t.Error("descendant fixture did not acknowledge cooperative stop")
				}
			})
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
				if port, err := os.ReadFile(ready); err == nil {
					if number, err := strconv.Atoi(string(port)); err == nil && number >= 1 && number <= 65535 {
						address = "127.0.0.1:" + strconv.Itoa(number)
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if address == "" {
				t.Fatal("descendant never established listener")
			}
			if mode != "leader-exits" {
				connection, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal("descendant not live before cancellation", err)
				}
				connection.Close()
				cancel()
			}
			select {
			case got := <-done:
				joined = true
				if mode == "leader-exits" {
					if got.err != nil || string(got.body) != "{}" {
						t.Fatal("leader exit did not confirm owned cleanup", got.err)
					}
				} else if !errors.Is(got.err, context.Canceled) || len(got.body) != 0 {
					t.Fatal("canceled child returned evidence", got.err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("descendant retained output or listener after owned deadline")
			}
			if connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
				connection.Close()
				t.Fatal("descendant listener survived owned cleanup")
			}
		})
	}
}
