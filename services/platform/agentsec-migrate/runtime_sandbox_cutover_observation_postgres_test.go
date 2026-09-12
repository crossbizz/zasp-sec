package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/internal/sandboxcutover"
)

// These are fixed approved-fixture templates, not live release/admission proof.
const fullObservationTemplate = `{"metadata":{"annotations":{"zasp.io/schema-version":"50"},"labels":{"app":"agentsec-api"}},"spec":{"containers":[{"env":[{"name":"ZASP_RUNTIME_SESSION_INDEX","value":"zasp-runtime-sessions-v1"}],"image":"fixture/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"api"}]}}`

type fullObservationFixture struct {
	*composedCutoverFixture
	observer *sandboxcutover.ObservationClient
	lists    map[string][]any
	reads    []string
	log      string
	expected string
}

func fullObservationClone(value any) map[string]any {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var copy map[string]any
	if err := json.Unmarshal(body, &copy); err != nil {
		panic(err)
	}
	return copy
}

func newFullObservationFixture(t *testing.T) *fullObservationFixture {
	t.Helper()
	to := strings.Replace(fullObservationTemplate, "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2", 1)
	f := &fullObservationFixture{composedCutoverFixture: newComposedCutoverTemplates(t, "none", fullObservationTemplate, to), lists: map[string][]any{}}
	names := []string{"agentsec-api", "agentsec-event-ingest", "agentsec-gateway-control", "agentsec-runtime-archive", "agentsec-runtime-complete", "agentsec-runtime-coordinator", "agentsec-runtime-correlation", "agentsec-runtime-index", "agentsec-runtime-outbox", "agentsec-runtime-projection", "agentsec-runtime-session-index-v2"}
	selections := map[string][][2]string{
		"agentsec-api":                      {{"ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v1"}},
		"agentsec-runtime-archive":          {{"ZASP_RUNTIME_STAGE_VERSION", "runtime-archive-v1"}},
		"agentsec-runtime-index":            {{"ZASP_RUNTIME_STAGE_VERSION", "runtime-index-v1"}, {"ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v1"}},
		"agentsec-runtime-session-index-v2": {{"ZASP_RUNTIME_STAGE_VERSION", "runtime-index-v1"}, {"ZASP_RUNTIME_SESSION_INDEX", "zasp-runtime-sessions-v2"}},
		"agentsec-runtime-correlation":      {{"ZASP_RUNTIME_STAGE_VERSION", "runtime-correlation-v2"}},
		"agentsec-runtime-projection":       {{"ZASP_RUNTIME_STAGE_VERSION", "runtime-projection-v1"}},
		"agentsec-runtime-complete":         {{"ZASP_RUNTIME_STAGE_VERSION", "runtime-complete-v1"}},
	}
	expected := []any{}
	for _, name := range names {
		deployment := fullObservationClone(f.deployment)
		if name == "agentsec-api" {
			deployment = f.deployment
		}
		meta := deployment["metadata"].(map[string]any)
		meta["name"], meta["generation"] = name, float64(1)
		if name != "agentsec-api" {
			meta["uid"] = name + "-owned"
		}
		template := deployment["spec"].(map[string]any)["template"].(map[string]any)
		template["metadata"].(map[string]any)["labels"] = map[string]any{"app": name}
		container := template["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
		env := []any{}
		for _, entry := range selections[name] {
			env = append(env, map[string]any{"name": entry[0], "value": entry[1]})
		}
		container["env"] = env
		deployment["status"] = fullObservationStatus(1)
		body, err := json.Marshal(template)
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, map[string]any{"name": name, "templateDigest": composedHash(body), "imageIDs": map[string]string{"api": "docker-pullable://" + container["image"].(string)}})
		f.lists["deployment"] = append(f.lists["deployment"], deployment)
		set, pod := fullObservationReplica(deployment, name+"-rs", name+"-pod")
		f.lists["replicaset"] = append(f.lists["replicaset"], set)
		f.lists["pod"] = append(f.lists["pod"], pod)
	}
	body, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	f.expected = string(body)
	f.observationList = f.serveLists
	root := t.TempDir()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("Node22 required", err)
	}
	node, err = filepath.EvalSymlinks(node)
	if err != nil {
		t.Fatal(err)
	}
	f.log = filepath.Join(root, "kubectl-calls")
	kubectl := filepath.Join(root, "kubectl")
	program := "#!" + node + "\n" + fullObservationKubectl
	program = strings.NewReplacer("FIXTURE_SERVER", strconv.Quote(f.binding.KubernetesServer), "FIXTURE_CA", strconv.Quote(f.caPEM), "FIXTURE_LOG", strconv.Quote(f.log)).Replace(program)
	if err := os.WriteFile(kubectl, []byte(program), 0700); err != nil {
		t.Fatal(err)
	}
	base, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	f.observer, err = sandboxcutover.NewObservation(sandboxcutover.ObservationConfig{Binding: f.binding, ExpectedJSON: f.expected, CAPEM: f.caPEM, BearerToken: "owned-token", ReleaseDirectory: base, NodeExecutable: node, KubectlExecutable: kubectl})
	if err != nil {
		t.Fatal("real observation construction", err)
	}
	t.Cleanup(func() {
		if err := f.observer.Close(); err != nil {
			t.Error(err)
		}
		f.assertPrivateCleanup()
	})
	f.dependencies.Observer = f.observer
	return f
}

func fullObservationStatus(generation float64) map[string]any {
	return map[string]any{"observedGeneration": generation, "replicas": float64(1), "updatedReplicas": float64(1), "readyReplicas": float64(1), "availableReplicas": float64(1)}
}
func fullObservationReplica(deployment map[string]any, setID, podID string) (map[string]any, map[string]any) {
	dm := deployment["metadata"].(map[string]any)
	template := fullObservationClone(deployment["spec"].(map[string]any)["template"])
	owner := func(kind, name, uid string) []any {
		return []any{map[string]any{"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": true}}
	}
	set := map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": map[string]any{"name": setID, "uid": setID, "namespace": "agentsec", "generation": float64(1), "ownerReferences": owner("Deployment", dm["name"].(string), dm["uid"].(string))}, "spec": map[string]any{"replicas": float64(1), "template": template}, "status": fullObservationStatus(1)}
	meta := fullObservationClone(template["metadata"])
	meta["name"], meta["uid"], meta["namespace"], meta["ownerReferences"] = podID, podID, "agentsec", owner("ReplicaSet", setID, setID)
	image := template["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"].(string)
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": template["spec"], "status": map[string]any{"phase": "Running", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}, "containerStatuses": []any{map[string]any{"name": "api", "imageID": "docker-pullable://" + image, "ready": true, "state": map[string]any{"running": map[string]any{"startedAt": "2026-09-12T00:00:00Z"}}}}}}
	return set, pod
}

// Called under the same mutex as the single-object GET and conditional PATCH.
func (f *fullObservationFixture) serveLists(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Owned-Observation") != "full11" {
		return false
	}
	paths := map[string]string{"/api/v1/namespaces/agentsec": "namespace", "/apis/apps/v1/namespaces/agentsec/deployments": "deployment", "/apis/apps/v1/namespaces/agentsec/replicasets": "replicaset", "/api/v1/namespaces/agentsec/pods": "pod"}
	kind, ok := paths[r.URL.Path]
	if !ok || r.Method != "GET" || r.URL.RawQuery != "" {
		f.t.Error("unowned observation request", r.Method, r.URL)
		w.WriteHeader(400)
		return true
	}
	f.reads = append(f.reads, kind)
	if kind == "namespace" {
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": f.binding.Namespace, "uid": f.binding.NamespaceUID}})
	} else {
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "items": f.lists[kind]})
	}
	return true
}
func (f *fullObservationFixture) assertPrivateCleanup() {
	f.t.Helper()
	body, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		f.t.Error(err)
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var file string
		if json.Unmarshal([]byte(line), &file) != nil {
			f.t.Error("bad owned kubectl log")
			continue
		}
		if _, err := os.Stat(filepath.Dir(file)); !os.IsNotExist(err) {
			f.t.Error("private observation credential directory survived", file, err)
		}
	}
}

func TestSandboxCutoverComposedFullObservation(t *testing.T) {
	f := newFullObservationFixture(t)
	before := f.snapshot()
	r := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	want := []string{"namespace", "deployment", "replicaset", "pod", "namespace", "namespace", "deployment", "replicaset", "pod", "namespace"}
	if r.Outcome != sandboxcutover.Applied || !r.CleanupConfirmed || r.Audit.ReceiptCount != 1 || f.patches != 1 || f.accepted != 1 || !reflect.DeepEqual(f.reads, want) {
		t.Fatal("cutover did not compose two real full11 observations", r, f.reads, f.patches, f.accepted)
	}
	if f.snapshot() != before {
		t.Fatal("observation cutover changed canonical evidence")
	}
	f.assertPrivateCleanup()
}

func (f *fullObservationFixture) addOldAPIPod() {
	oldSet, oldPod := fullObservationReplica(f.deployment, "api-old-rs", "api-old-pod")
	oldSet["spec"].(map[string]any)["replicas"] = float64(0)
	oldSet["status"].(map[string]any)["replicas"] = float64(0)
	f.lists["replicaset"] = append(f.lists["replicaset"], oldSet)
	f.lists["pod"] = append(f.lists["pod"], oldPod)
}

func TestSandboxCutoverComposedFullObservationRefusesDrift(t *testing.T) {
	for _, fault := range []string{"old-api-pod", "missing-target2-worker", "fenced-resource-version", "fenced-worker-template"} {
		t.Run(fault, func(t *testing.T) {
			f := newFullObservationFixture(t)
			before := f.snapshot()
			mutate := func() {
				f.mu.Lock()
				defer f.mu.Unlock()
				switch fault {
				case "old-api-pod":
					f.addOldAPIPod()
				case "missing-target2-worker":
					f.lists["deployment"] = f.lists["deployment"][:10]
				case "fenced-resource-version":
					f.deployment["metadata"].(map[string]any)["resourceVersion"] = "changed-after-initial/~"
				case "fenced-worker-template":
					worker := f.lists["deployment"][4].(map[string]any)
					worker["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = "fixture/changed@sha256:" + strings.Repeat("b", 64)
				}
			}
			fenced := strings.HasPrefix(fault, "fenced-")
			if fenced {
				f.dependencies.Database = composedBeforeFence{f.database, mutate}
			} else {
				mutate()
			}
			r := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
			if r.Outcome != sandboxcutover.Refused || f.patches != 0 || f.accepted != 0 {
				t.Fatal("full11 drift authorized dispatch", r, f.patches)
			}
			if fenced {
				if !r.CleanupConfirmed || f.searches != 1 || len(f.reads) < 9 {
					t.Fatal("fenced drift did not reach fresh full11 revalidation", r, f.searches, f.reads)
				}
				cleanup, err := f.database.WithFence(f.ctx, f.binding, func(fence sandboxcutover.Fence) error { return fence.Ready(f.ctx) })
				if err != nil || !cleanup.CleanupConfirmed {
					t.Fatal("refusal left actual fence behind", cleanup, err)
				}
			} else if f.searches != 0 || len(f.reads) != 4 {
				t.Fatal("initial drift did not refuse at actual full11 validation", f.searches, f.reads)
			}
			if f.snapshot() != before {
				t.Fatal("drift refusal changed canonical evidence")
			}
			f.assertPrivateCleanup()
		})
	}
}

// Explicit test-owned controller progress, never an executor mutation or a live
// rollout claim. The API list retains the exact object mutated by the TLS CAS.
func (f *fullObservationFixture) advanceQueryController() {
	f.mu.Lock()
	defer f.mu.Unlock()
	meta := f.deployment["metadata"].(map[string]any)
	meta["generation"], meta["resourceVersion"] = float64(2), "query-controller-ready/~"
	f.deployment["status"] = fullObservationStatus(2)
	old := f.lists["replicaset"][0].(map[string]any)
	old["spec"].(map[string]any)["replicas"] = float64(0)
	old["status"] = map[string]any{"observedGeneration": float64(1), "replicas": float64(0), "readyReplicas": float64(0), "availableReplicas": float64(0)}
	set, pod := fullObservationReplica(f.deployment, "api-query-rs", "api-query-pod")
	f.lists["replicaset"] = append(f.lists["replicaset"], set)
	f.lists["pod"][0] = pod
}

func TestSandboxCutoverComposedObservedQueryRollout(t *testing.T) {
	f := newFullObservationFixture(t)
	before := f.snapshot()
	r := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	if r.Outcome != sandboxcutover.Applied || !r.CleanupConfirmed || f.patches != 1 {
		t.Fatal("initial observed cutover failed", r)
	}
	reads := len(f.reads)
	pending := sandboxcutover.ReconcileSandboxQueryRollout(f.ctx, f.binding, r.Audit, f.kubernetes, f.observer)
	if pending.Outcome != sandboxcutover.Applied || pending.Rollout != sandboxcutover.Pending || pending.Audit != r.Audit || len(f.reads) != reads+4 {
		t.Fatal("old API replicas became complete or lost applied state", pending, f.reads)
	}
	f.advanceQueryController()
	reads = len(f.reads)
	complete := sandboxcutover.ReconcileSandboxQueryRollout(f.ctx, f.binding, r.Audit, f.kubernetes, f.observer)
	want := []string{"namespace", "deployment", "replicaset", "pod", "namespace"}
	if complete.Outcome != sandboxcutover.Applied || complete.Rollout != sandboxcutover.Complete || complete.Audit != r.Audit || complete.ResultResourceVersion != "query-controller-ready/~" || !reflect.DeepEqual(f.reads[reads:], want) {
		t.Fatal("healthy full11 query rollout not reconciled", complete, f.reads[reads:])
	}
	reads = len(f.reads)
	f.mu.Lock()
	f.deployment["status"].(map[string]any)["conditions"] = []any{map[string]any{"type": "Progressing", "status": "False", "reason": "ProgressDeadlineExceeded"}}
	f.mu.Unlock()
	failed := sandboxcutover.ReconcileSandboxQueryRollout(f.ctx, f.binding, r.Audit, f.kubernetes, f.observer)
	if failed.Outcome != sandboxcutover.Applied || failed.Rollout != sandboxcutover.Failed || failed.Audit != r.Audit || len(f.reads) != reads {
		t.Fatal("current-generation failure was not applied/failed", failed)
	}
	again := sandboxcutover.ExecuteSandboxQueryCutover(f.ctx, sandboxcutover.Request{ReleaseReference: "owned-approved-fixture"}, f.dependencies)
	if again.Outcome != sandboxcutover.Refused {
		t.Fatal("fresh invocation accepted query deployment", again)
	}
	if f.patches != 1 || f.accepted != 1 || f.searches != 1 || f.snapshot() != before {
		t.Fatal("read-only rollout changed dispatch/provider/canonical evidence", f.patches, f.accepted, f.searches)
	}
	state, err := f.kubernetes.Reconcile(f.ctx, f.binding, r.Audit)
	if err != nil || state.Audit != r.Audit {
		t.Fatal("read-only rollout changed winning audit", state, err)
	}
	f.assertPrivateCleanup()
}

const fullObservationKubectl = `const fs=require('fs'),https=require('https'),assert=require('assert/strict'),path=require('path');
const a=process.argv.slice(2), routes={namespace:'/api/v1/namespaces/agentsec',deployment:'/apis/apps/v1/namespaces/agentsec/deployments',replicaset:'/apis/apps/v1/namespaces/agentsec/replicasets',pod:'/api/v1/namespaces/agentsec/pods'};
assert.equal(a[0],'--kubeconfig');assert.equal(a[2],'--context');assert.equal(a[3],'sandbox-cutover');assert.equal(a[4],'get');assert.ok(Object.hasOwn(routes,a[5]));
const tail=a[5]==='namespace'?['agentsec','--output=json']:['--namespace','agentsec','--output=json'];assert.deepEqual(a.slice(6,-1),tail);assert.match(a.at(-1),/^--request-timeout=(?:5s|[1-9][0-9]{0,3}ms)$/);
const requestTimeout=a.at(-1).endsWith('=5s')?5000:Number(a.at(-1).slice('--request-timeout='.length,-2));assert.ok(requestTimeout>0&&requestTimeout<=5000);
const k=JSON.parse(fs.readFileSync(a[1]));assert.equal(fs.statSync(a[1]).mode&511,384);assert.equal(fs.statSync(path.join(path.dirname(a[1]),'request.json')).mode&511,384);
assert.equal(k['current-context'],'sandbox-cutover');assert.equal(k.clusters.length,1);assert.equal(k.users.length,1);assert.equal(k.contexts.length,1);
const c=k.clusters[0].cluster;assert.deepEqual(Object.keys(c).sort(),['certificate-authority-data','server']);assert.equal(c.server,FIXTURE_SERVER);const ca=Buffer.from(c['certificate-authority-data'],'base64').toString();assert.equal(ca,FIXTURE_CA);
assert.deepEqual(k.users[0].user,{token:'owned-token'});assert.deepEqual(k.contexts[0].context,{cluster:'pinned',namespace:'agentsec',user:'pinned'});assert.equal(process.env.KUBECONFIG,undefined);assert.equal(process.env.NODE_OPTIONS,undefined);assert.equal(process.env.HOME,path.dirname(a[1]));
fs.appendFileSync(FIXTURE_LOG,JSON.stringify(a[1])+'\n');
const req=https.get(c.server+routes[a[5]],{ca,rejectUnauthorized:true,agent:false,headers:{Authorization:'Bearer '+k.users[0].user.token,'X-Owned-Observation':'full11'}},res=>{assert.equal(res.statusCode,200);let size=0;const chunks=[];res.on('data',chunk=>{size+=chunk.length;assert.ok(size<=4*1024*1024);chunks.push(chunk)});res.on('end',()=>process.stdout.write(Buffer.concat(chunks)))});
req.setTimeout(requestTimeout,()=>req.destroy(new Error('owned read timeout')));req.on('error',()=>{process.stderr.write('owned kubectl read rejected\n');process.exitCode=1});`
