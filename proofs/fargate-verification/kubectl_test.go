package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBoundedProcessHelper(t *testing.T) {
	if os.Getenv("ZASP_M018_PROCESS_HELPER") != "true" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "overflow":
		fmt.Print(strings.Repeat("x", 8192))
	case "timeout":
		time.Sleep(10 * time.Second)
	case "success":
		fmt.Print("ok")
		fmt.Fprint(os.Stderr, "notice")
	}
	os.Exit(0)
}

type fakeProcessRunner struct {
	requests []ProcessRequest
	results  []ProcessResult
	errors   []error
}

type kubectlModelRunner struct {
	requests []ProcessRequest
	objects  map[string]map[string]any
}

func newKubectlModelRunner() *kubectlModelRunner {
	return &kubectlModelRunner{objects: make(map[string]map[string]any)}
}

func (model *kubectlModelRunner) Run(_ context.Context, request ProcessRequest) (ProcessResult, error) {
	request.Args = slices.Clone(request.Args)
	request.Env = slices.Clone(request.Env)
	request.Stdin = slices.Clone(request.Stdin)
	model.requests = append(model.requests, request)
	if len(request.Args) < 6 {
		return ProcessResult{ExitCode: 1}, nil
	}
	args := request.Args[5:]
	switch args[0] {
	case "create":
		return model.create(request.Stdin)
	case "get":
		if strings.HasPrefix(args[1], "--raw=") {
			return ProcessResult{Stdout: []byte(CanaryResponse), ExitCode: 0}, nil
		}
		return model.get(args)
	case "delete":
		return model.delete(strings.TrimPrefix(args[1], "--raw="), request.Stdin)
	default:
		return ProcessResult{ExitCode: 1}, nil
	}
}

func (model *kubectlModelRunner) create(stdin []byte) (ProcessResult, error) {
	var object map[string]any
	if err := json.Unmarshal(stdin, &object); err != nil {
		return ProcessResult{ExitCode: 1}, nil
	}
	metadata := object["metadata"].(map[string]any)
	kind := object["kind"].(string)
	name := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	uid := "uid-" + strings.ToLower(kind)
	metadata["uid"] = uid
	delete(object, "stringData")
	if kind == "Secret" {
		object["data"] = map[string]any{"token": "redacted"}
	}
	if kind == "Job" {
		object["status"] = map[string]any{"succeeded": 1, "failed": 0}
		model.addPodAndNode(object, uid)
	}
	model.objects[modelKey(kind, namespace, name)] = object
	return jsonResult(object), nil
}

func (model *kubectlModelRunner) addPodAndNode(job map[string]any, jobUID string) {
	jobMetadata := job["metadata"].(map[string]any)
	jobSpec := job["spec"].(map[string]any)
	template := jobSpec["template"].(map[string]any)
	templateMetadata := template["metadata"].(map[string]any)
	templateSpec := template["spec"].(map[string]any)
	namespace := jobMetadata["namespace"].(string)
	name := jobMetadata["name"].(string) + "-pod"
	podLabels := make(map[string]any)
	for key, value := range templateMetadata["labels"].(map[string]any) {
		podLabels[key] = value
	}
	podLabels["batch.kubernetes.io/controller-uid"] = jobUID
	podLabels["batch.kubernetes.io/job-name"] = jobMetadata["name"]
	podLabels["controller-uid"] = jobUID
	podLabels["job-name"] = jobMetadata["name"]
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       namespace,
			"uid":             "uid-pod",
			"labels":          podLabels,
			"annotations":     templateMetadata["annotations"],
			"ownerReferences": []any{map[string]any{"apiVersion": "batch/v1", "kind": "Job", "name": jobMetadata["name"], "uid": jobUID, "controller": true, "blockOwnerDeletion": true}},
		},
		"spec": map[string]any{
			"nodeName":           "fargate-node",
			"serviceAccountName": templateSpec["serviceAccountName"],
			"containers":         templateSpec["containers"],
		},
		"status": map[string]any{
			"phase": "Succeeded",
			"containerStatuses": []any{map[string]any{
				"imageID": CanaryImage,
				"state":   map[string]any{"terminated": map[string]any{"exitCode": 0}},
			}},
		},
	}
	node := map[string]any{
		"apiVersion": "v1",
		"kind":       "Node",
		"metadata": map[string]any{
			"name":        "fargate-node",
			"uid":         "uid-node",
			"labels":      map[string]any{"eks.amazonaws.com/compute-type": "fargate"},
			"annotations": map[string]any{},
		},
		"spec":   map[string]any{"providerID": "aws:///us-west-2a/fargate-node"},
		"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
	}
	model.objects[modelKey("Pod", namespace, name)] = pod
	model.objects[modelKey("Node", "", "fargate-node")] = node
}

func (model *kubectlModelRunner) get(args []string) (ProcessResult, error) {
	resource := args[1]
	kind := modelKind(resource)
	if len(args) > 2 && args[2] != "--all-namespaces" && args[2] != "--namespace" && args[2] != "--selector" && args[2] != "-o" {
		name := args[2]
		namespace := argumentValue(args, "--namespace")
		object, ok := model.objects[modelKey(kind, namespace, name)]
		if !ok {
			return modelNotFound(), nil
		}
		return jsonResult(object), nil
	}
	namespace := argumentValue(args, "--namespace")
	selector := argumentValue(args, "--selector")
	items := make([]any, 0)
	for _, object := range model.objects {
		if object["kind"] != kind {
			continue
		}
		metadata := object["metadata"].(map[string]any)
		objectNamespace, _ := metadata["namespace"].(string)
		if namespace != "" && objectNamespace != namespace {
			continue
		}
		if !matchesSelector(metadata, selector) {
			continue
		}
		items = append(items, object)
	}
	apiVersion := "v1"
	if kind == "Job" {
		apiVersion = "batch/v1"
	}
	return jsonResult(map[string]any{"apiVersion": apiVersion, "kind": kind + "List", "metadata": map[string]any{}, "items": items}), nil
}

func (model *kubectlModelRunner) delete(rawPath string, stdin []byte) (ProcessResult, error) {
	segments := strings.Split(strings.Trim(rawPath, "/"), "/")
	var kind, namespace, name string
	switch {
	case len(segments) == 4 && segments[0] == "api" && segments[2] == "namespaces":
		kind, name = "Namespace", segments[3]
	case len(segments) == 6 && segments[0] == "api" && segments[2] == "namespaces":
		namespace, name = segments[3], segments[5]
		kind = map[string]string{"serviceaccounts": "ServiceAccount", "secrets": "Secret"}[segments[4]]
	case len(segments) == 7 && segments[0] == "apis" && segments[2] == "v1" && segments[3] == "namespaces":
		kind, namespace, name = "Job", segments[4], segments[6]
	}
	object, ok := model.objects[modelKey(kind, namespace, name)]
	if !ok {
		return modelNotFound(), nil
	}
	var options map[string]any
	if json.Unmarshal(stdin, &options) != nil {
		return ProcessResult{ExitCode: 1}, nil
	}
	uid := options["preconditions"].(map[string]any)["uid"]
	if object["metadata"].(map[string]any)["uid"] != uid {
		return ProcessResult{ExitCode: 1}, nil
	}
	delete(model.objects, modelKey(kind, namespace, name))
	if kind == "Job" {
		delete(model.objects, modelKey("Pod", namespace, name+"-pod"))
	}
	if kind == "Namespace" {
		delete(model.objects, modelKey("Node", "", "fargate-node"))
	}
	return jsonResult(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Success", "code": 200}), nil
}

func modelKey(kind, namespace, name string) string { return kind + "/" + namespace + "/" + name }

func modelKind(resource string) string {
	return map[string]string{"namespaces": "Namespace", "serviceaccounts": "ServiceAccount", "secrets": "Secret", "jobs.batch": "Job", "pods": "Pod", "nodes": "Node"}[resource]
}

func argumentValue(args []string, name string) string {
	for index := range args {
		if args[index] == name && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

func matchesSelector(metadata map[string]any, selector string) bool {
	if selector == "" {
		return true
	}
	labels, _ := metadata["labels"].(map[string]any)
	for _, part := range strings.Split(selector, ",") {
		pieces := strings.SplitN(part, "=", 2)
		if len(pieces) != 2 || labels[pieces[0]] != pieces[1] {
			return false
		}
	}
	return true
}

func jsonResult(value any) ProcessResult {
	data, _ := json.Marshal(value)
	return ProcessResult{Stdout: data, ExitCode: 0}
}

func modelNotFound() ProcessResult {
	data, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": "NotFound", "code": 404})
	return ProcessResult{Stderr: data, ExitCode: 1}
}

func (f *fakeProcessRunner) Run(_ context.Context, request ProcessRequest) (ProcessResult, error) {
	request.Args = slices.Clone(request.Args)
	request.Env = slices.Clone(request.Env)
	request.Stdin = slices.Clone(request.Stdin)
	f.requests = append(f.requests, request)
	index := len(f.requests) - 1
	if index >= len(f.results) {
		return ProcessResult{}, errors.New("unexpected process request")
	}
	var err error
	if index < len(f.errors) {
		err = f.errors[index]
	}
	return f.results[index], err
}

func writeBoundaryFixture(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	executable := filepath.Join(directory, "kubectl")
	if err := os.WriteFile(executable, []byte("fixture"), 0o500); err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(directory, "kubeconfig")
	content := `{
  "apiVersion":"v1",
  "kind":"Config",
  "preferences":{},
  "current-context":"proof",
  "clusters":[{"name":"cluster","cluster":{"server":"https://cluster.example.test","certificate-authority-data":"Y2E="}}],
  "contexts":[{"name":"proof","context":{"cluster":"cluster","user":"proof-user"}}],
  "users":[{"name":"proof-user","user":{"token":"synthetic-static-token"}}]
}`
	if err := os.WriteFile(kubeconfig, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return executable, kubeconfig
}

func newFixtureBoundary(t *testing.T, runner ProcessRunner) *KubectlBoundary {
	t.Helper()
	executable, kubeconfig := writeBoundaryFixture(t)
	boundary, err := NewKubectlBoundary(KubectlBoundaryOptions{
		Executable:      executable,
		KubeconfigPath:  kubeconfig,
		Context:         "proof",
		ClusterName:     "cluster",
		Runner:          runner,
		ReadTimeout:     time.Second,
		MutationTimeout: time.Second,
		OutputLimit:     16 * 1024,
	})
	if err != nil {
		t.Fatalf("NewKubectlBoundary: %v", err)
	}
	return boundary
}

func stateJSON(kind, namespace, name, uid, specDigest string, labels map[string]string) string {
	labelParts := make([]string, 0, len(labels))
	for key, value := range labels {
		labelParts = append(labelParts, `"`+key+`":"`+value+`"`)
	}
	slices.Sort(labelParts)
	return `{"apiVersion":"v1","kind":"` + kind + `","metadata":{"name":"` + name + `","namespace":"` + namespace + `","uid":"` + uid + `","labels":{` + strings.Join(labelParts, ",") + `},"annotations":{"zasp.agentsec.dev/spec":"` + specDigest + `"}}}`
}

func TestKubectlBoundaryCreateAndDeleteContract(t *testing.T) {
	labels := map[string]string{ProofLabelKey: ProofLabelValue, RunLabelKey: strings.Repeat("a", 32), ProfileSelectorLabelKey: ProfileSelectorLabelValue}
	resource := Resource{Kind: KindSecret, Namespace: NamespacePrefix + strings.Repeat("a", 32), Name: "canary", Labels: labels, SpecDigest: digest("secret"), SecretValue: []byte("secret-not-argv")}
	runner := &fakeProcessRunner{results: []ProcessResult{
		{Stdout: []byte(stateJSON("Secret", resource.Namespace, resource.Name, "uid-secret", resource.SpecDigest, labels)), ExitCode: 0},
		{Stdout: []byte(stateJSON("Secret", resource.Namespace, resource.Name, "uid-secret", resource.SpecDigest, labels)), ExitCode: 0},
		{Stdout: []byte(`{"apiVersion":"v1","kind":"Status","status":"Success","code":200}`), ExitCode: 0},
	}}
	boundary := newFixtureBoundary(t, runner)

	state, err := boundary.Create(context.Background(), resource)
	if err != nil || state.UID != "uid-secret" {
		t.Fatalf("Create state=%#v err=%v", state, err)
	}
	if strings.Contains(strings.Join(runner.requests[0].Args, " ")+strings.Join(runner.requests[0].Env, " "), "secret-not-argv") || !strings.Contains(string(runner.requests[0].Stdin), "secret-not-argv") {
		t.Fatal("secret was not confined to manifest stdin")
	}
	if slices.ContainsFunc(resource.SecretValue, func(value byte) bool { return value != 0 }) {
		t.Fatal("secret input was not zeroed after the process call")
	}
	wantPrefix := []string{"--kubeconfig", boundary.kubeconfig.path, "--context", "proof", "--cache-dir=", "create", "-f", "-", "-o", "json"}
	if !slices.Equal(runner.requests[0].Args, wantPrefix) {
		t.Fatalf("create args=%#v want=%#v", runner.requests[0].Args, wantPrefix)
	}
	if err := boundary.Delete(context.Background(), OwnedObject{Expected: resource, State: state}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	deleteRequest := runner.requests[2]
	if !strings.Contains(strings.Join(deleteRequest.Args, " "), "delete --raw=/api/v1/namespaces/") || !strings.Contains(string(deleteRequest.Stdin), `"uid":"uid-secret"`) {
		t.Fatalf("delete did not carry exact UID precondition: args=%#v stdin=%s", deleteRequest.Args, deleteRequest.Stdin)
	}
}

func TestKubectlBoundaryReadRetryAndStrictJSON(t *testing.T) {
	labels := map[string]string{ProofLabelKey: ProofLabelValue, RunLabelKey: strings.Repeat("a", 32), ProfileSelectorLabelKey: ProfileSelectorLabelValue}
	ref := ResourceRef{Kind: KindServiceAccount, Namespace: NamespacePrefix + strings.Repeat("a", 32), Name: "canary"}
	runner := &fakeProcessRunner{results: []ProcessResult{
		{ExitCode: 1, Stderr: []byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}`)},
		{Stdout: []byte(stateJSON("ServiceAccount", ref.Namespace, ref.Name, "uid-sa", digest("sa"), labels)), ExitCode: 0},
	}}
	boundary := newFixtureBoundary(t, runner)
	state, err := boundary.Get(context.Background(), ref)
	if err != nil || state.UID != "uid-sa" || len(runner.requests) != 2 {
		t.Fatalf("Get state=%#v err=%v requests=%d", state, err, len(runner.requests))
	}

	duplicate := &fakeProcessRunner{results: []ProcessResult{{Stdout: []byte(`{"apiVersion":"v1","kind":"ServiceAccount","kind":"ServiceAccount","metadata":{}}`), ExitCode: 0}}}
	boundary = newFixtureBoundary(t, duplicate)
	if _, err := boundary.Get(context.Background(), ref); !errors.Is(err, ErrProvider) {
		t.Fatalf("duplicate JSON error=%v, want provider", err)
	}
}

func TestKubectlBoundaryFiltersGlobalNamePrefixAfterBoundedList(t *testing.T) {
	labels := map[string]string{}
	matching := stateJSON("Namespace", "", NamespacePrefix+strings.Repeat("a", 32), "uid-match", digest("match"), labels)
	unrelated := stateJSON("Namespace", "", "default", "uid-default", digest("default"), labels)
	runner := &fakeProcessRunner{results: []ProcessResult{{Stdout: []byte(`{"apiVersion":"v1","kind":"NamespaceList","metadata":{},"items":[` + matching + `,` + unrelated + `]}`), ExitCode: 0}}}
	boundary := newFixtureBoundary(t, runner)
	states, err := boundary.List(context.Background(), ListQuery{Kind: KindNamespace, NamePrefix: NamespacePrefix})
	if err != nil || len(states) != 1 || states[0].Name != NamespacePrefix+strings.Repeat("a", 32) {
		t.Fatalf("states=%#v err=%v", states, err)
	}
}

func TestKubernetesNamespaceProjectionBindsAutomaticNameLabel(t *testing.T) {
	name := NamespacePrefix + strings.Repeat("a", 32)
	labels := map[string]string{ProofLabelKey: ProofLabelValue, "kubernetes.io/metadata.name": name}
	state, err := parseKubernetesObject([]byte(stateJSON("Namespace", "", name, "uid-namespace", digest("namespace"), labels)))
	if err != nil || state.Labels[ProofLabelKey] != ProofLabelValue {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	if _, exists := state.Labels["kubernetes.io/metadata.name"]; exists {
		t.Fatal("server-owned namespace label crossed the normalized ownership projection")
	}
	labels["kubernetes.io/metadata.name"] = "different"
	if _, err := parseKubernetesObject([]byte(stateJSON("Namespace", "", name, "uid-namespace", digest("namespace"), labels))); !errors.Is(err, ErrProvider) {
		t.Fatalf("mismatched automatic label error=%v", err)
	}
}

func TestKubectlBoundaryRejectsUnsafeConfiguration(t *testing.T) {
	executable, kubeconfig := writeBoundaryFixture(t)
	data, err := os.ReadFile(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	unsafe := strings.Replace(string(data), `"token":"synthetic-static-token"`, `"exec":{"command":"aws"}`, 1)
	if err := os.WriteFile(kubeconfig, []byte(unsafe), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewKubectlBoundary(KubectlBoundaryOptions{Executable: executable, KubeconfigPath: kubeconfig, Context: "proof", ClusterName: "cluster", Runner: &fakeProcessRunner{}})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("unsafe kubeconfig error=%v, want configuration", err)
	}
}

func TestKubectlBoundaryBindsExpectedClusterName(t *testing.T) {
	executable, kubeconfig := writeBoundaryFixture(t)
	_, err := NewKubectlBoundary(KubectlBoundaryOptions{
		Executable: executable, KubeconfigPath: kubeconfig, Context: "proof", ClusterName: "different-cluster",
		Runner: &fakeProcessRunner{}, ReadTimeout: time.Second, MutationTimeout: time.Second, OutputLimit: 1024,
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("cluster mismatch error=%v, want configuration", err)
	}
}

func TestKubectlBoundaryMutationClassificationAndIdentity(t *testing.T) {
	labels := map[string]string{ProofLabelKey: ProofLabelValue, RunLabelKey: strings.Repeat("a", 32), ProfileSelectorLabelKey: ProfileSelectorLabelValue}
	resource := Resource{Kind: KindNamespace, Name: NamespacePrefix + strings.Repeat("a", 32), Labels: labels, SpecDigest: digest("namespace")}

	t.Run("definitive rejection is single attempt", func(t *testing.T) {
		runner := &fakeProcessRunner{results: []ProcessResult{{ExitCode: 1, Stderr: []byte(`{"kind":"Status","reason":"Forbidden"}`)}}}
		boundary := newFixtureBoundary(t, runner)
		if _, err := boundary.Create(context.Background(), resource); !errors.Is(err, ErrProvider) || isAmbiguousMutation(err) {
			t.Fatalf("Create error=%v", err)
		}
		if len(runner.requests) != 1 {
			t.Fatalf("mutation attempts=%d, want 1", len(runner.requests))
		}
	})

	t.Run("thrown outcome is ambiguous", func(t *testing.T) {
		runner := &fakeProcessRunner{results: []ProcessResult{{Attempted: true}}, errors: []error{errors.New("pipe failed")}}
		boundary := newFixtureBoundary(t, runner)
		if _, err := boundary.Create(context.Background(), resource); !isAmbiguousMutation(err) {
			t.Fatalf("Create error=%v, want ambiguity", err)
		}
	})

	t.Run("pre-start rejection is definitive and never adopted", func(t *testing.T) {
		runner := &fakeProcessRunner{results: []ProcessResult{{}}, errors: []error{errors.New("start failed")}}
		boundary := newFixtureBoundary(t, runner)
		if _, err := boundary.Create(context.Background(), resource); !errors.Is(err, ErrProvider) || isAmbiguousMutation(err) {
			t.Fatalf("Create error=%v, want definitive provider", err)
		}
	})

	t.Run("pre-canceled context never reaches process boundary", func(t *testing.T) {
		runner := &fakeProcessRunner{results: []ProcessResult{{}}}
		boundary := newFixtureBoundary(t, runner)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := boundary.Create(ctx, resource); !errors.Is(err, ErrProvider) || isAmbiguousMutation(err) {
			t.Fatalf("Create error=%v, want definitive provider", err)
		}
		if len(runner.requests) != 0 {
			t.Fatalf("canceled mutation reached process boundary: %d calls", len(runner.requests))
		}
	})

	t.Run("replacement executable is rejected before process call", func(t *testing.T) {
		runner := &fakeProcessRunner{results: []ProcessResult{{}}}
		boundary := newFixtureBoundary(t, runner)
		replacement := boundary.executable.path + ".replacement"
		if err := os.WriteFile(replacement, []byte("replacement"), 0o500); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, boundary.executable.path); err != nil {
			t.Fatal(err)
		}
		if _, err := boundary.Create(context.Background(), resource); !errors.Is(err, ErrOwnership) {
			t.Fatalf("Create error=%v, want ownership", err)
		}
		if len(runner.requests) != 0 {
			t.Fatalf("replacement reached process boundary: %d calls", len(runner.requests))
		}
	})
}

func TestBoundedProcessRunnerHardBounds(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := NewBoundedProcessRunner()
	base := ProcessRequest{
		Executable: executable,
		Env:        []string{"ZASP_M018_PROCESS_HELPER=true"},
		Timeout:    5 * time.Second,
		MaxOutput:  1024,
	}

	t.Run("combined output cap kills and reaps", func(t *testing.T) {
		request := base
		request.Args = []string{"-test.run=^TestBoundedProcessHelper$", "--", "overflow"}
		result, err := runner.Run(context.Background(), request)
		if err != nil || !result.OutputExceeded || result.TimedOut {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})

	t.Run("deadline kills and reaps", func(t *testing.T) {
		request := base
		request.Args = []string{"-test.run=^TestBoundedProcessHelper$", "--", "timeout"}
		request.Timeout = 50 * time.Millisecond
		started := time.Now()
		result, err := runner.Run(context.Background(), request)
		if err != nil || !result.TimedOut || time.Since(started) > time.Second {
			t.Fatalf("result=%#v elapsed=%s err=%v", result, time.Since(started), err)
		}
	})

	t.Run("stdout and stderr remain separated", func(t *testing.T) {
		request := base
		request.Args = []string{"-test.run=^TestBoundedProcessHelper$", "--", "success"}
		result, err := runner.Run(context.Background(), request)
		if err != nil || string(result.Stdout) != "ok" || string(result.Stderr) != "notice" || result.ExitCode != 0 {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})
}

func TestRunProofThroughKubectlBoundary(t *testing.T) {
	model := newKubectlModelRunner()
	boundary := newFixtureBoundary(t, model)
	options := happyOptions(boundary)
	result, err := RunProof(context.Background(), options)
	if err != nil || !result.Scheduled || !result.Canary || !result.Cleanup {
		t.Fatalf("RunProof result=%#v err=%v", result, err)
	}
	if len(model.objects) != 0 {
		t.Fatalf("model retained objects: %#v", model.objects)
	}
	for _, request := range model.requests {
		joined := strings.Join(request.Args, " ") + strings.Join(request.Env, " ")
		if strings.Contains(joined, string(options.CanaryToken)) {
			t.Fatal("canary token crossed argv/environment boundary")
		}
	}
}

func TestJobManifestUsesExactRestrictedFargateWorkload(t *testing.T) {
	labels := map[string]string{ProofLabelKey: ProofLabelValue, RunLabelKey: strings.Repeat("a", 32), ProfileSelectorLabelKey: ProfileSelectorLabelValue}
	resource := Resource{
		Kind: KindJob, Namespace: NamespacePrefix + strings.Repeat("a", 32), Name: "canary", Labels: labels,
		SpecDigest: digest("job"), Image: CanaryImage, ProfileName: "proof-profile", ServiceAccount: "canary",
		ProxyURL: "https://proxy.example.test/canary",
	}
	manifest, err := resourceManifest(resource)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(manifest, &document); err != nil {
		t.Fatal(err)
	}
	spec := document["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	templateLabels := document["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["labels"].(map[string]any)
	if templateLabels[FargateProfileLabelKey] != "proof-profile" {
		t.Fatalf("Fargate profile label=%#v", templateLabels)
	}
	security := spec["securityContext"].(map[string]any)
	if security["runAsNonRoot"] != true || security["runAsUser"] != float64(65534) || security["runAsGroup"] != float64(65534) || security["fsGroup"] != float64(65534) {
		t.Fatalf("pod securityContext=%#v", security)
	}
	if spec["automountServiceAccountToken"] != false || spec["hostNetwork"] != false || spec["hostPID"] != false || spec["hostIPC"] != false || spec["enableServiceLinks"] != false {
		t.Fatalf("pod isolation fields=%#v", spec)
	}
	containers := spec["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("containers=%d", len(containers))
	}
	container := containers[0].(map[string]any)
	containerSecurity := container["securityContext"].(map[string]any)
	if container["image"] != CanaryImage || container["imagePullPolicy"] != "IfNotPresent" || containerSecurity["readOnlyRootFilesystem"] != true || containerSecurity["allowPrivilegeEscalation"] != false {
		t.Fatalf("container=%#v", container)
	}
	if _, exists := spec["volumes"]; exists {
		t.Fatal("unexpected volumes")
	}
}
