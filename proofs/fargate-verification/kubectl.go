package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	kubectlReadAttempts  = 2
	kubectlReadBackoff   = 5 * time.Millisecond
	maxKubeconfigBytes   = 64 * 1024
	maxExecutableBytes   = 256 * 1024 * 1024
	specAnnotationKey    = "zasp.agentsec.dev/spec"
	imageAnnotationKey   = "zasp.agentsec.dev/image"
	profileAnnotationKey = "zasp.agentsec.dev/fargate-profile"
)

var contextNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type ProcessRequest struct {
	Executable string
	Args       []string
	Env        []string
	Stdin      []byte
	Timeout    time.Duration
	MaxOutput  int
}

type ProcessResult struct {
	Stdout         []byte
	Stderr         []byte
	ExitCode       int
	Attempted      bool
	Signaled       bool
	TimedOut       bool
	OutputExceeded bool
}

type ProcessRunner interface {
	Run(context.Context, ProcessRequest) (ProcessResult, error)
}

type KubectlBoundaryOptions struct {
	Executable      string
	KubeconfigPath  string
	Context         string
	ClusterName     string
	Region          string
	Runner          ProcessRunner
	ReadTimeout     time.Duration
	MutationTimeout time.Duration
	OutputLimit     int
}

type retainedRegularFile struct {
	path string
	real string
	info os.FileInfo
	hash [sha256.Size]byte
	max  int64
}

type KubectlBoundary struct {
	executable      retainedRegularFile
	kubeconfig      retainedRegularFile
	context         string
	runner          ProcessRunner
	readTimeout     time.Duration
	mutationTimeout time.Duration
	outputLimit     int
}

type kubeConfig struct {
	APIVersion     string              `yaml:"apiVersion"`
	Kind           string              `yaml:"kind"`
	Preferences    map[string]any      `yaml:"preferences"`
	CurrentContext string              `yaml:"current-context"`
	Clusters       []namedKubeCluster  `yaml:"clusters"`
	Contexts       []namedKubeContext  `yaml:"contexts"`
	Users          []namedKubeIdentity `yaml:"users"`
}

type namedKubeCluster struct {
	Name    string      `yaml:"name"`
	Cluster kubeCluster `yaml:"cluster"`
}

type kubeCluster struct {
	Server                   string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	TLSServerName            string `yaml:"tls-server-name,omitempty"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
	ProxyURL                 string `yaml:"proxy-url,omitempty"`
}

type namedKubeContext struct {
	Name    string      `yaml:"name"`
	Context kubeContext `yaml:"context"`
}

type kubeContext struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace,omitempty"`
}

type namedKubeIdentity struct {
	Name string       `yaml:"name"`
	User kubeIdentity `yaml:"user"`
}

type kubeIdentity struct {
	Token                 string         `yaml:"token,omitempty"`
	ClientCertificateData string         `yaml:"client-certificate-data,omitempty"`
	ClientKeyData         string         `yaml:"client-key-data,omitempty"`
	Exec                  map[string]any `yaml:"exec,omitempty"`
	AuthProvider          map[string]any `yaml:"auth-provider,omitempty"`
	TokenFile             string         `yaml:"tokenFile,omitempty"`
	Username              string         `yaml:"username,omitempty"`
	Password              string         `yaml:"password,omitempty"`
}

func NewKubectlBoundary(options KubectlBoundaryOptions) (*KubectlBoundary, error) {
	if options.Runner == nil || !contextNamePattern.MatchString(options.Context) || !contextNamePattern.MatchString(options.ClusterName) || !validCommercialRegion(options.Region) ||
		options.ReadTimeout <= 0 || options.MutationTimeout <= 0 || options.OutputLimit <= 0 || options.OutputLimit > 64*1024 {
		return nil, ErrConfiguration
	}
	executable, executableBytes, err := retainRegularFile(options.Executable, maxExecutableBytes, true)
	if err != nil || len(executableBytes) == 0 {
		return nil, ErrConfiguration
	}
	kubeconfig, kubeconfigBytes, err := retainRegularFile(options.KubeconfigPath, maxKubeconfigBytes, false)
	if err != nil || kubeconfig.info.Mode().Perm()&0o077 != 0 || validateKubeconfig(kubeconfigBytes, options.Context, options.ClusterName, options.Region) != nil {
		return nil, ErrConfiguration
	}
	clear(executableBytes)
	clear(kubeconfigBytes)
	return &KubectlBoundary{
		executable:      executable,
		kubeconfig:      kubeconfig,
		context:         options.Context,
		runner:          options.Runner,
		readTimeout:     options.ReadTimeout,
		mutationTimeout: options.MutationTimeout,
		outputLimit:     options.OutputLimit,
	}, nil
}

func retainRegularFile(path string, maxBytes int64, requireExecutable bool) (retainedRegularFile, []byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return retainedRegularFile{}, nil, ErrConfiguration
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxBytes {
		return retainedRegularFile{}, nil, ErrConfiguration
	}
	if requireExecutable && info.Mode().Perm()&0o111 == 0 {
		return retainedRegularFile{}, nil, ErrConfiguration
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(real) {
		return retainedRegularFile{}, nil, ErrConfiguration
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != info.Size() {
		return retainedRegularFile{}, nil, ErrConfiguration
	}
	return retainedRegularFile{path: path, real: real, info: info, hash: sha256.Sum256(data), max: maxBytes}, data, nil
}

func (retained retainedRegularFile) reprove() error {
	current, data, err := retainRegularFile(retained.path, retained.max, retained.info.Mode().Perm()&0o111 != 0)
	if err != nil {
		return ErrOwnership
	}
	defer clear(data)
	if current.real != retained.real || !os.SameFile(current.info, retained.info) || current.hash != retained.hash || current.info.Mode() != retained.info.Mode() {
		return ErrOwnership
	}
	return nil
}

func validateKubeconfig(data []byte, contextName, clusterName, region string) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var config kubeConfig
	if err := decoder.Decode(&config); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrConfiguration
	}
	if config.APIVersion != "v1" || config.Kind != "Config" || config.CurrentContext != contextName || len(config.Preferences) != 0 {
		return ErrConfiguration
	}
	contexts := make(map[string]kubeContext, len(config.Contexts))
	for _, item := range config.Contexts {
		if item.Name == "" || item.Context.Cluster == "" || item.Context.User == "" || item.Context.Namespace != "" {
			return ErrConfiguration
		}
		if _, exists := contexts[item.Name]; exists {
			return ErrConfiguration
		}
		contexts[item.Name] = item.Context
	}
	selected, ok := contexts[contextName]
	if !ok || selected.Cluster != clusterName {
		return ErrConfiguration
	}
	clusters := make(map[string]kubeCluster, len(config.Clusters))
	for _, item := range config.Clusters {
		if _, exists := clusters[item.Name]; exists || validateKubeCluster(item.Cluster, region) != nil {
			return ErrConfiguration
		}
		clusters[item.Name] = item.Cluster
	}
	if _, ok := clusters[selected.Cluster]; !ok {
		return ErrConfiguration
	}
	users := make(map[string]kubeIdentity, len(config.Users))
	for _, item := range config.Users {
		if _, exists := users[item.Name]; exists || validateKubeIdentity(item.User) != nil {
			return ErrConfiguration
		}
		users[item.Name] = item.User
	}
	if _, ok := users[selected.User]; !ok {
		return ErrConfiguration
	}
	return nil
}

func validateKubeCluster(cluster kubeCluster, region string) error {
	parsed, err := url.Parse(cluster.Server)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.Port() != "" || !validEKSClusterHost(parsed.Hostname(), region) ||
		cluster.InsecureSkipTLSVerify || cluster.ProxyURL != "" || cluster.TLSServerName != "" {
		return ErrConfiguration
	}
	decoded, err := base64.StdEncoding.DecodeString(cluster.CertificateAuthorityData)
	if err != nil || len(decoded) == 0 || len(decoded) > 64*1024 {
		return ErrConfiguration
	}
	clear(decoded)
	return nil
}

func validEKSClusterHost(host, region string) bool {
	regionExpression := regexp.QuoteMeta(region)
	legacy := regexp.MustCompile(`^[a-z0-9-]{10,64}\.[a-z0-9]{2,8}\.` + regionExpression + `\.eks\.amazonaws\.com$`)
	dualStack := regexp.MustCompile(`^[a-z0-9-]{10,64}\.eks-cluster\.` + regionExpression + `\.api\.aws$`)
	documentedDualStack := regexp.MustCompile(`^eks-cluster\.` + regionExpression + `\.api\.aws$`)
	return legacy.MatchString(host) || dualStack.MatchString(host) || documentedDualStack.MatchString(host)
}

func validateKubeIdentity(identity kubeIdentity) error {
	if len(identity.Exec) != 0 || len(identity.AuthProvider) != 0 || identity.TokenFile != "" || identity.Username != "" || identity.Password != "" {
		return ErrConfiguration
	}
	hasToken := identity.Token != ""
	hasCertificate := identity.ClientCertificateData != "" || identity.ClientKeyData != ""
	if hasToken == hasCertificate || containsControl(identity.Token) || len(identity.Token) > 16*1024 {
		return ErrConfiguration
	}
	if hasToken {
		return nil
	}
	certificate, certificateErr := base64.StdEncoding.DecodeString(identity.ClientCertificateData)
	key, keyErr := base64.StdEncoding.DecodeString(identity.ClientKeyData)
	defer clear(certificate)
	defer clear(key)
	if certificateErr != nil || keyErr != nil || len(certificate) == 0 || len(key) == 0 || len(certificate) > 64*1024 || len(key) > 64*1024 {
		return ErrConfiguration
	}
	return nil
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func (boundary *KubectlBoundary) baseArgs() []string {
	return []string{"--kubeconfig", boundary.kubeconfig.path, "--context", boundary.context, "--cache-dir="}
}

func (boundary *KubectlBoundary) request(ctx context.Context, mutation bool, args []string, stdin []byte) (ProcessResult, error) {
	if ctx.Err() != nil {
		return ProcessResult{}, ErrProvider
	}
	if boundary.executable.reprove() != nil || boundary.kubeconfig.reprove() != nil {
		return ProcessResult{}, ErrOwnership
	}
	timeout := boundary.readTimeout
	if mutation {
		timeout = boundary.mutationTimeout
	}
	request := ProcessRequest{
		Executable: boundary.executable.path,
		Args:       append(boundary.baseArgs(), args...),
		Env:        []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"},
		Stdin:      slices.Clone(stdin),
		Timeout:    timeout,
		MaxOutput:  boundary.outputLimit,
	}
	result, err := boundary.runner.Run(ctx, request)
	clear(request.Stdin)
	if err != nil || result.TimedOut || result.Signaled || result.OutputExceeded {
		if mutation && (result.Attempted || result.TimedOut || result.Signaled || result.OutputExceeded) {
			return ProcessResult{}, AmbiguousMutation(ErrProvider)
		}
		return ProcessResult{}, ErrProvider
	}
	if len(result.Stdout)+len(result.Stderr) > boundary.outputLimit {
		if mutation {
			return ProcessResult{}, AmbiguousMutation(ErrProvider)
		}
		return ProcessResult{}, ErrProvider
	}
	return result, nil
}

func (boundary *KubectlBoundary) Create(ctx context.Context, resource Resource) (ObjectState, error) {
	defer clear(resource.SecretValue)
	manifest, err := resourceManifest(resource)
	if err != nil {
		return ObjectState{}, ErrConfiguration
	}
	defer clear(manifest)
	result, err := boundary.request(ctx, true, []string{"create", "-f", "-", "-o", "json"}, manifest)
	if err != nil {
		return ObjectState{}, err
	}
	if result.ExitCode != 0 {
		return ObjectState{}, ErrProvider
	}
	if len(result.Stderr) != 0 {
		return ObjectState{}, AmbiguousMutation(ErrProvider)
	}
	state, err := parseKubernetesObject(result.Stdout)
	if err != nil {
		return ObjectState{}, AmbiguousMutation(ErrProvider)
	}
	return state, nil
}

func (boundary *KubectlBoundary) Get(ctx context.Context, reference ResourceRef) (ObjectState, error) {
	args, err := getArgs(reference)
	if err != nil {
		return ObjectState{}, ErrConfiguration
	}
	var lastErr error
	for attempt := 0; attempt < kubectlReadAttempts; attempt++ {
		result, requestErr := boundary.request(ctx, false, args, nil)
		if requestErr == nil && result.ExitCode == 0 && len(result.Stderr) == 0 && len(result.Stdout) == 0 {
			lastErr = ErrNotFound
		} else if requestErr == nil && result.ExitCode == 0 && len(result.Stderr) == 0 {
			state, parseErr := parseKubernetesObject(result.Stdout)
			if parseErr == nil {
				return state, nil
			}
			lastErr = ErrProvider
		} else if requestErr == nil && exactNotFound(result) {
			lastErr = ErrNotFound
		} else {
			lastErr = ErrProvider
		}
		if attempt+1 < kubectlReadAttempts && waitKubectlRead(ctx) {
			continue
		}
		break
	}
	return ObjectState{}, lastErr
}

func (boundary *KubectlBoundary) List(ctx context.Context, query ListQuery) ([]ObjectState, error) {
	args, err := listArgs(query)
	if err != nil {
		return nil, ErrConfiguration
	}
	for attempt := 0; attempt < kubectlReadAttempts; attempt++ {
		result, requestErr := boundary.request(ctx, false, args, nil)
		if requestErr == nil && result.ExitCode == 0 && len(result.Stderr) == 0 {
			states, parseErr := parseKubernetesList(result.Stdout, query.Kind)
			if parseErr == nil {
				filtered := make([]ObjectState, 0, len(states))
				for _, state := range states {
					if query.NamePrefix == "" || strings.HasPrefix(state.Name, query.NamePrefix) {
						filtered = append(filtered, state)
					}
				}
				return filtered, nil
			}
		}
		if attempt+1 < kubectlReadAttempts && waitKubectlRead(ctx) {
			continue
		}
		break
	}
	return nil, ErrProvider
}

func (boundary *KubectlBoundary) Delete(ctx context.Context, owned OwnedObject) error {
	current, err := boundary.Get(ctx, resourceRef(owned.Expected))
	if err != nil || !exactOwnedState(owned, current) {
		return ErrOwnership
	}
	rawPath, err := resourceURI(resourceRef(owned.Expected))
	if err != nil {
		return ErrConfiguration
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "DeleteOptions",
		"preconditions": map[string]string{
			"uid": owned.State.UID,
		},
		"propagationPolicy": "Foreground",
	})
	if err != nil {
		return ErrProvider
	}
	defer clear(body)
	result, err := boundary.request(ctx, true, []string{"delete", "--raw=" + rawPath, "-f", "-"}, body)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return ErrProvider
	}
	if len(result.Stderr) != 0 || !validDeleteStatus(result.Stdout) {
		return AmbiguousMutation(ErrProvider)
	}
	return nil
}

func (boundary *KubectlBoundary) Logs(ctx context.Context, pod OwnedPod) ([]byte, []byte, error) {
	if pod.State.Kind != KindPod || pod.State.Namespace == "" || pod.State.Name == "" || pod.State.UID == "" {
		return nil, nil, ErrConfiguration
	}
	current, err := boundary.Get(ctx, ResourceRef{Kind: KindPod, Namespace: pod.State.Namespace, Name: pod.State.Name})
	if err != nil || !equalPodState(pod.State, current) {
		return nil, nil, ErrOwnership
	}
	rawPath := "/api/v1/namespaces/" + url.PathEscape(pod.State.Namespace) + "/pods/" + url.PathEscape(pod.State.Name) + "/log?container=canary"
	result, err := boundary.request(ctx, false, []string{"get", "--raw=" + rawPath}, nil)
	if err != nil || result.ExitCode != 0 {
		return nil, nil, ErrProvider
	}
	return slices.Clone(result.Stdout), slices.Clone(result.Stderr), nil
}

func equalPodState(expected, current ObjectState) bool {
	return current.Kind == expected.Kind && current.Namespace == expected.Namespace && current.Name == expected.Name &&
		current.UID == expected.UID && equalStringMap(current.Labels, expected.Labels) &&
		current.OwnerUID == expected.OwnerUID && current.Phase == expected.Phase && current.ImageID == expected.ImageID &&
		current.RuntimeImageID == expected.RuntimeImageID && current.ProfileName == expected.ProfileName &&
		current.NodeName == expected.NodeName && current.ServiceAccount == expected.ServiceAccount && current.ExitCode == expected.ExitCode
}

func waitKubectlRead(ctx context.Context) bool {
	timer := time.NewTimer(kubectlReadBackoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func getArgs(reference ResourceRef) ([]string, error) {
	resource, err := kubectlResourceName(reference.Kind)
	if err != nil || reference.Name == "" || (reference.Kind != KindNamespace && reference.Kind != KindNode && reference.Namespace == "") {
		return nil, ErrConfiguration
	}
	args := []string{"get", resource, reference.Name}
	if reference.Namespace != "" {
		args = append(args, "--namespace", reference.Namespace)
	}
	return append(args, "--ignore-not-found=true", "-o", "json"), nil
}

func listArgs(query ListQuery) ([]string, error) {
	resource, err := kubectlResourceName(query.Kind)
	if err != nil {
		return nil, err
	}
	args := []string{"get", resource}
	if query.Namespace != "" {
		args = append(args, "--namespace", query.Namespace)
	} else if query.Kind != KindNamespace && query.Kind != KindNode {
		args = append(args, "--all-namespaces")
	}
	if len(query.Labels) != 0 {
		keys := make([]string, 0, len(query.Labels))
		for key := range query.Labels {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, key+"="+query.Labels[key])
		}
		args = append(args, "--selector", strings.Join(parts, ","))
	}
	return append(args, "-o", "json"), nil
}

func kubectlResourceName(kind ResourceKind) (string, error) {
	switch kind {
	case KindNamespace:
		return "namespaces", nil
	case KindServiceAccount:
		return "serviceaccounts", nil
	case KindSecret:
		return "secrets", nil
	case KindJob:
		return "jobs.batch", nil
	case KindPod:
		return "pods", nil
	case KindNode:
		return "nodes", nil
	default:
		return "", ErrConfiguration
	}
}

func resourceURI(reference ResourceRef) (string, error) {
	name := url.PathEscape(reference.Name)
	switch reference.Kind {
	case KindNamespace:
		return "/api/v1/namespaces/" + name, nil
	case KindServiceAccount:
		return "/api/v1/namespaces/" + url.PathEscape(reference.Namespace) + "/serviceaccounts/" + name, nil
	case KindSecret:
		return "/api/v1/namespaces/" + url.PathEscape(reference.Namespace) + "/secrets/" + name, nil
	case KindJob:
		return "/apis/batch/v1/namespaces/" + url.PathEscape(reference.Namespace) + "/jobs/" + name, nil
	default:
		return "", ErrConfiguration
	}
}

func resourceManifest(resource Resource) ([]byte, error) {
	metadata := map[string]any{
		"name":   resource.Name,
		"labels": resource.Labels,
		"annotations": map[string]string{
			specAnnotationKey:    resource.SpecDigest,
			imageAnnotationKey:   resource.Image,
			profileAnnotationKey: resource.ProfileName,
		},
	}
	if resource.Namespace != "" {
		metadata["namespace"] = resource.Namespace
	}
	var document map[string]any
	switch resource.Kind {
	case KindNamespace:
		document = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": metadata}
	case KindServiceAccount:
		document = map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata, "automountServiceAccountToken": false}
	case KindSecret:
		document = map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": metadata, "type": "Opaque", "stringData": map[string]string{"token": string(resource.SecretValue)}}
	case KindJob:
		templateLabels := cloneStringMap(resource.Labels)
		templateLabels[FargateProfileLabelKey] = resource.ProfileName
		document = map[string]any{
			"apiVersion": "batch/v1",
			"kind":       "Job",
			"metadata":   metadata,
			"spec": map[string]any{
				"backoffLimit":            0,
				"activeDeadlineSeconds":   120,
				"ttlSecondsAfterFinished": 60,
				"template": map[string]any{
					"metadata": map[string]any{
						"labels":      templateLabels,
						"annotations": map[string]string{imageAnnotationKey: resource.Image, profileAnnotationKey: resource.ProfileName},
					},
					"spec": map[string]any{
						"serviceAccountName":           resource.ServiceAccount,
						"automountServiceAccountToken": false,
						"enableServiceLinks":           false,
						"hostNetwork":                  false,
						"hostPID":                      false,
						"hostIPC":                      false,
						"restartPolicy":                "Never",
						"securityContext": map[string]any{
							"runAsNonRoot":   true,
							"runAsUser":      65534,
							"runAsGroup":     65534,
							"fsGroup":        65534,
							"seccompProfile": map[string]string{"type": "RuntimeDefault"},
						},
						"containers": []any{map[string]any{
							"name":            "canary",
							"image":           resource.Image,
							"imagePullPolicy": "IfNotPresent",
							"command":         []string{"sh", "-eu", "-c"},
							"args":            []string{`body="$(wget -qO- --header="Authorization: Bearer ${CANARY_TOKEN}" "${PROXY_URL}")"; test "${body}" = "` + CanaryResponse + `"; printf %s "${body}"`},
							"env": []any{
								map[string]any{"name": "PROXY_URL", "value": resource.ProxyURL},
								map[string]any{"name": "CANARY_TOKEN", "valueFrom": map[string]any{"secretKeyRef": map[string]string{"name": "canary", "key": "token"}}},
							},
							"resources":       map[string]any{"requests": map[string]string{"cpu": "10m", "memory": "16Mi"}, "limits": map[string]string{"cpu": "10m", "memory": "16Mi"}},
							"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true, "capabilities": map[string]any{"drop": []string{"ALL"}}},
						}},
					},
				},
			},
		}
	default:
		return nil, ErrConfiguration
	}
	return json.Marshal(document)
}

func parseUniqueJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := parseUniqueValue(decoder)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return nil, ErrProvider
	}
	return value, nil
}

func parseUniqueValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return nil, ErrProvider
				}
				if _, exists := object[key]; exists {
					return nil, ErrProvider
				}
				value, valueErr := parseUniqueValue(decoder)
				if valueErr != nil {
					return nil, valueErr
				}
				object[key] = value
			}
			if closing, closeErr := decoder.Token(); closeErr != nil || closing != json.Delim('}') {
				return nil, ErrProvider
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				value, valueErr := parseUniqueValue(decoder)
				if valueErr != nil {
					return nil, valueErr
				}
				array = append(array, value)
			}
			if closing, closeErr := decoder.Token(); closeErr != nil || closing != json.Delim(']') {
				return nil, ErrProvider
			}
			return array, nil
		}
	}
	return token, nil
}

func parseKubernetesObject(data []byte) (ObjectState, error) {
	value, err := parseUniqueJSON(data)
	if err != nil {
		return ObjectState{}, err
	}
	object, ok := value.(map[string]any)
	if !ok || !allowedKeys(object, "apiVersion", "kind", "metadata", "spec", "status", "automountServiceAccountToken", "type", "data", "immutable", "imagePullSecrets", "secrets") {
		return ObjectState{}, ErrProvider
	}
	kindName, ok := object["kind"].(string)
	if !ok {
		return ObjectState{}, ErrProvider
	}
	kind, err := resourceKind(kindName)
	if err != nil {
		return ObjectState{}, err
	}
	apiVersion, ok := object["apiVersion"].(string)
	if !ok || (kind == KindJob && apiVersion != "batch/v1") || (kind != KindJob && apiVersion != "v1") {
		return ObjectState{}, ErrProvider
	}
	metadata, ok := object["metadata"].(map[string]any)
	if !ok || !allowedKeys(metadata, "name", "generateName", "namespace", "uid", "labels", "annotations", "ownerReferences", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "finalizers", "managedFields", "selfLink") {
		return ObjectState{}, ErrProvider
	}
	state := ObjectState{Kind: kind}
	if state.Name, ok = metadata["name"].(string); !ok || state.Name == "" {
		return ObjectState{}, ErrProvider
	}
	state.Namespace, _ = metadata["namespace"].(string)
	if state.UID, ok = metadata["uid"].(string); !ok || state.UID == "" {
		return ObjectState{}, ErrProvider
	}
	if state.Labels, err = stringMap(metadata["labels"]); err != nil {
		return ObjectState{}, err
	}
	if state.Kind == KindNamespace {
		if value, exists := state.Labels["kubernetes.io/metadata.name"]; exists {
			if value != state.Name {
				return ObjectState{}, ErrProvider
			}
			delete(state.Labels, "kubernetes.io/metadata.name")
		}
	}
	annotations, err := stringMap(metadata["annotations"])
	if err != nil {
		return ObjectState{}, err
	}
	state.SpecDigest = annotations[specAnnotationKey]
	state.ImageID = annotations[imageAnnotationKey]
	state.ProfileName = annotations[profileAnnotationKey]
	if state.ProfileName == "" {
		state.ProfileName = state.Labels[FargateProfileLabelKey]
	}
	if owners, exists := metadata["ownerReferences"]; exists {
		ownerArray, arrayOK := owners.([]any)
		if !arrayOK || len(ownerArray) != 1 {
			return ObjectState{}, ErrProvider
		}
		owner, ownerOK := ownerArray[0].(map[string]any)
		if !ownerOK || !allowedKeys(owner, "apiVersion", "kind", "name", "uid", "controller", "blockOwnerDeletion") {
			return ObjectState{}, ErrProvider
		}
		state.OwnerUID, _ = owner["uid"].(string)
	}
	parseObjectSpecAndStatus(object, &state)
	return state, nil
}

func parseObjectSpecAndStatus(object map[string]any, state *ObjectState) {
	spec, _ := object["spec"].(map[string]any)
	status, _ := object["status"].(map[string]any)
	state.NodeName, _ = spec["nodeName"].(string)
	state.ServiceAccount, _ = spec["serviceAccountName"].(string)
	state.ProviderID, _ = spec["providerID"].(string)
	state.Phase, _ = status["phase"].(string)
	state.Succeeded = jsonInt(status["succeeded"])
	state.Failed = jsonInt(status["failed"])
	if state.Kind == KindJob && state.Succeeded == 1 && state.Failed == 0 {
		state.Phase = "Complete"
	}
	if state.Kind == KindPod {
		if containers, ok := spec["containers"].([]any); ok && len(containers) == 1 {
			container, _ := containers[0].(map[string]any)
			state.ImageID, _ = container["image"].(string)
		}
		if statuses, ok := status["containerStatuses"].([]any); ok && len(statuses) == 1 {
			container, _ := statuses[0].(map[string]any)
			if imageID, ok := container["imageID"].(string); ok && imageID != "" {
				state.RuntimeImageID = imageID
			}
			if containerState, ok := container["state"].(map[string]any); ok {
				if terminated, ok := containerState["terminated"].(map[string]any); ok {
					state.ExitCode = jsonInt(terminated["exitCode"])
				}
			}
		}
	}
	if state.Kind == KindNode {
		state.ComputeType = state.Labels["eks.amazonaws.com/compute-type"]
		if conditions, ok := status["conditions"].([]any); ok {
			for _, item := range conditions {
				condition, _ := item.(map[string]any)
				conditionType, _ := condition["type"].(string)
				conditionStatus, _ := condition["status"].(string)
				if conditionType == "Ready" && conditionStatus == "True" {
					state.Ready = true
				}
			}
		}
	}
}

func parseKubernetesList(data []byte, expectedKind ResourceKind) ([]ObjectState, error) {
	value, err := parseUniqueJSON(data)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok || !allowedKeys(object, "apiVersion", "kind", "metadata", "items") {
		return nil, ErrProvider
	}
	wantAPIVersion := "v1"
	if expectedKind == KindJob {
		wantAPIVersion = "batch/v1"
	}
	wantKind := string(expectedKind) + "List"
	if object["apiVersion"] != wantAPIVersion || object["kind"] != wantKind {
		return nil, ErrProvider
	}
	metadata, ok := object["metadata"].(map[string]any)
	if !ok || !allowedKeys(metadata, "resourceVersion", "continue", "remainingItemCount", "selfLink") {
		return nil, ErrProvider
	}
	items, ok := object["items"].([]any)
	if !ok {
		return nil, ErrProvider
	}
	states := make([]ObjectState, 0, len(items))
	for _, item := range items {
		encoded, marshalErr := json.Marshal(item)
		if marshalErr != nil {
			return nil, ErrProvider
		}
		state, parseErr := parseKubernetesObject(encoded)
		if parseErr != nil || state.Kind != expectedKind {
			return nil, parseErr
		}
		states = append(states, state)
	}
	return states, nil
}

func exactNotFound(result ProcessResult) bool {
	if result.ExitCode == 0 || len(result.Stdout) != 0 || len(result.Stderr) == 0 {
		return false
	}
	value, err := parseUniqueJSON(result.Stderr)
	if err != nil {
		return false
	}
	object, ok := value.(map[string]any)
	if !ok || !allowedKeys(object, "apiVersion", "kind", "status", "reason", "code", "message", "details", "metadata") {
		return false
	}
	return object["apiVersion"] == "v1" && object["kind"] == "Status" && object["status"] == "Failure" && object["reason"] == "NotFound" && jsonInt(object["code"]) == 404
}

func validDeleteStatus(data []byte) bool {
	value, err := parseUniqueJSON(data)
	if err != nil {
		return false
	}
	object, ok := value.(map[string]any)
	if !ok || !allowedKeys(object, "apiVersion", "kind", "status", "code", "message", "details", "metadata") {
		return false
	}
	return object["apiVersion"] == "v1" && object["kind"] == "Status" && object["status"] == "Success" && jsonInt(object["code"]) == 200
}

func allowedKeys(object map[string]any, allowed ...string) bool {
	for key := range object {
		if !slices.Contains(allowed, key) {
			return false
		}
	}
	return true
}

func stringMap(value any) (map[string]string, error) {
	if value == nil {
		return map[string]string{}, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrProvider
	}
	result := make(map[string]string, len(object))
	for key, raw := range object {
		text, textOK := raw.(string)
		if !textOK {
			return nil, ErrProvider
		}
		result[key] = text
	}
	return result, nil
}

func jsonInt(value any) int {
	number, ok := value.(json.Number)
	if !ok {
		return 0
	}
	parsed, err := number.Int64()
	if err != nil || parsed < 0 || parsed > 1<<31-1 {
		return 0
	}
	return int(parsed)
}

func resourceKind(value string) (ResourceKind, error) {
	switch value {
	case "Namespace":
		return KindNamespace, nil
	case "ServiceAccount":
		return KindServiceAccount, nil
	case "Secret":
		return KindSecret, nil
	case "Job":
		return KindJob, nil
	case "Pod":
		return KindPod, nil
	case "Node":
		return KindNode, nil
	default:
		return "", fmt.Errorf("%w: unknown kind", ErrProvider)
	}
}

type boundedProcessRunner struct{}

func NewBoundedProcessRunner() ProcessRunner {
	return boundedProcessRunner{}
}

type combinedOutput struct {
	mu       sync.Mutex
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	count    int
	limit    int
	exceeded chan struct{}
	once     sync.Once
}

type streamWriter struct {
	output *combinedOutput
	stderr bool
}

func (writer streamWriter) Write(data []byte) (int, error) {
	writer.output.mu.Lock()
	defer writer.output.mu.Unlock()
	if writer.output.count+len(data) > writer.output.limit {
		writer.output.once.Do(func() { close(writer.output.exceeded) })
		return 0, errors.New("output limit exceeded")
	}
	writer.output.count += len(data)
	if writer.stderr {
		return writer.output.stderr.Write(data)
	}
	return writer.output.stdout.Write(data)
}

func (boundedProcessRunner) Run(ctx context.Context, request ProcessRequest) (ProcessResult, error) {
	if !filepath.IsAbs(request.Executable) || request.Timeout <= 0 || request.MaxOutput <= 0 {
		return ProcessResult{}, ErrConfiguration
	}
	command := exec.Command(request.Executable, request.Args...)
	command.Env = slices.Clone(request.Env)
	command.Stdin = bytes.NewReader(request.Stdin)
	output := &combinedOutput{limit: request.MaxOutput, exceeded: make(chan struct{})}
	command.Stdout = streamWriter{output: output}
	command.Stderr = streamWriter{output: output, stderr: true}
	if err := command.Start(); err != nil {
		return ProcessResult{}, err
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	timer := time.NewTimer(request.Timeout)
	defer timer.Stop()
	result := ProcessResult{Attempted: true}
	var waitErr error
	select {
	case waitErr = <-waited:
	case <-ctx.Done():
		result.TimedOut = true
		_ = command.Process.Kill()
		waitErr = <-waited
	case <-timer.C:
		result.TimedOut = true
		_ = command.Process.Kill()
		waitErr = <-waited
	case <-output.exceeded:
		result.OutputExceeded = true
		_ = command.Process.Kill()
		waitErr = <-waited
	}
	output.mu.Lock()
	result.Stdout = slices.Clone(output.stdout.Bytes())
	result.Stderr = slices.Clone(output.stderr.Bytes())
	output.mu.Unlock()
	if command.ProcessState != nil {
		result.ExitCode = command.ProcessState.ExitCode()
		result.Signaled = result.ExitCode < 0
	}
	if waitErr != nil && result.ExitCode < 0 && !result.TimedOut && !result.OutputExceeded {
		result.Signaled = true
	}
	return result, nil
}
