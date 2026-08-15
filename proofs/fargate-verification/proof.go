package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

type ResourceKind string

const (
	KindNamespace      ResourceKind = "Namespace"
	KindServiceAccount ResourceKind = "ServiceAccount"
	KindSecret         ResourceKind = "Secret"
	KindJob            ResourceKind = "Job"
	KindPod            ResourceKind = "Pod"
	KindNode           ResourceKind = "Node"

	ProofLabelKey             = "zasp.agentsec.dev/proof"
	RunLabelKey               = "zasp.agentsec.dev/run"
	ProofLabelValue           = "m0-18"
	ProfileSelectorLabelKey   = "zasp.agentsec.dev/fargate"
	ProfileSelectorLabelValue = "true"
	FargateProfileLabelKey    = "eks.amazonaws.com/fargate-profile"
	NamespacePrefix           = "zasp-m018-"
	CanaryResponse            = "agentsec-attack-lab-canary-v1"
	CanaryImage               = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9"
	CanaryRuntimeImage        = "registry.k8s.io/e2e-test-images/busybox@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9"
	CanaryRuntimeImageAMD64   = "registry.k8s.io/e2e-test-images/busybox@sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb"
	CanaryRuntimeImageARM64   = "registry.k8s.io/e2e-test-images/busybox@sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303"
	readAttempts              = 2
	readBackoff               = 5 * time.Millisecond
)

var (
	ErrNotFound      = errors.New("not found")
	ErrConfiguration = errors.New("configuration rejected")
	ErrProvider      = errors.New("provider rejected")
	ErrScheduling    = errors.New("scheduling rejected")
	ErrCanary        = errors.New("canary rejected")
	ErrOwnership     = errors.New("ownership rejected")
	ErrCleanup       = errors.New("cleanup rejected")
	ErrDeadline      = errors.New("deadline rejected")
	ErrPanic         = errors.New("panic rejected")
)

var (
	markerPattern     = regexp.MustCompile(`^[a-f0-9]{32}$`)
	profilePattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	regionPattern     = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	providerIDPattern = regexp.MustCompile(`^aws:///([a-z0-9-]+)/fargate-[a-z0-9.-]+$`)
)

type MutationError struct {
	Cause     error
	Ambiguous bool
}

func (e *MutationError) Error() string {
	if e == nil || e.Cause == nil {
		return "mutation rejected"
	}
	return e.Cause.Error()
}

func (e *MutationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func AmbiguousMutation(cause error) error {
	return &MutationError{Cause: cause, Ambiguous: true}
}

type Resource struct {
	Kind           ResourceKind
	Namespace      string
	Name           string
	Labels         map[string]string
	SpecDigest     string
	OwnerUID       string
	Image          string
	ProfileName    string
	ServiceAccount string
	ProxyURL       string
	SecretValue    []byte
}

type ResourceRef struct {
	Kind      ResourceKind
	Namespace string
	Name      string
}

type ListQuery struct {
	Kind       ResourceKind
	Namespace  string
	NamePrefix string
	Labels     map[string]string
}

type ObjectState struct {
	Kind           ResourceKind
	Namespace      string
	Name           string
	UID            string
	Labels         map[string]string
	SpecDigest     string
	OwnerUID       string
	Phase          string
	ImageID        string
	RuntimeImageID string
	ProfileName    string
	NodeName       string
	ServiceAccount string
	ProviderID     string
	ComputeType    string
	Ready          bool
	Succeeded      int
	Failed         int
	ExitCode       int
}

type OwnedObject struct {
	Expected Resource
	State    ObjectState
}

type OwnedPod struct {
	State ObjectState
}

type ClusterBoundary interface {
	Create(context.Context, Resource) (ObjectState, error)
	Get(context.Context, ResourceRef) (ObjectState, error)
	List(context.Context, ListQuery) ([]ObjectState, error)
	Delete(context.Context, OwnedObject) error
	Logs(context.Context, OwnedPod) ([]byte, []byte, error)
}

type ProofOptions struct {
	Boundary       ClusterBoundary
	Marker         string
	Region         string
	FargateProfile string
	ProxyURL       string
	CanaryToken    []byte
	MainTimeout    time.Duration
	CleanupTimeout time.Duration
}

type ProofResult struct {
	Scheduled bool
	Canary    bool
	Cleanup   bool
}

type lifecycle struct {
	options   ProofOptions
	namespace string
	labels    map[string]string
	owned     []OwnedObject
	uncertain []Resource
	pod       *OwnedPod
}

func RunProof(parent context.Context, options ProofOptions) (result ProofResult, resultErr error) {
	if err := validateOptions(options); err != nil {
		return ProofResult{}, err
	}

	life := &lifecycle{
		options:   options,
		namespace: NamespacePrefix + options.Marker,
		labels: map[string]string{
			ProofLabelKey:           ProofLabelValue,
			RunLabelKey:             options.Marker,
			ProfileSelectorLabelKey: ProfileSelectorLabelValue,
		},
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			resultErr = ErrPanic
		}
		cleanupErr := life.cleanup()
		if cleanupErr != nil {
			result = ProofResult{}
			resultErr = cleanupErr
			return
		}
		if resultErr == nil {
			result.Cleanup = true
		}
	}()

	mainContext, cancel := context.WithTimeout(parent, options.MainTimeout)
	defer cancel()

	if mainContext.Err() != nil {
		return ProofResult{}, ErrDeadline
	}
	if err := life.requireGlobalAbsence(mainContext); err != nil {
		return ProofResult{}, err
	}
	resources := life.resources()
	for _, resource := range resources {
		if mainContext.Err() != nil {
			return ProofResult{}, ErrDeadline
		}
		owned, err := life.create(mainContext, resource)
		if err != nil {
			return ProofResult{}, err
		}
		life.owned = append(life.owned, owned)
	}

	if mainContext.Err() != nil {
		return ProofResult{}, ErrDeadline
	}
	if err := life.requireEvidence(mainContext); err != nil {
		return ProofResult{}, err
	}
	if err := mainContext.Err(); err != nil {
		return ProofResult{}, ErrDeadline
	}
	return ProofResult{Scheduled: true, Canary: true}, nil
}

func validateOptions(options ProofOptions) error {
	if options.Boundary == nil || !markerPattern.MatchString(options.Marker) ||
		!validCommercialRegion(options.Region) ||
		!profilePattern.MatchString(options.FargateProfile) ||
		len(options.CanaryToken) == 0 || len(options.CanaryToken) > 4096 ||
		options.MainTimeout <= 0 || options.CleanupTimeout <= 0 {
		return ErrConfiguration
	}
	parsed, err := url.Parse(options.ProxyURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return ErrConfiguration
	}
	return nil
}

func (life *lifecycle) resources() []Resource {
	labels := cloneStringMap(life.labels)
	secret := slices.Clone(life.options.CanaryToken)
	namespace := Resource{
		Kind:       KindNamespace,
		Name:       life.namespace,
		Labels:     cloneStringMap(labels),
		SpecDigest: digest("namespace", life.namespace),
	}
	serviceAccount := Resource{
		Kind:       KindServiceAccount,
		Namespace:  life.namespace,
		Name:       "canary",
		Labels:     cloneStringMap(labels),
		SpecDigest: digest("service-account", life.namespace, "canary", "automount=false"),
	}
	secretResource := Resource{
		Kind:        KindSecret,
		Namespace:   life.namespace,
		Name:        "canary",
		Labels:      cloneStringMap(labels),
		SpecDigest:  digest("secret", life.namespace, hex.EncodeToString(hashBytes(secret))),
		SecretValue: secret,
	}
	job := Resource{
		Kind:           KindJob,
		Namespace:      life.namespace,
		Name:           "canary",
		Labels:         cloneStringMap(labels),
		SpecDigest:     digest("job", life.namespace, CanarySpecVersion, CanarySecurityVersion, CanaryResponseVersion),
		Image:          CanaryImage,
		ProfileName:    life.options.FargateProfile,
		ServiceAccount: "canary",
		ProxyURL:       life.options.ProxyURL,
	}
	return []Resource{namespace, serviceAccount, secretResource, job}
}

const (
	CanarySpecVersion     = "canary-spec-v1"
	CanarySecurityVersion = "restricted-v1"
	CanaryResponseVersion = "exact-body-v1"
)

func (life *lifecycle) create(ctx context.Context, resource Resource) (OwnedObject, error) {
	life.uncertain = append(life.uncertain, resource)
	state, err := life.options.Boundary.Create(ctx, resource)
	if err == nil && exactResourceState(resource, state) {
		life.removeUncertain(resource)
		clear(resource.SecretValue)
		return OwnedObject{Expected: resource, State: state}, nil
	}
	if err != nil && !isAmbiguousMutation(err) {
		life.removeUncertain(resource)
		clear(resource.SecretValue)
		return OwnedObject{}, ErrProvider
	}
	owned, reconcileErr := life.reconcileResource(ctx, resource)
	clear(resource.SecretValue)
	if reconcileErr != nil {
		return OwnedObject{}, reconcileErr
	}
	life.removeUncertain(resource)
	return owned, nil
}

func (life *lifecycle) reconcileResource(reconcileContext context.Context, resource Resource) (OwnedObject, error) {
	for attempt := 0; attempt < readAttempts; attempt++ {
		state, err := life.options.Boundary.Get(reconcileContext, resourceRef(resource))
		if err == nil && exactResourceState(resource, state) {
			return OwnedObject{Expected: resource, State: state}, nil
		}
		if attempt+1 < readAttempts && !waitForRetry(reconcileContext) {
			break
		}
	}
	return OwnedObject{}, ErrOwnership
}

func (life *lifecycle) requireEvidence(ctx context.Context) error {
	jobOwned := life.owned[len(life.owned)-1]
	job, err := life.options.Boundary.Get(ctx, resourceRef(jobOwned.Expected))
	if err != nil || !exactOwnedState(jobOwned, job) || job.Phase != "Complete" || job.Succeeded != 1 || job.Failed != 0 {
		return ErrScheduling
	}
	pods, err := life.options.Boundary.List(ctx, ListQuery{
		Kind:      KindPod,
		Namespace: life.namespace,
		Labels:    cloneStringMap(life.labels),
	})
	if err != nil || len(pods) != 1 {
		return ErrScheduling
	}
	pod := pods[0]
	if pod.Kind != KindPod || pod.Namespace != life.namespace || pod.UID == "" ||
		!exactPodLabels(pod.Labels, life.labels, job.UID, job.Name, life.options.FargateProfile) || pod.OwnerUID != job.UID ||
		pod.Phase != "Succeeded" || pod.ExitCode != 0 || pod.ImageID != CanaryImage ||
		!exactCanaryRuntimeImage(pod.RuntimeImageID) ||
		pod.ProfileName != life.options.FargateProfile || pod.NodeName == "" || pod.ServiceAccount != "canary" {
		return ErrScheduling
	}
	node, err := life.options.Boundary.Get(ctx, ResourceRef{Kind: KindNode, Name: pod.NodeName})
	if err != nil || node.Kind != KindNode || node.Name != pod.NodeName || node.UID == "" ||
		!node.Ready || node.ComputeType != "fargate" || !providerInRegion(node.ProviderID, life.options.Region) {
		return ErrScheduling
	}
	ownedPod := OwnedPod{State: pod}
	stdout, stderr, err := life.options.Boundary.Logs(ctx, ownedPod)
	if err != nil || string(stdout) != CanaryResponse || len(stderr) != 0 {
		return ErrCanary
	}
	life.pod = &ownedPod
	return nil
}

func validCommercialRegion(region string) bool {
	return regionPattern.MatchString(region) && !strings.HasPrefix(region, "cn-") && !strings.HasPrefix(region, "us-gov-") && !strings.HasPrefix(region, "us-iso")
}

func providerInRegion(providerID, region string) bool {
	matches := providerIDPattern.FindStringSubmatch(providerID)
	if len(matches) != 2 {
		return false
	}
	zone := matches[1]
	return strings.HasPrefix(zone, region) && len(zone) == len(region)+1 && zone[len(region)] >= 'a' && zone[len(region)] <= 'z'
}

func exactCanaryRuntimeImage(value string) bool {
	for _, candidate := range []string{CanaryImage, CanaryRuntimeImage, CanaryRuntimeImageAMD64, CanaryRuntimeImageARM64} {
		if value == candidate || value == "docker-pullable://"+candidate {
			return true
		}
	}
	return false
}

func exactPodLabels(actual, required map[string]string, jobUID, jobName, profileName string) bool {
	for key, value := range required {
		if actual[key] != value {
			return false
		}
	}
	if actual[FargateProfileLabelKey] != profileName {
		return false
	}
	for key, value := range actual {
		if requiredValue, ok := required[key]; ok {
			if value != requiredValue {
				return false
			}
			continue
		}
		switch key {
		case "batch.kubernetes.io/controller-uid", "controller-uid":
			if value != jobUID {
				return false
			}
		case "batch.kubernetes.io/job-name", "job-name":
			if value != jobName {
				return false
			}
		case FargateProfileLabelKey:
			if value != profileName {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (life *lifecycle) cleanup() error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), life.options.CleanupTimeout)
	defer cancel()

	var cleanupErr error
	for _, resource := range slices.Clone(life.uncertain) {
		state, err := life.options.Boundary.Get(cleanupContext, resourceRef(resource))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil || !exactResourceState(resource, state) {
			cleanupErr = ErrCleanup
			continue
		}
		life.owned = append(life.owned, OwnedObject{Expected: resource, State: state})
	}

	for index := len(life.owned) - 1; index >= 0; index-- {
		owned := life.owned[index]
		current, err := life.options.Boundary.Get(cleanupContext, resourceRef(owned.Expected))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil || !exactOwnedState(owned, current) {
			cleanupErr = ErrCleanup
			continue
		}
		err = life.options.Boundary.Delete(cleanupContext, owned)
		if err != nil && !isAmbiguousMutation(err) {
			cleanupErr = ErrCleanup
			continue
		}
		if err := life.requireAbsent(cleanupContext, owned); err != nil {
			cleanupErr = ErrCleanup
		}
	}
	if err := life.requireGlobalAbsence(cleanupContext); err != nil {
		cleanupErr = ErrCleanup
	}
	return cleanupErr
}

func (life *lifecycle) requireAbsent(ctx context.Context, owned OwnedObject) error {
	for attempt := 0; attempt < readAttempts; attempt++ {
		state, err := life.options.Boundary.Get(ctx, resourceRef(owned.Expected))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err == nil && state.UID != owned.State.UID {
			return ErrCleanup
		}
		if attempt+1 < readAttempts && !waitForRetry(ctx) {
			break
		}
	}
	return ErrCleanup
}

func waitForRetry(ctx context.Context) bool {
	timer := time.NewTimer(readBackoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (life *lifecycle) requireGlobalAbsence(ctx context.Context) error {
	queries := []ListQuery{{Kind: KindNamespace, NamePrefix: NamespacePrefix}}
	for _, kind := range []ResourceKind{KindNamespace, KindServiceAccount, KindSecret, KindJob, KindPod} {
		queries = append(queries, ListQuery{Kind: kind, Labels: map[string]string{ProofLabelKey: ProofLabelValue}})
	}
	for _, query := range queries {
		states, err := life.options.Boundary.List(ctx, query)
		if err != nil || len(states) != 0 {
			return ErrOwnership
		}
	}
	return nil
}

func (life *lifecycle) removeUncertain(resource Resource) {
	for index := len(life.uncertain) - 1; index >= 0; index-- {
		candidate := life.uncertain[index]
		if candidate.Kind == resource.Kind && candidate.Namespace == resource.Namespace && candidate.Name == resource.Name {
			life.uncertain = append(life.uncertain[:index], life.uncertain[index+1:]...)
			return
		}
	}
}

func exactResourceState(resource Resource, state ObjectState) bool {
	return state.Kind == resource.Kind && state.Namespace == resource.Namespace && state.Name == resource.Name &&
		state.UID != "" && equalStringMap(state.Labels, resource.Labels) && state.SpecDigest == resource.SpecDigest &&
		state.OwnerUID == resource.OwnerUID && state.ImageID == resource.Image && state.ProfileName == resource.ProfileName
}

func exactOwnedState(owned OwnedObject, current ObjectState) bool {
	return exactResourceState(owned.Expected, current) && current.UID == owned.State.UID
}

func resourceRef(resource Resource) ResourceRef {
	return ResourceRef{Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
}

func isAmbiguousMutation(err error) bool {
	var mutationErr *MutationError
	return errors.As(err, &mutationErr) && mutationErr.Ambiguous
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func hashBytes(value []byte) []byte {
	hash := sha256.Sum256(value)
	return hash[:]
}

func digest(parts ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("sha256:%x", hash[:])
}
