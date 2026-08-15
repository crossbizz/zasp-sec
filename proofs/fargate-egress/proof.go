package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

type ResourceKind string

const (
	KindNamespace           ResourceKind = "Namespace"
	KindServiceAccount      ResourceKind = "ServiceAccount"
	KindSecret              ResourceKind = "Secret"
	KindSecurityGroupPolicy ResourceKind = "SecurityGroupPolicy"
	KindJob                 ResourceKind = "Job"
	KindPod                 ResourceKind = "Pod"
	KindNode                ResourceKind = "Node"

	ProofLabelKey             = "zasp.agentsec.dev/proof"
	RunLabelKey               = "zasp.agentsec.dev/run"
	ProofLabelValue           = "m0-19"
	ProfileSelectorLabelKey   = "zasp.agentsec.dev/fargate"
	ProfileSelectorLabelValue = "true"
	FargateProfileLabelKey    = "eks.amazonaws.com/fargate-profile"
	NamespacePrefix           = "zasp-m019-"
	CanaryResponse            = "agentsec-attack-lab-canary-v1"
	CanaryImage               = "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9"
	CanaryRuntimeImageAMD64   = "registry.k8s.io/e2e-test-images/busybox@sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb"
	CanaryRuntimeImageARM64   = "registry.k8s.io/e2e-test-images/busybox@sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303"
	readAttempts              = 2
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
	markerPattern        = regexp.MustCompile(`^[a-f0-9]{32}$`)
	profilePattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	regionPattern        = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	securityGroupPattern = regexp.MustCompile(`^sg-[a-f0-9]{17}$`)
	vpcPattern           = regexp.MustCompile(`^vpc-[a-f0-9]{17}$`)
	eniPattern           = regexp.MustCompile(`^eni-[a-f0-9]{17}$`)
	providerIDPattern    = regexp.MustCompile(`^aws:///([a-z0-9-]+)/fargate-[a-z0-9.-]+$`)
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
func AmbiguousMutation(cause error) error { return &MutationError{Cause: cause, Ambiguous: true} }

type SecurityGroupRule struct {
	Protocol                   string
	FromPort                   int32
	ToPort                     int32
	CIDR                       string
	DestinationSecurityGroupID string
}

type SecurityGroupState struct {
	ID      string
	VPCID   string
	Ingress []SecurityGroupRule
	Egress  []SecurityGroupRule
}

type NetworkInterfaceState struct {
	ID               string
	VPCID            string
	Status           string
	SecurityGroupIDs []string
}

type EC2Boundary interface {
	InspectSecurityGroup(context.Context, string) (SecurityGroupState, error)
	InspectNetworkInterface(context.Context, string) (NetworkInterfaceState, error)
}

type Resource struct {
	Kind            ResourceKind
	Namespace       string
	Name            string
	Labels          map[string]string
	SpecDigest      string
	OwnerUID        string
	Image           string
	ProfileName     string
	ServiceAccount  string
	ProxyURL        string
	DirectURL       string
	SecurityGroupID string
	SecretValue     []byte
}

type ResourceRef struct {
	Kind            ResourceKind
	Namespace, Name string
}
type ListQuery struct {
	Kind                  ResourceKind
	Namespace, NamePrefix string
	Labels                map[string]string
}

type ObjectState struct {
	Kind             ResourceKind
	Namespace        string
	Name             string
	UID              string
	Labels           map[string]string
	SpecDigest       string
	OwnerUID         string
	Phase            string
	ImageID          string
	RuntimeImageID   string
	ProfileName      string
	NodeName         string
	ServiceAccount   string
	ProviderID       string
	ComputeType      string
	Ready            bool
	Succeeded        int
	Failed           int
	ExitCode         int
	ENIID            string
	SecurityGroupIDs []string
	SelectorLabels   map[string]string
}

type OwnedObject struct {
	Expected Resource
	State    ObjectState
}
type OwnedPod struct{ State ObjectState }

type ClusterBoundary interface {
	Create(context.Context, Resource) (ObjectState, error)
	Get(context.Context, ResourceRef) (ObjectState, error)
	List(context.Context, ListQuery) ([]ObjectState, error)
	Delete(context.Context, OwnedObject) error
	Logs(context.Context, OwnedPod) ([]byte, []byte, error)
}

type ProofOptions struct {
	Boundary               ClusterBoundary
	EC2                    EC2Boundary
	Marker                 string
	Region                 string
	FargateProfile         string
	PodSecurityGroupID     string
	ClusterSecurityGroupID string
	ProxySecurityGroupID   string
	VPCID                  string
	DNSCIDR                string
	ProxyURL               string
	DirectURL              string
	CanaryToken            []byte
	MainTimeout            time.Duration
	CleanupTimeout         time.Duration
}

type ProofResult struct{ DirectDenied, ProxyAllowed, ENIAttached, Cleanup bool }

type lifecycle struct {
	options   ProofOptions
	namespace string
	labels    map[string]string
	owned     []OwnedObject
	uncertain []Resource
	mutated   bool
	pod       *OwnedPod
}

func RunProof(parent context.Context, options ProofOptions) (result ProofResult, resultErr error) {
	if err := validateOptions(options); err != nil {
		return ProofResult{}, err
	}
	life := &lifecycle{options: options, namespace: NamespacePrefix + options.Marker, labels: map[string]string{
		ProofLabelKey: ProofLabelValue, RunLabelKey: options.Marker, ProfileSelectorLabelKey: ProfileSelectorLabelValue,
	}}
	defer func() {
		if recover() != nil {
			resultErr = ErrPanic
		}
		if err := life.cleanup(); err != nil {
			result = ProofResult{}
			resultErr = err
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
	if err := life.requireSecurityGroup(mainContext); err != nil {
		return ProofResult{}, err
	}
	for _, resource := range life.resources() {
		if mainContext.Err() != nil {
			return ProofResult{}, ErrDeadline
		}
		owned, err := life.create(mainContext, resource)
		if err != nil {
			return ProofResult{}, err
		}
		life.owned = append(life.owned, owned)
	}
	if err := life.requireEvidence(mainContext); err != nil {
		return ProofResult{}, err
	}
	return ProofResult{DirectDenied: true, ProxyAllowed: true, ENIAttached: true}, nil
}

func validateOptions(o ProofOptions) error {
	if o.Boundary == nil || o.EC2 == nil || !markerPattern.MatchString(o.Marker) || !validRegion(o.Region) ||
		!profilePattern.MatchString(o.FargateProfile) || !securityGroupPattern.MatchString(o.PodSecurityGroupID) ||
		!securityGroupPattern.MatchString(o.ClusterSecurityGroupID) || !securityGroupPattern.MatchString(o.ProxySecurityGroupID) ||
		o.PodSecurityGroupID == o.ClusterSecurityGroupID || o.PodSecurityGroupID == o.ProxySecurityGroupID ||
		o.ClusterSecurityGroupID == o.ProxySecurityGroupID || !vpcPattern.MatchString(o.VPCID) || len(o.CanaryToken) == 0 ||
		len(o.CanaryToken) > 4096 || o.MainTimeout <= 0 || o.CleanupTimeout <= 0 {
		return ErrConfiguration
	}
	prefix, err := netip.ParsePrefix(o.DNSCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.Addr().IsUnspecified() || prefix.Addr().IsLoopback() {
		return ErrConfiguration
	}
	if !validHTTPS(o.ProxyURL) || !validHTTPS(o.DirectURL) || o.ProxyURL == o.DirectURL {
		return ErrConfiguration
	}
	return nil
}

func validRegion(value string) bool {
	return regionPattern.MatchString(value) && !strings.HasPrefix(value, "us-gov-") && !strings.HasPrefix(value, "cn-")
}
func validHTTPS(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && (parsed.Port() == "" || parsed.Port() == "443")
}

func (l *lifecycle) resources() []Resource {
	labels := cloneMap(l.labels)
	base := []Resource{
		{Kind: KindNamespace, Name: l.namespace, Labels: cloneMap(labels)},
		{Kind: KindServiceAccount, Namespace: l.namespace, Name: "canary", Labels: cloneMap(labels)},
		{Kind: KindSecret, Namespace: l.namespace, Name: "proxy", Labels: cloneMap(labels), SecretValue: slices.Clone(l.options.CanaryToken)},
		{Kind: KindSecurityGroupPolicy, Namespace: l.namespace, Name: "canary", Labels: cloneMap(labels), SecurityGroupID: l.options.PodSecurityGroupID},
		{Kind: KindJob, Namespace: l.namespace, Name: "canary", Labels: cloneMap(labels), Image: CanaryImage,
			ProfileName: l.options.FargateProfile, ServiceAccount: "canary", ProxyURL: l.options.ProxyURL, DirectURL: l.options.DirectURL},
	}
	for index := range base {
		base[index].SpecDigest = resourceDigest(base[index])
	}
	return base
}

func resourceDigest(resource Resource) string {
	keys := make([]string, 0, len(resource.Labels))
	for key := range resource.Labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{string(resource.Kind), resource.Namespace, resource.Name, resource.OwnerUID, resource.Image, resource.ProfileName, resource.ServiceAccount, resource.ProxyURL, resource.DirectURL, resource.SecurityGroupID}
	for _, key := range keys {
		parts = append(parts, key, resource.Labels[key])
	}
	if resource.Kind == KindSecret {
		sum := sha256.Sum256(resource.SecretValue)
		parts = append(parts, hex.EncodeToString(sum[:]))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func (l *lifecycle) requireSecurityGroup(ctx context.Context) error {
	state, err := readTwice(ctx, func() (SecurityGroupState, error) {
		return l.options.EC2.InspectSecurityGroup(ctx, l.options.PodSecurityGroupID)
	})
	if err != nil {
		return ErrProvider
	}
	want := []SecurityGroupRule{
		{Protocol: "tcp", FromPort: 443, ToPort: 443, DestinationSecurityGroupID: l.options.ClusterSecurityGroupID},
		{Protocol: "udp", FromPort: 53, ToPort: 53, CIDR: l.options.DNSCIDR},
		{Protocol: "tcp", FromPort: 53, ToPort: 53, CIDR: l.options.DNSCIDR},
		{Protocol: "tcp", FromPort: 443, ToPort: 443, DestinationSecurityGroupID: l.options.ProxySecurityGroupID},
	}
	if state.ID != l.options.PodSecurityGroupID || state.VPCID != l.options.VPCID || len(state.Ingress) != 0 || !sameRules(state.Egress, want) {
		return ErrOwnership
	}
	return nil
}

func sameRules(left, right []SecurityGroupRule) bool {
	if len(left) != len(right) {
		return false
	}
	canonical := func(values []SecurityGroupRule) []string {
		result := make([]string, len(values))
		for i, v := range values {
			result[i] = fmt.Sprintf("%s/%d/%d/%s/%s", v.Protocol, v.FromPort, v.ToPort, v.CIDR, v.DestinationSecurityGroupID)
		}
		sort.Strings(result)
		return result
	}
	return slices.Equal(canonical(left), canonical(right))
}

func (l *lifecycle) create(ctx context.Context, resource Resource) (OwnedObject, error) {
	l.mutated = true
	state, err := l.options.Boundary.Create(ctx, resource)
	if err == nil && exactState(resource, state) {
		return OwnedObject{Expected: resource, State: state}, nil
	}
	var mutation *MutationError
	if err != nil && (!errors.As(err, &mutation) || !mutation.Ambiguous) {
		return OwnedObject{}, ErrProvider
	}
	l.uncertain = append(l.uncertain, resource)
	reconcileContext, cancel := context.WithTimeout(context.Background(), l.options.CleanupTimeout)
	defer cancel()
	state, reconcileErr := l.findExact(reconcileContext, resource)
	if reconcileErr != nil {
		return OwnedObject{}, ErrOwnership
	}
	l.removeUncertain(resource)
	return OwnedObject{Expected: resource, State: state}, nil
}

func (l *lifecycle) findExact(ctx context.Context, resource Resource) (ObjectState, error) {
	for attempt := 0; attempt < readAttempts; attempt++ {
		state, err := l.options.Boundary.Get(ctx, ResourceRef{Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name})
		if err == nil && exactState(resource, state) {
			return state, nil
		}
		if err == nil && !exactState(resource, state) {
			return ObjectState{}, ErrOwnership
		}
		if !errors.Is(err, ErrNotFound) {
			return ObjectState{}, err
		}
		if attempt+1 < readAttempts {
			select {
			case <-ctx.Done():
				return ObjectState{}, ctx.Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	return ObjectState{}, ErrNotFound
}

func exactState(resource Resource, state ObjectState) bool {
	if state.Kind != resource.Kind || state.Namespace != resource.Namespace || state.Name != resource.Name || state.UID == "" ||
		state.SpecDigest != resource.SpecDigest || !equalMap(state.Labels, resource.Labels) {
		return false
	}
	return resource.Kind != KindSecurityGroupPolicy ||
		(slices.Equal(state.SecurityGroupIDs, []string{resource.SecurityGroupID}) && equalMap(state.SelectorLabels, resource.Labels))
}

func resourceRef(resource Resource) ResourceRef {
	return ResourceRef{Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name}
}

func exactOwnedState(owned OwnedObject, state ObjectState) bool {
	return state.UID == owned.State.UID && exactState(owned.Expected, state)
}

func (l *lifecycle) requireEvidence(ctx context.Context) error {
	job := l.owned[len(l.owned)-1]
	jobState, err := l.options.Boundary.Get(ctx, ResourceRef{Kind: KindJob, Namespace: l.namespace, Name: job.State.Name})
	if err != nil || !exactState(job.Expected, jobState) || jobState.Phase != "Complete" || jobState.Succeeded != 1 || jobState.Failed != 0 {
		return ErrScheduling
	}
	pods, err := l.options.Boundary.List(ctx, ListQuery{Kind: KindPod, Namespace: l.namespace, Labels: l.labels})
	if err != nil || len(pods) != 1 {
		return ErrScheduling
	}
	pod := pods[0]
	if pod.OwnerUID != job.State.UID || pod.UID == "" || pod.Phase != "Succeeded" || pod.ExitCode != 0 || pod.ServiceAccount != "canary" ||
		pod.ProfileName != l.options.FargateProfile || pod.Labels[FargateProfileLabelKey] != l.options.FargateProfile || !eniPattern.MatchString(pod.ENIID) ||
		!slices.Equal(pod.SecurityGroupIDs, []string{l.options.PodSecurityGroupID}) || pod.ImageID != CanaryImage ||
		(pod.RuntimeImageID != CanaryRuntimeImageAMD64 && pod.RuntimeImageID != CanaryRuntimeImageARM64) {
		return ErrScheduling
	}
	node, err := l.options.Boundary.Get(ctx, ResourceRef{Kind: KindNode, Name: pod.NodeName})
	if err != nil || !node.Ready || node.ComputeType != "fargate" || !providerIDPattern.MatchString(node.ProviderID) || !strings.Contains(node.ProviderID, l.options.Region) {
		return ErrScheduling
	}
	eni, err := readTwice(ctx, func() (NetworkInterfaceState, error) { return l.options.EC2.InspectNetworkInterface(ctx, pod.ENIID) })
	if err != nil {
		return ErrProvider
	}
	if eni.ID != pod.ENIID || eni.VPCID != l.options.VPCID || eni.Status != "in-use" || !slices.Equal(eni.SecurityGroupIDs, []string{l.options.PodSecurityGroupID}) {
		return ErrOwnership
	}
	stdout, stderr, err := l.options.Boundary.Logs(ctx, OwnedPod{State: pod})
	if err != nil || len(stderr) != 0 || string(stdout) != "direct=false proxy=true body="+CanaryResponse {
		return ErrCanary
	}
	l.pod = &OwnedPod{State: pod}
	return nil
}

func (l *lifecycle) cleanup() error {
	if !l.mutated {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.options.CleanupTimeout)
	defer cancel()
	failed := false
	for _, resource := range l.uncertain {
		state, err := l.findExact(ctx, resource)
		if err == nil {
			l.owned = append(l.owned, OwnedObject{Expected: resource, State: state})
		} else if !errors.Is(err, ErrNotFound) {
			failed = true
		}
	}
	for index := len(l.owned) - 1; index >= 0; index-- {
		owned := l.owned[index]
		state, err := l.options.Boundary.Get(ctx, ResourceRef{Kind: owned.State.Kind, Namespace: owned.State.Namespace, Name: owned.State.Name})
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil || state.UID != owned.State.UID || !exactState(owned.Expected, state) {
			failed = true
			continue
		}
		if err := l.options.Boundary.Delete(ctx, owned); err != nil {
			var mutation *MutationError
			if errors.As(err, &mutation) && mutation.Ambiguous {
				_, inspectErr := l.options.Boundary.Get(ctx, ResourceRef{Kind: owned.State.Kind, Namespace: owned.State.Namespace, Name: owned.State.Name})
				if errors.Is(inspectErr, ErrNotFound) {
					continue
				}
			}
			failed = true
		}
	}
	if err := l.requireGlobalAbsence(ctx); err != nil {
		failed = true
	}
	if failed {
		return ErrCleanup
	}
	return nil
}

func (l *lifecycle) requireGlobalAbsence(ctx context.Context) error {
	for _, kind := range []ResourceKind{KindNamespace, KindServiceAccount, KindSecret, KindSecurityGroupPolicy, KindJob, KindPod} {
		query := ListQuery{Kind: kind, Labels: map[string]string{ProofLabelKey: ProofLabelValue}}
		if kind == KindNamespace {
			query.NamePrefix = NamespacePrefix
		}
		states, err := l.options.Boundary.List(ctx, query)
		if err != nil {
			return ErrProvider
		}
		if len(states) != 0 {
			return ErrOwnership
		}
	}
	return nil
}

func (l *lifecycle) removeUncertain(resource Resource) {
	for i := range l.uncertain {
		if sameResource(l.uncertain[i], resource) {
			l.uncertain = append(l.uncertain[:i], l.uncertain[i+1:]...)
			return
		}
	}
}
func sameResource(a, b Resource) bool {
	return a.Kind == b.Kind && a.Namespace == b.Namespace && a.Name == b.Name
}
func equalMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func cloneMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for k, v := range source {
		result[k] = v
	}
	return result
}

func readTwice[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	var zero T
	var last error
	for attempt := 0; attempt < readAttempts; attempt++ {
		value, err := operation()
		if err == nil {
			return value, nil
		}
		last = err
		if attempt+1 < readAttempts {
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	return zero, last
}
