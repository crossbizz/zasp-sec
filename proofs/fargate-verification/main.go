package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	isolatedTestAttestation = "I_UNDERSTAND_THIS_MUTATES_A_DISPOSABLE_EKS_PROFILE"
	proofSuccessLine        = "EKS Fargate proof passed: scheduled=true canary=true cleanup=true."
	proofMainTimeout        = 10 * time.Minute
	proofCleanupTimeout     = 5 * time.Minute
	proofOverallTimeout     = proofMainTimeout + proofCleanupTimeout
)

var requiredMainEnvironment = []string{
	"AWS_M018_ISOLATED_TEST",
	"AWS_M018_KUBECONFIG",
	"AWS_M018_KUBE_CONTEXT",
	"AWS_M018_CLUSTER_NAME",
	"AWS_M018_REGION",
	"AWS_M018_FARGATE_PROFILE",
	"AWS_M018_PROFILE_NAMESPACE_PREFIX",
	"AWS_M018_PROFILE_LABEL_KEY",
	"AWS_M018_PROFILE_LABEL_VALUE",
	"AWS_M018_PROXY_URL",
	"AWS_M018_CANARY_TOKEN",
	"ZASP_M018_KUBECTL_EXECUTABLE",
}

type environmentLookup func(string) (string, bool)
type boundaryFactory func(KubectlBoundaryOptions) (ClusterBoundary, error)

func main() {
	code, line := executeMain(os.Args, os.LookupEnv, rand.Reader, defaultBoundaryFactory)
	if code == 0 {
		fmt.Fprintln(os.Stdout, line)
	} else {
		fmt.Fprintln(os.Stderr, line)
	}
	os.Exit(code)
}

func executeMain(arguments []string, lookup environmentLookup, random io.Reader, factory boundaryFactory) (code int, line string) {
	code, line = failureLine("panic")
	defer func() {
		if recover() != nil {
			code, line = failureLine("panic")
		}
	}()
	if len(arguments) != 1 || lookup == nil || random == nil || factory == nil {
		return failureLine("configuration")
	}
	values := make(map[string]string, len(requiredMainEnvironment))
	for _, name := range requiredMainEnvironment {
		value, exists := lookup(name)
		if !exists || value == "" {
			return failureLine("configuration")
		}
		values[name] = value
	}
	if !validMainValues(values) {
		return failureLine("configuration")
	}
	markerBytes := make([]byte, 16)
	if _, err := io.ReadFull(random, markerBytes); err != nil {
		return failureLine("configuration")
	}
	marker := hex.EncodeToString(markerBytes)
	clear(markerBytes)
	boundary, err := factory(KubectlBoundaryOptions{
		Executable:      values["ZASP_M018_KUBECTL_EXECUTABLE"],
		KubeconfigPath:  values["AWS_M018_KUBECONFIG"],
		Context:         values["AWS_M018_KUBE_CONTEXT"],
		ClusterName:     values["AWS_M018_CLUSTER_NAME"],
		Runner:          NewBoundedProcessRunner(),
		ReadTimeout:     5 * time.Second,
		MutationTimeout: 30 * time.Second,
		OutputLimit:     16 * 1024,
	})
	if err != nil || boundary == nil {
		return failureLine("configuration")
	}
	token := []byte(values["AWS_M018_CANARY_TOKEN"])
	defer clear(token)
	overallContext, cancel := context.WithTimeout(context.Background(), proofOverallTimeout)
	defer cancel()
	result, err := RunProof(overallContext, ProofOptions{
		Boundary:       boundary,
		Marker:         marker,
		Region:         values["AWS_M018_REGION"],
		FargateProfile: values["AWS_M018_FARGATE_PROFILE"],
		ProxyURL:       values["AWS_M018_PROXY_URL"],
		CanaryToken:    token,
		MainTimeout:    proofMainTimeout,
		CleanupTimeout: proofCleanupTimeout,
	})
	if err != nil {
		return failureLine(fixedCategory(err))
	}
	if result != (ProofResult{Scheduled: true, Canary: true, Cleanup: true}) {
		return failureLine("provider")
	}
	return 0, proofSuccessLine
}

func validMainValues(values map[string]string) bool {
	if values["AWS_M018_ISOLATED_TEST"] != isolatedTestAttestation ||
		values["AWS_M018_PROFILE_NAMESPACE_PREFIX"] != NamespacePrefix ||
		values["AWS_M018_PROFILE_LABEL_KEY"] != ProfileSelectorLabelKey ||
		values["AWS_M018_PROFILE_LABEL_VALUE"] != ProfileSelectorLabelValue ||
		!contextNamePattern.MatchString(values["AWS_M018_KUBE_CONTEXT"]) ||
		!contextNamePattern.MatchString(values["AWS_M018_CLUSTER_NAME"]) ||
		!profilePattern.MatchString(values["AWS_M018_FARGATE_PROFILE"]) ||
		!validCommercialRegion(values["AWS_M018_REGION"]) {
		return false
	}
	token := []byte(values["AWS_M018_CANARY_TOKEN"])
	defer clear(token)
	return validateOptions(ProofOptions{
		Boundary:       configurationBoundary{},
		Marker:         "00000000000000000000000000000000",
		Region:         values["AWS_M018_REGION"],
		FargateProfile: values["AWS_M018_FARGATE_PROFILE"],
		ProxyURL:       values["AWS_M018_PROXY_URL"],
		CanaryToken:    token,
		MainTimeout:    proofMainTimeout,
		CleanupTimeout: proofCleanupTimeout,
	}) == nil
}

type configurationBoundary struct{}

func (configurationBoundary) Create(context.Context, Resource) (ObjectState, error) {
	return ObjectState{}, ErrProvider
}
func (configurationBoundary) Get(context.Context, ResourceRef) (ObjectState, error) {
	return ObjectState{}, ErrProvider
}
func (configurationBoundary) List(context.Context, ListQuery) ([]ObjectState, error) {
	return nil, ErrProvider
}
func (configurationBoundary) Delete(context.Context, OwnedObject) error { return ErrProvider }
func (configurationBoundary) Logs(context.Context, OwnedPod) ([]byte, []byte, error) {
	return nil, nil, ErrProvider
}

func defaultBoundaryFactory(options KubectlBoundaryOptions) (ClusterBoundary, error) {
	return NewKubectlBoundary(options)
}

func fixedCategory(err error) string {
	switch {
	case errors.Is(err, ErrConfiguration):
		return "configuration"
	case errors.Is(err, ErrProvider):
		return "provider"
	case errors.Is(err, ErrScheduling):
		return "scheduling"
	case errors.Is(err, ErrCanary):
		return "canary"
	case errors.Is(err, ErrOwnership):
		return "ownership"
	case errors.Is(err, ErrCleanup):
		return "cleanup"
	case errors.Is(err, ErrDeadline):
		return "deadline"
	case errors.Is(err, ErrPanic):
		return "panic"
	default:
		return "provider"
	}
}

func failureLine(category string) (int, string) {
	return 1, fmt.Sprintf("EKS Fargate proof failed: %s rejected.", category)
}
