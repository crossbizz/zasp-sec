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
	isolatedTestAttestation = "I_UNDERSTAND_THIS_APPLIES_A_DISPOSABLE_EKS_EGRESS_POLICY"
	proofSuccessLine        = "EKS Fargate egress proof passed: direct_denied=true proxy_allowed=true eni_attached=true cleanup=true."
	proofMainTimeout        = 10 * time.Minute
	proofCleanupTimeout     = 5 * time.Minute
	proofOverallTimeout     = proofMainTimeout + proofCleanupTimeout
)

var requiredMainEnvironment = []string{
	"AWS_M019_ISOLATED_TEST", "AWS_M019_KUBECONFIG", "AWS_M019_KUBE_CONTEXT", "AWS_M019_CLUSTER_NAME", "AWS_M019_REGION",
	"AWS_M019_FARGATE_PROFILE", "AWS_M019_PROFILE_NAMESPACE_PREFIX", "AWS_M019_PROFILE_LABEL_KEY", "AWS_M019_PROFILE_LABEL_VALUE",
	"AWS_M019_PROXY_URL", "AWS_M019_DIRECT_URL", "AWS_M019_CANARY_TOKEN", "AWS_M019_POD_SECURITY_GROUP_ID",
	"AWS_M019_CLUSTER_SECURITY_GROUP_ID", "AWS_M019_PROXY_SECURITY_GROUP_ID", "AWS_M019_VPC_ID", "AWS_M019_DNS_CIDR",
	"AWS_M019_ACCESS_KEY_ID", "AWS_M019_SECRET_ACCESS_KEY", "ZASP_M019_KUBECTL_EXECUTABLE",
}

type environmentLookup func(string) (string, bool)
type boundaryFactory func(KubectlBoundaryOptions, RealEC2Options) (ClusterBoundary, EC2Boundary, error)

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
	values := make(map[string]string, len(requiredMainEnvironment)+1)
	for _, name := range requiredMainEnvironment {
		value, exists := lookup(name)
		if !exists || value == "" {
			return failureLine("configuration")
		}
		values[name] = value
	}
	if token, exists := lookup("AWS_M019_SESSION_TOKEN"); exists {
		values["AWS_M019_SESSION_TOKEN"] = token
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
	cluster, ec2Boundary, err := factory(KubectlBoundaryOptions{Executable: values["ZASP_M019_KUBECTL_EXECUTABLE"], KubeconfigPath: values["AWS_M019_KUBECONFIG"], Context: values["AWS_M019_KUBE_CONTEXT"], ClusterName: values["AWS_M019_CLUSTER_NAME"], Region: values["AWS_M019_REGION"], Runner: NewBoundedProcessRunner(), ReadTimeout: 5 * time.Second, MutationTimeout: 30 * time.Second, OutputLimit: 16 * 1024}, RealEC2Options{Region: values["AWS_M019_REGION"], AccessKeyID: values["AWS_M019_ACCESS_KEY_ID"], SecretAccessKey: values["AWS_M019_SECRET_ACCESS_KEY"], SessionToken: values["AWS_M019_SESSION_TOKEN"]})
	if err != nil || cluster == nil || ec2Boundary == nil {
		return failureLine("configuration")
	}
	token := []byte(values["AWS_M019_CANARY_TOKEN"])
	defer clear(token)
	overall, cancel := context.WithTimeout(context.Background(), proofOverallTimeout)
	defer cancel()
	result, err := RunProof(overall, ProofOptions{Boundary: cluster, EC2: ec2Boundary, Marker: marker, Region: values["AWS_M019_REGION"], FargateProfile: values["AWS_M019_FARGATE_PROFILE"], PodSecurityGroupID: values["AWS_M019_POD_SECURITY_GROUP_ID"], ClusterSecurityGroupID: values["AWS_M019_CLUSTER_SECURITY_GROUP_ID"], ProxySecurityGroupID: values["AWS_M019_PROXY_SECURITY_GROUP_ID"], VPCID: values["AWS_M019_VPC_ID"], DNSCIDR: values["AWS_M019_DNS_CIDR"], ProxyURL: values["AWS_M019_PROXY_URL"], DirectURL: values["AWS_M019_DIRECT_URL"], CanaryToken: token, MainTimeout: proofMainTimeout, CleanupTimeout: proofCleanupTimeout})
	if err != nil {
		return failureLine(fixedCategory(err))
	}
	if result != (ProofResult{DirectDenied: true, ProxyAllowed: true, ENIAttached: true, Cleanup: true}) {
		return failureLine("provider")
	}
	return 0, proofSuccessLine
}

func validMainValues(values map[string]string) bool {
	if values["AWS_M019_ISOLATED_TEST"] != isolatedTestAttestation || values["AWS_M019_PROFILE_NAMESPACE_PREFIX"] != NamespacePrefix || values["AWS_M019_PROFILE_LABEL_KEY"] != ProfileSelectorLabelKey || values["AWS_M019_PROFILE_LABEL_VALUE"] != ProfileSelectorLabelValue || !contextNamePattern.MatchString(values["AWS_M019_KUBE_CONTEXT"]) || !contextNamePattern.MatchString(values["AWS_M019_CLUSTER_NAME"]) || !profilePattern.MatchString(values["AWS_M019_FARGATE_PROFILE"]) || !validRegion(values["AWS_M019_REGION"]) {
		return false
	}
	token := []byte(values["AWS_M019_CANARY_TOKEN"])
	defer clear(token)
	return validateOptions(ProofOptions{Boundary: configurationCluster{}, EC2: configurationEC2{}, Marker: "00000000000000000000000000000000", Region: values["AWS_M019_REGION"], FargateProfile: values["AWS_M019_FARGATE_PROFILE"], PodSecurityGroupID: values["AWS_M019_POD_SECURITY_GROUP_ID"], ClusterSecurityGroupID: values["AWS_M019_CLUSTER_SECURITY_GROUP_ID"], ProxySecurityGroupID: values["AWS_M019_PROXY_SECURITY_GROUP_ID"], VPCID: values["AWS_M019_VPC_ID"], DNSCIDR: values["AWS_M019_DNS_CIDR"], ProxyURL: values["AWS_M019_PROXY_URL"], DirectURL: values["AWS_M019_DIRECT_URL"], CanaryToken: token, MainTimeout: proofMainTimeout, CleanupTimeout: proofCleanupTimeout}) == nil && accessKeyPattern.MatchString(values["AWS_M019_ACCESS_KEY_ID"]) && len(values["AWS_M019_SECRET_ACCESS_KEY"]) >= 16 && len(values["AWS_M019_SECRET_ACCESS_KEY"]) <= 256 && !containsControl(values["AWS_M019_SECRET_ACCESS_KEY"]) && len(values["AWS_M019_SESSION_TOKEN"]) <= 4096 && !containsControl(values["AWS_M019_SESSION_TOKEN"])
}

type configurationCluster struct{}

func (configurationCluster) Create(context.Context, Resource) (ObjectState, error) {
	return ObjectState{}, ErrProvider
}
func (configurationCluster) Get(context.Context, ResourceRef) (ObjectState, error) {
	return ObjectState{}, ErrProvider
}
func (configurationCluster) List(context.Context, ListQuery) ([]ObjectState, error) {
	return nil, ErrProvider
}
func (configurationCluster) Delete(context.Context, OwnedObject) error { return ErrProvider }
func (configurationCluster) Logs(context.Context, OwnedPod) ([]byte, []byte, error) {
	return nil, nil, ErrProvider
}

type configurationEC2 struct{}

func (configurationEC2) InspectSecurityGroup(context.Context, string) (SecurityGroupState, error) {
	return SecurityGroupState{}, ErrProvider
}
func (configurationEC2) InspectNetworkInterface(context.Context, string) (NetworkInterfaceState, error) {
	return NetworkInterfaceState{}, ErrProvider
}

func defaultBoundaryFactory(kube KubectlBoundaryOptions, awsOptions RealEC2Options) (ClusterBoundary, EC2Boundary, error) {
	cluster, err := NewKubectlBoundary(kube)
	if err != nil {
		return nil, nil, err
	}
	ec2Boundary, err := NewRealEC2Boundary(awsOptions)
	if err != nil {
		return nil, nil, err
	}
	return cluster, ec2Boundary, nil
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
	return 1, fmt.Sprintf("EKS Fargate egress proof failed: %s rejected.", category)
}
