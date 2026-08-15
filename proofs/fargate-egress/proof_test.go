package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeCluster struct {
	objects     map[string]ObjectState
	created     []ResourceKind
	deleted     []ResourceKind
	logs        []byte
	createError map[ResourceKind]error
	applyCreate map[ResourceKind]bool
	deleteError map[ResourceKind]error
	applyDelete map[ResourceKind]bool
}

type fakeEC2 struct {
	group          SecurityGroupState
	interfaceState NetworkInterfaceState
	groupCalls     int
	interfaceCalls int
}

func (f *fakeEC2) InspectSecurityGroup(context.Context, string) (SecurityGroupState, error) {
	f.groupCalls++
	return f.group, nil
}

func (f *fakeEC2) InspectNetworkInterface(context.Context, string) (NetworkInterfaceState, error) {
	f.interfaceCalls++
	return f.interfaceState, nil
}

func resourceKey(kind ResourceKind, namespace, name string) string {
	return string(kind) + "/" + namespace + "/" + name
}

func (f *fakeCluster) Create(_ context.Context, resource Resource) (ObjectState, error) {
	f.created = append(f.created, resource.Kind)
	err := f.createError[resource.Kind]
	if err != nil && !f.applyCreate[resource.Kind] {
		return ObjectState{}, err
	}
	state := ObjectState{Kind: resource.Kind, Namespace: resource.Namespace, Name: resource.Name,
		UID: "uid-" + string(resource.Kind), Labels: cloneMap(resource.Labels), SpecDigest: resource.SpecDigest}
	if resource.Kind == KindSecurityGroupPolicy {
		state.SecurityGroupIDs = []string{resource.SecurityGroupID}
		state.SelectorLabels = cloneMap(resource.Labels)
	}
	f.objects[resourceKey(state.Kind, state.Namespace, state.Name)] = state
	if resource.Kind == KindJob {
		state.Phase, state.Succeeded = "Complete", 1
		f.objects[resourceKey(state.Kind, state.Namespace, state.Name)] = state
		pod := ObjectState{Kind: KindPod, Namespace: resource.Namespace, Name: resource.Name + "-pod",
			UID: "uid-pod", Labels: cloneMap(resource.Labels), OwnerUID: state.UID, Phase: "Succeeded",
			ImageID: CanaryImage, RuntimeImageID: CanaryRuntimeImageAMD64, NodeName: "fargate-node",
			ServiceAccount: "canary", ProfileName: resource.ProfileName, ExitCode: 0, ENIID: "eni-0123456789abcdef0",
			SecurityGroupIDs: []string{"sg-0123456789abcdef0"}}
		pod.Labels[FargateProfileLabelKey] = resource.ProfileName
		f.objects[resourceKey(pod.Kind, pod.Namespace, pod.Name)] = pod
		f.objects[resourceKey(KindNode, "", pod.NodeName)] = ObjectState{Kind: KindNode, Name: pod.NodeName,
			ProviderID: "aws:///us-west-2a/fargate-node", ComputeType: "fargate", Ready: true}
	}
	if err != nil {
		return ObjectState{}, err
	}
	return state, nil
}

func (f *fakeCluster) Get(_ context.Context, ref ResourceRef) (ObjectState, error) {
	state, ok := f.objects[resourceKey(ref.Kind, ref.Namespace, ref.Name)]
	if !ok {
		return ObjectState{}, ErrNotFound
	}
	return state, nil
}

func (f *fakeCluster) List(_ context.Context, query ListQuery) ([]ObjectState, error) {
	result := []ObjectState{}
	for _, state := range f.objects {
		if state.Kind != query.Kind || (query.Namespace != "" && state.Namespace != query.Namespace) ||
			(query.NamePrefix != "" && !strings.HasPrefix(state.Name, query.NamePrefix)) {
			continue
		}
		matches := true
		for key, value := range query.Labels {
			if state.Labels[key] != value {
				matches = false
			}
		}
		if matches {
			result = append(result, state)
		}
	}
	return result, nil
}

func (f *fakeCluster) Delete(_ context.Context, owned OwnedObject) error {
	err := f.deleteError[owned.State.Kind]
	if err != nil && !f.applyDelete[owned.State.Kind] {
		return err
	}
	delete(f.objects, resourceKey(owned.State.Kind, owned.State.Namespace, owned.State.Name))
	f.deleted = append(f.deleted, owned.State.Kind)
	if owned.State.Kind == KindJob {
		for key, state := range f.objects {
			if state.Kind == KindPod && state.OwnerUID == owned.State.UID {
				delete(f.objects, key)
			}
		}
	}
	return err
}

func (f *fakeCluster) Logs(context.Context, OwnedPod) ([]byte, []byte, error) {
	return f.logs, nil, nil
}

func happyProof() (*fakeCluster, *fakeEC2, ProofOptions) {
	cluster := &fakeCluster{objects: map[string]ObjectState{}, createError: map[ResourceKind]error{}, applyCreate: map[ResourceKind]bool{}, deleteError: map[ResourceKind]error{},
		applyDelete: map[ResourceKind]bool{},
		logs:        []byte("direct=false proxy=true body=agentsec-attack-lab-canary-v1")}
	ec2 := &fakeEC2{
		group: SecurityGroupState{ID: "sg-0123456789abcdef0", VPCID: "vpc-0123456789abcdef0", Egress: []SecurityGroupRule{
			{Protocol: "tcp", FromPort: 443, ToPort: 443, DestinationSecurityGroupID: "sg-11111111111111111"},
			{Protocol: "udp", FromPort: 53, ToPort: 53, CIDR: "10.0.0.2/32"},
			{Protocol: "tcp", FromPort: 53, ToPort: 53, CIDR: "10.0.0.2/32"},
			{Protocol: "tcp", FromPort: 443, ToPort: 443, DestinationSecurityGroupID: "sg-22222222222222222"},
		}},
		interfaceState: NetworkInterfaceState{ID: "eni-0123456789abcdef0", VPCID: "vpc-0123456789abcdef0", Status: "in-use", SecurityGroupIDs: []string{"sg-0123456789abcdef0"}},
	}
	options := ProofOptions{Boundary: cluster, EC2: ec2, Marker: strings.Repeat("a", 32), Region: "us-west-2",
		FargateProfile: "zasp-disposable-profile", PodSecurityGroupID: "sg-0123456789abcdef0",
		ClusterSecurityGroupID: "sg-11111111111111111", ProxySecurityGroupID: "sg-22222222222222222",
		VPCID: "vpc-0123456789abcdef0", DNSCIDR: "10.0.0.2/32", ProxyURL: "https://proxy.example.test/canary",
		DirectURL: "https://undeclared.example.test/canary", CanaryToken: []byte("synthetic-token"),
		MainTimeout: time.Second, CleanupTimeout: time.Second}
	return cluster, ec2, options
}

func TestRunProofReconcilesAppliedAmbiguousDelete(t *testing.T) {
	cluster, _, options := happyProof()
	cluster.deleteError[KindJob] = AmbiguousMutation(errors.New("lost acknowledgement"))
	cluster.applyDelete[KindJob] = true
	result, err := RunProof(context.Background(), options)
	if err != nil || !result.Cleanup {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestRunProofRejectsCanceledParentBeforeMutation(t *testing.T) {
	cluster, _, options := happyProof()
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := RunProof(parent, options)
	if !errors.Is(err, ErrDeadline) || len(cluster.created) != 0 {
		t.Fatalf("err=%v created=%v", err, cluster.created)
	}
}

func TestRunProofHappyPath(t *testing.T) {
	cluster, ec2, options := happyProof()
	result, err := RunProof(context.Background(), options)
	if err != nil {
		t.Fatalf("RunProof: %v", err)
	}
	if !result.DirectDenied || !result.ProxyAllowed || !result.ENIAttached || !result.Cleanup {
		t.Fatalf("result=%#v", result)
	}
	wantCreate := []ResourceKind{KindNamespace, KindServiceAccount, KindSecret, KindSecurityGroupPolicy, KindJob}
	if strings.TrimSpace(strings.Join(kinds(cluster.created), ",")) != strings.Join(kinds(wantCreate), ",") {
		t.Fatalf("created=%v", cluster.created)
	}
	wantDelete := []ResourceKind{KindJob, KindSecurityGroupPolicy, KindSecret, KindServiceAccount, KindNamespace}
	if strings.Join(kinds(cluster.deleted), ",") != strings.Join(kinds(wantDelete), ",") {
		t.Fatalf("deleted=%v", cluster.deleted)
	}
	if ec2.groupCalls == 0 || ec2.interfaceCalls == 0 {
		t.Fatalf("EC2 calls group=%d eni=%d", ec2.groupCalls, ec2.interfaceCalls)
	}
}

func kinds(values []ResourceKind) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func TestRunProofRejectsSecurityGroupDriftBeforeMutation(t *testing.T) {
	cluster, ec2, options := happyProof()
	ec2.group.Egress = append(ec2.group.Egress, SecurityGroupRule{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDR: "0.0.0.0/0"})
	_, err := RunProof(context.Background(), options)
	if !errors.Is(err, ErrOwnership) {
		t.Fatalf("err=%v", err)
	}
	if len(cluster.created) != 0 {
		t.Fatalf("created=%v", cluster.created)
	}
}

func TestRunProofRejectsENIAndEvidenceDriftAndCleans(t *testing.T) {
	tests := map[string]func(*fakeCluster, *fakeEC2){
		"wrong ENI group": func(_ *fakeCluster, ec2 *fakeEC2) {
			ec2.interfaceState.SecurityGroupIDs = []string{"sg-33333333333333333"}
		},
		"direct unexpectedly succeeds": func(cluster *fakeCluster, _ *fakeEC2) {
			cluster.logs = []byte("direct=true proxy=true body=agentsec-attack-lab-canary-v1")
		},
		"wrong body": func(cluster *fakeCluster, _ *fakeEC2) { cluster.logs = []byte("direct=false proxy=true body=wrong") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cluster, ec2, options := happyProof()
			mutate(cluster, ec2)
			_, err := RunProof(context.Background(), options)
			if err == nil {
				t.Fatal("expected error")
			}
			if len(cluster.deleted) != 5 {
				t.Fatalf("deleted=%v", cluster.deleted)
			}
		})
	}
}

func TestRunProofReconcilesOnlyAmbiguousCreateAndPreservesCleanupPrecedence(t *testing.T) {
	cluster, _, options := happyProof()
	cluster.createError[KindSecurityGroupPolicy] = AmbiguousMutation(errors.New("timeout"))
	cluster.applyCreate[KindSecurityGroupPolicy] = true
	cluster.deleteError[KindNamespace] = errors.New("cleanup detail")
	_, err := RunProof(context.Background(), options)
	if !errors.Is(err, ErrCleanup) {
		t.Fatalf("err=%v", err)
	}
	if len(cluster.deleted) != 4 {
		t.Fatalf("deleted=%v", cluster.deleted)
	}

	cluster, _, options = happyProof()
	cluster.createError[KindNamespace] = errors.New("definite rejection")
	_, err = RunProof(context.Background(), options)
	if errors.Is(err, ErrCleanup) || len(cluster.deleted) != 0 {
		t.Fatalf("err=%v deleted=%v", err, cluster.deleted)
	}
}
