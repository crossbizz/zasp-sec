package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeCluster struct {
	objects          map[string]ObjectState
	deleted          []ResourceKind
	created          []ResourceKind
	createdResources []Resource
	jobUID           string
	createErrors     map[ResourceKind]error
	applyCreateError map[ResourceKind]bool
	invalidCreate    map[ResourceKind]bool
	panicAfterCreate map[ResourceKind]bool
	deleteErrors     map[ResourceKind]error
	applyDeleteError map[ResourceKind]bool
	getHook          func(ResourceRef, ObjectState, error) (ObjectState, error)
	listHook         func(ListQuery, []ObjectState, error) ([]ObjectState, error)
	logsStdout       []byte
	logsStderr       []byte
	logsErr          error
}

func happyOptions(cluster ClusterBoundary) ProofOptions {
	return ProofOptions{
		Boundary:       cluster,
		Marker:         strings.Repeat("a", 32),
		Region:         "us-west-2",
		FargateProfile: "zasp-disposable-profile",
		ProxyURL:       "https://proxy.example.test/canary",
		CanaryToken:    []byte("synthetic-test-token"),
		MainTimeout:    time.Second,
		CleanupTimeout: time.Second,
	}
}

func newHappyCluster() *fakeCluster {
	return &fakeCluster{
		objects:          make(map[string]ObjectState),
		createErrors:     make(map[ResourceKind]error),
		applyCreateError: make(map[ResourceKind]bool),
		invalidCreate:    make(map[ResourceKind]bool),
		panicAfterCreate: make(map[ResourceKind]bool),
		deleteErrors:     make(map[ResourceKind]error),
		applyDeleteError: make(map[ResourceKind]bool),
		logsStdout:       []byte(CanaryResponse),
	}
}

func objectKey(kind ResourceKind, namespace, name string) string {
	return string(kind) + "/" + namespace + "/" + name
}

func cloneLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}

func (f *fakeCluster) Create(_ context.Context, resource Resource) (ObjectState, error) {
	f.created = append(f.created, resource.Kind)
	f.createdResources = append(f.createdResources, resource)
	createErr := f.createErrors[resource.Kind]
	if createErr != nil && !f.applyCreateError[resource.Kind] {
		return ObjectState{}, createErr
	}
	state := ObjectState{
		Kind:        resource.Kind,
		Namespace:   resource.Namespace,
		Name:        resource.Name,
		UID:         "uid-" + string(resource.Kind),
		Labels:      cloneLabels(resource.Labels),
		SpecDigest:  resource.SpecDigest,
		OwnerUID:    resource.OwnerUID,
		ImageID:     resource.Image,
		ProfileName: resource.ProfileName,
	}
	f.objects[objectKey(state.Kind, state.Namespace, state.Name)] = state
	if resource.Kind == KindJob {
		f.jobUID = state.UID
		state.Phase = "Complete"
		state.Succeeded = 1
		f.objects[objectKey(state.Kind, state.Namespace, state.Name)] = state
		pod := ObjectState{
			Kind:           KindPod,
			Namespace:      resource.Namespace,
			Name:           resource.Name + "-pod",
			UID:            "uid-pod",
			Labels:         cloneLabels(resource.Labels),
			OwnerUID:       state.UID,
			Phase:          "Succeeded",
			ImageID:        resource.Image,
			RuntimeImageID: resource.Image,
			ProfileName:    resource.ProfileName,
			NodeName:       "fargate-node",
			ServiceAccount: "canary",
			ExitCode:       0,
		}
		pod.Labels[FargateProfileLabelKey] = resource.ProfileName
		f.objects[objectKey(pod.Kind, pod.Namespace, pod.Name)] = pod
		f.objects[objectKey(KindNode, "", pod.NodeName)] = ObjectState{
			Kind:        KindNode,
			Name:        pod.NodeName,
			UID:         "uid-node",
			ProviderID:  "aws:///us-west-2a/fargate-node",
			ComputeType: "fargate",
			Ready:       true,
		}
	}
	if f.panicAfterCreate[resource.Kind] {
		panic("fake create panic")
	}
	if f.invalidCreate[resource.Kind] {
		return ObjectState{}, nil
	}
	if createErr != nil {
		return ObjectState{}, createErr
	}
	return state, nil
}

func (f *fakeCluster) Get(_ context.Context, reference ResourceRef) (ObjectState, error) {
	state, ok := f.objects[objectKey(reference.Kind, reference.Namespace, reference.Name)]
	if !ok {
		if f.getHook != nil {
			return f.getHook(reference, ObjectState{}, ErrNotFound)
		}
		return ObjectState{}, ErrNotFound
	}
	if f.getHook != nil {
		return f.getHook(reference, state, nil)
	}
	return state, nil
}

func (f *fakeCluster) List(_ context.Context, query ListQuery) ([]ObjectState, error) {
	result := make([]ObjectState, 0)
	for _, state := range f.objects {
		if state.Kind == KindNode || state.Kind != query.Kind {
			continue
		}
		if query.Namespace != "" && state.Namespace != query.Namespace {
			continue
		}
		if query.NamePrefix != "" && !strings.HasPrefix(state.Name, query.NamePrefix) {
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
	if f.listHook != nil {
		return f.listHook(query, result, nil)
	}
	return result, nil
}

func (f *fakeCluster) Delete(_ context.Context, owned OwnedObject) error {
	deleteErr := f.deleteErrors[owned.State.Kind]
	if deleteErr != nil && !f.applyDeleteError[owned.State.Kind] {
		return deleteErr
	}
	key := objectKey(owned.State.Kind, owned.State.Namespace, owned.State.Name)
	delete(f.objects, key)
	f.deleted = append(f.deleted, owned.State.Kind)
	if owned.State.Kind == KindJob {
		for objectKeyValue, state := range f.objects {
			if state.Kind == KindPod && state.OwnerUID == f.jobUID {
				delete(f.objects, objectKeyValue)
			}
		}
	}
	if deleteErr != nil {
		return deleteErr
	}
	return nil
}

func (f *fakeCluster) Logs(_ context.Context, _ OwnedPod) ([]byte, []byte, error) {
	return f.logsStdout, f.logsStderr, f.logsErr
}

func TestRunProofHappyPath(t *testing.T) {
	t.Parallel()

	cluster := newHappyCluster()
	result, err := RunProof(context.Background(), happyOptions(cluster))
	if err != nil {
		t.Fatalf("RunProof returned error: %v", err)
	}
	if !result.Scheduled || !result.Canary || !result.Cleanup {
		t.Fatalf("unexpected result: %#v", result)
	}
	wantDelete := []ResourceKind{KindJob, KindSecret, KindServiceAccount, KindNamespace}
	if len(cluster.deleted) != len(wantDelete) {
		t.Fatalf("delete order length = %d, want %d: %#v", len(cluster.deleted), len(wantDelete), cluster.deleted)
	}
	for index, want := range wantDelete {
		if cluster.deleted[index] != want {
			t.Fatalf("delete[%d] = %q, want %q", index, cluster.deleted[index], want)
		}
	}
	job := cluster.createdResources[len(cluster.createdResources)-1]
	if job.Kind != KindJob || job.Labels[ProfileSelectorLabelKey] != ProfileSelectorLabelValue {
		t.Fatalf("job profile selector = %q, want %q", job.Labels[ProfileSelectorLabelKey], ProfileSelectorLabelValue)
	}
}

func TestRunProofMutationClassificationAndCleanup(t *testing.T) {
	t.Run("definitive create rejection is never adopted", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.createErrors[KindSecret] = errors.New("definitive")

		_, err := RunProof(context.Background(), happyOptions(cluster))
		if !errors.Is(err, ErrProvider) {
			t.Fatalf("error = %v, want provider", err)
		}
		for _, kind := range cluster.deleted {
			if kind == KindSecret || kind == KindJob {
				t.Fatalf("definitively rejected resource was deleted: %#v", cluster.deleted)
			}
		}
	})

	t.Run("ambiguous applied create reconciles exact state", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.createErrors[KindSecret] = AmbiguousMutation(errors.New("lost acknowledgement"))
		cluster.applyCreateError[KindSecret] = true

		result, err := RunProof(context.Background(), happyOptions(cluster))
		if err != nil || !result.Cleanup {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})

	t.Run("ambiguous applied create tolerates one delayed read", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.createErrors[KindSecret] = AmbiguousMutation(errors.New("lost acknowledgement"))
		cluster.applyCreateError[KindSecret] = true
		secretReads := 0
		cluster.getHook = func(reference ResourceRef, state ObjectState, err error) (ObjectState, error) {
			if reference.Kind == KindSecret {
				secretReads++
				if secretReads == 1 {
					return ObjectState{}, ErrNotFound
				}
			}
			return state, err
		}

		result, err := RunProof(context.Background(), happyOptions(cluster))
		if err != nil || !result.Cleanup {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})

	t.Run("deferred cleanup retries a delayed ambiguous create independently", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.createErrors[KindSecret] = AmbiguousMutation(errors.New("lost acknowledgement"))
		cluster.applyCreateError[KindSecret] = true
		secretReads := 0
		cluster.getHook = func(reference ResourceRef, state ObjectState, err error) (ObjectState, error) {
			if reference.Kind == KindSecret {
				secretReads++
				if secretReads <= 3 {
					return ObjectState{}, ErrNotFound
				}
			}
			return state, err
		}

		_, err := RunProof(context.Background(), happyOptions(cluster))
		if !errors.Is(err, ErrOwnership) {
			t.Fatalf("error = %v, want original ownership failure", err)
		}
		secretDeleted := false
		for _, kind := range cluster.deleted {
			if kind == KindSecret {
				secretDeleted = true
			}
		}
		if !secretDeleted {
			t.Fatalf("delayed ambiguous secret was not independently cleaned: %#v", cluster.deleted)
		}
	})

	t.Run("malformed applied success reconciles exact state", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.invalidCreate[KindJob] = true

		result, err := RunProof(context.Background(), happyOptions(cluster))
		if err != nil || !result.Scheduled || !result.Cleanup {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})

	t.Run("panic after apply is independently armed and cleaned", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.panicAfterCreate[KindJob] = true

		_, err := RunProof(context.Background(), happyOptions(cluster))
		if !errors.Is(err, ErrPanic) {
			t.Fatalf("error = %v, want panic", err)
		}
		if len(cluster.deleted) != 4 || cluster.deleted[0] != KindJob {
			t.Fatalf("applied candidate was not cleaned: %#v", cluster.deleted)
		}
	})

	t.Run("ambiguous applied delete reconciles absence", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.deleteErrors[KindJob] = AmbiguousMutation(errors.New("lost delete acknowledgement"))
		cluster.applyDeleteError[KindJob] = true

		result, err := RunProof(context.Background(), happyOptions(cluster))
		if err != nil || !result.Cleanup {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})

	t.Run("successful delete tolerates one delayed absence read", func(t *testing.T) {
		cluster := newHappyCluster()
		var retainedJob ObjectState
		jobMissingReads := 0
		cluster.getHook = func(reference ResourceRef, state ObjectState, err error) (ObjectState, error) {
			if reference.Kind == KindJob && err == nil {
				retainedJob = state
			}
			if reference.Kind == KindJob && errors.Is(err, ErrNotFound) {
				jobMissingReads++
				if jobMissingReads == 1 {
					return retainedJob, nil
				}
			}
			return state, err
		}

		result, err := RunProof(context.Background(), happyOptions(cluster))
		if err != nil || !result.Cleanup {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
	})
}

func TestRunProofSchedulingAndCanaryEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeCluster)
		want   error
	}{
		{
			name: "job must complete exactly once",
			mutate: func(cluster *fakeCluster) {
				cluster.getHook = func(reference ResourceRef, state ObjectState, err error) (ObjectState, error) {
					if err == nil && reference.Kind == KindJob {
						state.Failed = 1
					}
					return state, err
				}
			},
			want: ErrScheduling,
		},
		{
			name: "pod profile must match",
			mutate: func(cluster *fakeCluster) {
				cluster.listHook = func(query ListQuery, states []ObjectState, err error) ([]ObjectState, error) {
					if err == nil && query.Kind == KindPod && query.Namespace != "" && len(states) == 1 {
						states[0].ProfileName = "other-profile"
					}
					return states, err
				}
			},
			want: ErrScheduling,
		},
		{
			name: "runtime image digest must match",
			mutate: func(cluster *fakeCluster) {
				cluster.listHook = func(query ListQuery, states []ObjectState, err error) ([]ObjectState, error) {
					if err == nil && query.Kind == KindPod && query.Namespace != "" && len(states) == 1 {
						states[0].RuntimeImageID = "docker-pullable://attacker.invalid/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					}
					return states, err
				}
			},
			want: ErrScheduling,
		},
		{
			name: "node compute type must be fargate",
			mutate: func(cluster *fakeCluster) {
				cluster.getHook = func(reference ResourceRef, state ObjectState, err error) (ObjectState, error) {
					if err == nil && reference.Kind == KindNode {
						state.ComputeType = "ec2"
					}
					return state, err
				}
			},
			want: ErrScheduling,
		},
		{
			name: "node provider identity must be AWS fargate",
			mutate: func(cluster *fakeCluster) {
				cluster.getHook = func(reference ResourceRef, state ObjectState, err error) (ObjectState, error) {
					if err == nil && reference.Kind == KindNode {
						state.ProviderID = "docker:///forged"
					}
					return state, err
				}
			},
			want: ErrScheduling,
		},
		{
			name: "node provider region must match",
			mutate: func(cluster *fakeCluster) {
				cluster.getHook = func(reference ResourceRef, state ObjectState, err error) (ObjectState, error) {
					if err == nil && reference.Kind == KindNode {
						state.ProviderID = "aws:///eu-west-1a/fargate-node"
					}
					return state, err
				}
			},
			want: ErrScheduling,
		},
		{
			name: "canary body is byte exact",
			mutate: func(cluster *fakeCluster) {
				cluster.logsStdout = []byte(CanaryResponse + "\n")
			},
			want: ErrCanary,
		},
		{
			name: "canary stderr must be empty",
			mutate: func(cluster *fakeCluster) {
				cluster.logsStderr = []byte("warning")
			},
			want: ErrCanary,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cluster := newHappyCluster()
			test.mutate(cluster)
			_, err := RunProof(context.Background(), happyOptions(cluster))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if len(cluster.deleted) != 4 {
				t.Fatalf("cleanup did not continue: %#v", cluster.deleted)
			}
		})
	}
}

func TestRunProofAcceptsOnlyExactKubernetesControllerLabels(t *testing.T) {
	t.Run("exact controller and Fargate labels are accepted", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.listHook = func(query ListQuery, states []ObjectState, err error) ([]ObjectState, error) {
			if err == nil && query.Kind == KindPod && len(states) == 1 {
				states[0].Labels = cloneLabels(states[0].Labels)
				states[0].Labels["batch.kubernetes.io/controller-uid"] = cluster.jobUID
				states[0].Labels["batch.kubernetes.io/job-name"] = "canary"
				states[0].Labels["controller-uid"] = cluster.jobUID
				states[0].Labels["job-name"] = "canary"
				states[0].Labels["eks.amazonaws.com/fargate-profile"] = "zasp-disposable-profile"
			}
			return states, err
		}
		result, err := RunProof(context.Background(), happyOptions(cluster))
		if err != nil || !result.Cleanup {
			t.Fatalf("result=%#v error=%v", result, err)
		}
	})

	t.Run("unknown controller label is rejected", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.listHook = func(query ListQuery, states []ObjectState, err error) ([]ObjectState, error) {
			if err == nil && query.Kind == KindPod && len(states) == 1 {
				states[0].Labels = cloneLabels(states[0].Labels)
				states[0].Labels["attacker.example/claim"] = "forged"
			}
			return states, err
		}
		_, err := RunProof(context.Background(), happyOptions(cluster))
		if !errors.Is(err, ErrScheduling) {
			t.Fatalf("error=%v, want scheduling", err)
		}
	})
}

func TestRunProofOwnershipAndFailurePrecedence(t *testing.T) {
	t.Run("stale global resource blocks mutation and is not deleted", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.objects[objectKey(KindNamespace, "", NamespacePrefix+"stale")] = ObjectState{
			Kind:   KindNamespace,
			Name:   NamespacePrefix + "stale",
			UID:    "uid-stale",
			Labels: map[string]string{ProofLabelKey: ProofLabelValue, RunLabelKey: strings.Repeat("b", 32)},
		}

		_, err := RunProof(context.Background(), happyOptions(cluster))
		if !errors.Is(err, ErrCleanup) {
			t.Fatalf("error = %v, want cleanup precedence", err)
		}
		if len(cluster.created) != 0 || len(cluster.deleted) != 0 {
			t.Fatalf("stale object was mutated: created=%#v deleted=%#v", cluster.created, cluster.deleted)
		}
	})

	t.Run("cleanup replacement is never deleted", func(t *testing.T) {
		cluster := newHappyCluster()
		jobReads := 0
		cluster.getHook = func(reference ResourceRef, state ObjectState, err error) (ObjectState, error) {
			if err == nil && reference.Kind == KindJob {
				jobReads++
				if jobReads >= 2 {
					state.UID = "uid-replacement"
				}
			}
			return state, err
		}

		_, err := RunProof(context.Background(), happyOptions(cluster))
		if !errors.Is(err, ErrCleanup) {
			t.Fatalf("error = %v, want cleanup", err)
		}
		for _, kind := range cluster.deleted {
			if kind == KindJob {
				t.Fatalf("replacement job was deleted: %#v", cluster.deleted)
			}
		}
	})

	t.Run("cleanup failure overrides canary failure and cleanup continues", func(t *testing.T) {
		cluster := newHappyCluster()
		cluster.logsStdout = []byte("wrong")
		cluster.deleteErrors[KindJob] = errors.New("delete rejected")

		_, err := RunProof(context.Background(), happyOptions(cluster))
		if !errors.Is(err, ErrCleanup) {
			t.Fatalf("error = %v, want cleanup", err)
		}
		if len(cluster.deleted) != 3 {
			t.Fatalf("later cleanup did not continue: %#v", cluster.deleted)
		}
	})

	t.Run("final cancellation cannot return success", func(t *testing.T) {
		cluster := newHappyCluster()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := RunProof(ctx, happyOptions(cluster))
		if !errors.Is(err, ErrDeadline) {
			t.Fatalf("error = %v, want deadline", err)
		}
		if len(cluster.created) != 0 || len(cluster.deleted) != 0 {
			t.Fatalf("canceled run mutated the cluster: created=%#v deleted=%#v", cluster.created, cluster.deleted)
		}
	})
}

func TestRunProofRejectsInvalidConfigurationWithoutClusterCalls(t *testing.T) {
	tests := []func(*ProofOptions){
		func(options *ProofOptions) { options.Marker = "ABC" },
		func(options *ProofOptions) { options.FargateProfile = "Invalid_Profile" },
		func(options *ProofOptions) { options.ProxyURL = "http://proxy.example.test/canary" },
		func(options *ProofOptions) { options.ProxyURL = "https://user@proxy.example.test/canary" },
		func(options *ProofOptions) { options.ProxyURL = "https://proxy.example.test/canary?token=x" },
		func(options *ProofOptions) { options.CanaryToken = nil },
		func(options *ProofOptions) { options.MainTimeout = 0 },
	}

	for index, mutate := range tests {
		cluster := newHappyCluster()
		options := happyOptions(cluster)
		mutate(&options)
		_, err := RunProof(context.Background(), options)
		if !errors.Is(err, ErrConfiguration) {
			t.Fatalf("case %d error = %v, want configuration", index, err)
		}
		if len(cluster.created) != 0 || len(cluster.deleted) != 0 {
			t.Fatalf("case %d touched cluster: created=%#v deleted=%#v", index, cluster.created, cluster.deleted)
		}
	}
}
