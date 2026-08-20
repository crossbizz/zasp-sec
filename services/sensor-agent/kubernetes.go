package main

import (
	"context"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcoordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

type kubernetesClusterAPI struct {
	leases typedcoordinationv1.LeaseInterface
	pods   typedcorev1.PodInterface
}

func newInClusterAPI(namespace string) (*kubernetesClusterAPI, error) {
	if !validKubernetesName(namespace) {
		return nil, ErrCluster
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, ErrClusterRetryable
	}
	config.Timeout = 5 * time.Second
	config.QPS = 5
	config.Burst = 10
	config.UserAgent = "zasp-sensor-agent/v1"
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, ErrClusterRetryable
	}
	return &kubernetesClusterAPI{leases: client.CoordinationV1().Leases(namespace), pods: client.CoreV1().Pods(namespace)}, nil
}

func (api *kubernetesClusterAPI) Get(ctx context.Context, name string, options metav1.GetOptions) (*coordinationv1.Lease, error) {
	if api == nil || api.leases == nil {
		return nil, ErrCluster
	}
	return api.leases.Get(ctx, name, options)
}
func (api *kubernetesClusterAPI) Create(ctx context.Context, value *coordinationv1.Lease, options metav1.CreateOptions) (*coordinationv1.Lease, error) {
	if api == nil || api.leases == nil {
		return nil, ErrCluster
	}
	return api.leases.Create(ctx, value, options)
}
func (api *kubernetesClusterAPI) Update(ctx context.Context, value *coordinationv1.Lease, options metav1.UpdateOptions) (*coordinationv1.Lease, error) {
	if api == nil || api.leases == nil {
		return nil, ErrCluster
	}
	return api.leases.Update(ctx, value, options)
}
func (api *kubernetesClusterAPI) List(ctx context.Context, options metav1.ListOptions) (*coordinationv1.LeaseList, error) {
	if api == nil || api.leases == nil {
		return nil, ErrCluster
	}
	return api.leases.List(ctx, options)
}
func (api *kubernetesClusterAPI) ListPods(ctx context.Context, options metav1.ListOptions) (*corev1.PodList, error) {
	if api == nil || api.pods == nil {
		return nil, ErrCluster
	}
	return api.pods.List(ctx, options)
}
