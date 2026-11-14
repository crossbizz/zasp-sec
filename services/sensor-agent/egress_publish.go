package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zasp-ai/zasp-sec/services/platform/agentsignals"
)

var errEgressPublish = errors.New("sensor egress observations not published")

// egressConfigMaps is the part of the ConfigMap API the publisher uses; the
// typed client-go interface satisfies it.
type egressConfigMaps interface {
	Get(ctx context.Context, name string, options metav1.GetOptions) (*corev1.ConfigMap, error)
	Create(ctx context.Context, value *corev1.ConfigMap, options metav1.CreateOptions) (*corev1.ConfigMap, error)
	Update(ctx context.Context, value *corev1.ConfigMap, options metav1.UpdateOptions) (*corev1.ConfigMap, error)
}

// One ConfigMap per node, in the sensor's own namespace. The name hides
// nothing; the digest only keeps long node names inside the name limit.
func egressConfigMapName(node string) string {
	digest := sha256.Sum256([]byte("zasp-egress-node-v1\x00" + node))
	return "zasp-egress-" + hex.EncodeToString(digest[:12])
}

func egressConfigMapLabels() map[string]string {
	return map[string]string{"app.kubernetes.io/name": "zasp-sensor-agent", agentsignals.EgressObservationsLabel: agentsignals.EgressObservationsLabelValue}
}

// loadEgressObservations returns the node's published document, or false
// when there is none or it is not this sensor's document.
func loadEgressObservations(ctx context.Context, api egressConfigMaps, node string) (agentsignals.EgressObservations, bool) {
	existing, err := api.Get(ctx, egressConfigMapName(node), metav1.GetOptions{})
	if err != nil || existing == nil || existing.Labels[agentsignals.EgressObservationsLabel] != agentsignals.EgressObservationsLabelValue {
		return agentsignals.EgressObservations{}, false
	}
	document, ok := agentsignals.ParseEgressObservations([]byte(existing.Data[agentsignals.EgressObservationsKey]))
	return document, ok && document.Node == node
}

// publishEgressObservations writes the document. A node that has never seen
// a catalog destination writes nothing, so the collector reads ConfigMaps
// only for nodes that have something to say.
func publishEgressObservations(ctx context.Context, api egressConfigMaps, document agentsignals.EgressObservations) error {
	body, err := json.Marshal(document)
	if err != nil || len(body) > agentsignals.MaximumEgressDocumentBytes {
		return errEgressPublish
	}
	if _, ok := agentsignals.ParseEgressObservations(body); !ok {
		return errEgressPublish
	}
	name := egressConfigMapName(document.Node)
	existing, err := api.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if len(document.Workloads) == 0 {
			return nil
		}
		_, err = api.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: egressConfigMapLabels()}, Data: map[string]string{agentsignals.EgressObservationsKey: string(body)}}, metav1.CreateOptions{})
		if err != nil {
			return errEgressPublish
		}
		return nil
	}
	if err != nil || existing == nil {
		return errEgressPublish
	}
	updated := existing.DeepCopy()
	updated.Labels = egressConfigMapLabels()
	updated.Data = map[string]string{agentsignals.EgressObservationsKey: string(body)}
	updated.BinaryData = nil
	if _, err := api.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return errEgressPublish
	}
	return nil
}
