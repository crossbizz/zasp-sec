package gatewaypodidentity

import (
	"context"
	"net/http"
	"net/url"
)

type chainFacts struct {
	VerifiedPod
	NodeName, ReplicaSetName, DeploymentName string
}

func (v *Verifier) get(ctx context.Context, secret []byte, path, kind, version, name, namespace string) (map[string]any, error) {
	raw, e := v.read(ctx, secret, http.MethodGet, path, nil, 1<<20)
	if e != nil {
		return nil, ErrDenied
	}
	o, e := parseJSON(raw)
	clear(raw)
	if e != nil {
		return nil, ErrDenied
	}
	m := obj(o, "metadata")
	deletion, exists := m["deletionTimestamp"]
	if str(o, "kind") != kind || str(o, "apiVersion") != version || str(m, "name") != name || !validUID(str(m, "uid")) || str(m, "namespace") != namespace || exists && deletion != nil {
		return nil, ErrDenied
	}
	// Cluster-scoped objects may omit namespace, but may not use null or a
	// non-string value to impersonate an absent namespace.
	if x, exists := m["namespace"]; exists {
		if s, ok := x.(string); !ok || s != namespace {
			return nil, ErrDenied
		}
	}
	return o, nil
}
func controller(o map[string]any, kind string) (name, uid string, ok bool) {
	owners, ok := obj(o, "metadata")["ownerReferences"].([]any)
	if !ok || len(owners) < 1 || len(owners) > 16 {
		return "", "", false
	}
	count := 0
	for _, value := range owners {
		owner, yes := value.(map[string]any)
		if !yes {
			return "", "", false
		}
		flag, exists := owner["controller"]
		if !exists {
			continue
		}
		isController, yes := flag.(bool)
		if !yes {
			return "", "", false
		}
		if isController {
			count++
			name = str(owner, "name")
			uid = str(owner, "uid")
			if str(owner, "kind") != kind || str(owner, "apiVersion") != "apps/v1" || !namePattern.MatchString(name) || !validUID(uid) {
				return "", "", false
			}
		}
	}
	return name, uid, count == 1
}
func templateSA(o map[string]any) (string, bool) {
	template, ok := obj(o, "spec")["template"].(map[string]any)
	if !ok {
		return "", false
	}
	spec, ok := template["spec"].(map[string]any)
	if !ok {
		return "", false
	}
	value, exists := spec["serviceAccountName"]
	if !exists {
		return "default", true
	}
	s, ok := value.(string)
	if !ok {
		return "", false
	}
	if s == "" {
		s = "default"
	}
	return s, namePattern.MatchString(s)
}
func (v *Verifier) readChain(ctx context.Context, secret []byte, id reviewIdentity) (chainFacts, error) {
	fail := func() (chainFacts, error) { return chainFacts{}, ErrDenied }
	ns := "/api/v1/namespaces/" + url.PathEscape(id.namespace)
	apps := "/apis/apps/v1/namespaces/" + url.PathEscape(id.namespace)
	cluster, e := v.get(ctx, secret, "/api/v1/namespaces/kube-system", "Namespace", "v1", "kube-system", "")
	if e != nil || str(obj(cluster, "metadata"), "uid") != v.config.ClusterUID {
		return fail()
	}
	sa, e := v.get(ctx, secret, ns+"/serviceaccounts/"+url.PathEscape(id.sa), "ServiceAccount", "v1", id.sa, id.namespace)
	if e != nil || str(obj(sa, "metadata"), "uid") != id.saUID {
		return fail()
	}
	pod, e := v.get(ctx, secret, ns+"/pods/"+url.PathEscape(id.pod), "Pod", "v1", id.pod, id.namespace)
	if e != nil || str(obj(pod, "metadata"), "uid") != id.podUID || str(obj(pod, "spec"), "serviceAccountName") != id.sa || str(obj(pod, "status"), "phase") != "Running" {
		return fail()
	}
	nodeName := str(obj(pod, "spec"), "nodeName")
	if !namePattern.MatchString(nodeName) {
		return fail()
	}
	rsName, rsUID, ok := controller(pod, "ReplicaSet")
	if !ok {
		return fail()
	}
	rs, e := v.get(ctx, secret, apps+"/replicasets/"+url.PathEscape(rsName), "ReplicaSet", "apps/v1", rsName, id.namespace)
	if e != nil || str(obj(rs, "metadata"), "uid") != rsUID {
		return fail()
	}
	saName, ok := templateSA(rs)
	if !ok || saName != id.sa {
		return fail()
	}
	depName, depUID, ok := controller(rs, "Deployment")
	if !ok {
		return fail()
	}
	dep, e := v.get(ctx, secret, apps+"/deployments/"+url.PathEscape(depName), "Deployment", "apps/v1", depName, id.namespace)
	if e != nil || str(obj(dep, "metadata"), "uid") != depUID || str(obj(obj(dep, "metadata"), "labels"), "zasp.ai/entity-kind") != "agent" {
		return fail()
	}
	saName, ok = templateSA(dep)
	if !ok || saName != id.sa {
		return fail()
	}
	node, e := v.get(ctx, secret, "/api/v1/nodes/"+url.PathEscape(nodeName), "Node", "v1", nodeName, "")
	if e != nil {
		return fail()
	}
	boot := str(obj(obj(node, "status"), "nodeInfo"), "bootID")
	if !validUID(boot) {
		return fail()
	}
	return chainFacts{VerifiedPod: VerifiedPod{ClusterUID: v.config.ClusterUID, Namespace: id.namespace, ServiceAccountName: id.sa, ServiceAccountUID: id.saUID, PodName: id.pod, PodUID: id.podUID, ReplicaSetUID: rsUID, DeploymentUID: depUID, NodeUID: str(obj(node, "metadata"), "uid"), BootID: boot}, NodeName: nodeName, ReplicaSetName: rsName, DeploymentName: depName}, nil
}
