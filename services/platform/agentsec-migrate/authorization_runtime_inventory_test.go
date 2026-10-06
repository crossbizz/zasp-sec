package main

import (
	"reflect"
	"testing"
)

func TestAuthorizationRuntimeProfileResumesOwnedWorkerRuntimeSchema(t *testing.T) {
	namespaces := []string{"zasp_temporal65", "zasp_temporal66", "zasp_temporal67", "zasp_temporal68", "zasp_temporal69", "zasp_temporal70", "zasp_temporal71", "zasp_temporal72", "zasp_temporal73", "zasp_temporal74", "zasp_temporal75", "zasp_temporal76", "zasp_temporal77", "zasp_temporal78", "zasp_authorization79", "zasp_authorization80", "zasp_authorization80_temporal", "zasp_authorization80_audit", "zasp_authorization80_identity", "zasp_authorization80_worker", "zasp_authorization80_runtime"}
	plan, err := authorizationRuntimeProfilePlan(61, namespaces)
	if err != nil || !reflect.DeepEqual(plan, []string{"up-authorization-temporal-identity-profile", "up-authorization-worker-profile"}) {
		t.Fatal("installed worker runtime cannot reach exact native revalidation", err)
	}
	for _, bad := range [][]string{namespaces[:len(namespaces)-2], {"zasp_authorization80_runtime"}} {
		partial := append(append([]string(nil), bad...), "zasp_authorization80_runtime")
		if _, err := authorizationRuntimeProfilePlan(61, partial); err == nil {
			t.Fatal("orphan/duplicate runtime schema selected")
		}
	}
	unknown := append(append([]string(nil), namespaces...), "zasp_authorization80_unrecognized")
	if _, err := authorizationRuntimeProfilePlan(61, unknown); err == nil {
		t.Fatal("unknown runtime sibling selected")
	}
}
