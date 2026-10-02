package main

import (
	"reflect"
	"testing"
)

func TestAuthorizationRuntimeProfilePlan(t *testing.T) {
	base := []string{"up-temporal-domain", "up-temporal-executor", "up-temporal-workflow", "up-temporal-compatibility", "up-temporal-legacy-tests", "up-temporal-discovery", "up-temporal-admission", "up-temporal-test-executor", "up-temporal-test-selector", "up-temporal-human-admission", "up-temporal-automatic-sources", "up-temporal-finding-response", "up-authorization-temporal-identity-profile", "up-authorization-worker-profile"}
	for _, version := range []int64{0, 60, 61} {
		want := append([]string(nil), base...)
		if version < 61 {
			want = append([]string{"up-to-60"}, want...)
		}
		got, err := authorizationRuntimeProfilePlan(version, nil)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("fresh/canonical %d plan=%v err=%v", version, got, err)
		}
	}
	full := []string{"zasp_temporal65", "zasp_temporal66", "zasp_temporal67", "zasp_temporal68", "zasp_temporal69", "zasp_temporal70", "zasp_temporal71", "zasp_temporal72", "zasp_temporal73", "zasp_temporal74", "zasp_temporal75", "zasp_temporal76", "zasp_temporal77", "zasp_temporal78"}
	for highest := 0; highest < len(temporalProfileCommands); highest++ {
		got, err := authorizationRuntimeProfilePlan(61, full[:highest+3])
		if err != nil || !reflect.DeepEqual(got, base[highest:]) {
			t.Fatalf("exact native boundary %d resume=%v err=%v", 67+highest, got, err)
		}
	}
	got, err := authorizationRuntimeProfilePlan(61, full)
	if err != nil || !reflect.DeepEqual(got, base[11:]) {
		t.Fatalf("logical78 must replay its exact native installer before upgrade: %v %v", got, err)
	}
	got, err = authorizationRuntimeProfilePlan(61, append(append([]string(nil), full...), "zasp_authorization79"))
	if err != nil || !reflect.DeepEqual(got, base[12:]) {
		t.Fatalf("independently installed79 must validate through native identity profile: %v %v", got, err)
	}
	current := append(append([]string(nil), full...), "zasp_authorization79", "zasp_authorization80", "zasp_authorization80_temporal", "zasp_authorization80_audit", "zasp_authorization80_identity", "zasp_authorization80_worker")
	got, err = authorizationRuntimeProfilePlan(61, current)
	if err != nil || !reflect.DeepEqual(got, base[12:]) {
		t.Fatalf("current profile must revalidate exact identity/catalog, never replay old DDL: %v %v", got, err)
	}
	for _, namespaces := range [][]string{{"zasp_temporal78"}, {"zasp_temporal67", "zasp_temporal69"}, {"zasp_temporal66", "zasp_temporal67"}, {"zasp_temporal65", "zasp_temporal67"}, {"zasp_authorization80"}, append(append([]string(nil), full...), "zasp_authorization79", "zasp_authorization80"), append(append([]string(nil), current...), "zasp_temporal99"), append(append([]string(nil), current...), "zasp_authorization81")} {
		if _, err := authorizationRuntimeProfilePlan(61, namespaces); err == nil {
			t.Fatalf("partial/mixed profile accepted: %v", namespaces)
		}
	}
	for _, version := range []int64{1, 49, 59, 62, 78, 80} {
		if _, err := authorizationRuntimeProfilePlan(version, nil); err == nil {
			t.Fatalf("unknown baseline %d accepted", version)
		}
	}
}
