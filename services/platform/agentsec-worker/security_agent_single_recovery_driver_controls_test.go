package main

import "testing"

func TestSingleTestRecoveryNativeDriverEndpoint(t *testing.T) {
	const namespace = "zasp-single-recovery-123456"
	for _, endpoint := range []string{"", "localhost:7233", "203.0.113.1:7233", "127.0.0.1:0", "127.0.0.1:07233", "127.0.0.1:65536", "127.0.0.1:7233/path"} {
		if singleRecoveryNativeEndpoint(endpoint, namespace) == nil {
			t.Error("unowned endpoint accepted", endpoint)
		}
	}
	for _, value := range []string{"", "default", "other-owned", "zasp-single-recovery-", "zasp-single-recovery-/escape"} {
		if singleRecoveryNativeEndpoint("127.0.0.1:17233", value) == nil {
			t.Error("unowned namespace accepted", value)
		}
	}
	if err := singleRecoveryNativeEndpoint("127.0.0.1:17233", namespace); err != nil {
		t.Fatal(err)
	}
}
