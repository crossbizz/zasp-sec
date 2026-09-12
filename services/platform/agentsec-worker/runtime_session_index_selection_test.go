package main

import "testing"

func TestWorkerSessionIndexSelectionIsClosedAndModeScoped(t *testing.T) {
	for _, name := range []string{"", "zasp-runtime-sessions-v1", "zasp-runtime-sessions-v2", "zasp-runtime-sessions-v3", "*", " zasp-runtime-sessions-v2"} {
		config := validRuntimeIndexConfig()
		config.RuntimeSessionIndex = name
		want := name == "" || name == "zasp-runtime-sessions-v1" || name == "zasp-runtime-sessions-v2"
		if validWorkerRuntimeConfig(config) != want {
			t.Fatal("index worker selection", name)
		}
		unrelated := validRuntimeCompleteConfig()
		unrelated.RuntimeSessionIndex = name
		if validWorkerRuntimeConfig(unrelated) != (name == "") {
			t.Fatal("non-index worker accepted search authority", name)
		}
	}
}
