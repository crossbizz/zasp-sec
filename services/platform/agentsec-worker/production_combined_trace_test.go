package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestProductionCombinedPostgresTraceRetainsBoundedFailureSequence(t *testing.T) {
	trace := &combinedE2EPostgresTrace{}
	trace.set("store:40001:policy deployment authority changed")
	trace.set("read:P0002:policy deployment bundle missing")
	if got := trace.String(); got != "store:40001:policy deployment authority changed,read:P0002:policy deployment bundle missing" {
		t.Fatalf("causal failure sequence was lost: %s", got)
	}
	for index := 0; index < 100; index++ {
		trace.set(fmt.Sprintf("bounded-%d", index))
	}
	values := strings.Split(trace.String(), ",")
	if len(values) != 32 || values[0] != "bounded-68" || values[31] != "bounded-99" {
		t.Fatal("trace did not retain only the latest 32 failures")
	}
}

func TestProductionCombinedPostgresTraceNamesPolicyOperations(t *testing.T) {
	for _, operation := range []string{"claim", "heartbeat", "store", "read", "finish"} {
		name := "zasp_policy_deployment_" + operation
		if got := combinedE2EDatabaseStage("SELECT " + name + "($1)"); got != name {
			t.Fatalf("policy operation %s was not identified: %s", name, got)
		}
	}
}
