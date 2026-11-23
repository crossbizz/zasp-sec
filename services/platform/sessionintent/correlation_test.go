package sessionintent

import (
	"slices"
	"testing"
	"time"
)

func TestPossibleLinksStayWithinAgentWindowAndIgnoreAmbiguousPredecessors(t *testing.T) {
	start := time.Now()
	read := Observation{"read", "agent", "file", "read", "tetragon", start}
	tool := Observation{"use", "agent", "tool", "invoke", "otlp", start.Add(10 * time.Second)}
	process := Observation{"exec", "agent", "runtime", "exec", "tetragon", start.Add(time.Minute)}
	foreign := Observation{"foreign", "other", "file", "read", "tetragon", start.Add(50 * time.Second)}
	old := Observation{"stale", "agent", "network", "connect", "tetragon", start.Add(4 * time.Minute)}
	blocked := Observation{"prevented", "agent", "tool", "block", "authenticated_workload", start.Add(45 * time.Second)}
	got := PossibleLinks([]Observation{old, process, foreign, tool, read, blocked})
	want := []Link{{"read", "use", "read_then_tool"}, {"use", "exec", "tool_then_activity"}}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
	twin := tool
	twin.ID = "tie"
	got = PossibleLinks([]Observation{process, twin, read, tool})
	if len(got) != 2 || got[0].Target == "exec" || got[1].Target == "exec" {
		t.Fatal("ambiguous link", got)
	}
	got = PossibleLinks([]Observation{read, process})
	if len(got) != 1 || got[0].Reason != "read_then_activity" {
		t.Fatal(got)
	}
}
