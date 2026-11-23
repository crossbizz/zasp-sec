package sessionintent

import (
	"slices"
	"sort"
	"time"
)

// Observation has already passed the request's session boundary and strong
// agent attribution checks. It contains no raw content.
type Observation struct {
	ID, AgentID, Class, Action, Source string
	At                                 time.Time
}

type Link struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

func (v Observation) stage() string {
	switch {
	case v.Class == "file" && v.Action == "read":
		return "read"
	case v.Class == "tool" && (v.Action == "invoke" || (v.Source == "authenticated_workload" && v.Action == "allow")):
		return "tool"
	case v.Class == "runtime" && v.Action == "exec", v.Class == "credential" && v.Action == "use", v.Class == "network" && v.Action == "connect":
		return "activity"
	}
	return ""
}

// PossibleLinks uses event time, so late input produces the same graph on
// reread. Within the capped page, display the nearest unique compatible prior
// observation from the same agent. Time and attribution suggest a relationship
// but cannot establish causality or change either endpoint's outcome.
func PossibleLinks(observations []Observation) []Link {
	ordered := slices.Clone(observations)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].At.Equal(ordered[j].At) {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].At.Before(ordered[j].At)
	})
	links := []Link{}
	for index, target := range ordered {
		stage := target.stage()
		if target.AgentID == "" || (stage != "tool" && stage != "activity") {
			continue
		}
		var previous *Observation
		for n := index - 1; n >= 0; n-- {
			source := &ordered[n]
			if target.At.Sub(source.At) > 2*time.Minute || (previous != nil && source.At.Before(previous.At)) {
				break
			}
			if source.AgentID != target.AgentID || target.At.Sub(source.At) < time.Millisecond {
				continue
			}
			from := source.stage()
			if from != "read" && !(from == "tool" && stage == "activity") {
				continue
			}
			if previous != nil {
				previous = nil
				break
			}
			previous = source
		}
		if previous != nil {
			links = append(links, Link{previous.ID, target.ID, previous.stage() + "_then_" + stage})
		}
	}
	return links
}
