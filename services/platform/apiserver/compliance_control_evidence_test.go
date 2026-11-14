package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"
)

type complianceEvidenceStub struct {
	sources []ComplianceEvidence // In source order.
	calls   []ComplianceListOptions
	fail    int // The call (one-based) that fails; zero never.
	endless bool
}

var complianceStubFamilies = map[string]string{"hipaa-audit": "audit", "soc2_security-audit": "audit", "hipaa-findings": "finding", "hipaa-tests": "test"}

// ListEvidence pages the sources as the repository does: a control filters by
// its one source family, a cursor continues after its offset.
func (s *complianceEvidenceStub) ListEvidence(_ context.Context, _ RequestIdentity, _ []byte, options ComplianceListOptions) (ComplianceEvidencePage, error) {
	s.calls = append(s.calls, options)
	if s.fail == len(s.calls) {
		return ComplianceEvidencePage{}, ErrRepositoryUnavailable
	}
	var matching []ComplianceEvidence
	for _, source := range s.sources {
		if options.ControlID == "" || source.Source == complianceStubFamilies[options.ControlID] {
			matching = append(matching, source)
		}
	}
	offset := 0
	if len(options.Cursor) != 0 {
		offset, _ = strconv.Atoi(string(options.Cursor))
	}
	page := ComplianceEvidencePage{Items: matching[min(offset, len(matching)):min(offset+options.Limit, len(matching))]}
	if offset+options.Limit < len(matching) || s.endless {
		page.NextCursor = json.RawMessage(strconv.Itoa(offset + options.Limit))
	}
	return page, nil
}

// A page of controls reads the Environment's sources once and divides them
// by family; the result equals reading each control by itself.
func TestComplianceControlEvidence(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	controls := []ComplianceControl{
		{Framework: "hipaa", ControlID: "hipaa-audit", RequiredSources: []string{"audit"}},
		{Framework: "hipaa", ControlID: "hipaa-findings", RequiredSources: []string{"finding"}},
		{Framework: "hipaa", ControlID: "hipaa-tests", RequiredSources: []string{"test"}},
		{Framework: "soc2_security", ControlID: "soc2_security-audit", RequiredSources: []string{"audit"}},
	}
	sources := func(audit, finding int) []ComplianceEvidence {
		var result []ComplianceEvidence
		for n := range audit {
			result = append(result, ComplianceEvidence{ID: fmt.Sprintf("audit-%04d", n), Source: "audit"})
		}
		for n := range finding {
			result = append(result, ComplianceEvidence{ID: fmt.Sprintf("finding-%04d", n), Source: "finding"})
		}
		return result
	}
	ids := func(items []ComplianceEvidence) []string {
		result := []string{}
		for _, item := range items {
			result = append(result, item.ID)
		}
		return result
	}
	for _, c := range []struct {
		name           string
		audit, finding int
		reads          int
	}{
		{"one page", 7, 9, 1},
		{"empty environment", 0, 0, 1},
		{"several pages, a family beyond a hundred", 150, 60, 3},
		{"beyond the batch bound", 1100, 5, complianceControlEvidencePages + len(controls)},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &complianceEvidenceStub{sources: sources(c.audit, c.finding)}
			evidence, err := complianceControlEvidence(context.Background(), stub, identity, nil, controls)
			if err != nil || len(evidence) != len(controls) || len(stub.calls) != c.reads {
				t.Fatalf("evidence=%d reads=%d err=%v", len(evidence), len(stub.calls), err)
			}
			for n, control := range controls {
				single, err := (&complianceEvidenceStub{sources: sources(c.audit, c.finding)}).ListEvidence(context.Background(), identity, nil, ComplianceListOptions{Framework: control.Framework, ControlID: control.ControlID, Limit: 100})
				if err != nil || !slices.Equal(ids(evidence[n]), ids(single.Items)) {
					t.Fatalf("%s: batched %d items, by itself %d", control.ControlID, len(evidence[n]), len(single.Items))
				}
			}
		})
	}
	for _, fail := range []int{1, 2} {
		stub := &complianceEvidenceStub{sources: sources(150, 5), fail: fail}
		if evidence, err := complianceControlEvidence(context.Background(), stub, identity, nil, controls); !errors.Is(err, ErrRepositoryUnavailable) || evidence != nil {
			t.Fatalf("failed read %d was used: %v", fail, err)
		}
	}
	stub := &complianceEvidenceStub{sources: sources(3, 3), endless: true, fail: complianceControlEvidencePages + 2}
	if evidence, err := complianceControlEvidence(context.Background(), stub, identity, nil, controls); !errors.Is(err, ErrRepositoryUnavailable) || evidence != nil {
		t.Fatalf("failed per-control read was used: %v", err)
	}
	stub = &complianceEvidenceStub{sources: sources(3, 3)}
	if evidence, err := complianceControlEvidence(context.Background(), stub, identity, nil, []ComplianceControl{{Framework: "hipaa", ControlID: "hipaa-audit", RequiredSources: []string{"audit", "finding"}}}); !errors.Is(err, ErrRepositoryUnavailable) || evidence != nil || len(stub.calls) != 0 {
		t.Fatalf("control with two source families was read: %v", err)
	}
	if evidence, err := complianceControlEvidence(context.Background(), stub, identity, nil, nil); err != nil || len(evidence) != 0 || len(stub.calls) != 0 {
		t.Fatalf("empty page read evidence: %v", err)
	}
}
