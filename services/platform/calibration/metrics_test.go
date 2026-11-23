package calibration

import (
	"math"
	"testing"
)

func TestMetricsDistinguishAbsentEvidenceAndExactOne(t *testing.T) {
	empty, ok := Compute(nil)
	if !ok || empty.Brier != nil || empty.ECE != nil || empty.Bins[0].ObservedRate != nil {
		t.Fatal(empty)
	}
	// 0.2 true, 0.2 false, and exactly 1.0 true.
	curves, ok := Compute([]Bucket{{2, 2, .4, 1, .68}, {10, 1, 1, 1, 0}})
	if !ok || curves.Brier == nil || math.Abs(*curves.Brier-.68/3) > 1e-10 || math.Abs(*curves.ECE-.2) > 1e-10 || *curves.Bins[2].ObservedRate != .5 || curves.Bins[9].Count != 1 {
		t.Fatal(curves)
	}
	if threshold := curves.Thresholds[10]; threshold.TP != 1 || threshold.FP != 0 || threshold.TN != 1 || threshold.FN != 1 {
		t.Fatal(threshold)
	}
	if _, ok := Compute([]Bucket{{11, 1, .1, 0, .01}}); ok {
		t.Fatal("invalid index admitted")
	}
}
