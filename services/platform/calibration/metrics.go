// Package calibration computes reliability and decision curves over scoped
// aggregate counts. Scores are probabilities of a true positive.
package calibration

import "math"

type Counts struct {
	TP int64 `json:"tp"`
	FP int64 `json:"fp"`
	FN int64 `json:"fn"`
}
type Threshold struct {
	Threshold float64 `json:"threshold"`
	Counts
	TN        int64 `json:"tn"`
	SeriousTP int64 `json:"serious_tp"`
	SeriousFN int64 `json:"serious_fn"`
}
type Reliability struct {
	Lower           float64  `json:"lower"`
	Upper           float64  `json:"upper"`
	Count           int64    `json:"count"`
	MeanProbability *float64 `json:"mean_probability"`
	ObservedRate    *float64 `json:"observed_rate"`
}
type Bucket struct {
	Bucket           int     `json:"bucket"`
	N                int64   `json:"n"`
	PSum             float64 `json:"psum"`
	Positives        int64   `json:"positives"`
	Squares          float64 `json:"squares"`
	SeriousPositives int64   `json:"serious_positives"`
}
type Curves struct {
	Bins       [10]Reliability `json:"bins"`
	Thresholds [11]Threshold   `json:"thresholds"`
	Brier      *float64        `json:"brier"`
	ECE        *float64        `json:"ece"`
}

func Ratio(numerator float64, denominator int64) *float64 {
	if denominator <= 0 {
		return nil
	}
	r := numerator / float64(denominator)
	return &r
}

func Compute(buckets []Bucket) (Curves, bool) {
	var curves Curves
	var positive [10]int64
	var prob [10]float64
	var seen [11]bool
	var total int64
	var sq, calErr float64
	for i := range curves.Bins {
		curves.Bins[i] = Reliability{Lower: float64(i) / 10, Upper: float64(i+1) / 10}
	}
	for i := range curves.Thresholds {
		curves.Thresholds[i].Threshold = float64(i) / 10
	}
	for _, b := range buckets {
		if b.Bucket < 0 || b.Bucket > 10 || seen[b.Bucket] || b.N < 1 || b.N > 1e12 || b.Positives < 0 || b.Positives > b.N || b.SeriousPositives < 0 || b.SeriousPositives > b.Positives || !bounded(b.PSum, float64(b.N)) || !bounded(b.Squares, float64(b.N)) {
			return Curves{}, false
		}
		seen[b.Bucket] = true
		i := min(9, b.Bucket)
		curves.Bins[i].Count += b.N
		positive[i] += b.Positives
		prob[i] += b.PSum
		total += b.N
		sq += b.Squares
		for j := range curves.Thresholds {
			t := &curves.Thresholds[j]
			if b.Bucket >= j {
				t.TP += b.Positives
				t.SeriousTP += b.SeriousPositives
				t.FP += b.N - b.Positives
			} else {
				t.FN += b.Positives
				t.SeriousFN += b.SeriousPositives
				t.TN += b.N - b.Positives
			}
		}
	}
	for i := range curves.Bins {
		b := &curves.Bins[i]
		b.MeanProbability = Ratio(prob[i], b.Count)
		b.ObservedRate = Ratio(float64(positive[i]), b.Count)
		calErr += math.Abs(float64(positive[i]) - prob[i])
	}
	curves.Brier = Ratio(sq, total)
	curves.ECE = Ratio(calErr, total)
	return curves, true
}
func bounded(v, max float64) bool { return v >= 0 && v <= max }
