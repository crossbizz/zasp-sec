// Package sessionintent interprets scoped, recorded runtime evidence at the
// boundary that observed an action. It never infers a downstream write.
package sessionintent

type Outcome string

const (
	Prevented Outcome = "prevented"
	Completed Outcome = "completed"
	Unknown   Outcome = "outcome_unknown"
)

// Tier: 4 | Purpose: determine the outcome of the observed action.
// Model: none. Authority: canonical gateway, process or linked workload receipts.
// Fallback: intentions, missing receipts and ambiguous side effects stay open.
func Evaluate(source, class, action, receipt string) Outcome {
	switch source {
	case "gateway":
		if class == "policy" && action == "block" {
			return Prevented
		}
	case "tetragon":
		if class == "runtime" && (action == "exec" || action == "exit") {
			return Completed
		}
	case "authenticated_workload":
		if action == "block" && receipt == "not_dispatched" {
			return Prevented
		}
		if receipt == "returned" {
			return Completed
		}
	}
	return Unknown
}
